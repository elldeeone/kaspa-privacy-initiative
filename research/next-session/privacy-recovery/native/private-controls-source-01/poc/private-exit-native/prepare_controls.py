#!/usr/bin/env python3
"""Prepare public private-action controls; never execute a VM or contact a node.

The four base statements and genuine proofs come from the separately reviewed
new lifecycle. This producer is not an independent proof or history oracle.
Every mutation retains its original proof, including deliberately native-
consistent transcript mutations that must fail Groth16 verification.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

CLASS = "PUBLIC_SYNTHETIC_DO_NOT_FUND"
DOMAIN = "aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2"
NATIVE_SHA = "077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061"
STAGES = ("spend", "bob-partial", "bob-full", "charlie-terminal")
MAX = 2_870_000_000_000_000_000
G16_UNITS = 14_750_000
G16_ERROR = 'ZkIntegrity("Groth16 verification failed")'


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    if path.exists():
        raise ValueError("refuse overwrite: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def pin(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular public file required")
    path = path.resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def u64(value):
    return value.to_bytes(8, "little")


def u32(value):
    return value.to_bytes(4, "little")


def payload(case):
    return bytes.fromhex(case["transaction"]["payload"])


def patch(case, offset, data):
    raw = bytearray(payload(case))
    if offset < 0 or offset + len(data) > len(raw):
        raise ValueError("mutation outside payload")
    raw[offset:offset + len(data)] = data
    case["transaction"]["payload"] = raw.hex()


def flip(case, offset):
    patch(case, offset, bytes([payload(case)[offset] ^ 1]))


def p2sh(redeem):
    return "0000aa20" + hashlib.blake2b(redeem, digest_size=32).hexdigest() + "87"


def current_state(case, state):
    """Counterfactual supplied current policy, with no accepted-lineage claim."""
    raw = bytearray.fromhex(case["transaction"]["inputs"][0]["signatureScript"])
    if len(state) != 112 or raw[199:201] != b"\x4c\x70":
        raise ValueError("canonical State112 prefix required")
    raw[201:313] = state
    case["transaction"]["inputs"][0]["signatureScript"] = raw.hex()
    case["entries"][0]["scriptPublicKey"] = p2sh(raw[199:])
    patch(case, 76, state)


def signature_byte(case, offset):
    raw = bytearray.fromhex(case["transaction"]["inputs"][0]["signatureScript"])
    raw[offset] ^= 1
    case["transaction"]["inputs"][0]["signatureScript"] = raw.hex()


def successor(case, *, code=False, vk=None, state=None):
    raw = bytearray.fromhex(case["transaction"]["inputs"][0]["signatureScript"])[199:]
    raw[2:114] = state if state is not None else payload(case)[364:476]
    if code:
        raw[-1] ^= 1
    if vk is not None:
        locations = [i for i in range(114, len(raw) - len(vk) + 1) if raw[i:i + len(vk)] == vk]
        if len(locations) != 1:
            raise ValueError("expected exactly one embedded trusted VK")
        raw[locations[0]] ^= 1
    case["transaction"]["outputs"][0]["scriptPublicKey"] = p2sh(raw)


class Producer:
    def __init__(self, args):
        self.args = args
        self.rows = []
        self.sources = {Path(__file__).resolve(), args.native.resolve(),
                        args.prepared / "MATERIALIZED.json", args.setup_report.resolve()}
        repo = Path(__file__).resolve().parents[2]
        self.sources.add(repo / "research/next-session/privacy-recovery/PRIVATE-EXIT-CONTRACT.md")
        self.sources.update(repo / "poc/private-exit-native" / file for file in
                            ("Cargo.toml", "Cargo.lock", "src/lib.rs", "src/main.rs", "src/native.rs", "src/policy.rs"))

    def construct(self, name, mode, value):
        vector = self.args.output / "vectors" / (name + ".json")
        directory = self.args.output / "bodies" / name
        save(vector, value)
        process = subprocess.run([str(self.args.native), mode, str(vector), str(directory)],
                                 capture_output=True, text=True, check=False)
        save(directory / "preparation-command.json", {"argv_mode": mode,
            "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr,
            "native_VM_or_Full_executed": False})
        if process.returncode:
            raise ValueError("preparation failed; retained: " + name)
        return load(directory / "validation-case.json"), directory

    def record(self, name, stage, directory, kind, cause, supplied=False, exact_error=None):
        self.rows.append({"case_id": name, "base_stage": stage, "classification": CLASS,
            "validation_case": pin(directory / "validation-case.json"),
            "transaction": pin(directory / "transaction.json"),
            "supplied_context": pin(directory / "supplied-context.json"),
            "expected": kind, "expected_exact_error": exact_error,
            "intended_cause": cause, "supplied_context_counterfactual": supplied,
            "retained_original_genuine_proof": True,
            "changed_statement_proof_validity_claimed": False})

    def control(self, name, stage, base, mutate, cause, *, kind="REJECT_BEFORE_G16",
                supplied=False, exact_error=None):
        case = copy.deepcopy(base)
        mutate(case)
        _, directory = self.construct(name, "control-normalize-freeze", case)
        self.record(name, stage, directory, kind, cause, supplied, exact_error)


def checked_base(producer, stage, setup):
    args = producer.args
    vp = args.prepared / (stage + "-native-vector.json")
    fp = args.prepared / (stage + "-fixture.json")
    pp = args.proof_root / stage
    report = load(pp / "report.json")
    vector = load(vp)
    fixture = load(fp)
    auth = bytes.fromhex(vector["auth_hex"])
    proof = (pp / "proof128.bin").read_bytes()
    vk = (pp / "verification-key.bin").read_bytes()
    if (len(auth) != 528 or len(proof) != 128 or len(vk) != 328
            or auth[:8] != b"KPX3AU01" or auth[8:40].hex() != DOMAIN
            or fixture["classification"] != CLASS or fixture["auth_hex528"] != auth.hex()
            or report.get("genuine_Groth16_verified") is not True
            or report.get("existing_PK_or_matrix_loaded") is not False
            or report["source_identity"] != setup["source_identity"]
            or report["fixture_sha256"] != pin(fp)["sha256"]
            or report["authorization_sha256"] != hashlib.sha256(auth).hexdigest()
            or report["proof_sha256"] != hashlib.sha256(proof).hexdigest()
            or report["vk_sha256"] != hashlib.sha256(vk).hexdigest()
            or vk.hex() != vector["vk_hex"] or vk.hex() != setup["vk_hex328"]
            or (pp / "authorization528.bin").read_bytes() != auth):
        raise ValueError("genuine same-profile proof/source/statement mismatch: " + stage)
    producer.sources.update((vp, fp, pp / "report.json", pp / "proof128.bin",
                             pp / "verification-key.bin", pp / "authorization528.bin"))
    vector["proof_hex"] = proof.hex()
    case, directory = producer.construct("base-" + stage, "private-freeze", vector)
    script = bytes.fromhex(case["transaction"]["inputs"][0]["signatureScript"])
    if (script[:68] != b"\x41" + bytes(65) + b"\x4c\x80"
            or script[68:196] != proof or script[201:313] != auth[76:188]
            or payload(case)[:528] != auth):
        raise ValueError("actual native base does not preserve proof/Auth/frame")
    producer.record("base-" + stage, stage, directory, "ACCEPT", "genuine unchanged authorized action")
    return case


def prepare(args):
    args.native = args.native.resolve(strict=True)
    args.prepared = args.prepared.resolve(strict=True)
    args.proof_root = args.proof_root.resolve(strict=True)
    if pin(args.native)["sha256"] != NATIVE_SHA:
        raise ValueError("selected reviewed private-native executable identity differs")
    materialized = load(args.prepared / "MATERIALIZED.json")
    setup = load(args.setup_report)
    if (materialized.get("classification") != CLASS or materialized["domain_hex32"] != DOMAIN
            or setup.get("classification") != CLASS
            or setup.get("schema") != "kpx3-private-action-new-setup/v1"
            or setup.get("existing_PK_or_matrix_loaded") is not False
            or setup["source_identity"]["domain_hex32"] != DOMAIN
            or setup["vk_sha256"] != materialized["vk_sha256"]):
        raise ValueError("selected new lifecycle/setup identity differs")
    if args.output.exists():
        raise ValueError("fresh public control identity required")
    args.output.mkdir(parents=True)
    p = Producer(args)
    bases = {stage: checked_base(p, stage, setup) for stage in STAGES}
    ordinary, partial, full, terminal = (bases[s] for s in STAGES)

    def control(name, mutate, cause, *, stage="bob-partial", **kwargs):
        p.control(name, stage, bases[stage], mutate, cause, **kwargs)

    # Exact actual-context binding, distinct from changing Auth consistently.
    control("actual-outpoint-index", lambda c: c["transaction"]["inputs"][0]["previousOutpoint"].update(index=1),
            "actual input outpoint must equal Auth prior outpoint")
    control("actual-reserve-plus1", lambda c: c["entries"][0].update(amount=c["entries"][0]["amount"] + 1),
            "actual supplied reserve must equal Auth R", supplied=True)
    control("auth-domain", lambda c: flip(c, 8), "authorization uses exact current profile domain")
    control("auth-prior-state", lambda c: flip(c, 116), "authorization prior State112 equals actual policy")
    control("auth-old-magic", lambda c: patch(c, 0, b"KPX2AU01"), "old private authorization cannot select new private branch")
    control("auth-old-width", lambda c: c["transaction"].update(payload=(payload(c)[:484] + payload(c)[528:]).hex()),
            "old Auth484 framing cannot enter Auth528 branch")
    for name, field, value in (("version", "version", 2), ("locktime", "lockTime", 1), ("gas", "gas", 1),
                                ("subnetwork", "subnetworkId", "01" + "00" * 19)):
        control("common-" + name, lambda c, f=field, v=value: c["transaction"].update({f: v}),
                "common exact native context: " + name)
    control("common-sequence", lambda c: c["transaction"]["inputs"][0].update(sequence=0), "no relative-lock sequence")
    control("common-coinbase", lambda c: c["entries"][0].update(isCoinbase=True), "pool input is noncoinbase", supplied=True)
    control("common-input-covenant", lambda c: c["entries"][0].update(covenantId="01" + "00" * 31),
            "pool input has no covenant identity", supplied=True)
    for name, byte in (("inactive-signature-first", 1), ("inactive-signature-last", 65)):
        control(name, lambda c, i=byte: signature_byte(c, i), "all inactive signature65 bytes must be zero")
    control("terminal-inactive-signature-last", lambda c: signature_byte(c, 65),
            "terminal still checks the complete inactive signature65", stage="charlie-terminal")

    # All supported positions, including terminal output0, forbid metadata.
    for stage in ("spend", "bob-partial", "charlie-terminal"):
        for index in range(len(bases[stage]["transaction"]["outputs"])):
            control(f"{stage}-covenant-output{index}",
                    lambda c, i=index: c["transaction"]["outputs"][i].update(
                        covenant={"authorizingInput": 0, "covenantId": "01" + "00" * 31}),
                    "every output requires absent authorizing-input metadata", stage=stage)
    control("output-extra", lambda c: c["transaction"]["outputs"].append(
        {"value": 1, "scriptPublicKey": c["transaction"]["outputs"][1]["scriptPublicKey"], "covenant": None}),
        "exact two-output topology forbids extra payout")
    control("output-missing-payout", lambda c: c["transaction"]["outputs"].pop(), "exact native payout output required")
    control("output-missing-reserve", lambda c: c["transaction"]["outputs"].pop(0), "continuing reserve successor required")
    control("output-payout-value", lambda c: c["transaction"]["outputs"][1].update(
        value=c["transaction"]["outputs"][1]["value"] - 1), "actual native payout equals Auth P")
    control("output-reserve-value", lambda c: c["transaction"]["outputs"][0].update(
        value=c["transaction"]["outputs"][0]["value"] - 1), "actual native reserve equals Auth Rprime")
    control("successor-code", lambda c: successor(c, code=True), "successor preserves immutable complete code suffix")
    control("successor-vk", lambda c: successor(c, vk=bytes.fromhex(setup["vk_hex328"])), "successor preserves actual profile VK")
    control("successor-domain", lambda c: successor(c, state=payload(c)[364:372] + bytes(32) + payload(c)[404:476]),
            "successor preserves actual profile domain")

    # Matching output and Auth malformed SPKs reach canonical native SPK guards.
    for name, relative, byte in (("version", 1, 1), ("push", 2, 0x21), ("suffix", 35, 0xad)):
        def malformed(c, relative=relative, byte=byte):
            patch(c, 492 + relative, bytes([byte]))
            c["transaction"]["outputs"][1]["scriptPublicKey"] = payload(c)[492:528].hex()
        control("payout-spk-" + name, malformed, "Auth completeSPK36 must be version0 exact P2PK")
    control("payout-spk-unbound-output", lambda c: c["transaction"]["outputs"][1].update(
        scriptPublicKey=payload(c)[492:495].hex() + (bytes([payload(c)[495] ^ 1]) + payload(c)[496:528]).hex()),
        "actual native destination equals Auth fullSPK36")
    control("p0-nonzero-destination", lambda c: patch(c, 492, b"\x01"), "P0 requires complete zero destination", stage="spend")

    # Sequential current-state NF authentication, before any expensive proof.
    for name, offset in (("nf0-pred-path", 1128), ("nf0-append-path", 1672),
                         ("nf1-pred-path", 2288), ("nf1-append-path", 2832),
                         ("cm0-append-path", 3376), ("cm1-append-path", 3888),
                         ("next-nf-root", 440), ("next-cm-root", 404)):
        control(name, lambda c, o=offset: flip(c, o), "specific authenticated " + name)
    control("nf-duplicate", lambda c: patch(c, 236, payload(c)[204:236]), "two action nullifiers must be distinct")
    control("nf-order", lambda c: patch(c, 204, payload(c)[236:268] + payload(c)[204:236]),
            "slot1 authenticates against slot0 updated NF state")
    control("nf1-stale-slot0-witness", lambda c: patch(c, 2216, payload(c)[1056:2216]),
            "second NF insert cannot reuse prior-root slot0 witness")
    control("nf0-predecessor-equality", lambda c: patch(c, 1060, payload(c)[204:236]),
            "predecessor must be strictly less than new NF; genuine occupied-current witness is tested separately")
    control("nf1-predecessor-equality", lambda c: patch(c, 2220, payload(c)[236:268]),
            "second predecessor must be strictly less than new NF")

    # Counterfactual authenticated context is explicitly labelled; no lineage.
    for name, n, m in (("n-zero", 0, 1), ("n-over", 65536, 1), ("m-zero", 2, 0),
                        ("m-over", 65535, 131072), ("m-profile", 2, 6), ("cm-capacity", 65534, 1)):
        def counts(c, n=n, m=m):
            state = bytearray(payload(c)[76:188])
            state[72:76], state[108:112] = u32(n), u32(m)
            current_state(c, state)
        control("count-" + name, counts, "explicit current/successor capacity bound", supplied=True)
    control("next-n-count", lambda c: patch(c, 436, u32(0)), "exact two continuing CM appends")
    control("next-m-count", lambda c: patch(c, 472, u32(0)), "exact two NF inserts")

    # Terminal omitted work has canonical-zero checks BEFORE the skip.
    for name, offset in (("cm0", 268), ("cm1", 300), ("cipher-first", 528), ("cipher-last", 1055),
                         ("cm0-path-first", 3376), ("cm1-path-last", 4399)):
        control("terminal-nonzero-" + name, lambda c, o=offset: flip(c, o),
                "terminal complete inactive " + name + " must be zero before CM skip", stage="charlie-terminal")
    control("terminal-zero-hash", lambda c: patch(c, 332, bytes(32)), "terminal cipher digest is SHA256(zero528), not zero digest", stage="charlie-terminal")
    control("terminal-changed-cmroot", lambda c: flip(c, 404), "terminal CMroot carries prior root without append", stage="charlie-terminal")
    control("terminal-next-n", lambda c: patch(c, 436, u32(int.from_bytes(payload(c)[148:152], "little") + 2)),
            "terminal n carries prior n without append", stage="charlie-terminal")
    control("terminal-extra-reserve", lambda c: c["transaction"]["outputs"].append(
        {"value": 1, "scriptPublicKey": c["entries"][0]["scriptPublicKey"], "covenant": None}),
        "terminal has one payout and no reserve successor", stage="charlie-terminal")
    for name, offset, value in (("fee-zero", 196, 0), ("fee-over", 196, MAX + 1),
                                ("payout-over", 484, MAX + 1), ("reserveprime-over", 476, MAX + 1)):
        control("amount-" + name, lambda c, o=offset, v=value: patch(c, o, u64(v)), "bounded native amount: " + name)

    # All checks before G16 remain coherent while the original proof is replayed.
    def binding(name, mutate, cause, stage="bob-partial"):
        control(name, mutate, cause, stage=stage, kind="REJECT_AT_G16", exact_error=G16_ERROR)

    def destination(c):
        flip(c, 495)
        c["transaction"]["outputs"][1]["scriptPublicKey"] = payload(c)[492:528].hex()
    binding("proof-binds-destination", destination, "original proof cannot authorize another native payout destination")

    def payout_plus(c):
        raw = payload(c)
        patch(c, 484, u64(int.from_bytes(raw[484:492], "little") + 1))
        patch(c, 476, u64(int.from_bytes(raw[476:484], "little") - 1))
        c["transaction"]["outputs"][0]["value"] -= 1
        c["transaction"]["outputs"][1]["value"] += 1
    binding("proof-binds-payout", payout_plus, "original proof cannot increase P while decreasing reserve equally")

    def fee_plus(c):
        raw = payload(c)
        patch(c, 196, u64(int.from_bytes(raw[196:204], "little") + 1))
        patch(c, 476, u64(int.from_bytes(raw[476:484], "little") - 1))
        c["transaction"]["outputs"][0]["value"] -= 1
    binding("proof-binds-fee", fee_plus, "original proof cannot authorize changed exact native fee")

    def outpoint(c):
        point = c["transaction"]["inputs"][0]["previousOutpoint"]
        point["index"] += 1
        patch(c, 72, u32(point["index"]))
    binding("proof-binds-outpoint", outpoint, "original proof cannot authorize a different otherwise identical supplied input")

    def ciphertext(c):
        flip(c, 528)
        patch(c, 332, hashlib.sha256(payload(c)[528:1056]).digest())
    binding("proof-binds-ciphertext", ciphertext, "original proof cannot authorize a different cipher transcript with matching native SHA")
    binding("proof-binds-u64-p-negative-zero", lambda c: patch(c, 484, u64(1 << 63)),
            "native sign-magnitude negative-zero decodes zero; unsigned Auth-bound proof must reject", stage="spend")
    binding("proof-binds-u64-rprime-negative-zero", lambda c: patch(c, 476, u64(1 << 63)),
            "terminal native negative-zero decodes zero; unsigned Auth-bound proof must reject", stage="charlie-terminal")

    # Typed malformed-proof failure is separate from valid-curve binding cases.
    def zero_proof(c):
        raw = bytearray.fromhex(c["transaction"]["inputs"][0]["signatureScript"])
        raw[68:196] = bytes(128)
        c["transaction"]["inputs"][0]["signatureScript"] = raw.hex()
    control("proof-malformed-zero128", zero_proof, "zero bytes are not a valid G16 proof", kind="REJECT_AT_G16")
    manifest = {"classification": CLASS, "scope": "PRIVATE_EXIT_NATIVE_ORDINARY_CONTROLS",
        "domain_hex32": DOMAIN, "native_binary": pin(args.native),
        "g16_minimum_script_units": G16_UNITS,
        "native_VM_or_Full_executed_here": False, "sources": [pin(path) for path in sorted(p.sources)],
        "cases": p.rows, "case_count": len(p.rows),
        "not_claimed": ["accepted chain backing", "confirmed payout", "privacy qualification", "security audit"],
        "genuine_current_occupied_NF_races_owned_by": "private-exit-lifecycle"}
    save(args.output / "EXPECTED.json", manifest)
    return {"prepared_cases": len(p.rows), "manifest_sha256": pin(args.output / "EXPECTED.json")["sha256"],
            "native_VM_or_Full_executed": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "prepared", "proof-root", "setup-report", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    print(json.dumps(prepare(parser.parse_args()), sort_keys=True))
