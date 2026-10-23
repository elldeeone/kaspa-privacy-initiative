#!/usr/bin/env python3
"""Independent public synthetic private-authorization oracle; no repo imports.

Reads frozen source-pinned artifact cases. Verifies exact Auth484 framing,
raw-CM/private ownership/NF/public-limb relations and all 3344 public-update
witness bytes. It does not verify a Groth16 proof or accepted chain lineage.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import resource
import time

D = bytes.fromhex("9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c")
MAX = 2_870_000_000_000_000_000
FLOOR = 60_000_000
ZERO = bytes(32)


class Rejected(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Rejected(reason)


def sha(*values):
    return hashlib.sha256(b"".join(values)).digest()


def raw(value, size):
    need(type(value) is str, "hex-type")
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise Rejected("hex-format") from None
    need(len(result) == size and result.hex() == value, "hex-width-or-canonicality")
    return result


def integer(value, bits):
    need(type(value) is int and 0 <= value < 1 << bits, "integer-range")
    return value


def le(value, width):
    return integer(value, 8 * width).to_bytes(width, "little")


def num(value):
    return int.from_bytes(value, "little")


def state(data):
    need(len(data) == 112 and data[:8] == b"KPX2ST01", "state-framing")
    need(data[8:40] == D, "state-domain")
    n, m = num(data[72:76]), num(data[108:112])
    need(1 <= n <= 65_535 and 1 <= m <= 2 * n + 1 <= 131_071, "state-counts")
    return {"cm": data[40:72], "n": n, "nf": data[76:108], "m": m}


def note(data, positive):
    need(len(data) == 168, "note-width")
    v = num(data[64:72])
    if positive:
        need(FLOOR <= v <= MAX, "positive-note-range")
    else:
        need(v == 0 and data[:72] == bytes(72) and data[104:] == bytes(64),
             "dummy-note-fields")
    return v, sha(b"KPX1NOT\0", D, data)


def fold(leaf, index, path, tag):
    need(len(path) in (16, 17), "path-depth")
    need(0 <= index < 1 << len(path), "path-index")
    for level, sibling in enumerate(path):
        leaf = sha(tag, sibling, leaf) if index >> level & 1 else sha(tag, leaf, sibling)
    return leaf


def path(data, depth):
    need(len(data) == 32 * depth, "path-width")
    return [data[i:i + 32] for i in range(0, len(data), 32)]


def insert_nf(root, count, value, witness):
    need(len(witness) == 1160 and count < 1 << 17, "nf-witness-or-capacity")
    at = num(witness[:4])
    leaf = witness[4:72]
    previous, following, next_index = leaf[:32], leaf[32:64], num(leaf[64:68])
    need(at < count and (at == 0) == (previous == ZERO), "nf-predecessor-index")
    need((following == ZERO) == (next_index == 0), "nf-tail-equivalence")
    need(next_index < count, "nf-next-index")
    if following != ZERO:
        need(num(previous) < num(following), "nf-current-order")
    need(value != ZERO and num(previous) < num(value), "nf-lower-or-zero")
    need(following == ZERO or num(value) < num(following), "nf-upper-or-spent")
    old_path = path(witness[72:616], 17)
    append_path = path(witness[616:1160], 17)
    need(fold(sha(b"KPX1NFL\0", leaf), at, old_path, b"KPX1NFN\0") == root,
         "nf-old-path")
    replaced = previous + value + le(count, 4)
    middle = fold(sha(b"KPX1NFL\0", replaced), at, old_path, b"KPX1NFN\0")
    need(fold(sha(b"KPX1NFE\0"), count, append_path, b"KPX1NFN\0") == middle,
         "nf-intermediate-empty-path")
    appended = value + following + le(next_index, 4)
    return fold(sha(b"KPX1NFL\0", appended), count, append_path, b"KPX1NFN\0")


def native_context(case, auth, payload):
    """Inspect actual pinned native serde body/UTXOs; never execute native code.

    V1 IDs use native BLAKE3, which hashlib does not supply. This oracle does
    not invent a replacement or independently recompute transaction IDs.
    """
    body_bytes = Path(case["transaction_path"]).read_bytes()
    context_bytes = Path(case["supplied_context_path"]).read_bytes()
    need(sha(body_bytes).hex() == case["transaction_sha256"], "actual-transaction-pin")
    need(sha(context_bytes).hex() == case["supplied_context_sha256"], "actual-context-pin")
    tx, context = json.loads(body_bytes), json.loads(context_bytes)
    need(tx["version"] == 1 and tx["lockTime"] == tx["gas"] == 0
         and raw(tx["subnetworkId"], 20) == bytes(20), "actual-native-metadata")
    need(len(tx["inputs"]) == len(tx["outputs"]) == len(context) == 1, "actual-native-arity")
    inp, output, entry = tx["inputs"][0], tx["outputs"][0], context[0]
    need(inp["sequence"] == (1 << 64) - 1 and entry["is_coinbase"] is False,
         "actual-native-input-metadata")
    outpoint = inp["previousOutpoint"]
    need(raw(outpoint["transactionId"], 32) + le(outpoint["index"], 4) == auth[40:76],
         "actual-native-outpoint")
    need(integer(entry["amount_sompi"], 64) == num(auth[188:196]), "actual-native-input-value")
    need(integer(output["value"], 64) == num(auth[476:484]) and output["covenant"] is None,
         "actual-native-output-value-or-covenant")
    need(entry["amount_sompi"] - output["value"] == num(auth[196:204]), "actual-native-fee")
    need(raw(tx["payload"], 4356) == payload, "actual-native-payload")
    sig = bytes.fromhex(inp["signatureScript"])
    need(sig.hex() == inp["signatureScript"] and len(sig) > 313, "actual-scriptSig-canonicality")
    need(sig[0] == 65 and sig[1:66] == bytes(65) and sig[66:68] == b"\x4c\x80"
         and sig[196] == 0x4d,
         "actual-private-common-witness")
    proof_stage = case["proof_stage"]
    need(proof_stage in ("PLACEHOLDER_NOT_VERIFIED", "GENUINE_NATIVE_VALIDATED"), "proof-stage")
    need((sig[68:196] == bytes(128)) == (proof_stage == "PLACEHOLDER_NOT_VERIFIED"),
         "proof-stage-bytes")
    redeem = sig[199:]
    need(num(sig[197:199]) == len(redeem) and redeem[:2] == b"\x4c\x70"
         and redeem[2:114] == auth[76:188], "actual-prior-redeem-state")
    p2sh = lambda r: (b"\x00\x00\xaa\x20" + hashlib.blake2b(r, digest_size=32).digest() + b"\x87").hex()
    need(entry["script_public_key"] == p2sh(redeem), "actual-prior-P2SH")
    successor = redeem[:2] + auth[364:476] + redeem[114:]
    need(output["scriptPublicKey"] == p2sh(successor), "actual-immutable-successor-P2SH")
    return {"transaction_sha256": case["transaction_sha256"],
            "supplied_context_sha256": case["supplied_context_sha256"],
            "actual_body_context_and_immutable_P2SH": "PASS",
            "proof_stage": proof_stage,
            "transaction_id_independently_recomputed": False}


def verify(case):
    need(case["classification"] == "PUBLIC_SYNTHETIC_DO_NOT_FUND", "classification")
    auth = raw(case["auth_hex484"], 484)
    need(auth[:8] == b"KPX2AU01" and auth[8:40] == D, "auth-framing-or-domain")
    old, new = state(auth[76:188]), state(auth[364:476])
    reserve, fee, next_reserve = num(auth[188:196]), num(auth[196:204]), num(auth[476:484])
    need(FLOOR <= reserve <= MAX and 1 <= fee <= MAX, "reserve-or-fee-range")
    need(next_reserve == reserve - fee and FLOOR <= next_reserve <= MAX, "reserve-conservation")
    need(new["n"] == old["n"] + 2 and new["m"] == old["m"] + 2, "successor-counts")
    need(auth[40:76] == raw(case["actual_previous_outpoint_hex36"], 36), "actual-outpoint")
    need(reserve == integer(case["actual_reserve_sompi"], 64), "actual-reserve")
    need(fee == integer(case["actual_fee_sompi"], 64), "actual-fee")
    need(next_reserve == integer(case["actual_successor_reserve_sompi"], 64), "actual-successor-reserve")
    need(auth[364:476] == raw(case["actual_successor_state_hex112"], 112), "actual-successor-state")
    need(len(case["inputs"]) == len(case["outputs"]) == 2, "private-arity")
    nfs = [auth[204:236], auth[236:268]]
    cms = [auth[268:300], auth[300:332]]
    need(all(x != ZERO for x in nfs) and nfs[0] != nfs[1], "nf-zero-or-duplicate")
    real_positions, total_in = [], 0
    for slot, inp in enumerate(case["inputs"]):
        need(type(inp["real"]) is bool, "input-real-flag")
        data = raw(inp["note_hex168"], 168)
        s, k = raw(inp["s_hex32"], 32), raw(inp["k_hex32"], 32)
        index = integer(inp["position"], 32)
        membership = [raw(x, 32) for x in inp["cm_path_hex"]]
        need(len(membership) == 16, "input-path-depth")
        dk, ds = raw(inp["dummy_key_hex32"], 32), raw(inp["dummy_seed_hex32"], 32)
        v, cm = note(data, inp["real"])
        if inp["real"]:
            need(index < old["n"] and index < 1 << 16, "input-position")
            need(data[:32] == sha(b"KPX1OWN\0", D, s, data[32:64]), "private-owner")
            need(data[104:136] == sha(b"KPX1KEY\0", D, k), "private-key-commitment")
            need(dk == ds == ZERO, "real-dummy-material")
            need(fold(cm, index, membership, b"KPX1CMN\0") == old["cm"], "private-cm-membership")
            expected_nf = hmac.digest(k, b"KPX1NF\0\0" + D + cm + le(index, 4), "sha256")
            real_positions.append(index)
            total_in += v
        else:
            need(data == bytes(168) and s == k == ZERO and index == 0
                 and all(x == ZERO for x in membership), "dummy-input-witness")
            expected_nf = hmac.digest(dk, b"KPX2DMY\0" + D + ds + bytes([slot]), "sha256")
        need(expected_nf == nfs[slot], "private-nf")
    need(real_positions and len(real_positions) == len(set(real_positions)), "real-input-uniqueness")
    need(total_in <= reserve <= MAX, "real-input-sum-bound")
    total_out, positives = 0, 0
    for slot, output in enumerate(case["outputs"]):
        data = raw(output["note_hex168"], 168)
        positive = num(data[64:72]) != 0
        v, cm = note(data, positive)
        need(cm == cms[slot], "output-cm")
        total_out += v
        positives += positive
    need(positives and cms[0] != cms[1], "output-positive-or-duplicate")
    need(total_in == total_out + fee <= MAX, "private-value-conservation")
    ciphers = [raw(x, 264) for x in case["ciphertexts_hex264"]]
    need(len(ciphers) == 2 and sha(*ciphers) == auth[332:364], "ciphertext-binding")
    witness = raw(case["public_witness_hex3344"], 3344)
    nf_root = insert_nf(old["nf"], old["m"], nfs[0], witness[:1160])
    nf_root = insert_nf(nf_root, old["m"] + 1, nfs[1], witness[1160:2320])
    need(nf_root == new["nf"], "successor-nf-root")
    cm_root = old["cm"]
    for slot in range(2):
        append_path = path(witness[2320 + slot * 512:2832 + slot * 512], 16)
        at = old["n"] + slot
        need(fold(sha(b"KPX1CME\0"), at, append_path, b"KPX1CMN\0") == cm_root,
             "cm-empty-append")
        cm_root = fold(cms[slot], at, append_path, b"KPX1CMN\0")
    need(cm_root == new["cm"], "successor-cm-root")
    digest = sha(auth)
    limbs = [num(digest[:16]), num(digest[16:])]
    need(case["public_limbs_decimal"] == [str(x) for x in limbs], "public-le128-limbs")
    payload = auth + b"".join(ciphers) + witness
    need(raw(case["payload_hex4356"], 4356) == payload, "complete-private-payload")
    context_result = native_context(case, auth, payload)
    return {"case_id": case["case_id"], "auth_sha256": digest.hex(),
            "public_limbs_decimal": [str(x) for x in limbs], "real_inputs": len(real_positions),
            "exact_relation_and_public_updates": "PASS",
            "native_body_inspection": context_result,
            "Groth16_native_chain_privacy_or_recovery_qualification": False}


def main():
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    parser = argparse.ArgumentParser()
    parser.add_argument("freeze", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    freeze_bytes = args.freeze.read_bytes()
    freeze = json.loads(freeze_bytes)
    need(freeze["runtime_authorized"] is True, "missing-root-authorization")
    need(freeze["oracle_sha256"] == sha(Path(__file__).read_bytes()).hex(), "oracle-pin")
    for path_name, expected in freeze["source_pins"].items():
        need(sha(Path(path_name).read_bytes()).hex() == expected, "source-pin")
    cases_path = Path(freeze["cases_path"])
    cases_bytes = cases_path.read_bytes()
    need(sha(cases_bytes).hex() == freeze["cases_sha256"], "cases-pin")
    cases = json.loads(cases_bytes)
    need(cases["schema"] == "independent-private-auth-cases-v1", "cases-schema")
    results = [verify(case) for case in cases["cases"]]
    need(results and len({x["case_id"] for x in results}) == len(results), "case-identities")
    usage = resource.getrusage(resource.RUSAGE_SELF)
    result = {"classification": "INDEPENDENT_PUBLIC_SYNTHETIC_RELATION_ORACLE",
              "oracle_sha256": freeze["oracle_sha256"], "freeze_sha256": sha(freeze_bytes).hex(),
              "cases_sha256": freeze["cases_sha256"], "results": results,
              "limits": "No proof verifier, native runtime, accepted lineage, cryptographic audit or privacy qualification",
              "resources": {"threads": 1, "wall_seconds": time.monotonic() - started,
                            "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
                            "peak_rss_kib_linux": usage.ru_maxrss}}
    need(not args.output.exists(), "output-already-exists")
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"cases": len(results), "output_sha256": sha(args.output.read_bytes()).hex()}))


if __name__ == "__main__":
    main()
