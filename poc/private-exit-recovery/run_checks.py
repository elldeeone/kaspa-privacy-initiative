#!/usr/bin/env python3
"""One public replay/control run using previously selected native evidence only."""
from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path

from dependencies import ROOT, old
from public_adapter import replay
from native_evidence import ExistingNativeResults

FIXTURE = ROOT / "research/next-session/privacy-recovery/compatibility/fixtures-01"


def save(path, value):
    with path.open("x") as file:
        json.dump(value, file, indent=2, sort_keys=True)
        file.write("\n")


def main(args):
    raw = args.freeze.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.reviewed_freeze_sha256:
        raise ValueError("reviewed-source-fixture-identity")
    frozen = json.loads(raw)
    for item in frozen["files"]:
        path = ROOT / item["path"]
        raw = path.read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("reviewed-public-artifact-changed")
    args.output.mkdir(parents=True, exist_ok=False)
    descriptor = json.loads((FIXTURE / "descriptor.json").read_bytes())
    bundle = json.loads((FIXTURE / "supplied-public-bodies.json").read_bytes())
    evidence = ExistingNativeResults()
    positive = replay(descriptor, bundle, evidence)
    if not (len(positive["deliveries"]) == 8 and len(positive["nullifiers"]) == 9
            and positive["head"]["reserve_sompi"] == 0 and positive["head"]["outpoint"] is None
            and len(positive["operations"]) == 6 and positive["ordinary_ancestors"] == 1
            and [p["amount_sompi"] for p in positive["payouts"]] == [200000000, 762000200, 981042400]
            and len(evidence.calls) == 7 and not positive["completeness"]["complete"]
            and positive["completeness"]["accepted_chain_backing"] is False):
        raise ValueError("positive-final-state-or-boundary")
    save(args.output / "replayed.json", positive)
    rows = []

    def private(b, index=3):
        return b["transactions"][index]["transaction"]

    def patch(b, offset, value, index=3):
        tx = private(b, index)
        raw = bytearray.fromhex(tx["payload"])
        raw[offset:offset + len(value)] = value
        tx["payload"] = raw.hex()

    def flip(b, offset, index=3):
        raw = bytes.fromhex(private(b, index)["payload"])
        patch(b, offset, bytes([raw[offset] ^ 1]), index)

    def check(name, mutate, error, *, evidence_lookup=False):
        d, b = deepcopy(descriptor), deepcopy(bundle)
        mutate(d, b)
        selected = ExistingNativeResults()
        try:
            replay(d, b, selected)
        except old.Invalid as exception:
            actual = str(exception)
        else:
            raise ValueError("negative-control-accepted: " + name)
        if actual != error or bool(selected.calls) != evidence_lookup:
            raise ValueError("control-error-family-or-evidence-stage: " + name + ":" + actual)
        rows.append({"case_id": name, "expected_public_error": error, "actual_public_error": actual,
                     "evidence_lookups": len(selected.calls), "matched": True})

    check("network-schema-refused", lambda d, b: b.update(schema="kpx2-network-fetch/v1"), "offline-descriptor-binding")
    check("fake-accepting-header-refused", lambda d, b: b["transactions"][3].update(accepting_block_header={}), "offline-row-fields")
    check("old-descriptor-refused", lambda d, b: d.update(schema="kpx2-recovery-descriptor/v1"), "descriptor-network-profile")

    def policy(d, b):
        raw = bytearray.fromhex(d["initial_redeem_hex"])
        raw[-1] ^= 1
        d.update(initial_redeem_hex=raw.hex(), immutable_policy_sha256=old.h(raw[114:]).hex())
        b["descriptor_sha256"] = old.digest(d)
    check("caller-policy-selfhash-refused", policy, "unapproved-new-policy-semantics")

    def initial(d, b):
        raw = bytearray.fromhex(d["initial_redeem_hex"])
        raw[42] ^= 1
        d["initial_redeem_hex"] = raw.hex()
        b["descriptor_sha256"] = old.digest(d)
    check("wrong-initial-cmroot", initial, "incoherent-founding-state")
    check("duplicate-row", lambda d, b: b["transactions"].append(deepcopy(b["transactions"][3])), "duplicate-supplied-transaction")
    check("missing-middle", lambda d, b: b["transactions"].pop(2), "unrelated-or-broken-pool-history")

    def reused_funding(d, b):
        founding = b["transactions"][1]
        admit = b["transactions"][2]
        admit["transaction"]["inputs"][1]["previousOutpoint"] = deepcopy(founding["transaction"]["inputs"][0]["previousOutpoint"])
        admit["input_contexts"][1]["outpoint"] = deepcopy(founding["input_contexts"][0]["outpoint"])
    check("external-funding-input-reuse", reused_funding, "duplicate-or-competing-supplied-spend")
    check("trailing-payload-byte", lambda d, b: private(b).update(payload=private(b)["payload"] + "00"), "private-frame")
    check("old-authorization-magic", lambda d, b: patch(b, 0, b"KPX2AU01"), "unsupported-new-pool-operation")
    check("wrong-auth-outpoint", lambda d, b: flip(b, 40), "private-auth-context")
    check("wrong-auth-reserve", lambda d, b: flip(b, 188), "private-reserve-fee-payout")
    check("wrong-auth-fee", lambda d, b: flip(b, 196), "private-reserve-fee-payout")
    check("wrong-public-payout", lambda d, b: flip(b, 484, 4), "private-reserve-fee-payout")
    check("wrong-remaining-reserve", lambda d, b: flip(b, 476, 4), "private-reserve-fee-payout")
    check("malformed-auth-full-spk", lambda d, b: patch(b, 493, b"\x01", 4), "private-payout-script")
    check("P0-nonzero-full-spk", lambda d, b: patch(b, 492, b"\x01"), "private-P0-destination")
    check("nf0-current-path", lambda d, b: flip(b, 1128), "nf-current-path")
    check("nf1-current-path", lambda d, b: flip(b, 2288), "nf-current-path")
    check("nf1-stale-append-path", lambda d, b: flip(b, 2832), "nf-intermediate-append-path")
    check("cm0-current-path", lambda d, b: flip(b, 3376), "cm-append-path")
    check("cm1-current-path", lambda d, b: flip(b, 3888), "cm-append-path")
    check("ciphertext-sha", lambda d, b: flip(b, 528), "private-ciphertext-binding")
    for name, offset in (("cm0", 268), ("cm1", 300), ("cipher-first", 528), ("cipher-last", 1055),
                         ("cm0-path", 3376), ("cm1-path", 4399)):
        check("terminal-nonzero-" + name, lambda d, b, o=offset: flip(b, o, 6), "terminal-inactive-fields")
    check("terminal-wrong-zero-cipher-hash", lambda d, b: patch(b, 332, bytes(32), 6), "private-ciphertext-binding")
    check("terminal-CMroot-carry", lambda d, b: flip(b, 404, 6), "private-next-state")
    check("terminal-no-CMappend-count", lambda d, b: flip(b, 436, 6), "private-next-state")
    check("terminal-still-needs-NF1", lambda d, b: flip(b, 2288, 6), "nf-current-path")
    check("terminal-inactive-signature", lambda d, b: private(b, 6)["inputs"][0].update(
        signatureScript=private(b, 6)["inputs"][0]["signatureScript"][:130] + "01" + private(b, 6)["inputs"][0]["signatureScript"][132:]), "private-frame")
    check("payout-output-value", lambda d, b: private(b, 4)["outputs"][1].update(value=199999999), "private-native-payout")
    check("payout-output-missing", lambda d, b: private(b, 4)["outputs"].pop(), "private-output-count")
    check("payout-output-covenant", lambda d, b: private(b, 4)["outputs"][1].update(
        covenant={"authorizingInput": 0, "covenantId": "01" * 32}), "output-fields")

    def consistent_destination(d, b):
        flip(b, 495, 4)
        private(b, 4)["outputs"][1]["scriptPublicKey"] = bytes.fromhex(private(b, 4)["payload"])[492:528].hex()
    check("consistent-destination-original-proof-evidence", consistent_destination, "selected-offline-native-evidence", evidence_lookup=True)

    def proof_witness(d, b):
        tx = private(b)
        raw = bytearray.fromhex(tx["inputs"][0]["signatureScript"])
        raw[70] ^= 1
        tx["inputs"][0]["signatureScript"] = raw.hex()
    check("same-v1-id-mutated-proof-witness", proof_witness, "selected-offline-native-evidence", evidence_lookup=True)
    check("same-body-changed-entire-context", lambda d, b: b["transactions"][3]["input_contexts"][0].update(block_daa_score=1),
          "selected-offline-native-evidence", evidence_lookup=True)
    # Ordering is not authority, and a missing terminal never becomes a zero balance.
    shuffled = deepcopy(bundle)
    shuffled["transactions"].reverse()
    other = replay(descriptor, shuffled, ExistingNativeResults())
    if other["head"] != positive["head"]:
        raise ValueError("row-order-changed-state")
    truncated = deepcopy(bundle)
    truncated["transactions"].pop()
    tail = replay(descriptor, truncated, ExistingNativeResults())
    if not (tail["head"]["reserve_sompi"] == 1000000000 and not tail["completeness"]["terminal"]
            and tail["completeness"]["complete"] is False):
        raise ValueError("truncated-tail-false-zero")
    result = {"classification": "PUBLIC_SYNTHETIC_OFFLINE_PRIVATE_EXIT_RECOVERY_COMPATIBILITY",
              "public_decoder_negative_controls": len(rows), "matched": len(rows), "controls": rows,
              "positive_reused_native_cases": len(evidence.calls), "positive_cm_count": 8, "positive_nf_count": 9,
              "positive_reserve_sompi": 0, "pool_operations": 6, "ordinary_funding_ancestors": 1,
              "unordered_rows_same_state": True, "truncated_tail_returns_nonterminal_not_zero": True,
              "new_native_or_proof_executions": 0, "seed_private_witness_PK_prover_read": False,
              "accepted_chain_backing": False, "network_fetch_or_wallet_support": False, "complete": False}
    save(args.output / "RESULTS.json", result)
    for item in frozen["files"]:
        raw = (ROOT / item["path"]).read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("post-run-frozen-public-artifact-changed")
    print(json.dumps({key: result[key] for key in ("public_decoder_negative_controls", "matched", "positive_cm_count", "positive_nf_count", "positive_reserve_sompi")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", required=True, type=Path)
    parser.add_argument("--reviewed-freeze-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    main(parser.parse_args())
