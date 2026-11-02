#!/usr/bin/env python3
"""Run frozen observer controls without reading private workload or truth."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from observer import enumerate_arm, load, predict


HERE = Path(__file__).resolve().parent
PREVIOUS = HERE.parent / "wallet-local-payment-privacy-2026-11-01" / "run-v2" / "public"
PREVIOUS_MANIFEST_SHA = "ad2e9b18bc11311648ce2ccf5ebfb47595ed147b676e531fd4cdd98ffb63df1c"


def count_signature(result: dict) -> dict:
    signature = {}
    for run in result["runs"]:
        signature[run["run"]] = {}
        for checkpoint, observers in run["checkpoints"].items():
            signature[run["run"]][checkpoint] = {}
            for observer in ("O-public", "O-service"):
                item = observers[observer]
                signature[run["run"]][checkpoint][observer] = {
                    "first": {
                        key: value["count"] if key == "amountSompi" else len(value)
                        for key, value in item["firstPayment"].items()
                        if key not in {"relationship"}
                    },
                    "firstRelationships": len(item["firstPayment"]["relationship"]),
                    "second": None
                    if item["secondPayment"] is None
                    else {
                        key: value["count"] if key == "amountSompi" else len(value)
                        for key, value in item["secondPayment"].items()
                        if key not in {"relationship"}
                    },
                    "secondRelationships": None
                    if item["secondPayment"] is None
                    else len(item["secondPayment"]["relationship"]),
                    "chains": len(item["jointRelationshipChain"]),
                    "complete": item["completeStructuralAssignmentCount"],
                }
    return signature


def rewrite_capture_token(path: Path) -> None:
    capture = load(path)
    capture["request"]["relayToken"] = "irrelevant-renamed-token"
    raw = json.dumps(capture["request"], sort_keys=True, separators=(",", ":")).encode()
    capture["requestRawHex"] = raw.hex()
    capture["requestBytes"] = len(raw)
    capture["requestSha256"] = hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: controls.py PUBLIC_DIR OUTPUT.json")
    public_root = Path(sys.argv[1])
    output = Path(sys.argv[2])
    if output.exists():
        raise SystemExit("control output exists")

    previous_manifest_hash = hashlib.sha256((PREVIOUS / "manifest.json").read_bytes()).hexdigest()
    previous_score = load(PREVIOUS / "score.json")
    previous_amount_unique = all(
        trial["O-public"]["truthUniquelyIdentified"]["paymentSompi"]
        and trial["O-service"]["truthUniquelyIdentified"]["paymentSompi"]
        for trial in previous_score["perTrial"]
    )
    prior_preserved = (
        previous_manifest_hash == PREVIOUS_MANIFEST_SHA
        and previous_score["privacyGatePassed"] is False
        and previous_amount_unique
    )

    original = predict(public_root)
    with tempfile.TemporaryDirectory(prefix="private-spend-alias-") as temp:
        variant_root = Path(temp) / "public"
        shutil.copytree(public_root, variant_root)
        aux = load(variant_root / "auxiliary.json")
        aux["runs"].reverse()
        (variant_root / "auxiliary.json").write_text(
            json.dumps(aux, indent=2, sort_keys=True) + "\n"
        )
        for path in variant_root.glob("pair-*/*/capture-*.json"):
            rewrite_capture_token(path)
        renamed = predict(variant_root)
    alias_order_invariant = count_signature(original) == count_signature(renamed)

    aux_index = load(public_root / "auxiliary.json")
    aux_by_run = {item["run"]: item for item in aux_index["runs"]}
    pair0_aux = aux_by_run["pair-00/continued"]
    mapped = enumerate_arm(public_root / "pair-00" / "continued", pair0_aux)
    unmapped_aux = copy.deepcopy(pair0_aux)
    unmapped_aux["knownExitDestinationIdentity"] = {}
    unmapped = enumerate_arm(public_root / "pair-00" / "continued", unmapped_aux)
    mapped_post = mapped["checkpoints"]["post-cashout"]["O-public"]
    unmapped_post = unmapped["checkpoints"]["post-cashout"]["O-public"]
    mapping_effect = (
        unmapped_post["completeStructuralAssignmentCount"]
        >= mapped_post["completeStructuralAssignmentCount"]
        and len(unmapped_post["jointRelationshipChain"])
        >= len(mapped_post["jointRelationshipChain"])
        and (
            unmapped_post["completeStructuralAssignmentCount"]
            > mapped_post["completeStructuralAssignmentCount"]
            or len(unmapped_post["jointRelationshipChain"])
            > len(mapped_post["jointRelationshipChain"])
        )
    )

    with tempfile.TemporaryDirectory(prefix="private-spend-missing-exit-") as temp:
        variant_arm = Path(temp) / "continued"
        shutil.copytree(public_root / "pair-00" / "continued", variant_arm)
        last_event = sorted(variant_arm.glob("event-*.json"))[-1]
        event = load(last_event)
        (variant_arm / event["capture"]).unlink()
        last_event.unlink()
        missing_exit_invalidated = False
        try:
            enumerate_arm(variant_arm, pair0_aux, strict=True)
        except (ValueError, StopIteration):
            missing_exit_invalidated = True

    score = load(public_root / "score.json")
    truth_retained = all(
        checkpoint[observer]["completeTruthRetained"]
        for run in score["runs"]
        for checkpoint in run["checkpoints"].values()
        for observer in ("O-public", "O-service")
    )
    result = {
        "schema": "wallet-local-private-spend-controls-v1",
        "previousV2ManifestSha256": previous_manifest_hash,
        "previousV2ImmediateExitFailurePreserved": prior_preserved,
        "irrelevantRelayAliasAndAuxOrderInvariant": alias_order_invariant,
        "payoutIdentityRemovalWeaklyIncreasesCandidates": mapping_effect,
        "pair00PostCashoutCompleteAssignments": {
            "withIdentityMappings": mapped_post["completeStructuralAssignmentCount"],
            "withoutIdentityMappings": unmapped_post["completeStructuralAssignmentCount"],
        },
        "pair00PostCashoutRelationshipChains": {
            "withIdentityMappings": len(mapped_post["jointRelationshipChain"]),
            "withoutIdentityMappings": len(unmapped_post["jointRelationshipChain"]),
        },
        "missingEventualExitInvalidatesCoverage": missing_exit_invalidated,
        "allTruthRetained": truth_retained,
    }
    result["allPassed"] = all(
        [prior_preserved, alias_order_invariant, mapping_effect, missing_exit_invalidated, truth_retained]
    )
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["allPassed"]:
        raise SystemExit("one or more observer controls failed")
    print(json.dumps({"output": str(output), "allPassed": True}))


if __name__ == "__main__":
    main()
