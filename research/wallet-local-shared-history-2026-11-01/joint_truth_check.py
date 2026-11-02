#!/usr/bin/env python3
"""Post-seal check that the exact coupled history survived joint enumeration.

This publishes booleans and hashes only. It does not alter frozen candidates,
counts, thresholds, or the sealed scorer.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import observer


OBSERVERS = ("O-public-known", "O-public-unmapped", "O-service-known", "O-service-unmapped")


def load(path: Path):
    return json.loads(path.read_text())


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: joint_truth_check.py PUBLIC_DIR PRIVATE_TRUTH.json OUTPUT.json")
    public_root, truth_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    predictions = load(public_root / "PREDICTIONS.json")
    sealed = (public_root / "PREDICTIONS.json.sha256").read_text().strip()
    if hashlib.sha256(observer.canonical(predictions)).hexdigest() != sealed:
        raise SystemExit("predictions are not sealed")
    truth = load(truth_path)
    _, aux, events = observer.load_public(public_root)
    _, _, exits = observer.public_material(aux, events)

    topology = [
        {
            "chain": chain["chain"],
            "sender": chain["sender"],
            "firstRecipient": chain["firstRecipient"],
            "secondRecipient": chain["secondRecipient"],
        }
        for chain in truth["chains"]
    ]
    schedule = tuple(
        chain_index
        for _, chain_index in sorted(
            (transfer["eventOrdinal"], chain["chain"])
            for chain in truth["chains"]
            for transfer in chain["transfers"]
        )
    )
    target_payment_ordinal = next(
        item["payout"]["ordinal"]
        for item in truth["exits"]
        if item["chain"] == truth["targetChain"] and item["role"] == "secondPayment"
    )
    true_roles = []
    for chain_index in (0, 1):
        true_roles.append({
            item["role"]: index
            for index, item in enumerate(truth["exits"])
            if item["chain"] == chain_index
        })

    results = {}
    for observer_name in OBSERVERS:
        known = observer_name.endswith("-known")
        pre = observer.pre_records()
        target = observer.target_records(exits, aux, known)
        full = observer.full_records(exits, aux, known)
        results[observer_name] = {
            "transferScheduleRetained": schedule in observer.schedules(),
            "preCashoutCoupledTruthRetained": any(record["chains"] == topology for record in pre),
            "targetCashoutCoupledTruthRetained": any(
                record["chains"] == topology
                and record["targetChain"] == truth["targetChain"]
                and record["targetP1"] == truth["chains"][truth["targetChain"]]["p1Sompi"]
                and record["targetP2"] == truth["chains"][truth["targetChain"]]["p2Sompi"]
                and record["targetPaymentExitOrdinal"] == target_payment_ordinal
                for record in target
            ),
            "fullCashoutCoupledTruthRetained": any(
                record["chains"] == topology
                and list(record["amounts"]) == [
                    (truth["chains"][0]["p1Sompi"], truth["chains"][0]["p2Sompi"]),
                    (truth["chains"][1]["p1Sompi"], truth["chains"][1]["p2Sompi"]),
                ]
                and list(record["roleAssignments"]) == true_roles
                for record in full
            ),
        }
    all_passed = all(all(items.values()) for items in results.values())
    result = {
        "schema": "wallet-local-shared-history-joint-truth-check-v1",
        "sealedPredictionsCanonicalSha256": sealed,
        "privateTruthSha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "privateTruthValuesPublished": False,
        "views": results,
        "allPassed": all_passed,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not all_passed:
        raise SystemExit("coupled truth did not survive enumeration")
    print(json.dumps({"output": str(output), "allPassed": True}))


if __name__ == "__main__":
    main()
