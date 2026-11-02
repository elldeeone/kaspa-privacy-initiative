#!/usr/bin/env python3
"""Score sealed shared-ledger predictions against owner-local truth."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


OBSERVERS = ("O-public-known", "O-public-unmapped", "O-service-known", "O-service-unmapped")
QUERY_FIELDS = ("sender", "recipient", "relationship", "amountSompi", "historicalNote", "outputPartition", "logicalSubmitter")


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def contains(descriptor: dict, value: int) -> bool:
    if descriptor["kind"] == "set":
        return value in descriptor["values"]
    return descriptor["minimum"] <= value <= descriptor["maximum"]


def payment_truth(chain: dict, which: str) -> dict:
    transfer = chain["transfers"][0 if which == "firstPayment" else 1]
    if which == "firstPayment":
        sender, recipient = chain["sender"], chain["firstRecipient"]
        amount = chain["p1Sompi"]
        historical = chain["historicalCredit"]
    else:
        sender, recipient = chain["firstRecipient"], chain["secondRecipient"]
        amount = chain["p2Sompi"]
        historical = transfer["inputCommitment"]
    return {
        "sender": sender,
        "recipient": recipient,
        "relationship": {"sender": sender, "recipient": recipient},
        "amountSompi": amount,
        "historicalNote": historical,
        "outputPartition": {
            "paymentOutputIndex": transfer["paymentOutputIndex"],
            "changeOutputIndex": transfer["changeOutputIndex"],
        },
        "logicalSubmitter": sender,
    }


def score_payment(candidates: dict, truth: dict) -> dict:
    counts = {}
    retained = {}
    for field in QUERY_FIELDS:
        if field == "amountSompi":
            counts[field] = candidates[field]["count"]
            retained[field] = contains(candidates[field], truth[field])
        else:
            counts[field] = len(candidates[field])
            retained[field] = truth[field] in candidates[field]
    return {
        "candidateCounts": counts,
        "truthRetained": retained,
        "truthUniquelyIdentified": {field: retained[field] and counts[field] == 1 for field in QUERY_FIELDS},
        "networkEndpointIdentity": "unmeasured",
    }


def score_view(view: dict, truth: dict) -> dict:
    scored_chains = []
    all_retained = True
    gate = True
    for chain_index in (0, 1):
        candidates = view["chains"][chain_index]
        true_chain = truth["chains"][chain_index]
        payments = {}
        for key in ("firstPayment", "secondPayment"):
            payments[key] = score_payment(candidates[key], payment_truth(true_chain, key))
            all_retained &= all(payments[key]["truthRetained"].values())
            gate &= all(count >= 2 for count in payments[key]["candidateCounts"].values())
        scored_chains.append({"chain": chain_index, **payments})
    gate &= all_retained and view["joint"]["topologyCount"] >= 2 and view["joint"]["completeCompatibleHistoryCount"] >= 2
    return {
        "chains": scored_chains,
        "joint": view["joint"],
        "completeTruthRetained": all_retained,
        "privacyGatePassed": gate,
    }


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: score.py PREDICTIONS.json PRIVATE_TRUTH.json RESULT.json")
    predictions_path, truth_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("score output exists")
    predictions = load(predictions_path)
    expected = predictions_path.with_suffix(predictions_path.suffix + ".sha256").read_text().strip()
    actual = hashlib.sha256(canonical(predictions)).hexdigest()
    if actual != expected:
        raise SystemExit("sealed prediction hash mismatch")
    truth = load(truth_path)
    checkpoints = {}
    for checkpoint, views in predictions["checkpoints"].items():
        checkpoints[checkpoint] = {observer: score_view(views[observer], truth) for observer in OBSERVERS}
        checkpoints[checkpoint]["allViewsPrivacyGatePassed"] = all(
            checkpoints[checkpoint][observer]["privacyGatePassed"] for observer in OBSERVERS
        )
    result = {
        "schema": "wallet-local-shared-history-score-v1",
        "experiment": predictions["experiment"],
        "sealedPredictionsCanonicalSha256": actual,
        "privateTruthSha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "privateTruthValuesPublished": False,
        "coverageComplete": predictions["coverage"]["complete"],
        "checkpoints": checkpoints,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "result": str(output),
        "gates": {checkpoint: item["allViewsPrivacyGatePassed"] for checkpoint, item in checkpoints.items()},
    }))


if __name__ == "__main__":
    main()
