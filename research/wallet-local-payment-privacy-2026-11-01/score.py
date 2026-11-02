#!/usr/bin/env python3
"""Score sealed observer predictions against owner-local truth."""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def score_candidates(candidates: dict, truth: dict) -> dict:
    true_partition = {
        "paymentOutputIndex": truth["paymentOutputIndex"],
        "changeOutputIndex": truth["changeOutputIndex"],
    }
    true_assignment = {
        "sender": truth["sender"],
        "recipient": truth["recipient"],
        "paymentSompi": truth["paymentSompi"],
        "historicalNote": truth["historicalNote"],
        **true_partition,
    }
    true_items = {
        "sender": truth["sender"],
        "recipient": truth["recipient"],
        "paymentSompi": truth["paymentSompi"],
        "historicalNote": truth["historicalNote"],
        "outputPartition": true_partition,
        "completeAssignment": true_assignment,
    }
    counts = {key: len(value) for key, value in candidates.items()}
    retained = {key: value in candidates[key] for key, value in true_items.items()}
    unique = {
        key: retained[key] and counts[key] == 1 for key in true_items
    }
    return {"candidateCounts": counts, "truthRetained": retained, "truthUniquelyIdentified": unique}


def aggregate(per_trial: list[dict], observer: str) -> dict:
    keys = [
        "sender",
        "recipient",
        "paymentSompi",
        "historicalNote",
        "outputPartition",
        "completeAssignment",
    ]
    return {
        key: {
            "minimum": min(item[observer]["candidateCounts"][key] for item in per_trial),
            "median": statistics.median(
                item[observer]["candidateCounts"][key] for item in per_trial
            ),
            "maximum": max(item[observer]["candidateCounts"][key] for item in per_trial),
            "truthRetainedAll": all(
                item[observer]["truthRetained"][key] for item in per_trial
            ),
            "uniqueIdentificationCount": sum(
                item[observer]["truthUniquelyIdentified"][key] for item in per_trial
            ),
        }
        for key in keys
    }


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: score.py PREDICTIONS.json PRIVATE_TRUTH_DIR RESULT.json")
    predictions_path = Path(sys.argv[1])
    truth_root = Path(sys.argv[2])
    output = Path(sys.argv[3])
    if output.exists():
        raise SystemExit("score output already exists")
    predictions = load(predictions_path)
    expected_hash = predictions_path.with_suffix(predictions_path.suffix + ".sha256").read_text().strip()
    actual_hash = hashlib.sha256(canonical(predictions)).hexdigest()
    if actual_hash != expected_hash:
        raise SystemExit("sealed predictions hash mismatch")
    truths = load(truth_root / "truth-index.json")["trials"]
    truth_by_trial = {truth["trial"]: truth for truth in truths}
    per_trial = []
    for predicted in predictions["trials"]:
        truth = truth_by_trial[predicted["trial"]]
        item = {
            "trial": predicted["trial"],
            "coverageComplete": predicted["coverage"]["complete"],
            "O-public": score_candidates(predicted["O-public"], truth),
            "O-service": score_candidates(predicted["O-service"], truth),
        }
        per_trial.append(item)
    privacy_gate = all(
        item[observer]["truthRetained"][key]
        and item[observer]["candidateCounts"][key] >= 2
        for item in per_trial
        for observer in ("O-public", "O-service")
        for key in ("sender", "recipient", "paymentSompi", "historicalNote", "outputPartition")
    ) and all(
        item[observer]["candidateCounts"]["completeAssignment"] >= 2
        for item in per_trial
        for observer in ("O-public", "O-service")
    )
    result = {
        "schema": "wallet-local-privacy-score-v1",
        "experiment": predictions["experiment"],
        "sealedPredictionsCanonicalSha256": actual_hash,
        "truthFileSha256": hashlib.sha256((truth_root / "truth-index.json").read_bytes()).hexdigest(),
        "privateTruthValuesPublished": False,
        "trialCount": len(per_trial),
        "perTrial": per_trial,
        "aggregate": {
            observer: aggregate(per_trial, observer)
            for observer in ("O-public", "O-service")
        },
        "privacyGatePassed": privacy_gate,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": str(output), "privacyGatePassed": privacy_gate}))


if __name__ == "__main__":
    main()
