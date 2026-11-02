#!/usr/bin/env python3
"""Score post-hoc role-conditioned predictions without publishing truth values."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from observer_correction_v2 import canonical


OBSERVERS = ("O-public-known", "O-public-unmapped", "O-service-known", "O-service-unmapped")
FIELDS = (
    "originalFunder",
    "firstRecipient",
    "secondRecipient",
    "firstRelationship",
    "onwardRelationship",
    "earlierReceivedAmountSompi",
    "onwardPaymentAmountSompi",
    "historicalFundingNote",
    "onwardHistoricalInput",
    "firstPaymentOutputPartition",
    "onwardPaymentOutputPartition",
    "transferPositionPair",
    "firstTransferOrdinal",
    "onwardTransferOrdinal",
)


def load(path: Path):
    return json.loads(path.read_text())


def contains(descriptor: dict, value) -> bool:
    if descriptor["kind"] == "set":
        return value in descriptor["values"]
    if descriptor["kind"] == "integer-interval-union":
        return any(item["minimum"] <= value <= item["maximum"] for item in descriptor["ranges"])
    raise ValueError("unknown descriptor")


def truth_for_chain(chain: dict) -> dict:
    first, onward = chain["transfers"]
    return {
        "originalFunder": chain["sender"],
        "firstRecipient": chain["firstRecipient"],
        "secondRecipient": chain["secondRecipient"],
        "firstRelationship": {"sender": chain["sender"], "recipient": chain["firstRecipient"]},
        "onwardRelationship": {"sender": chain["firstRecipient"], "recipient": chain["secondRecipient"]},
        "earlierReceivedAmountSompi": chain["p1Sompi"],
        "onwardPaymentAmountSompi": chain["p2Sompi"],
        "historicalFundingNote": chain["historicalCredit"],
        "onwardHistoricalInput": onward["inputCommitment"],
        "firstPaymentOutputPartition": {
            "paymentOutputIndex": first["paymentOutputIndex"],
            "changeOutputIndex": first["changeOutputIndex"],
        },
        "onwardPaymentOutputPartition": {
            "paymentOutputIndex": onward["paymentOutputIndex"],
            "changeOutputIndex": onward["changeOutputIndex"],
        },
        "transferPositionPair": {
            "firstTransferOrdinal": first["eventOrdinal"],
            "onwardTransferOrdinal": onward["eventOrdinal"],
        },
        "firstTransferOrdinal": first["eventOrdinal"],
        "onwardTransferOrdinal": onward["eventOrdinal"],
    }


def score_role(candidates: dict, truth: dict, chain_indices: list[int]) -> dict:
    per_actual_chain = []
    for chain_index in chain_indices:
        actual = truth_for_chain(truth["chains"][chain_index])
        retained = {field: contains(candidates[field], actual[field]) for field in FIELDS}
        joint_retained = {}
        if "withdrawalLinkedTuple" in candidates:
            joint_retained["withdrawalLinkedTuple"] = contains(
                candidates["withdrawalLinkedTuple"],
                {
                    "firstRecipient": actual["firstRecipient"],
                    "secondRecipient": actual["secondRecipient"],
                    "earlierReceivedAmountSompi": actual["earlierReceivedAmountSompi"],
                    "onwardPaymentAmountSompi": actual["onwardPaymentAmountSompi"],
                },
            )
            joint_retained["endToEndTuple"] = contains(
                candidates["endToEndTuple"],
                {
                    "originalFunder": actual["originalFunder"],
                    "firstRecipient": actual["firstRecipient"],
                    "secondRecipient": actual["secondRecipient"],
                    "earlierReceivedAmountSompi": actual["earlierReceivedAmountSompi"],
                    "onwardPaymentAmountSompi": actual["onwardPaymentAmountSompi"],
                },
            )
        exit_retained = {}
        if candidates["exitRole"].get("status") != "not-observed-at-checkpoint":
            for role, field in (
                ("secondPayment", "secondPaymentExitOrdinal"),
                ("secondChange", "firstRecipientChangeExitOrdinal"),
            ):
                ordinal = next(
                    item["payout"]["ordinal"]
                    for item in truth["exits"]
                    if item["chain"] == chain_index and item["role"] == role
                )
                exit_retained[field] = contains(candidates["exitRole"][field], ordinal)
        per_actual_chain.append({
            "actualChainTruthValuesPublished": False,
            "truthRetained": retained,
            "jointTruthRetained": joint_retained,
            "exitRoleTruthRetained": exit_retained,
            "allTruthRetained": all(retained.values()) and all(joint_retained.values()) and all(exit_retained.values()),
        })
    counts = {field: candidates[field]["count"] for field in FIELDS}
    if candidates["exitRole"].get("status") != "not-observed-at-checkpoint":
        counts.update({field: descriptor["count"] for field, descriptor in candidates["exitRole"].items()})
    return {
        "candidateCounts": counts,
        "properties": candidates["properties"],
        "actualChainChecks": per_actual_chain,
        "allTruthRetained": all(item["allTruthRetained"] for item in per_actual_chain),
    }


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: score_correction_v2.py PREDICTIONS.json PRIVATE_TRUTH.json OUTPUT.json")
    predictions_path, truth_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    predictions = load(predictions_path)
    sealed = predictions_path.with_suffix(predictions_path.suffix + ".sha256").read_text().strip()
    if hashlib.sha256(canonical(predictions)).hexdigest() != sealed:
        raise SystemExit("prediction seal mismatch")
    truth = load(truth_path)
    checkpoints = {}
    for checkpoint, views in predictions["checkpoints"].items():
        checkpoints[checkpoint] = {}
        for observer_name in OBSERVERS:
            view = views[observer_name]
            if checkpoint == "pre-cashout":
                roles = {"anyPaymentChain": [0, 1]}
            else:
                target = truth["targetChain"]
                roles = {"withdrawingChain": [target], "unrelatedChain": [1 - target]}
            scored_roles = {
                role: score_role(view[role], truth, indices) for role, indices in roles.items()
            }
            checkpoints[checkpoint][observer_name] = {
                "roles": scored_roles,
                "allTruthRetained": all(item["allTruthRetained"] for item in scored_roles.values()),
                "hiddenChainLabelsUsedAsPrivacyMetric": False,
            }
    result = {
        "schema": "wallet-local-shared-history-posthoc-correction-score-v2",
        "experiment": predictions["experiment"],
        "status": predictions["status"],
        "sealedCorrectionPredictionsCanonicalSha256": sealed,
        "privateTruthSha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "privateTruthValuesPublished": False,
        "checkpoints": checkpoints,
        "correctedHeadline": {
            "preCashout": "queried facts remain ambiguous under admitted evidence",
            "targetCashout": "mixed and insufficient for full payment privacy; exact facts are reported per property",
            "fullCashout": "fails for payment amounts and original funding origins; residual grouping and position ambiguity remains",
            "legacyTargetCashoutBlanketPassValid": False,
        },
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(output), "truthRetained": all(
        item["allTruthRetained"]
        for checkpoint in checkpoints.values()
        for item in checkpoint.values()
    )}))


if __name__ == "__main__":
    main()
