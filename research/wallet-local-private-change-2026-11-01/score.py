#!/usr/bin/env python3
"""Score sealed role-conditioned predictions without publishing private truth."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from observer import ARMS, OBSERVERS, canonical


BASE_FIELDS = (
    "originalFunder",
    "firstRecipient",
    "secondRecipient",
    "firstRelationship",
    "onwardRelationship",
    "earlierReceivedAmountSompi",
    "onwardPaymentAmountSompi",
    "historicalFundingNote",
    "onwardHistoricalInput",
    "originalFirstOutputPartition",
    "originalOnwardOutputPartition",
    "originalTransferPositionPair",
)


def load(path: Path):
    return json.loads(path.read_text())


def contains(item: dict, value) -> bool:
    if item["kind"] == "set":
        return value in item["values"]
    if item["kind"] == "integer-interval-union":
        return any(part["minimum"] <= value <= part["maximum"] for part in item["ranges"])
    raise ValueError("descriptor")


def chain_truth(chain: dict):
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
        "originalFirstOutputPartition": {
            "paymentOutputIndex": first["paymentOutputIndex"],
            "changeOutputIndex": first["changeOutputIndex"],
        },
        "originalOnwardOutputPartition": {
            "paymentOutputIndex": onward["paymentOutputIndex"],
            "changeOutputIndex": onward["changeOutputIndex"],
        },
        "originalTransferPositionPair": {
            "firstTransferOrdinal": first["eventOrdinal"],
            "onwardTransferOrdinal": onward["eventOrdinal"],
        },
    }


def exit_truth(arm_truth: dict, chain: int, role: str, phase: str):
    matches = [item for item in arm_truth["exits"] if item["chain"] == chain and item["role"] == role and item["phase"] == phase]
    if len(matches) != 1:
        raise ValueError("exit truth role")
    return matches[0]


def split_truth(arm_truth: dict, chain: int, role: str):
    matches = [item for item in arm_truth["splits"] if item["chain"] == chain and item["role"] == role]
    if len(matches) != 1:
        raise ValueError("split truth role")
    return matches[0]


def score_one(candidates: dict, arm_truth: dict, chain_index: int, arm: str, checkpoint: str):
    actual = chain_truth(arm_truth["chains"][chain_index])
    retained = {field: contains(candidates[field], actual[field]) for field in BASE_FIELDS}
    extra = {}
    if arm == ARMS[1] and checkpoint != "pre-withdrawal" and chain_index == arm_truth["targetChain"]:
        payment_split = split_truth(arm_truth, chain_index, "secondPayment")
        change_split = split_truth(arm_truth, chain_index, "secondChange")
        extra["splitHistoricalInput"] = (
            contains(candidates["splitHistoricalInput"], payment_split["inputCommitment"])
            and contains(candidates["splitHistoricalInput"], change_split["inputCommitment"])
        )
        extra["splitOutputPartition"] = (
            contains(candidates["splitOutputPartition"], {
                "requestedOutputIndex": payment_split["withdrawalOutputIndex"],
                "changeOutputIndex": payment_split["changeOutputIndex"],
            })
            and contains(candidates["splitOutputPartition"], {
                "requestedOutputIndex": change_split["withdrawalOutputIndex"],
                "changeOutputIndex": change_split["changeOutputIndex"],
            })
        )
        extra["splitEventOrdinal"] = (
            contains(candidates["splitEventOrdinal"], payment_split["eventOrdinal"])
            and contains(candidates["splitEventOrdinal"], change_split["eventOrdinal"])
        )
        split_values = candidates["splitValues"]
        extra["requestedSplitValues"] = (
            contains(split_values["secondRecipientRequestedSompi"], payment_split["requestedSompi"])
            and contains(split_values["firstRecipientRequestedSompi"], change_split["requestedSompi"])
        )
        if checkpoint in {"remainder-withdrawal", "full-drainage"}:
            extra["remainderSplitValues"] = (
                contains(split_values["secondRecipientRemainderSompi"], payment_split["remainderSompi"])
                and contains(split_values["firstRecipientRemainderSompi"], change_split["remainderSompi"])
            )
    exit_retained = {}
    if candidates["exitRole"].get("status") not in {"not-observed-at-checkpoint", "full-note exits in final drainage"}:
        requested_payment = exit_truth(arm_truth, chain_index, "secondPayment", "requested")
        requested_change = exit_truth(arm_truth, chain_index, "secondChange", "requested")
        exit_retained["requestedExitRoles"] = (
            contains(candidates["exitRole"]["secondRecipientRequestedExitOrdinal"], requested_payment["payout"]["ordinal"])
            and contains(candidates["exitRole"]["firstRecipientRequestedExitOrdinal"], requested_change["payout"]["ordinal"])
        )
        if arm == ARMS[1] and checkpoint in {"remainder-withdrawal", "full-drainage"}:
            remainder_payment = exit_truth(arm_truth, chain_index, "secondPayment", "remainder")
            remainder_change = exit_truth(arm_truth, chain_index, "secondChange", "remainder")
            exit_retained["remainderExitRoles"] = (
                contains(candidates["exitRole"]["secondRecipientRemainderExitOrdinal"], remainder_payment["payout"]["ordinal"])
                and contains(candidates["exitRole"]["firstRecipientRemainderExitOrdinal"], remainder_change["payout"]["ordinal"])
            )
    counts = {field: candidates[field]["count"] for field in BASE_FIELDS}
    for field in ("splitHistoricalInput", "splitOutputPartition", "splitEventOrdinal"):
        if "count" in candidates[field]:
            counts[field] = candidates[field]["count"]
    return {
        "candidateCounts": counts,
        "properties": candidates["properties"],
        "truthRetained": retained,
        "changedPathTruthRetained": extra,
        "exitRoleTruthRetained": exit_retained,
        "allTruthRetained": all(retained.values()) and all(extra.values()) and all(exit_retained.values()),
        "privateTruthValuesPublished": False,
    }


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: score.py PREDICTIONS.json PRIVATE_TRUTH_INDEX.json OUTPUT.json")
    predictions_path, truth_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    predictions = load(predictions_path)
    sealed = predictions_path.with_suffix(predictions_path.suffix + ".sha256").read_text().strip()
    if hashlib.sha256(canonical(predictions)).hexdigest() != sealed:
        raise SystemExit("prediction seal mismatch")
    truth_index = load(truth_path)
    truth_by_arm = {item["arm"]: item for item in truth_index["arms"]}
    scored_arms = {}
    for arm in ARMS:
        truth = truth_by_arm[arm]
        checkpoints = {}
        for checkpoint, views in predictions["arms"][arm]["checkpoints"].items():
            checkpoints[checkpoint] = {}
            for observer_name in OBSERVERS:
                view = views[observer_name]
                if checkpoint == "pre-withdrawal":
                    roles = {"anyPaymentChain": [0, 1]}
                else:
                    target = truth["targetChain"]
                    roles = {"withdrawingChain": [target], "unrelatedChain": [1 - target]}
                role_scores = {
                    role: {
                        "actualChainChecks": [score_one(view[role], truth, chain, arm, checkpoint) for chain in chains]
                    }
                    for role, chains in roles.items()
                }
                for role in role_scores.values():
                    role["allTruthRetained"] = all(item["allTruthRetained"] for item in role["actualChainChecks"])
                checkpoints[checkpoint][observer_name] = {
                    "roles": role_scores,
                    "allTruthRetained": all(role["allTruthRetained"] for role in role_scores.values()),
                    "hiddenChainLabelsUsedAsPrivacyMetric": False,
                }
        scored_arms[arm] = {"checkpoints": checkpoints}
    all_retained = all(
        view["allTruthRetained"]
        for arm in scored_arms.values()
        for checkpoint in arm["checkpoints"].values()
        for view in checkpoint.values()
    )
    comparison = predictions["requestedWithdrawalComparison"]
    result = {
        "schema": "wallet-local-private-change-score-v1",
        "experiment": predictions["experiment"],
        "sealedPredictionsCanonicalSha256": sealed,
        "privateTruthSha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "privateTruthValuesPublished": False,
        "arms": scored_arms,
        "allTruthRetained": all_retained,
        "requestedWithdrawalAmountImprovementPassed": all(
            item["P1StrictlyImproved"] and item["P2StrictlyImproved"] for item in comparison.values()
        ),
        "propertySpecificConclusion": "amount unlinkability improves at requested withdrawal; relationship, origin, grouping, and position are reported independently",
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(output), "allTruthRetained": all_retained, "amountImprovement": result["requestedWithdrawalAmountImprovementPassed"]}))


if __name__ == "__main__":
    main()
