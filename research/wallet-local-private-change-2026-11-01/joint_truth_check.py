#!/usr/bin/env python3
"""Post-seal boolean check that exact coupled histories survived enumeration."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import observer


def load(path: Path):
    return json.loads(path.read_text())


def topology_truth(truth):
    return [
        {
            "chain": item["chain"],
            "sender": item["sender"],
            "firstRecipient": item["firstRecipient"],
            "secondRecipient": item["secondRecipient"],
        }
        for item in truth["chains"]
    ]


def exit_index_map(truth, phase: str, offset: int):
    items = [item for item in truth["exits"] if item["phase"] == phase]
    return {(item["chain"], item["role"]): item["payout"]["ordinal"] - offset for item in items}


def requested_region_contains(record, truth):
    chain = truth["chains"][truth["targetChain"]]
    region = record["region"]
    return (
        region["p1Minimum"] <= chain["p1Sompi"] <= region["p1Maximum"]
        and region["p2Minimum"] <= chain["p2Sompi"] <= region["p2Maximum"]
        and chain["p2Sompi"] <= chain["p1Sompi"] - region["secondChangeMinimum"]
    )


def record_matches(arm, checkpoint, record, truth):
    topology = topology_truth(truth)
    if record["topology"] != topology:
        return False
    if checkpoint == "pre-withdrawal":
        return True
    target = truth["targetChain"]
    if record["target"] != target:
        return False
    chains = truth["chains"]
    if arm == observer.ARMS[0]:
        requested = exit_index_map(truth, "requested", 8)
        if record["secondPaymentExitOrdinal"] != requested[(target, "secondPayment")] + 8:
            return False
        if record["secondChangeExitOrdinal"] != requested[(target, "secondChange")] + 8:
            return False
        if record["amounts"][target] != (chains[target]["p1Sompi"], chains[target]["p2Sompi"]):
            return False
        if checkpoint == "full-drainage":
            if any(record["amounts"][index] != (chains[index]["p1Sompi"], chains[index]["p2Sompi"]) for index in (0, 1)):
                return False
            full_map = exit_index_map(truth, "requested", 8) | exit_index_map(truth, "final", 8)
            if any(record["exitAssignments"][chain][role] != index for (chain, role), index in full_map.items()):
                return False
        return True

    splits = {item["role"]: item for item in truth["splits"]}
    requested = {item["role"]: item for item in truth["exits"] if item["phase"] == "requested"}
    if record["requestedSecondPayment"] != splits["secondPayment"]["requestedSompi"]:
        return False
    if record["requestedSecondChange"] != splits["secondChange"]["requestedSompi"]:
        return False
    if record["secondPaymentExitOrdinal"] != requested["secondPayment"]["payout"]["ordinal"]:
        return False
    if record["secondChangeExitOrdinal"] != requested["secondChange"]["payout"]["ordinal"]:
        return False
    if checkpoint == "requested-withdrawal":
        return requested_region_contains(record, truth)
    remainder = {item["role"]: item for item in truth["exits"] if item["phase"] == "remainder"}
    if record["remainderSecondPayment"] != splits["secondPayment"]["remainderSompi"]:
        return False
    if record["remainderSecondChange"] != splits["secondChange"]["remainderSompi"]:
        return False
    if record["secondPaymentRemainderExitOrdinal"] != remainder["secondPayment"]["payout"]["ordinal"]:
        return False
    if record["secondChangeRemainderExitOrdinal"] != remainder["secondChange"]["payout"]["ordinal"]:
        return False
    if record["amounts"][target] != (chains[target]["p1Sompi"], chains[target]["p2Sompi"]):
        return False
    if checkpoint == "full-drainage":
        if any(record["amounts"][index] != (chains[index]["p1Sompi"], chains[index]["p2Sompi"]) for index in (0, 1)):
            return False
        final_map = exit_index_map(truth, "final", 14)
        if any(record["finalAssignments"][(chain, role)] != index for (chain, role), index in final_map.items()):
            return False
    return True


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: joint_truth_check.py PUBLIC_DIR PREDICTIONS.json PRIVATE_TRUTH OUTPUT.json")
    public_root, predictions_path, truth_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    predictions = load(predictions_path)
    seal = predictions_path.with_suffix(predictions_path.suffix + ".sha256").read_text().strip()
    if hashlib.sha256(observer.canonical(predictions)).hexdigest() != seal:
        raise SystemExit("predictions not sealed")
    truths = {item["arm"]: item for item in load(truth_path)["arms"]}
    results = {}
    for arm in observer.ARMS:
        _, aux, _, _, _, _, exits = observer.load_arm(public_root, arm)
        results[arm] = {}
        for checkpoint in ("pre-withdrawal", "requested-withdrawal", "remainder-withdrawal", "full-drainage"):
            results[arm][checkpoint] = {}
            for observer_name in observer.OBSERVERS:
                known = observer_name.endswith("-known")
                records = observer.arm_records(arm, checkpoint, exits, aux, known)
                results[arm][checkpoint][observer_name] = any(
                    record_matches(arm, checkpoint, record, truths[arm]) for record in records
                )
    passed = all(
        retained
        for arm in results.values()
        for checkpoint in arm.values()
        for retained in checkpoint.values()
    )
    result = {
        "schema": "wallet-local-private-change-joint-truth-check-v1",
        "sealedPredictionsCanonicalSha256": seal,
        "privateTruthSha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "privateTruthValuesPublished": False,
        "retained": results,
        "allPassed": passed,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not passed:
        raise SystemExit("coupled truth was not retained")
    print(json.dumps({"output": str(output), "allPassed": True}))


if __name__ == "__main__":
    main()
