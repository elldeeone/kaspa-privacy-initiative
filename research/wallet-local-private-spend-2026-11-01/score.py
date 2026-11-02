#!/usr/bin/env python3
"""Score sealed joint predictions without publishing private truth values."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def amount_count(descriptor: dict) -> int:
    return descriptor["count"]


def amount_contains(descriptor: dict, value: int) -> bool:
    if descriptor["kind"] == "set":
        return value in descriptor["values"]
    return descriptor["minimum"] <= value <= descriptor["maximum"]


def payment_truth(truth: dict, key: str) -> dict | None:
    item = truth[key]
    if item is None:
        return None
    return {
        "sender": item["sender"],
        "recipient": item["recipient"],
        "amountSompi": item["amountSompi"],
        "historicalNote": item["historicalCredit"] if key == "firstPayment" else item["historicalOutput"],
        "outputPartition": {
            "paymentOutputIndex": item["paymentOutputIndex"],
            "changeOutputIndex": item["changeOutputIndex"],
        },
        "endpointIdentity": item["sender"],
        "relationship": {"sender": item["sender"], "recipient": item["recipient"]},
    }


def score_payment(candidates: dict, truth: dict) -> dict:
    counts = {
        "sender": len(candidates["sender"]),
        "recipient": len(candidates["recipient"]),
        "amountSompi": amount_count(candidates["amountSompi"]),
        "historicalNote": len(candidates["historicalNote"]),
        "outputPartition": len(candidates["outputPartition"]),
        "endpointIdentity": len(candidates["endpointIdentity"]),
        "relationship": len(candidates["relationship"]),
    }
    retained = {
        "sender": truth["sender"] in candidates["sender"],
        "recipient": truth["recipient"] in candidates["recipient"],
        "amountSompi": amount_contains(candidates["amountSompi"], truth["amountSompi"]),
        "historicalNote": truth["historicalNote"] in candidates["historicalNote"],
        "outputPartition": truth["outputPartition"] in candidates["outputPartition"],
        "endpointIdentity": truth["endpointIdentity"] in candidates["endpointIdentity"],
        "relationship": truth["relationship"] in candidates["relationship"],
    }
    unique = {key: retained[key] and counts[key] == 1 for key in counts}
    return {"candidateCounts": counts, "truthRetained": retained, "truthUniquelyIdentified": unique}


def score_checkpoint(candidates: dict, truth: dict) -> dict:
    first_truth = payment_truth(truth, "firstPayment")
    second_truth = payment_truth(truth, "secondPayment")
    first = score_payment(candidates["firstPayment"], first_truth)
    second = (
        score_payment(candidates["secondPayment"], second_truth)
        if candidates["secondPayment"] is not None
        else None
    )
    true_chain = {
        "firstSender": first_truth["sender"],
        "firstRecipient": first_truth["recipient"],
    }
    if second_truth is not None:
        true_chain["secondRecipient"] = second_truth["recipient"]
    chain_count = len(candidates["jointRelationshipChain"])
    chain_retained = true_chain in candidates["jointRelationshipChain"]
    all_retained = all(first["truthRetained"].values()) and (
        second is None or all(second["truthRetained"].values())
    ) and chain_retained
    return {
        "firstPayment": first,
        "secondPayment": second,
        "jointRelationshipChain": {
            "candidateCount": chain_count,
            "truthRetained": chain_retained,
            "truthUniquelyIdentified": chain_retained and chain_count == 1,
        },
        "completeStructuralAssignmentCount": candidates["completeStructuralAssignmentCount"],
        "completeTruthRetained": all_retained,
    }


def privacy_gate(scored: dict) -> bool:
    for observer in ("O-public", "O-service"):
        item = scored[observer]
        for payment in (item["firstPayment"], item["secondPayment"]):
            if payment is None:
                continue
            if not all(payment["truthRetained"].values()):
                return False
            if any(count < 2 for count in payment["candidateCounts"].values()):
                return False
        if item["jointRelationshipChain"]["candidateCount"] < 2:
            return False
        if not item["completeTruthRetained"]:
            return False
    return True


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: score.py PREDICTIONS.json PRIVATE_TRUTH_DIR RESULT.json")
    predictions_path = Path(sys.argv[1])
    truth_root = Path(sys.argv[2])
    output = Path(sys.argv[3])
    if output.exists():
        raise SystemExit("score output exists")
    predictions = load(predictions_path)
    sealed = predictions_path.with_suffix(predictions_path.suffix + ".sha256").read_text().strip()
    digest = hashlib.sha256(canonical(predictions)).hexdigest()
    if digest != sealed:
        raise SystemExit("sealed prediction hash mismatch")
    truth_path = truth_root / "truth-index.json"
    truths = {f"{item['pair']}/{item['arm']}": item for item in load(truth_path)["runs"]}
    scored_runs = []
    for predicted in predictions["runs"]:
        truth = truths[predicted["run"]]
        checkpoints = {}
        for checkpoint, by_observer in predicted["checkpoints"].items():
            checkpoints[checkpoint] = {
                observer: score_checkpoint(by_observer[observer], truth)
                for observer in ("O-public", "O-service")
            }
            checkpoints[checkpoint]["privacyGatePassed"] = privacy_gate(
                checkpoints[checkpoint]
            )
        scored_runs.append(
            {
                "run": predicted["run"],
                "pair": predicted["pair"],
                "arm": predicted["arm"],
                "coverageComplete": predicted["coverage"]["complete"],
                "checkpoints": checkpoints,
            }
        )
    continued = [item for item in scored_runs if item["arm"] == "continued"]
    result = {
        "schema": "wallet-local-private-spend-score-v1",
        "experiment": predictions["experiment"],
        "sealedPredictionsCanonicalSha256": digest,
        "truthFileSha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "privateTruthValuesPublished": False,
        "runs": scored_runs,
        "continuedPrivatePreCashoutGatePassed": all(
            item["checkpoints"]["pre-cashout"]["privacyGatePassed"] for item in continued
        ),
        "continuedPrivatePostCashoutGatePassed": all(
            item["checkpoints"]["post-cashout"]["privacyGatePassed"] for item in continued
        ),
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "result": str(output),
                "preCashout": result["continuedPrivatePreCashoutGatePassed"],
                "postCashout": result["continuedPrivatePostCashoutGatePassed"],
            }
        )
    )


if __name__ == "__main__":
    main()
