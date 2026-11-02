#!/usr/bin/env python3
"""Post-hoc, label-invariant reassessment of the existing public run.

This does not replace the frozen v1 observer. It reprojects the same compatible
histories onto observable roles instead of hidden internal chain slots.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import observer as base


ORIGINAL_MANIFEST_SHA = "1a9463269ef5647a1ce22b0af6b8e2121f236950fe2333873107c204f49677d9"
ORIGINAL_PREDICTIONS_SHA = "e006e033117e076b83e1cf57447ab6c624d6ebfa772c725a3aedcdafebe98863"
ORIGINAL_SCORE_SHA = "2c7c1d43acdeb9953488ce198943b234180a4be4bf61343017accfa669e7d64a"
OBSERVERS = ("O-public-known", "O-public-unmapped", "O-service-known", "O-service-unmapped")
PARTITIONS = (
    {"paymentOutputIndex": 0, "changeOutputIndex": 1},
    {"paymentOutputIndex": 1, "changeOutputIndex": 0},
)
POSITION_PAIRS = tuple(
    {"firstTransferOrdinal": first + 4, "onwardTransferOrdinal": second + 4}
    for first in range(4)
    for second in range(first + 1, 4)
)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def descriptor(values) -> dict:
    unique = sorted(set(values))
    return {"kind": "set", "values": unique, "count": len(unique)}


def object_descriptor(values) -> dict:
    unique = base.dedupe(list(values))
    return {"kind": "set", "values": unique, "count": len(unique)}


def interval_union(ranges) -> dict:
    ordered = sorted(set(ranges))
    merged: list[list[int]] = []
    for low, high in ordered:
        if not merged or low > merged[-1][1] + 1:
            merged.append([low, high])
        else:
            merged[-1][1] = max(merged[-1][1], high)
    return {
        "kind": "integer-interval-union",
        "ranges": [{"minimum": low, "maximum": high} for low, high in merged],
        "count": sum(high - low + 1 for low, high in merged),
    }


def policy_amount(chain: int, which: str) -> tuple[int, int]:
    policy = base.CHAIN_POLICY[chain]
    if which == "p1":
        return policy["p1"]
    return policy["p2min"], policy["p1"][1] - policy["p2min"]


def full_target_chain(record: dict) -> int:
    candidates = [
        index
        for index, roles in enumerate(record["roleAssignments"])
        if {roles["secondPayment"], roles["secondChange"]} == {0, 1}
    ]
    if len(candidates) != 1:
        raise ValueError("full-cashout target chain is not unique")
    return candidates[0]


def selected_indices(checkpoint: str, record: dict, role: str) -> list[int]:
    if checkpoint == "pre-cashout":
        if role != "anyPaymentChain":
            raise ValueError("pre-cashout role")
        return [0, 1]
    target = record["targetChain"] if checkpoint == "target-cashout" else full_target_chain(record)
    if role == "withdrawingChain":
        return [target]
    if role == "unrelatedChain":
        return [1 - target]
    raise ValueError("cashout role")


def role_rows(checkpoint: str, records: list[dict], role: str):
    return [(record, index, record["chains"][index]) for record in records for index in selected_indices(checkpoint, record, role)]


def amount_candidates(checkpoint: str, role: str, rows, which: str) -> dict:
    amount_index = 0 if which == "p1" else 1
    if checkpoint == "pre-cashout" or (checkpoint == "target-cashout" and role == "unrelatedChain"):
        return interval_union(policy_amount(index, which) for _, index, _ in rows)
    if checkpoint == "target-cashout":
        key = "targetP1" if which == "p1" else "targetP2"
        return descriptor(record[key] for record, _, _ in rows)
    return descriptor(record["amounts"][index][amount_index] for record, index, _ in rows)


def exit_candidates(checkpoint: str, role: str, rows) -> dict:
    if checkpoint == "pre-cashout" or (checkpoint == "target-cashout" and role == "unrelatedChain"):
        return {"status": "not-observed-at-checkpoint"}
    if checkpoint == "target-cashout":
        payment = descriptor(record["targetPaymentExitOrdinal"] for record, _, _ in rows)
        change = descriptor(17 - record["targetPaymentExitOrdinal"] for record, _, _ in rows)
    else:
        payment = descriptor(record["roleAssignments"][index]["secondPayment"] + 8 for record, index, _ in rows)
        change = descriptor(record["roleAssignments"][index]["secondChange"] + 8 for record, index, _ in rows)
    return {"secondPaymentExitOrdinal": payment, "firstRecipientChangeExitOrdinal": change}


def amount_value(record: dict, index: int, checkpoint: str, role: str, which: str):
    if checkpoint == "target-cashout" and role == "withdrawingChain":
        return record["targetP1" if which == "p1" else "targetP2"]
    if checkpoint == "full-cashout":
        return record["amounts"][index][0 if which == "p1" else 1]
    return None


def project_role(checkpoint: str, role: str, records: list[dict], credits: dict, historical_outputs: list[str]) -> dict:
    rows = role_rows(checkpoint, records, role)
    senders = descriptor(chain["sender"] for _, _, chain in rows)
    first = descriptor(chain["firstRecipient"] for _, _, chain in rows)
    second = descriptor(chain["secondRecipient"] for _, _, chain in rows)
    first_relationship = object_descriptor(
        {"sender": chain["sender"], "recipient": chain["firstRecipient"]} for _, _, chain in rows
    )
    onward_relationship = object_descriptor(
        {"sender": chain["firstRecipient"], "recipient": chain["secondRecipient"]} for _, _, chain in rows
    )
    p1 = amount_candidates(checkpoint, role, rows, "p1")
    p2 = amount_candidates(checkpoint, role, rows, "p2")
    funding = descriptor(credits[chain["sender"]]["commitment"] for _, _, chain in rows)
    position_pairs = object_descriptor(POSITION_PAIRS)
    result = {
        "originalFunder": senders,
        "firstRecipient": first,
        "secondRecipient": second,
        "firstRelationship": first_relationship,
        "onwardRelationship": onward_relationship,
        "earlierReceivedAmountSompi": p1,
        "onwardPaymentAmountSompi": p2,
        "historicalFundingNote": funding,
        "onwardHistoricalInput": descriptor(historical_outputs),
        "firstPaymentOutputPartition": object_descriptor(PARTITIONS),
        "onwardPaymentOutputPartition": object_descriptor(PARTITIONS),
        "transferPositionPair": position_pairs,
        "firstTransferOrdinal": descriptor(pair["firstTransferOrdinal"] for pair in POSITION_PAIRS),
        "onwardTransferOrdinal": descriptor(pair["onwardTransferOrdinal"] for pair in POSITION_PAIRS),
        "exitRole": exit_candidates(checkpoint, role, rows),
    }
    exact_amounts = checkpoint == "full-cashout" or (checkpoint == "target-cashout" and role == "withdrawingChain")
    if exact_amounts:
        result["withdrawalLinkedTuple"] = object_descriptor(
            {
                "firstRecipient": chain["firstRecipient"],
                "secondRecipient": chain["secondRecipient"],
                "earlierReceivedAmountSompi": amount_value(record, index, checkpoint, role, "p1"),
                "onwardPaymentAmountSompi": amount_value(record, index, checkpoint, role, "p2"),
            }
            for record, index, chain in rows
        )
        result["endToEndTuple"] = object_descriptor(
            {
                "originalFunder": chain["sender"],
                "firstRecipient": chain["firstRecipient"],
                "secondRecipient": chain["secondRecipient"],
                "earlierReceivedAmountSompi": amount_value(record, index, checkpoint, role, "p1"),
                "onwardPaymentAmountSompi": amount_value(record, index, checkpoint, role, "p2"),
            }
            for record, index, chain in rows
        )
    result["properties"] = {
        "originalFundingOriginProtected": senders["count"] >= 2,
        "firstRelationshipProtected": first_relationship["count"] >= 2,
        "onwardRelationshipProtected": onward_relationship["count"] >= 2,
        "earlierReceivedAmountProtected": p1["count"] >= 2,
        "onwardPaymentAmountProtected": p2["count"] >= 2,
        "historicalFundingNoteProtected": funding["count"] >= 2,
        "onwardHistoricalInputProtected": len(historical_outputs) >= 2,
        "firstOutputGroupingProtected": len(PARTITIONS) >= 2,
        "onwardOutputGroupingProtected": len(PARTITIONS) >= 2,
        "transactionPositionProtected": position_pairs["count"] >= 2,
    }
    return result


def project_checkpoint(checkpoint: str, records: list[dict], credits: dict, historical_outputs: list[str]) -> dict:
    if not records:
        raise ValueError("no compatible histories")
    roles = ("anyPaymentChain",) if checkpoint == "pre-cashout" else ("withdrawingChain", "unrelatedChain")
    result = {role: project_role(checkpoint, role, records, credits, historical_outputs) for role in roles}
    result["diagnostics"] = {
        "compatibleRecordCount": len(records),
        "hiddenTargetLabelCount": 0
        if checkpoint == "pre-cashout"
        else len(
            {
                record["targetChain"] if checkpoint == "target-cashout" else full_target_chain(record)
                for record in records
            }
        ),
        "hiddenChainLabelsUsedAsPrivacyMetric": False,
    }
    return result


def rename_hidden_chains(records: list[dict], checkpoint: str) -> list[dict]:
    renamed = copy.deepcopy(records)
    for record in renamed:
        record["chains"].reverse()
        for chain in record["chains"]:
            chain["chain"] = 1 - chain["chain"]
        if checkpoint == "target-cashout":
            record["targetChain"] = 1 - record["targetChain"]
        elif checkpoint == "full-cashout":
            record["amounts"] = tuple(reversed(record["amounts"]))
            record["roleAssignments"] = tuple(reversed(record["roleAssignments"]))
    return renamed


def build_predictions(public_root: Path) -> dict:
    if hashlib.sha256((public_root / "manifest.json").read_bytes()).hexdigest() != ORIGINAL_MANIFEST_SHA:
        raise ValueError("original manifest changed")
    if hashlib.sha256((public_root / "PREDICTIONS.json").read_bytes()).hexdigest() != ORIGINAL_PREDICTIONS_SHA:
        raise ValueError("original predictions changed")
    if hashlib.sha256((public_root / "SCORE.json").read_bytes()).hexdigest() != ORIGINAL_SCORE_SHA:
        raise ValueError("original score changed")
    ledger, aux, events = base.load_public(public_root)
    credits, historical_outputs, exits = base.public_material(aux, events)
    checkpoints = {}
    public_inference = {
        "targetExitOrdinals": [8, 9],
        "targetExitAmountsSompi": [exits[0]["value"], exits[1]["value"]],
        "earlierReceivedAmountRule": "P1 = target exit amount at ordinal 8 + target exit amount at ordinal 9",
        "onwardPaymentAmountRuleKnown": "P2 = target exit whose payout identity is the second recipient",
        "onwardPaymentAmountRuleUnmapped": "P2 is either target exit amount when both role assignments remain compatible",
        "eventPositionRule": "opaque commitments/nullifiers leave six first-before-onward transfer position pairs",
    }
    for checkpoint in ("pre-cashout", "target-cashout", "full-cashout"):
        views = {}
        for observer_name in OBSERVERS:
            known = observer_name.endswith("-known")
            if checkpoint == "pre-cashout":
                records = base.pre_records()
            elif checkpoint == "target-cashout":
                records = base.target_records(exits, aux, known)
            else:
                records = base.full_records(exits, aux, known)
            views[observer_name] = project_checkpoint(checkpoint, records, credits, historical_outputs)
        checkpoints[checkpoint] = views
    return {
        "schema": "wallet-local-shared-history-posthoc-correction-predictions-v2",
        "experiment": ledger["experiment"],
        "status": "post-hoc reassessment; not frozen or blind",
        "sourceArtifacts": {
            "originalManifestSha256": ORIGINAL_MANIFEST_SHA,
            "originalPredictionsFileSha256": ORIGINAL_PREDICTIONS_SHA,
            "originalScoreFileSha256": ORIGINAL_SCORE_SHA,
            "originalSealedPredictionsCanonicalSha256": (public_root / "PREDICTIONS.json.sha256").read_text().strip(),
        },
        "observerBoundary": {
            "publicAndServiceEvidenceOnly": True,
            "privateTruthRead": False,
            "hiddenChainLabelsUsedAsPrivacyMetric": False,
            "networkEndpointIdentity": "unmeasured",
        },
        "publicInference": public_inference,
        "checkpoints": checkpoints,
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: observer_correction_v2.py ORIGINAL_PUBLIC_DIR OUTPUT.json")
    public_root, output = map(Path, sys.argv[1:])
    seal = output.with_suffix(output.suffix + ".sha256")
    if output.exists() or seal.exists():
        raise SystemExit("output exists")
    predictions = build_predictions(public_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(predictions, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256(canonical(predictions)).hexdigest()
    seal.write_text(digest + "\n")
    print(json.dumps({"output": str(output), "canonicalSha256": digest}))


if __name__ == "__main__":
    main()
