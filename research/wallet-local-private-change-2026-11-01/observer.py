#!/usr/bin/env python3
"""Public-only, role-conditioned observer for private-change withdrawals."""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
import copy
from pathlib import Path


ARMS = ("direct-exit-baseline", "private-change-candidate")
OBSERVERS = ("O-public-known", "O-public-unmapped", "O-service-known", "O-service-unmapped")
POLICY = {
    0: {"senders": ("A", "B"), "p1": (220_000_000, 500_000_000), "p2min": 80_000_000},
    1: {"senders": ("C", "D"), "p1": (180_000_000, 400_000_000), "p2min": 60_000_000},
}
CREDIT = {"A": 900_000_000, "B": 800_000_000, "C": 700_000_000, "D": 600_000_000}
MIN_SPLIT = 10_000_000
SELECTION_SHA = "619a586a0f68ca7342834f59da0208a2f4a56331c4960f1bbc90aac422d79e7e"
WORKLOAD_SHA = "833ca8a1006ce5cf2a07282062a6fc092f28d2554bcbc3f3a7e4f11d6fb47536"


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def hbytes(value) -> str:
    return bytes(value).hex()


def statement(event: dict) -> dict:
    return event["operation"]["statement"]


def dedupe(values) -> list:
    return [json.loads(raw) for raw in sorted({json.dumps(value, sort_keys=True) for value in values})]


def descriptor(values) -> dict:
    unique = sorted(set(values))
    return {"kind": "set", "values": unique, "count": len(unique)}


def objects(values) -> dict:
    unique = dedupe(values)
    return {"kind": "set", "values": unique, "count": len(unique)}


def interval_union(ranges) -> dict:
    merged = []
    for low, high in sorted(set(ranges)):
        if high < low:
            continue
        if not merged or low > merged[-1][1] + 1:
            merged.append([low, high])
        else:
            merged[-1][1] = max(merged[-1][1], high)
    return {
        "kind": "integer-interval-union",
        "ranges": [{"minimum": low, "maximum": high} for low, high in merged],
        "count": sum(high - low + 1 for low, high in merged),
    }


def schedules():
    return [tuple(0 if i in positions else 1 for i in range(4)) for positions in itertools.combinations(range(4), 2)]


def position_pairs():
    return tuple(
        {"firstTransferOrdinal": first + 4, "onwardTransferOrdinal": second + 4}
        for first in range(4)
        for second in range(first + 1, 4)
    )


def topologies():
    result = []
    for sender0 in POLICY[0]["senders"]:
        for sender1 in POLICY[1]["senders"]:
            for first in (("E", "F"), ("F", "E")):
                for second in (("G", "H"), ("H", "G")):
                    result.append([
                        {"chain": 0, "sender": sender0, "firstRecipient": first[0], "secondRecipient": second[0]},
                        {"chain": 1, "sender": sender1, "firstRecipient": first[1], "secondRecipient": second[1]},
                    ])
    return result


def amount_valid(chain: int, p1: int, p2: int) -> bool:
    low, high = POLICY[chain]["p1"]
    minimum = POLICY[chain]["p2min"]
    return low <= p1 <= high and minimum <= p2 <= p1 - minimum


def policy_range(chain: int, which: str):
    if which == "p1":
        return POLICY[chain]["p1"]
    minimum = POLICY[chain]["p2min"]
    return minimum, POLICY[chain]["p1"][1] - minimum


def other_sender(chain: int, sender: str) -> str:
    return POLICY[chain]["senders"][1 - POLICY[chain]["senders"].index(sender)]


def policy_group(sender: str) -> int:
    return 0 if sender in POLICY[0]["senders"] else 1


def validate_capture(root: Path, event: dict) -> None:
    capture = load(root / event["capture"])
    raw = bytes.fromhex(capture["requestRawHex"])
    if len(raw) != capture["requestBytes"] or hashlib.sha256(raw).hexdigest() != capture["requestSha256"]:
        raise ValueError("capture bytes/hash")
    request = json.loads(raw)
    if request != capture["request"] or request["operation"] != event["operation"]:
        raise ValueError("capture operation")
    if set(request) != {"schema", "trial", "ordinal", "relayToken", "operation"}:
        raise ValueError("capture fields")


def load_arm(root: Path, arm: str):
    arm_root = root / arm
    ledger = load(arm_root / "ledger.json")
    aux = load(arm_root / "auxiliary.json")
    expected = 16 if arm == ARMS[0] else 20
    events = [load(arm_root / f"event-{ordinal:02}.json") for ordinal in range(expected)]
    if ledger["selectionSha256"] != SELECTION_SHA or ledger["privateWorkloadSha256"] != WORKLOAD_SHA:
        raise ValueError("experiment identity")
    if ledger["eventOrdinals"] != list(range(expected)) or [event["ordinal"] for event in events] != list(range(expected)):
        raise ValueError("event coverage")
    expected_kinds = [1] * 4 + [2] * (4 if arm == ARMS[0] else 6) + [3] * (8 if arm == ARMS[0] else 10)
    if [statement(event)["kind"] for event in events] != expected_kinds:
        raise ValueError("operation kinds")
    for event in events:
        validate_capture(arm_root, event)
    owner_map = aux["depositOwnerIdentity"]
    credits = {}
    for event in events[:4]:
        item = statement(event)
        owner = owner_map[hbytes(item["deposit_owner"])]
        credits[owner] = {"commitment": hbytes(item["outputs"][0]), "value": item["deposit_value"]}
    original_transfers = events[4:8]
    historical_outputs = [hbytes(output) for event in original_transfers[:3] for output in statement(event)["outputs"]]
    split_inputs = [hbytes(output) for event in original_transfers[1:] for output in statement(event)["outputs"]]
    exits = [
        {
            "ordinal": event["ordinal"],
            "value": statement(event)["exit_value"],
            "destination": hbytes(statement(event)["exit_destination"]),
        }
        for event in events
        if statement(event)["kind"] == 3
    ]
    return ledger, aux, events, credits, historical_outputs, split_inputs, exits


def identity_ok(exit_item: dict, expected: str, aux: dict, known: bool) -> bool:
    return not known or aux["knownExitDestinationIdentity"].get(exit_item["destination"]) == expected


def pre_records():
    return [{"topology": topology} for topology in topologies()]


def baseline_requested_records(exits, aux, known):
    result = []
    for topology in topologies():
        for target in (0, 1):
            chain = topology[target]
            for payment_index in (0, 1):
                payment = exits[payment_index]
                change = exits[1 - payment_index]
                p2 = payment["value"]
                p1 = p2 + change["value"]
                if not amount_valid(target, p1, p2):
                    continue
                if not identity_ok(payment, chain["secondRecipient"], aux, known):
                    continue
                if not identity_ok(change, chain["firstRecipient"], aux, known):
                    continue
                result.append({
                    "topology": topology,
                    "target": target,
                    "amounts": {target: (p1, p2)},
                    "secondPaymentExitOrdinal": payment["ordinal"],
                    "secondChangeExitOrdinal": change["ordinal"],
                })
    return result


def all_role_assignments(exits, chain: int):
    roles = ("untouchedCredit", "firstChange", "secondPayment", "secondChange")
    result = []
    for sender in POLICY[chain]["senders"]:
        source = CREDIT[sender]
        other = other_sender(chain, sender)
        for indices in itertools.permutations(range(len(exits)), 4):
            assigned = dict(zip(roles, indices))
            if exits[assigned["untouchedCredit"]]["value"] != CREDIT[other]:
                continue
            p1 = source - exits[assigned["firstChange"]]["value"]
            p2 = exits[assigned["secondPayment"]]["value"]
            if exits[assigned["secondChange"]]["value"] != p1 - p2 or not amount_valid(chain, p1, p2):
                continue
            result.append({"sender": sender, "roles": assigned, "p1": p1, "p2": p2})
    return result


def baseline_full_records(exits, aux, known):
    by_chain = [all_role_assignments(exits, chain) for chain in (0, 1)]
    result = []
    for left in by_chain[0]:
        left_indices = set(left["roles"].values())
        for right in by_chain[1]:
            if left_indices & set(right["roles"].values()) or left_indices | set(right["roles"].values()) != set(range(8)):
                continue
            for first in (("E", "F"), ("F", "E")):
                for second in (("G", "H"), ("H", "G")):
                    topology = [
                        {"chain": 0, "sender": left["sender"], "firstRecipient": first[0], "secondRecipient": second[0]},
                        {"chain": 1, "sender": right["sender"], "firstRecipient": first[1], "secondRecipient": second[1]},
                    ]
                    compatible = True
                    for chain_index, assignment in enumerate((left, right)):
                        expected = {
                            "untouchedCredit": other_sender(chain_index, assignment["sender"]),
                            "firstChange": assignment["sender"],
                            "secondPayment": topology[chain_index]["secondRecipient"],
                            "secondChange": topology[chain_index]["firstRecipient"],
                        }
                        compatible &= all(identity_ok(exits[index], expected[role], aux, known) for role, index in assignment["roles"].items())
                    if compatible:
                        target_candidates = [
                            chain_index
                            for chain_index, assignment in enumerate((left, right))
                            if {assignment["roles"]["secondPayment"], assignment["roles"]["secondChange"]} == {0, 1}
                        ]
                        if len(target_candidates) != 1:
                            continue
                        result.append({
                            "topology": topology,
                            "target": target_candidates[0],
                            "amounts": {0: (left["p1"], left["p2"]), 1: (right["p1"], right["p2"])},
                            "exitAssignments": {0: left["roles"], 1: right["roles"]},
                            "secondPaymentExitOrdinal": exits[(left, right)[target_candidates[0]]["roles"]["secondPayment"]]["ordinal"],
                            "secondChangeExitOrdinal": exits[(left, right)[target_candidates[0]]["roles"]["secondChange"]]["ordinal"],
                        })
    return result


def requested_region(chain: int, w_change: int, w_payment: int):
    p1_policy_low, p1_high = POLICY[chain]["p1"]
    policy_min = POLICY[chain]["p2min"]
    change_min = max(policy_min, w_change + MIN_SPLIT)
    p2_low = max(policy_min, w_payment + MIN_SPLIT)
    p1_low = max(p1_policy_low, p2_low + change_min)
    p2_high = p1_high - change_min
    if p1_low > p1_high or p2_low > p2_high:
        return None
    first_count = p1_low - change_min - p2_low + 1
    last_count = p1_high - change_min - p2_low + 1
    pair_count = (p1_high - p1_low + 1) * (first_count + last_count) // 2
    return {
        "p1Minimum": p1_low,
        "p1Maximum": p1_high,
        "p2Minimum": p2_low,
        "p2Maximum": p2_high,
        "secondChangeMinimum": change_min,
        "compatibleP1P2PairCount": pair_count,
    }


def candidate_requested_records(exits, aux, known):
    requested = exits[:2]
    result = []
    for topology in topologies():
        for target in (0, 1):
            chain = topology[target]
            for payment_index in (0, 1):
                payment = requested[payment_index]
                change = requested[1 - payment_index]
                if not identity_ok(payment, chain["secondRecipient"], aux, known):
                    continue
                if not identity_ok(change, chain["firstRecipient"], aux, known):
                    continue
                region = requested_region(target, change["value"], payment["value"])
                if region is None:
                    continue
                result.append({
                    "topology": topology,
                    "target": target,
                    "requestedSecondPayment": payment["value"],
                    "requestedSecondChange": change["value"],
                    "secondPaymentExitOrdinal": payment["ordinal"],
                    "secondChangeExitOrdinal": change["ordinal"],
                    "region": region,
                })
    return result


def candidate_remainder_records(exits, aux, known):
    requested = exits[:2]
    remainder = exits[2:4]
    result = []
    for topology in topologies():
        for target in (0, 1):
            chain = topology[target]
            for requested_payment_index in (0, 1):
                wp = requested[requested_payment_index]
                wc = requested[1 - requested_payment_index]
                for remainder_payment_index in (0, 1):
                    rp = remainder[remainder_payment_index]
                    rc = remainder[1 - remainder_payment_index]
                    expected = ((wp, chain["secondRecipient"]), (wc, chain["firstRecipient"]), (rp, chain["secondRecipient"]), (rc, chain["firstRecipient"]))
                    if not all(identity_ok(item, owner, aux, known) for item, owner in expected):
                        continue
                    if min(wp["value"], wc["value"], rp["value"], rc["value"]) < MIN_SPLIT:
                        continue
                    p2 = wp["value"] + rp["value"]
                    p1 = p2 + wc["value"] + rc["value"]
                    if not amount_valid(target, p1, p2):
                        continue
                    result.append({
                        "topology": topology,
                        "target": target,
                        "amounts": {target: (p1, p2)},
                        "requestedSecondPayment": wp["value"],
                        "requestedSecondChange": wc["value"],
                        "remainderSecondPayment": rp["value"],
                        "remainderSecondChange": rc["value"],
                        "secondPaymentExitOrdinal": wp["ordinal"],
                        "secondChangeExitOrdinal": wc["ordinal"],
                        "secondPaymentRemainderExitOrdinal": rp["ordinal"],
                        "secondChangeRemainderExitOrdinal": rc["ordinal"],
                    })
    return result


def expected_owner(topology, chain: int, role: str):
    item = topology[chain]
    if role == "untouchedCredit":
        return other_sender(chain, item["sender"])
    if role == "firstChange":
        return item["sender"]
    if role == "secondPayment":
        return item["secondRecipient"]
    if role == "secondChange":
        return item["firstRecipient"]
    raise ValueError("role")


def candidate_full_records(exits, aux, known):
    partial = candidate_remainder_records(exits, aux, known)
    final = exits[4:]
    result = []
    for record in partial:
        target = record["target"]
        other = 1 - target
        topology = record["topology"]
        roles = [(0, "untouchedCredit"), (0, "firstChange"), (1, "untouchedCredit"), (1, "firstChange"), (other, "secondPayment"), (other, "secondChange")]
        for permutation in itertools.permutations(range(6)):
            assignment = {role: index for role, index in zip(roles, permutation)}
            compatible = True
            for role, index in assignment.items():
                compatible &= identity_ok(final[index], expected_owner(topology, *role), aux, known)
            if not compatible:
                continue
            amounts = dict(record["amounts"])
            for chain in (0, 1):
                sender = topology[chain]["sender"]
                untouched = final[assignment[(chain, "untouchedCredit")]]["value"]
                first_change = final[assignment[(chain, "firstChange")]]["value"]
                if untouched != CREDIT[other_sender(chain, sender)]:
                    compatible = False
                    break
                p1_from_change = CREDIT[sender] - first_change
                if chain == target:
                    if p1_from_change != amounts[target][0]:
                        compatible = False
                        break
                else:
                    p2 = final[assignment[(chain, "secondPayment")]]["value"]
                    second_change = final[assignment[(chain, "secondChange")]]["value"]
                    if second_change != p1_from_change - p2 or not amount_valid(chain, p1_from_change, p2):
                        compatible = False
                        break
                    amounts[chain] = (p1_from_change, p2)
            if compatible:
                result.append({**record, "amounts": amounts, "finalAssignments": assignment})
    return result


def role_rows(checkpoint: str, records, role: str):
    result = []
    for record in records:
        if checkpoint == "pre-withdrawal":
            indices = (0, 1)
        else:
            indices = (record["target"],) if role == "withdrawingChain" else (1 - record["target"],)
        result.extend((record, index, record["topology"][index]) for index in indices)
    return result


def amount_descriptor(arm: str, checkpoint: str, role: str, rows, which: str):
    if checkpoint == "pre-withdrawal" or (
        role == "unrelatedChain" and checkpoint in {"requested-withdrawal", "remainder-withdrawal"}
    ):
        return interval_union(policy_range(policy_group(chain["sender"]), which) for _, _, chain in rows)
    if arm == ARMS[1] and checkpoint == "requested-withdrawal":
        key_min = "p1Minimum" if which == "p1" else "p2Minimum"
        key_max = "p1Maximum" if which == "p1" else "p2Maximum"
        return interval_union((record["region"][key_min], record["region"][key_max]) for record, _, _ in rows)
    amount_index = 0 if which == "p1" else 1
    return descriptor(record["amounts"][index][amount_index] for record, index, _ in rows)


def exit_projection(arm: str, checkpoint: str, role: str, rows):
    if checkpoint == "pre-withdrawal" or role == "unrelatedChain" and checkpoint != "full-drainage":
        return {"status": "not-observed-at-checkpoint"}
    if role == "unrelatedChain" and checkpoint == "full-drainage":
        return {"status": "full-note exits in final drainage"}
    result = {
        "secondRecipientRequestedExitOrdinal": descriptor(record["secondPaymentExitOrdinal"] for record, _, _ in rows),
        "firstRecipientRequestedExitOrdinal": descriptor(record["secondChangeExitOrdinal"] for record, _, _ in rows),
    }
    if arm == ARMS[1] and checkpoint in {"remainder-withdrawal", "full-drainage"}:
        result.update({
            "secondRecipientRemainderExitOrdinal": descriptor(record["secondPaymentRemainderExitOrdinal"] for record, _, _ in rows),
            "firstRecipientRemainderExitOrdinal": descriptor(record["secondChangeRemainderExitOrdinal"] for record, _, _ in rows),
        })
    return result


def split_value_projection(arm: str, checkpoint: str, role: str, rows):
    if arm == ARMS[0] or checkpoint == "pre-withdrawal" or role == "unrelatedChain":
        return {"status": "not-applicable"}
    result = {
        "secondRecipientRequestedSompi": descriptor(record["requestedSecondPayment"] for record, _, _ in rows),
        "firstRecipientRequestedSompi": descriptor(record["requestedSecondChange"] for record, _, _ in rows),
    }
    if checkpoint in {"remainder-withdrawal", "full-drainage"}:
        result.update({
            "secondRecipientRemainderSompi": descriptor(record["remainderSecondPayment"] for record, _, _ in rows),
            "firstRecipientRemainderSompi": descriptor(record["remainderSecondChange"] for record, _, _ in rows),
        })
    else:
        result["remainderStatus"] = "private-and-unobserved"
    return result


def project_role(arm: str, checkpoint: str, role: str, records, credits, historical_outputs, split_inputs):
    rows = role_rows(checkpoint, records, role)
    senders = descriptor(chain["sender"] for _, _, chain in rows)
    first_rel = objects({"sender": chain["sender"], "recipient": chain["firstRecipient"]} for _, _, chain in rows)
    onward_rel = objects({"sender": chain["firstRecipient"], "recipient": chain["secondRecipient"]} for _, _, chain in rows)
    p1 = amount_descriptor(arm, checkpoint, role, rows, "p1")
    p2 = amount_descriptor(arm, checkpoint, role, rows, "p2")
    result = {
        "originalFunder": senders,
        "firstRecipient": descriptor(chain["firstRecipient"] for _, _, chain in rows),
        "secondRecipient": descriptor(chain["secondRecipient"] for _, _, chain in rows),
        "firstRelationship": first_rel,
        "onwardRelationship": onward_rel,
        "earlierReceivedAmountSompi": p1,
        "onwardPaymentAmountSompi": p2,
        "historicalFundingNote": descriptor(credits[chain["sender"]]["commitment"] for _, _, chain in rows),
        "onwardHistoricalInput": descriptor(historical_outputs),
        "originalFirstOutputPartition": objects([
            {"paymentOutputIndex": 0, "changeOutputIndex": 1},
            {"paymentOutputIndex": 1, "changeOutputIndex": 0},
        ]),
        "originalOnwardOutputPartition": objects([
            {"paymentOutputIndex": 0, "changeOutputIndex": 1},
            {"paymentOutputIndex": 1, "changeOutputIndex": 0},
        ]),
        "originalTransferPositionPair": objects(position_pairs()),
        "exitRole": exit_projection(arm, checkpoint, role, rows),
        "splitValues": split_value_projection(arm, checkpoint, role, rows),
    }
    if arm == ARMS[1] and checkpoint != "pre-withdrawal" and role == "withdrawingChain":
        result.update({
            "splitHistoricalInput": descriptor(split_inputs),
            "splitOutputPartition": objects([
                {"requestedOutputIndex": 0, "changeOutputIndex": 1},
                {"requestedOutputIndex": 1, "changeOutputIndex": 0},
            ]),
            "splitEventOrdinal": descriptor([8, 9]),
        })
    else:
        result.update({"splitHistoricalInput": {"status": "not-applicable"}, "splitOutputPartition": {"status": "not-applicable"}, "splitEventOrdinal": {"status": "not-applicable"}})
    result["properties"] = {
        "originalFundingOriginProtected": senders["count"] >= 2,
        "firstRelationshipProtected": first_rel["count"] >= 2,
        "onwardRelationshipProtected": onward_rel["count"] >= 2,
        "earlierReceivedAmountProtected": p1["count"] >= 2,
        "onwardPaymentAmountProtected": p2["count"] >= 2,
        "historicalFundingNoteProtected": result["historicalFundingNote"]["count"] >= 2,
        "onwardHistoricalInputProtected": result["onwardHistoricalInput"]["count"] >= 2,
        "originalGroupingProtected": True,
        "originalTransactionPositionProtected": True,
        "splitGroupingProtected": result["splitOutputPartition"].get("count", 0) >= 2,
        "splitPositionProtected": result["splitEventOrdinal"].get("count", 0) >= 2,
    }
    return result


def project_checkpoint(arm: str, checkpoint: str, records, credits, historical_outputs, split_inputs):
    if not records:
        raise ValueError(f"no compatible records: {arm}/{checkpoint}")
    roles = ("anyPaymentChain",) if checkpoint == "pre-withdrawal" else ("withdrawingChain", "unrelatedChain")
    result = {role: project_role(arm, checkpoint, role, records, credits, historical_outputs, split_inputs) for role in roles}
    result["diagnostics"] = {
        "compatibleRecordCount": len(records),
        "hiddenTargetLabelCount": 0 if checkpoint == "pre-withdrawal" else len({record["target"] for record in records}),
        "hiddenChainLabelsUsedAsPrivacyMetric": False,
    }
    if arm == ARMS[1] and checkpoint == "requested-withdrawal":
        result["diagnostics"]["compatibleAmountRegionCount"] = len(
            {json.dumps(record["region"], sort_keys=True) for record in records}
        )
        result["diagnostics"]["weightedCompatibleP1P2Pairs"] = sum(record["region"]["compatibleP1P2PairCount"] for record in records)
    return result


def rename_hidden_chains(records, arm: str, checkpoint: str):
    # Copy each record independently: enumeration intentionally reuses topology
    # objects, and a shared deepcopy memo would make repeated reversals cancel.
    result = [copy.deepcopy(record) for record in records]
    for record in result:
        record["topology"].reverse()
        for chain in record["topology"]:
            chain["chain"] = 1 - chain["chain"]
        if checkpoint != "pre-withdrawal":
            record["target"] = 1 - record["target"]
        if "amounts" in record:
            record["amounts"] = {1 - key: value for key, value in record["amounts"].items()}
        if "exitAssignments" in record:
            record["exitAssignments"] = {1 - key: value for key, value in record["exitAssignments"].items()}
        if "finalAssignments" in record:
            record["finalAssignments"] = {
                (1 - chain, role): index
                for (chain, role), index in record["finalAssignments"].items()
            }
    return result


def arm_records(arm: str, checkpoint: str, exits, aux, known):
    if checkpoint == "pre-withdrawal":
        return pre_records()
    if arm == ARMS[0]:
        if checkpoint in {"requested-withdrawal", "remainder-withdrawal"}:
            return baseline_requested_records(exits, aux, known)
        return baseline_full_records(exits, aux, known)
    if checkpoint == "requested-withdrawal":
        return candidate_requested_records(exits, aux, known)
    if checkpoint == "remainder-withdrawal":
        return candidate_remainder_records(exits, aux, known)
    return candidate_full_records(exits, aux, known)


def predict(root: Path):
    receipt = load(root / "run-receipt.json")
    if receipt["selectionSha256"] != SELECTION_SHA or receipt["privateWorkloadSha256"] != WORKLOAD_SHA:
        raise ValueError("run identity")
    arms = {}
    for arm in ARMS:
        _, aux, _, credits, history, split_inputs, exits = load_arm(root, arm)
        checkpoints = {}
        for checkpoint in ("pre-withdrawal", "requested-withdrawal", "remainder-withdrawal", "full-drainage"):
            views = {}
            for observer_name in OBSERVERS:
                known = observer_name.endswith("-known")
                records = arm_records(arm, checkpoint, exits, aux, known)
                views[observer_name] = project_checkpoint(arm, checkpoint, records, credits, history, split_inputs)
            checkpoints[checkpoint] = views
        arms[arm] = {"checkpoints": checkpoints}
    baseline = arms[ARMS[0]]["checkpoints"]["requested-withdrawal"]
    candidate = arms[ARMS[1]]["checkpoints"]["requested-withdrawal"]
    comparison = {}
    for observer_name in OBSERVERS:
        b = baseline[observer_name]["withdrawingChain"]
        c = candidate[observer_name]["withdrawingChain"]
        comparison[observer_name] = {
            "baselineP1Count": b["earlierReceivedAmountSompi"]["count"],
            "candidateP1Count": c["earlierReceivedAmountSompi"]["count"],
            "baselineP2Count": b["onwardPaymentAmountSompi"]["count"],
            "candidateP2Count": c["onwardPaymentAmountSompi"]["count"],
            "P1StrictlyImproved": c["earlierReceivedAmountSompi"]["count"] > b["earlierReceivedAmountSompi"]["count"],
            "P2StrictlyImproved": c["onwardPaymentAmountSompi"]["count"] > b["onwardPaymentAmountSompi"]["count"],
        }
    return {
        "schema": "wallet-local-private-change-predictions-v1",
        "experiment": receipt["experiment"],
        "selectionSha256": SELECTION_SHA,
        "privateWorkloadSha256": WORKLOAD_SHA,
        "observerBoundary": {
            "publicAndServiceEvidenceOnly": True,
            "privateTruthRead": False,
            "armsScoredAsCounterfactualsNotJointlyObserved": True,
            "hiddenChainLabelsUsedAsPrivacyMetric": False,
            "networkEndpointIdentity": "unmeasured",
        },
        "arms": arms,
        "requestedWithdrawalComparison": comparison,
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: observer.py PUBLIC_RUN_DIR PREDICTIONS.json")
    root, output = map(Path, sys.argv[1:])
    seal = output.with_suffix(output.suffix + ".sha256")
    if output.exists() or seal.exists():
        raise SystemExit("output exists")
    predictions = predict(root)
    output.write_text(json.dumps(predictions, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256(canonical(predictions)).hexdigest()
    seal.write_text(digest + "\n")
    print(json.dumps({"output": str(output), "canonicalSha256": digest}))


if __name__ == "__main__":
    main()
