#!/usr/bin/env python3
"""Joint observer for the frozen one-ledger, two-chain experiment."""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
from pathlib import Path


CHAIN_POLICY = {
    0: {"senders": ("A", "B"), "p1": (220_000_000, 500_000_000), "p2min": 80_000_000},
    1: {"senders": ("C", "D"), "p1": (180_000_000, 400_000_000), "p2min": 60_000_000},
}
CREDIT_VALUE = {"A": 900_000_000, "B": 800_000_000, "C": 700_000_000, "D": 600_000_000}
OBSERVERS = ("O-public-known", "O-public-unmapped", "O-service-known", "O-service-unmapped")


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def hbytes(value) -> str:
    return bytes(value).hex()


def statement(event: dict) -> dict:
    return event["operation"]["statement"]


def interval(low: int, high: int) -> dict:
    return {"kind": "integer-interval", "minimum": low, "maximum": high, "count": high - low + 1}


def value_set(values) -> dict:
    result = sorted(set(values))
    return {"kind": "set", "values": result, "count": len(result)}


def dedupe(values: list) -> list:
    return [json.loads(raw) for raw in sorted({json.dumps(value, sort_keys=True) for value in values})]


def amount_pair_count(chain: int) -> int:
    low, high = CHAIN_POLICY[chain]["p1"]
    minimum = CHAIN_POLICY[chain]["p2min"]
    count = high - low + 1
    return count * (low + high - 4 * minimum + 2) // 2


def amount_valid(chain: int, p1: int, p2: int) -> bool:
    low, high = CHAIN_POLICY[chain]["p1"]
    minimum = CHAIN_POLICY[chain]["p2min"]
    return low <= p1 <= high and minimum <= p2 <= p1 - minimum


def schedules() -> list[tuple[int, ...]]:
    result = []
    for zero_positions in itertools.combinations(range(4), 2):
        zeros = set(zero_positions)
        result.append(tuple(0 if index in zeros else 1 for index in range(4)))
    return result


def topologies() -> list[tuple[dict, dict]]:
    result = []
    for sender0 in CHAIN_POLICY[0]["senders"]:
        for sender1 in CHAIN_POLICY[1]["senders"]:
            for first in (("E", "F"), ("F", "E")):
                for second in (("G", "H"), ("H", "G")):
                    result.append((
                        {"chain": 0, "sender": sender0, "firstRecipient": first[0], "secondRecipient": second[0]},
                        {"chain": 1, "sender": sender1, "firstRecipient": first[1], "secondRecipient": second[1]},
                    ))
    return result


def validate_capture(root: Path, event: dict) -> None:
    capture = load(root / event["capture"])
    raw = bytes.fromhex(capture["requestRawHex"])
    if len(raw) != capture["requestBytes"] or hashlib.sha256(raw).hexdigest() != capture["requestSha256"]:
        raise ValueError("service capture bytes/hash")
    request = json.loads(raw)
    if request != capture["request"] or request["operation"] != event["operation"]:
        raise ValueError("service capture operation")
    if set(request) != {"schema", "trial", "ordinal", "relayToken", "operation"}:
        raise ValueError("unexpected service request field")


def load_public(root: Path):
    ledger = load(root / "ledger.json")
    aux = load(root / "auxiliary.json")
    if ledger["checkpointEventCounts"] != {"preCashout": 8, "targetCashout": 10, "fullCashout": 16}:
        raise ValueError("checkpoint coverage")
    if ledger["eventOrdinals"] != list(range(16)) or len(ledger["payouts"]) != 8:
        raise ValueError("event/exit coverage")
    events = [load(root / f"event-{ordinal:02}.json") for ordinal in range(16)]
    if [event["ordinal"] for event in events] != list(range(16)):
        raise ValueError("event order")
    if [statement(event)["kind"] for event in events] != [1] * 4 + [2] * 4 + [3] * 8:
        raise ValueError("operation-kind coverage")
    if [event["label"] for event in events] != ["credit"] * 4 + ["transfer"] * 4 + ["exit-target"] * 2 + ["exit-final"] * 6:
        raise ValueError("event-label coverage")
    for event in events:
        validate_capture(root, event)
    return ledger, aux, events


def public_material(aux: dict, events: list[dict]):
    credits = {}
    owner_map = aux["depositOwnerIdentity"]
    for event in events[:4]:
        item = statement(event)
        owner = owner_map[hbytes(item["deposit_owner"])]
        credits[owner] = {"commitment": hbytes(item["outputs"][0]), "value": item["deposit_value"]}
    transfers = events[4:8]
    historical_outputs = [hbytes(output) for event in transfers[:3] for output in statement(event)["outputs"]]
    exits = [
        {
            "ordinal": event["ordinal"],
            "value": statement(event)["exit_value"],
            "destination": hbytes(statement(event)["exit_destination"]),
        }
        for event in events[8:]
    ]
    return credits, historical_outputs, exits


def identity_ok(exit_item: dict, expected: str, aux: dict, known: bool) -> bool:
    if not known:
        return True
    return aux["knownExitDestinationIdentity"].get(exit_item["destination"]) == expected


def pre_records() -> list[dict]:
    return [{"chains": list(topology)} for topology in topologies()]


def target_records(exits: list[dict], aux: dict, known: bool) -> list[dict]:
    result = []
    target_exits = exits[:2]
    for topology in topologies():
        for target_chain in (0, 1):
            chain = topology[target_chain]
            for payment_index in (0, 1):
                payment_exit = target_exits[payment_index]
                change_exit = target_exits[1 - payment_index]
                p2 = payment_exit["value"]
                p1 = p2 + change_exit["value"]
                if not amount_valid(target_chain, p1, p2):
                    continue
                if not identity_ok(payment_exit, chain["secondRecipient"], aux, known):
                    continue
                if not identity_ok(change_exit, chain["firstRecipient"], aux, known):
                    continue
                result.append({
                    "chains": list(topology),
                    "targetChain": target_chain,
                    "targetP1": p1,
                    "targetP2": p2,
                    "targetPaymentExitOrdinal": payment_exit["ordinal"],
                    "weight": amount_pair_count(1 - target_chain),
                })
    return result


def role_assignments(chain: int, exits: list[dict]) -> list[dict]:
    result = []
    roles = ("untouchedCredit", "firstChange", "secondPayment", "secondChange")
    for sender in CHAIN_POLICY[chain]["senders"]:
        other = CHAIN_POLICY[chain]["senders"][1 - CHAIN_POLICY[chain]["senders"].index(sender)]
        source = CREDIT_VALUE[sender]
        for indices in itertools.permutations(range(8), 4):
            assigned = dict(zip(roles, indices))
            if exits[assigned["untouchedCredit"]]["value"] != CREDIT_VALUE[other]:
                continue
            p1 = source - exits[assigned["firstChange"]]["value"]
            p2 = exits[assigned["secondPayment"]]["value"]
            if exits[assigned["secondChange"]]["value"] != p1 - p2 or not amount_valid(chain, p1, p2):
                continue
            result.append({"sender": sender, "other": other, "roles": assigned, "p1": p1, "p2": p2})
    return result


def full_records(exits: list[dict], aux: dict, known: bool) -> list[dict]:
    by_chain = [role_assignments(chain, exits) for chain in (0, 1)]
    result = []
    for left in by_chain[0]:
        left_indices = set(left["roles"].values())
        for right in by_chain[1]:
            if left_indices & set(right["roles"].values()) or left_indices | set(right["roles"].values()) != set(range(8)):
                continue
            for first in (("E", "F"), ("F", "E")):
                for second in (("G", "H"), ("H", "G")):
                    chains = [
                        {"chain": 0, "sender": left["sender"], "firstRecipient": first[0], "secondRecipient": second[0]},
                        {"chain": 1, "sender": right["sender"], "firstRecipient": first[1], "secondRecipient": second[1]},
                    ]
                    compatible = True
                    for chain_index, assignment in enumerate((left, right)):
                        expected = {
                            "untouchedCredit": assignment["other"],
                            "firstChange": assignment["sender"],
                            "secondPayment": chains[chain_index]["secondRecipient"],
                            "secondChange": chains[chain_index]["firstRecipient"],
                        }
                        for role, exit_index in assignment["roles"].items():
                            compatible &= identity_ok(exits[exit_index], expected[role], aux, known)
                    if compatible:
                        result.append({
                            "chains": chains,
                            "amounts": ((left["p1"], left["p2"]), (right["p1"], right["p2"])),
                            "roleAssignments": (left["roles"], right["roles"]),
                        })
    return result


def amount_descriptor(checkpoint: str, records: list[dict], chain: int, which: str) -> dict:
    index = 0 if which == "p1" else 1
    if checkpoint == "pre-cashout":
        if which == "p1":
            return interval(*CHAIN_POLICY[chain]["p1"])
        minimum = CHAIN_POLICY[chain]["p2min"]
        return interval(minimum, CHAIN_POLICY[chain]["p1"][1] - minimum)
    if checkpoint == "target-cashout" and any(record["targetChain"] != chain for record in records):
        if which == "p1":
            return interval(*CHAIN_POLICY[chain]["p1"])
        minimum = CHAIN_POLICY[chain]["p2min"]
        return interval(minimum, CHAIN_POLICY[chain]["p1"][1] - minimum)
    if checkpoint == "target-cashout":
        return value_set(record["targetP1" if which == "p1" else "targetP2"] for record in records if record["targetChain"] == chain)
    return value_set(record["amounts"][chain][index] for record in records)


def project(checkpoint: str, records: list[dict], credits: dict, historical_outputs: list[str]) -> dict:
    if not records:
        raise ValueError(f"no compatible histories at {checkpoint}")
    chains = []
    partitions = [
        {"paymentOutputIndex": 0, "changeOutputIndex": 1},
        {"paymentOutputIndex": 1, "changeOutputIndex": 0},
    ]
    for chain in (0, 1):
        topologies_here = [record["chains"][chain] for record in records]
        senders = sorted({item["sender"] for item in topologies_here})
        first = sorted({item["firstRecipient"] for item in topologies_here})
        second = sorted({item["secondRecipient"] for item in topologies_here})
        chains.append({
            "chain": chain,
            "firstPayment": {
                "sender": senders,
                "recipient": first,
                "relationship": dedupe([{"sender": item["sender"], "recipient": item["firstRecipient"]} for item in topologies_here]),
                "amountSompi": amount_descriptor(checkpoint, records, chain, "p1"),
                "historicalNote": sorted({credits[sender]["commitment"] for sender in senders}),
                "outputPartition": partitions,
                "logicalSubmitter": senders,
                "networkEndpointIdentity": "unmeasured",
            },
            "secondPayment": {
                "sender": first,
                "recipient": second,
                "relationship": dedupe([{"sender": item["firstRecipient"], "recipient": item["secondRecipient"]} for item in topologies_here]),
                "amountSompi": amount_descriptor(checkpoint, records, chain, "p2"),
                "historicalNote": sorted(set(historical_outputs)),
                "outputPartition": partitions,
                "logicalSubmitter": first,
                "networkEndpointIdentity": "unmeasured",
            },
        })
    unique_topologies = {json.dumps(record["chains"], sort_keys=True) for record in records}
    if checkpoint == "pre-cashout":
        complete = len(records) * len(schedules()) * 16 * amount_pair_count(0) * amount_pair_count(1)
    elif checkpoint == "target-cashout":
        complete = sum(record["weight"] for record in records) * len(schedules()) * 16
    else:
        complete = len(records) * len(schedules()) * 16
    return {
        "chains": chains,
        "joint": {
            "topologyCount": len(unique_topologies),
            "scheduleMappingCount": len(schedules()),
            "completeCompatibleHistoryCount": complete,
        },
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: observer.py PUBLIC_RUN_DIR PREDICTIONS.json")
    root = Path(sys.argv[1])
    output = Path(sys.argv[2])
    seal = output.with_suffix(output.suffix + ".sha256")
    if output.exists() or seal.exists():
        raise SystemExit("prediction output already exists")
    ledger, aux, events = load_public(root)
    credits, historical_outputs, exits = public_material(aux, events)
    pre = pre_records()
    checkpoints = {}
    for checkpoint in ("pre-cashout", "target-cashout", "full-cashout"):
        by_observer = {}
        for observer in OBSERVERS:
            known = observer.endswith("-known")
            if checkpoint == "pre-cashout":
                records = pre
            elif checkpoint == "target-cashout":
                records = target_records(exits, aux, known)
            else:
                records = full_records(exits, aux, known)
            by_observer[observer] = project(checkpoint, records, credits, historical_outputs)
        checkpoints[checkpoint] = by_observer
    predictions = {
        "schema": "wallet-local-shared-history-predictions-v1",
        "experiment": ledger["experiment"],
        "selectionSha256": ledger["selectionSha256"],
        "privateWorkloadSha256": ledger["privateWorkloadSha256"],
        "coverage": {"acceptedOperations": 16, "serviceCaptures": 16, "complete": True},
        "observerAssumptions": {
            "commitmentsNullifiersAndCiphertextsOpaque": True,
            "relayTokensHaveNoIdentityMapping": True,
            "networkEndpointIdentity": "unmeasured",
            "allSelectionRulesPublic": True,
        },
        "checkpoints": checkpoints,
    }
    output.write_text(json.dumps(predictions, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256(canonical(predictions)).hexdigest()
    seal.write_text(digest + "\n")
    print(json.dumps({"predictions": str(output), "canonicalSha256": digest}))


if __name__ == "__main__":
    main()
