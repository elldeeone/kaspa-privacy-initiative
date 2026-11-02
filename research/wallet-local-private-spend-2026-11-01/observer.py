#!/usr/bin/env python3
"""Joint observer enumeration for continued private spending and later exits."""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
from pathlib import Path


LABELS = ["A", "B", "C", "D", "E", "F"]


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def hex_bytes(value) -> str:
    return bytes(value).hex()


def statement(event: dict) -> dict:
    return event["operation"]["statement"]


def validate_capture(arm_dir: Path, event: dict) -> None:
    capture = load(arm_dir / event["capture"])
    raw = bytes.fromhex(capture["requestRawHex"])
    request = capture["request"]
    if len(raw) != capture["requestBytes"]:
        raise ValueError("service request length")
    if hashlib.sha256(raw).hexdigest() != capture["requestSha256"]:
        raise ValueError("service request hash")
    if json.loads(raw) != request or request["operation"] != event["operation"]:
        raise ValueError("service request operation")
    if set(request) != {"schema", "trial", "ordinal", "relayToken", "operation"}:
        raise ValueError("unexpected service request field")


def contact_maps(aux: dict):
    forward = {label: set() for label in LABELS}
    for left, right in aux["contactEdges"]:
        forward[left].add(right)
        forward[right].add(left)
    return forward


def interval(minimum: int, maximum: int) -> dict:
    if maximum < minimum:
        return {"kind": "integer-interval", "minimum": 0, "maximum": -1, "count": 0}
    return {
        "kind": "integer-interval",
        "minimum": minimum,
        "maximum": maximum,
        "count": maximum - minimum + 1,
    }


def dedupe(values: list) -> list:
    return [json.loads(raw) for raw in sorted({json.dumps(value, sort_keys=True) for value in values})]


def base_candidates(events: list[dict], aux: dict):
    credits = [event for event in events if statement(event)["kind"] == 1]
    transfers = [event for event in events if statement(event)["kind"] == 2]
    owner_map = aux["depositOwnerIdentity"]
    credit_notes = []
    for event in credits:
        item = statement(event)
        owner_hash = hex_bytes(item["deposit_owner"])
        credit_notes.append(
            {
                "commitment": hex_bytes(item["outputs"][0]),
                "owner": owner_map[owner_hash],
                "value": item["deposit_value"],
            }
        )
    return credits, transfers, credit_notes


def pre_continued(events: list[dict], aux: dict) -> dict:
    _, transfers, credits = base_candidates(events, aux)
    if len(transfers) != 2 or len(credits) != 2:
        raise ValueError("continued pre structure")
    contacts = contact_maps(aux)
    senders = sorted(item["owner"] for item in credits)
    first_recipients = sorted(
        {candidate for sender in senders for candidate in contacts[sender] if candidate in {"C", "D"}}
    )
    second_recipients = sorted(
        {
            candidate
            for first in first_recipients
            for candidate in contacts[first]
            if candidate in {"E", "F"}
        }
    )
    max_input = max(item["value"] for item in credits)
    first_partitions = [
        {"paymentOutputIndex": 0, "changeOutputIndex": 1},
        {"paymentOutputIndex": 1, "changeOutputIndex": 0},
    ]
    second_partitions = list(first_partitions)
    chains = [
        {"firstSender": sender, "firstRecipient": first, "secondRecipient": second}
        for sender in senders
        for first in first_recipients
        if first in contacts[sender]
        for second in second_recipients
        if second in contacts[first]
    ]
    amount_pair_count = sum(
        (item["value"] - 1) * (item["value"] - 2) // 2 for item in credits
    )
    complete_count = amount_pair_count * len(first_recipients) * len(second_recipients) * 4
    return {
        "firstPayment": {
            "sender": senders,
            "recipient": first_recipients,
            "amountSompi": interval(2, max_input - 1),
            "historicalNote": [item["commitment"] for item in credits],
            "outputPartition": first_partitions,
            "endpointIdentity": senders,
            "relationship": [
                {"sender": sender, "recipient": recipient}
                for sender in senders
                for recipient in first_recipients
                if recipient in contacts[sender]
            ],
        },
        "secondPayment": {
            "sender": first_recipients,
            "recipient": second_recipients,
            "amountSompi": interval(1, max_input - 2),
            "historicalNote": [hex_bytes(value) for value in transfers[0]["operation"]["statement"]["outputs"]],
            "outputPartition": second_partitions,
            "endpointIdentity": first_recipients,
            "relationship": [
                {"sender": sender, "recipient": recipient}
                for sender in first_recipients
                for recipient in second_recipients
                if recipient in contacts[sender]
            ],
        },
        "jointRelationshipChain": chains,
        "completeStructuralAssignmentCount": complete_count,
    }


def identity_compatible(exit_event: dict, expected: str, aux: dict) -> bool:
    destination = hex_bytes(statement(exit_event)["exit_destination"])
    known = aux["knownExitDestinationIdentity"].get(destination)
    return known is None or known == expected


def pre_control(events: list[dict], aux: dict) -> dict:
    _, transfers, credits = base_candidates(events, aux)
    immediate = [event for event in events if event["label"] == "exit-immediate"]
    if len(transfers) != 1 or len(immediate) != 1:
        raise ValueError("control pre structure")
    exit_event = immediate[0]
    amount = statement(exit_event)["exit_value"]
    contacts = contact_maps(aux)
    historical = [item for item in credits if item["value"] > amount]
    senders = sorted(item["owner"] for item in historical)
    recipients = sorted(
        {
            recipient
            for sender in senders
            for recipient in contacts[sender]
            if recipient in {"C", "D"} and identity_compatible(exit_event, recipient, aux)
        }
    )
    partitions = [
        {"paymentOutputIndex": 0, "changeOutputIndex": 1},
        {"paymentOutputIndex": 1, "changeOutputIndex": 0},
    ]
    return {
        "firstPayment": {
            "sender": senders,
            "recipient": recipients,
            "amountSompi": {"kind": "set", "values": [amount], "count": 1},
            "historicalNote": [item["commitment"] for item in historical],
            "outputPartition": partitions,
            "endpointIdentity": senders,
            "relationship": [
                {"sender": sender, "recipient": recipient}
                for sender in senders
                for recipient in recipients
                if recipient in contacts[sender]
            ],
        },
        "secondPayment": None,
        "jointRelationshipChain": [
            {"firstSender": sender, "firstRecipient": recipient}
            for sender in senders
            for recipient in recipients
            if recipient in contacts[sender]
        ],
        "completeStructuralAssignmentCount": len(historical) * len(recipients) * 2,
    }


def project_continued(records: list[dict], transfer1: dict) -> dict:
    first_partitions = dedupe(
        [
            {"paymentOutputIndex": record["firstPaymentOutputIndex"], "changeOutputIndex": 1 - record["firstPaymentOutputIndex"]}
            for record in records
        ]
    )
    second_partitions = dedupe(
        [
            {"paymentOutputIndex": record["secondPaymentOutputIndex"], "changeOutputIndex": 1 - record["secondPaymentOutputIndex"]}
            for record in records
        ]
    )
    first_outputs = [hex_bytes(value) for value in statement(transfer1)["outputs"]]
    return {
        "firstPayment": {
            "sender": sorted({record["firstSender"] for record in records}),
            "recipient": sorted({record["firstRecipient"] for record in records}),
            "amountSompi": {"kind": "set", "values": sorted({record["p1"] for record in records}), "count": len({record["p1"] for record in records})},
            "historicalNote": sorted({record["historicalCredit"] for record in records}),
            "outputPartition": first_partitions,
            "endpointIdentity": sorted({record["firstSender"] for record in records}),
            "relationship": dedupe(
                [{"sender": record["firstSender"], "recipient": record["firstRecipient"]} for record in records]
            ),
        },
        "secondPayment": {
            "sender": sorted({record["firstRecipient"] for record in records}),
            "recipient": sorted({record["secondRecipient"] for record in records}),
            "amountSompi": {"kind": "set", "values": sorted({record["p2"] for record in records}), "count": len({record["p2"] for record in records})},
            "historicalNote": sorted({first_outputs[record["firstPaymentOutputIndex"]] for record in records}),
            "outputPartition": second_partitions,
            "endpointIdentity": sorted({record["firstRecipient"] for record in records}),
            "relationship": dedupe(
                [{"sender": record["firstRecipient"], "recipient": record["secondRecipient"]} for record in records]
            ),
        },
        "jointRelationshipChain": dedupe(
            [
                {
                    "firstSender": record["firstSender"],
                    "firstRecipient": record["firstRecipient"],
                    "secondRecipient": record["secondRecipient"],
                }
                for record in records
            ]
        ),
        "completeStructuralAssignmentCount": len(records),
    }


def post_continued(events: list[dict], aux: dict) -> dict:
    _, transfers, credits = base_candidates(events, aux)
    exits = [event for event in events if statement(event)["kind"] == 3]
    if len(transfers) != 2 or len(exits) != 4:
        raise ValueError("continued post structure")
    contacts = contact_maps(aux)
    credit_by_owner = {item["owner"]: item for item in credits}
    records = []
    roles = ["untouched", "firstChange", "secondPayment", "secondChange"]
    for sender in ("A", "B"):
        other = "B" if sender == "A" else "A"
        selected_value = credit_by_owner[sender]["value"]
        other_value = credit_by_owner[other]["value"]
        for first_recipient in ("C", "D"):
            if first_recipient not in contacts[sender]:
                continue
            for second_recipient in ("E", "F"):
                if second_recipient not in contacts[first_recipient]:
                    continue
                expected_owners = [other, sender, second_recipient, first_recipient]
                for permutation in itertools.permutations(exits):
                    assigned = dict(zip(roles, permutation))
                    if any(
                        not identity_compatible(event, owner, aux)
                        for event, owner in zip(permutation, expected_owners)
                    ):
                        continue
                    values = {role: statement(event)["exit_value"] for role, event in assigned.items()}
                    if values["untouched"] != other_value:
                        continue
                    p2 = values["secondPayment"]
                    p1 = p2 + values["secondChange"]
                    if p2 <= 0 or p1 <= p2 or p1 >= selected_value:
                        continue
                    if values["firstChange"] != selected_value - p1:
                        continue
                    for first_index in (0, 1):
                        for second_index in (0, 1):
                            records.append(
                                {
                                    "firstSender": sender,
                                    "firstRecipient": first_recipient,
                                    "secondRecipient": second_recipient,
                                    "p1": p1,
                                    "p2": p2,
                                    "historicalCredit": credit_by_owner[sender]["commitment"],
                                    "firstPaymentOutputIndex": first_index,
                                    "secondPaymentOutputIndex": second_index,
                                    "exitOrdinals": {role: assigned[role]["ordinal"] for role in roles},
                                }
                            )
    return project_continued(dedupe(records), transfers[0])


def project_control(records: list[dict]) -> dict:
    partitions = dedupe(
        [
            {"paymentOutputIndex": record["paymentOutputIndex"], "changeOutputIndex": 1 - record["paymentOutputIndex"]}
            for record in records
        ]
    )
    amounts = sorted({record["p1"] for record in records})
    return {
        "firstPayment": {
            "sender": sorted({record["firstSender"] for record in records}),
            "recipient": sorted({record["firstRecipient"] for record in records}),
            "amountSompi": {"kind": "set", "values": amounts, "count": len(amounts)},
            "historicalNote": sorted({record["historicalCredit"] for record in records}),
            "outputPartition": partitions,
            "endpointIdentity": sorted({record["firstSender"] for record in records}),
            "relationship": dedupe(
                [{"sender": record["firstSender"], "recipient": record["firstRecipient"]} for record in records]
            ),
        },
        "secondPayment": None,
        "jointRelationshipChain": dedupe(
            [{"firstSender": record["firstSender"], "firstRecipient": record["firstRecipient"]} for record in records]
        ),
        "completeStructuralAssignmentCount": len(records),
    }


def post_control(events: list[dict], aux: dict) -> dict:
    _, transfers, credits = base_candidates(events, aux)
    immediate = [event for event in events if event["label"] == "exit-immediate"]
    eventual = [event for event in events if event["label"] == "exit-eventual"]
    if len(transfers) != 1 or len(immediate) != 1 or len(eventual) != 2:
        raise ValueError("control post structure")
    amount = statement(immediate[0])["exit_value"]
    contacts = contact_maps(aux)
    credit_by_owner = {item["owner"]: item for item in credits}
    records = []
    for sender in ("A", "B"):
        other = "B" if sender == "A" else "A"
        selected_value = credit_by_owner[sender]["value"]
        if not (0 < amount < selected_value):
            continue
        for recipient in ("C", "D"):
            if recipient not in contacts[sender] or not identity_compatible(immediate[0], recipient, aux):
                continue
            for permutation in itertools.permutations(eventual):
                if not identity_compatible(permutation[0], other, aux):
                    continue
                if not identity_compatible(permutation[1], sender, aux):
                    continue
                if statement(permutation[0])["exit_value"] != credit_by_owner[other]["value"]:
                    continue
                if statement(permutation[1])["exit_value"] != selected_value - amount:
                    continue
                for payment_index in (0, 1):
                    records.append(
                        {
                            "firstSender": sender,
                            "firstRecipient": recipient,
                            "p1": amount,
                            "historicalCredit": credit_by_owner[sender]["commitment"],
                            "paymentOutputIndex": payment_index,
                            "exitOrdinals": {
                                "immediatePayment": immediate[0]["ordinal"],
                                "untouched": permutation[0]["ordinal"],
                                "firstChange": permutation[1]["ordinal"],
                            },
                        }
                    )
    return project_control(dedupe(records))


def enumerate_arm(arm_dir: Path, aux: dict, strict: bool = True) -> dict:
    summary = load(arm_dir / "arm.json")
    checkpoint = load(arm_dir / "checkpoint-pre-cashout.json")
    events = [load(path) for path in sorted(arm_dir.glob("event-*.json"))]
    captures = sorted(arm_dir.glob("capture-*.json"))
    for event in events:
        validate_capture(arm_dir, event)
    expected_count = 8 if summary["arm"] == "continued" else 6
    coverage = {
        "eventCount": len(events),
        "captureCount": len(captures),
        "expectedEventCount": expected_count,
        "preCashoutEventCount": checkpoint["eventCount"],
        "summaryOrdinalsMatch": summary["eventOrdinals"] == [event["ordinal"] for event in events],
        "allAccepted": all(event["accepted"] is True for event in events),
        "zeroFinalReserveAndLiability": summary["final"]["reserveSompi"] == 0
        and summary["final"]["privateLiabilitySompi"] == 0,
    }
    coverage["complete"] = (
        len(events) == expected_count
        and len(captures) == expected_count
        and coverage["summaryOrdinalsMatch"]
        and coverage["allAccepted"]
        and coverage["zeroFinalReserveAndLiability"]
    )
    if strict and not coverage["complete"]:
        raise ValueError(f"{arm_dir}: incomplete coverage")
    pre_events = events[: checkpoint["eventCount"]]
    if summary["arm"] == "continued":
        pre = pre_continued(pre_events, aux)
        post = post_continued(events, aux)
    else:
        pre = pre_control(pre_events, aux)
        post = post_control(events, aux)
    return {
        "run": aux["run"],
        "pair": summary["pair"],
        "arm": summary["arm"],
        "coverage": coverage,
        "checkpoints": {
            "pre-cashout": {"O-public": pre, "O-service": json.loads(json.dumps(pre))},
            "post-cashout": {"O-public": post, "O-service": json.loads(json.dumps(post))},
        },
    }


def predict(public_root: Path, strict: bool = True) -> dict:
    aux_index = load(public_root / "auxiliary.json")
    aux_by_run = {item["run"]: item for item in aux_index["runs"]}
    runs = []
    for pair in ("pair-00", "pair-01"):
        for arm in ("continued", "control"):
            run = f"{pair}/{arm}"
            runs.append(enumerate_arm(public_root / pair / arm, aux_by_run[run], strict=strict))
    return {
        "schema": "wallet-local-private-spend-sealed-predictions-v1",
        "experiment": "wallet-local-private-spend-v2",
        "truthRead": False,
        "jointHistoryEnumeration": True,
        "runs": runs,
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: observer.py PUBLIC_DIR PREDICTIONS.json")
    public_root = Path(sys.argv[1])
    output = Path(sys.argv[2])
    sidecar = output.with_suffix(output.suffix + ".sha256")
    if output.exists() or sidecar.exists():
        raise SystemExit("sealed prediction output exists")
    result = predict(public_root)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256(canonical(result)).hexdigest()
    sidecar.write_text(digest + "\n")
    print(json.dumps({"predictions": str(output), "canonicalSha256": digest}))


if __name__ == "__main__":
    main()
