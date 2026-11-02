#!/usr/bin/env python3
"""Enumerate privacy candidates from admitted observations without private truth."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path


EXPECTED_KINDS = [1, 1, 2, 3]


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def operation(event):
    return event["operation"]


def validate_capture(public_trial: Path, event: dict) -> None:
    capture = load(public_trial / event["capture"])
    raw = bytes.fromhex(capture["requestRawHex"])
    request = capture["request"]
    if len(raw) != capture["requestBytes"]:
        raise ValueError("capture request length mismatch")
    if hashlib.sha256(raw).hexdigest() != capture["requestSha256"]:
        raise ValueError("capture request hash mismatch")
    if json.loads(raw) != request:
        raise ValueError("capture raw request mismatch")
    if request["trial"] != event["trial"] or request["ordinal"] != event["ordinal"]:
        raise ValueError("capture trial/ordinal mismatch")
    if request["operation"] != event["operation"]:
        raise ValueError("capture operation mismatch")
    if set(request) != {"schema", "trial", "ordinal", "relayToken", "operation"}:
        raise ValueError("unexpected service request fields")


def enumerate_trial(public_trial: Path, aux: dict, strict: bool = True) -> dict:
    summary = load(public_trial / "trial.json")
    events = [load(path) for path in sorted(public_trial.glob("event-*.json"))]
    captures = sorted(public_trial.glob("capture-*.json"))
    kinds = [operation(event)["statement"]["kind"] for event in events]
    coverage = {
        "eventCount": len(events),
        "captureCount": len(captures),
        "expectedKinds": kinds == EXPECTED_KINDS,
        "allAccepted": all(event.get("accepted") is True for event in events),
        "summaryOrdinalsMatch": summary.get("events")
        == [event.get("ordinal") for event in events],
    }
    for event in events:
        validate_capture(public_trial, event)
    coverage["complete"] = (
        coverage["eventCount"] == 4
        and coverage["captureCount"] == 4
        and coverage["expectedKinds"]
        and coverage["allAccepted"]
        and coverage["summaryOrdinalsMatch"]
    )
    if strict and not coverage["complete"]:
        raise ValueError(f"{public_trial.name}: incomplete required observation")
    credits = [event for event in events if operation(event)["statement"]["kind"] == 1]
    transfer = next(event for event in events if operation(event)["statement"]["kind"] == 2)
    exit_event = next(event for event in events if operation(event)["statement"]["kind"] == 3)
    exit_value = operation(exit_event)["statement"]["exit_value"]
    exit_destination = bytes(operation(exit_event)["statement"]["exit_destination"]).hex()
    owner_map = aux["depositOwnerIdentity"]

    historical = []
    for event in credits:
        statement = operation(event)["statement"]
        owner = bytes(statement["deposit_owner"]).hex()
        if statement["deposit_value"] > exit_value and owner in owner_map:
            historical.append(
                {
                    "commitment": bytes(statement["outputs"][0]).hex(),
                    "owner": owner_map[owner],
                    "creditedValueSompi": statement["deposit_value"],
                }
            )
    senders = sorted({item["owner"] for item in historical})

    endpoint_identities = set()
    for event in events:
        capture = load(public_trial / event["capture"])
        identity = capture["request"].get("authenticatedEndpointIdentity")
        if identity:
            endpoint_identities.add(identity)
    service_senders = senders
    if endpoint_identities:
        service_senders = sorted(set(senders) & endpoint_identities)

    contacts = {sender: set() for sender in aux["identityUniverse"]}
    for left, right in aux["contactEdges"]:
        contacts.setdefault(left, set()).add(right)
        contacts.setdefault(right, set()).add(left)
    recipients = sorted(
        {
            candidate
            for sender in senders
            for candidate in contacts.get(sender, set())
            if candidate in {"C", "D"}
        }
    )
    known_exit = aux["knownExitDestinationIdentity"].get(exit_destination)
    if known_exit is not None:
        recipients = [candidate for candidate in recipients if candidate == known_exit]

    partitions = [
        {"paymentOutputIndex": 0, "changeOutputIndex": 1},
        {"paymentOutputIndex": 1, "changeOutputIndex": 0},
    ]
    if "paymentOutputIndex" in transfer:
        index = transfer["paymentOutputIndex"]
        partitions = [{"paymentOutputIndex": index, "changeOutputIndex": 1 - index}]

    def assignments(sender_candidates):
        return [
            {
                "sender": note["owner"],
                "recipient": recipient,
                "paymentSompi": exit_value,
                "historicalNote": note["commitment"],
                **partition,
            }
            for note in historical
            if note["owner"] in sender_candidates
            for recipient in recipients
            for partition in partitions
        ]

    public = {
        "sender": senders,
        "recipient": recipients,
        "paymentSompi": [exit_value],
        "historicalNote": [item["commitment"] for item in historical],
        "outputPartition": partitions,
        "completeAssignment": assignments(senders),
    }
    service = copy.deepcopy(public)
    service["sender"] = service_senders
    service["historicalNote"] = [
        item["commitment"] for item in historical if item["owner"] in service_senders
    ]
    service["completeAssignment"] = assignments(service_senders)
    return {
        "trial": public_trial.name,
        "coverage": coverage,
        "observed": {
            "transferWireSha256": transfer["wireSha256"],
            "exitValueSompi": exit_value,
            "exitDestination": exit_destination,
            "neutralRelayTokensOnly": not endpoint_identities,
        },
        "O-public": public,
        "O-service": service,
    }


def predict(public_root: Path, strict: bool = True) -> dict:
    aux_index = load(public_root / "auxiliary.json")
    aux = {item["trial"]: item for item in aux_index["trials"]}
    trial_dirs = sorted(path for path in public_root.glob("trial-*") if path.is_dir())
    if strict and [path.name for path in trial_dirs] != ["trial-00", "trial-01", "trial-02"]:
        raise ValueError("required trial set mismatch")
    results = [enumerate_trial(path, aux[path.name], strict=strict) for path in trial_dirs]
    return {
        "schema": "wallet-local-sealed-observer-predictions-v1",
        "experiment": "wallet-local-practical-privacy-v2",
        "truthRead": False,
        "observerAlgorithm": "frozen-enumeration-v1",
        "trials": results,
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: observer.py PUBLIC_DIR PREDICTIONS.json")
    public_root = Path(sys.argv[1])
    output = Path(sys.argv[2])
    if output.exists() or output.with_suffix(output.suffix + ".sha256").exists():
        raise SystemExit("sealed prediction output already exists")
    result = predict(public_root)
    raw = canonical(result)
    output.write_bytes(json.dumps(result, indent=2, sort_keys=True).encode() + b"\n")
    digest = hashlib.sha256(raw).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(digest + "\n")
    print(json.dumps({"predictions": str(output), "canonicalSha256": digest}))


if __name__ == "__main__":
    main()
