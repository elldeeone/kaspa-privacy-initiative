#!/usr/bin/env python3
"""Score public transcript shape without reading execution truth or wallet stores."""

from __future__ import annotations

from collections import defaultdict
import argparse
import hashlib
import json
from pathlib import Path


UNIT = 10_000_000
ACTORS = ("A", "B", "M", "S")
PLAUSIBLE_EDGES = (("A", "M"), ("B", "M"), ("M", "S"), ("A", "S"))
ALL_EDGES = tuple((left, right) for left in ACTORS for right in ACTORS if left != right)
INITIAL = (("A", 10), ("B", 10))
KNOWN_TERMINAL = (("A", 6), ("B", 8), ("M", 2), ("M", 3), ("S", 1))


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def enumerate_sequences(edges, terminal, steps=3, initial=INITIAL):
    by_sender = defaultdict(list)
    for sender, recipient in edges:
        by_sender[sender].append(recipient)
    results = []

    def visit(notes, history):
        if len(history) == steps:
            if terminal(notes):
                results.append(tuple(history))
            return
        used = set()
        for index, (sender, value) in enumerate(notes):
            if (sender, value) in used:
                continue
            used.add((sender, value))
            for recipient in by_sender[sender]:
                for amount in range(1, value):
                    next_notes = list(notes)
                    next_notes.pop(index)
                    next_notes.extend(((recipient, amount), (sender, value - amount)))
                    visit(tuple(sorted(next_notes)), (*history, (sender, recipient, amount)))

    visit(tuple(sorted(initial)), ())
    return results


def gross(sequence):
    return tuple(sorted(sequence))


def history_json(history):
    return [
        {"sender": sender, "recipient": recipient, "amountSompi": amount * UNIT}
        for sender, recipient, amount in history
    ]


def summary(sequences):
    histories = sorted({gross(sequence) for sequence in sequences})
    return {
        "compatibleEventSequences": len(sequences),
        "uniqueGrossPaymentHistories": len(histories),
        "grossHistories": [history_json(history) for history in histories],
        "grossHistorySha256": [hashlib.sha256(canonical(history_json(history))).hexdigest() for history in histories],
        "relationshipSetVaries": len({tuple(sorted((sender, recipient) for sender, recipient, _ in history)) for history in histories}) > 1,
        "individualAmountVaries": any(
            len({amount for history in histories for sender, recipient, amount in history if (sender, recipient) == edge}) > 1
            for edge in PLAUSIBLE_EDGES
        ),
    }


def load(path: Path):
    return json.loads(path.read_text())


def trial_projection(trial: Path) -> dict:
    events = [load(path) for path in sorted(trial.glob("event-*.json"))]
    if len(events) != 10:
        raise ValueError(f"{trial.name}: event count")
    kinds = [event["publicMetadata"]["kind"] for event in events]
    if kinds != [1, 1, 2, 2, 2, 3, 3, 3, 3, 3]:
        raise ValueError(f"{trial.name}: operation shape")
    if any(event["publicMetadata"]["feeSompi"] != 0 for event in events):
        raise ValueError(f"{trial.name}: nonzero application fee")
    if any(event["publicMetadata"]["proofBytes"] != 128 for event in events):
        raise ValueError(f"{trial.name}: proof size")
    if any(event["publicMetadata"]["ciphertextBytes"] != [185, 185] for event in events[2:5]):
        raise ValueError(f"{trial.name}: transfer ciphertext shape")
    if any(event["publicMetadata"]["ciphertextBytes"] != [0, 0] for event in events[5:]):
        raise ValueError(f"{trial.name}: exit ciphertext shape")
    deposits = load(trial / "deposits.json")
    if sorted(item["amountSompi"] for item in deposits) != [100_000_000, 100_000_000]:
        raise ValueError(f"{trial.name}: deposit values")
    known = load(trial / "known-owner-evidence.json")
    exits = []
    for event in events[5:]:
        metadata = event["publicMetadata"]
        exits.append((known["exitOwnerByDestination"][metadata["exitDestination"]], metadata["exitValueSompi"]))
    if sorted(exits) != sorted((owner, value * UNIT) for owner, value in KNOWN_TERMINAL):
        raise ValueError(f"{trial.name}: known exits")
    relays = {}
    for service in ("default", "replacement"):
        captures = [load(path) for path in sorted((trial / f"relay-{service}").glob("capture-*.json"))]
        relays[service] = {
            "requests": len(captures),
            "requestBytes": [capture["requestBytes"] for capture in captures],
            "receivedMonotonicNs": [capture["receivedMonotonicNs"] for capture in captures],
            "canonicalRequestSha256": [capture["canonicalRequestSha256"] for capture in captures],
            "walletIdentityFieldObserved": False,
        }
    nullifiers = [event["publicMetadata"]["nullifier"] for event in events if event["publicMetadata"]["kind"] in (2, 3)]
    commitments = [item for event in events for item in event["publicMetadata"]["outputCommitments"] if item != "00" * 32]
    receipt = load(trial / "run-receipt.json")
    return {
        "alias": trial.name,
        "operationKinds": kinds,
        "wireBytesByKind": {
            str(kind): sorted({event["publicMetadata"]["wireBytes"] for event in events if event["publicMetadata"]["kind"] == kind})
            for kind in (1, 2, 3)
        },
        "knownOwnerExits": [{"owner": owner, "amountSompi": value} for owner, value in sorted(exits)],
        "allEconomicNullifiersDistinct": len(nullifiers) == len(set(nullifiers)),
        "allOutputCommitmentsDistinct": len(commitments) == len(set(commitments)),
        "relayEvidence": relays,
        "finalAccounting": receipt["finalAccounting"],
        "walletProofSeconds": receipt["walletProofSeconds"],
        "proofTimingClassification": "experiment telemetry, not a protocol or relay identity field",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("public_root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("output exists")
    root_summary = load(args.public_root / "summary.json")
    trials = [trial_projection(args.public_root / alias) for alias in root_summary["trialAliases"]]
    known_terminal = lambda notes: tuple(sorted(notes)) == KNOWN_TERMINAL
    unmapped_terminal = lambda notes: tuple(sorted(value for _, value in notes)) == (1, 2, 3, 6, 8)
    plausible_sequences = enumerate_sequences(PLAUSIBLE_EDGES, known_terminal)
    strong_sequences = [sequence for sequence in plausible_sequences if ("M", "S", 1) in sequence]
    protocol_known = enumerate_sequences(ALL_EDGES, known_terminal)
    protocol_unmapped = enumerate_sequences(ALL_EDGES, unmapped_terminal)
    sparse_known = enumerate_sequences(
        (("A", "B"),),
        lambda notes: tuple(sorted(notes)) == (("A", 6), ("B", 4)),
        steps=1,
        initial=(("A", 10),),
    )
    result = {
        "schema": "full-drainage-executed-public-score-v1",
        "publicOnly": True,
        "privateTruthRead": False,
        "literalCrossWorldByteEqualityClaimed": False,
        "cryptographicOpacityAssumedNotProved": True,
        "trialProjections": trials,
        "views": {
            "protocolKnownOwner": summary(protocol_known),
            "protocolUnmappedOwner": summary(protocol_unmapped),
            "plausibleKnownOwner": summary(plausible_sequences),
            "serviceKnownOwner": summary(plausible_sequences),
            "strongExternalWorkload": summary(strong_sequences),
            "sparseKnownOwnerFailure": summary(sparse_known),
        },
        "serviceConclusion": "The executed relay observed fixed operation shapes, request order/time, variable JSON request lengths and fresh tokens, but no wallet identity field. No frozen mapping from those measurements to a payer was available; they do not add a payment fact in this bounded score.",
        "decision": {
            "bothExecutedTrialsShareDeclaredFactShape": True,
            "boundedGrossHistoryAmbiguity": len({gross(sequence) for sequence in plausible_sequences}) == 2,
            "strongObserverDefeatsAmbiguity": len({gross(sequence) for sequence in strong_sequences}) == 1,
            "sparseFailureUnique": len({gross(sequence) for sequence in sparse_known}) == 1,
            "ordinaryUserPrivacyMeasured": False,
            "equalLikelihoodClaimed": False,
            "computationalIndistinguishabilityClaimed": False,
        },
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["decision"], sort_keys=True))


if __name__ == "__main__":
    main()
