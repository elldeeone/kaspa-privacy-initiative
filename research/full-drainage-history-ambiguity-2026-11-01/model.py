#!/usr/bin/env python3
"""Exhaustive finite constraint model for full-drainage gross history ambiguity."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import sys
from pathlib import Path


UNIT = 10_000_000
ACTORS = ("A", "B", "M", "S")
ALL_EDGES = tuple((left, right) for left in ACTORS for right in ACTORS if left != right)
PLAUSIBLE_EDGES = (("A", "M"), ("B", "M"), ("M", "S"), ("A", "S"))
INITIAL = (("A", 10), ("B", 10))
KNOWN_TERMINAL = (("A", 6), ("B", 8), ("M", 2), ("M", 3), ("S", 1))
UNMAPPED_TERMINAL_VALUES = (1, 2, 3, 6, 8)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def enumerate_sequences(initial, edges, steps, terminal):
    by_sender = defaultdict(list)
    for sender, recipient in edges:
        by_sender[sender].append(recipient)
    results = []

    def visit(notes, history):
        if len(history) == steps:
            if terminal(notes):
                results.append(tuple(history))
            return
        used_notes = set()
        for index, (sender, value) in enumerate(notes):
            if (sender, value) in used_notes:
                continue
            used_notes.add((sender, value))
            for recipient in by_sender[sender]:
                for amount in range(1, value):
                    next_notes = list(notes)
                    next_notes.pop(index)
                    next_notes.extend(((recipient, amount), (sender, value - amount)))
                    next_notes.sort()
                    visit(tuple(next_notes), (*history, (sender, recipient, amount)))

    visit(tuple(sorted(initial)), ())
    return results


def gross(history):
    return tuple(sorted(history))


def sompi_history(history):
    return [
        {"sender": sender, "recipient": recipient, "amountSompi": amount * UNIT}
        for sender, recipient, amount in history
    ]


def summarize(sequences, include_histories=False):
    histories = sorted({gross(sequence) for sequence in sequences})
    relationship_amounts = defaultdict(set)
    relationships_by_history = []
    for history in histories:
        relationships = set()
        for sender, recipient, amount in history:
            relationship_amounts[(sender, recipient)].add(amount * UNIT)
            relationships.add((sender, recipient))
        relationships_by_history.append(relationships)
    union = set().union(*relationships_by_history) if relationships_by_history else set()
    intersection = set.intersection(*relationships_by_history) if relationships_by_history else set()
    result = {
        "compatibleEventSequenceCount": len(sequences),
        "uniqueGrossPaymentHistoryCount": len(histories),
        "grossHistorySha256": [hashlib.sha256(canonical(sompi_history(history))).hexdigest() for history in histories],
        "relationshipCandidates": [
            {
                "sender": sender,
                "recipient": recipient,
                "amountSompiCandidates": sorted(relationship_amounts[(sender, recipient)]),
                "amountCandidateCount": len(relationship_amounts[(sender, recipient)]),
                "presentInEveryGrossHistory": (sender, recipient) in intersection,
            }
            for sender, recipient in sorted(union)
        ],
        "relationshipSetVaries": len({tuple(sorted(items)) for items in relationships_by_history}) > 1,
        "individualPaymentAmountVaries": any(len(values) > 1 for values in relationship_amounts.values()),
        "eventPositionUsedAsPrivacyMetric": False,
        "noteOrCommitmentAssignmentUsedAsPrivacyMetric": False,
    }
    if include_histories:
        result["grossPaymentHistories"] = [sompi_history(history) for history in histories]
    return result


def known_terminal(notes):
    return tuple(sorted(notes)) == KNOWN_TERMINAL


def unmapped_terminal(notes):
    return tuple(sorted(value for _, value in notes)) == UNMAPPED_TERMINAL_VALUES


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: model.py OUTPUT.json")
    output = Path(sys.argv[1])
    if output.exists():
        raise SystemExit("output exists")

    protocol_known_sequences = enumerate_sequences(INITIAL, ALL_EDGES, 3, known_terminal)
    protocol_unmapped_sequences = enumerate_sequences(INITIAL, ALL_EDGES, 3, unmapped_terminal)
    plausible_sequences = enumerate_sequences(INITIAL, PLAUSIBLE_EDGES, 3, known_terminal)
    strong_sequences = [sequence for sequence in plausible_sequences if ("M", "S", 1) in sequence]

    witness_one = gross((("A", "M", 4), ("B", "M", 2), ("M", "S", 1)))
    witness_two = gross((("A", "M", 3), ("A", "S", 1), ("B", "M", 2)))
    plausible_gross = {gross(sequence) for sequence in plausible_sequences}
    if witness_one not in plausible_gross or witness_two not in plausible_gross:
        raise SystemExit("frozen witness histories not retained")

    failure_known = enumerate_sequences((("A", 10),), (("A", "B"),), 1, lambda notes: tuple(sorted(notes)) == (("A", 6), ("B", 4)))
    failure_unmapped = enumerate_sequences((("A", 10),), (("A", "B"),), 1, lambda notes: tuple(sorted(value for _, value in notes)) == (4, 6))

    plausible_summary = summarize(plausible_sequences, include_histories=True)
    failure_known_summary = summarize(failure_known, include_histories=True)
    failure_unmapped_summary = summarize(failure_unmapped, include_histories=True)
    candidate_passed = (
        plausible_summary["uniqueGrossPaymentHistoryCount"] >= 2
        and plausible_summary["relationshipSetVaries"]
        and plausible_summary["individualPaymentAmountVaries"]
        and failure_known_summary["uniqueGrossPaymentHistoryCount"] == 1
    )

    result = {
        "schema": "full-drainage-history-ambiguity-model-v1",
        "selectionSha256": "bec548ad0a97b2b6320560495ba7d648b7d2d655bc78505d445f55791b1d24ef",
        "unitSompi": UNIT,
        "sampling": "none; exhaustive finite enumeration",
        "cryptographicOpacityAssumed": True,
        "views": {
            "protocolKnown": summarize(protocol_known_sequences),
            "protocolUnmapped": summarize(protocol_unmapped_sequences),
            "plausibleExternalKnown": plausible_summary,
            "strongExternalWorkload": summarize(strong_sequences, include_histories=True),
        },
        "publicEvidence": {
            "deposits": [{"owner": owner, "amountSompi": value * UNIT} for owner, value in INITIAL],
            "privateTransferCount": 3,
            "knownOwnerExits": [{"owner": owner, "amountSompi": value * UNIT} for owner, value in KNOWN_TERMINAL],
            "unmappedExitAmountsSompi": [value * UNIT for value in UNMAPPED_TERMINAL_VALUES],
            "knownOwnerNetBalancesSompi": {"A": 6 * UNIT, "B": 8 * UNIT, "M": 5 * UNIT, "S": UNIT},
            "liabilityAfterAllExitsSompi": 0,
        },
        "explicitCompatibleWitnesses": [sompi_history(witness_one), sompi_history(witness_two)],
        "mergeProjection": {
            "implementedByCurrentWallet": False,
            "additionalPrivateOperationCount": 1,
            "knownOwnerExitsAfterMerge": [
                {"owner": "A", "amountSompi": 6 * UNIT},
                {"owner": "B", "amountSompi": 8 * UNIT},
                {"owner": "M", "amountSompi": 5 * UNIT},
                {"owner": "S", "amountSompi": UNIT},
            ],
            "compatibleGrossPaymentHistoryCount": plausible_summary["uniqueGrossPaymentHistoryCount"],
            "grossHistoryAmbiguityPreserved": plausible_summary["uniqueGrossPaymentHistoryCount"] >= 2,
            "terminalExitGranularity": "one net exit per owner in this projection",
        },
        "failureControl": {
            "knownOwner": failure_known_summary,
            "unmappedOwner": failure_unmapped_summary,
            "knownOwnerUniqueExpected": True,
            "knownOwnerUniqueObserved": failure_known_summary["uniqueGrossPaymentHistoryCount"] == 1,
        },
        "decision": {
            "candidatePossibilityDemonstrated": candidate_passed,
            "universalWithdrawalUnlinkabilityDemonstrated": False,
            "ordinaryUserPrivacyMeasured": False,
            "equalPosteriorLikelihoodClaimed": False,
            "netBalanceDisclosureSeparatedFromGrossPaymentAmbiguity": True,
        },
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not candidate_passed:
        raise SystemExit("frozen candidate/control decision failed")
    print(json.dumps({
        "output": str(output),
        "plausibleGrossHistories": plausible_summary["uniqueGrossPaymentHistoryCount"],
        "strongGrossHistories": result["views"]["strongExternalWorkload"]["uniqueGrossPaymentHistoryCount"],
        "failureKnownGrossHistories": failure_known_summary["uniqueGrossPaymentHistoryCount"],
    }))


if __name__ == "__main__":
    main()
