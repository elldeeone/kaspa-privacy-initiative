#!/usr/bin/env python3
"""Score the actual TN10 transcript without reading private truth or wallets."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

UNIT = 10_000_000
ACTORS = ("A", "B", "M", "S")
PLAUSIBLE_EDGES = (("A", "M"), ("B", "M"), ("M", "S"), ("A", "S"))
ALL_EDGES = tuple((left, right) for left in ACTORS for right in ACTORS if left != right)
INITIAL = (("A", 10), ("B", 10))
KNOWN_TERMINAL = (("A", 6), ("B", 8), ("M", 2), ("M", 3), ("S", 1))


def load(path: Path):
    return json.loads(path.read_text())


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def hex_bytes(values) -> str:
    return bytes(values).hex()


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


def histories(sequences):
    unique = sorted({tuple(sorted(sequence)) for sequence in sequences})
    rendered = [
        [{"sender": sender, "recipient": recipient, "amountSompi": amount * UNIT} for sender, recipient, amount in history]
        for history in unique
    ]
    return {
        "compatibleEventSequences": len(sequences),
        "uniqueGrossPaymentHistories": len(unique),
        "grossHistories": rendered,
        "grossHistorySha256": [digest(value) for value in rendered],
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: score-live-tn10.py PRIVATE_RUN NEW_OUTPUT")
    run = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    if output.exists():
        raise SystemExit("output exists")
    public = run / "wallet-public"
    operations = [load(public / f"operation-{index:02}.json") for index in range(1, 11)]
    proof_reports = [load(public / f"operation-{index:02}-proof.json") for index in range(1, 11)]
    kinds = [operation["statement"]["kind"] for operation in operations]
    if kinds != [1, 1, 2, 2, 2, 3, 3, 3, 3, 3]:
        raise RuntimeError("unexpected operation shape")
    metadata = []
    for operation, proof in zip(operations, proof_reports, strict=True):
        statement = operation["statement"]
        metadata.append(
            {
                "kind": statement["kind"],
                "anchor": hex_bytes(statement["anchor"]),
                "nullifier": hex_bytes(statement["nullifier"]),
                "outputs": [hex_bytes(value) for value in statement["outputs"]],
                "exitDestination": hex_bytes(statement["exit_destination"]),
                "exitValueSompi": statement["exit_value"],
                "wireBytes": proof["wireBytes"],
                "proofSeconds": proof["proofSeconds"],
                "proofBytes": len(operation["proof"]),
                "ciphertextBytes": [len(value["ciphertext"]) for value in operation["deliveries"]],
            }
        )
    known = load(public / "known-owner-evidence.json")
    exits = [
        (known["exitOwnerByDestination"][row["exitDestination"]], row["exitValueSompi"])
        for row in metadata[5:]
    ]
    if sorted(exits) != sorted((owner, amount * UNIT) for owner, amount in KNOWN_TERMINAL):
        raise RuntimeError("known terminal exits differ from frozen score")
    accepted = []
    for label in [
        "deposit-a",
        "deposit-b",
        *[f"publish-{index:02}" for index in range(1, 11)],
        *[f"payout-{index:02}" for index in range(1, 6)],
    ]:
        record = load(run / f"{label}-accepted.json")
        accepted.append(
            {
                "label": label,
                "transactionId": record["transactionId"],
                "acceptingBlock": record["header"]["hash"],
                "timestamp": record["header"]["timestamp"],
            }
        )
    payloads = []
    for index in range(1, 11):
        record = load(run / f"publish-{index:02}-build/transaction.json")
        payloads.append({"ordinal": index, "bytes": len(record["transaction"]["payload"]) // 2})
    final = load(run / "batch-07-checkpoint/checkpoint.json")["accounting"]
    if any(final[key] != 0 for key in ("reserve_principal", "private_liability", "pending_deposits", "unpaid_exits", "outstanding_permission_rent_excluded")):
        raise RuntimeError("nonzero terminal accounting")
    plausible = enumerate_sequences(PLAUSIBLE_EDGES, lambda notes: tuple(sorted(notes)) == KNOWN_TERMINAL)
    strong = [sequence for sequence in plausible if ("M", "S", 1) in sequence]
    protocol_known = enumerate_sequences(ALL_EDGES, lambda notes: tuple(sorted(notes)) == KNOWN_TERMINAL)
    protocol_unmapped = enumerate_sequences(ALL_EDGES, lambda notes: tuple(sorted(value for _, value in notes)) == (1, 2, 3, 6, 8))
    result = {
        "schema": "full-drainage-live-tn10-public-score-v1",
        "trial": load(run / "trial/trial.json")["trial"],
        "publicOnly": True,
        "privateTruthRead": False,
        "cryptographicOpacityAssumedNotProved": True,
        "actualTranscript": {
            "confirmedTransactionsScored": len(accepted),
            "confirmationsRequired": 10,
            "accepted": accepted,
            "operationKinds": kinds,
            "operationPayloadBytes": payloads,
            "wireBytes": [row["wireBytes"] for row in metadata],
            "proofSeconds": [row["proofSeconds"] for row in metadata],
            "sameSponsorLinksTrialTransactions": True,
            "sameSponsorRevealsLogicalPayer": False,
            "knownOwnerExits": [{"owner": owner, "amountSompi": amount} for owner, amount in sorted(exits)],
            "allEconomicNullifiersDistinct": len({row["nullifier"] for row in metadata[2:]}) == 8,
            "terminalAccounting": final,
        },
        "views": {
            "protocolKnownOwner": histories(protocol_known),
            "protocolUnmappedOwner": histories(protocol_unmapped),
            "plausibleKnownOwner": histories(plausible),
            "serviceKnownOwner": histories(plausible),
            "strongExternalWorkload": histories(strong),
        },
        "decision": {
            "boundedGrossHistoryAmbiguity": len({tuple(sorted(value)) for value in plausible}) == 2,
            "strongObserverDefeatsAmbiguity": len({tuple(sorted(value)) for value in strong}) == 1,
            "ordinaryUserPrivacyMeasured": False,
            "equalLikelihoodClaimed": False,
            "computationalIndistinguishabilityClaimed": False,
        },
        "conclusion": "The accepted TN10 transcript links every protocol transaction to one sponsor and exposes deposits, exit amounts, batching and timing. Under the frozen plausible known-owner model, two gross payment histories remain compatible; the frozen strong observer selects one. This is bounded transcript evidence, not a general privacy claim.",
    }
    descriptor = output.open("x")
    with descriptor:
        json.dump(result, descriptor, indent=2, sort_keys=True)
        descriptor.write("\n")
    print(json.dumps(result["decision"], sort_keys=True))


if __name__ == "__main__":
    main()
