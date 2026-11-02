#!/usr/bin/env python3
"""Decode the frozen public TN10 wallet operations and emit privacy facts.

This is an evidence adapter, not a protocol implementation or verifier.
It mirrors the public byte offsets in poc/private-note-wallet/src/protocol.rs.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "poc/tn10-live/evidence"
SELECTION = Path(__file__).with_name("SELECTION.md")
SELECTION_SHA256 = "52c2c7d0be6c6155d8d42869df2a5ce21e426687f939e4f79f188221f8c51bd0"
HEAD = "7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1"
TAG = b"KPI-private-operation-v1\0"
PUBLIC_LEN = 410


def read_json(path: Path):
    return json.loads(path.read_text())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def all_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from all_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from all_strings(item)


def operation_payload(path: Path) -> bytes:
    prefix = TAG.hex()
    candidates = {s for s in all_strings(read_json(path)) if s.startswith(prefix)}
    if len(candidates) != 1:
        raise AssertionError(f"{path}: expected one operation payload, got {len(candidates)}")
    return bytes.fromhex(candidates.pop())


def parse_operation(payload: bytes):
    if not payload.startswith(TAG):
        raise AssertionError("operation tag")
    cursor = len(TAG)
    wire_len = int.from_bytes(payload[cursor : cursor + 4], "little")
    cursor += 4
    wire = payload[cursor : cursor + wire_len]
    cursor += wire_len
    destination_key = payload[cursor : cursor + 32]
    if cursor + 32 != len(payload):
        raise AssertionError("operation envelope length")
    if len(wire) < PUBLIC_LEN + 128:
        raise AssertionError("operation wire length")
    statement = wire[:PUBLIC_LEN]
    kind = statement[1]
    output_count = {1: 1, 2: 2, 3: 0, 4: 0}[kind]
    expected = PUBLIC_LEN + 128 + 185 * output_count
    if len(wire) != expected:
        raise AssertionError("canonical operation wire length")

    def h(offset: int) -> str:
        return statement[offset : offset + 32].hex()

    def u64(offset: int) -> int:
        return int.from_bytes(statement[offset : offset + 8], "little")

    return {
        "payload_bytes": len(payload),
        "payload_sha256": sha256(payload),
        "wire_bytes": len(wire),
        "version": statement[0],
        "kind": kind,
        "domain": h(2),
        "verifier": h(34),
        "anchor": h(66),
        "nullifier": h(98),
        "outputs": [h(130), h(162)],
        "delivery_hashes": [h(194), h(226)],
        "deposit": h(258),
        "deposit_owner": h(290),
        "deposit_value_sompi": u64(322),
        "exit_destination": h(330),
        "exit_value_sompi": u64(362),
        "fee_recipient": h(370),
        "application_fee_sompi": u64(402),
        "proof_bytes": 128,
        "ciphertext_bytes": [185 if i < output_count else 0 for i in range(2)],
        "destination_key_active": destination_key != bytes(32),
    }


def accepted_time_and_fee(name: str):
    accepted = read_json(EVIDENCE / f"native/{name}-accepted.json")
    transaction = read_json(EVIDENCE / f"native/{name}-transaction.json")
    return {
        "transaction_id": accepted["transactionId"],
        "header_timestamp_ms": accepted["header"]["timestamp"],
        "header_daa_score": accepted["header"]["daaScore"],
        "native_fee_sompi": transaction["qualification"]["feeSompi"],
    }


def accepted_header_timestamp(name: str) -> int:
    return read_json(EVIDENCE / f"native/{name}-accepted.json")["header"]["timestamp"]


def accounting(stage: str):
    return read_json(EVIDENCE / stage / "freeze-report.json")["accounting"]


def main():
    if sha256(SELECTION.read_bytes()) != SELECTION_SHA256:
        raise AssertionError("selection changed")
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if head != HEAD:
        raise AssertionError(f"unexpected HEAD {head}")

    tracked = subprocess.check_output(
        ["git", "ls-files", "-s", "poc/tn10-live/evidence"],
        cwd=ROOT,
        text=True,
    ).splitlines()
    corpus_identity = sha256(("\n".join(tracked) + "\n").encode())

    operations = {}
    for name in ("publish-credit", "publish-invalid-transfer", "publish-transfer", "publish-exit"):
        paths = [
            EVIDENCE / f"native/{name}-request.json",
            EVIDENCE / f"native/{name}-transaction.json",
            EVIDENCE / f"native/{name}-accepted.json",
        ]
        payloads = [operation_payload(path) for path in paths]
        if not payloads[0] == payloads[1] == payloads[2]:
            raise AssertionError(f"{name}: request/transaction/accepted payload mismatch")
        operations[name] = parse_operation(payloads[0])

    invalid = operation_payload(EVIDENCE / "native/publish-invalid-transfer-accepted.json")
    valid = operation_payload(EVIDENCE / "native/publish-transfer-accepted.json")
    byte_differences = [
        {"offset": i, "invalid": a, "valid": b}
        for i, (a, b) in enumerate(zip(invalid, valid))
        if a != b
    ]
    if len(invalid) != len(valid):
        raise AssertionError("invalid/valid payload length mismatch")

    timeline = {
        name: accepted_time_and_fee(name)
        for name in ("publish-credit", "publish-invalid-transfer", "publish-transfer", "publish-exit", "payout")
    }
    timeline["valid_transfer_to_exit_seconds"] = (
        timeline["publish-exit"]["header_timestamp_ms"]
        - timeline["publish-transfer"]["header_timestamp_ms"]
    ) / 1000
    timeline["accepted_transfer_settlement_to_exit_publication_seconds"] = (
        timeline["publish-exit"]["header_timestamp_ms"]
        - accepted_header_timestamp("credit-transfer-settlement")
    ) / 1000
    timeline["invalid_to_valid_publication_seconds"] = (
        timeline["publish-transfer"]["header_timestamp_ms"]
        - timeline["publish-invalid-transfer"]["header_timestamp_ms"]
    ) / 1000
    timeline["exit_to_payout_seconds"] = (
        timeline["payout"]["header_timestamp_ms"]
        - timeline["publish-exit"]["header_timestamp_ms"]
    ) / 1000

    result = read_json(EVIDENCE / "result.json")
    physical = read_json(EVIDENCE / "native/final-physical.json")
    wallet_source = (ROOT / "poc/private-native-tn10/src/wallet.rs").read_text()
    sender_match = re.search(r'"credit-transfer"\s*=>\s*"([a-z]+)"', wallet_source)
    notes_match = re.search(r"let notes = \[(.*?)\];", wallet_source, re.S)
    if sender_match is None or notes_match is None:
        raise AssertionError("published role/value source observations not found")
    notes_source = notes_match.group(1)
    payment_match = re.search(
        r"Note::for_address\(&([a-z]+),\s*([0-9_]+)\)", notes_source
    )
    change_match = re.search(r"wallet\.note\(([0-9_]+)\)", notes_source)
    if payment_match is None or change_match is None:
        raise AssertionError("published payment/change construction not found")
    sender_candidates = [sender_match.group(1).title()]
    recipient_candidates = [payment_match.group(1).title()]
    source_payment = int(payment_match.group(2).replace("_", ""))
    source_change = int(change_match.group(1).replace("_", ""))
    exit_value = operations["publish-exit"]["exit_value_sompi"]
    amount_candidates = [source_payment] if source_payment == exit_value else []
    historical_candidates = [
        commitment
        for commitment, ciphertext_bytes in zip(
            operations["publish-credit"]["outputs"],
            operations["publish-credit"]["ciphertext_bytes"],
        )
        if commitment != "00" * 32 and ciphertext_bytes > 0
    ]
    payment_index = int(payment_match.start() > change_match.start())
    output_partitions = [{"payment": payment_index, "change": 1 - payment_index}]
    complete_assignments = [
        {
            "sender": sender,
            "recipient": recipient,
            "payment_principal_sompi": amount,
            "historical_spent_note": note,
            **partition,
        }
        for sender in sender_candidates
        for recipient in recipient_candidates
        for amount in amount_candidates
        for note in historical_candidates
        for partition in output_partitions
    ]
    candidate_sets = {
        "sender": sender_candidates,
        "recipient": recipient_candidates,
        "payment_principal_sompi": amount_candidates,
        "historical_spent_note": historical_candidates,
        "payment_change_output_partitions": output_partitions,
        "complete_assignments": complete_assignments,
    }
    candidate_counts = {
        "sender_identities": len(sender_candidates),
        "recipient_identities": len(recipient_candidates),
        "exact_payment_amounts": len(amount_candidates),
        "historical_spent_notes": len(historical_candidates),
        "payment_change_output_partitions": len(output_partitions),
        "complete_sender_recipient_amount_note_assignments": len(complete_assignments),
    }
    report = {
        "selection_sha256": SELECTION_SHA256,
        "repository_head": head,
        "selected_tracked_file_count": len(tracked),
        "selected_git_index_manifest_sha256": corpus_identity,
        "operations": operations,
        "invalid_to_valid": {
            "same_length": len(invalid) == len(valid),
            "byte_difference_count": len(byte_differences),
            "byte_differences": byte_differences,
            "difference_is_first_nullifier_byte": byte_differences
            == [{"offset": len(TAG) + 4 + 98, "invalid": invalid[len(TAG) + 4 + 98], "valid": valid[len(TAG) + 4 + 98]}],
        },
        "timeline": timeline,
        "accounting": {
            "after_deposit": accounting("deposit"),
            "after_credit_and_transfer": accounting("credit-transfer"),
            "after_exit": accounting("exit"),
            "after_payout_reconciliation": accounting("reconcile"),
            "bob_principal_sompi": result["native"]["bobPrincipalSompi"],
            "bob_rent_refund_sompi": result["native"]["bobRentRefundSompi"],
            "bob_native_output_sompi": physical["bob"]["utxoEntry"]["amount"],
        },
        "candidate_counts_under_frozen_auxiliary_overlay": {
            "O_public": candidate_counts,
            "O_service": candidate_counts,
        },
        "candidate_sets_under_frozen_auxiliary_overlay": candidate_sets,
        "candidate_derivation": {
            "sender": "published credit-transfer role branch",
            "recipient_amount_partition": "published transfer note construction order",
            "amount_cross_check": "published source amount intersected with public exit value",
            "historical_note": "all nonzero encrypted credit outputs before the transfer",
            "source_change_sompi": source_change,
            "hard_coded_candidate_output": False,
        },
        "chain_bytes_only_diagnostic_not_the_frozen_public_corpus": {
            "payment_change_output_partitions_under_key_privacy": 2,
            "reason": "the wire format does not label either transfer output, but the selected public source fixes Bob as output 0 and Alice change as output 1",
        },
        "evidence_boundaries": {
            "cryptographic_assumption": "commitments, ciphertexts, proofs and nullifiers reveal no hidden preimage beyond their public fields",
            "simulated_auxiliary": "four-person contact graph, Alice deposit identity, Bob payout identity, Alice service endpoint",
            "actual_custody_record": result["custody"],
            "independent_user_live_recovery_and_exit_demonstrated": False,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
