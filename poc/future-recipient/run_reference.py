"""One frozen, offline recipient run; separate observer and truth exports."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import time
import unittest

from recipient import *


DOMAIN = h(b"KPI/future-private-native-integration/DO-NOT-FUND/v1/2026-10-23")
REPO = Path(__file__).resolve().parents[2]


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def verify_manifest(path):
    manifest = json.loads(path.read_text())
    for record in manifest["files"]:
        data = (REPO / record["path"]).read_bytes()
        if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise Invalid("frozen-source-changed")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export_reference(output: Path, crypto: Crypto):
    bob_seed = h(b"PUBLIC_SYNTHETIC_BOB_SEED_DO_NOT_FUND")
    alice_seed = h(b"PUBLIC_SYNTHETIC_ALICE_SEED_DO_NOT_FUND")
    bob = Receiver(bob_seed, DOMAIN, crypto)
    alice = Receiver(alice_seed, DOMAIN, crypto)
    invoices = [("Bob", bob, 7, 120_000_000), ("Alice", alice, 0, 180_000_000),
                ("Bob", bob, 8, 240_000_000)]
    records = [deliver(crypto, wallet.invoice(index), value,
                       h(b"PUBLIC_SYNTHETIC_TRACE_RHO_DO_NOT_FUND", u32(pos)), pos)
               for pos, (_, wallet, index, value) in enumerate(invoices)]
    snapshot = Snapshot(records, nf_entries([h(b"SYNTHETIC_PRIOR_DUMMY_NF_A"),
                                            h(b"SYNTHETIC_PRIOR_DUMMY_NF_B")]))
    expected = snapshot.pin(DOMAIN)
    # The local wallet is reconstructed from seed after receipts exist. No
    # preferred-service or withdrawal-authorization handle is available here.
    restored = Receiver(bytes(bob_seed), DOMAIN, crypto)
    recovery = recover(restored, expected, snapshot)
    reveals, witnesses = [], []
    for claim in recovery.owned:
        note = claim.receipt
        witness = exit_witness(restored, claim, expected, snapshot)
        witnesses.append(witness)
        fee = 20_000_000
        reveals.append({
            "stage": "PUBLIC_WITNESS_UNBROADCAST",
            "ordering": "INDEPENDENT_REFERENCE_SNAPSHOT_NOT_SEQUENTIAL_CHAIN",
            "opening": {"domain": DOMAIN.hex(), "owner": note.owner.hex(),
                        "incoming": note.incoming.hex(), "value_sompi": note.value_sompi,
                        "rho": note.rho.hex(), "k": restored.keys(note.index).nf_secret.hex(),
                        "native_pk": note.native_pk.hex(), "position": claim.position,
                        "cm": note.commitment().hex(), "nf": claim.nf.hex()},
            "payout": {"fee_sompi": fee, "payout_sompi": note.value_sompi - fee,
                       "classification": "ARITHMETIC_ONLY_NO_TRANSACTION_OR_RELAY_QUOTE"}})
    public_wire = {
        "schema": "kpx1-recipient-public-wire/v1",
        "classification": "SYNTHETIC_OFFLINE_CANDIDATE_C",
        "domain": DOMAIN.hex(),
        "chainrecords": [d.public() for d in records],
        "NFrecords": [{"value": e.value.hex(), "next_value": e.next_value.hex(),
                       "next_index": e.next_index} for e in snapshot.nullifiers],
        "reveals": reveals,
        "limitations": ["Not accepted or relation-valid history", "Reveals are not transactions",
                        "No private proof, accepted backing, relay or chain confirmation"]}
    directory = {"schema": "kpx1-recipient-invoice-directory/v1", "entries": []}
    for label, wallet, index, _ in invoices:
        invoice = wallet.invoice(index)
        directory["entries"].append({"owner_label": label, "index": index,
            "domain": DOMAIN.hex(), "O": invoice.owner.hex(),
            "incoming": invoice.incoming.hex(), "K": invoice.key_commitment.hex(),
            "nativePK": invoice.native_pk.hex(), "invoice176": invoice.encode().hex()})
    truth = {"classification": "PUBLIC_TEST_FIXTURES_DO_NOT_FUND_NOT_OBSERVER_INPUT",
             "ordinary_payments": [], "receiver_keys": []}
    for position, (label, wallet, index, value) in enumerate(invoices):
        keys = wallet.keys(index)
        truth["ordinary_payments"].append({"position": position, "payer": "SyntheticSender",
            "payee": label, "value_sompi": value,
            "relation": "SYNTHETIC_RECEIPT_NOT_PRIVATE_PROOF"})
        truth["receiver_keys"].append({"owner_label": label, "index": index,
            "s": keys.owner_secret.hex(), "k": keys.nf_secret.hex(),
            "native_secret": keys.native_secret.hex(), "delivery_secret": keys.delivery_secret.hex()})
    save(output / "public-wire.json", public_wire)
    save(output / "invoice-directory.json", directory)
    save(output / "synthetic-truth.json", truth)
    save(output / "reconstructed-witnesses.json", {
        "classification": "PUBLIC_SYNTHETIC_REVEAL_CREDENTIALS_DO_NOT_FUND",
        "expected_state": {key: value.hex() if isinstance(value, bytes) else value
                           for key, value in asdict(expected).items()},
        "witnesses": witnesses})
    first = recovery.owned[0]
    keys = restored.keys(first.receipt.index)
    vector = {
        "classification": "PUBLIC_KNOWN_ANSWER_TEST_FIXTURE_DO_NOT_FUND",
        "domain": DOMAIN.hex(), "receiver_seed": bob_seed.hex(),
        "index": first.receipt.index, "position": first.position,
        "s": keys.owner_secret.hex(), "k": keys.nf_secret.hex(),
        "native_secret": keys.native_secret.hex(), "delivery_secret": keys.delivery_secret.hex(),
        "O": keys.invoice.owner.hex(), "incoming": keys.invoice.incoming.hex(),
        "K": keys.invoice.key_commitment.hex(), "nativePK": keys.invoice.native_pk.hex(),
        "invoice176": keys.invoice.encode().hex(), "receipt216": first.receipt.encode().hex(),
        "CM": first.receipt.commitment().hex(), "NF": first.nf.hex()}
    save(output / "known-answer.json", vector)
    return {"owned_positions": [c.position for c in recovery.owned],
            "normal_credit_sompi": recovery.normal_credit_sompi,
            "all_owned_unspent_sompi": recovery.all_owned_unspent_sompi,
            "current_witnesses": len(witnesses),
            "foreign_recipient_records_not_credited": len(recovery.rejected),
            "service_interface_present": False,
            "withdrawal_authorization_present": False,
            "accepted_state_oracle": expected.oracle,
            "data_archive_pin_is_out_of_band": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest_sha = verify_manifest(args.source_manifest)
    if args.output.exists():
        raise Invalid("output-already-exists")
    args.output.mkdir(parents=True)
    os.environ["KPX_RECIPIENT_CRYPTO"] = str(args.bridge.resolve(strict=True))
    log = io.StringIO()
    start = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromName("test_recipient")
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    (args.output / "tests.log").write_text(log.getvalue())
    report = {"classification": "OFFLINE_REFERENCE_NOT_CHAIN_OR_PRIVACY_QUALIFICATION",
              "domain": DOMAIN.hex(), "source_manifest_sha256": manifest_sha,
              "bridge_binary_sha256": hashlib.sha256(args.bridge.read_bytes()).hexdigest(),
              "tests_run": result.testsRun, "test_failures": len(result.failures),
              "test_errors": len(result.errors), "tests_passed": result.wasSuccessful()}
    if result.wasSuccessful():
        report["recovery"] = export_reference(args.output, Crypto(args.bridge))
    report["elapsed_seconds"] = time.monotonic() - start
    verify_manifest(args.source_manifest)
    save(args.output / "results.json", report)
    print(json.dumps({"tests_run": result.testsRun, "passed": result.wasSuccessful(),
                      "output": str(args.output)}, sort_keys=True))
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
