"""V3 one-use invoice and private-ledger controls; public synthetic data only."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import copy
from dataclasses import replace
import tempfile
import unittest

from recipient import *


BRIDGE = Path(os.environ.get(
    "KPX_RECIPIENT_CRYPTO",
    "/home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/"
    "kpi-future-recipient-crypto"))


class RecipientV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = Crypto(BRIDGE)
        cls.seed = hashlib.sha256(b"PUBLIC V3 BOB SEED DO NOT FUND").digest()
        cls.binding = LedgerBinding(
            domain=hashlib.sha256(b"PUBLIC V3 DOMAIN DO NOT FUND").digest(),
            profile_id=hashlib.sha256(b"PUBLIC V3 PROFILE DO NOT FUND").digest(),
            owner_id=hashlib.sha256(b"PUBLIC V3 OWNER BOB DO NOT FUND").digest(),
            attempt_id=hashlib.sha256(b"PUBLIC V3 ATTEMPT 1 DO NOT FUND").digest())

    def export_invoice(self, wallet, index):
        allocation = wallet.allocate(index)
        offer = wallet.export_private_invoice(allocation)
        raw = offer.take_invoice_bytes()
        return allocation, offer, raw

    def accept_invoice(self, wallet, index):
        _, offer, raw = self.export_invoice(wallet, index)
        accepted = wallet.accept_private_invoice(
            offer, raw, attempt_id=self.binding.attempt_id)
        return accepted, Invoice.parse(raw)

    def test_per_index_delivery_keys_and_fixed_wire_widths(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        first, invoice_a = self.accept_invoice(wallet, 7)
        _, invoice_b = self.accept_invoice(wallet, 8)

        self.assertEqual(len(invoice_a.encode()), 208)
        self.assertNotEqual(invoice_a.delivery_pk, invoice_b.delivery_pk)

        delivery = deliver(
            self.crypto, first, 120_000_000,
            hashlib.sha256(b"PUBLIC V3 RHO DO NOT FUND").digest(), 0,
            attempt_id=self.binding.attempt_id)
        self.assertEqual(len(delivery.ciphertext), 264)

    def test_exact_delivery_kdf_vector_and_profile_separation(self):
        self.assertEqual(
            derive(self.seed, self.binding, b"DELIVERY", 7).hex(),
            "a16602deea6f3016ea438656e834d4587cdc7961c7671363f4b503f49a0c3e48")
        changed_profile = LedgerBinding(
            self.binding.domain, hashlib.sha256(b"OTHER V3 PROFILE").digest(),
            self.binding.owner_id, self.binding.attempt_id)
        changed_domain = LedgerBinding(
            hashlib.sha256(b"OTHER V3 DOMAIN").digest(), self.binding.profile_id,
            self.binding.owner_id, self.binding.attempt_id)
        original = derive(self.seed, self.binding, b"DELIVERY", 7)
        retained_v2 = hmac.digest(
            self.seed,
            b"KPX1DRV\0" + b"DELIVERY" + self.binding.domain
            + (7).to_bytes(8, "little"),
            "sha256")
        self.assertNotEqual(original, retained_v2)
        self.assertNotEqual(original, derive(
            self.seed, self.binding, b"DELIVERY", 8))
        self.assertNotEqual(original, derive(
            self.seed, changed_profile, b"DELIVERY", 7))
        self.assertNotEqual(original, derive(
            self.seed, changed_domain, b"DELIVERY", 7))

    def test_v3_formats_ranges_and_v2_confusion_refuse(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        authorities = {}
        for index in (0, (1 << 64) - 1):
            authority, invoice = self.accept_invoice(wallet, index)
            authorities[index] = authority
            self.assertEqual(len(invoice.encode()), 208)
            for value in (MIN_NOTE_SOMPI, MAX_SOMPI):
                receipt = Receipt.for_invoice(invoice, value, ZERO)
                self.assertEqual(Receipt.parse(receipt.encode()), receipt)
                self.assertEqual(len(receipt.encode()), 216)
        for index in (True, -1, 1 << 64):
            with self.subTest(index=index), self.assertRaises(Invalid):
                wallet.allocate(index)

        invoice = authorities[0].invoice()
        for bad in (invoice.encode()[:-1], invoice.encode() + b"\0",
                    b"KPX2IN01" + invoice.encode()[8:]):
            with self.assertRaises(Invalid):
                Invoice.parse(bad)
        receipt = Receipt.for_invoice(invoice, MIN_NOTE_SOMPI, ZERO)
        for value in (True, -1, 0, MIN_NOTE_SOMPI - 1,
                      MAX_SOMPI + 1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(Invalid):
                replace(receipt, value_sompi=value).encode()
        for bad in (receipt.encode()[:-1], receipt.encode() + b"\0",
                    b"KPX1RC01" + receipt.encode()[8:]):
            with self.assertRaises(Invalid):
                Receipt.parse(bad)

    def test_allocate_export_accept_use_are_one_shot_and_logged(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        allocation = wallet.allocate(9)
        offer = wallet.export_private_invoice(allocation)
        raw = offer.take_invoice_bytes()
        parsed = Invoice.parse(raw)
        rho = hashlib.sha256(b"PUBLIC V3 ONE USE RHO").digest()

        with self.assertRaisesRegex(Invalid, "^honest-invoice-capability$"):
            deliver(self.crypto, parsed, 120_000_000, rho, 0,
                    attempt_id=self.binding.attempt_id)
        with self.assertRaisesRegex(Invalid, "^invoice-not-live$"):
            wallet.export_private_invoice(allocation)
        with self.assertRaisesRegex(Invalid, "^private-invoice-already-taken$"):
            offer.take_invoice_bytes()
        with self.assertRaisesRegex(Invalid, "^honest-invoice-capability$"):
            copy.copy(offer)

        accepted = wallet.accept_private_invoice(
            offer, raw, attempt_id=self.binding.attempt_id)
        with self.assertRaisesRegex(Invalid, "^invoice-not-live$"):
            wallet.accept_private_invoice(
                offer, raw, attempt_id=self.binding.attempt_id)

        deliver(self.crypto, accepted, 120_000_000, rho, 0,
                attempt_id=self.binding.attempt_id)
        with self.assertRaisesRegex(Invalid, "^invoice-not-live$"):
            deliver(self.crypto, accepted, 120_000_000, rho, 1,
                    attempt_id=self.binding.attempt_id)
        with self.assertRaisesRegex(Invalid, "^invoice-index-reuse$"):
            wallet.allocate(9)

        restored = restore_private_ledger(
            self.seed, self.binding, self.crypto,
            wallet.export_private_ledger())
        self.assertEqual(restored.entry_statuses(), ((9, "CONSUMED"),))

    def test_wrong_acceptance_and_abandon_poison_every_live_stage(self):
        for index, stage in ((10, "ALLOCATED"), (11, "EXPORTED"),
                             (12, "ACCEPTED")):
            with self.subTest(stage=stage):
                wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
                allocation = wallet.allocate(index)
                capability = allocation
                if stage in ("EXPORTED", "ACCEPTED"):
                    offer = wallet.export_private_invoice(allocation)
                    raw = offer.take_invoice_bytes()
                    capability = offer
                if stage == "ACCEPTED":
                    capability = wallet.accept_private_invoice(
                        offer, raw, attempt_id=self.binding.attempt_id)
                wallet.abandon(capability)
                with self.assertRaisesRegex(Invalid, "^invoice-not-live$"):
                    wallet.abandon(capability)
                restored = restore_private_ledger(
                    self.seed, self.binding, self.crypto,
                    wallet.export_private_ledger())
                self.assertEqual(
                    restored.entry_statuses(), ((index, "POISONED"),))

        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        _, offer, raw = self.export_invoice(wallet, 13)
        with self.assertRaisesRegex(Invalid, "^cross-attempt-invoice$"):
            wallet.accept_private_invoice(
                offer, raw,
                attempt_id=hashlib.sha256(b"OTHER ATTEMPT").digest())
        restored = restore_private_ledger(
            self.seed, self.binding, self.crypto,
            wallet.export_private_ledger())
        self.assertEqual(restored.entry_statuses(), ((13, "POISONED"),))

        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        _, offer, raw = self.export_invoice(wallet, 14)
        changed = raw[:-1] + bytes([raw[-1] ^ 1])
        with self.assertRaisesRegex(Invalid, "^private-invoice-mismatch$"):
            wallet.accept_private_invoice(
                offer, changed, attempt_id=self.binding.attempt_id)
        restored = restore_private_ledger(
            self.seed, self.binding, self.crypto,
            wallet.export_private_ledger())
        self.assertEqual(restored.entry_statuses(), ((14, "POISONED"),))

        with self.assertRaisesRegex(Invalid, "^invoice-index-reuse$"):
            wallet.allocate(14)
        _, fresh_offer, fresh_raw = self.export_invoice(wallet, 15)
        self.assertNotEqual(
            Invoice.parse(raw).delivery_pk,
            Invoice.parse(fresh_raw).delivery_pk)
        wallet.abandon(fresh_offer)

        with self.assertRaisesRegex(Invalid, "^invoice-not-live$"):
            wallet.accept_private_invoice(
                offer, raw, attempt_id=self.binding.attempt_id)

    def test_raw_invoice_cannot_mint_accepted_producer_capability(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        _, offer, raw = self.export_invoice(wallet, 15)
        parsed = Invoice.parse(raw)
        rho = hashlib.sha256(b"PUBLIC V3 RAW INVOICE RHO").digest()
        with self.assertRaisesRegex(Invalid, "^honest-invoice-capability$"):
            wallet.export_private_invoice(parsed)
        with self.assertRaisesRegex(Invalid, "^honest-invoice-capability$"):
            deliver(self.crypto, parsed, 120_000_000, rho, 0,
                    attempt_id=self.binding.attempt_id)
        with self.assertRaisesRegex(Invalid, "^honest-invoice-capability$"):
            AcceptedInvoiceCapability(object(), wallet, 15)

        accepted = wallet.accept_private_invoice(
            offer, raw, attempt_id=self.binding.attempt_id)
        delivery = deliver(
            self.crypto, accepted, 120_000_000, rho, 0,
            attempt_id=self.binding.attempt_id)
        self.assertEqual(len(delivery.ciphertext), 264)

    def test_authenticated_append_only_ledger_round_trip_is_recovery_only(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        consumed, _ = self.accept_invoice(wallet, 21)
        poisoned = wallet.allocate(22)
        wallet.allocate(23)
        deliver(self.crypto, consumed, 120_000_000,
                hashlib.sha256(b"PUBLIC V3 CONSUMED RHO").digest(), 0,
                attempt_id=self.binding.attempt_id)
        wallet.abandon(poisoned)

        raw = wallet.export_private_ledger()
        self.assertTrue(raw.endswith(b"\n"))
        delivery_secret = derive(
            self.seed, self.binding, b"DELIVERY", 21)
        private_values = [
            delivery_secret,
            derive(self.seed, self.binding, b"OWNSEC\0\0", 21),
            derive(self.seed, self.binding, b"KSECRET\0", 21),
            derive(self.seed, self.binding, b"NATIVE\0\0", 21, 0),
        ]
        for secret in private_values:
            self.assertNotIn(secret, raw)
            self.assertNotIn(secret.hex().encode(), raw)

        restored = restore_private_ledger(
            self.seed, self.binding, self.crypto, raw)
        self.assertEqual(restored.entry_statuses(), (
            (21, "CONSUMED"), (22, "POISONED"), (23, "ALLOCATED")))
        self.assertFalse(hasattr(restored, "issue"))

    def test_each_persisted_edge_restores_but_old_authentic_head_is_rollback(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        allocation = wallet.allocate(24)
        snapshots = [("ALLOCATED", wallet.export_private_ledger())]
        offer = wallet.export_private_invoice(allocation)
        snapshots.append(("EXPORTED", wallet.export_private_ledger()))
        raw = offer.take_invoice_bytes()
        accepted = wallet.accept_private_invoice(
            offer, raw, attempt_id=self.binding.attempt_id)
        snapshots.append(("ACCEPTED", wallet.export_private_ledger()))
        delivery = deliver(
            self.crypto, accepted, 120_000_000,
            hashlib.sha256(b"PUBLIC V3 CRASH EDGE RHO").digest(), 0,
            attempt_id=self.binding.attempt_id)
        snapshots.append(("CONSUMED", wallet.export_private_ledger()))

        for state, snapshot in snapshots:
            with self.subTest(state=state):
                restored = restore_private_ledger(
                    self.seed, self.binding, self.crypto, snapshot)
                self.assertEqual(restored.entry_statuses(), ((24, state),))
                self.assertFalse(hasattr(restored, "allocate"))

        # Without an external latest-head authority, the old authentic snapshot
        # remains valid. This is retained evidence of the CONFIGURED0 blocker.
        old = restore_private_ledger(
            self.seed, self.binding, self.crypto, snapshots[0][1])
        self.assertEqual(old.entry_statuses(), ((24, "ALLOCATED"),))
        recovered = recover(
            self.seed, self.binding, self.crypto, snapshots[-1][1], [delivery])
        self.assertEqual(recovered.phase1_consumed_sompi, 120_000_000)

    def test_seed_plus_ledger_recovers_and_seed_only_refuses(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        first, _ = self.accept_invoice(wallet, 31)
        second, _ = self.accept_invoice(wallet, 32)
        records = [
            deliver(self.crypto, first, 120_000_000,
                    hashlib.sha256(b"PUBLIC V3 FIRST RECOVERY RHO").digest(), 0,
                    attempt_id=self.binding.attempt_id),
            deliver(self.crypto, second, 180_000_000,
                    hashlib.sha256(b"PUBLIC V3 SECOND RECOVERY RHO").digest(), 1,
                    attempt_id=self.binding.attempt_id),
        ]
        ledger = wallet.export_private_ledger()

        result = recover(
            self.seed, self.binding, self.crypto, ledger, records)
        self.assertEqual([claim.receipt.index for claim in result.owned], [31, 32])
        self.assertEqual(result.recovered_liability_sompi, 300_000_000)
        self.assertEqual(result.phase1_consumed_sompi, 300_000_000)
        self.assertTrue(all(len(claim.receipt.encode()) == 216
                            for claim in result.owned))

        for missing in (None, b""):
            with self.subTest(missing=missing), self.assertRaisesRegex(
                    Invalid, "^private-ledger-required$"):
                recover(self.seed, self.binding, self.crypto, missing, records)

    def test_ledger_corruption_and_cross_binding_fail_closed(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        first, _ = self.accept_invoice(wallet, 41)
        wallet.allocate(42)
        deliver(self.crypto, first, 120_000_000,
                hashlib.sha256(b"PUBLIC V3 LEDGER CORRUPTION RHO").digest(), 0,
                attempt_id=self.binding.attempt_id)
        raw = wallet.export_private_ledger()
        parsed = json.loads(raw)

        missing = dict(parsed)
        missing.pop("head_sha256")
        reordered_events = dict(parsed)
        reordered_events["events"] = list(reversed(parsed["events"]))
        duplicated_event = dict(parsed)
        duplicated_event["events"] = parsed["events"] + [parsed["events"][0]]
        duplicated_event["event_count"] += 1
        extra = dict(parsed, caller_claimed_complete=True)
        transformed = [
            raw[:-1],
            raw[:-17] + b"\n",
            json.dumps(missing, sort_keys=True, separators=(",", ":")).encode() + b"\n",
            json.dumps(reordered_events, sort_keys=True,
                       separators=(",", ":")).encode() + b"\n",
            json.dumps(duplicated_event, sort_keys=True,
                       separators=(",", ":")).encode() + b"\n",
            json.dumps(extra, sort_keys=True, separators=(",", ":")).encode() + b"\n",
            raw[:-2] + (
                b',"schema":"kpx3-private-invoice-ledger/v1"}\n'),
        ]
        for changed in transformed:
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()), \
                    self.assertRaises(Invalid):
                restore_private_ledger(
                    self.seed, self.binding, self.crypto, changed)

        wrong_seed = hashlib.sha256(b"WRONG V3 SEED").digest()
        variants = [
            LedgerBinding(self.binding.domain, self.binding.profile_id,
                          hashlib.sha256(b"OTHER OWNER").digest(),
                          self.binding.attempt_id),
            LedgerBinding(self.binding.domain,
                          hashlib.sha256(b"OTHER PROFILE").digest(),
                          self.binding.owner_id, self.binding.attempt_id),
            LedgerBinding(self.binding.domain, self.binding.profile_id,
                          self.binding.owner_id,
                          hashlib.sha256(b"OTHER ATTEMPT").digest()),
        ]
        with self.assertRaises(Invalid):
            restore_private_ledger(
                wrong_seed, self.binding, self.crypto, raw)
        for binding in variants:
            with self.subTest(binding=binding), self.assertRaises(Invalid):
                restore_private_ledger(
                    self.seed, binding, self.crypto, raw)

    def test_multiple_successful_key_trials_fail_as_ambiguous(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        first, invoice = self.accept_invoice(wallet, 51)
        self.accept_invoice(wallet, 52)
        receipt = Receipt.for_invoice(
            invoice, 120_000_000,
            hashlib.sha256(b"PUBLIC V3 AMBIGUOUS RHO").digest())

        ambiguous = Crypto(BRIDGE)
        ambiguous.unseal = lambda secret, ciphertext: receipt.encode()
        delivery = Delivery(0, receipt.commitment(), bytes(264))
        with self.assertRaisesRegex(Invalid, "^ambiguous-decrypt$"):
            recover(self.seed, self.binding, ambiguous,
                    wallet.export_private_ledger(), [delivery])

    def test_public_history_requires_canonical_integer_positions(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        first, _ = self.accept_invoice(wallet, 61)
        second, _ = self.accept_invoice(wallet, 62)
        records = [
            deliver(self.crypto, first, 120_000_000,
                    hashlib.sha256(b"PUBLIC V3 POSITION ZERO").digest(), 0,
                    attempt_id=self.binding.attempt_id),
            deliver(self.crypto, second, 120_000_000,
                    hashlib.sha256(b"PUBLIC V3 POSITION ONE").digest(), 1,
                    attempt_id=self.binding.attempt_id),
        ]
        records[1] = replace(records[1], position=True)
        with self.assertRaisesRegex(Invalid, "^public-history$"):
            recover(self.seed, self.binding, self.crypto,
                    wallet.export_private_ledger(), records)

    def test_invoice_capability_is_bound_to_selected_crypto_instance(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        authority, _ = self.accept_invoice(wallet, 71)
        rho = hashlib.sha256(b"PUBLIC V3 CRYPTO BINDING RHO").digest()

        class CallerCrypto:
            @staticmethod
            def seal(public, plaintext):
                return bytes(264)

        with self.assertRaisesRegex(Invalid, "^crypto-adapter-binding$"):
            IssuanceWallet(self.seed, self.binding, CallerCrypto())
        with self.assertRaisesRegex(Invalid, "^crypto-adapter-binding$"):
            deliver(CallerCrypto(), authority, 120_000_000, rho, 0,
                    attempt_id=self.binding.attempt_id)
        # A rejected caller adapter must not consume the genuine capability.
        accepted = deliver(self.crypto, authority, 120_000_000, rho, 0,
                           attempt_id=self.binding.attempt_id)
        self.assertEqual(len(accepted.ciphertext), 264)

    def test_mature_crypto_bridge_identity_is_pinned(self):
        self.assertEqual(hashlib.sha256(BRIDGE.read_bytes()).hexdigest(),
                         SELECTED_CRYPTO_SHA256)
        descriptor = self.crypto._open_selected()
        try:
            expected_seals = (
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            self.assertEqual(
                fcntl.fcntl(descriptor, fcntl.F_GET_SEALS), expected_seals)
        finally:
            os.close(descriptor)
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "changed-bridge"
            changed.write_bytes(BRIDGE.read_bytes() + b"changed")
            changed.chmod(0o500)
            with self.assertRaisesRegex(Invalid, "^selected-crypto-pin$"):
                Crypto(changed)

            selected = Crypto(BRIDGE)
            selected.executable = changed
            with self.assertRaisesRegex(Invalid, "^selected-crypto-pin$"):
                selected.delivery_public(bytes(32))

            symlink = Path(directory) / "bridge-symlink"
            symlink.symlink_to(BRIDGE)
            with self.assertRaisesRegex(Invalid, "^selected-crypto-pin$"):
                Crypto(symlink)

            selected_path = Path(directory) / "selected-bridge"
            selected_path.write_bytes(BRIDGE.read_bytes())
            selected_path.chmod(0o500)
            selected = Crypto(selected_path)
            replacement = Path(directory) / "replacement-bridge"
            replacement.write_bytes(BRIDGE.read_bytes() + b"replacement")
            replacement.chmod(0o500)
            os.replace(replacement, selected_path)
            with self.assertRaisesRegex(Invalid, "^selected-crypto-pin$"):
                selected.delivery_public(bytes(32))

    def test_crypto_failure_poisoned_key_cannot_be_retried(self):
        crypto = Crypto(BRIDGE)
        wallet = IssuanceWallet(self.seed, self.binding, crypto)
        _, offer, raw = self.export_invoice(wallet, 72)
        authority = wallet.accept_private_invoice(
            offer, raw, attempt_id=self.binding.attempt_id)
        original_seal = crypto.seal

        def fail_seal(public, plaintext):
            raise Invalid("crypto-seal")

        crypto.seal = fail_seal
        with self.assertRaisesRegex(Invalid, "^crypto-seal$"):
            deliver(crypto, authority, 120_000_000,
                    hashlib.sha256(b"PUBLIC V3 FAILED SEAL RHO").digest(), 0,
                    attempt_id=self.binding.attempt_id)
        crypto.seal = original_seal

        restored = restore_private_ledger(
            self.seed, self.binding, crypto, wallet.export_private_ledger())
        self.assertEqual(restored.entry_statuses(), ((72, "POISONED"),))
        with self.assertRaisesRegex(Invalid, "^invoice-not-live$"):
            deliver(crypto, authority, 120_000_000,
                    hashlib.sha256(b"PUBLIC V3 RETRY RHO").digest(), 0,
                    attempt_id=self.binding.attempt_id)

    def test_successful_decrypt_with_wrong_descriptor_or_cm_halts(self):
        cases = {
            "domain": hashlib.sha256(b"WRONG V3 DOMAIN").digest(),
            "index": 82,
            "owner": hashlib.sha256(b"WRONG V3 OWNER").digest(),
            "incoming": hashlib.sha256(b"WRONG V3 INCOMING").digest(),
            "key_commitment": hashlib.sha256(b"WRONG V3 KEY").digest(),
            "native_pk": hashlib.sha256(b"WRONG V3 NATIVE").digest(),
        }
        for field, changed in cases.items():
            with self.subTest(field=field):
                wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
                _, invoice = self.accept_invoice(wallet, 81)
                receipt = Receipt.for_invoice(
                    invoice, 120_000_000,
                    hashlib.sha256(b"PUBLIC V3 ALTERED RECEIPT").digest())
                receipt = replace(receipt, **{field: changed})
                ciphertext = self.crypto.seal(
                    invoice.delivery_pk, receipt.encode())
                record = Delivery(0, receipt.commitment(), ciphertext)
                reason = "receipt-domain" if field == "domain" else "receipt-descriptor"
                with self.assertRaisesRegex(Invalid, "^" + reason + "$"):
                    recover(self.seed, self.binding, self.crypto,
                            wallet.export_private_ledger(), [record])

        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        _, invoice = self.accept_invoice(wallet, 83)
        receipt = Receipt.for_invoice(
            invoice, 120_000_000,
            hashlib.sha256(b"PUBLIC V3 WRONG CM").digest())
        record = Delivery(0, hashlib.sha256(b"WRONG ACCEPTED CM").digest(),
                          self.crypto.seal(invoice.delivery_pk, receipt.encode()))
        with self.assertRaisesRegex(Invalid, "^receipt-cm$"):
            recover(self.seed, self.binding, self.crypto,
                    wallet.export_private_ledger(), [record])

    def test_duplicate_reordered_truncated_and_tampered_history_refuses(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        first, _ = self.accept_invoice(wallet, 91)
        second, _ = self.accept_invoice(wallet, 92)
        records = [
            deliver(self.crypto, first, 120_000_000,
                    hashlib.sha256(b"PUBLIC V3 HISTORY FIRST").digest(), 0,
                    attempt_id=self.binding.attempt_id),
            deliver(self.crypto, second, 180_000_000,
                    hashlib.sha256(b"PUBLIC V3 HISTORY SECOND").digest(), 1,
                    attempt_id=self.binding.attempt_id),
        ]
        ledger = wallet.export_private_ledger()
        for malformed in (
                [records[1], records[0]],
                [replace(records[0], ciphertext=records[0].ciphertext[:-1])],
                [replace(records[0], position=-1)],
                [replace(records[0], cm=records[0].cm[:-1])]):
            with self.subTest(malformed=malformed), self.assertRaises(Invalid):
                recover(self.seed, self.binding, self.crypto, ledger, malformed)

        duplicate = [records[0], replace(records[0], position=1)]
        with self.assertRaisesRegex(Invalid, "^invoice-reuse-in-history$"):
            recover(self.seed, self.binding, self.crypto, ledger, duplicate)

        tampered = bytearray(records[0].ciphertext)
        tampered[-1] ^= 1
        for incomplete in (
                [],
                [records[0]],
                [replace(records[0], ciphertext=bytes(tampered)), records[1]]):
            with self.subTest(incomplete=incomplete), self.assertRaisesRegex(
                    Invalid, "^missing-consumed-delivery$"):
                recover(self.seed, self.binding, self.crypto, ledger, incomplete)

    def test_poisoned_invoice_can_recover_liability_but_not_honest_provenance(self):
        wallet = IssuanceWallet(self.seed, self.binding, self.crypto)
        authority, invoice = self.accept_invoice(wallet, 101)
        wallet.abandon(authority)
        receipt = Receipt.for_invoice(
            invoice, 120_000_000,
            hashlib.sha256(b"PUBLIC V3 POISONED LIABILITY").digest())
        record = Delivery(
            0, receipt.commitment(),
            self.crypto.seal(invoice.delivery_pk, receipt.encode()))

        result = recover(self.seed, self.binding, self.crypto,
                         wallet.export_private_ledger(), [record])
        self.assertEqual(result.recovered_liability_sompi, 120_000_000)
        self.assertEqual(result.phase1_consumed_sompi, 0)
        self.assertEqual(result.owned[0].ledger_state, "POISONED")
        self.assertFalse(result.owned[0].phase1_route_completed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
