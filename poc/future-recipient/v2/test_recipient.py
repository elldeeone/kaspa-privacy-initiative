"""Meaningful recipient/DA/authority controls. No prover, node or wallet import."""
from dataclasses import replace
import hashlib
import hmac
import os
from pathlib import Path
import unittest

from recipient import *


class RecipientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = Crypto(Path(os.environ["KPX_RECIPIENT_CRYPTO"]))
        cls.domain = h(b"KPI/future-private-native-integration/DO-NOT-FUND/v1/2026-10-23")
        cls.alice = Receiver(h(b"PUBLIC_SYNTHETIC_ALICE_SEED_DO_NOT_FUND"), cls.domain, cls.crypto)
        cls.bob_seed = h(b"PUBLIC_SYNTHETIC_BOB_SEED_DO_NOT_FUND")
        cls.bob = Receiver(cls.bob_seed, cls.domain, cls.crypto)

    def delivery(self, index=7, position=0, value=120_000_000, receiver=None, rho=None):
        receiver = receiver or self.bob
        return deliver(self.crypto, receiver.invoice(index), value,
                       rho or h(b"PUBLIC_SYNTHETIC_RHO", u32(position)), position)

    def snapshot(self, records=None, spent=()):
        snap = Snapshot(records or [self.delivery()], nf_entries(list(spent)))
        return snap, snap.pin(self.domain)

    def altered(self, receipt, **fields):
        changed = replace(receipt, **fields)
        return Delivery(0, changed.commitment(), self.crypto.seal(self.bob.invoice(7).delivery_pk,
                                                                 changed.encode()))

    def test_01_hmac_rfc4231_and_exact_key_messages(self):
        self.assertEqual(hmac.digest(bytes([0x0b]) * 20, b"Hi There", "sha256").hex(),
                         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        expected = hmac.new(self.bob_seed, b"KPX1DRV\0KSECRET\0" + self.domain + u64(7),
                            hashlib.sha256).digest()
        self.assertEqual(derive(self.bob_seed, self.domain, b"KSECRET\0", 7), expected)
        self.assertNotEqual(expected, derive(self.bob_seed, self.domain, b"OWNSEC\0\0", 7))

    def test_02_supported_secp_bridge_known_vector_and_invalid_scalar(self):
        self.assertEqual(self.crypto.xonly((3).to_bytes(32, "big")).hex(),
                         "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
        for secret in (ZERO, bytes.fromhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")):
            with self.assertRaisesRegex(Invalid, "^crypto-scalar$"):
                self.crypto.xonly(secret)

    def test_03_backup_before_receipt_recovers_large_unknown_invoice_index(self):
        index = (1 << 64) - 1
        # Backup is seed-only and exists before the sender constructs a receipt.
        backup = bytes(self.bob_seed)
        record = self.delivery(index=index)
        restored = Receiver(backup, self.domain, self.crypto)
        snap, pin = self.snapshot([record])
        result = recover(restored, pin, snap)
        self.assertEqual(result.owned[0].receipt.index, index)
        self.assertEqual(result.normal_credit_sompi, 120_000_000)

    def test_04_public_invoice_sender_and_domain_stable_delivery(self):
        invoice = Invoice.parse(self.bob.invoice(7).encode())
        self.assertEqual(len(invoice.encode()), 208)
        self.assertNotEqual(invoice.incoming, self.bob.invoice(8).incoming)
        self.assertEqual(invoice.delivery_pk, self.bob.invoice(8).delivery_pk)
        self.assertNotEqual(invoice.incoming, invoice.delivery_pk)
        self.assertNotEqual(invoice.owner, self.bob.invoice(8).owner)
        self.assertNotEqual(invoice.key_commitment, self.bob.invoice(8).key_commitment)
        self.assertNotEqual(invoice.native_pk, self.bob.invoice(8).native_pk)
        self.assertNotEqual(invoice.incoming, self.alice.invoice(7).incoming)
        record = deliver(self.crypto, invoice, 60_000_000, h(b"public sender rho"), 0)
        self.assertEqual(len(record.ciphertext), 264)
        self.assertEqual(self.bob.open(record.ciphertext).commitment(), record.cm)

    def test_05_real_sealed_box_randomness_integrity_and_wrong_receiver(self):
        first, second = self.delivery(), self.delivery()
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertEqual(self.bob.open(first.ciphertext), self.bob.open(second.ciphertext))
        with self.assertRaisesRegex(Invalid, "^crypto-unseal$"):
            self.alice.open(first.ciphertext)
        tampered = first.ciphertext[:-1] + bytes([first.ciphertext[-1] ^ 1])
        with self.assertRaisesRegex(Invalid, "^crypto-unseal$"):
            self.bob.open(tampered)

    def test_06_invoice_canonical_parse(self):
        raw = self.bob.invoice(7).encode()
        for bad in (raw[:-1], raw + b"\0", b"BADMAGIC" + raw[8:]):
            with self.assertRaises(Invalid):
                Invoice.parse(bad)

    def test_07_receipt_strict_ranges_and_lengths(self):
        invoice = self.bob.invoice(7)
        for value in (True, -1, 0, MIN_NOTE_SOMPI - 1, MAX_SOMPI + 1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(Invalid):
                Receipt.for_invoice(invoice, value, ZERO).encode()
        for value in (MIN_NOTE_SOMPI, MAX_SOMPI):
            note = Receipt.for_invoice(invoice, value, ZERO)
            self.assertEqual(Receipt.parse(note.encode()), note)
        raw = Receipt.for_invoice(invoice, MIN_NOTE_SOMPI, ZERO).encode()
        for bad in (raw[:-1], raw + b"\0", b"BADMAGIC" + raw[8:]):
            with self.assertRaises(Invalid):
                Receipt.parse(bad)

    def test_08_sender_substitutions_rejected_before_credit(self):
        receipt = self.bob.open(self.delivery().ciphertext)
        changes = {"owner": h(b"wrong owner"), "incoming": h(b"wrong incoming"),
                   "key_commitment": h(b"sender chosen NF credential"),
                   "native_pk": self.alice.invoice(7).native_pk, "index": 8,
                   "domain": h(b"wrong domain")}
        for key, value in changes.items():
            with self.subTest(field=key):
                record = self.altered(receipt, **{key: value})
                snap, pin = self.snapshot([record])
                result = recover(self.bob, pin, snap)
                self.assertEqual(result.normal_credit_sompi, 0)
                self.assertEqual(result.owned, [])
                self.assertEqual(len(result.rejected), 1)

    def test_09_sender_chosen_key_that_matches_cm_still_rejected(self):
        original = self.bob.open(self.delivery().ciphertext)
        changed = self.altered(original, key_commitment=h(KEY_TAG, self.domain, h(b"sender k")))
        # The accepted CM is consistent with the altered opening. Descriptor
        # ownership, not just successful decryption/CM equality, rejects it.
        self.assertEqual(self.bob.crypto.unseal(self.bob.keys(7).delivery_secret,
                                              changed.ciphertext)[152:184],
                         h(KEY_TAG, self.domain, h(b"sender k")))
        snap, pin = self.snapshot([changed])
        self.assertEqual(recover(self.bob, pin, snap).rejected[0]["reason"], "receipt-descriptor")

    def test_10_consistent_decryption_wrong_accepted_cm_rejected(self):
        record = replace(self.delivery(), cm=h(b"another accepted CM"))
        snap, pin = self.snapshot([record])
        result = recover(self.bob, pin, snap)
        self.assertEqual(result.rejected[0]["reason"], "receipt-cm")
        self.assertEqual(result.normal_credit_sompi, 0)

    def test_11_spent_receipt_not_credit_and_current_witness_rejected(self):
        record = self.delivery()
        note = self.bob.open(record.ciphertext)
        nullifier = self.bob.nullifier(note, 0)
        snap, pin = self.snapshot([record], [nullifier])
        result = recover(self.bob, pin, snap)
        self.assertEqual(result.normal_credit_sompi, 0)
        self.assertTrue(result.owned[0].spent)
        self.assertFalse(result.owned[0].owner_action_available)
        with self.assertRaisesRegex(Invalid, "^already-spent$"):
            exit_witness(self.bob, result.owned[0], pin, snap)

    def test_12_reused_invoice_no_new_credit_and_no_retroactive_freeze(self):
        records = [self.delivery(position=i) for i in range(2)]
        snap, pin = self.snapshot(records)
        result = recover(self.bob, pin, snap)
        self.assertEqual(result.normal_credit_sompi, 120_000_000)
        self.assertEqual(result.all_owned_unspent_sompi, 240_000_000)
        self.assertFalse(result.owned[0].duplicate_invoice)
        self.assertTrue(result.owned[1].duplicate_invoice)
        self.assertTrue(all(c.privacy_contaminated and c.owner_action_available for c in result.owned))
        # Both owner-authorized paths remain constructible; this avoids a
        # descriptor-holder freezing earlier funds with an unsolicited reuse.
        for claim in result.owned:
            self.assertEqual(exit_witness(self.bob, claim, pin, snap)["nf"], claim.nf.hex())

    def test_13_identical_cm_new_position_still_distinct_owned_liability(self):
        first = self.delivery()
        snap, pin = self.snapshot([first, replace(first, position=1)])
        result = recover(self.bob, pin, snap)
        self.assertEqual(len(result.owned), 2)
        self.assertEqual(result.owned[0].receipt.commitment(), result.owned[1].receipt.commitment())
        self.assertNotEqual(result.owned[0].nf, result.owned[1].nf)
        self.assertEqual(result.all_owned_unspent_sompi, 240_000_000)
        self.assertEqual(result.normal_credit_sompi, 120_000_000)

    def test_14_spent_historical_invoice_does_not_reset_one_time_use(self):
        records = [self.delivery(position=i) for i in range(2)]
        first_nf = self.bob.nullifier(self.bob.open(records[0].ciphertext), 0)
        snap, pin = self.snapshot(records, [first_nf])
        result = recover(Receiver(self.bob_seed, self.domain, self.crypto), pin, snap)
        self.assertEqual(result.normal_credit_sompi, 0)
        self.assertEqual(result.all_owned_unspent_sompi, 120_000_000)
        self.assertTrue(result.owned[1].owner_action_available)

    def test_15_duplicate_record_same_position_and_reordered_archive_rejected(self):
        first, second = self.delivery(), self.delivery(index=8, position=1)
        for records in ([first, first], [second, first]):
            snap, pin = self.snapshot(records)
            with self.assertRaisesRegex(Invalid, "^snapshot-order$"):
                recover(self.bob, pin, snap)

    def test_16_archive_missing_or_substituted_ciphertext_is_not_recovery(self):
        snap, pin = self.snapshot()
        unavailable = Snapshot([replace(snap.deliveries[0], ciphertext=None)], snap.nullifiers)
        with self.assertRaisesRegex(Invalid, "^receipt-data-unavailable$"):
            recover(self.bob, pin, unavailable)
        modified = Snapshot([replace(snap.deliveries[0], ciphertext=b"untrusted replacement")], snap.nullifiers)
        with self.assertRaisesRegex(Invalid, "^archive-pin$"):
            recover(self.bob, pin, modified)

    def test_17_stale_wrong_state_counts_and_domain(self):
        snap, pin = self.snapshot()
        for changed, reason in ((replace(pin, n=2), "snapshot-count"),
                                (replace(pin, m=2), "snapshot-count"),
                                (replace(pin, cm_root=ZERO), "snapshot-root"),
                                (replace(pin, nf_root=ZERO), "snapshot-root"),
                                (replace(pin, domain=ZERO), "snapshot-domain")):
            with self.subTest(reason=reason), self.assertRaisesRegex(Invalid, "^" + reason + "$"):
                recover(self.bob, changed, snap)

    def test_18_nf_link_invariants_reject_even_under_matching_oracle_root(self):
        record = self.delivery()
        a, b = (1).to_bytes(32, "little"), (2).to_bytes(32, "little")
        bad_sets = [
            [NFEntry(a, ZERO, 0)],
            [NFEntry(ZERO, a, 1), NFEntry(a, ZERO, 0), NFEntry(a, ZERO, 0)],
            [NFEntry(ZERO, b, 2), NFEntry(a, ZERO, 0), NFEntry(b, ZERO, 0)],
            [NFEntry(ZERO, a, 1), NFEntry(a, b, 1)],
            [NFEntry(ZERO, ZERO, 1)],
        ]
        for entries in bad_sets:
            with self.subTest(entries=entries):
                snap = Snapshot([record], entries)
                with self.assertRaises(Invalid):
                    recover(self.bob, snap.pin(self.domain), snap)

    def test_19_new_private_padding_counter_not_old_parity_or_m_le_n(self):
        # n=1,m=3 is allowed by the candidate 2*n+1 capacity bound. These are
        # arbitrary synthetic historical NFs, not proof of legitimate lineage.
        snap, pin = self.snapshot(spent=[h(b"dummy1"), h(b"dummy2")])
        self.assertEqual((pin.n, pin.m), (1, 3))
        self.assertEqual(recover(self.bob, pin, snap).normal_credit_sompi, 120_000_000)
        with self.assertRaisesRegex(Invalid, "^nf-counter$"):
            snap.verify(replace(pin, m=4))

    def test_20_current_witness_paths_and_intermediate_append_root(self):
        snap, pin = self.snapshot()
        claim = recover(self.bob, pin, snap).owned[0]
        witness = exit_witness(self.bob, claim, pin, snap)
        cm_tree, nf_tree = snap.verify(pin)
        self.assertEqual(fold_path(claim.receipt.commitment(), claim.position,
                                  [bytes.fromhex(x) for x in witness["cm_path"]], CM_NODE), pin.cm_root)
        predecessor = snap.nullifiers[witness["predecessor_index"]]
        self.assertEqual(fold_path(predecessor.leaf(), 0,
                                  [bytes.fromhex(x) for x in witness["predecessor_path"]], NF_NODE), pin.nf_root)
        updated = NFEntry(predecessor.value, claim.nf, pin.m)
        intermediate = nf_tree.with_leaf(0, updated.leaf())
        self.assertEqual(intermediate.root.hex(), witness["intermediate_nf_root"])
        append_path = [bytes.fromhex(x) for x in witness["append_path_after_predecessor_update"]]
        self.assertEqual(fold_path(NF_EMPTY, pin.m, append_path, NF_NODE), intermediate.root)
        self.assertNotEqual(fold_path(NF_EMPTY, pin.m, nf_tree.path(pin.m), NF_NODE), intermediate.root)
        appended = NFEntry(claim.nf, predecessor.next_value, predecessor.next_index)
        self.assertEqual(fold_path(appended.leaf(), pin.m, append_path, NF_NODE).hex(), witness["successor_nf_root"])

    def test_21_separate_domain_and_position_nf_replay(self):
        receipt = self.bob.open(self.delivery().ciphertext)
        self.assertNotEqual(self.bob.nullifier(receipt, 0), self.bob.nullifier(receipt, 1))
        other = Receiver(self.bob_seed, h(b"OTHER_DOMAIN"), self.crypto)
        self.assertNotEqual(self.bob.invoice(7).key_commitment, other.invoice(7).key_commitment)
        self.assertNotEqual(self.bob.invoice(7).native_pk, other.invoice(7).native_pk)
        with self.assertRaisesRegex(Invalid, "^receipt-descriptor$"):
            other.nullifier(receipt, 0)

    def test_22_restore_has_no_service_or_authorization_input(self):
        # The only inputs are the backup, public archive and explicit synthetic
        # accepted-state pin. There is no service connection to switch back on.
        records = [self.delivery(index=9), self.delivery(index=10, position=1)]
        snap, pin = self.snapshot(records)
        restored = Receiver(bytes(self.bob_seed), self.domain, self.crypto)
        result = recover(restored, pin, snap)
        self.assertEqual(result.normal_credit_sompi, 240_000_000)
        for claim in result.owned:
            self.assertEqual(len(exit_witness(restored, claim, pin, snap)["predecessor_path"]), 17)

    def test_23_exit_rejects_wrong_domain_and_noncanonical_claim_position(self):
        snap, pin = self.snapshot()
        claim = recover(self.bob, pin, snap).owned[0]
        with self.assertRaisesRegex(Invalid, "^snapshot-domain$"):
            exit_witness(self.bob, claim, replace(pin, domain=ZERO), snap)
        for position in (-1, True, 1 << 32, 1):
            changed = replace(claim, position=position)
            with self.subTest(position=position), self.assertRaises(Invalid):
                exit_witness(self.bob, changed, pin, snap)

    def test_24_exit_rejects_inconsistent_oracle_counter_successor(self):
        # Count-valid supplied roots alone do not prove a valid backing/history.
        # This context has no capacity for the declared successor, so refuse it.
        snap, pin = self.snapshot(spent=[h(b"dummy1"), h(b"dummy2")])
        claim = recover(self.bob, pin, snap).owned[0]
        with self.assertRaisesRegex(Invalid, "^nf-capacity$"):
            exit_witness(self.bob, claim, pin, snap)

    def test_25_exit_zero_nf_guard_is_explicit(self):
        snap, pin = self.snapshot()
        claim = recover(self.bob, pin, snap).owned[0]
        # An explicit boundary injection, not a claimed real HMAC preimage.
        restored = Receiver(self.bob_seed, self.domain, self.crypto)
        restored.nullifier = lambda receipt, position: ZERO
        with self.assertRaisesRegex(Invalid, "^nf-zero$"):
            exit_witness(restored, claim, pin, snap)

    def test_26_delivery_pk_substitution_rejected_and_not_in_note_or_reveal(self):
        invoice = self.bob.invoice(7)
        self.bob.validate_invoice(invoice)
        wrong = replace(invoice, delivery_pk=self.alice.invoice(0).delivery_pk)
        with self.assertRaisesRegex(Invalid, "^invoice-descriptor$"):
            self.bob.validate_invoice(wrong)
        # A sender obeying the wrong delivery field cannot deliver to Bob;
        # successful decryption is not claimed to authenticate the sender.
        record = deliver(self.crypto, wrong, 120_000_000, h(b"wrong delivery key"), 0)
        snap, pin = self.snapshot([record])
        result = recover(self.bob, pin, snap)
        self.assertEqual(result.normal_credit_sompi, 0)
        self.assertEqual(result.rejected[0]["reason"], "crypto-unseal")
        normal = self.delivery()
        note = self.bob.open(normal.ciphertext)
        self.assertEqual(len(note.note_bytes()), 168)
        self.assertEqual(len(note.encode()), 216)
        self.assertNotIn(invoice.delivery_pk, note.note_bytes())
        self.assertNotIn(invoice.delivery_pk, note.encode())

    def test_27_wrong_delivery_field_old_invoice_and_profile_rejected(self):
        invoice = self.bob.invoice(7)
        note = Receipt.for_invoice(invoice, 120_000_000, h(b"V2 new receipt"))
        bad_cipher = self.crypto.seal(invoice.incoming, note.encode())
        with self.assertRaisesRegex(Invalid, "^crypto-unseal$"):
            self.bob.open(bad_cipher)
        for old in (b"KPX1IN01" + invoice.encode()[8:176],
                    b"KPX1IN01" + invoice.encode()[8:]):
            with self.assertRaises(Invalid):
                Invoice.parse(old)
        # V1's note incoming was deliveryPK. Its old width/receipt magic does
        # not make its consistently formed note acceptable under the V2 pin.
        v1_note = replace(note, incoming=invoice.delivery_pk,
                          owner=h(OWNER_TAG, self.domain, self.bob.keys(7).owner_secret,
                                  invoice.delivery_pk))
        v1_cipher = self.crypto.seal(invoice.delivery_pk, v1_note.encode())
        with self.assertRaisesRegex(Invalid, "^receipt-descriptor$"):
            self.bob.open(v1_cipher)
        snap, pin = self.snapshot()
        with self.assertRaisesRegex(Invalid, "^unsupported-recipient-profile$"):
            recover(self.bob, replace(pin, recipient_profile="KPX1-INVOICE176"), snap)


if __name__ == "__main__":
    unittest.main(verbosity=2)
