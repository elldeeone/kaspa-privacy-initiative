"""ADR80 public known-seed controls using real mature secp and EdDSA.

No actual Original, private trial, native acceptance or privacy experiment is
used here. Genuine existing-key proof/native controls are recorded separately.
"""
from dataclasses import replace
import json
import unittest
from unittest.mock import patch

import exit_wire
import fresh_self_payout as fresh
import wallet_profile as wallet
import test_exit_wire as exit_controls
from test_wallet_profile import NODE, CRYPTO, JS_ROOT, LEAF_MAP, LEAF_MAP_SHA, SEEDS, PROFILE


class FreshSelfPayoutControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = wallet.Authority(NODE, wallet.authenticate_js(LEAF_MAP, LEAF_MAP_SHA, JS_ROOT))
        cls.crypto = wallet.Crypto(CRYPTO)
        cls.receiver = wallet.Receiver(SEEDS[0], PROFILE, cls.crypto, cls.authority)

    @classmethod
    def tearDownClass(cls):
        cls.authority.close()

    def fixture(self):
        instance = exit_controls.ExitWireControls()
        instance.receiver, instance.crypto = self.receiver, self.crypto
        return instance.fixture()

    def destination(self, raw_body, script, tail):
        changed = bytearray(raw_body)
        changed[376:412] = script
        return exit_wire.projection(bytes(changed), tail)

    def test_deterministic_Original_only_public_projection_recovery(self):
        context, claim, _, projection, tail = self.fixture()
        action = exit_wire.validate_public(projection).action
        first = fresh.derive(self.receiver, context, claim.nf, action)
        restored = wallet.Receiver(SEEDS[0], PROFILE, self.crypto, self.authority)
        historical = fresh.recover_history(restored, replace(claim, spent=True), projection, tail)
        self.assertEqual(historical.kind, 'fresh-self')
        self.assertEqual(historical.owned_key.secret, first.secret)
        self.assertEqual(self.crypto.xonly(historical.owned_key.secret), first.public_key)
        self.assertEqual(first.script_public_key, exit_wire.validate_public(projection).payout_spk)

    def test_public_note_nonce_and_selected_head_separate_keys(self):
        context, claim, _, projection, _ = self.fixture()
        action = exit_wire.validate_public(projection).action
        keys = [fresh.derive(self.receiver, context, claim.nf, action).public_key,
            fresh.derive(self.receiver, context, bytes([83]) * 32, action).public_key,
            fresh.derive(self.receiver, context, claim.nf, bytes([84]) * 32).public_key,
            fresh.derive(self.receiver, replace(context, point=bytes([85]) * 32 + bytes(4)), claim.nf, action).public_key,
            fresh.derive(self.receiver, replace(context, nf_root=bytes([86]) * 32), claim.nf, action).public_key]
        self.assertEqual(len(set(keys)), len(keys))
        # Restoring an old actual Exit does not use the later ambient head.
        self.assertEqual(keys[0], fresh.derive(self.receiver, context, claim.nf, action).public_key)

    def test_native_key_recovery_needs_no_receipt_invoice_or_note_cache(self):
        _, _, _, projection, tail = self.fixture()
        restored = wallet.Receiver(SEEDS[0], PROFILE, self.crypto, self.authority)
        with patch.object(restored, 'keys', side_effect=AssertionError('no receipt/index lookup allowed')):
            owned = fresh.recover_public(restored, projection, tail)
        self.assertIsNotNone(owned)
        self.assertEqual(owned.script_public_key, exit_wire.validate_public(projection).payout_spk)

    def test_first_canonical_secp_scalar_rejection_and_no_reduction(self):
        context, claim, _, projection, _ = self.fixture()
        action = exit_wire.validate_public(projection).action
        proposed = [bytes(32), fresh.SECP_N.to_bytes(32, 'big'), (fresh.SECP_N + 1).to_bytes(32, 'big'), (1).to_bytes(32, 'big')]
        retries = []
        def candidate(_root, _identity, retry):
            retries.append(retry)
            return proposed[retry]
        with patch.object(fresh, 'candidate', candidate):
            payout = fresh.derive(self.receiver, context, claim.nf, action)
        self.assertEqual(retries, [0, 1, 2, 3])
        self.assertEqual(payout.secret, (1).to_bytes(32, 'big'))
        self.assertEqual(payout.public_key.hex(), '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')

    def test_malformed_identity_and_wrong_profile_refuse(self):
        context, claim, _, projection, _ = self.fixture()
        action = exit_wire.validate_public(projection).action
        for nf, nonce in ((bytes(32), action), (claim.nf, bytes(32)), (b'x', action), (claim.nf, b'x'), (True, action)):
            with self.assertRaises(wallet.Invalid): fresh.derive(self.receiver, context, nf, nonce)
        with self.assertRaises(wallet.Invalid):
            fresh.derive(self.receiver, replace(context, profile=bytes([87]) * 32), claim.nf, action)
        with patch.object(fresh, 'candidate', lambda *_: b'bad'):
            with self.assertRaises(wallet.Invalid): fresh.derive(self.receiver, context, claim.nf, action)

    def test_new_authorization_refuses_legacy_and_arbitrary_destinations(self):
        context, claim, raw_body, projection, tail = self.fixture()
        allowed = wallet.authorize_exit(self.receiver, claim, projection, context, tail, approved_fee_sompi=1_000_000)
        self.assertTrue(self.authority.verify(allowed.statement, allowed.authorization))
        legacy = b'\0\0\x20' + claim.receipt.native_pk + b'\xac'
        with self.assertRaisesRegex(wallet.Invalid, 'invoice-linked-destination-refused'):
            wallet.authorize_exit(self.receiver, claim, self.destination(raw_body, legacy, tail), context, tail,
                                  approved_fee_sompi=1_000_000)
        other = b'\0\0\x20' + bytes([88]) * 32 + b'\xac'
        with self.assertRaisesRegex(wallet.Invalid, 'selected-fresh-self-destination'):
            wallet.authorize_exit(self.receiver, claim, self.destination(raw_body, other, tail), context, tail,
                                  approved_fee_sompi=1_000_000)

    def test_actual_signature_binds_changed_destination_fee_head_and_nonce(self):
        context, claim, raw_body, projection, tail = self.fixture()
        signed = wallet.authorize_exit(self.receiver, claim, projection, context, tail, approved_fee_sompi=1_000_000)
        for offset in (8 + 160, 284, 379):
            raw = bytearray(raw_body); raw[offset] ^= 1
            changed = exit_wire.projection(bytes(raw), tail)
            self.assertFalse(self.authority.verify(exit_wire.statement(changed), signed.authorization))
        raw = bytearray(raw_body)
        raw[360:368] = (1_000_001).to_bytes(8, 'little')
        raw[368:376] = (198_999_999).to_bytes(8, 'little')
        changed = exit_wire.projection(bytes(raw), tail)
        self.assertFalse(self.authority.verify(exit_wire.statement(changed), signed.authorization))

    def test_historical_legacy_and_other_destinations_do_not_invalidate_history(self):
        _, claim, raw_body, _, tail = self.fixture()
        legacy = b'\0\0\x20' + claim.receipt.native_pk + b'\xac'
        restored = wallet.Receiver(SEEDS[0], PROFILE, self.crypto, self.authority)
        owned = fresh.recover_history(restored, replace(claim, spent=True), self.destination(raw_body, legacy, tail), tail)
        self.assertEqual(owned.kind, 'legacy-invoice-key')
        self.assertEqual(owned.owned_key.script_public_key, legacy)
        self.assertEqual(self.crypto.xonly(owned.owned_key.secret), claim.receipt.native_pk)
        outside = wallet.Receiver(SEEDS[2], PROFILE, self.crypto, self.authority).invoice(19).native_pk
        result = fresh.recover_history(restored, replace(claim, spent=True),
            self.destination(raw_body, b'\0\0\x20' + outside + b'\xac', tail), tail)
        self.assertEqual(result.kind, 'other-destination')
        self.assertIsNone(result.owned_key)

    def test_wrong_owner_cannot_claim_historical_native_key(self):
        _, claim, _, projection, tail = self.fixture()
        wrong = wallet.Receiver(SEEDS[1], PROFILE, self.crypto, self.authority)
        with self.assertRaises(wallet.Invalid): fresh.recover_history(wrong, claim, projection, tail)

    def test_known_invoice_lookup_removed_without_hiding_old_baseline(self):
        _, claim, _, projection, _ = self.fixture()
        invoice_script = b'\0\0\x20' + claim.receipt.native_pk + b'\xac'
        known_invoice_scripts = [b'\0\0\x20' + wallet.Receiver(seed, PROFILE, self.crypto, self.authority).invoice(7).native_pk + b'\xac'
                                 for seed in SEEDS]
        self.assertEqual(sum(script == invoice_script for script in known_invoice_scripts), 1)
        fresh_script = exit_wire.validate_public(projection).payout_spk
        self.assertEqual(sum(script == fresh_script for script in known_invoice_scripts), 0)
        # This asserts only exact address equality, not overall anonymity.

    def test_private_owned_key_objects_do_not_repr_or_JSON_export(self):
        context, claim, _, projection, _ = self.fixture()
        key = fresh.derive(self.receiver, context, claim.nf, exit_wire.validate_public(projection).action)
        self.assertNotIn(key.secret.hex(), repr(key))
        with self.assertRaises(TypeError): json.dumps(key)


if __name__ == '__main__':
    unittest.main()
