import copy
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

import actions
import history
from native_runtime import DOMAIN, context, p2sh, public_case, push, quote_id, tx
from owner import metadata_guard, minimum_shape_fee
from primitives import ZERO, h, parse, singleton
import receiver
from synthetic import G


class PublicBoundaryControls(unittest.TestCase):
    def test_backup_hardlink_refused_before_any_public_read(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            backup = base / 'own-backup'
            backup.write_bytes(b'CANARY_UNREAD_BACKUP')
            backup.chmod(0o600)
            public = base / 'public-parameters'
            os.link(backup, public)
            with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('private bytes read')):
                with self.assertRaisesRegex(ValueError, 'public-input-aliases-own-backup'):
                    metadata_guard(backup, [public], base / 'fresh-output')

    def test_backup_symlink_refused_before_any_public_read(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            backup = base / 'own-backup'
            backup.write_bytes(b'CANARY_UNREAD_BACKUP')
            backup.chmod(0o600)
            public = base / 'public-manifest'
            public.symlink_to(backup)
            with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('private bytes read')):
                with self.assertRaisesRegex(ValueError, 'symlink-path'):
                    metadata_guard(backup, [public], base / 'fresh-output')

    def test_strict_duplicate_JSON_fields(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-JSON-field'):
            parse('{"seed":"PUBLIC_CANARY","seed":"PUBLIC_OTHER"}')

    def test_quote_excludes_proof_and_derived_ID_only(self):
        redeem = b'PUBLIC_CANARY_FAKE_PROGRAM'
        signature = push(bytes(65)) + push(bytes(128)) + push(bytes(300))
        previous = {'transactionId': '11' * 32, 'index': 0}
        body = tx(previous, [(1_000_000_000, ('000020' + G.hex() + 'ac'))],
                  b'PUBLIC_NOT_NATIVE_ACTION', signature, 1600)
        entries = [context(2_000_000_000, redeem, 7)]
        expected = quote_id(body, entries, 100)
        changed = copy.deepcopy(body)
        raw = bytearray.fromhex(changed['inputs'][0]['signatureScript'])
        raw[68:196] = bytes([1]) * 128
        changed['inputs'][0]['signatureScript'] = raw.hex()
        changed['id'] = '22' * 32
        self.assertEqual(quote_id(changed, entries, 100), expected)
        for mutate in (
                lambda b: b['outputs'][0].update(value=999_999_999),
                lambda b: b['inputs'][0].update(computeBudget=1601),
                lambda b: b.update(mass=1)):
            changed = copy.deepcopy(body)
            mutate(changed)
            self.assertNotEqual(quote_id(changed, entries, 100), expected)
        changed_entries = copy.deepcopy(entries)
        changed_entries[0]['block_daa_score'] = '8'
        self.assertNotEqual(quote_id(body, changed_entries, 100), expected)
        for key, value in [('is_coinbase', True), ('covenant_id', '11' * 32),
                           ('amount_sompi', 2_000_000_000), ('block_daa_score', '07'),
                           ('script_public_key', 'NOT_HEX')]:
            changed_entries = copy.deepcopy(entries)
            changed_entries[0][key] = value
            with self.assertRaises(ValueError):
                quote_id(body, changed_entries, 100)

    def test_strict_singleton_bootstrap_refuses_hidden_initial_CM(self):
        from synthetic import note, box
        note_bytes = note('PUBLIC_BOOTSTRAP', 1_000_000_000)[0]
        cipher = box('PUBLIC_BOOTSTRAP', 0)
        snapshot = singleton(DOMAIN, note_bytes, cipher)
        class PublicEmitter:
            def emit(self, state, compact, wide):
                return b'\x4c\x70' + state + b'PUBLIC_NOT_REAL_PROGRAM'
        emitter = PublicEmitter()
        redeem = emitter.emit(snapshot.state(DOMAIN), b'', b'')
        payload = b'KPX2GN01' + DOMAIN + note_bytes + snapshot.deliveries[0].cm + cipher + h(cipher)
        previous = {'transactionId': '11' * 32, 'index': 0}
        body = tx(previous, [(1_000_000_000, p2sh(redeem))], payload, bytes(66), 10)
        body['id'] = '22' * 32
        source = {'amount_sompi': '1000001000', 'script_public_key': '000020' + G.hex() + 'ac'}
        selected = {'initial_redeem_hex': redeem.hex(),
                    'founding_outpoint': {'transactionId': body['id'], 'index': 0}}
        valid, value, _ = history.validate_genesis(body, source, selected, emitter, b'', b'')
        self.assertEqual((valid.cm_cursor, len(valid.nullifiers), value), (1, 1, 1_000_000_000))
        forged = bytearray(redeem)
        forged[74:78] = (2).to_bytes(4, 'little')
        selected['initial_redeem_hex'] = forged.hex()
        body['outputs'][0]['scriptPublicKey'] = p2sh(bytes(forged))
        with self.assertRaisesRegex(ValueError, 'strict-singleton-initial-policy-reserve-outpoint'):
            history.validate_genesis(body, source, selected, emitter, b'', b'')


class EstablishedCryptoBatchControls(unittest.TestCase):
    def test_all32_own_receipts_recover_at_physical_positions_and_drain(self):
        """Crypto/state integration only; no PK, proof, native or chain claim."""
        crypto, v2 = receiver.Crypto(), receiver.module()
        payer_seed = h(b'PUBLIC_CANARY_SPARSE_PAYER_SEED_DO_NOT_FUND')
        payer = v2.Receiver(payer_seed, DOMAIN, crypto)
        owners = [v2.Receiver(h(b'PUBLIC_CANARY_OWNER_DO_NOT_FUND', i.to_bytes(4, 'little')),
                              DOMAIN, crypto) for i in range(32)]
        gross = 1_018_867_700
        wide_fee = minimum_shape_fee(32, 23575, 100)
        reserve = 32 * gross + wide_fee
        initial = v2.Receipt.for_invoice(payer.invoice(0), reserve, h(b'PUBLIC_CANARY_INITIAL_RHO'))
        cipher = crypto.seal(payer.invoice(0).delivery_pk, initial.encode())
        before = singleton(DOMAIN, initial.note_bytes(), cipher)
        recovered = receiver.recover(payer, before, before.state(DOMAIN))
        point = {'transactionId': '33' * 32, 'index': 0}
        candidate = actions.payment(payer, before, recovered.owned[0], point, reserve, wide_fee,
            [owner.invoice(0).encode() for owner in owners], [gross] * 32)
        snapshot, reserve = candidate.after, candidate.reserve_after
        self.assertEqual((snapshot.cm_cursor, len(snapshot.deliveries)), (64, 33))
        self.assertEqual(candidate.auth[268:300], h(candidate.cm_list))
        payouts, fees = [], [wide_fee]
        for ordinal, wallet in enumerate(owners):
            restored = receiver.recover(wallet, snapshot, snapshot.state(DOMAIN))
            claims = [claim for claim in restored.owned if claim.owner_action_available]
            self.assertEqual(len(claims), 1)
            claim = claims[0]
            self.assertTrue(32 <= claim.position < 64)
            self.assertEqual(claim.receipt.value_sompi, gross)
            mode = 0 if claim.receipt.value_sompi == reserve else 2
            fee = minimum_shape_fee(mode, 23575, 100)
            seed = h(b'PUBLIC_CANARY_OWNER_DO_NOT_FUND', ordinal.to_bytes(4, 'little'))
            exited = actions.cashout(seed, wallet, snapshot, claim, point, point, reserve, fee)
            with self.assertRaisesRegex(ValueError, 'owned-original-unspent-nullifier'):
                actions.cashout(seed, wallet, exited.after, claim, point, point, reserve, fee)
            snapshot, reserve = exited.after, exited.reserve_after
            payouts.append(exited.payout)
            fees.append(exited.fee)
        self.assertEqual((snapshot.cm_cursor, len(snapshot.deliveries), len(snapshot.nullifiers)), (126, 95, 67))
        self.assertEqual(reserve, 0)
        self.assertEqual(payouts, [1_000_000_000] * 31 + [1_000_149_500])
        self.assertEqual(initial.value_sompi, sum(payouts) + sum(fees))


if __name__ == '__main__':
    unittest.main()
