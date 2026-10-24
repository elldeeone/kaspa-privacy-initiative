"""Public deterministic fixtures only; mock crypto/proofs are not fundable."""
import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch
import history
import paths
import run_owner
import support
import worker
from trees import PublicState, sha


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, paths.ROOT / relative)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


WIRE = load('poc/owner-private-lifecycle/verification/wire.py', '_kpx8_control_wire')
CODEC = load('poc/owner-private-lifecycle/integration/construction/codec.py', '_kpx8_control_codec')
V2 = support.recipient()


class PublicCrypto:
    """Cleartext PUBLIC test envelope, explicitly not encryption."""
    def xonly(self, secret):
        return sha(b'PUBLIC-UNSAFE-XONLY', secret)

    def delivery_public(self, secret):
        return sha(b'PUBLIC-UNSAFE-DELIVERY', secret)

    def seal(self, public, payload):
        return public + payload + bytes(16)

    def unseal(self, secret, cf):
        if cf[:32] != self.delivery_public(secret):
            raise V2.Invalid('crypto-unseal')
        return cf[32:248]


class MockRelation:
    def __init__(self):
        self.calls = []

    def verify(self, role, statement, proof):
        paths.need(proof == bytes([7]) * 128, 'mock-proof-refused')
        self.calls.append((role, statement))

    def output(self, row):
        paths.need(len(row) == 520 and sha(row[96:360]) == row[360:392], 'mock-output-frame')
        self.verify('output', b'KPX8OU01' + support.DOMAIN + row[:96] + row[360:392], row[392:])

    def balance(self, *args):
        pass  # No genuine group-conservation claim from these source controls.

    def commit(self, value, blind):
        return sha(b'PUBLIC-INVALID-CV', value.to_bytes(8, 'little'), blind) * 2

    def prove(self, role, statement, witness):
        self.calls.append((role, statement, witness))
        return bytes([7]) * 128


class WalletControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kpx8-public-unsafe-wallet-controls-')
        self.root = Path(self.temp.name); self.crypto = PublicCrypto(); self.relation = MockRelation()
        self.ids = [bytes([i + 41]).hex() * 32 for i in range(3)]
        self.wallets = [V2.Receiver(bytes([i + 1]) * 32, support.DOMAIN, self.crypto) for i in range(3)]
        self.receipts = [V2.Receipt.for_invoice(w.invoice(0), 2_000_000_000, bytes([i + 80]) * 32)
                         for i, w in enumerate(self.wallets)]
        self.records = []
        for wallet, receipt in zip(self.wallets, self.receipts):
            cf = self.crypto.seal(wallet.invoice(0).delivery_pk, receipt.encode())
            self.records.append(receipt.note_bytes() + receipt.commitment() + cf + sha(cf))
        self.state = PublicState([r.commitment() for r in self.receipts])
        initial = {'state_hex112': self.state.state(support.DOMAIN).hex(), 'reserve_sompi': 6_000_000_000,
                   'outpoint_hex36': (bytes([42]) * 32 + bytes(4)).hex(), 'records_hex496': [r.hex() for r in self.records]}
        self.head = {k: initial[k] for k in ('state_hex112', 'reserve_sompi', 'outpoint_hex36')}
        self.h = {'schema': 'kpx8-owner-private-history/v1', 'domain_hex32': support.DOMAIN.hex(),
                  'genesis': initial, 'transitions': [], 'head': self.head}
        self.owner = self.root / 'owner'; self.owner.mkdir(mode=0o700)
        self.mpc = self.root / 'mpc'; self.mpc.mkdir(mode=0o700)
        self.out = self.root / 'out'; self.out.mkdir(mode=0o700)
        self.a = SimpleNamespace(owner=self.owner, mpc=self.mpc, output=self.out,
            participant_id=self.ids[0], position=0, admission_sompi=2_000_000_000, crypto=None)

    def tearDown(self):
        self.temp.cleanup()

    def parsed(self, value=None, expected=None):
        return history.load(paths.encoded(self.h if value is None else value),
            self.head if expected is None else expected, self.relation, WIRE, CODEC, '11' * 32)

    def test_three_records_reconstruct_selected_checkpoint(self):
        actual = self.parsed()
        self.assertEqual(actual.checkpoint(), self.head)
        self.assertEqual(len(actual.deliveries), 3)

    def test_wrong_checkpoint_refused(self):
        target = dict(self.head, reserve_sompi=5_000_000_000)
        with self.assertRaisesRegex(ValueError, 'selected-checkpoint'):
            self.parsed(expected=target)

    def test_float_and_boolean_amounts_refused(self):
        for value in (6_000_000_000.0, True, -1, 1 << 64):
            changed = copy.deepcopy(self.h); changed['genesis']['reserve_sompi'] = value
            with self.assertRaises(ValueError):
                self.parsed(changed)

    def test_missing_ciphertext_refused(self):
        changed = copy.deepcopy(self.h)
        changed['genesis']['records_hex496'][0] = changed['genesis']['records_hex496'][0][:-2]
        with self.assertRaises(ValueError):
            self.parsed(changed)

    def test_wrong_domain_and_duplicate_records_refused(self):
        changed = copy.deepcopy(self.h); changed['domain_hex32'] = '00' * 32
        with self.assertRaises(ValueError):
            self.parsed(changed)
        changed = copy.deepcopy(self.h); changed['genesis']['records_hex496'][1] = changed['genesis']['records_hex496'][0]
        with self.assertRaises(ValueError):
            self.parsed(changed)

    def test_foreign_ciphertexts_are_expected_but_owned_invalid_is_not(self):
        actual = self.parsed(); owned = history.claims(actual, self.wallets[0], self.ids[0])
        self.assertEqual([(r['position'], r['kind']) for r in owned], [(0, 'initial')])
        malformed = bytearray(self.receipts[0].encode()); malformed[:8] = b'INVALID!'
        actual.deliveries[0] = (self.receipts[0].commitment(),
            self.crypto.seal(self.wallets[0].invoice(0).delivery_pk, bytes(malformed)))
        with self.assertRaisesRegex(V2.Invalid, 'receipt-magic'):
            history.claims(actual, self.wallets[0], self.ids[0])

    def test_decrypted_wrong_domain_and_descriptor_refused(self):
        for at in (8, 48):
            actual = self.parsed(); malformed = bytearray(self.receipts[0].encode()); malformed[at] ^= 1
            actual.deliveries[0] = (self.receipts[0].commitment(),
                self.crypto.seal(self.wallets[0].invoice(0).delivery_pk, bytes(malformed)))
            with self.assertRaises(V2.Invalid):
                history.claims(actual, self.wallets[0], self.ids[0])

    def test_broken_adapter_is_not_foreign_ciphertext(self):
        class Broken(PublicCrypto):
            def unseal(self, secret, cf):
                raise V2.Invalid('crypto-adapter')
        broken = V2.Receiver(bytes([1]) * 32, support.DOMAIN, Broken())
        with self.assertRaisesRegex(V2.Invalid, 'crypto-adapter'):
            history.claims(self.parsed(), broken, self.ids[0])

    def test_invoice_indices_are_session_and_role_separated(self):
        indices = {history.invoice_index(sha(b'PUBLIC SESSION', bytes([round])).hex(), sender, role)
                   for round in range(4) for sender in range(3) for role in (b'PAYMENT\0', b'CHANGE\0\0')}
        self.assertEqual(len(indices), 24)
        self.assertFalse(indices & {0, 0xffffffff})

    def test_init_backup_contains_only_seed_domain_participant(self):
        with patch.object(worker, 'crypto', return_value=self.crypto), \
             patch.object(worker.secrets, 'token_bytes', return_value=bytes([9]) * 32):
            worker.initialize(self.a)
        backup = worker.decode_backup((self.owner / 'BACKUP.json').read_bytes())
        self.assertEqual(set(backup), set(worker.BACKUP_FIELDS))
        public = paths.parse((self.out / 'PUBLIC.json').read_bytes())
        self.assertEqual(len(bytes.fromhex(public['initial_record_hex496'])), 496)
        wallet = V2.Receiver(bytes([9]) * 32, support.DOMAIN, self.crypto)
        self.assertEqual(public['funding']['xonly_hex32'], wallet.keys(0xffffffff).invoice.native_pk.hex())
        self.assertNotEqual(public['funding']['xonly_hex32'], wallet.invoice(0).native_pk.hex())
        self.assertNotIn('seed_hex32', public)

    def test_restore_requires_only_one_original_seed_backup(self):
        original = self.root / 'PUBLIC-UNSAFE-backup.json'
        paths.write_new(original, paths.encoded({'schema': 'kpx8-owner-seed-backup/v1',
            'domain_hex32': support.DOMAIN.hex(), 'participant_id_hex32': self.ids[0], 'seed_hex32': '01' * 32}))
        self.a.backup = original; worker.restore(self.a)
        owner, wallet = worker.own_wallet(self.a, self.crypto)
        self.assertEqual(wallet.invoice(0), self.wallets[0].invoice(0))
        self.assertFalse((self.owner / 'INITIAL-PUBLIC.json').exists())
        self.assertFalse((self.owner / 'attempts').exists())
        with self.assertRaisesRegex(ValueError, 'fresh-restoration'):
            worker.restore(self.a)
    def test_pending_authorization_blocks_new_mix_but_not_fallback_exit(self):
        accepted = self.parsed(); nf = self.wallets[0].nullifier(self.receipts[0], 0)
        attempt = worker.new_attempt(self.a, {'session_sha256': '55' * 32, 'nf_hex32': nf.hex()})
        paths.write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
        with patch.object(worker, 'private_json', wraps=worker.private_json) as reader:
            with self.assertRaisesRegex(ValueError, 'reconciliation-required'):
                worker.reconcile(self.a, accepted)
            worker.reconcile(self.a, accepted, require_settled=False)
            self.assertTrue(all(call.args[0].name == 'GUARD.json' for call in reader.call_args_list))
        self.assertFalse((attempt / 'RECONCILED').exists())
        accepted.state.insert(nf); worker.reconcile(self.a, accepted)
        self.assertTrue((attempt / 'RECONCILED').exists())

    def test_fresh_exit_destination_rederives_from_backup_and_current_point(self):
        accepted = self.parsed(); owned = history.claims(accepted, self.wallets[0], self.ids[0]); claim = owned[0]
        first = worker.payout_spk(accepted, self.wallets[0], owned, claim)
        restored = V2.Receiver(bytes([1]) * 32, support.DOMAIN, self.crypto)
        self.assertEqual(first, worker.payout_spk(accepted, restored, owned, claim))
        self.assertNotEqual(first[3:35], self.wallets[0].invoice(0).native_pk)
        self.assertNotEqual(first[3:35], self.wallets[0].invoice(0xffffffff).native_pk)
        accepted.point = bytes([43]) * 32 + bytes(4)
        self.assertNotEqual(first, worker.payout_spk(accepted, restored, owned, claim))

    def test_spent_note_is_never_selected(self):
        accepted = self.parsed(); nf = self.wallets[0].nullifier(self.receipts[0], 0)
        accepted.state.insert(nf)
        with self.assertRaisesRegex(ValueError, 'no-available-claim'):
            worker.select_claim(accepted, self.wallets[0], self.ids[0], 'any')

    def test_backup_foreign_domain_and_extra_fields_refused(self):
        backup = {'schema': 'kpx8-owner-seed-backup/v1', 'domain_hex32': support.DOMAIN.hex(),
                  'participant_id_hex32': self.ids[0], 'seed_hex32': '01' * 32}
        for changed in (dict(backup, domain_hex32='00' * 32), dict(backup, saved_position=0)):
            with self.assertRaises(ValueError):
                worker.decode_backup(paths.encoded(changed))

    def test_authorization_barrier_is_checked_before_reopening_private_map(self):
        attempt = worker.new_attempt(self.a, {'session_sha256': '55' * 32, 'nf_hex32': '44' * 32})
        paths.write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
        with patch.object(worker, 'load_assets', side_effect=AssertionError('assets opened')), \
             patch.object(worker, 'private_json', side_effect=AssertionError('old map opened')):
            with self.assertRaisesRegex(ValueError, 'reconciliation-required'):
                worker.authorize(self.a)




def public_projection(initial_cms, inputs, rows, session_sha, roster, fee, tail):
    import struct
    state = PublicState(initial_cms); before = state.state(support.DOMAIN)
    nf_paths = [state.insert(nf) for nf, cv in inputs]
    cm_paths = [state.append(row[:32]) for row in rows]; after = state.state(support.DOMAIN)
    point = bytes([42]) * 32 + bytes(4); reserve = 6_000_000_000
    body = (b'KPX8PB01' + struct.pack('<4H', 1, 3, 6, 0) + support.DOMAIN + bytes.fromhex(session_sha)
        + sha(b'KPX8RO01', *(bytes.fromhex(p) for p in roster)) + point + before + reserve.to_bytes(8, 'little')
        + after + (reserve - fee).to_bytes(8, 'little') + fee.to_bytes(8, 'little') + bytes(8) + bytes(32)
        + b''.join(nf + cv for nf, cv in inputs) + b''.join(rows) + b''.join(nf_paths)
        + b''.join(cm_paths) + bytes([7]) * 384)
    prefix = (b'KPX8FX01' + struct.pack('<2H', 1, 1) + point + bytes([255]) * 8
        + reserve.to_bytes(8, 'little') + struct.pack('<H', 37) + WIRE.state_spk(before, tail)
        + struct.pack('<H', 1) + (reserve - fee).to_bytes(8, 'little') + struct.pack('<H', 37)
        + WIRE.state_spk(after, tail) + bytes(37) + WIRE.BODY_LEN.to_bytes(4, 'little'))
    actual = prefix + body; WIRE.validate_public(actual)
    return actual


class AuthorizationControls(unittest.TestCase):
    setUp_base = WalletControls.setUp
    tearDown = WalletControls.tearDown

    def setUp(self):
        self.setUp_base(); self.profile = sha(b'PUBLIC UNSAFE PROFILE').hex()
        self.assets = {'component_profile_sha256': self.profile, 'program_source_sha256': '11' * 32}
        self.a.assets = None; self.a.assets_sha256 = '22' * 32
        self.a.history = self.root / 'HISTORY.json'; paths.write_new(self.a.history, paths.encoded(self.h))
        self.a.history_sha256 = paths.digest(self.a.history.read_bytes())
        self.context = {'schema': 'kpx8-wallet-premix-context/v1', 'domain_hex32': support.DOMAIN.hex(),
            'component_profile_sha256': self.profile, 'prior_state_hex112': self.head['state_hex112'],
            'previous_outpoint_hex36': self.head['outpoint_hex36'], 'reserve_sompi': 6_000_000_000,
            'fee_sompi': 30_000_000, 'fee_shares_sompi': [10_000_000] * 3,
            'native_tail_hex': b'\x75PUBLIC INVALID POLICY'.hex()}
        self.a.context = self.root / 'CONTEXT.json'; paths.write_new(self.a.context, paths.encoded(self.context))
        self.a.context_sha256 = paths.digest(self.a.context.read_bytes())
        self.session = {'schema': 'kpx8-private-construction-session/v1', 'session_id': '33' * 32,
            'domain_hex': support.DOMAIN.hex(), 'prior_state_digest': sha(bytes.fromhex(self.head['state_hex112'])).hex(),
            'circuit_profile_sha256': self.profile, 'public_effects_context_sha256': self.a.context_sha256,
            'roster': self.ids, 'program_source_sha256': '11' * 32, 'tuple_bytes': 520,
            'outputs_per_party': 2, 'mpc_prime': str(support.Q)}
        self.a.session = self.root / 'SESSION.json'; paths.write_new(self.a.session, CODEC.canonical_json(self.session))
        self.a.session_sha256 = paths.digest(self.a.session.read_bytes()); self.session_sha = self.a.session_sha256
        paths.write_new(self.owner / 'BACKUP.json', paths.encoded({'schema': 'kpx8-owner-seed-backup/v1',
            'domain_hex32': support.DOMAIN.hex(), 'participant_id_hex32': self.ids[0], 'seed_hex32': '01' * 32}))
        self.a.party = 0; self.a.note_kind = 'initial'
        self.a.payment_sompi = getattr(self, 'payment_request', None)
        peers = self.root / 'peers'; peers.mkdir()
        for index, wallet in enumerate(self.wallets):
            invoice = wallet.invoice(history.invoice_index(self.session_sha, 0, b'PAYMENT\0'))
            paths.write_new(peers / (str(index) + '.bin'), bytes.fromhex(self.ids[index]) + invoice.encode(), 0o400)
        original = worker.stable_read
        def read(path, *args, **kwargs):
            path = Path(path)
            return original(peers / path.name if path.parent == Path('/peers') else path, *args, **kwargs)
        with patch.object(worker, 'load_assets', return_value=(self.assets, self.relation, self.crypto, CODEC, WIRE)), \
             patch.object(worker, 'stable_read', side_effect=read), patch.object(worker.secrets, 'randbelow', return_value=0):
            worker.prepare(self.a)
        self.ready = paths.parse((self.out / 'PUBLIC.json').read_bytes())
        self.state = worker.private_json(self.owner / 'attempts/000001/STATE.json')
        self.rows = [bytes.fromhex(o['tuple_hex520']) for o in self.state['outputs']]
        for creator in (1, 2):
            for slot in range(2):
                receipt = V2.Receipt.for_invoice(self.wallets[creator].invoice(100 + slot), 995_000_000,
                    bytes([120 + creator * 2 + slot]) * 32)
                cf = self.crypto.seal(self.wallets[creator].invoice(100 + slot).delivery_pk, receipt.encode())
                self.rows.append(receipt.commitment() + bytes([60 + creator + slot]) * 64 + cf + sha(cf) + bytes([7]) * 128)
        self.rows.reverse()
        self.inputs = [(self.wallets[i].nullifier(r, i), self.relation.commit(r.value_sompi,
            bytes.fromhex(self.state['rin_hex32']) if i == 0 else bytes([i]) * 32)) for i, r in enumerate(self.receipts)]
        result = self.mpc / 'mpc-private-publicunsafe/OWN-MPC-PROJECTION.json'; result.parent.mkdir(mode=0o700)
        paths.write_new(result, paths.encoded({'schema': 'kpx8-mixed-complete-outputs/v1',
            'session_sha256': self.session_sha, 'rows_hex': [r.hex() for r in self.rows], 'delta_decimal': '0',
            'tuple_bytes': 520, 'row_count': 6, 'scope': 'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION'}))
        self.a.own_mpc_result = result.relative_to(self.mpc)
        self.a.output = self.root / 'authorization'; self.a.output.mkdir(mode=0o700)
        self.project()

    def project(self, rows=None, fee=None, inputs=None, tail=None):
        raw = public_projection([r.commitment() for r in self.receipts], self.inputs if inputs is None else inputs,
            self.rows if rows is None else rows, self.session_sha, self.ids,
            self.context['fee_sompi'] if fee is None else fee,
            bytes.fromhex(self.context['native_tail_hex']) if tail is None else tail)
        path = self.root / ('PROJECTION-' + str(len(list(self.root.glob('PROJECTION-*')))) + '.bin')
        paths.write_new(path, raw, 0o400); self.a.projection = path; self.a.projection_sha256 = paths.digest(raw)
        return raw

    def authorize(self):
        with patch.object(worker, 'load_assets', return_value=(self.assets, self.relation, self.crypto, CODEC, WIRE)):
            worker.authorize(self.a)

    def test_ready_has_no_recovered_note_identity(self):
        self.assertEqual(set(self.ready), {'schema', 'participant_id_hex32', 'session_sha256', 'nf_hex32',
            'cv_hex64', 'own_output_count', 'mpc_input_written', 'financial_authorization'})
        self.assertNotIn('input_cm_hex32', self.ready)
        self.assertNotIn('position', self.ready)

    def test_authorize_complete_mixed_effects(self):
        self.authorize()
        public = paths.parse((self.a.output / 'PUBLIC.json').read_bytes())
        self.assertEqual(len(bytes.fromhex(public['statement_hex200'])), 200)
        self.assertTrue((self.owner / 'attempts/000001/DISCLOSURE-CLOSED').exists())
        witness = [c[2] for c in self.relation.calls if len(c) == 3 and c[0] == 'spend'][0]
        self.assertEqual(len(witness['cm_path_hex']), 16)
        self.assertNotIn('seed_hex32', witness)

    def test_changed_fee_refused_before_barrier(self):
        self.project(fee=20_000_000)
        with self.assertRaisesRegex(ValueError, 'exact-approved-financial-effects'):
            self.authorize()
        self.assertFalse((self.owner / 'attempts/000001/DISCLOSURE-CLOSED').exists())

    def test_changed_policy_refused(self):
        self.project(tail=b'\x75CHANGED PUBLIC INVALID POLICY')
        with self.assertRaisesRegex(ValueError, 'selected-native-policy'):
            self.authorize()

    def test_missing_own_output_refused(self):
        rows = list(self.rows); own = bytes.fromhex(self.state['outputs'][0]['tuple_hex520'])
        index = rows.index(own); changed = bytearray(own); changed[0] ^= 1; rows[index] = bytes(changed)
        self.project(rows=rows)
        with self.assertRaisesRegex(ValueError, 'same-own-engine-pool'):
            self.authorize()

    def test_foreign_input_skeleton_cannot_authorize_own_note(self):
        inputs = list(self.inputs); inputs[0] = (inputs[0][0], bytes([91]) * 64)
        self.project(inputs=inputs)
        with self.assertRaisesRegex(ValueError, 'own-current-note-NF-CV'):
            self.authorize()

    def test_one_authorization_only_without_reconciliation(self):
        self.authorize()
        with patch.object(worker, 'private_json', side_effect=AssertionError('private map reopened')):
            with self.assertRaisesRegex(ValueError, 'reconciliation-required'):
                self.authorize()
    def test_public_history_verifies_all_components_and_recovers_change(self):
        raw = self.a.projection.read_bytes(); body = WIRE.parse_projection(raw).body
        expected = {'state_hex112': body.new_state.raw.hex(), 'reserve_sompi': body.new_reserve,
                    'outpoint_hex36': (bytes([43]) * 32 + bytes(4)).hex()}
        updated = copy.deepcopy(self.h)
        updated['transitions'] = [{'kind': 'batch', 'session': self.session, 'projection_hex': raw.hex(),
                                  'successor_outpoint_hex36': expected['outpoint_hex36']}]
        updated['head'] = expected
        relation = MockRelation()
        actual = history.load(paths.encoded(updated), expected, relation, WIRE, CODEC, '11' * 32)
        self.assertEqual(len(relation.calls), 9)
        restored = V2.Receiver(bytes([1]) * 32, support.DOMAIN, self.crypto)
        claim = worker.select_claim(actual, restored, self.ids[0], 'change')
        self.assertEqual(claim['receipt'].encode().hex(), self.state['outputs'][1]['receipt_hex216'])
        self.assertEqual(restored.nullifier(claim['receipt'], claim['position']), claim['nf'])
        self.assertEqual(claim['kind'], 'change')
        # Restoration has only original seed and public data, no creator's
        # CV blinding/STATE/TRUTH/receive-index map.
        self.assertNotIn('blind', claim)
        self.assertTrue(any(row['spent'] for row in history.claims(actual, restored, self.ids[0])))

    def test_public_history_rejects_changed_component_proof(self):
        raw = bytearray(self.a.projection.read_bytes()); raw[-1] ^= 1
        body = WIRE.parse_projection(bytes(raw)).body
        expected = {'state_hex112': body.new_state.raw.hex(), 'reserve_sompi': body.new_reserve,
                    'outpoint_hex36': (bytes([43]) * 32 + bytes(4)).hex()}
        updated = copy.deepcopy(self.h)
        updated['transitions'] = [{'kind': 'batch', 'session': self.session, 'projection_hex': raw.hex(),
                                  'successor_outpoint_hex36': expected['outpoint_hex36']}]
        updated['head'] = expected
        with self.assertRaisesRegex(ValueError, 'mock-proof-refused'):
            history.load(paths.encoded(updated), expected, MockRelation(), WIRE, CODEC, '11' * 32)


def public_exit_projection(state, point, reserve, nf, value, fee, payout_spk, tail):
    import struct
    before = state.state(support.DOMAIN); witness = state.insert(nf); after = state.state(support.DOMAIN)
    remaining = reserve - value; payout = value - fee
    body = (b'KPX8XB01' + struct.pack('<4H', 1, 1, 0, 1) + support.DOMAIN + bytes([66]) * 32 + bytes(32)
        + point + before + reserve.to_bytes(8, 'little') + after + remaining.to_bytes(8, 'little')
        + fee.to_bytes(8, 'little') + payout.to_bytes(8, 'little') + payout_spk + nf + witness)
    outputs = ([(remaining, WIRE.state_spk(after, tail))] if remaining else []) + [(payout, payout_spk)]
    prefix = (b'KPX8FX01' + struct.pack('<2H', 1, 1) + point + bytes([255]) * 8 + reserve.to_bytes(8, 'little')
        + struct.pack('<H', 37) + WIRE.state_spk(before, tail) + struct.pack('<H', len(outputs))
        + b''.join(v.to_bytes(8, 'little') + struct.pack('<H', len(spk)) + spk + b'\0' for v, spk in outputs)
        + bytes(36) + len(body).to_bytes(4, 'little'))
    raw = prefix + body; WIRE.validate_exit_public(raw)
    return raw


class ExitControls(unittest.TestCase):
    tearDown = WalletControls.tearDown
    def setUp(self):
        # Only use plain original fixture state; no mixed authorization here.
        WalletControls.setUp(self)
        self.profile = sha(b'PUBLIC UNSAFE PROFILE').hex()
        self.assets = {'component_profile_sha256': self.profile, 'program_source_sha256': '11' * 32}
        self.a.history = self.root / 'HISTORY.json'; paths.write_new(self.a.history, paths.encoded(self.h))
        self.a.history_sha256 = paths.digest(self.a.history.read_bytes())
        self.context = {'schema': 'kpx8-wallet-premix-context/v1', 'domain_hex32': support.DOMAIN.hex(),
            'component_profile_sha256': self.profile, 'prior_state_hex112': self.head['state_hex112'],
            'previous_outpoint_hex36': self.head['outpoint_hex36'], 'reserve_sompi': 6_000_000_000,
            'fee_sompi': 10_000_000, 'fee_shares_sompi': [3_333_333, 3_333_333, 3_333_334],
            'native_tail_hex': b'\x75PUBLIC INVALID POLICY'.hex()}
        self.a.context = self.root / 'CONTEXT.json'; paths.write_new(self.a.context, paths.encoded(self.context))
        self.a.context_sha256 = paths.digest(self.a.context.read_bytes()); self.a.note_kind = 'initial'
        paths.write_new(self.owner / 'BACKUP.json', paths.encoded({'schema': 'kpx8-owner-seed-backup/v1',
            'domain_hex32': support.DOMAIN.hex(), 'participant_id_hex32': self.ids[0], 'seed_hex32': '01' * 32}))
        self.accepted = history.load(paths.encoded(self.h), self.head, self.relation, WIRE, CODEC, '11' * 32)
        self.owned = history.claims(self.accepted, self.wallets[0], self.ids[0]); self.claim = self.owned[0]
        self.spk = worker.payout_spk(self.accepted, self.wallets[0], self.owned, self.claim)
        self.raw = public_exit_projection(self.state, bytes.fromhex(self.head['outpoint_hex36']), 6_000_000_000,
            self.claim['nf'], 2_000_000_000, 10_000_000, self.spk, bytes.fromhex(self.context['native_tail_hex']))
        self.a.projection = self.root / 'EXIT.bin'; paths.write_new(self.a.projection, self.raw, 0o400)
        self.a.projection_sha256 = paths.digest(self.raw)

    def invoke_exit(self):
        with patch.object(worker, 'load_assets', return_value=(self.assets, self.relation, self.crypto, CODEC, WIRE)):
            worker.exit_note(self.a)

    def test_exit_proves_without_creator_blinding_or_MPC(self):
        self.invoke_exit()
        export = paths.parse((self.out / 'PUBLIC.json').read_bytes())
        self.assertEqual(export['statement_hex152'], WIRE.exit_statement(self.raw).hex())
        witness = [c[2] for c in self.relation.calls if len(c) == 3 and c[0] == 'exit'][0]
        self.assertEqual(set(witness), {'schema', 'note_hex168', 's_hex32', 'k_hex32', 'position', 'cm_path_hex'})
        self.assertEqual(list(self.mpc.iterdir()), [])

    def test_unsettled_mixed_authorization_does_not_block_current_exit(self):
        attempt = worker.new_attempt(self.a, {'session_sha256': '55' * 32, 'nf_hex32': self.claim['nf'].hex()})
        paths.write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
        self.invoke_exit()
        self.assertTrue((self.out / 'PUBLIC.json').exists())
        self.assertFalse((attempt / 'RECONCILED').exists())

    def test_changed_payout_destination_refused(self):
        changed = bytearray(self.raw); width = len(changed) - WIRE.EXIT_BODY_LEN
        changed[width + 407] ^= 1
        changed[width - 40 - 37] ^= 1  # arbitrary prefix mutation also must fail.
        self.a.projection = self.root / 'WRONG-EXIT.bin'; paths.write_new(self.a.projection, bytes(changed))
        self.a.projection_sha256 = paths.digest(bytes(changed))
        with self.assertRaises(ValueError):
            self.invoke_exit()

    def test_historical_payout_keys_rederive_after_terminal_head(self):
        self.accepted.exits = [{'point': self.accepted.point, 'nf': self.claim['nf'], 'payout_spk': self.spk,
                               'delivery_count': 3, 'session_count': 0}]
        self.accepted.point = None; self.accepted.reserve = 0
        self.assertTrue(worker.final_payout_reconciliation(self.accepted, self.wallets[0], self.ids[0], self.owned))
        self.accepted.exits[0]['payout_spk'] = b'\0\0\x20' + bytes([77]) * 32 + b'\xac'
        with self.assertRaisesRegex(ValueError, 'historical-payout-key'):
            worker.final_payout_reconciliation(self.accepted, self.wallets[0], self.ids[0], self.owned)


class LauncherControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kpx8-public-unsafe-launcher-controls-')
        self.root = Path(self.temp.name); self.private = self.root / 'private'; self.private.mkdir(mode=0o700)
        self.old = [self.root / ('old-' + str(i)) for i in range(2)]
        for parent in self.old:
            for role in 'ABCD':
                directory = parent / 'owners' / role; directory.mkdir(parents=True)
                paths.write_new(directory / 'backup.json', b'PUBLIC UNSAFE SENTINEL NO REAL SEED')
        self.owners = []
        for i in range(3):
            parent = self.private / ('party-' + str(i)); parent.mkdir(mode=0o700)
            (parent / 'owner').mkdir(mode=0o700); (parent / 'mpc').mkdir(mode=0o700)
            self.owners.append(parent / 'owner')
        self.fake_elf = self.root / 'PUBLIC-INVALID-ELF'
        paths.write_new(self.fake_elf, b'\x7fELFPUBLIC INVALID ELF NEVER EXECUTE', 0o500)
        self.a = SimpleNamespace(operation='init', owner_directory=self.owners[0],
            mpc_directory=self.owners[0].parent / 'mpc', private_run_directory=self.private / 'controller' / 'init-000001',
            output=self.root / 'public', exclude_old_trial=self.old, exclude_new_private_directory=[self.private],
            peer_owner_directory=None, crypto=self.fake_elf, participant_id='41' * 32, position=0,
            admission_sompi=2_000_000_000, assets=None, assets_sha256=None, session=None, session_sha256=None,
            context=None, context_sha256=None, history=None, history_sha256=None,
            projection=None, projection_sha256=None, backup=None, own_mpc_result=None, party=None,
            note_kind='any', execute=False)

    def tearDown(self):
        self.temp.cleanup()

    def staged(self):
        with patch.object(run_owner, 'PRIVATE_PARENT', self.private), \
             patch.object(run_owner, 'CRYPTO_SHA', paths.digest(self.fake_elf.read_bytes())):
            return run_owner.run(self.a)

    def test_staging_has_no_network_and_no_foreign_owner_mounts(self):
        result = self.staged(); self.assertTrue(result['staged']); self.assertFalse(result['executed'])
        plan = paths.parse((self.a.private_run_directory / 'PRIVATE-PLAN.json').read_bytes())
        command = plan['command']; self.assertIn('--unshare-all', command)
        self.assertNotIn(str(self.owners[1]), command); self.assertNotIn(str(self.owners[2]), command)
        self.assertIn(str(self.owners[0]), command)
        self.assertEqual(list(self.a.output.iterdir()), [])
        self.assertFalse((self.a.output / 'PRIVATE-PLAN.json').exists())

    def test_partial_private_exclusions_refused_before_source_read(self):
        self.a.exclude_new_private_directory = [p.parent for p in self.owners]
        with patch.object(run_owner, 'PRIVATE_PARENT', self.private), \
             patch.object(paths, 'stable_read', side_effect=AssertionError('public read before whole-parent check')):
            with self.assertRaisesRegex(ValueError, 'whole-private-parent'):
                run_owner.run(self.a)

    def test_restore_mounts_one_original_leaf_without_reading_it(self):
        backup = self.owners[0] / 'BACKUP.json'; paths.write_new(backup, b'PUBLIC UNSAFE BACKUP SENTINEL')
        fresh = self.private / 'fresh'; fresh.mkdir(mode=0o700)
        self.a.owner_directory = fresh / 'owner'; self.a.owner_directory.mkdir(mode=0o700)
        self.a.mpc_directory = fresh / 'mpc'; self.a.mpc_directory.mkdir(mode=0o700)
        self.a.operation = 'restore'; self.a.backup = backup
        original = paths.stable_read
        def checked_read(path, *args, **kwargs):
            self.assertNotEqual(Path(path), backup, 'supervisor read original seed leaf')
            return original(path, *args, **kwargs)
        with patch.object(paths, 'stable_read', side_effect=checked_read):
            self.staged()
        command = paths.parse((self.a.private_run_directory / 'PRIVATE-PLAN.json').read_bytes())['command']
        at = command.index(str(backup))
        self.assertEqual(command[at - 1:at + 2], ['--ro-bind', str(backup), '/backup.json'])
        self.assertNotIn(str(self.owners[0]), command)

    def test_private_alias_refused_before_first_byte(self):
        sentinel = self.owners[1] / 'OPAQUE'; paths.write_new(sentinel, b'PUBLIC UNSAFE PRIVATE SENTINEL')
        policy = paths.HostPolicy(self.old, [self.private]); alias = self.root / 'alias'; alias.hardlink_to(sentinel)
        with patch.object(paths.os, 'open', side_effect=AssertionError('private alias opened')):
            with self.assertRaisesRegex(ValueError, 'private-alias'):
                policy.read(alias)

    def test_private_metadata_walk_opens_no_leaf(self):
        paths.write_new(self.owners[2] / 'OPAQUE', b'PUBLIC UNSAFE PRIVATE SENTINEL')
        with patch.object(paths.os, 'open', side_effect=AssertionError('metadata opened bytes')):
            policy = paths.HostPolicy(self.old, [self.private])
        self.assertIn(self.private, policy.directories)




class ExactPaymentControls(unittest.TestCase):
    def test_requested_payment_is_exact_and_not_in_ready(self):
        fixture = AuthorizationControls('test_ready_has_no_recovered_note_identity')
        fixture.payment_request = 500_000_000
        try:
            fixture.setUp()
            values = [V2.Receipt.parse(bytes.fromhex(o['receipt_hex216'])).value_sompi
                      for o in fixture.state['outputs']]
            self.assertEqual(values, [500_000_000, 1_490_000_000])
            self.assertNotIn('payment_sompi', fixture.ready)
        finally:
            fixture.tearDown()

    def test_oversized_or_wrongly_typed_request_is_refused(self):
        for amount in (2_000_000_000, 59_999_999, 500_000_000.0, True):
            fixture = AuthorizationControls('test_ready_has_no_recovered_note_identity')
            fixture.payment_request = amount
            try:
                with self.assertRaises(ValueError):
                    fixture.setUp()
                self.assertFalse((fixture.owner / 'attempts').exists())
            finally:
                fixture.tearDown()




class ReceivedChangePreferenceControls(unittest.TestCase):
    setUp = WalletControls.setUp
    tearDown = WalletControls.tearDown

    def private_round_history(self, destinations):
        state = PublicState([r.commitment() for r in self.receipts])
        deliveries = [(r.commitment(), self.crypto.seal(w.invoice(0).delivery_pk, r.encode()))
                      for w, r in zip(self.wallets, self.receipts)]
        for i, receipt in enumerate(self.receipts):
            state.insert(self.wallets[i].nullifier(receipt, i))
        session_sha = sha(b'PUBLIC UNSAFE PREFERENCE ROUND').hex()
        for sender, destination in enumerate(destinations):
            for kind, target, value in ((b'PAYMENT\0', destination, 500_000_000),
                                       (b'CHANGE\0\0', sender, 1_490_000_000)):
                invoice = self.wallets[target].invoice(history.invoice_index(session_sha, sender, kind))
                receipt = V2.Receipt.for_invoice(invoice, value, sha(b'PUBLIC UNSAFE NOTE', bytes([sender]), kind))
                cf = self.crypto.seal(invoice.delivery_pk, receipt.encode())
                state.append(receipt.commitment()); deliveries.append((receipt.commitment(), cf))
        return history.History(state, 5_970_000_000, bytes([43]) * 32 + bytes(4),
                               deliveries, [(session_sha, self.ids)])

    def test_received_preferred_to_larger_change_and_missing_received_falls_back(self):
        accepted = self.private_round_history([1, 0, 0])
        selected = worker.select_claim(accepted, self.wallets[0], self.ids[0], 'received-or-change', 210_000_000)
        self.assertEqual((selected['kind'], selected['receipt'].value_sompi), ('received', 500_000_000))
        selected = worker.select_claim(accepted, self.wallets[2], self.ids[2], 'received-or-change', 210_000_000)
        self.assertEqual((selected['kind'], selected['receipt'].value_sompi), ('change', 1_490_000_000))
        selected = worker.select_claim(accepted, self.wallets[0], self.ids[0], 'received-or-change', 600_000_000)
        self.assertEqual(selected['kind'], 'change')
        for row in history.claims(accepted, self.wallets[0], self.ids[0]):
            if not row['spent'] and row['kind'] == 'received':
                accepted.state.insert(row['nf'])
        selected = worker.select_claim(accepted, self.wallets[0], self.ids[0], 'received-or-change', 210_000_000)
        self.assertEqual(selected['kind'], 'change')

    def test_all_eight_nonself_recipient_patterns_allow_received_and_change_spending(self):
        import itertools
        patterns = list(itertools.product((1, 2), (0, 2), (0, 1)))
        self.assertEqual(len(patterns), 8)
        for destinations in patterns:
            with self.subTest(public_unsafe_destinations=destinations):
                accepted = self.private_round_history(destinations)
                kinds = ['received-or-change', 'change', 'received-or-change']
                selected = [worker.select_claim(accepted, self.wallets[i], self.ids[i], kinds[i], 210_000_000)
                            for i in range(3)]
                self.assertEqual(selected[1]['kind'], 'change')
                self.assertTrue(any(row['kind'] == 'received' for row in selected))
                self.assertTrue(all(not row['spent'] for row in selected))
                self.assertTrue(all(row['receipt'].value_sompi >= 210_000_000 for row in selected))


if __name__ == '__main__':
    unittest.main()
