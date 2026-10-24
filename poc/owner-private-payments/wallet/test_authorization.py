"""Owner preflight controls with PUBLIC UNSAFE notes and explicit proof mocks.

Uses real public wire/root checks. No G16, curve, encryption, native or accepted
state claim; no real fixture directories or original private files are read.
"""
import sys
import unittest
from unittest.mock import patch

import paths
import support
import worker
import test_boundary as boundary

sys.path.insert(0, str(paths.ROOT / 'poc/owner-private-payments/integration'))
import public as assembly


class PublicDelivery(boundary.PublicCrypto):
    def unseal(self, secret, cf):
        return cf[:216]  # PUBLIC PLAINTEXT MOCK, not encryption.


class MockRelation:
    def __init__(self):
        self.proved = []

    def commit(self, value, blind):
        return bytes.fromhex(paths.digest(b'PUBLIC-INVALID-CV' + value.to_bytes(8, 'little') + blind)) * 2

    def output(self, row):
        paths.need(row[392:] == bytes([7]) * 128, 'mock-output-proof-refused')

    def balance(self, inputs, outputs, fee, delta):
        pass  # Curve and genuine balance qualification belongs to relation tests.

    def prove(self, role, statement, witness):
        self.proved.append((role, statement, witness))
        return bytes([8]) * 128  # PUBLIC INVALID G16 BYTES.


class Authorization(boundary.Boundary):
    # Inherit only temporary sentinel fixture setup/cleanup, not its test list.
    __unittest_skip__ = False

    def setUp(self):
        super().setUp()
        self.v2 = support.recipient(); self.crypto = PublicDelivery(); self.relation = MockRelation()
        self.codec = boundary.load_public('poc/owner-private-payments/construction/codec.py', '_kpx7_public_auth_codec')
        self.wallets = [self.v2.Receiver(bytes([i + 1]) * 32, support.DOMAIN, self.crypto) for i in range(3)]
        self.input_receipts = [self.v2.Receipt.for_invoice(w.invoice(0), 2_000_000_000,
            bytes([i + 21]) * 32) for i, w in enumerate(self.wallets)]
        self.initial = assembly.genesis([r.commitment() for r in self.input_receipts], 6_000_000_000)
        self.ids = [bytes([i + 40]).hex() * 32 for i in range(3)]
        self.profile_sha = paths.digest(b'PUBLIC MOCK PROFILE')
        self.context = assembly.premix_context(self.initial,
            [{'admission_sompi': r.value_sompi} for r in self.input_receipts], self.profile_sha,
            (bytes([42]) * 32 + bytes(4)).hex(), 30_000_000, b'\x75PUBLIC UNSAFE TAIL'.hex())
        self.context_raw = paths.encoded(self.context) + b'\n'
        self.session = {'schema': 'kpx7-private-construction-session/v1',
            'session_id': paths.digest(b'PUBLIC MOCK SESSION'), 'domain_hex': support.DOMAIN.hex(),
            'prior_state_digest': paths.digest(bytes.fromhex(self.initial['state_hex112'])),
            'circuit_profile_sha256': self.profile_sha,
            'public_effects_context_sha256': paths.digest(self.context_raw), 'roster': self.ids,
            'program_source_sha256': worker.PROGRAM_SHA, 'tuple_bytes': 520,
            'outputs_per_party': 2, 'mpc_prime': str(support.Q)}
        self.session_raw = self.codec.canonical_json(self.session)
        self.session_sha = paths.digest(self.session_raw)
        self.rows, self.own_outputs = [], []
        for owner in range(3):
            for index in range(2):
                recipient = (owner + 1) % 3 if index == 0 else owner
                invoice = self.wallets[recipient].invoice(1 + owner if index == 0 else 4)
                receipt = self.v2.Receipt.for_invoice(invoice, 995_000_000,
                    bytes([70 + owner * 2 + index]) * 32)
                blind = (owner * 2 + index + 1).to_bytes(32, 'little')
                cv = self.relation.commit(receipt.value_sompi, blind)
                cf = receipt.encode() + bytes([90 + owner * 2 + index]) * 48
                row = receipt.commitment() + cv + cf + bytes.fromhex(paths.digest(cf)) + bytes([7]) * 128
                self.rows.append(row)
                if owner == 0:
                    self.own_outputs.append({'tuple_hex520': row.hex(), 'receipt_hex216': receipt.encode().hex(),
                        'blind_hex32': blind.hex(), 'recipient_id_hex32': self.ids[recipient]})
        self.rin = bytes([3]) + bytes(31)
        self.inputs = [(self.wallets[i].nullifier(r, i), self.relation.commit(r.value_sompi,
            self.rin if i == 0 else bytes([i + 3]) + bytes(31))) for i, r in enumerate(self.input_receipts)]
        paths.write_new(self.a.owner / 'OWNER.json', paths.encoded({
            'schema': 'kpx7-unfunded-owner-state/v1', 'domain_hex32': support.DOMAIN.hex(),
            'participant_id_hex32': self.ids[0], 'seed_hex32': bytes([1]).hex() * 32,
            'initial_position': 0, 'input_receipt_hex216': self.input_receipts[0].encode().hex()}))
        self.attempt = self.a.owner / 'attempts' / '000001'; self.attempt.mkdir(parents=True, mode=0o700)
        worker.private_save(self.attempt / 'SESSION.json', {'session': self.session, 'session_sha256': self.session_sha})
        paths.write_new(self.attempt / 'CONTEXT.json', self.context_raw)
        inp = self.a.mpc / 'Input-P0-0'; paths.write_new(inp, self.codec.owner_input(self.rows[:2], 0), 0o400)
        info = inp.stat()
        worker.private_save(self.attempt / 'STATE.json', {'schema': 'kpx7-private-owner-attempt/v1',
            'session_sha256': self.session_sha, 'party': 0, 'rin_hex32': self.rin.hex(),
            'nf_hex32': self.inputs[0][0].hex(), 'cv_hex64': self.inputs[0][1].hex(), 'outputs': self.own_outputs,
            'input_device_hex8': info.st_dev.to_bytes(8, 'little').hex(),
            'input_inode_hex8': info.st_ino.to_bytes(8, 'little').hex()})
        self.result = self.a.mpc / 'mpc-private-public-unsafe' / 'OWN-MPC-PROJECTION.json'
        self.result.parent.mkdir(mode=0o700)
        self.save_mpc(self.rows)
        self.a.own_mpc_result = self.result.relative_to(self.a.mpc)
        self.a.session = self.root / 'SESSION.json'; paths.write_new(self.a.session, self.session_raw)
        self.a.session_sha256 = self.session_sha
        self.a.output = self.root / 'PUBLIC-INVALID-PROOF-EXPORT'; self.a.output.mkdir(mode=0o700)
        self.a.projection = self.root / 'PROJECTION.bin'
        self.project()

    def save_mpc(self, rows):
        raw = paths.encoded({'schema': 'kpx7-mixed-complete-outputs/v1', 'session_sha256': self.session_sha,
            'rows_hex': [r.hex() for r in rows], 'delta_decimal': '0', 'tuple_bytes': 520, 'row_count': 6,
            'scope': 'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION'})
        if self.result.exists():
            self.result.unlink()
        paths.write_new(self.result, raw)

    def project(self, rows=None, fee=None, inputs=None, session=None):
        body = assembly.body_core(self.initial, self.inputs if inputs is None else inputs,
            self.rows if rows is None else rows, bytes(32), self.session_sha if session is None else session,
            self.ids, bytes.fromhex(self.context['previous_outpoint_hex36']),
            self.context['fee_sompi'] if fee is None else fee)
        parsed = assembly.wire.parse_body(body); tail = bytes.fromhex(self.context['native_tail_hex'])
        raw = assembly.project(body, assembly.wire.state_spk(parsed.old_state.raw, tail),
            assembly.wire.state_spk(parsed.new_state.raw, tail))
        if self.a.projection.exists():
            self.a.projection.unlink()
        paths.write_new(self.a.projection, raw, 0o400); self.a.projection_sha256 = paths.digest(raw)

    def authorize(self):
        with patch.object(worker, 'load_assets', return_value=(
                {'component_profile_sha256': self.profile_sha}, self.relation, self.crypto, self.codec, assembly.wire)):
            worker.authorize(self.a)

    def reject(self, expected):
        with self.assertRaisesRegex(ValueError, expected):
            self.authorize()
        self.assertFalse(self.relation.proved)
        self.assertFalse((self.attempt / 'DISCLOSURE-CLOSED').exists())

    def test_preflight_accepts_same_effects_and_exports_minimal_witness(self):
        self.authorize()
        role, statement, witness = self.relation.proved[0]
        self.assertEqual((role, len(statement)), ('spend', 200))
        self.assertEqual(set(witness), {'schema', 'note_hex168', 's_hex32', 'k_hex32', 'position',
                                       'cm_path_hex', 'blind_hex32'})
        exported = paths.parse((self.a.output / 'PUBLIC.json').read_bytes())
        self.assertEqual(set(exported), {'schema', 'session_sha256', 'effects_digest_hex32',
            'nf_hex32', 'cv_hex64', 'statement_hex200', 'proof_hex128'})
        self.assertTrue((self.attempt / 'DISCLOSURE-CLOSED').exists())
        self.assertNotIn('seed_hex32', witness)

    def test_changed_fee_rejected_even_with_coherent_native_reserve(self):
        self.project(fee=20_000_000)
        self.reject('exact-approved-native-effects')

    def test_changed_session_rejected_before_authorization(self):
        self.project(session=paths.digest(b'PUBLIC WRONG SESSION'))
        self.reject('exact-approved-native-effects')

    def test_coordinator_pool_cannot_replace_own_engine_receipt(self):
        rows = self.rows[1:] + self.rows[:1]
        self.project(rows=rows)
        self.reject('same-own-engine-pool')

    def test_own_payment_omission_rejected_after_both_pools_agree(self):
        cf = bytes([201]) * 264
        replacement = bytes([200]) * 32 + bytes([202]) * 64 + cf + bytes.fromhex(paths.digest(cf)) + bytes([7]) * 128
        rows = [replacement] + self.rows[1:]
        self.save_mpc(rows); self.project(rows=rows)
        self.reject('own-complete-output-inclusion')

    def test_changed_output_proof_rejected_before_spend_proof(self):
        rows = self.rows[:]; rows[4] = rows[4][:-1] + b'\x06'
        self.save_mpc(rows); self.project(rows=rows)
        self.reject('mock-output-proof-refused')

    def test_changed_own_nf_rejected_with_otherwise_valid_public_roots(self):
        inputs = self.inputs[:]; inputs[0] = (bytes([123]) * 32, inputs[0][1])
        self.project(inputs=inputs)
        self.reject('own-stable-original-NF')


# Boundary fixtures are reused; do not recount its ten groups here.
for inherited in tuple(name for name in dir(boundary.Boundary) if name.startswith('test_')):
    setattr(Authorization, inherited, None)

if __name__ == '__main__':
    unittest.main(verbosity=2)
