"""State/replay and controller-boundary tests; no proof-validity claims.

Rows use explicit model proof bytes and a finite test verifier. Actual Output,
aggregate, R0 and NativeFull qualifications remain separate executed evidence.
"""
from dataclasses import replace
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import exit_wire
import private_lifecycle
import wallet_history as history
import wallet_profile as wallet

IDENTITY = tuple(hashlib.sha256(label).digest() for label in (b'chain', b'pool', b'profile', b'domain', b'service'))
PROFILE = wallet.Profile(IDENTITY[3], IDENTITY[2])
TAIL = b'PUBLIC UNFUNDED STATE-REPLAY CONTROL TAIL'
CV = bytes([71]) * 64
POINT = hashlib.sha256(b'public genesis point').digest() + (3).to_bytes(4, 'little')
NEXT = hashlib.sha256(b'public payment point').digest() + (7).to_bytes(4, 'little')


def row(index):
    cm = hashlib.sha256(b'model CM' + bytes([index])).digest()
    ciphertext = bytes([index + 1]) * 264
    return cm + CV + ciphertext + hashlib.sha256(ciphertext).digest() + bytes([index + 11]) * 128


ROWS = tuple(row(i) for i in range(9))


def vector():
    state = history.trees.PublicState([item[:32] for item in ROWS[:3]])
    old = history.context(IDENTITY, POINT, state, 6_000_000_000)
    following = state.copy()
    nfs = [(index + 1).to_bytes(32, 'little') for index in range(3)]
    witnesses = [following.insert(nf) for nf in nfs]
    paths = [following.append(item[:32]) for item in ROWS[3:]]
    new_reserve, fee = 5_979_000_000, 21_000_000
    body = (b'KPBAEF01' + old.encode() + following.cm.root() + following.nf.root()
        + (9).to_bytes(4, 'little') + (4).to_bytes(4, 'little') + new_reserve.to_bytes(8, 'little')
        + fee.to_bytes(8, 'little') + bytes(32)
        + b''.join(nf + CV for nf in nfs) + b''.join(ROWS[3:]) + b''.join(witnesses) + b''.join(paths)
        + bytes([99]) * 128)
    prefix = (b'KPBAFX01' + b'\x01\0\x01\0' + POINT + b'\xff' * 8
        + (6_000_000_000).to_bytes(8, 'little') + b'\x25\0' + exit_wire.state_spk(old.state(), TAIL)
        + b'\x01\0' + new_reserve.to_bytes(8, 'little') + b'\x25\0'
        + exit_wire.state_spk(history.state_bytes(following, PROFILE.domain), TAIL)
        + b'\0' + bytes(36) + (10492).to_bytes(4, 'little'))
    value = {'schema': 'kpb-private-batch-public-history/v1', 'scope': history.SCOPE,
        **dict(zip(('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'),
                   (part.hex() for part in IDENTITY))),
        'genesis': {'outpoint_hex36': POINT.hex(), 'state_hex112': old.state().hex(),
                    'reserve_sompi': 6_000_000_000, 'outputs_hex520': [item.hex() for item in ROWS[:3]]},
        'transitions': [{'kind': 'payment', 'projection_hex': (prefix + body).hex(),
                         'successor_outpoint_hex36': NEXT.hex()}],
        'head': {'outpoint_hex36': NEXT.hex(), 'state_hex112': history.state_bytes(following, PROFILE.domain).hex(),
                 'reserve_sompi': new_reserve}}
    return value


def load(value):
    return history.load_supplied(value, PROFILE, IDENTITY, TAIL, lambda item: item in ROWS, CV)


class PublicHistoryControls(unittest.TestCase):
    def test_complete_ordered_state_replay(self):
        actual = load(vector())
        self.assertEqual(len(actual.rows), 9)
        self.assertEqual(actual.head.cm_count, 9)
        self.assertEqual(actual.head.nf_count, 4)
        self.assertEqual(actual.reserve, 5_979_000_000)

    def test_no_caller_accepted_flag_or_scope_upgrade(self):
        for mutation in ('flag', 'scope'):
            value = vector()
            if mutation == 'flag':
                value['accepted'] = True
            else:
                value['scope'] = 'AUTHENTICATED_ACCEPTED_HISTORY'
            with self.subTest(mutation=mutation), self.assertRaises(wallet.Invalid):
                load(value)

    def test_wrong_identity_and_noncanonical_hex(self):
        for name in ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'):
            value = vector(); value[name] = bytes([17]).hex() * 32
            with self.subTest(field=name), self.assertRaises(wallet.Invalid):
                load(value)
        value = vector(); value['pool_hex32'] = value['pool_hex32'].upper()
        with self.assertRaises(wallet.Invalid):
            load(value)

    def test_initial_liability_amount_and_integer_semantics(self):
        for amount in (True, 6_000_000_001, 5_999_999_999):
            value = vector(); value['genesis']['reserve_sompi'] = amount
            with self.subTest(amount=amount), self.assertRaises(wallet.Invalid):
                load(value)
        value = vector(); value['genesis']['outputs_hex520'][1] = value['genesis']['outputs_hex520'][0]
        with self.assertRaises(wallet.Invalid):
            load(value)
        with self.assertRaises(wallet.Invalid):
            history.load_supplied(vector(), PROFILE, IDENTITY, TAIL, lambda item: True, bytes(64))

    def test_missing_or_reordered_history_fails_current_head(self):
        for mutation in ('missing', 'genesis-order', 'replay', 'wrong-final-point'):
            value = vector()
            if mutation == 'missing': value['transitions'] = []
            if mutation == 'genesis-order': value['genesis']['outputs_hex520'].reverse()
            if mutation == 'replay': value['transitions'].append(copy.deepcopy(value['transitions'][0]))
            if mutation == 'wrong-final-point': value['head']['outpoint_hex36'] = POINT.hex()
            with self.subTest(mutation=mutation), self.assertRaises((wallet.Invalid, ValueError)):
                load(value)

    def test_mutated_actual_transition_bytes_refuse(self):
        # Core current point/root/count; fee; NF/CV; output; NF path; CM path;
        # plus actual input/successor-policy scripts in the canonical prefix.
        for offset in (12, 66, 115, 193 + 168, 193 + 204, 193 + 268,
                       193 + 356, 193 + 364, 193 + 404, 193 + 692,
                       193 + 3812, 193 + 7292):
            value = vector()
            raw = bytearray.fromhex(value['transitions'][0]['projection_hex']); raw[offset] ^= 1
            value['transitions'][0]['projection_hex'] = raw.hex()
            with self.subTest(offset=offset), self.assertRaises((wallet.Invalid, ValueError)):
                load(value)

    def test_full_output_proof_callback_mandatory(self):
        with self.assertRaises(wallet.Invalid):
            history.load_supplied(vector(), PROFILE, IDENTITY, TAIL, lambda item: False, CV)

    def test_benchmark_second_round_selection_uses_original_recovered_index(self):
        received = SimpleNamespace(receipt=SimpleNamespace(index=1), spent=False)
        change = SimpleNamespace(receipt=SimpleNamespace(index=2), spent=False)
        self.assertIs(history.select_for_round([change, received], 2, 0), received)
        self.assertIs(history.select_for_round([received, change], 2, 1), change)
        self.assertIs(history.select_for_round([change, received], 2, 2), received)
        with self.assertRaises(wallet.Invalid): history.select_for_round([received, received], 2, 0)
        with self.assertRaises(wallet.Invalid): history.select_for_round([SimpleNamespace(receipt=received.receipt, spent=True)], 2, 0)
        with self.assertRaises(wallet.Invalid): history.select_for_round([received], True, 0)


class ControllerBoundaryControls(unittest.TestCase):
    def test_payment_construction_dependency_not_required_for_Exit_or_scan(self):
        def public_fixture_read(path, expected=None):
            if Path(path).name == 'SOURCE-FREEZE-02.json':
                return private_lifecycle.encoded({'files': [
                    {'path': name, 'sha256': 'public-fixture-pin'} for name in
                    ('harness/worker.mjs', 'source-bridge/signature-component-adapter-selected.mjs')]})
            return b'public fixture only'
        for operation in ('invoice', 'scan', 'exit'):
            rows = private_lifecycle.selected_runtime(public_fixture_read, operation)
            aliases = {alias for alias, _, _ in rows}
            with self.subTest(operation=operation):
                self.assertNotIn('/runtime/owner-aux', aliases)
                if operation != 'exit': self.assertNotIn('/generator/private_authorization', aliases)

    def test_private_leaf_admission_never_opens_body_and_refuses_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'PUBLIC_TEST_ONLY.bin'
            path.write_bytes(bytes(208)); path.chmod(0o600)
            with patch.object(Path, 'open', side_effect=AssertionError('body-open-forbidden')):
                self.assertEqual(private_lifecycle.private_leaf(path, 208), path)
            alias = path.with_name('LINK.bin'); alias.symlink_to(path)
            with self.assertRaises(ValueError): private_lifecycle.private_leaf(alias, 208)
            alias.unlink(); alias.hardlink_to(path)
            with self.assertRaises(ValueError): private_lifecycle.private_leaf(path, 208)

    def test_extra_private_field_cannot_leave_typed_public_receipt(self):
        value = {'schema': 'kpb-original-lifecycle-operation/v1', 'operation': 'invoice',
            'scope': history.SCOPE, 'private_original_or_witness_exported': False,
            'accepted_backing_or_native_settlement': False, 'authenticated_private_invoice_ready': True,
            'invoice_exported_publicly': False}
        self.assertEqual(private_lifecycle.public_receipt(value, 'invoice'), value)
        with self.assertRaises(ValueError): private_lifecycle.public_receipt({**value, 'private_note': 'fixture'}, 'invoice')
        with self.assertRaises(ValueError): private_lifecycle.public_receipt({**value, 'accepted_backing_or_native_settlement': True}, 'invoice')


if __name__ == '__main__':
    unittest.main()
