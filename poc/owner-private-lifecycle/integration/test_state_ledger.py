"""Boundary/lineage controls; synthetic fixtures carry no proof authority."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest

from ledger import complete
from trees import CM_EMPTY, PublicState, SparseTree, ZERO, sha

DOMAIN = bytes.fromhex('be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480')
MAGIC = b'KPX8ST01'
OLD_WIRE = Path(__file__).resolve().parents[2] / 'owner-private-payments/verification/wire.py'
spec = importlib.util.spec_from_file_location('retained_kpx7_path_consumer', OLD_WIRE)
wire = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wire
spec.loader.exec_module(wire)


def cms(count, prefix=b'public test CM'):
    return [sha(prefix, i.to_bytes(4, 'little')) for i in range(count)]


def case(identifier, sources, outputs):
    return {'transaction': {'id': '%064x' % identifier,
            'inputs': [{'previousOutpoint': {'transactionId': tx, 'index': index}}
                       for tx, index, _, _ in sources],
            'outputs': [{'value': value, 'scriptPublicKey': script} for value, script in outputs]},
            'entries': [{'amount': value, 'scriptPublicKey': script} for _, _, value, script in sources]}


RESERVE = '0000aa20' + '12' * 32 + '87'
PAYOUT = '000020' + '34' * 32 + 'ac'


def lifecycle():
    sources = [('%064x' % (100 + i), 0, 1000, PAYOUT) for i in range(3)]
    result = [('funding', case(1, sources, [(2700, RESERVE), (200, PAYOUT)]))]
    value = 2700
    for identifier in (2, 3):
        following = value - 100
        result.append(('batch', case(identifier, [('%064x' % (identifier - 1), 0, value, RESERVE)],
                                      [(following, RESERVE)])))
        value = following
    for ordinal in range(9):
        identifier = 4 + ordinal
        terminal = ordinal == 8
        payout = value - 10 if terminal else 200
        following = value - payout - 10
        outputs = [(payout, PAYOUT)] if terminal else [(following, RESERVE), (payout, PAYOUT)]
        result.append(('exit', case(identifier, [('%064x' % (identifier - 1), 0, value, RESERVE)], outputs)))
        value = following
    return result


class StateTests(unittest.TestCase):
    def test_tree_index_boundaries_and_no_boolean_indices(self):
        tree = SparseTree(16, b'KPX1CMN\0', CM_EMPTY)
        tree.set((1 << 16) - 1, sha(b'last occupied'))
        self.assertEqual(len(tree.path((1 << 16) - 1)), 512)
        for index in (-1, 1 << 16, True):
            with self.assertRaises(ValueError):
                tree.path(index)

    def test_nf_insertions_match_retained_independent_path_consumer(self):
        state = PublicState(cms(3))
        for value in (7, 3, 11, (1 << 256) - 1, 1):
            old, count = state.nf.root(), len(state.entries)
            nf = value.to_bytes(32, 'little')
            witness = state.insert(nf)
            self.assertEqual(len(witness), 1160)
            self.assertEqual(wire.insert_nf(old, count, nf, witness), state.nf.root())
        for value in (ZERO, (7).to_bytes(32, 'little')):
            with self.assertRaises(ValueError):
                state.insert(value)

    def test_multiple_rounds_exits_and_state_counts(self):
        state = PublicState(cms(3))
        for round_number in range(2):
            before = state.state(DOMAIN, MAGIC)
            after = state.copy()
            nullifiers = [(round_number * 3 + i + 1).to_bytes(32, 'little') for i in range(3)]
            outputs = cms(6, b'round' + bytes([round_number]))
            for nf in nullifiers:
                after.insert(nf)
            for cm in outputs:
                after.append(cm)
            state, nf_paths, cm_paths = state.transition('batch', nullifiers, outputs, before,
                                                        after.state(DOMAIN, MAGIC), DOMAIN, MAGIC)
            self.assertEqual((len(nf_paths), len(cm_paths)), (3, 6))
        self.assertEqual((len(state.cms), len(state.entries)), (15, 7))
        for index in range(9):
            before = state.state(DOMAIN, MAGIC)
            following = state.copy()
            nf = (100 + index).to_bytes(32, 'little')
            following.insert(nf)
            state, _, paths = state.transition('exit', [nf], [], before,
                                               following.state(DOMAIN, MAGIC), DOMAIN, MAGIC)
            self.assertEqual(paths, [])
        self.assertEqual((len(state.cms), len(state.entries)), (15, 16))

    def test_wrong_root_duplicate_and_cross_domain_are_atomic_rejections(self):
        state = PublicState(cms(3))
        before = state.state(DOMAIN, MAGIC)
        nfs = [i.to_bytes(32, 'little') for i in (1, 2, 3)]
        for old, new, values in ((ZERO * 3 + bytes(16), before, nfs),
                                 (before, before, nfs), (before, before, [nfs[0]] * 3)):
            with self.assertRaises(ValueError):
                state.transition('batch', values, cms(6, b'new'), old, new, DOMAIN, MAGIC)
            self.assertEqual(state.state(DOMAIN, MAGIC), before)
        with self.assertRaises(ValueError):
            state.transition('batch', nfs, cms(6, b'new'), before, before, sha(b'wrong domain'), MAGIC)


class LedgerTests(unittest.TestCase):
    def test_complete_two_round_nine_exit_integer_ledger(self):
        result = complete(lifecycle(), expected_rounds=2, expected_exits=9,
                          useful_payment_sompi=20_000)
        self.assertEqual(result['transaction_count'], 12)
        self.assertEqual(result['total_fee_sompi'], 390)
        self.assertEqual(result['native_payouts_sompi'], 2410)
        self.assertEqual(result['terminal_reserve_sompi'], 0)
        self.assertTrue(result['complete_2_percent_fee_target_met'])
        self.assertFalse(result['proofs_native_VM_chain_currentness_wallet_ownership_or_privacy_verified'])

    def test_wrong_native_point_input_amount_and_script_fail(self):
        for field in ('point', 'amount', 'script'):
            rows = deepcopy(lifecycle())
            if field == 'point':
                rows[2][1]['transaction']['inputs'][0]['previousOutpoint']['transactionId'] = 'ff' * 32
            elif field == 'amount':
                rows[2][1]['entries'][0]['amount'] += 1
            else:
                rows[2][1]['entries'][0]['scriptPublicKey'] = PAYOUT
            with self.assertRaises(ValueError):
                complete(rows, expected_rounds=2, expected_exits=9)

    def test_incomplete_missing_exit_and_boolean_amount_fail(self):
        for rows in (lifecycle()[:-1], lifecycle()[:2] + lifecycle()[3:]):
            with self.assertRaises(ValueError):
                complete(rows, expected_rounds=2, expected_exits=9)
        rows = lifecycle()
        rows[0][1]['entries'][0]['amount'] = True
        with self.assertRaises(ValueError):
            complete(rows, expected_rounds=2, expected_exits=9)

    def test_unpaid_terminal_and_fake_output_shape_fail(self):
        rows = lifecycle()
        rows[-1][1]['transaction']['outputs'].insert(0, {'value': 1, 'scriptPublicKey': RESERVE})
        with self.assertRaises(ValueError):
            complete(rows, expected_rounds=2, expected_exits=9)
        rows = lifecycle()
        rows[1][1]['transaction']['outputs'].append({'value': 1, 'scriptPublicKey': PAYOUT})
        with self.assertRaises(ValueError):
            complete(rows, expected_rounds=2, expected_exits=9)

    def test_acquisition_fee_included_and_no_double_spent_input(self):
        rows = lifecycle()
        acquisition = case(99, [('%064x' % 1000, 0, 3050, PAYOUT)],
                           [(1000, PAYOUT), (1000, PAYOUT), (1000, PAYOUT)])
        rows[0][1]['transaction']['inputs'] = [{'previousOutpoint': {'transactionId': '%064x' % 99,
                                                                    'index': i}} for i in range(3)]
        result = complete(rows, expected_rounds=2, expected_exits=9, acquisition_cases=[acquisition])
        self.assertEqual((result['total_fee_sompi'], result['acquisition_fees_sompi']), (440, 50))
        rows[0][1]['transaction']['inputs'][1] = deepcopy(rows[0][1]['transaction']['inputs'][0])
        with self.assertRaises(ValueError):
            complete(rows, expected_rounds=2, expected_exits=9, acquisition_cases=[acquisition])


if __name__ == '__main__':
    unittest.main()
