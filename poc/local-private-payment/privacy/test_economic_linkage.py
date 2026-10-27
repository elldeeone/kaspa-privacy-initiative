"""Prospectively frozen public fixtures; never actual payment plans or truth."""
from copy import deepcopy
import hashlib
import json
import math
import random
import unittest

from economic_linkage import ForestDP, analyze, parse, validate_ledger
from economic_oracle import brute_force


def public_word(label):
    return hashlib.sha256(('PUBLIC ECONOMIC TOY/' + label).encode()).hexdigest()


def symmetric_public_fixture():
    value = {'schema': 'kpxa-public-economic-ledger/v1', 'terminal': True,
        'terminal_reserve_sompi': 0, 'genesis': [], 'payments': [], 'exits': []}
    for index in range(3):
        value['genesis'].append({'cm_hex32': public_word('genesis-%d' % index),
            'position': index, 'value_sompi': 2_000_000_000})
    for index in range(6):
        value['payments'].append({'action_id_hex32': public_word('payment-action-%d' % index),
            'event_index': index, 'nf_hex32': public_word('payment-NF-%d' % index), 'fee_sompi': 1000,
            'outputs': [{'cm_hex32': public_word('payment-%d-slot-%d' % (index, slot)),
                         'position': 3 + 2 * index + slot} for slot in range(2)]})
    for index in range(9):
        value['exits'].append({'action_id_hex32': public_word('exit-action-%d' % index),
            'event_index': 6 + index, 'nf_hex32': public_word('exit-NF-%d' % index),
            'payout_sompi': 666_665_000, 'fee_sompi': 1000})
    return value


class EconomicControls(unittest.TestCase):
    def compare_oracle(self, roots, fees, gross, pt, et, floor=1):
        result = ForestDP(roots, fees, gross, pt, et, note_floor=floor).solve()
        oracle = brute_force(roots, fees, gross, pt, et, note_floor=floor)
        self.assertEqual(result['forest_count'], oracle['forest_count'])
        self.assertEqual(result['labeled_root_and_output_position_forest_count'], oracle['labeled_assignment_count'])
        self.assertEqual(result['possible'], oracle['possible'])
        self.assertEqual(result['must'], oracle['must'])
        return result

    def test_symmetric_nine_exit_exact_analytic_counts(self):
        roots, fees, gross = [2_000_000_000] * 3, [1000] * 6, [666_666_000] * 9
        result = ForestDP(roots, fees, gross, list(range(6)), list(range(6, 15))).solve()
        self.assertEqual(result['exit_partition_count'], math.factorial(9) // (math.factorial(3) ** 3 * math.factorial(3)))
        self.assertEqual(result['joint_root_cover_count'], 25_200)
        self.assertEqual(result['forest_count'], 680_400)
        self.assertEqual(result['labeled_output_slot_forest_count'], 43_545_600)
        self.assertEqual(result['labeled_root_and_output_position_forest_count'], 261_273_600)
        self.assertEqual(len(result['possible']['co_root_exit']), 36)
        self.assertEqual(result['must']['co_root_exit'], set())
        self.assertLessEqual(result['work']['evaluated_states'], 6435)

    def test_unique_economic_partition_is_not_root_owner_identity(self):
        result = self.compare_oracle([100, 100], [1, 2], [30, 69, 40, 58], [0, 1], [2, 3, 4, 5])
        self.assertEqual((result['forest_count'], result['exit_partition_count']), (1, 1))
        self.assertEqual(result['labeled_root_and_output_position_forest_count'], 8)
        self.assertEqual(result['must']['co_root_exit'], {(0, 1), (2, 3)})

    def test_independent_forward_assignment_oracle_on_public_random_toys(self):
        rng = random.Random(660026)
        for trial in range(20):
            roots = [100, 100]; count = trial % 4
            fees = [rng.randrange(1, 4) for _ in range(count)]
            live = list(roots)
            for fee in fees:
                eligible = [i for i, value in enumerate(live) if value >= 2 + fee]
                position = rng.choice(eligible); incoming = live.pop(position)
                left = rng.randrange(1, incoming - fee)
                live += [left, incoming - fee - left]
            rng.shuffle(live)
            with self.subTest(trial=trial):
                self.compare_oracle(roots, fees, live, list(range(count)), list(range(count, count + len(live))))

    def test_chronology_is_total_and_changes_ancestry_without_tie_breaking(self):
        gross = [30, 20, 47]
        broad = self.compare_oracle([100], [1, 2], gross, [0, 1], [2, 3, 4])
        restricted = self.compare_oracle([100], [1, 2], gross, [0, 2], [1, 3, 4])
        impossible = self.compare_oracle([100], [1, 2], gross, [1, 2], [0, 3, 4])
        self.assertEqual((broad['forest_count'], restricted['forest_count'], impossible['forest_count']), (3, 1, 0))
        self.assertIn((0, 1), restricted['must']['parent'])
        for pt, et in [([0, 0], [2, 3, 4]), ([True, 1], [2, 3, 4])]:
            with self.assertRaises(ValueError): ForestDP([100], [1, 2], gross, pt, et, note_floor=1)

    def test_masked_payout_control_contains_exact_models(self):
        roots, fees, gross, pt, et = [100, 100], [1, 2], [30, 69, 40, 58], [0, 1], [2, 3, 4, 5]
        exact = ForestDP(roots, fees, gross, pt, et, note_floor=1).solve()
        masked = ForestDP(roots, fees, gross, pt, et, note_floor=1, masked=True).solve()
        self.assertLessEqual(exact['forest_count'], masked['forest_count'])
        for kind in exact['possible']:
            self.assertLessEqual(exact['possible'][kind], masked['possible'][kind])
            self.assertLessEqual(masked['must'][kind], exact['must'][kind])
        broad = ForestDP([2_000_000_000] * 3, [1000] * 6, [666_666_000] * 9,
            list(range(6)), list(range(6, 15)), masked=True).solve()
        forward_named_histories = math.prod(range(3, 9)) * math.factorial(9)
        self.assertEqual(broad['forest_count'], forward_named_histories // (2 ** 6 * math.factorial(3)))

    def test_actual_profile_public_schema_and_private_field_rejection(self):
        value = symmetric_public_fixture(); validate_ledger(value)
        parse(json.dumps(value))
        for mutation in ('owner', 'intent', 'float', 'bool', 'one-sompi', 'not-terminal', 'extra-exit',
                         'duplicate-time', 'position', 'string-amount', 'duplicate-NF'):
            bad = deepcopy(value)
            if mutation == 'owner': bad['exits'][0]['owner'] = 0
            elif mutation == 'intent': bad['payments'][0]['payment_sompi'] = 1
            elif mutation == 'float': bad['exits'][0]['payout_sompi'] = float(bad['exits'][0]['payout_sompi'])
            elif mutation == 'bool': bad['payments'][0]['fee_sompi'] = True
            elif mutation == 'one-sompi': bad['exits'][0]['payout_sompi'] += 1
            elif mutation == 'not-terminal': bad['terminal'] = False
            elif mutation == 'extra-exit': bad['exits'].append(deepcopy(bad['exits'][0]))
            elif mutation == 'duplicate-time': bad['exits'][0]['event_index'] = 0
            elif mutation == 'position': bad['payments'][0]['outputs'][0]['position'] = 1
            elif mutation == 'string-amount': bad['exits'][0]['fee_sompi'] = '1000'
            else: bad['exits'][0]['nf_hex32'] = bad['payments'][0]['nf_hex32']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): validate_ledger(bad)
        with self.assertRaises(ValueError): parse('{"schema":1,"schema":2}')

    def test_position_identity_and_CM_label_symmetry(self):
        value = symmetric_public_fixture()
        baseline = ForestDP([2_000_000_000] * 3, [1000] * 6, [666_666_000] * 9,
                            list(range(6)), list(range(6, 15))).solve()
        renamed = deepcopy(value)
        renamed['genesis'][0]['cm_hex32'], renamed['genesis'][2]['cm_hex32'] = \
            renamed['genesis'][2]['cm_hex32'], renamed['genesis'][0]['cm_hex32']
        for row in renamed['payments']:
            row['outputs'][0]['cm_hex32'], row['outputs'][1]['cm_hex32'] = \
                row['outputs'][1]['cm_hex32'], row['outputs'][0]['cm_hex32']
        # A historical identical CM remains a separate funded note position.
        renamed['payments'][0]['outputs'][0]['cm_hex32'] = renamed['genesis'][0]['cm_hex32']
        validate_ledger(renamed)
        report = analyze(renamed)
        self.assertEqual(report['exact']['forest_count'], baseline['forest_count'])
        self.assertEqual(report['root_cm_label_permutations_preserved'], 6)
        self.assertFalse(report['root_identity_inferred_from_economics'])
        self.assertFalse(report['common_ownership_inferred_from_asset_ancestry'])
        self.assertFalse(report['posterior_probability_or_uniform_prior_claim'])
        self.assertFalse(report['public_payment_two_output_grouping_scored_as_new_inference'])


if __name__ == '__main__':
    unittest.main()
