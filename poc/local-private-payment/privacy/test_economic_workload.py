"""Synthetic controls for the separate conditional public-workload arm."""
from copy import deepcopy
import random
import unittest

from economic_linkage import ForestDP, validate_ledger
from economic_oracle import brute_force
from economic_workload import WorkloadDP, analyze
from test_economic_linkage import symmetric_public_fixture


def advertised_public_fixture():
    value = symmetric_public_fixture()
    for index, row in enumerate(value['exits']):
        gross = (200_000_000, 500_000_000, 1_299_998_000)[index % 3]
        row['payout_sompi'] = gross - row['fee_sompi']
    validate_ledger(value)
    return value


class PublicWorkloadControls(unittest.TestCase):
    def compare_oracle(self, roots, fees, gross, pt, et, high_count):
        result = WorkloadDP(roots, fees, gross, pt, et, note_floor=1,
                            advertised_values=(2, 5), high_count=high_count).solve()
        oracle = brute_force(roots, fees, gross, pt, et, note_floor=1,
                             advertised_values=(2, 5), high_count=high_count)
        self.assertEqual(result['forest_count'], oracle['forest_count'])
        self.assertEqual(result['labeled_root_and_output_position_forest_count'], oracle['labeled_assignment_count'])
        self.assertEqual(result['possible'], oracle['possible'])
        self.assertEqual(result['must'], oracle['must'])
        return result

    def test_ambiguous_roles_do_not_multiply_forests(self):
        result = self.compare_oracle([8, 8], [1, 1], [2, 5, 2, 5], [0, 1], [2, 3, 4, 5], 1)
        self.assertEqual(result['forest_count'], 4)
        self.assertEqual(result['labeled_root_and_output_position_forest_count'], 32)
        # Each of these forests admits two global role assignments. It is
        # still one asset forest, never two observations or twice the evidence.
        self.assertNotEqual(result['forest_count'], 8)

    def test_nested_global_count_signatures_and_rejection(self):
        results = [self.compare_oracle([11], [1, 1], [2, 2, 5], [0, 1], [2, 3, 4], count)
                   for count in (0, 1, 2)]
        self.assertEqual([result['forest_count'] for result in results], [2, 3, 0])
        forced_low = self.compare_oracle([10], [1], [2, 7], [0], [1, 2], 1)
        self.assertEqual(forced_low['forest_count'], 0)

    def test_interleaved_exit_chronology_is_retained_in_stronger_arm(self):
        feasible = self.compare_oracle([11], [1, 1], [2, 2, 5], [0, 2], [1, 3, 4], 1)
        impossible = self.compare_oracle([11], [1, 1], [2, 2, 5], [1, 2], [0, 3, 4], 1)
        self.assertEqual((feasible['forest_count'], impossible['forest_count']), (1, 0))
        self.assertIn((0, 2), feasible['must']['parent'])

    def test_independent_explicit_role_oracle_on_public_random_toys(self):
        rng = random.Random(660027)
        for trial in range(12):
            count = trial % 4
            live, fees = [20, 20], [1] * count
            for fee in fees:
                selected = rng.choice([i for i, value in enumerate(live) if value >= 7])
                incoming = live.pop(selected)
                advertised = rng.choice((2, 5))
                live.extend((advertised, incoming - fee - advertised))
            rng.shuffle(live)
            for high_count in range(count + 1):
                with self.subTest(trial=trial, high_count=high_count):
                    self.compare_oracle([20, 20], fees, live, list(range(count)),
                                        list(range(count, count + len(live))), high_count)

    def test_actual_profile_analytic_counts_and_chain_containment(self):
        value = advertised_public_fixture()
        report = analyze(value)
        base, stronger = report['chain_only_exact'], report['workload_known_exact']
        self.assertEqual(base['forest_count'], 87_480)
        self.assertEqual(stronger['forest_count'], 25_920)
        self.assertEqual(stronger['joint_root_cover_count'], 3_240)
        self.assertEqual(stronger['exit_partition_count'], 36)
        for kind in stronger['possible']:
            self.assertLessEqual(set(map(tuple, stronger['possible'][kind])), set(map(tuple, base['possible'][kind])))
            self.assertLessEqual(set(map(tuple, base['must'][kind])), set(map(tuple, stronger['must'][kind])))

    def test_CM_slots_root_labels_and_asset_ownership_boundary(self):
        value = advertised_public_fixture(); renamed = deepcopy(value)
        for row in renamed['payments']:
            row['outputs'][0]['cm_hex32'], row['outputs'][1]['cm_hex32'] = \
                row['outputs'][1]['cm_hex32'], row['outputs'][0]['cm_hex32']
        renamed['genesis'][0]['cm_hex32'], renamed['genesis'][2]['cm_hex32'] = \
            renamed['genesis'][2]['cm_hex32'], renamed['genesis'][0]['cm_hex32']
        report = analyze(renamed)
        self.assertEqual(report['workload_known_exact']['forest_count'], 25_920)
        self.assertFalse(report['public_CM_slot_role_assumed'])
        self.assertFalse(report['owner_or_action_amount_mapping_used'])
        self.assertFalse(report['role_assignments_multiply_forest_count'])
        self.assertTrue(report['public_source_publication_is_conditional'])
        self.assertFalse(report['root_owner_identity_inferred'])
        self.assertFalse(report['common_ownership_inferred_from_asset_ancestry'])
        self.assertFalse(report['posterior_or_privacy_pass'])

    def test_zero_stronger_models_are_not_unique_linkage_or_privacy_pass(self):
        report = analyze(symmetric_public_fixture())
        self.assertEqual(report['workload_known_exact']['forest_count'], 0)
        self.assertEqual(report['status'], 'INCONSISTENT_PUBLIC_WORKLOAD_MODEL_OR_INPUT')
        self.assertTrue(all(not rows for rows in report['new_must_relations_beyond_chain_only'].values()))
        self.assertFalse(report['posterior_or_privacy_pass'])


if __name__ == '__main__':
    unittest.main()
