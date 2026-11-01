"""Public fake mask controls; no actual truth or private score leaf used."""
import copy
import hashlib
import unittest

import privacy_owner_comparison as comparison
import privacy_owner_comparison_launch as comparison_launcher
import privacy_source_closure as source_closure


def binding(label):
    return {
        'method_sha256': '01' * 32,
        'selection_sha256': ('02' if label == 'base' else '03') * 32,
        'trial_id': ('11111111-1111-4111-8111-111111111111'
                     if label == 'base' else
                     '22222222-2222-4222-8222-222222222222'),
        'phase': 'private-batch-privacy', 'attempt_id': label,
    }


def config():
    runtime = source_closure.runtime_identity()
    return {
        'comparison_selection_sha256': '04' * 32,
        'baseline_run_selection_sha256': '05' * 32,
        'candidate_run_selection_sha256': '06' * 32,
        'owner_comparison_source_sha256': comparison.source_sha256(),
        'owner_comparison_launcher_source_sha256': hashlib.sha256(
            (source_closure.HERE / 'privacy_owner_comparison_launch.py')
            .read_bytes()).hexdigest(),
        'source_closure_sha256': source_closure.all_digests(),
        'runtime_identity_sha256': source_closure.runtime_digest(),
        'python_runtime_sha256': runtime['python_runtime_sha256'],
        'namespace_tool_sha256': runtime['namespace_tool_sha256'],
        'root_guard_helper_sha256': runtime['root_guard_helper_sha256'],
        'host_runtime_trust_boundary':
            runtime['host_runtime_trust_boundary'],
        'step3_terminal_gate':
            'REQUIRED_SEPARATE_EXIT_LINKABILITY_GATE_BEFORE_STEP3',
        'baseline_binding': binding('base'),
        'candidate_binding': binding('candidate'),
        'baseline_capsule_seal_sha256': [('%02x' % (10 + index)) * 32
                                             for index in range(4)],
        'candidate_capsule_seal_sha256': [('%02x' % (20 + index)) * 32
                                              for index in range(4)],
        'baseline_score_bundle_seal_sha256': [('%02x' % (30 + index)) * 32
                                                   for index in range(3)],
        'candidate_score_bundle_seal_sha256': [('%02x' % (40 + index)) * 32
                                                    for index in range(3)],
    }


def round_score(number, bits):
    mask = (1 << bits) - 1
    return {'round': number, 'input_masks': [mask, mask],
        'output_masks': [mask, mask], 'joint_masks': [mask, mask],
        'eligible_inputs': 1, 'eligible_outputs': 2,
        'correct_unique_inputs': 0, 'wrong_unique_inputs': 0,
        'correct_unique_outputs': 0, 'wrong_unique_outputs': 0,
        'correct_unique_pair_links': 0, 'wrong_unique_pair_links': 0,
        'nf_pair_candidate_floor_met': True}


def workload_round_score(number):
    return {'round': number, 'eligible_inputs': 1, 'eligible_outputs': 2,
        'correct_unique_inputs': 0, 'wrong_unique_inputs': 0,
        'correct_unique_outputs': 0, 'wrong_unique_outputs': 0,
        'correct_unique_pair_links': 0, 'wrong_unique_pair_links': 0,
        'nf_pair_candidate_floor_met': True}


def bundles(label, bits):
    selected = config(); bound = selected[label + '_binding']
    run = selected[label + '_run_selection_sha256']
    seals = selected[label + '_capsule_seal_sha256']
    result = []
    for owner in (0, 1, 2):
        leaves = []
        for view, seal in zip(comparison.VIEWS, seals):
            leaves.append({'schema': 'kpb-private-direct-score-leaf/v2',
                'binding': bound, 'view': view,
                'capsule_seal_sha256': seal, 'owner_component': owner,
                'rounds': [round_score(1, bits), round_score(2, bits)],
                'round_candidate_counts': [
                    {'inputs': bits, 'outputs': bits, 'joint': bits},
                    {'inputs': bits, 'outputs': bits, 'joint': bits}],
                'workload_masks': [(1 << bits) - 1, (1 << bits) - 1],
                'workload_candidate_count': bits,
                'workload_rounds': [workload_round_score(1),
                                    workload_round_score(2)]})
        result.append({'schema': 'kpb-private-all-view-count-leaves/v2',
            'binding': bound, 'run_selection_sha256': run,
            'owner_component': owner, 'views': leaves})
    return result


class OwnerComparisonControls(unittest.TestCase):
    def test_self_authored_launch_receipt_is_never_authority(self):
        with self.assertRaises(ValueError):
            comparison_launcher.validate_launch_receipt({})

    def test_both_honest_owners_nonregress_and_strictly_gain(self):
        result = comparison.compare(config(), bundles('baseline', 1),
                                    bundles('candidate', 2))
        self.assertTrue(result['all_honest_owner_counts_nonregressed'])
        self.assertEqual(result['honest_owners_with_strict_gain'], 2)
        self.assertFalse(result['private_owner_counts_exported'])
        self.assertNotIn('owner_counts', result)

    def test_one_honest_owner_regression_fails_closed(self):
        candidate = bundles('candidate', 2)
        owner = next(row for row in candidate if row['owner_component'] == 2)
        owner['views'][0]['rounds'][0]['input_masks'][0] = 0
        result = comparison.compare(config(), bundles('baseline', 1), candidate)
        self.assertFalse(result['all_honest_owner_counts_nonregressed'])

    def test_no_strict_gain_is_not_accepted_by_gate_receipt(self):
        result = comparison.compare(config(), bundles('baseline', 1),
                                    bundles('candidate', 1))
        self.assertTrue(result['all_honest_owner_counts_nonregressed'])
        self.assertEqual(result['honest_owners_with_strict_gain'], 0)

    def test_source_capsule_binding_and_exact_private_schema_refuse_tamper(self):
        for mutation in ('source', 'seal', 'extra'):
            with self.subTest(mutation=mutation):
                selected = config(); candidate = bundles('candidate', 2)
                if mutation == 'source':
                    selected['owner_comparison_source_sha256'] = 'ff' * 32
                elif mutation == 'seal':
                    candidate[0]['views'][0]['capsule_seal_sha256'] = 'ff' * 32
                else:
                    candidate[0]['owner_counts'] = [1, 2]
                with self.assertRaises(ValueError):
                    comparison.compare(selected, bundles('baseline', 1),
                                       candidate)

    def test_swapped_or_reused_trial_refuses(self):
        selected = config()
        selected['candidate_binding'] = copy.deepcopy(
            selected['baseline_binding'])
        with self.assertRaisesRegex(ValueError, 'fresh-distinct-runs'):
            comparison.compare(selected, bundles('baseline', 1),
                               bundles('candidate', 2))

    def test_launcher_closure_runtime_and_terminal_pins_refuse_mutation(self):
        for mutation in ('launcher', 'closure', 'runtime', 'terminal'):
            with self.subTest(mutation=mutation):
                selected = config()
                if mutation == 'launcher':
                    selected['owner_comparison_launcher_source_sha256'] = \
                        'ff' * 32
                elif mutation == 'closure':
                    selected['source_closure_sha256'][
                        'owner-comparison'] = 'ff' * 32
                elif mutation == 'runtime':
                    selected['runtime_identity_sha256'] = 'ff' * 32
                else:
                    selected['step3_terminal_gate'] = 'NOT_REQUIRED'
                with self.assertRaises(ValueError):
                    comparison.compare(selected, bundles('baseline', 1),
                                       bundles('candidate', 2))


if __name__ == '__main__':
    unittest.main()
