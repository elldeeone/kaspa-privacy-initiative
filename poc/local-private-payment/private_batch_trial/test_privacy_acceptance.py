"""Public controls for the frozen four-view privacy acceptance gate."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import privacy_acceptance as gate


WORD = '01' * 32


def binding(label):
    return {'method_sha256': WORD, 'selection_sha256': ('02' if label == 'base' else '03') * 32,
            'trial_id': ('11111111-1111-4111-8111-111111111111'
                         if label == 'base' else
                         '22222222-2222-4222-8222-222222222222'),
            'phase': 'private-batch-privacy', 'attempt_id': label}


def round_result(number, candidate):
    if candidate:
        histogram = {'1': 1, '6': 2}
        values = {'input_owner_assignments': 2, 'output_creator_assignments': 3,
                  'output_pair_partitions': 3, 'joint_candidates': 6,
                  'nf_to_created_pair_relations': 6,
                  'honest_input_swap_retained': True,
                  'honest_graph_alternative_retained': True,
                  'honest_nf_pair_candidate_floor_met': True,
                  'strict_H1_status': 'PASS_BOUNDED_DIRECT_CHECK'}
    else:
        histogram = {'1': 3}
        values = {'input_owner_assignments': 1, 'output_creator_assignments': 1,
                  'output_pair_partitions': 1, 'joint_candidates': 1,
                  'nf_to_created_pair_relations': 1,
                  'honest_input_swap_retained': False,
                  'honest_graph_alternative_retained': False,
                  'honest_nf_pair_candidate_floor_met': False,
                  'strict_H1_status': 'FAIL'}
    return {'round': number, **values, 'truth_retained': True,
        'nf_pair_candidate_count_histogram': histogram, 'forbidden_exports': 0,
        'eligible_inputs': 2, 'eligible_outputs': 4,
        'correct_unique_inputs': 0 if candidate else 2,
        'wrong_unique_inputs': 0, 'correct_unique_outputs': 0 if candidate else 4,
        'wrong_unique_outputs': 0, 'correct_unique_pair_links': 0 if candidate else 2,
        'wrong_unique_pair_links': 0}


def view(name, candidate, label, index):
    return {'schema': 'kpb-public-direct-linkage-counts/v2',
        'binding': binding(label), 'view': name,
        'capsule_seal_sha256': ('%02x' %
            ((20 if candidate else 10) + index)) * 32,
        'rounds': [round_result(1, candidate), round_result(2, candidate)],
        'coverage': {'modeled_artifacts': 40 + index, 'unmodeled_artifacts': 0,
                     'missing_artifacts': 0, 'terminal_modeled': True},
        'category_coverage': {
            category: {'modeled_artifacts': 2, 'unmodeled_artifacts': 0,
                       'missing_artifacts': 0,
                       'constraint_modeled_fields': 1,
                       'source_assumption_covered_fields': 0,
                       'unmodeled_fields': 0}
            for category in gate.REQUIRED_CATEGORIES[name]
        },
        'workload': {
            'full_workload_candidates': 6 if candidate else 1,
            'truth_vector_retained': True,
            'honest_graph_alternative_retained': candidate,
            'correct_unique_full_vectors': 0 if candidate else 1,
            'wrong_unique_full_vectors': 0,
            'eligible_inputs': 4, 'eligible_outputs': 8,
            'correct_unique_inputs': 0 if candidate else 4,
            'wrong_unique_inputs': 0,
            'correct_unique_outputs': 0 if candidate else 8,
            'wrong_unique_outputs': 0,
            'correct_unique_pair_links': 0 if candidate else 4,
            'wrong_unique_pair_links': 0,
            'honest_nf_pair_candidate_floor_met': candidate,
            'cross_round_constraints_modeled': True,
            'terminal_constraints_modeled': True,
            'candidate_set_commitment_sha256':
                ('%02x' % ((60 if candidate else 50) + index)) * 32,
        },
        'combined_terminal_status': ('PASS_BOUNDED_DIRECT_CHECK' if candidate else 'FAIL'),
        'scope': 'FINITE_DIRECT_CONSTRAINTS_NOT_CRYPTOGRAPHIC_OR_GENERAL_ANONYMITY',
        'posterior_probability_claim': False,
        'private_truth_or_per_owner_scores_exported': False}


def bundle(candidate):
    label = 'candidate' if candidate else 'base'
    runtime = gate.source_closure.runtime_identity()
    offset = 120 if candidate else 110
    return {'schema': 'kpb-privacy-all-view-bundle/v2',
        'classification': ('ACTUAL_HIDDEN_MAPPING_CANDIDATE' if candidate
                           else 'ACTUAL_TRANSPARENT_BASELINE'),
        'comparison_selection_sha256': '0a' * 32,
        'run_selection_sha256': ('0c' if candidate else '0b') * 32,
        'diagnostic_selection_sha256': ('03' if candidate else '02') * 32,
        'diagnostic_run_selection_sha256':
            ('03' if candidate else '02') * 32,
        'binding': binding(label),
        'method_sha256': WORD, 'workload_sha256': '04' * 32,
        'measurement_freeze_sha256': '0d' * 32,
        'observer_source_sha256': '05' * 32,
        'capture_source_sha256': '06' * 32,
        'coverage_policy_sha256': '07' * 32,
        'bundle_producer_source_sha256': '0e' * 32,
        'owner_comparison_source_sha256': '0f' * 32,
        'owner_comparison_launcher_source_sha256': '10' * 32,
        'capture_producer_source_sha256': '12' * 32,
        'capture_producer_build_sha256': '13' * 32,
        'capture_producer_launcher_source_sha256': '14' * 32,
        'capture_launcher_source_sha256': '11' * 32,
        'source_closure_sha256': gate.source_closure.all_digests(),
        'runtime_identity_sha256': gate.source_closure.runtime_digest(),
        'python_runtime_sha256': runtime['python_runtime_sha256'],
        'namespace_tool_sha256': runtime['namespace_tool_sha256'],
        'root_guard_helper_sha256': runtime['root_guard_helper_sha256'],
        'host_runtime_trust_boundary':
            runtime['host_runtime_trust_boundary'],
        'terminal_scope': gate.TERMINAL_SCOPE,
        'step3_terminal_gate': gate.STEP3_TERMINAL_GATE,
        'capture_identity': ('33333333-3333-4333-8333-333333333333'
            if candidate else '44444444-4444-4444-8444-444444444444'),
        'capture_receipt_sha256': ('09' if candidate else '08') * 32,
        'capture_manifest_seal_sha256': ('31' if candidate else '30') * 32,
        'construction_classification_receipt_sha256':
            ('2f' if candidate else '2e') * 32,
        'capture_producer_receipt_sha256':
            ('2d' if candidate else '2c') * 32,
        'capture_launch_receipt_sha256':
            ('2b' if candidate else '2a') * 32,
        'financial_rounds': [{
            'round': number,
            'financial_run_id': ('%02x' % (offset + number)) * 32,
            'financial_artifacts_sha256':
                ('%02x' % (offset + 2 + number)) * 32,
            'financial_result_sha256':
                ('%02x' % (offset + 4 + number)) * 32,
            'retained_projection_sha256':
                ('%02x' % (offset + 6 + number)) * 32,
        } for number in (1, 2)],
        'observation_receipt_sha256': ('33' if candidate else '32') * 32,
        'observation_launch_sha256': ('35' if candidate else '34') * 32,
        'barrier_sha256': ('37' if candidate else '36') * 32,
        'score_receipt_sha256': [('%02x' %
            ((80 if candidate else 70) + index)) * 32 for index in range(3)],
        'score_launch_sha256': [('%02x' %
            ((90 if candidate else 86) + index)) * 32 for index in range(3)],
        'aggregate_result_sha256': ('39' if candidate else '38') * 32,
        'aggregate_launch_sha256': ('3b' if candidate else '3a') * 32,
        'coverage_categories': {name: list(gate.REQUIRED_CATEGORIES[name])
                                for name in gate.VIEWS},
        'lattice_attestation': {
            'exact_union_artifact_set': True,
            'exact_union_constraints': True,
            'candidate_subset_lattice_verified': True,
            'full_workload_subset_lattice_verified': True,
        },
        'views': [view(name, candidate, label, index)
                  for index, name in enumerate(gate.VIEWS)]}


def owner_comparison(baseline=None, candidate=None):
    baseline = bundle(False) if baseline is None else baseline
    candidate = bundle(True) if candidate is None else candidate
    return {
        'schema': 'kpb-privacy-owner-nonregression/v1',
        'comparison_selection_sha256':
            baseline['comparison_selection_sha256'],
        'baseline_run_selection_sha256': baseline['run_selection_sha256'],
        'candidate_run_selection_sha256': candidate['run_selection_sha256'],
        'owner_comparison_source_sha256':
            baseline['owner_comparison_source_sha256'],
        'owner_comparison_launcher_source_sha256':
            baseline['owner_comparison_launcher_source_sha256'],
        'source_closure_sha256': baseline['source_closure_sha256'],
        'runtime_identity_sha256': baseline['runtime_identity_sha256'],
        'step3_terminal_gate': gate.STEP3_TERMINAL_GATE,
        'baseline_capsule_seal_sha256': [row['capsule_seal_sha256']
                                            for row in baseline['views']],
        'candidate_capsule_seal_sha256': [row['capsule_seal_sha256']
                                             for row in candidate['views']],
        'baseline_score_bundle_seal_sha256': [('%02x' % (40 + index)) * 32
                                                   for index in range(3)],
        'candidate_score_bundle_seal_sha256': [('%02x' % (44 + index)) * 32
                                                    for index in range(3)],
        'dimensions': list(gate.OWNER_COMPARISON_DIMENSIONS),
        'honest_owner_count': 2,
        'all_honest_owner_counts_nonregressed': True,
        'honest_owners_with_strict_gain': 2,
        'private_owner_counts_exported': False,
    }


def assess(baseline, candidate, comparison=None):
    return gate.evaluate_synthetic_model(baseline, candidate,
        owner_comparison(baseline, candidate)
        if comparison is None else comparison)


class AcceptanceControls(unittest.TestCase):
    def test_synthetic_model_baseline_to_hidden_mapping_candidate_passes(self):
        result = assess(bundle(False), bundle(True))
        self.assertEqual(result['status'],
                         'PASS_BOUNDED_SYNTHETIC_MODEL_CHECK')
        self.assertEqual(result['schema'],
                         'kpb-privacy-synthetic-model-result/v1')
        self.assertFalse(result['actual_authority_chain_verified'])
        self.assertFalse(result['actual_privacy_status_minted'])
        self.assertTrue(result['all_four_candidate_views_complete'])
        self.assertEqual(result['candidate_unique_eligible_predictions'], 0)
        self.assertEqual(result['candidate_trial_id'],
                         bundle(True)['binding']['trial_id'])
        self.assertEqual(result['candidate_bundle_sha256'],
            hashlib.sha256(gate.encoded(bundle(True))).hexdigest())

    def test_owner_relabel_only_cannot_pass_payment_graph_gate(self):
        candidate = bundle(True)
        for observed in candidate['views']:
            for row in observed['rounds']:
                row['output_pair_partitions'] = 1
                row['nf_to_created_pair_relations'] = 1
                row['nf_pair_candidate_count_histogram'] = {'1': 3}
        result = assess(bundle(False), candidate)
        self.assertEqual(result['status'], 'FAIL_PRIVACY_GATE')

    def test_source_derived_colluder_floor_cannot_be_weakened(self):
        candidate = bundle(True)
        for observed in candidate['views']:
            for row in observed['rounds']:
                row['output_creator_assignments'] = 2
                row['output_pair_partitions'] = 2
                row['joint_candidates'] = 4
                row['nf_to_created_pair_relations'] = 4
                row['nf_pair_candidate_count_histogram'] = {'1': 1, '4': 2}
        self.assertEqual(assess(bundle(False), candidate)['status'],
                         'FAIL_PRIVACY_GATE')

    def test_no_public_ambiguity_dimension_may_regress(self):
        baseline = bundle(False)
        for observed in baseline['views']:
            for row in observed['rounds']:
                row['input_owner_assignments'] = 6
        result = assess(baseline, bundle(True))
        self.assertEqual(result['status'], 'FAIL_PRIVACY_GATE')
        self.assertFalse(
            result['all_view_round_count_dimensions_pareto_nonregressed'])

    def test_private_honest_owner_nonregression_receipt_is_mandatory(self):
        baseline, candidate = bundle(False), bundle(True)
        for mutation in ('regression', 'no-gain', 'wrong-capsule'):
            with self.subTest(mutation=mutation):
                receipt = owner_comparison(baseline, candidate)
                if mutation == 'regression':
                    receipt['all_honest_owner_counts_nonregressed'] = False
                elif mutation == 'no-gain':
                    receipt['honest_owners_with_strict_gain'] = 0
                else:
                    receipt['candidate_capsule_seal_sha256'][0] = 'ff' * 32
                with self.assertRaises(ValueError):
                    assess(baseline, candidate, receipt)

    def test_missing_unmodeled_or_unqualified_view_never_passes(self):
        for kind in ('missing', 'unmodeled', 'terminal', 'status'):
            with self.subTest(kind=kind):
                candidate = bundle(True)
                union = candidate['views'][-1]
                if kind == 'missing':
                    union['coverage']['missing_artifacts'] = 1
                    for row in union['rounds']:
                        row['strict_H1_status'] = 'UNQUALIFIED'
                    union['combined_terminal_status'] = 'UNQUALIFIED'
                elif kind == 'unmodeled':
                    union['coverage']['unmodeled_artifacts'] = 1
                    for row in union['rounds']:
                        row['strict_H1_status'] = 'UNQUALIFIED'
                    union['combined_terminal_status'] = 'UNQUALIFIED'
                elif kind == 'terminal':
                    union['coverage']['terminal_modeled'] = False
                    union['combined_terminal_status'] = 'UNQUALIFIED'
                else:
                    union['coverage']['missing_artifacts'] = 1
                    for row in union['rounds']:
                        row['strict_H1_status'] = 'UNQUALIFIED'
                    union['combined_terminal_status'] = 'UNQUALIFIED'
                self.assertEqual(assess(bundle(False), candidate)['status'],
                                 'UNQUALIFIED')

    def test_wrong_prediction_or_lost_truth_is_failure(self):
        for kind in ('wrong', 'truth'):
            with self.subTest(kind=kind):
                candidate = bundle(True)
                if kind == 'wrong':
                    candidate['views'][-1]['rounds'][0]['wrong_unique_pair_links'] = 1
                    candidate['views'][-1]['rounds'][0]['truth_retained'] = False
                    candidate['views'][-1]['rounds'][0]['strict_H1_status'] = 'FAIL'
                    candidate['views'][-1]['combined_terminal_status'] = 'FAIL'
                else:
                    candidate['views'][-1]['rounds'][0]['truth_retained'] = False
                    candidate['views'][-1]['rounds'][0]['strict_H1_status'] = 'FAIL'
                    candidate['views'][-1]['combined_terminal_status'] = 'FAIL'
                self.assertEqual(assess(bundle(False), candidate)['status'],
                                 'FAIL_PRIVACY_GATE')

    def test_zero_candidate_exclusion_is_a_retained_failure_not_parse_error(self):
        candidate = bundle(True); union = candidate['views'][-1]
        row = union['rounds'][0]
        row['joint_candidates'] = 0
        row['nf_to_created_pair_relations'] = 0
        row['nf_pair_candidate_count_histogram'] = {'0': 3}
        row['truth_retained'] = False
        row['honest_input_swap_retained'] = False
        row['honest_graph_alternative_retained'] = False
        row['strict_H1_status'] = 'FAIL'
        union['combined_terminal_status'] = 'FAIL'
        self.assertEqual(assess(bundle(False), candidate)['status'],
                         'FAIL_PRIVACY_GATE')

    def test_weaker_view_facts_are_evaluated_not_its_pass_label(self):
        candidate = bundle(True)
        candidate['views'][0]['rounds'][0]['correct_unique_pair_links'] = 1
        candidate['views'][1]['rounds'][0]['correct_unique_pair_links'] = 1
        self.assertEqual(candidate['views'][1]['combined_terminal_status'],
                         'PASS_BOUNDED_DIRECT_CHECK')
        self.assertEqual(assess(bundle(False), candidate)['status'],
                         'FAIL_PRIVACY_GATE')

        candidate = bundle(True)
        weaker = candidate['views'][1]
        weaker['rounds'][0]['nf_pair_candidate_count_histogram'] = {'1': 3}
        self.assertEqual(assess(bundle(False), candidate)['status'],
                         'FAIL_PRIVACY_GATE')

    def test_spoofed_round_pass_status_is_rejected(self):
        candidate = bundle(True)
        row = candidate['views'][1]['rounds'][0]
        row['truth_retained'] = False
        with self.assertRaisesRegex(ValueError,
                                    'round-status-derived-from-facts'):
            assess(bundle(False), candidate)

    def test_round_arithmetic_and_logical_invariants_are_enforced(self):
        mutations = ('input-max', 'joint-product', 'unique-eligible',
                     'wrong-with-truth', 'joint-without-input-swap')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = bundle(True)
                row = candidate['views'][0]['rounds'][0]
                if mutation == 'input-max':
                    row['input_owner_assignments'] = 7
                elif mutation == 'joint-product':
                    row['joint_candidates'] = 7
                elif mutation == 'unique-eligible':
                    row['correct_unique_inputs'] = 3
                elif mutation == 'wrong-with-truth':
                    row['wrong_unique_inputs'] = 1
                else:
                    row['honest_input_swap_retained'] = False
                with self.assertRaises(ValueError):
                    assess(bundle(False), candidate)

    def test_baseline_must_detect_actual_link_in_both_rounds(self):
        baseline = bundle(False)
        for observed in baseline['views']:
            observed['rounds'][1] = round_result(2, True)
        self.assertEqual(assess(baseline, bundle(True))['status'],
                         'INVALID_BASELINE_CONTROL')

    def test_union_cannot_increase_candidates_or_change_order(self):
        candidate = bundle(True)
        candidate['views'][0]['rounds'][0]['joint_candidates'] = 5
        candidate['views'][0]['rounds'][0]['nf_to_created_pair_relations'] = 5
        with self.assertRaisesRegex(ValueError, 'union-candidates-must-not-increase'):
            assess(bundle(False), candidate)
        candidate = bundle(True)
        candidate['views'][1], candidate['views'][2] = \
            candidate['views'][2], candidate['views'][1]
        with self.assertRaisesRegex(ValueError, 'view-schema-and-order'):
            assess(bundle(False), candidate)

    def test_full_view_lattice_cannot_restore_or_drop_observations(self):
        mutations = ('side-count-increase', 'truth-restored',
                     'export-disappears', 'unique-disappears',
                     'workload-eligibility-changes')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = bundle(True)
                baseline = bundle(False)
                if mutation == 'side-count-increase':
                    candidate['views'][0]['rounds'][0]['joint_candidates'] = 5
                    candidate['views'][0]['rounds'][0][
                        'nf_to_created_pair_relations'] = 5
                elif mutation == 'truth-restored':
                    row = candidate['views'][1]['rounds'][0]
                    row['truth_retained'] = False
                    row['strict_H1_status'] = 'FAIL'
                    candidate['views'][1]['combined_terminal_status'] = 'FAIL'
                elif mutation == 'export-disappears':
                    row = candidate['views'][2]['rounds'][0]
                    row['forbidden_exports'] = 1
                    row['strict_H1_status'] = 'FAIL'
                    candidate['views'][2]['combined_terminal_status'] = 'FAIL'
                elif mutation == 'workload-eligibility-changes':
                    candidate['views'][1]['workload']['eligible_inputs'] = 5
                else:
                    candidate['views'][2]['rounds'][0][
                        'correct_unique_pair_links'] = 1
                # This control exercises the later lattice invariant, not the
                # independently tested source-drift hard stop.  Other agents
                # may update a transitive source while this loop constructs
                # its two synthetic bundles, so bind both to one freshly
                # recomputed snapshot for the duration of this assertion.
                closure = gate.source_closure.all_digests()
                baseline['source_closure_sha256'] = closure
                candidate['source_closure_sha256'] = closure
                with mock.patch.object(
                        gate.source_closure, 'all_digests',
                        return_value=closure):
                    with self.assertRaisesRegex(
                            ValueError, 'union-candidates-must-not-increase'):
                        assess(baseline, candidate)

    def test_coverage_categories_and_capture_receipts_are_bound(self):
        candidate = bundle(True)
        candidate['coverage_categories']['union'].remove('retry-history')
        with self.assertRaisesRegex(ValueError, 'exact-required-coverage-union'):
            assess(bundle(False), candidate)
        candidate = bundle(True)
        candidate['capture_receipt_sha256'] = bundle(False)['capture_receipt_sha256']
        with self.assertRaisesRegex(
                ValueError, 'distinct-actual-capture-receipt-sha256'):
            assess(bundle(False), candidate)

    def test_extra_truth_or_owner_label_field_refuses(self):
        candidate = bundle(True)
        candidate['views'][-1]['rounds'][0]['owner_truth'] = 0
        with self.assertRaisesRegex(ValueError, 'exact-fields'):
            assess(bundle(False), candidate)

    def test_binding_is_exact_method_bound_and_fresh_between_runs(self):
        candidate = bundle(True)
        candidate['views'][0]['binding']['hidden_truth'] = 1
        with self.assertRaisesRegex(ValueError, 'exact-fields'):
            assess(bundle(False), candidate)

        candidate = bundle(True)
        candidate['binding']['method_sha256'] = 'ff' * 32
        for observed in candidate['views']:
            observed['binding']['method_sha256'] = 'ff' * 32
        with self.assertRaisesRegex(ValueError,
                                    'top-binding-source-selection'):
            assess(bundle(False), candidate)

        candidate = bundle(True)
        candidate['binding']['trial_id'] = \
            bundle(False)['binding']['trial_id']
        for observed in candidate['views']:
            observed['binding']['trial_id'] = \
                bundle(False)['views'][0]['binding']['trial_id']
        with self.assertRaisesRegex(ValueError, 'distinct-actual-trial-id'):
            assess(bundle(False), candidate)

    def test_parse_requires_canonical_unique_json(self):
        canonical = gate.encoded({'a': 1, 'b': 2})
        self.assertEqual(gate.parse(canonical), {'a': 1, 'b': 2})
        with self.assertRaises(ValueError):
            gate.parse(b'{"b":2,"a":1}\n')
        with self.assertRaises(ValueError):
            gate.parse(b'{"a":1,"a":2}\n')

    def test_canonical_bundle_round_trip_keeps_category_map_valid(self):
        baseline = gate.parse(gate.encoded(bundle(False)))
        candidate = gate.parse(gate.encoded(bundle(True)))
        self.assertEqual(assess(baseline, candidate)['status'],
                         'PASS_BOUNDED_SYNTHETIC_MODEL_CHECK')

    def test_canonical_0400_file_round_trip_is_cli_admissible(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / 'BASELINE.json'
            candidate_path = Path(directory) / 'CANDIDATE.json'
            gate.write_new(baseline_path, bundle(False))
            gate.write_new(candidate_path, bundle(True))
            baseline = gate.read_canonical(baseline_path)
            candidate = gate.read_canonical(candidate_path)
            result = assess(baseline, candidate)
            self.assertEqual(result['status'],
                             'PASS_BOUNDED_SYNTHETIC_MODEL_CHECK')

    def test_standalone_0400_bundles_cannot_mint_actual_privacy_pass(self):
        baseline, candidate = bundle(False), bundle(True)
        comparison = owner_comparison(baseline, candidate)
        direct = gate.evaluate(baseline, candidate, comparison)
        self.assertEqual(direct['schema'],
                         'kpb-privacy-acceptance-source-only/v1')
        self.assertEqual(direct['status'],
                         'UNQUALIFIED_ACTUAL_AUTHORITY_ABSENT')
        self.assertEqual(direct['synthetic_model_status'],
                         'PASS_BOUNDED_SYNTHETIC_MODEL_CHECK')
        self.assertFalse(direct['actual_authority_chain_verified'])
        self.assertFalse(direct['actual_privacy_status_minted'])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / 'BASELINE.json'
            candidate_path = root / 'CANDIDATE.json'
            output_path = root / 'RESULT.json'
            gate.write_new(baseline_path, baseline)
            gate.write_new(candidate_path, candidate)
            with mock.patch.object(gate, 'read_owner_comparison_chain',
                    return_value=comparison), mock.patch('sys.argv', [
                        'privacy_acceptance.py', '--baseline',
                        str(baseline_path), '--candidate',
                        str(candidate_path), '--output', str(output_path)]):
                gate.main()
            emitted = gate.read_canonical(output_path)
            self.assertEqual(emitted, direct)
            self.assertNotIn('PASS_BOUNDED_ACTUAL_PRIVACY_IMPROVEMENT',
                             gate.encoded(emitted).decode())


if __name__ == '__main__':
    unittest.main()
