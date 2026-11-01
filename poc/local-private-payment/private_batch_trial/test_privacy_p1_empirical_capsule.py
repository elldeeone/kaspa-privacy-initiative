import unittest
from pathlib import Path

import privacy_p1_empirical_capsule as capsule
import privacy_p1_empirical_observer as empirical
from test_privacy_p1_empirical_observer import (
    attempt_history,
    complete_capture,
    exact_constraint_plan,
)


def receipt(*, corrupt_b=False, omit_fork=False):
    raw = complete_capture()
    features = empirical.extract_c03_features(raw, attempt_history(raw))
    plan = exact_constraint_plan(features, corrupt_b=corrupt_b)
    if omit_fork:
        for candidate in plan['candidates']:
            for join in candidate['joins']:
                if join['p1_ref']['kind'] == 'FRAME':
                    join['exact_fields'].remove('fork_hex')
    return empirical.apply_within_run_constraints(features, plan)


class P1EmpiricalCapsuleResultControls(unittest.TestCase):
    def test_unique_receipt_reduces_to_fixed_non_authorizing_result(self):
        value = capsule.reduce_two_hypothesis_receipt(
            receipt(corrupt_b=True))

        self.assertEqual(set(value), {
            'schema', 'status', 'hypothesis_ids', 'retained_hypotheses',
            'edge_count', 'hypothesis_edge_match_masks',
            'within_run_field_coverage_complete',
            'candidate_edge_coverage_complete',
            'zero_unmodeled_categories',
            'exhaustive_four_view_bridge_completed', 'gate_authorizing',
        })
        self.assertEqual(
            value['schema'],
            'kpb-p1-passive-empirical-internal-result/v1')
        self.assertEqual(value['status'], capsule.STATUS_UNIQUE)
        self.assertEqual(value['hypothesis_ids'], [0, 1])
        self.assertEqual(value['retained_hypotheses'], [True, False])
        self.assertGreater(value['edge_count'], 0)
        self.assertEqual(len(value['hypothesis_edge_match_masks']), 2)
        self.assertTrue(value['within_run_field_coverage_complete'])
        self.assertTrue(value['candidate_edge_coverage_complete'])
        self.assertFalse(value['zero_unmodeled_categories'])
        self.assertFalse(value['exhaustive_four_view_bridge_completed'])
        self.assertFalse(value['gate_authorizing'])
        self.assertTrue(all(
            fragment not in repr(value).lower() for fragment in (
                'sha256', 'hash', 'path', 'body', 'payload', 'nonce',
                'authority')))

    def test_ambiguous_receipt_is_preserved_not_promoted(self):
        value = capsule.reduce_two_hypothesis_receipt(receipt())

        self.assertEqual(value['status'], capsule.STATUS_AMBIGUOUS)
        self.assertEqual(value['retained_hypotheses'], [True, True])
        self.assertFalse(value['exhaustive_four_view_bridge_completed'])
        self.assertFalse(value['gate_authorizing'])

    def test_missing_coverage_stays_unqualified(self):
        value = capsule.reduce_two_hypothesis_receipt(
            receipt(omit_fork=True))

        self.assertEqual(value['status'],
                         capsule.STATUS_UNQUALIFIED_MISSING_COVERAGE)
        self.assertFalse(value['within_run_field_coverage_complete'])
        self.assertFalse(value['zero_unmodeled_categories'])
        self.assertFalse(value['gate_authorizing'])

    def test_inconsistent_candidate_edges_refuse(self):
        selected = receipt()
        removed = selected['candidate_results'][1]['exact_results'][0][
            'join_id']
        selected['candidate_results'][1]['exact_results'] = [
            row for row in selected['candidate_results'][1]['exact_results']
            if row['join_id'] != removed]
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-candidate-edge-set'):
            capsule.reduce_two_hypothesis_receipt(selected)

    def test_more_than_64_edges_refuses(self):
        selected = receipt()
        for candidate in selected['candidate_results']:
            template = dict(candidate['exact_results'][0])
            candidate['exact_results'] = [
                {**template, 'join_id': 'edge-' + str(index)}
                for index in range(65)]
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-edge-bound'):
            capsule.reduce_two_hypothesis_receipt(selected)

    def test_deleted_and_extra_receipt_fields_refuse(self):
        deleted = receipt()
        deleted.pop('method_sha256')
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-receipt'):
            capsule.reduce_two_hypothesis_receipt(deleted)

        extra = receipt()
        extra['caller_result'] = True
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-receipt'):
            capsule.reduce_two_hypothesis_receipt(extra)

    def test_deleted_field_status_refuses_complete_claim(self):
        selected = receipt()
        selected['field_status'].pop('header.fork')
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-field-catalog'):
            capsule.reduce_two_hypothesis_receipt(selected)

    def test_rank_and_timing_schema_or_asymmetry_refuses(self):
        bad_rank = receipt()
        bad_rank['candidate_results'][0]['rank_results'][0].pop(
            'source_id')
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-rank-result'):
            capsule.reduce_two_hypothesis_receipt(bad_rank)

        bad_timing = receipt()
        bad_timing['candidate_results'][1]['timing_results'][0][
            'metric'] = 'CALLER_THRESHOLD'
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-timing-result'):
            capsule.reduce_two_hypothesis_receipt(bad_timing)

    def test_identical_event_provenance_under_distinct_maps_refuses(self):
        selected = receipt()
        by_edge = {}
        for row in selected['candidate_results'][0]['exact_results']:
            by_edge.setdefault(row['join_id'], row['event_id'])
        for row in selected['candidate_results'][1]['exact_results']:
            row['event_id'] = by_edge[row['join_id']]
        with self.assertRaisesRegex(
                capsule.CapsuleRefused,
                'p1-empirical-capsule-edge-provenance'):
            capsule.reduce_two_hypothesis_receipt(selected)

    def test_acceptance_sources_cannot_consume_optional_classifier(self):
        root = Path(__file__).resolve().parent
        selected = (
            'privacy_acceptance.py', 'privacy_actual_capture.py',
            'privacy_roles.py', 'privacy_measurement_worker_capsule.cpp',
            'privacy_measurement_child_supervisor.cpp',
            'privacy_measurement_preexec_sandbox.cpp',
        )
        forbidden = (
            'score_candidates(', 'freeze_calibration(',
            'OPTIONAL_CLASSIFIER', 'CALIBRATION_SCHEMA',
        )
        for name in selected:
            text = (root / name).read_text()
            for token in forbidden:
                with self.subTest(file=name, token=token):
                    self.assertNotIn(token, text)


if __name__ == '__main__':
    unittest.main()
