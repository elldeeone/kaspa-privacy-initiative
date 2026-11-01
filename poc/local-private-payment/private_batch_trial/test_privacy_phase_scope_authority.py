"""Adversarial controls for the pre-network/private phase split."""

import copy
from pathlib import Path
import unittest
from unittest import mock

import privacy_capture_model as capture
import privacy_phase_scope_authority as phase


def inputs(suffix=''):
    publics = [
        {'projection_sha256': ('11' if number == 1 else '22') * 32}
        for number in (1, 2)
    ]
    artifacts = [[{
        'artifact_sha256': format(round_number * 10 + index, '064x')
    } for index in range(5)] for round_number in (1, 2)]
    if suffix:
        artifacts[1][4]['artifact_sha256'] = suffix * 64
    return publics, artifacts


def deferred_rows():
    return [{
        'round': round_number,
        'artifact_kind': 'public-projection',
        'category': category,
        'field_path': field_path,
        'proposed_resolution':
            'direct_constraint_pending_source_authority',
        'mapping_dependent': False,
        'evidence_requirement': phase.STEP3_ACCEPTED_CHAIN_REQUIREMENT,
        'coverage_relabel_allowed': False,
    } for round_number in (1, 2)
      for category, field_path in phase.STEP3_DEFERRED_FAMILIES]


def partition():
    summary_views = [{
        'view_index': view_index,
        'candidate_count': 36,
        'all_candidate_edges_covered': False,
        'missing_artifact_count': 0,
        'unmodeled_field_count': 4,
        'source_assumption_mask': 0,
    } for view_index in range(4)]
    return {
        'schema': 'kpb-private-completion-phase-partition/v1',
        'coverage_summary': {
            'schema': 'kpb-private-four-view-coverage-summary/v1',
            'views': summary_views,
            'exact_ten_typed_leaves': True,
            'exhaustive_lattice': True,
            'completion_ready': False,
        },
        'views': [{
            'view_index': view_index,
            'step2_open_fields': [],
            'deferred_step3_open_fields': deferred_rows(),
        } for view_index in range(4)],
    }


class PrivacyPhaseScopeAuthorityTests(unittest.TestCase):
    def hook(self, value):
        return mock.patch.object(
            capture, '_private_completion_phase_partition',
            create=True, return_value=value)

    def test_real_model_partitions_without_covering_step3_rows(self):
        from test_privacy_capture_model import (
            colluder_fixture, corrupt_fixture, dispatcher_fixture, projection,
            raw, terminal_fixture)

        publics = []
        artifact_rounds = []
        for number in (1, 2):
            projection_bytes, public = projection(number)
            publics.append(public)
            artifact_rounds.append([
                capture.public_projection(projection_bytes, public),
                capture.terminal(raw(terminal_fixture(public)), public),
                capture.dispatcher(raw(dispatcher_fixture(public)), public),
                capture.corrupt_server(raw(corrupt_fixture(
                    public, projection_bytes)), public, projection_bytes),
                capture.colluder_wallet(raw(colluder_fixture(public)), public),
            ])
        value = capture._private_completion_phase_partition(
            publics, artifact_rounds)
        self.assertEqual(value['schema'],
                         'kpb-private-completion-phase-partition/v1')
        self.assertEqual(
            [len(view['step2_open_fields']) for view in value['views']],
            [row['unmodeled_field_count'] - 4
             for row in value['coverage_summary']['views']])
        self.assertEqual([
            capture._public_projection_blocker_matrix(artifacts[0])[
                'row_count'] for artifacts in artifact_rounds], [21, 21])
        structural_keys = {
            ('context-identities',
             'context.two_round_structural_profile_script_binding'),
            ('state-transition',
             'state.two_round_projection_structural_continuity'),
        }
        for view in value['views']:
            self.assertEqual(view['deferred_step3_open_fields'],
                             deferred_rows())
            self.assertTrue(structural_keys <= {
                (row['category'], row['field_path'])
                for row in view['step2_open_fields']})
        with self.assertRaisesRegex(
                ValueError, 'phase-scope-step2-still-open'):
            phase.require_step2_private_coverage(publics, artifact_rounds)

    def test_forged_python_structural_types_cannot_enter_phase_scope(self):
        from test_privacy_capture_model import projection

        projection_bytes, public = projection(1)
        forged_context = capture._SelectedFd40StructuralContext(
            capture._SELECTED_STRUCTURAL_CONTEXT_CONSTRUCTOR,
            291600, 291600)
        with self.assertRaisesRegex(
                ValueError,
                'selected-fd40-native-structural-authority-required'):
            capture._public_projection_model(
                projection_bytes, public, forged_context)

        forged_models = capture._SelectedFd40StructuralModels(
            capture._SELECTED_STRUCTURAL_MODELS_CONSTRUCTOR,
            [{}, {}], [{}, {}], [{} for _ in range(10)])
        publics, artifacts = inputs()
        with self.assertRaisesRegex(
                ValueError, 'private-completion-two-rounds'):
            phase.require_step2_private_coverage(publics, forged_models)
        self.assertFalse(hasattr(
            phase, 'consume_step2_private_coverage_for_prediction'))

        source = Path(phase.__file__).read_text()
        self.assertNotIn('consume_selected_fd40', source)
        self.assertNotIn('privacy_fd40_archive', source)

    def test_ready_partition_still_refuses_without_native_authority(self):
        publics, artifacts = inputs()
        with self.hook(partition()):
            for _ in range(2):
                with self.assertRaisesRegex(
                        ValueError, 'phase-scope-native-authority-required'):
                    phase.require_step2_private_coverage(
                        publics, artifacts)

        source = Path(phase.__file__).read_text()
        self.assertNotIn('test_only_mint', source)
        self.assertFalse(hasattr(
            phase, 'complete_step3_accepted_chain_coverage'))
        self.assertFalse(hasattr(
            phase, 'consume_step2_private_coverage_for_prediction'))
        self.assertFalse(hasattr(
            phase,
            '_consume_step2_prediction_authorization_for_isolated_derivation'))

    def test_imported_sentinel_registry_and_object_new_forgery_have_no_seam(self):
        forbidden = (
            '_STEP2_AUTHORITY_CONSTRUCTOR',
            '_STEP2_PREDICTION_CONSTRUCTOR',
            '_STEP3_RESIDUAL_CONSTRUCTOR',
            '_LIVE_PHASE_OBJECTS',
            '_Step2PrivateCoverageAuthority',
            '_Step2PredictionAuthorization',
            '_DeferredStep3AcceptedChainCoverageAuthority',
            'consume_step2_private_coverage_for_prediction',
        )
        for name in forbidden:
            with self.subTest(name=name):
                self.assertFalse(hasattr(phase, name))

        class HostileStep2Authority:
            pass

        forged = object.__new__(HostileStep2Authority)
        forged._input_identity = 'ff' * 32
        forged._live = True
        hostile_registry = {id(forged): forged}
        self.assertIs(hostile_registry[id(forged)], forged)
        with self.hook(partition()):
            with self.assertRaisesRegex(
                    ValueError, 'phase-scope-native-authority-required'):
                phase.require_step2_private_coverage(forged, forged)

    def test_repeat_and_cross_input_attempts_never_yield_authority(self):
        publics, artifacts = inputs()
        changed_publics, changed_artifacts = inputs('a')
        with self.hook(partition()):
            for supplied_publics, supplied_artifacts in (
                    (publics, artifacts),
                    (changed_publics, changed_artifacts),
                    (publics, artifacts)):
                with self.assertRaisesRegex(
                        ValueError, 'phase-scope-native-authority-required'):
                    phase.require_step2_private_coverage(
                        supplied_publics, supplied_artifacts)

    def test_extra_step2_open_row_and_coverage_relabel_refuse(self):
        publics, artifacts = inputs()
        extra = partition()
        extra['views'][2]['step2_open_fields'].append({
            'round': 1, 'artifact_kind': 'public-projection',
            'category': 'ciphertexts', 'field_path': 'still.open',
            'proposed_resolution': 'source_assumption_pending_selection',
            'mapping_dependent': False,
            'evidence_requirement': 'STILL_OPEN_STEP2_EVIDENCE',
            'coverage_relabel_allowed': False})
        extra['coverage_summary']['views'][2][
            'unmodeled_field_count'] += 1
        relabelled = partition()
        relabelled['coverage_summary']['completion_ready'] = True
        relabelled['coverage_summary']['views'][0][
            'all_candidate_edges_covered'] = True
        for label, value in (
                ('phase-scope-step2-still-open', extra),
                ('phase-scope-base-summary', relabelled)):
            with self.subTest(label=label), self.hook(value):
                with self.assertRaisesRegex(ValueError, label):
                    phase.require_step2_private_coverage(publics, artifacts)

    def test_missing_extra_wrong_round_and_wrong_requirement_refuse(self):
        publics, artifacts = inputs()
        mutations = []
        missing = partition()
        missing['views'][0]['deferred_step3_open_fields'].pop()
        mutations.append(('phase-scope-exact-four-deferred', missing))
        extra = partition()
        extra['views'][0]['deferred_step3_open_fields'].append(
            copy.deepcopy(extra['views'][0][
                'deferred_step3_open_fields'][0]))
        mutations.append(('phase-scope-exact-four-deferred', extra))
        wrong_round = partition()
        wrong_round['views'][1]['deferred_step3_open_fields'][0]['round'] = 2
        mutations.append(('phase-scope-duplicate-deferred-row', wrong_round))
        wrong_requirement = partition()
        wrong_requirement['views'][3]['deferred_step3_open_fields'][0][
            'evidence_requirement'] = 'CALLER_SAYS_ACCEPTED'
        mutations.append(('phase-scope-deferred-row-binding',
                          wrong_requirement))
        relabel = partition()
        relabel['views'][2]['deferred_step3_open_fields'][0][
            'coverage_relabel_allowed'] = True
        mutations.append(('phase-scope-deferred-row-binding', relabel))
        for label, value in mutations:
            with self.subTest(label=label), self.hook(value):
                with self.assertRaisesRegex(ValueError, label):
                    phase.require_step2_private_coverage(publics, artifacts)


if __name__ == '__main__':
    unittest.main()
