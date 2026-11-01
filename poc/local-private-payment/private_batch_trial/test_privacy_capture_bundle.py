"""Public receipt-chain controls; no private capture, capsule or truth input."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import privacy_acceptance as gate
import privacy_actual_capture_launch as capture_launcher
import privacy_capture_bundle as producer
import privacy_roles as roles
import privacy_source_closure as source_closure
import test_privacy_acceptance as acceptance_fixture


def raw(value):
    return producer.encoded(value)


class ActualChainFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.public_base = self.root / 'actual-public'
        self.selections = self.root / 'selections'
        self.selections.mkdir(); self.public_base.mkdir()
        self.runs = []
        common = {
            **producer.expected_common_security(),
            # No genuine build/launcher exists.  Digest-shaped placeholders
            # exercise the exact refusal boundary; they are never authority.
            'capture_producer_build_sha256': '12' * 32,
            'capture_producer_launcher_source_sha256': '13' * 32,
        }
        for index, classification in enumerate(producer.CLASSIFICATIONS):
            label = 'actual-base-01' if index == 0 else 'actual-candidate-01'
            operation_path = self.selections / ('operation-' + str(index) + '.json')
            operation_sha = self.write(operation_path, {
                'schema': 'kpb-test-operation-selection/v1', 'index': index})
            binding = {
                'method_sha256': common['method_sha256'],
                'selection_sha256': operation_sha,
                'trial_id': ('11111111-1111-4111-8111-111111111111'
                    if index == 0 else
                    '22222222-2222-4222-8222-222222222222'),
                'phase': 'private-batch-privacy',
                'attempt_id': 'base' if index == 0 else 'candidate',
            }
            bootstrap_path = self.selections / ('bootstrap-' + str(index) + '.json')
            bootstrap_sha = self.write(bootstrap_path, {
                'schema': 'kpb-test-bootstrap/v1', 'index': index})
            diagnostic_path = self.selections / ('diagnostic-' + str(index) + '.json')
            diagnostic_sha = self.write(diagnostic_path, {
                'schema': 'kpb-private-diagnostic-launch-selection/v1',
                'binding': binding,
                'run_selection': {'path': str(operation_path),
                                  'sha256': operation_sha},
                'bootstrap_trial': {'path': str(bootstrap_path),
                                    'sha256': bootstrap_sha},
                'source_members': [], 'rounds': [],
                'corrupt_server_view': None})
            run = {
                'schema': producer.ACTUAL_RUN_SCHEMA,
                'scope': 'FRESH_UNFUNDED_ACTUAL_PRIVATE_BATCH',
                'classification': classification,
                'trial_label': label,
                'binding': binding,
                **common,
                'capture_identity': (
                    '33333333-3333-4333-8333-333333333333'
                    if index == 0 else
                    '44444444-4444-4444-8444-444444444444'),
                'diagnostic_selection': {
                    'path': str(diagnostic_path), 'sha256': diagnostic_sha},
                'public_root': str(self.public_base / label /
                                   'privacy-diagnostics'),
            }
            run_path = self.selections / ('run-' + str(index) + '.json')
            run_sha = self.write(run_path, run)
            self.runs.append({'path': run_path, 'sha256': run_sha,
                              'value': run})
        comparison = {
            'schema': 'kpb-privacy-comparison-selection/v2', **common,
            'runs': [
                {'classification': classification,
                 'path': str(selected['path']),
                 'sha256': selected['sha256']}
                for classification, selected in
                zip(producer.CLASSIFICATIONS, self.runs)
            ],
        }
        self.comparison_path = self.selections / 'comparison.json'
        self.comparison = comparison
        self.comparison_sha = self.write(self.comparison_path, comparison)
        for index in (0, 1):
            self.emit(index)

    @staticmethod
    def write(path, value):
        path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
        data = raw(value); path.write_bytes(data); path.chmod(0o400)
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def rewrite(path, value):
        path = Path(path); path.chmod(0o600); path.write_bytes(raw(value))
        path.chmod(0o400)
        return hashlib.sha256(raw(value)).hexdigest()

    def launch(self, operation, run, result_path, result_sha):
        return {
            'schema': 'kpb-private-diagnostic-launch-result/v1',
            'operation': operation, 'binding': run['binding'],
            'selection_sha256': run['diagnostic_selection']['sha256'],
            'public_result': str(result_path),
            'public_result_sha256': result_sha,
            'persistent_query_consumed': True,
            'private_bodies_read_or_hashed': False,
            'network_enabled': False,
        }

    def emit(self, index):
        candidate = index == 1
        selected = self.runs[index]
        run, run_sha = selected['value'], selected['sha256']
        root = Path(run['public_root'])
        template = acceptance_fixture.bundle(candidate)
        views = copy.deepcopy(template['views'])
        for view in views:
            view['binding'] = copy.deepcopy(run['binding'])
        capture_views = []
        for view in views:
            total = view['coverage']['modeled_artifacts']
            parts = (total // 2, total - total // 2)
            rounds = []
            for number, modeled in zip((1, 2), parts):
                rounds.append({
                    'round': number, 'artifact_count': 30,
                    'artifact_bytes': 4096,
                    'category_coverage': {
                        category: {'modeled_artifacts': 1,
                                   'unmodeled_artifacts': 0,
                                   'missing_artifacts': 0}
                        for category in
                        gate.REQUIRED_CATEGORIES[view['view']]},
                    'modeled_artifacts': modeled,
                    'unmodeled_artifacts': 0, 'missing_artifacts': 0,
                    'terminal_modeled': True,
                })
            capture_views.append({
                'view': view['view'],
                'categories': list(gate.REQUIRED_CATEGORIES[view['view']]),
                'rounds': rounds, 'coverage': view['coverage'],
            })
        capture = {
            'schema': 'kpb-privacy-actual-capture-receipt/v1',
            'comparison_selection_sha256': self.comparison_sha,
            'run_selection_sha256': run_sha,
            'classification': run['classification'],
            'binding': run['binding'],
            'method_sha256': run['method_sha256'],
            'workload_sha256': run['workload_sha256'],
            'observer_source_sha256': run['observer_source_sha256'],
            'capture_source_sha256': run['capture_source_sha256'],
            'coverage_policy_sha256': run['coverage_policy_sha256'],
            'capture_identity': run['capture_identity'],
            'capture_manifest_seal_sha256':
                ('31' if candidate else '30') * 32,
            'construction_classification_receipt_sha256':
                ('2f' if candidate else '2e') * 32,
            'terminal_scope': gate.TERMINAL_SCOPE,
            'views': capture_views, 'capture_roots_closed': True,
            'exact_union_derived': True,
            'predictions_or_truth_mounted': False,
            'private_artifact_paths_hashes_or_bodies_exported': False,
        }
        capture_path = root / 'capture' / 'PUBLIC.json'
        capture_sha = self.write(capture_path, capture)
        observation_views = []
        for view in views:
            observation_views.append({
                'view': view['view'],
                'capsule_seal_sha256': view['capsule_seal_sha256'],
                'capsule_bytes': 1024,
                'rounds': [{'round': 1}, {'round': 2}],
                'coverage': view['coverage'],
                'category_coverage': view['category_coverage'],
                'workload': {name: view['workload'][name] for name in
                    producer.OBSERVATION_WORKLOAD_FIELDS},
                'lattice_attestation': template['lattice_attestation'],
            })
        observation = {
            'schema': 'kpb-direct-observation-receipt/v2',
            'binding': run['binding'],
            'comparison_selection_sha256': self.comparison_sha,
            'run_selection_sha256': run_sha,
            'capture_receipt_sha256': capture_sha,
            'capture_manifest_seal_sha256':
                capture['capture_manifest_seal_sha256'],
            'construction_classification_receipt_sha256':
                capture['construction_classification_receipt_sha256'],
            'terminal_scope': capture['terminal_scope'],
            'views': observation_views,
            'predictions_frozen_before_truth': True,
            'private_view_or_prediction_records_exported': False,
        }
        observation_path = root / 'observe' / 'PUBLIC.json'
        observation_sha = self.write(observation_path, observation)
        barrier = {
            'schema': 'kpb-direct-prediction-barrier/v2',
            'binding': run['binding'],
            'comparison_selection_sha256': self.comparison_sha,
            'run_selection_sha256': run_sha,
            'capture_receipt_sha256': capture_sha,
            'capture_manifest_seal_sha256':
                capture['capture_manifest_seal_sha256'],
            'construction_classification_receipt_sha256':
                capture['construction_classification_receipt_sha256'],
            'terminal_scope': capture['terminal_scope'],
            'observation_receipt_sha256': observation_sha,
            'capsules': [{'view': row['view'],
                          'capsule_seal_sha256':
                            row['capsule_seal_sha256']}
                         for row in observation_views],
        }
        barrier_path = root / 'observe' / 'BARRIER.json'
        barrier_sha = self.write(barrier_path, barrier)
        self.write(root / 'observe' / 'LAUNCH.json',
            self.launch('observe', run, observation_path, observation_sha))
        for owner in (0, 1, 2):
            score_path = root / ('score-owner-' + str(owner)) / 'PUBLIC.json'
            score = {
                'schema': 'kpb-private-score-completed/v2',
                'binding': run['binding'],
                'comparison_selection_sha256': self.comparison_sha,
                'run_selection_sha256': run_sha,
                'barrier_sha256': barrier_sha, 'owner_component': owner,
                'per_owner_counts_or_truth_exported': False,
            }
            score_sha = self.write(score_path, score)
            self.write(score_path.parent / 'LAUNCH.json',
                self.launch('score', run, score_path, score_sha))
        aggregate = {
            'schema': 'kpb-public-all-view-direct-counts/v2',
            'binding': run['binding'],
            'comparison_selection_sha256': self.comparison_sha,
            'run_selection_sha256': run_sha,
            'capture_receipt_sha256': capture_sha,
            'barrier_sha256': barrier_sha,
            'lattice_attestation': template['lattice_attestation'],
            'views': views,
            'private_records_masks_or_per_owner_counts_exported': False,
        }
        aggregate_path = root / 'aggregate' / 'PUBLIC.json'
        aggregate_sha = self.write(aggregate_path, aggregate)
        self.write(root / 'aggregate' / 'LAUNCH.json',
            self.launch('aggregate', run, aggregate_path, aggregate_sha))

    def value(self, path):
        return json.loads(Path(path).read_text())


class CaptureBundleControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = ActualChainFixture(self.temp.name)
        self.patch = patch.object(producer, 'PUBLIC_BASE',
                                  self.fixture.public_base)
        self.patch.start()

    def tearDown(self):
        self.patch.stop(); self.temp.cleanup()

    def produce(self, index):
        return producer.produce(str(self.fixture.comparison_path),
            self.fixture.comparison_sha, index)

    @staticmethod
    def direct_run():
        common = producer.expected_common_security()
        return {
            'classification': producer.CLASSIFICATIONS[1],
            'binding': {
                'method_sha256': common['method_sha256'],
                'selection_sha256': '21' * 32,
                'trial_id': '22222222-2222-4222-8222-222222222222',
                'phase': 'private-batch-privacy', 'attempt_id': 'candidate'},
            'capture_identity': '44444444-4444-4444-8444-444444444444',
            **common,
            '_capture_producer_receipt_sha256': '22' * 32,
        }

    @classmethod
    def direct_capture(cls):
        run = cls.direct_run(); views = []
        for view in gate.VIEWS:
            categories = gate.REQUIRED_CATEGORIES[view]
            rounds = []
            for number in (1, 2):
                rounds.append({
                    'round': number, 'artifact_count': 1,
                    'artifact_bytes': 1,
                    'category_counts': {category: 1
                                        for category in categories},
                    'category_coverage': {category: {
                        'modeled_artifacts': 1, 'unmodeled_artifacts': 0,
                        'missing_artifacts': 0,
                        'constraint_modeled_fields': 1,
                        'source_assumption_covered_fields': 0,
                        'unmodeled_fields': 0} for category in categories},
                    'modeled_artifacts': 1, 'unmodeled_artifacts': 0,
                    'missing_artifacts': 0, 'terminal_modeled': True,
                })
            views.append({
                'view': view, 'categories': list(categories),
                'rounds': rounds,
                'coverage': {'modeled_artifacts': 2,
                             'unmodeled_artifacts': 0,
                             'missing_artifacts': 0,
                             'terminal_modeled': True},
            })
        return run, {
            'schema': 'kpb-privacy-actual-capture-receipt/v2',
            'comparison_selection_sha256': '23' * 32,
            'run_selection_sha256': '24' * 32,
            'classification': run['classification'],
            'binding': run['binding'],
            'method_sha256': run['method_sha256'],
            'workload_sha256': run['workload_sha256'],
            'observer_source_sha256': run['observer_source_sha256'],
            'capture_source_sha256': run['capture_source_sha256'],
            'coverage_policy_sha256': run['coverage_policy_sha256'],
            'capture_identity': run['capture_identity'],
            'capture_manifest_seal_sha256': '25' * 32,
            'construction_classification_receipt_sha256': '26' * 32,
            'terminal_scope': gate.TERMINAL_SCOPE,
            'step3_terminal_gate': gate.STEP3_TERMINAL_GATE,
            'capture_producer_receipt_sha256':
                run['_capture_producer_receipt_sha256'],
            'source_closure_sha256': run['source_closure_sha256'],
            'runtime_identity_sha256': run['runtime_identity_sha256'],
            'views': views, 'capture_roots_closed': True,
            'exact_union_derived': True,
            'predictions_or_truth_mounted': False,
            'private_artifact_paths_hashes_or_bodies_exported': False,
        }

    def test_synthetic_full_chain_cannot_be_promoted_to_actual(self):
        with self.assertRaisesRegex(
                ValueError, 'actual-capture-producer-launch-authority-absent'):
            self.produce(0)

    def test_source_only_receipt_cannot_substitute_for_actual_receipt(self):
        run = {
            'schema': 'kpb-privacy-actual-run-selection/v2',
            'scope': 'FRESH_UNFUNDED_ACTUAL_PRIVATE_BATCH',
            'classification': producer.CLASSIFICATIONS[1],
            'trial_label': 'actual-candidate-01',
            'binding': {
                'method_sha256': producer.expected_common_security()[
                    'method_sha256'], 'selection_sha256': '21' * 32,
                'trial_id': '22222222-2222-4222-8222-222222222222',
                'phase': 'private-batch-privacy', 'attempt_id': 'candidate'},
            **producer.expected_common_security(),
            'capture_producer_build_sha256': '12' * 32,
            'capture_producer_launcher_source_sha256': '13' * 32,
            'capture_identity': '44444444-4444-4444-8444-444444444444',
            'diagnostic_selection': {'path': str(self.fixture.comparison_path),
                                     'sha256': self.fixture.comparison_sha},
            'public_root': str(self.fixture.public_base /
                'actual-candidate-01/privacy-diagnostics'),
            'capture_producer_receipt': {}, 'financial_rounds': [],
        }
        source_only = {
            'schema': 'kpb-capture-producer-source-only/v1',
            'status': 'UNQUALIFIED_SOURCE_ONLY',
            'launch_authorized': False, 'actual_receipt_emitted': False,
        }
        path = Path(run['public_root']) / 'capture-producer/PUBLIC.json'
        digest = self.fixture.write(path, source_only)
        run['capture_producer_receipt'] = {
            'path': str(path), 'sha256': digest}
        with self.assertRaises(ValueError):
            producer.validate_run(run, run['classification'],
                                  producer.expected_common_security())

    def test_capture_v1_relabel_and_terminal_gate_refuse(self):
        run, capture = self.direct_capture()
        producer.validate_capture(capture, '23' * 32, '24' * 32, run)
        for name, value in (
                ('schema', 'kpb-privacy-actual-capture-receipt/v1'),
                ('classification', producer.CLASSIFICATIONS[0]),
                ('step3_terminal_gate', 'NOT_REQUIRED')):
            mutated = copy.deepcopy(capture); mutated[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                producer.validate_capture(
                    mutated, '23' * 32, '24' * 32, run)

    def test_capture_category_counts_reconcile_exactly(self):
        run, capture = self.direct_capture()
        mutated = copy.deepcopy(capture)
        mutated['views'][0]['rounds'][0]['category_counts']['amounts'] = 2
        with self.assertRaisesRegex(ValueError, 'category-count-reconciled'):
            producer.validate_capture(
                mutated, '23' * 32, '24' * 32, run)

    def test_public_selection_must_be_mode_0400(self):
        self.fixture.comparison_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'owned-single-link-public-leaf'):
            producer.load_comparison(
                str(self.fixture.comparison_path), self.fixture.comparison_sha)

    def test_frozen_bundle_source_pin_is_required(self):
        comparison = copy.deepcopy(self.fixture.comparison)
        comparison['bundle_producer_source_sha256'] = 'ff' * 32
        digest = self.fixture.rewrite(self.fixture.comparison_path, comparison)
        with self.assertRaises(ValueError):
            producer.load_comparison(str(self.fixture.comparison_path), digest)

    def test_capture_producer_closure_includes_every_selected_hook_source(self):
        manifest = source_closure.manifest('capture-producer')
        self.assertEqual([row['name'] for row in manifest['members']], [
            'privacy_capture_producer.py',
            'privacy_capture_hook.hpp',
            'privacy_capture_hook.cpp',
            'privacy_capture_private_hook.hpp',
            'privacy_capture_private_hook.cpp',
            'privacy_source_closure.py',
        ])
        # There is no actual selected build receipt yet.  Source closure is
        # not allowed to manufacture one from source bytes.
        self.assertNotIn('capture_producer_build_sha256',
                         producer.expected_common_security())

    def test_ast_import_closure_refuses_undeclared_local_dependency(self):
        actual = source_closure.ROLE_MEMBERS['actual-capture']
        self.assertIn('wallet_profile.py', actual)
        dynamic = '../../future-recipient/v2/recipient.py'
        self.assertIn(dynamic,
                      source_closure._local_imports('wallet_profile.py'))
        self.assertIn('../verification/wire.py',
                      source_closure._local_imports('exit_wire.py'))
        with patch.dict(source_closure.ROLE_MEMBERS, {
                'actual-capture': tuple(
                    name for name in actual
                    if name != 'wallet_profile.py')}):
            self.assertEqual(source_closure.transitive_missing(
                'actual-capture'), ('wallet_profile.py',))
            with self.assertRaisesRegex(
                    ValueError,
                    'incomplete-actual-capture-closure'):
                source_closure.manifest('actual-capture')
        with patch.dict(source_closure.ROLE_MEMBERS, {
                'actual-capture': tuple(
                    name for name in actual if name != dynamic)}):
            self.assertIn(dynamic, source_closure.transitive_missing(
                'actual-capture'))

    def test_observer_namespace_validates_only_its_mounted_role(self):
        runtime = source_closure.runtime_identity()
        config = {
            'source_members': [{
                'name': row['name'],
                'path': str((source_closure.NAMESPACE_SOURCE_ROOT /
                             row['name']).resolve()),
                'sha256': row['sha256'],
            } for row in source_closure.manifest('observer')['members']],
            'source_closure_sha256': source_closure.all_digests(),
            'runtime_identity_sha256': source_closure.runtime_digest(),
            'python_runtime_sha256': runtime['python_runtime_sha256'],
            'namespace_tool_sha256': runtime['namespace_tool_sha256'],
            'root_guard_helper_sha256':
                runtime['root_guard_helper_sha256'],
            'host_runtime_trust_boundary':
                runtime['host_runtime_trust_boundary'],
            'step3_terminal_gate':
                'REQUIRED_SEPARATE_EXIT_LINKABILITY_GATE_BEFORE_STEP3',
        }
        with patch.object(source_closure, 'all_digests',
                          side_effect=AssertionError('global closure read')), \
                patch.object(source_closure, 'runtime_digest',
                             side_effect=AssertionError('host runtime read')):
            roles.validate_v2_worker_identity(
                config, source_closure.ROOT_GUARD)

    def test_capture_launch_schema_is_exact_v2_without_legacy_fallback(self):
        self.assertEqual(producer.COMPARISON_SCHEMA,
                         capture_launcher.COMPARISON_SCHEMA)
        self.assertEqual(producer.COMPARISON_SCHEMA,
                         'kpb-privacy-comparison-selection/v2')
        self.assertNotEqual(producer.COMPARISON_SCHEMA,
                            'kpb-privacy-comparison-selection/v1')
        self.assertEqual(producer.DIAGNOSTIC_SCHEMA,
                         capture_launcher.DIAGNOSTIC_SCHEMA)
        self.assertEqual(producer.DIAGNOSTIC_SCHEMA,
                         'kpb-private-diagnostic-launch-selection/v2')
        self.assertNotEqual(producer.DIAGNOSTIC_SCHEMA,
                            'kpb-private-diagnostic-launch-selection/v1')
        self.assertEqual(producer.ACTUAL_RUN_SCHEMA,
                         capture_launcher.RUN_SCHEMA)
        self.assertEqual(producer.ACTUAL_RUN_SCHEMA,
                         'kpb-privacy-actual-run-selection/v2')
        self.assertNotEqual(producer.ACTUAL_RUN_SCHEMA,
                            'kpb-privacy-actual-run-selection/v1')
        self.assertEqual(producer.CAPTURE_LAUNCH_SCHEMA,
                         capture_launcher.LAUNCH_SCHEMA)
        self.assertEqual(producer.CAPTURE_LAUNCH_SCHEMA,
                         'kpb-actual-capture-launch/v2')
        self.assertNotEqual(producer.CAPTURE_LAUNCH_SCHEMA,
                            'kpb-actual-capture-launch/v1')

    def test_bundle_cannot_accept_self_authored_v2_capture_launch(self):
        with self.assertRaisesRegex(
                ValueError, 'privacy-actual-capture-launch-launch-fields'):
            producer.validate_capture_launch(
                {}, '11' * 32, '12' * 32, {}, Path('/unused'),
                '13' * 32, {}, '14' * 32)

    def test_bundle_cannot_accept_self_authored_worker_launches(self):
        for operation in ('observe', 'score', 'aggregate'):
            with self.subTest(operation=operation), \
                    self.assertRaises(ValueError):
                producer.validate_launch(
                    {}, operation, {}, Path('/unused'), '11' * 32)

if __name__ == '__main__':
    unittest.main()
