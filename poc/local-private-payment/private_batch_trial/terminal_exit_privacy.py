#!/usr/bin/env python3
"""Frozen terminal Exit-privacy capture model and source-only acceptance.

This contract is deliberately independent from the private-batch privacy gate.
It models the nine clear-value independent exits, ordered financial-service
loss, and the terminal cold scans under the full union observer.  Private owner
truth is consumed only by ``compare_private`` and is never returned.

The module does not capture a real run and cannot authorize a rehearsal.  Its
``source_only_acceptance`` result stays false until a separate actual isolated
capture/private-score producer is implemented and executed.
"""
import ast
import hashlib
import itertools
import json
from functools import lru_cache
from pathlib import Path
import re
import stat
import uuid

import new_private_trial as bootstrap
import private_lifecycle


HERE = Path(__file__).resolve().parent
FREEZE_SCHEMA = 'kpb-terminal-exit-privacy-freeze/v1'
BUNDLE_SCHEMA = 'kpb-terminal-exit-union-capture/v1'
TRUTH_SCHEMA = 'kpb-terminal-exit-private-truth/v1'
SCORE_SCHEMA = 'kpb-terminal-exit-private-comparison/v1'
ACCEPTANCE_SCHEMA = 'kpb-terminal-exit-source-only-acceptance/v1'
MODEL_PASS_STATUS = 'PASS_SOURCE_ONLY_TERMINAL_EXIT_MODEL'
MODEL_FAIL_STATUS = 'FAIL_SOURCE_ONLY_TERMINAL_EXIT_MODEL'
CLASSIFICATIONS = (
    'ACTUAL_TRANSPARENT_TERMINAL_EXIT_BASELINE',
    'ACTUAL_HIDDEN_TERMINAL_EXIT_CANDIDATE',
)
RUNTIME_ROLES = (
    'native-node', 'native-crypto', 'auth-exit-prover', 'component-profile',
    'output-parameters-manifest', 'exit-parameters-manifest',
)
COVERAGE_CATEGORIES = (
    'clear-payout-amounts', 'fresh-payout-scripts',
    'transaction-identities', 'native-order', 'monotonic-timing',
    'owner-origin-routes', 'contact-side-information', 'cohort-membership',
    'retry-history', 'rejection-history', 'orphan-history', 'reorg-history',
    'ordered-service-loss', 'cold-scan-observations',
    'invoice-side-information', 'union-observer-candidate-graph',
)
FROZEN_THRESHOLDS = {
    'exit_count': 9,
    'owner_count': 3,
    'exits_per_owner': 3,
    'honest_owner_count': 2,
    'min_candidate_joint_assignments': 2,
    'min_honest_owner_exit_sets': 2,
    'min_honest_exit_eligible_owners': 2,
    'require_all_honest_nonregression': True,
    'require_all_honest_strict_gain': True,
}
SIDE_CATEGORIES = frozenset({
    'transparent-owner-label', 'payout-amount', 'payout-script',
    'invoice-script', 'native-order', 'timing-bucket', 'origin-route',
    'contact', 'cohort', 'retry-route', 'rejection-route', 'orphan-route',
    'reorg-route', 'colluder-receipt',
    'transaction-id',
    'attempt-route', 'attempt-timing-bucket', 'attempt-contact',
    'attempt-cohort', 'attempt-transaction-id',
})
JOINT_CATEGORIES = (
    'payout-amount-intersection', 'transaction-id-intersection',
    'timing-intersection', 'contact-intersection', 'cohort-intersection',
    'retry-intersection',
)
ASSIGNMENT_CATEGORIES = JOINT_CATEGORIES + ('amount-sum-intersection',)
ATTEMPT_KINDS = frozenset({'accepted', 'retry', 'rejected', 'orphaned', 'reorged'})


def need(value, category):
    if not value:
        raise ValueError('terminal-exit-privacy-' + category)


def fields(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='canonical-sha256'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         category)
    return value


def natural(value, category):
    need(type(value) is int and value >= 0, category)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError('terminal-exit-privacy-nonfinite-json')))
    need(encoded(value) == raw, 'canonical-json')
    return value


def sha(value):
    return hashlib.sha256(value if type(value) is bytes else encoded(value)).hexdigest()


def record(value):
    fields(value, ('path', 'sha256', 'bytes'), 'exact-record')
    path = Path(value['path'])
    need(path.is_absolute() and '..' not in path.parts, 'absolute-record')
    word(value['sha256'])
    natural(value['bytes'], 'record-bytes')
    return value


def _read_record(read, value):
    value = record(value)
    raw = read(Path(value['path']), value['sha256'])
    need(type(raw) is bytes and len(raw) == value['bytes'], 'record-byte-count')
    return raw


def _source_paths():
    local = (
        'terminal_exit_privacy.py', 'terminal_exit_privacy_acceptance.py',
        'private_lifecycle.py', 'component_run.py',
        'lifecycle_worker.py', 'c1_capture_supervisor.py',
        'wallet_history.py', 'private_worker.py',
        'wallet_profile.py', 'output_producer.py', 'output_verifier.py',
        'exit_wire.py', 'exit_release.py', 'fresh_self_payout.py',
        'new_private_trial.py', 'owner_authority.mjs',
        'genesis.py', 'funding.py', 'owner_record.py',
        'privacy_codec.py', 'privacy_owner.py',
    )
    paths = [HERE / name for name in local]
    paths += [
        HERE.parent / 'private_batch/intent.py',
        HERE.parent / 'private_batch/__init__.py',
        HERE.parent / 'integration/trees.py',
        HERE.parent / 'verification/wire.py',
        HERE.parents[1] / 'future-recipient/v2/recipient.py',
        HERE.parent / 'bootstrap/gn3_runtime.py',
        HERE.parent / 'bootstrap/gn3_common.py',
        HERE.parent / 'bootstrap/gn3_selection.py',
        HERE.parent / 'bootstrap/sdk.mjs',
    ]
    return tuple(path.resolve() for path in paths)


def _local_python_imports(paths):
    """Return every repo-local Python import reachable from ``paths``."""
    search = (HERE, HERE.parent, HERE.parents[1],
              HERE.parents[1] / 'future-recipient/v2')
    queued = [path for path in paths if path.suffix == '.py']
    found = set(queued)
    while queued:
        source = queued.pop()
        tree = ast.parse(source.read_text(), filename=str(source))
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
                modules.extend(node.module + '.' + alias.name
                               for alias in node.names if alias.name != '*')
        for module in modules:
            parts = module.split('.')
            candidates = []
            for root in search:
                candidates.extend((root.joinpath(*parts).with_suffix('.py'),
                                   root.joinpath(*parts, '__init__.py')))
            target = next((path.resolve() for path in candidates
                           if path.is_file()), None)
            if target is not None and target not in found:
                found.add(target)
                queued.append(target)
    return found


def current_source_closure():
    paths = _source_paths()
    local_imports = _local_python_imports(paths)
    need(local_imports <= set(paths), 'incomplete-transitive-source-closure')
    rows = []
    root = HERE.parents[2]
    for path in paths:
        raw = path.read_bytes()
        rows.append({
            'role': path.relative_to(root).as_posix(),
            'path': str(path),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw),
        })
    return rows


def current_model_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def current_runtime_closure():
    rows = (
        ('native-node', bootstrap.NODE, bootstrap.wallet.NODE_SHA256),
        ('native-crypto', bootstrap.CRYPTO, bootstrap.wallet.CRYPTO_SHA256),
        ('auth-exit-prover', bootstrap.BINARY, bootstrap.BINARY_SHA),
        ('component-profile', bootstrap.PROFILE, bootstrap.PROFILE_SHA),
        ('output-parameters-manifest', bootstrap.PARAMETERS / 'MANIFEST.json',
         bootstrap.MANIFEST_SHA),
        ('exit-parameters-manifest',
         private_lifecycle.EXIT_PARAMETERS / 'MANIFEST.json',
         private_lifecycle.EXIT_MANIFEST_SHA),
    )
    return [{'role': role, 'path': str(Path(path).resolve()), 'sha256': pin,
             'bytes': Path(path).stat().st_size} for role, path, pin in rows]


@lru_cache(maxsize=None)
def _runtime_file_sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _verify_current_runtime(rows):
    expected = current_runtime_closure()
    need(rows == expected, 'runtime-closure-not-caller-selected')
    for row in expected:
        need(_runtime_file_sha(row['path']) == row['sha256'],
             'runtime-current-file-sha256')


def closure_sha(value):
    return sha(value)


def evidence_sha(value):
    return sha(value)


def _reopen_named_closure(read, rows, roles, category):
    need(type(rows) is list and [row.get('role') for row in rows] == list(roles),
         category + '-roles')
    paths = []
    for row in rows:
        fields(row, ('role', 'path', 'sha256', 'bytes'), category + '-record')
        _read_record(read, {key: row[key] for key in ('path', 'sha256', 'bytes')})
        paths.append(row['path'])
    need(len(paths) == len(set(paths)), category + '-distinct-paths')


def _operation_plan(value, category, selection, read):
    fields(value, ('operation_id', 'output_root', 'root_marker'),
           category + '-fields')
    path = Path(value['output_root'])
    need(type(value['operation_id']) is str
         and re.fullmatch('[A-Za-z0-9_-]{1,128}', value['operation_id'])
         and path.is_absolute() and '..' not in path.parts,
         category)
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
         category + '-source-owned-root-mode')
    marker_path = path / '.terminal-exit-pre-result-root.json'
    need(value['root_marker']['path'] == str(marker_path),
         category + '-root-marker-path')
    marker = parse(_read_record(read, value['root_marker']))
    fields(marker, ('schema', 'trial_id', 'freeze_nonce_hex32', 'operation_id',
        'output_root', 'created_monotonic_ns', 'state', 'result_record_count'),
        category + '-root-marker-fields')
    need(marker == {
        'schema': 'kpb-terminal-exit-source-owned-root/v1',
        'trial_id': selection['trial_id'],
        'freeze_nonce_hex32': selection['freeze_nonce_hex32'],
        'operation_id': value['operation_id'], 'output_root': str(path),
        'created_monotonic_ns': marker['created_monotonic_ns'],
        'state': 'EMPTY_PRE_RESULT', 'result_record_count': 0,
    } and type(marker['created_monotonic_ns']) is int
      and 0 <= marker['created_monotonic_ns'] < selection['freeze_monotonic_ns'],
      category + '-durable-pre-result-root-marker')
    return marker


def _reopen_preexecution_evidence(read, selection):
    registered = selection['registered_evidence']
    need(type(registered) is list and len(registered) == 2,
         'two-registered-rounds')
    for expected_round, row in enumerate(registered, 1):
        fields(row, ('round', 'driver_selection', 'driver_result',
                     'public_artifacts'), 'registered-evidence-fields')
        need(type(row['round']) is int and row['round'] == expected_round,
             'registered-round-order')
        artifacts = parse(_read_record(read, row['public_artifacts']))
        fields(artifacts, ('schema', 'trial_id', 'round',
            'accepted_head_sha256', 'owner_contract_set_sha256',
            'public_projection_sha256', 'source_closure_sha256',
            'runtime_closure_sha256'), 'registered-artifacts-body-fields')
        for name in ('accepted_head_sha256', 'owner_contract_set_sha256',
                     'public_projection_sha256'):
            word(artifacts[name], 'registered-artifacts-' + name)
        need(artifacts['schema'] ==
                'kpb-terminal-registered-public-artifacts/v1'
             and artifacts['trial_id'] == selection['trial_id']
             and artifacts['round'] == expected_round
             and artifacts['source_closure_sha256'] ==
                 closure_sha(selection['source_closure'])
             and artifacts['runtime_closure_sha256'] ==
                 closure_sha(selection['runtime_closure']),
             'semantic-registered-artifacts')
        selected = parse(_read_record(read, row['driver_selection']))
        fields(selected, ('schema', 'trial_id', 'round',
            'public_artifacts_sha256', 'source_closure_sha256',
            'runtime_closure_sha256', 'selected_and_configured',
            'network_or_funding'), 'registered-selection-body-fields')
        need(selected == {
            'schema': 'kpb-terminal-registered-round-selection/v1',
            'trial_id': selection['trial_id'], 'round': expected_round,
            'public_artifacts_sha256': row['public_artifacts']['sha256'],
            'source_closure_sha256': closure_sha(selection['source_closure']),
            'runtime_closure_sha256': closure_sha(selection['runtime_closure']),
            'selected_and_configured': True, 'network_or_funding': False,
        }, 'semantic-registered-selection')
        result = parse(_read_record(read, row['driver_result']))
        fields(result, ('schema', 'trial_id', 'round',
            'driver_selection_sha256', 'public_artifacts_sha256',
            'accepted_head_sha256', 'owner_contract_set_sha256',
            'all_three_party_agreement', 'durable_egress',
            'executed_registered_driver', 'network_or_funding'),
            'registered-result-body-fields')
        need(result == {
            'schema': 'kpb-terminal-registered-round-result/v1',
            'trial_id': selection['trial_id'], 'round': expected_round,
            'driver_selection_sha256': row['driver_selection']['sha256'],
            'public_artifacts_sha256': row['public_artifacts']['sha256'],
            'accepted_head_sha256': artifacts['accepted_head_sha256'],
            'owner_contract_set_sha256': artifacts['owner_contract_set_sha256'],
            'all_three_party_agreement': True, 'durable_egress': True,
            'executed_registered_driver': True, 'network_or_funding': False,
        }, 'semantic-registered-result')

    plan = selection['terminal_plan']
    fields(plan, ('pre_result_barrier', 'terminal_roots_sha256',
                  'service_loss', 'exits', 'cold_scan'), 'terminal-plan-fields')
    root_markers = []
    root_markers.append(_operation_plan(plan['service_loss'],
        'service-loss-plan', selection, read))
    root_markers.append(_operation_plan(plan['cold_scan'],
        'cold-scan-plan', selection, read))
    lifecycle = plan['exits']
    need(type(lifecycle) is list and len(lifecycle) == 9, 'nine-exit-plans')
    for ordinal, row in enumerate(lifecycle):
        fields(row, ('ordinal', 'operation_id', 'output_root',
                    'root_marker', 'owner_receipt_seal_sha256'),
               'exit-plan-fields')
        need(type(row['ordinal']) is int and row['ordinal'] == ordinal,
             'exit-plan-order')
        word(row['owner_receipt_seal_sha256'], 'owner-receipt-seal')
        root_markers.append(_operation_plan({key: row[key] for key in
            ('operation_id', 'output_root', 'root_marker')},
            'exit-plan-operation', selection, read))
    roots = [plan['service_loss']['output_root'], plan['cold_scan']['output_root']]
    roots += [row['output_root'] for row in lifecycle]
    capture_plans = []
    for name in ('baseline', 'candidate'):
        capture_plan = {key: selection[name][key] for key in
                        ('operation_id', 'output_root', 'root_marker')}
        capture_plans.append(capture_plan)
        root_markers.append(_operation_plan(capture_plan,
            name + '-capture-plan', selection, read))
        roots.append(capture_plan['output_root'])
    need(len(roots) == len(set(roots)), 'distinct-terminal-output-roots')
    all_plans = [plan['service_loss'], *plan['exits'], plan['cold_scan'],
                 *capture_plans]
    need(plan['terminal_roots_sha256'] == sha(all_plans),
         'terminal-root-plan-seal')
    barrier = parse(_read_record(read, plan['pre_result_barrier']))
    fields(barrier, ('schema', 'trial_id', 'freeze_nonce_hex32',
        'method_sha256', 'workload_sha256', 'source_closure_sha256',
        'runtime_closure_sha256', 'terminal_roots_sha256',
        'created_monotonic_ns', 'state', 'result_record_count'),
        'pre-result-barrier-fields')
    need(barrier == {
        'schema': 'kpb-terminal-exit-pre-result-barrier/v1',
        'trial_id': selection['trial_id'],
        'freeze_nonce_hex32': selection['freeze_nonce_hex32'],
        'method_sha256': selection['method_sha256'],
        'workload_sha256': selection['workload_sha256'],
        'source_closure_sha256': closure_sha(selection['source_closure']),
        'runtime_closure_sha256': closure_sha(selection['runtime_closure']),
        'terminal_roots_sha256': plan['terminal_roots_sha256'],
        'created_monotonic_ns': barrier['created_monotonic_ns'],
        'state': 'FROZEN_BEFORE_RESULTS', 'result_record_count': 0,
    } and type(barrier['created_monotonic_ns']) is int
      and max(row['created_monotonic_ns'] for row in root_markers)
          < barrier['created_monotonic_ns'] < selection['freeze_monotonic_ns'],
      'durable-one-shot-pre-result-barrier')


def validate_freeze(value, read):
    fields(value, ('schema', 'phase', 'status', 'trial_id',
        'freeze_nonce_hex32', 'freeze_monotonic_ns', 'method_sha256',
        'workload_sha256', 'observer_model_sha256', 'coverage_policy_sha256',
        'colluding_owner_component', 'source_closure', 'runtime_closure',
        'registered_evidence', 'terminal_plan', 'baseline', 'candidate', 'thresholds',
        'coverage_categories', 'execution_started',
        'private_truth_or_bodies_exported', 'rehearsal_authorized'),
        'freeze-fields')
    fields(value['thresholds'], FROZEN_THRESHOLDS, 'threshold-fields')
    for name in ('exit_count', 'owner_count', 'exits_per_owner',
                 'honest_owner_count', 'min_candidate_joint_assignments',
                 'min_honest_owner_exit_sets',
                 'min_honest_exit_eligible_owners'):
        need(type(value['thresholds'][name]) is int
             and value['thresholds'][name] == FROZEN_THRESHOLDS[name],
             'threshold-' + name)
    for name in ('require_all_honest_nonregression',
                 'require_all_honest_strict_gain'):
        need(type(value['thresholds'][name]) is bool
             and value['thresholds'][name] is FROZEN_THRESHOLDS[name],
             'threshold-' + name)
    need(value['schema'] == FREEZE_SCHEMA
         and value['phase'] == 'terminal-exit-privacy'
         and value['status'] == 'FROZEN_UNEXECUTED'
         and str(uuid.UUID(value['trial_id'])) == value['trial_id']
         and type(value['freeze_monotonic_ns']) is int
         and value['freeze_monotonic_ns'] >= 0
         and type(value['colluding_owner_component']) is int
         and value['colluding_owner_component'] in (0, 1, 2)
         and value['coverage_categories'] == list(COVERAGE_CATEGORIES)
         and value['execution_started'] is False
         and value['private_truth_or_bodies_exported'] is False
         and value['rehearsal_authorized'] is False,
         'frozen-unexecuted-selection')
    for name in ('freeze_nonce_hex32', 'method_sha256', 'workload_sha256',
                 'observer_model_sha256', 'coverage_policy_sha256'):
        word(value[name], 'freeze-' + name)
    need(value['observer_model_sha256'] == current_model_sha256(),
         'current-observer-model')
    expected_sources = current_source_closure()
    need(value['source_closure'] == expected_sources,
         'source-closure-not-self-authored')
    _reopen_named_closure(read, value['source_closure'],
        tuple(row['role'] for row in expected_sources), 'source-closure')
    _verify_current_runtime(value['runtime_closure'])
    for arm, classification, transparent in (
            (value['baseline'], CLASSIFICATIONS[0], True),
            (value['candidate'], CLASSIFICATIONS[1], False)):
        fields(arm, ('classification', 'operation_id', 'capture_identity',
                    'attempt_id', 'output_root', 'root_marker',
                    'transparent_owner_labels'), 'freeze-arm-fields')
        output_root = Path(arm['output_root'])
        need(arm['classification'] == classification
             and str(uuid.UUID(arm['capture_identity'])) == arm['capture_identity']
             and type(arm['attempt_id']) is str
             and re.fullmatch('[A-Za-z0-9_-]{1,128}', arm['attempt_id'])
             and type(arm['operation_id']) is str
             and re.fullmatch('[A-Za-z0-9_-]{1,128}', arm['operation_id'])
             and output_root.is_absolute() and '..' not in output_root.parts
             and arm['transparent_owner_labels'] is transparent,
             'frozen-baseline-candidate-arm')
    need(value['baseline']['capture_identity'] != value['candidate']['capture_identity']
         and value['baseline']['attempt_id'] != value['candidate']['attempt_id'],
         'distinct-arm-identities')
    _reopen_preexecution_evidence(read, value)
    return value


EXIT_FIELDS = (
    'ordinal', 'exit_id', 'input_history', 'case', 'lifecycle_selection',
    'lifecycle_result', 'released_candidate', 'release_selection', 'release_receipt',
    'transaction_id_hex32',
    'payout_script_hex37', 'amount_sompi', 'native_order',
    'observed_monotonic_ns', 'origin_route_id', 'contact_id', 'cohort_id',
)
ATTEMPT_FIELDS = (
    'sequence', 'exit_id', 'kind', 'monotonic_ns', 'route_id', 'contact_id',
    'cohort_id', 'transaction_id_hex32',
)
SERVICE_FIELDS = (
    'sequence', 'stage', 'monotonic_ns', 'active_processes',
    'active_listeners', 'private_service_state_mounted',
    'owner_exit_service_dependency',
)
SCAN_FIELDS = (
    'scan_slot', 'monotonic_ns', 'status', 'terminal_reserve_sompi',
    'payout_script_or_exit_id_exported',
)
BUNDLE_FIELDS = (
    'schema', 'classification', 'selection_sha256', 'trial_id',
    'capture_identity', 'attempt_id', 'capture_started_monotonic_ns',
    'capture_completed_monotonic_ns', 'source_closure_sha256',
    'runtime_closure_sha256', 'registered_evidence_sha256',
    'lifecycle_evidence_sha256', 'capture_authority',
    'consumed_pre_result_barrier',
    'service_loss_barrier', 'cold_scan', 'exits',
    'attempts', 'service_observations', 'cold_scan_observations',
    'side_information', 'coverage_categories', 'capture_complete',
    'truth_or_private_bodies_exported',
)


def _arm(selection, classification):
    if classification == CLASSIFICATIONS[0]:
        return selection['baseline']
    if classification == CLASSIFICATIONS[1]:
        return selection['candidate']
    need(False, 'classification')


def _planned_record(read, value, root, category):
    value = record(value)
    path = Path(value['path']).resolve()
    planned = Path(root).resolve()
    need(path.is_relative_to(planned), category + '-outside-planned-root')
    _read_record(read, value)
    return value


def _planned_json(read, value, root, category):
    value = record(value)
    path = Path(value['path']).resolve()
    planned = Path(root).resolve()
    need(path.is_relative_to(planned), category + '-outside-planned-root')
    return parse(_read_record(read, value))


def _exit_tokens(exit_row, attempts):
    result = {
        ('transparent-owner-label', exit_row['exit_id']),
        ('payout-amount', str(exit_row['amount_sompi'])),
        ('payout-script', exit_row['payout_script_hex37']),
        ('invoice-script', exit_row['payout_script_hex37']),
        ('native-order', str(exit_row['native_order'])),
        ('timing-bucket', str(exit_row['observed_monotonic_ns'] // 1_000_000_000)),
        ('origin-route', exit_row['origin_route_id']),
        ('contact', exit_row['contact_id']),
        ('cohort', exit_row['cohort_id']),
        ('colluder-receipt', exit_row['exit_id']),
        ('transaction-id', exit_row['transaction_id_hex32']),
    }
    category = {
        'retry': 'retry-route', 'rejected': 'rejection-route',
        'orphaned': 'orphan-route', 'reorged': 'reorg-route',
    }
    for attempt in attempts:
        if attempt['exit_id'] != exit_row['exit_id']:
            continue
        prefix = attempt['kind'] + ':'
        result.update({
            ('attempt-route', prefix + attempt['route_id']),
            ('attempt-timing-bucket', prefix + str(
                attempt['monotonic_ns'] // 1_000_000_000)),
            ('attempt-contact', prefix + attempt['contact_id']),
            ('attempt-cohort', prefix + attempt['cohort_id']),
            ('attempt-transaction-id', prefix +
             attempt['transaction_id_hex32']),
        })
        if attempt['kind'] in category:
            result.add((category[attempt['kind']], attempt['route_id']))
    return result


def mapping_evidence_sha(classification, category, value, owners,
                         source_receipts):
    return sha({'schema': 'kpb-terminal-exit-mapping-evidence/v1',
                'classification': classification, 'category': category,
                'value': value, 'owner_components': owners,
                'source_receipt_sha256': sorted(source_receipts),
                'source_only': True})


def joint_evidence_sha(classification, left_exit_id, right_exit_id,
                       categories, allowed_owner_pairs, source_receipts):
    return sha({'schema': 'kpb-terminal-exit-joint-evidence/v1',
                'classification': classification,
                'left_exit_id': left_exit_id,
                'right_exit_id': right_exit_id,
                'categories': categories,
                'allowed_owner_pairs': allowed_owner_pairs,
                'source_receipt_sha256': sorted(source_receipts),
                'source_only': True})


def assignment_evidence_sha(classification, owners, source_receipts):
    return sha({'schema': 'kpb-terminal-exit-assignment-evidence/v1',
                'classification': classification,
                'categories': list(ASSIGNMENT_CATEGORIES),
                'owners': owners,
                'source_receipt_sha256': sorted(source_receipts),
                'source_only': True})


def _side_information(value, classification, exits, attempts,
                      colluding_owner_component):
    fields(value, ('schema', 'mappings', 'joint_constraints',
        'assignment_constraints',
        'prior_payout_scripts_hex37', 'prior_transaction_ids_hex32',
        'invoice_record_count', 'contact_record_count',
        'private_truth_or_bodies_exported'), 'side-information-fields')
    need(value['schema'] == 'kpb-terminal-exit-union-side-information/v1'
         and type(value['mappings']) is list
         and type(value['joint_constraints']) is list
         and type(value['assignment_constraints']) is list
         and type(value['prior_payout_scripts_hex37']) is list
         and type(value['prior_transaction_ids_hex32']) is list
         and type(value['invoice_record_count']) is int
         and value['invoice_record_count'] >= 0
         and type(value['contact_record_count']) is int
         and value['contact_record_count'] >= 0
         and value['private_truth_or_bodies_exported'] is False,
         'side-information-public-boundary')
    token_sources = {}
    for exit_row in exits:
        for token in _exit_tokens(exit_row, attempts):
            token_sources.setdefault(token, set()).add(
                exit_row['release_receipt']['sha256'])
    mappings = {}
    categories = set()
    for row in value['mappings']:
        fields(row, ('category', 'value', 'owner_components', 'evidence_sha256'),
               'side-mapping-fields')
        need(row['category'] in SIDE_CATEGORIES
             and type(row['value']) is str and row['value']
             and type(row['owner_components']) is list
             and row['owner_components'] == sorted(set(row['owner_components']))
             and row['owner_components']
             and all(type(owner) is int and owner in (0, 1, 2)
                     for owner in row['owner_components']),
             'typed-side-mapping')
        word(row['evidence_sha256'], 'side-mapping-evidence')
        key = (row['category'], row['value'])
        need(key not in mappings, 'distinct-side-mapping')
        need(key in token_sources
             and row['evidence_sha256'] == mapping_evidence_sha(
                 classification, row['category'], row['value'],
                 row['owner_components'], token_sources[key]),
             'side-mapping-evidence-binding')
        mappings[key] = set(row['owner_components'])
        categories.add(row['category'])
    required = {'payout-amount', 'invoice-script', 'native-order',
                'timing-bucket', 'origin-route', 'contact', 'cohort',
                'transaction-id', 'attempt-route',
                'attempt-timing-bucket', 'attempt-contact',
                'attempt-cohort', 'attempt-transaction-id'}
    need(required <= categories and value['invoice_record_count'] == 9
         and value['contact_record_count'] == 9,
         'invoice-contact-side-information-coverage')
    transparent = [key for key in mappings if key[0] == 'transparent-owner-label']
    colluder = [key for key in mappings if key[0] == 'colluder-receipt']
    if classification == CLASSIFICATIONS[0]:
        need(len(transparent) == 9 and not colluder,
             'transparent-baseline-owner-labels')
    else:
        need(not transparent and len(colluder) == 3
             and all(mappings[key] == {colluding_owner_component}
                     for key in colluder),
             'candidate-no-transparent-labels-and-one-colluder')

    prior = value['prior_payout_scripts_hex37']
    need(len(prior) == len(set(prior))
         and all(type(script) is str
                 and re.fullmatch('[0-9a-f]{74}', script) is not None
                 for script in prior), 'prior-payout-scripts')
    scripts = {row['payout_script_hex37'] for row in exits}
    need(not scripts.intersection(prior), 'fresh-distinct-payout-scripts')
    prior_txids = value['prior_transaction_ids_hex32']
    need(len(prior_txids) == len(set(prior_txids))
         and all(type(txid) is str
                 and re.fullmatch('[0-9a-f]{64}', txid) is not None
                 for txid in prior_txids), 'prior-transaction-identities')
    txids = {row['transaction_id_hex32'] for row in exits}
    need(not txids.intersection(prior_txids), 'fresh-transaction-identities')

    pairs = [(left, right) for left in range(9) for right in range(left + 1, 9)]
    exits_by_id = {row['exit_id']: row for row in exits}
    need(len(exits_by_id) == 9, 'distinct-joint-exit-identities')
    constraints = {}
    allowed_pairs = {(left, right) for left in range(3) for right in range(3)}
    for row in value['joint_constraints']:
        fields(row, ('left_exit_id', 'right_exit_id', 'categories',
                    'allowed_owner_pairs', 'evidence_sha256'),
               'joint-constraint-fields')
        need(row['categories'] == list(JOINT_CATEGORIES)
             and type(row['allowed_owner_pairs']) is list,
             'joint-constraint-categories')
        word(row['evidence_sha256'], 'joint-constraint-evidence')
        pair = (row['left_exit_id'], row['right_exit_id'])
        need(pair not in constraints and pair[0] in exits_by_id
             and pair[1] in exits_by_id, 'distinct-joint-constraint')
        parsed = set()
        for owners in row['allowed_owner_pairs']:
            need(type(owners) is list and len(owners) == 2
                 and all(type(owner) is int and owner in (0, 1, 2)
                         for owner in owners), 'joint-owner-pair')
            parsed.add(tuple(owners))
        need(parsed and parsed <= allowed_pairs, 'joint-owner-pair-set')
        need(row['evidence_sha256'] == joint_evidence_sha(
            classification, row['left_exit_id'], row['right_exit_id'],
            row['categories'], row['allowed_owner_pairs'],
            (exits_by_id[row['left_exit_id']]['release_receipt']['sha256'],
             exits_by_id[row['right_exit_id']]['release_receipt']['sha256'])),
            'joint-constraint-evidence-binding')
        constraints[pair] = parsed
    expected_pairs = {(exits[left]['exit_id'], exits[right]['exit_id'])
                      for left, right in pairs}
    need(set(constraints) == expected_pairs, 'complete-cross-exit-constraints')

    assignment_constraints = set()
    source_receipts = [row['release_receipt']['sha256'] for row in exits]
    for row in value['assignment_constraints']:
        fields(row, ('categories', 'owners', 'evidence_sha256'),
               'assignment-constraint-fields')
        need(row['categories'] == list(ASSIGNMENT_CATEGORIES)
             and type(row['owners']) is list and len(row['owners']) == 9
             and sorted(row['owners']) == [0, 0, 0, 1, 1, 1, 2, 2, 2]
             and row['evidence_sha256'] == assignment_evidence_sha(
                 classification, row['owners'], source_receipts),
             'assignment-constraint-evidence-binding')
        assignment_constraints.add(tuple(row['owners']))
    need(len(assignment_constraints) == len(value['assignment_constraints'])
         and assignment_constraints, 'complete-assignment-constraints')

    candidates = {}
    for exit_row in exits:
        tokens = _exit_tokens(exit_row, attempts)
        required_tokens = {token for token in tokens if token[0] in required}
        required_tokens |= {token for token in tokens if token[0] in
            {'retry-route', 'rejection-route', 'orphan-route', 'reorg-route'}}
        if classification == CLASSIFICATIONS[0]:
            required_tokens.add(('transparent-owner-label', exit_row['exit_id']))
        need(required_tokens <= set(mappings), 'complete-side-mapping')
        owners = {0, 1, 2}
        for token in tokens:
            if token in mappings:
                owners &= mappings[token]
        need(owners, 'union-observer-truth-space-not-empty')
        candidates[exit_row['exit_id']] = owners
    return (candidates, constraints, assignment_constraints,
            set(key[1] for key in colluder))


def validate_bundle(selection, selection_sha256, value, read):
    fields(value, BUNDLE_FIELDS, 'bundle-fields')
    word(selection_sha256, 'selection-sha256')
    need(sha(selection) == selection_sha256
         and selection.get('schema') == FREEZE_SCHEMA
         and selection.get('status') == 'FROZEN_UNEXECUTED'
         and selection.get('execution_started') is False
         and selection.get('rehearsal_authorized') is False,
         'selection-sha256-binding')
    arm = _arm(selection, value['classification'])
    need(value['schema'] == BUNDLE_SCHEMA
         and value['selection_sha256'] == selection_sha256
         and value['trial_id'] == selection['trial_id']
         and value['capture_identity'] == arm['capture_identity']
         and value['attempt_id'] == arm['attempt_id']
         and type(value['capture_started_monotonic_ns']) is int
         and value['capture_started_monotonic_ns'] > selection['freeze_monotonic_ns']
         and type(value['capture_completed_monotonic_ns']) is int
         and value['capture_completed_monotonic_ns'] >
             value['capture_started_monotonic_ns'],
         'freeze-before-capture')
    need(value['source_closure_sha256'] == closure_sha(selection['source_closure'])
         and value['runtime_closure_sha256'] == closure_sha(selection['runtime_closure'])
         and value['registered_evidence_sha256'] ==
             evidence_sha(selection['registered_evidence']),
         'frozen-source-runtime-registered-lifecycle-binding')
    plan = selection['terminal_plan']
    service_body = _planned_json(read, value['service_loss_barrier'],
        plan['service_loss']['output_root'], 'service-loss-result')
    fields(value['cold_scan'], ('selection', 'result'), 'cold-scan-records')
    scan_selection_body = _planned_json(read, value['cold_scan']['selection'],
        plan['cold_scan']['output_root'], 'cold-scan-selection')
    scan_result_body = _planned_json(read, value['cold_scan']['result'],
        plan['cold_scan']['output_root'], 'cold-scan-result')
    capture_body = _planned_json(read, value['capture_authority'],
        arm['output_root'], 'capture-authority')
    consumed_body = _planned_json(read, value['consumed_pre_result_barrier'],
        arm['output_root'], 'consumed-pre-result-barrier')
    fields(consumed_body, ('schema', 'pre_result_barrier_sha256',
        'selection_sha256', 'classification', 'capture_identity', 'attempt_id',
        'consumed_monotonic_ns', 'state'), 'consumed-barrier-fields')
    need(consumed_body == {
        'schema': 'kpb-terminal-exit-consumed-pre-result-barrier/v1',
        'pre_result_barrier_sha256':
            plan['pre_result_barrier']['sha256'],
        'selection_sha256': selection_sha256,
        'classification': value['classification'],
        'capture_identity': value['capture_identity'],
        'attempt_id': value['attempt_id'],
        'consumed_monotonic_ns': consumed_body['consumed_monotonic_ns'],
        'state': 'CONSUMED_ONCE_BEFORE_RESULTS',
    } and type(consumed_body['consumed_monotonic_ns']) is int
      and selection['freeze_monotonic_ns'] <
          consumed_body['consumed_monotonic_ns'] <
          value['capture_started_monotonic_ns'],
      'durable-consumed-pre-result-barrier')
    need(value['coverage_categories'] == list(COVERAGE_CATEGORIES)
         and value['capture_complete'] is True
         and value['truth_or_private_bodies_exported'] is False,
         'coverage-and-forbidden-private-export')

    exits = value['exits']
    need(type(exits) is list and len(exits) == 9, 'nine-exit-evidence')
    scripts, txids, exit_ids = [], [], []
    prior_time = -1
    actual_evidence = []
    for ordinal, (row, exit_plan) in enumerate(zip(exits, plan['exits'])):
        fields(row, EXIT_FIELDS, 'exit-fields')
        need(type(row['ordinal']) is int and row['ordinal'] == ordinal
             and type(row['native_order']) is int and row['native_order'] == ordinal
             and type(row['exit_id']) is str
             and re.fullmatch('[A-Za-z0-9_-]{1,128}', row['exit_id'])
             and type(row['amount_sompi']) is int and row['amount_sompi'] > 0
             and type(row['observed_monotonic_ns']) is int
             and row['observed_monotonic_ns'] >= prior_time
             and all(type(row[name]) is str and row[name]
                     for name in ('origin_route_id', 'contact_id', 'cohort_id')),
             'ordered-typed-exit-evidence')
        prior_time = row['observed_monotonic_ns']
        bodies = {name: _planned_json(read, row[name], exit_plan['output_root'],
                                      'exit-' + name)
                  for name in ('input_history', 'case', 'lifecycle_selection',
                               'lifecycle_result', 'released_candidate',
                               'release_selection', 'release_receipt')}
        word(row['transaction_id_hex32'], 'exit-transaction-id')
        need(type(row['payout_script_hex37']) is str
             and re.fullmatch('0000aa20[0-9a-f]{64}87',
                              row['payout_script_hex37']) is not None,
             'payout-script-shape')
        history = bodies['input_history']
        fields(history, ('schema', 'trial_id', 'ordinal', 'operation_id',
                         'previous_transaction_id_hex32'),
               'input-history-body-fields')
        previous_txid = '00' * 32 if ordinal == 0 else exits[ordinal - 1][
            'transaction_id_hex32']
        need(history['schema'] == 'kpb-terminal-exit-input-history/v1'
             and history['trial_id'] == selection['trial_id']
             and type(history['ordinal']) is int and history['ordinal'] == ordinal
             and history['operation_id'] == exit_plan['operation_id']
             and history['previous_transaction_id_hex32'] == previous_txid,
             'semantic-input-history-body')
        lifecycle_selection = bodies['lifecycle_selection']
        fields(lifecycle_selection, ('schema', 'trial_id', 'ordinal',
            'operation_id', 'input_history_sha256',
            'owner_receipt_seal_sha256', 'source_closure_sha256',
            'runtime_closure_sha256', 'owner_label_exported'),
            'lifecycle-selection-body-fields')
        need(lifecycle_selection['schema'] ==
                'kpb-terminal-exit-lifecycle-selection/v1'
             and lifecycle_selection['trial_id'] == selection['trial_id']
             and lifecycle_selection['ordinal'] == ordinal
             and lifecycle_selection['operation_id'] == exit_plan['operation_id']
             and lifecycle_selection['input_history_sha256'] ==
                 row['input_history']['sha256']
             and lifecycle_selection['owner_receipt_seal_sha256'] ==
                 exit_plan['owner_receipt_seal_sha256']
             and lifecycle_selection['source_closure_sha256'] ==
                 value['source_closure_sha256']
             and lifecycle_selection['runtime_closure_sha256'] ==
                 value['runtime_closure_sha256']
             and lifecycle_selection['owner_label_exported'] is False,
             'semantic-lifecycle-selection-body')
        released = bodies['released_candidate']
        fields(released, ('schema', 'trial_id', 'ordinal', 'operation_id',
            'exit_id', 'transaction_id_hex32', 'payout_script_hex37',
            'amount_sompi', 'native_order'), 'released-candidate-body-fields')
        expected_public = {
            'trial_id': selection['trial_id'], 'ordinal': ordinal,
            'operation_id': exit_plan['operation_id'],
            'exit_id': row['exit_id'],
            'transaction_id_hex32': row['transaction_id_hex32'],
            'payout_script_hex37': row['payout_script_hex37'],
            'amount_sompi': row['amount_sompi'],
            'native_order': row['native_order'],
        }
        need(released == {'schema': 'kpb-terminal-exit-released-candidate/v1',
                          **expected_public}, 'semantic-released-candidate-body')
        lifecycle_result = bodies['lifecycle_result']
        fields(lifecycle_result, ('schema', 'trial_id', 'ordinal',
            'operation_id', 'selection_sha256', 'owner_receipt_seal_sha256',
            'candidate_sha256', 'completed_monotonic_ns',
            'owner_label_exported'), 'lifecycle-result-body-fields')
        need(lifecycle_result['schema'] ==
                'kpb-terminal-exit-lifecycle-result/v1'
             and lifecycle_result['trial_id'] == selection['trial_id']
             and lifecycle_result['ordinal'] == ordinal
             and lifecycle_result['operation_id'] == exit_plan['operation_id']
             and lifecycle_result['selection_sha256'] ==
                 row['lifecycle_selection']['sha256']
             and lifecycle_result['owner_receipt_seal_sha256'] ==
                 exit_plan['owner_receipt_seal_sha256']
             and lifecycle_result['candidate_sha256'] ==
                 row['released_candidate']['sha256']
             and type(lifecycle_result['completed_monotonic_ns']) is int
             and lifecycle_result['completed_monotonic_ns'] <=
                 row['observed_monotonic_ns']
             and lifecycle_result['owner_label_exported'] is False,
             'semantic-lifecycle-result-body')
        release_selection = bodies['release_selection']
        fields(release_selection, ('schema', 'trial_id', 'ordinal',
            'operation_id', 'lifecycle_result_sha256', 'candidate_sha256',
            'owner_receipt_seal_sha256', 'route_id', 'contact_id', 'cohort_id',
            'launch_monotonic_ns', 'owner_label_exported'),
            'release-selection-body-fields')
        need(release_selection['schema'] ==
                'kpb-terminal-exit-release-selection/v1'
             and release_selection['trial_id'] == selection['trial_id']
             and release_selection['ordinal'] == ordinal
             and release_selection['operation_id'] == exit_plan['operation_id']
             and release_selection['lifecycle_result_sha256'] ==
                 row['lifecycle_result']['sha256']
             and release_selection['candidate_sha256'] ==
                 row['released_candidate']['sha256']
             and release_selection['owner_receipt_seal_sha256'] ==
                 exit_plan['owner_receipt_seal_sha256']
             and release_selection['route_id'] == row['origin_route_id']
             and release_selection['contact_id'] == row['contact_id']
             and release_selection['cohort_id'] == row['cohort_id']
             and type(release_selection['launch_monotonic_ns']) is int
             and release_selection['owner_label_exported'] is False,
             'semantic-release-selection-body')
        release_receipt = bodies['release_receipt']
        fields(release_receipt, ('schema', 'trial_id', 'ordinal',
            'operation_id', 'release_selection_sha256', 'candidate_sha256',
            'transaction_id_hex32', 'route_id', 'contact_id', 'cohort_id',
            'attempts', 'observed_monotonic_ns', 'accepted'),
            'release-receipt-body-fields')
        claimed_attempts = [attempt for attempt in value['attempts']
                            if attempt['exit_id'] == row['exit_id']]
        need(release_receipt['schema'] ==
                'kpb-terminal-exit-release-receipt/v1'
             and release_receipt['trial_id'] == selection['trial_id']
             and release_receipt['ordinal'] == ordinal
             and release_receipt['operation_id'] == exit_plan['operation_id']
             and release_receipt['release_selection_sha256'] ==
                 row['release_selection']['sha256']
             and release_receipt['candidate_sha256'] ==
                 row['released_candidate']['sha256']
             and release_receipt['transaction_id_hex32'] ==
                 row['transaction_id_hex32']
             and release_receipt['route_id'] == row['origin_route_id']
             and release_receipt['contact_id'] == row['contact_id']
             and release_receipt['cohort_id'] == row['cohort_id']
             and release_receipt['attempts'] == claimed_attempts
             and release_receipt['observed_monotonic_ns'] ==
                 row['observed_monotonic_ns']
             and release_receipt['accepted'] is True,
             'semantic-release-receipt-body')
        case = bodies['case']
        fields(case, ('schema', 'trial_id', 'ordinal', 'operation_id',
            'candidate_sha256', 'transaction_id_hex32', 'payout_script_hex37',
            'amount_sompi', 'native_order'), 'case-body-fields')
        case_public = {key: expected_public[key] for key in
            ('trial_id', 'ordinal', 'operation_id', 'transaction_id_hex32',
             'payout_script_hex37', 'amount_sompi', 'native_order')}
        need(case == {'schema': 'kpb-terminal-exit-native-case/v1',
                      **case_public,
                      'candidate_sha256': row['released_candidate']['sha256']},
             'semantic-native-case-body')
        actual_evidence.append({
            'ordinal': ordinal,
            'input_history': row['input_history'],
            'lifecycle_selection': row['lifecycle_selection'],
            'lifecycle_result': row['lifecycle_result'],
            'released_candidate': row['released_candidate'],
            'release_selection': row['release_selection'],
            'release_receipt': row['release_receipt'],
            'case': row['case'],
        })
        scripts.append(row['payout_script_hex37'])
        txids.append(row['transaction_id_hex32'])
        exit_ids.append(row['exit_id'])
    need(len(set(scripts)) == len(set(txids)) == len(set(exit_ids)) == 9,
         'fresh-distinct-payout-scripts')
    need(value['lifecycle_evidence_sha256'] == evidence_sha(actual_evidence),
         'actual-lifecycle-evidence-seal')

    attempts = value['attempts']
    need(type(attempts) is list and len(attempts) >= 9, 'complete-attempt-history')
    events = {exit_id: [] for exit_id in exit_ids}
    prior_time = -1
    for sequence, row in enumerate(attempts):
        fields(row, ATTEMPT_FIELDS, 'attempt-fields')
        need(type(row['sequence']) is int and row['sequence'] == sequence
             and row['exit_id'] in events and row['kind'] in ATTEMPT_KINDS
             and type(row['monotonic_ns']) is int
             and value['capture_started_monotonic_ns'] <= row['monotonic_ns']
             and row['monotonic_ns'] >= prior_time
             and all(type(row[name]) is str and row[name]
                     for name in ('route_id', 'contact_id', 'cohort_id')),
             'ordered-complete-attempt')
        prior_time = row['monotonic_ns']
        word(row['transaction_id_hex32'], 'attempt-transaction-id')
        events[row['exit_id']].append(row)
    for exit_row in exits:
        rows = events[exit_row['exit_id']]
        accepted = [row for row in rows if row['kind'] == 'accepted']
        need(rows and rows[-1]['kind'] == 'accepted' and accepted
             and accepted[-1]['transaction_id_hex32'] ==
                 exit_row['transaction_id_hex32']
             and accepted[-1]['monotonic_ns'] <= exit_row['observed_monotonic_ns'],
             'accepted-exit-attempt')

    service = value['service_observations']
    stages = ['after-service-loss'] + [f'before-exit-{n}' for n in range(9)] \
        + ['after-cold-scan']
    need(type(service) is list and len(service) == len(stages),
         'service-loss-observation-count')
    prior_time = -1
    for sequence, (row, stage) in enumerate(zip(service, stages)):
        fields(row, SERVICE_FIELDS, 'service-observation-fields')
        need(type(row['sequence']) is int and row['sequence'] == sequence
             and row['stage'] == stage
             and type(row['monotonic_ns']) is int
             and row['monotonic_ns'] >= prior_time
             and type(row['active_processes']) is int
             and row['active_processes'] == 0
             and type(row['active_listeners']) is int
             and row['active_listeners'] == 0
             and row['private_service_state_mounted'] is False
             and row['owner_exit_service_dependency'] is False,
             'service-remained-absent')
        prior_time = row['monotonic_ns']
    need(service[0]['monotonic_ns'] < attempts[0]['monotonic_ns'],
         'service-loss-before-exits')
    for ordinal in range(9):
        first_attempt = min(row['monotonic_ns'] for row in attempts
                            if row['exit_id'] == exits[ordinal]['exit_id'])
        need(service[ordinal + 1]['monotonic_ns'] < first_attempt,
             'service-absence-before-each-exit')

    scans = value['cold_scan_observations']
    need(type(scans) is list and len(scans) == 3, 'three-cold-scans')
    for slot, row in enumerate(scans):
        fields(row, SCAN_FIELDS, 'cold-scan-fields')
        need(type(row['scan_slot']) is int and row['scan_slot'] == slot
             and type(row['monotonic_ns']) is int
             and row['monotonic_ns'] > exits[-1]['observed_monotonic_ns']
             and row['status'] == 'COMPLETE_ZERO_RESERVE'
             and type(row['terminal_reserve_sompi']) is int
             and row['terminal_reserve_sompi'] == 0,
             'cold-scan-after-exits')
        need(row['payout_script_or_exit_id_exported'] is False,
             'cold-scan-public-boundary')
    need(service[-1]['monotonic_ns'] > max(row['monotonic_ns'] for row in scans)
         and value['capture_completed_monotonic_ns'] >= service[-1]['monotonic_ns'],
         'cold-scan-public-boundary')

    fields(service_body, ('schema', 'trial_id', 'operation_id',
        'classification', 'observations', 'private_service_state_exported'),
        'service-loss-result-body-fields')
    need(service_body == {
        'schema': 'kpb-terminal-exit-service-loss-result/v1',
        'trial_id': selection['trial_id'],
        'operation_id': plan['service_loss']['operation_id'],
        'classification': value['classification'],
        'observations': service,
        'private_service_state_exported': False,
    }, 'semantic-service-loss-body')
    fields(scan_selection_body, ('schema', 'trial_id', 'operation_id',
        'classification', 'history_tail_transaction_id_hex32'),
        'scan-selection-body-fields')
    need(scan_selection_body == {
        'schema': 'kpb-terminal-exit-cold-scan-selection/v1',
        'trial_id': selection['trial_id'],
        'operation_id': plan['cold_scan']['operation_id'],
        'classification': value['classification'],
        'history_tail_transaction_id_hex32': exits[-1]['transaction_id_hex32'],
    }, 'semantic-cold-scan-selection-body')
    fields(scan_result_body, ('schema', 'trial_id', 'operation_id',
        'selection_sha256', 'observations',
        'private_original_or_claim_exported'), 'scan-result-body-fields')
    need(scan_result_body == {
        'schema': 'kpb-terminal-exit-cold-scan-result/v1',
        'trial_id': selection['trial_id'],
        'operation_id': plan['cold_scan']['operation_id'],
        'selection_sha256': value['cold_scan']['selection']['sha256'],
        'observations': scans,
        'private_original_or_claim_exported': False,
    }, 'semantic-cold-scan-result-body')
    fields(capture_body, ('schema', 'selection_sha256', 'classification',
        'capture_identity', 'attempt_id', 'consumed_barrier_sha256',
        'exits', 'attempts',
        'service_observations', 'cold_scan_observations', 'side_information',
        'coverage_categories', 'unknown_record_count', 'capture_closed'),
        'capture-authority-body-fields')
    need(capture_body == {
        'schema': 'kpb-terminal-exit-capture-authority/v1',
        'selection_sha256': selection_sha256,
        'classification': value['classification'],
        'capture_identity': value['capture_identity'],
        'attempt_id': value['attempt_id'],
        'consumed_barrier_sha256':
            value['consumed_pre_result_barrier']['sha256'],
        'exits': exits,
        'attempts': attempts,
        'service_observations': service,
        'cold_scan_observations': scans,
        'side_information': value['side_information'],
        'coverage_categories': value['coverage_categories'],
        'unknown_record_count': 0,
        'capture_closed': True,
    }, 'source-capture-authority-completeness')

    candidates, constraints, assignments, colluder_exit_ids = _side_information(
        value['side_information'], value['classification'], exits, attempts,
        selection['colluding_owner_component'])
    return {'exit_ids': exit_ids, 'owner_candidates': candidates,
            'joint_constraints': constraints,
            'assignment_constraints': assignments,
            'colluder_exit_ids': colluder_exit_ids,
            'transaction_ids': txids, 'payout_scripts': scripts,
            'amounts': [row['amount_sompi'] for row in exits],
            'cohorts': [row['cohort_id'] for row in exits],
            'contacts': [row['contact_id'] for row in exits],
            'prior_transaction_ids': set(
                value['side_information']['prior_transaction_ids_hex32']),
            'prior_payout_scripts': set(
                value['side_information']['prior_payout_scripts_hex37'])}


def _assignments(graph):
    exit_ids = graph['exit_ids']
    result = []
    choices = [sorted(graph['owner_candidates'][exit_id]) for exit_id in exit_ids]
    for owners in itertools.product(*choices):
        assignment = dict(zip(exit_ids, owners))
        if (all(owners.count(owner) == 3 for owner in (0, 1, 2))
                and all((assignment[left], assignment[right]) in allowed
                        for (left, right), allowed in
                        graph['joint_constraints'].items())
                and tuple(owners) in graph['assignment_constraints']):
            result.append(tuple(owners))
    return result


def _truth(value, selection, selection_sha256, exit_ids):
    fields(value, ('schema', 'selection_sha256', 'exits',
                   'private_originals_or_bodies_exported'), 'truth-fields')
    need(value['schema'] == TRUTH_SCHEMA
         and value['selection_sha256'] == selection_sha256
         and value['private_originals_or_bodies_exported'] is False
         and type(value['exits']) is list and len(value['exits']) == 9,
         'private-truth-binding')
    owners = []
    ids = []
    for ordinal, (row, plan) in enumerate(
            zip(value['exits'], selection['terminal_plan']['exits'])):
        fields(row, ('exit_id', 'owner_receipt'), 'truth-exit-fields')
        receipt = row['owner_receipt']
        fields(receipt, ('schema', 'trial_id', 'freeze_nonce_hex32', 'ordinal',
            'operation_id', 'owner_component', 'salt_hex32',
            'private_original_or_body_exported'), 'owner-receipt-fields')
        need(type(row['exit_id']) is str
             and receipt['schema'] == 'kpb-terminal-exit-private-owner-receipt/v1'
             and receipt['trial_id'] == selection['trial_id']
             and receipt['freeze_nonce_hex32'] == selection['freeze_nonce_hex32']
             and type(receipt['ordinal']) is int and receipt['ordinal'] == ordinal
             and receipt['operation_id'] == plan['operation_id']
             and type(receipt['owner_component']) is int
             and receipt['owner_component'] in (0, 1, 2)
             and word(receipt['salt_hex32'], 'owner-receipt-salt')
             and receipt['private_original_or_body_exported'] is False
             and sha(receipt) == plan['owner_receipt_seal_sha256'],
             'truth-owner-receipt-binding')
        ids.append(row['exit_id']); owners.append(receipt['owner_component'])
    need(ids == exit_ids and sorted(owners) == [0, 0, 0, 1, 1, 1, 2, 2, 2],
         'truth-owner-counts')
    return tuple(owners)


def _owner_set_counts(assignments, exit_ids, owners):
    return {
        owner: len({tuple(exit_ids[index] for index, assigned in enumerate(row)
                          if assigned == owner) for row in assignments})
        for owner in owners
    }


def compare_private(selection, selection_sha256, baseline, candidate, truth, read):
    validate_freeze(selection, read)
    need(sha(selection) == selection_sha256, 'selection-sha256-binding')
    baseline_graph = validate_bundle(selection, selection_sha256, baseline, read)
    candidate_graph = validate_bundle(selection, selection_sha256, candidate, read)
    need(baseline['classification'] == CLASSIFICATIONS[0]
         and candidate['classification'] == CLASSIFICATIONS[1]
         and baseline_graph['exit_ids'] == candidate_graph['exit_ids'],
         'baseline-candidate-workload')
    need(not set(baseline_graph['transaction_ids']).intersection(
            candidate_graph['transaction_ids'])
         and baseline['consumed_pre_result_barrier']['sha256'] !=
             candidate['consumed_pre_result_barrier']['sha256']
         and not set(baseline_graph['payout_scripts']).intersection(
            candidate_graph['payout_scripts'])
         and baseline_graph['prior_transaction_ids'] ==
            candidate_graph['prior_transaction_ids']
         and baseline_graph['prior_payout_scripts'] ==
            candidate_graph['prior_payout_scripts']
         and not set(baseline_graph['transaction_ids']).intersection(
            baseline_graph['prior_transaction_ids'])
         and not set(candidate_graph['transaction_ids']).intersection(
            candidate_graph['prior_transaction_ids'])
         and not set(baseline_graph['payout_scripts']).intersection(
            baseline_graph['prior_payout_scripts'])
         and not set(candidate_graph['payout_scripts']).intersection(
            candidate_graph['prior_payout_scripts']),
         'cross-arm-prior-identity-script-ledger')
    def partition(rows):
        return [[left, right] for left in range(len(rows))
                for right in range(left + 1, len(rows))
                if rows[left] == rows[right]]
    need(baseline_graph['amounts'] == candidate_graph['amounts']
         and partition(baseline_graph['cohorts']) ==
             partition(candidate_graph['cohorts'])
         and partition(baseline_graph['contacts']) ==
             partition(candidate_graph['contacts']),
         'cross-arm-amount-contact-cohort-workload')
    truth_owners = _truth(truth, selection, selection_sha256,
                          baseline_graph['exit_ids'])
    baseline_assignments = _assignments(baseline_graph)
    candidate_assignments = _assignments(candidate_graph)
    need(len(baseline_assignments) == 1
         and baseline_assignments[0] == truth_owners,
         'transparent-baseline-control')
    need(candidate_assignments, 'candidate-truth-space')
    baseline_truth = truth_owners in baseline_assignments
    candidate_truth = truth_owners in candidate_assignments
    honest = tuple(owner for owner in (0, 1, 2)
                   if owner != selection['colluding_owner_component'])
    expected_colluder_exits = {
        baseline_graph['exit_ids'][index]
        for index, owner in enumerate(truth_owners)
        if owner == selection['colluding_owner_component']
    }
    need(not baseline_graph['colluder_exit_ids']
         and candidate_graph['colluder_exit_ids'] == expected_colluder_exits,
         'exact-true-colluder-exit-receipts')
    baseline_counts = _owner_set_counts(
        baseline_assignments, baseline_graph['exit_ids'], honest)
    candidate_counts = _owner_set_counts(
        candidate_assignments, candidate_graph['exit_ids'], honest)
    nonregressed = all(candidate_counts[owner] >= baseline_counts[owner]
                       for owner in honest)
    strict = sum(candidate_counts[owner] > baseline_counts[owner]
                 for owner in honest)
    minimum = min(candidate_counts.values())
    honest_exit_eligible = [
        len({row[index] for row in candidate_assignments})
        for index, owner in enumerate(truth_owners) if owner in honest
    ]
    need(len(honest_exit_eligible) == 6, 'six-honest-exits')
    minimum_exit_eligible = min(honest_exit_eligible)
    thresholds = selection['thresholds']
    passed = (
        baseline_truth and candidate_truth
        and len(candidate_assignments) >= thresholds['min_candidate_joint_assignments']
        and minimum >= thresholds['min_honest_owner_exit_sets']
        and minimum_exit_eligible >=
            thresholds['min_honest_exit_eligible_owners']
        and (not thresholds['require_all_honest_nonregression'] or nonregressed)
        and (not thresholds['require_all_honest_strict_gain']
             or strict == thresholds['honest_owner_count'])
    )
    return {
        'schema': SCORE_SCHEMA,
        'selection_sha256': selection_sha256,
        'baseline_bundle_sha256': sha(baseline),
        'candidate_bundle_sha256': sha(candidate),
        'status': (MODEL_PASS_STATUS if passed else MODEL_FAIL_STATUS),
        'baseline_joint_assignments': len(baseline_assignments),
        'candidate_joint_assignments': len(candidate_assignments),
        'minimum_honest_owner_candidate_exit_sets': minimum,
        'minimum_honest_exit_eligible_owners': minimum_exit_eligible,
        'all_honest_owner_counts_nonregressed': nonregressed,
        'honest_owners_with_strict_gain': strict,
        'baseline_truth_retained': baseline_truth,
        'candidate_truth_retained': candidate_truth,
        'transparent_baseline_control_passed': True,
        'union_observer_scored': True,
        'private_truth_or_owner_labels_exported': False,
    }


def source_only_acceptance(selection_sha256, baseline_bundle_sha256,
                           candidate_bundle_sha256, score):
    fields(score, ('schema', 'selection_sha256', 'baseline_bundle_sha256',
        'candidate_bundle_sha256', 'status', 'baseline_joint_assignments',
        'candidate_joint_assignments', 'minimum_honest_owner_candidate_exit_sets',
        'minimum_honest_exit_eligible_owners',
        'all_honest_owner_counts_nonregressed',
        'honest_owners_with_strict_gain', 'baseline_truth_retained',
        'candidate_truth_retained', 'transparent_baseline_control_passed',
        'union_observer_scored', 'private_truth_or_owner_labels_exported'),
        'score-fields')
    for name in ('baseline_joint_assignments', 'candidate_joint_assignments',
                 'minimum_honest_owner_candidate_exit_sets',
                 'minimum_honest_exit_eligible_owners',
                 'honest_owners_with_strict_gain'):
        need(type(score[name]) is int and score[name] >= 0,
             'score-nonnegative-' + name)
    for name in ('all_honest_owner_counts_nonregressed',
                 'baseline_truth_retained', 'candidate_truth_retained',
                 'transparent_baseline_control_passed',
                 'union_observer_scored',
                 'private_truth_or_owner_labels_exported'):
        need(type(score[name]) is bool, 'score-boolean-' + name)
    semantic_pass = (
        score['baseline_joint_assignments'] == 1
        and score['candidate_joint_assignments'] >=
            FROZEN_THRESHOLDS['min_candidate_joint_assignments']
        and score['minimum_honest_owner_candidate_exit_sets'] >=
            FROZEN_THRESHOLDS['min_honest_owner_exit_sets']
        and score['minimum_honest_exit_eligible_owners'] >=
            FROZEN_THRESHOLDS['min_honest_exit_eligible_owners']
        and score['all_honest_owner_counts_nonregressed'] is True
        and score['honest_owners_with_strict_gain'] ==
            FROZEN_THRESHOLDS['honest_owner_count']
        and score['baseline_truth_retained'] is True
        and score['candidate_truth_retained'] is True
        and score['transparent_baseline_control_passed'] is True
        and score['union_observer_scored'] is True
        and score['private_truth_or_owner_labels_exported'] is False
    )
    need(score['schema'] == SCORE_SCHEMA
         and score['selection_sha256'] == selection_sha256
         and score['baseline_bundle_sha256'] == baseline_bundle_sha256
         and score['candidate_bundle_sha256'] == candidate_bundle_sha256
         and score['private_truth_or_owner_labels_exported'] is False,
         'score-bundle-binding')
    need(score['status'] in (MODEL_PASS_STATUS, MODEL_FAIL_STATUS)
         and ((score['status'] == MODEL_PASS_STATUS)
              is semantic_pass), 'score-status-semantics')
    word(baseline_bundle_sha256, 'baseline-bundle-sha256')
    word(candidate_bundle_sha256, 'candidate-bundle-sha256')
    return {
        'schema': ACCEPTANCE_SCHEMA,
        'selection_sha256': selection_sha256,
        'baseline_bundle_sha256': baseline_bundle_sha256,
        'candidate_bundle_sha256': candidate_bundle_sha256,
        'private_score_result_sha256': sha(score),
        'model_status': score['status'],
        'privacy_status': 'UNQUALIFIED_SOURCE_ONLY',
        'terminal_exit_privacy_contract_frozen': True,
        'private_batch_privacy_result_substituted': False,
        'actual_capture_and_private_score_executed': False,
        'rehearsal_authorized': False,
        'authorization_blocker':
            'actual-terminal-exit-capture-and-isolated-private-score-not-executed',
    }
