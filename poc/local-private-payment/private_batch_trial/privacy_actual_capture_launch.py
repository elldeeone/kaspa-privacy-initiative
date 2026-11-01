#!/usr/bin/env python3
"""Fail-closed launcher boundary for actual privacy capture.

No genuine upstream capture producer source/build/one-shot launch is currently
selected.  This launcher therefore validates the public comparison/run/D
chain, reports SOURCE_ONLY_UNQUALIFIED, and refuses ``--execute`` before any
private read, attempt consumption, namespace launch, or public output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

import privacy_actual_capture as worker
import privacy_codec as codec
import privacy_source_closure as source_closure


HERE = Path(__file__).absolute().parent
PUBLIC_BASE = Path('/var/tmp/kpi-private-batch-bootstrap-20261028')
FINANCIAL_FIELDS = (
    'round', 'financial_run_id', 'financial_artifacts',
    'financial_result', 'retained_projection',
)
RUN_FIELDS = (
    'schema', 'scope', 'classification', 'trial_label', 'binding',
    'method_sha256', 'measurement_freeze_sha256', 'workload_sha256',
    'observer_source_sha256', 'capture_source_sha256',
    'coverage_policy_sha256', 'bundle_producer_source_sha256',
    'owner_comparison_source_sha256',
    'owner_comparison_launcher_source_sha256',
    'capture_producer_source_sha256',
    'capture_producer_build_sha256',
    'capture_producer_launcher_source_sha256',
    'capture_launcher_source_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'python_runtime_sha256',
    'namespace_tool_sha256', 'root_guard_helper_sha256',
    'host_runtime_trust_boundary', 'capture_identity',
    'diagnostic_selection', 'public_root', 'capture_producer_receipt',
    'financial_rounds',
)
COMPARISON_FIELDS = (
    'schema', 'method_sha256', 'measurement_freeze_sha256',
    'workload_sha256', 'observer_source_sha256',
    'capture_source_sha256', 'coverage_policy_sha256',
    'bundle_producer_source_sha256', 'owner_comparison_source_sha256',
    'owner_comparison_launcher_source_sha256',
    'capture_producer_source_sha256',
    'capture_producer_build_sha256',
    'capture_producer_launcher_source_sha256',
    'capture_launcher_source_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'python_runtime_sha256',
    'namespace_tool_sha256', 'root_guard_helper_sha256',
    'host_runtime_trust_boundary', 'runs',
)
DIAGNOSTIC_FIELDS = (
    'schema', 'binding', 'expected_classification', 'run_selection',
    'bootstrap_trial', 'source_members', 'source_closure_sha256',
    'runtime_identity_sha256', 'capture_producer_receipt',
    'financial_rounds', 'rounds', 'corrupt_server_view',
)
DIAGNOSTIC_SOURCES = (
    'privacy_codec.py', 'privacy_capture_model.py', 'privacy_observer.py',
    'privacy_owner.py', 'privacy_roles.py', 'privacy_launch.py',
    'privacy_source_closure.py',
)
COMPARISON_SCHEMA = 'kpb-privacy-comparison-selection/v2'
DIAGNOSTIC_SCHEMA = 'kpb-private-diagnostic-launch-selection/v2'
RUN_SCHEMA = 'kpb-privacy-actual-run-selection/v2'
LAUNCH_SCHEMA = 'kpb-actual-capture-launch/v2'
LAUNCH_FIELDS = (
    'schema', 'operation', 'binding', 'comparison_selection_sha256',
    'run_selection_sha256', 'diagnostic_selection_sha256',
    'classification', 'capture_identity',
    'capture_launcher_source_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'python_runtime_sha256',
    'namespace_tool_sha256', 'root_guard_helper_sha256',
    'host_runtime_trust_boundary', 'capture_producer_receipt_sha256',
    'financial_rounds', 'construction_classification_receipt_sha256',
    'capture_receipt_sha256', 'capture_manifest_seal_sha256',
    'public_result', 'public_result_sha256',
    'persistent_capture_consumed', 'capture_roots_closed',
    'financial_host_crypto_rechecked', 'network_enabled',
    'predictions_or_truth_mounted',
    'private_capture_bodies_read_inside_namespace',
    'private_artifact_paths_hashes_or_bodies_exported',
    'terminal_scope', 'step3_terminal_gate',
)


def need(condition, category):
    if not condition:
        raise ValueError('privacy-actual-capture-launch-' + category)


def exact(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='word'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         category)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError('privacy-actual-capture-launch-nonfinite-number')))
    need(encoded(value) == raw, 'canonical-json')
    return value


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def read_public(path, expected=None):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts,
         'absolute-public-path')
    parent = worker.open_directory(path.parent)
    try:
        raw = worker.stable_read_at(parent, path.name, 16 << 20,
                                    expected_mode=0o400)
    finally:
        os.close(parent)
    digest = hashlib.sha256(raw).hexdigest()
    if expected is not None:
        need(digest == word(expected), 'selected-public-hash')
    return parse(raw), raw, digest


def reference(value):
    exact(value, ('path', 'sha256'), 'reference-fields')
    return read_public(value['path'], value['sha256'])


def validate_financial_refs(value):
    need(type(value) is list and len(value) == 2,
         'two-financial-rounds')
    for number, row in zip((1, 2), value):
        exact(row, FINANCIAL_FIELDS, 'financial-round-fields')
        need(row['round'] == number, 'financial-round-order')
        word(row['financial_run_id'], 'financial-run-id')
        for name in ('financial_artifacts', 'financial_result',
                     'retained_projection'):
            exact(row[name], ('path', 'sha256'),
                  'financial-reference-fields')
            need(Path(row[name]['path']).is_absolute(),
                 'financial-absolute-path')
            word(row[name]['sha256'], 'financial-reference-hash')
    need(value[0]['financial_run_id'] != value[1]['financial_run_id']
         and value[0]['retained_projection']['sha256'] !=
             value[1]['retained_projection']['sha256'],
         'distinct-financial-rounds')


def admit(comparison_path, comparison_sha256, run_index):
    """Admit public selections only; never open the producer/private bodies."""
    need(type(run_index) is int and run_index in (0, 1), 'run-index')
    comparison, _, comparison_sha = read_public(
        comparison_path, comparison_sha256)
    exact(comparison, COMPARISON_FIELDS, 'comparison-fields')
    need(comparison['schema'] == COMPARISON_SCHEMA,
         'comparison-schema')
    runtime = source_closure.runtime_identity()
    need(comparison['capture_launcher_source_sha256'] == source_sha256()
         and comparison['capture_source_sha256'] ==
            hashlib.sha256((HERE / 'privacy_actual_capture.py')
                           .read_bytes()).hexdigest()
         and comparison['capture_producer_source_sha256'] ==
            hashlib.sha256((HERE / 'privacy_capture_producer.py')
                           .read_bytes()).hexdigest()
         and comparison['observer_source_sha256'] ==
            source_closure.digest('observer')
         and comparison['source_closure_sha256'] ==
            source_closure.all_digests()
         and comparison['runtime_identity_sha256'] ==
            source_closure.runtime_digest()
         and comparison['python_runtime_sha256'] ==
            runtime['python_runtime_sha256']
         and comparison['namespace_tool_sha256'] ==
            runtime['namespace_tool_sha256']
         and comparison['root_guard_helper_sha256'] ==
            runtime['root_guard_helper_sha256']
         and comparison['host_runtime_trust_boundary'] ==
            runtime['host_runtime_trust_boundary'],
         'current-source-runtime-closure')
    word(comparison['capture_producer_build_sha256'],
         'capture-producer-build')
    word(comparison['capture_producer_launcher_source_sha256'],
         'capture-producer-role-launch')
    need(type(comparison['runs']) is list and len(comparison['runs']) == 2,
         'comparison-two-runs')
    selected = comparison['runs'][run_index]
    exact(selected, ('classification', 'path', 'sha256'),
          'run-reference-fields')
    need(selected['classification'] == worker.CLASSIFICATIONS[run_index],
         'classification-order')
    run, _, run_sha = reference(selected)
    exact(run, RUN_FIELDS, 'run-fields')
    need(run['schema'] == RUN_SCHEMA
         and run['scope'] == 'FRESH_UNFUNDED_ACTUAL_PRIVATE_BATCH'
         and run['classification'] == selected['classification'],
         'actual-run-schema')
    for name in COMPARISON_FIELDS[1:-1]:
        need(run[name] == comparison[name], 'comparison-run-' + name)
    codec.binding(run['binding'])
    need(run['binding']['method_sha256'] == run['method_sha256']
         and type(run['capture_identity']) is str
         and str(uuid.UUID(run['capture_identity'])) ==
            run['capture_identity'], 'run-binding-identity')
    need(type(run['trial_label']) is str
         and re.fullmatch('[a-z][a-z0-9-]{0,63}', run['trial_label'])
         and Path(run['public_root']) ==
            PUBLIC_BASE / run['trial_label'] / 'privacy-diagnostics',
         'fixed-trial-public-root')
    validate_financial_refs(run['financial_rounds'])
    diagnostic, _, diagnostic_sha = reference(run['diagnostic_selection'])
    exact(diagnostic, DIAGNOSTIC_FIELDS, 'diagnostic-fields')
    need(diagnostic['schema'] == DIAGNOSTIC_SCHEMA
         and diagnostic['binding'] == run['binding']
         and diagnostic['expected_classification'] == run['classification']
         and diagnostic['source_closure_sha256'] ==
            run['source_closure_sha256']
         and diagnostic['runtime_identity_sha256'] ==
            run['runtime_identity_sha256']
         and diagnostic['capture_producer_receipt'] ==
            run['capture_producer_receipt']
         and diagnostic['financial_rounds'] == run['financial_rounds'],
         'diagnostic-run-binding')
    need(type(diagnostic['source_members']) is list
         and [row.get('name') for row in diagnostic['source_members']] ==
            list(DIAGNOSTIC_SOURCES), 'diagnostic-source-order')
    for row in diagnostic['source_members']:
        exact(row, ('name', 'sha256'), 'diagnostic-source-fields')
        need(row['sha256'] == hashlib.sha256(
            (HERE / row['name']).read_bytes()).hexdigest(),
            'diagnostic-source-' + row['name'])
    _, _, inner_sha = reference(diagnostic['run_selection'])
    need(inner_sha == run['binding']['selection_sha256'],
         'diagnostic-inner-run-binding')
    need(type(diagnostic['rounds']) is list
         and [row.get('round') for row in diagnostic['rounds']] == [1, 2]
         and all(type(row) is dict and set(row) ==
                 {'round', 'pay_result', 'financial_round'}
                 for row in diagnostic['rounds'])
         and [row['financial_round'] for row in diagnostic['rounds']] ==
            run['financial_rounds']
         and diagnostic['corrupt_server_view'] == {
             'owner_component': 1,
             'capture_kind': 'corrupt-server-capture'},
         'diagnostic-rounds-and-view')
    exact(run['capture_producer_receipt'], ('path', 'sha256'),
          'producer-reference-fields')
    producer_path = Path(run['capture_producer_receipt']['path'])
    need(producer_path == Path(run['public_root']) /
         'capture-producer/PUBLIC.json', 'fixed-producer-path')
    return {
        'schema': 'kpb-actual-capture-launch-plan/v1',
        'status': 'SOURCE_ONLY_UNQUALIFIED',
        'blocker':
            'GENUINE_FIVE_ROLE_BUILD_SUPERVISION_AND_OUTER_LAUNCH_AUTHORITY_ABSENT',
        'comparison_selection_sha256': comparison_sha,
        'run_selection_sha256': run_sha,
        'diagnostic_selection_sha256': diagnostic_sha,
        'classification': run['classification'],
        'capture_identity': run['capture_identity'],
        'producer_receipt_path_present': producer_path.is_file(),
        'financial_host_crypto_rechecked': False,
        'private_capture_bodies_read_or_hashed': False,
        'persistent_capture_consumed': False,
        'public_output_created': False,
        'network_enabled': False,
    }


def validate_launch_receipt(value):
    """Recognize the frozen shape, then refuse it while authority is absent."""
    exact(value, LAUNCH_FIELDS, 'launch-fields')
    need(value['schema'] == LAUNCH_SCHEMA
         and value['operation'] == 'actual-capture'
         and value['persistent_capture_consumed'] is True
         and value['capture_roots_closed'] is True
         and value['financial_host_crypto_rechecked'] is True
         and value['network_enabled'] is False
         and value['predictions_or_truth_mounted'] is False
         and value['private_capture_bodies_read_inside_namespace'] is True
         and value['private_artifact_paths_hashes_or_bodies_exported']
            is False
         and value['terminal_scope'] == worker.TERMINAL_SCOPE
         and value['step3_terminal_gate'] == worker.STEP3_TERMINAL_GATE,
         'launch-authority-flags')
    need(False, 'actual-launch-receipt-disabled-source-only')


def run(comparison_path, comparison_sha256, run_index, execute=False):
    plan = admit(comparison_path, comparison_sha256, run_index)
    if execute:
        need(False, 'source-only-no-genuine-producer-authority')
    return plan


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--comparison', required=True)
    parser.add_argument('--comparison-sha256', required=True)
    parser.add_argument('--run-index', type=int, choices=(0, 1), required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.comparison, args.comparison_sha256,
                             args.run_index, args.execute), sort_keys=True))
    except BaseException:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
