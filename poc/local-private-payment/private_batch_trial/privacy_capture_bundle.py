#!/usr/bin/env python3
"""Build an actual four-view bundle from a frozen pre-truth selection.

No classification, provenance hash, category list, private path or receipt is
accepted from the CLI.  The producer derives them from one of two fresh run
selections already named by a common comparison selection.  It reads public
receipts only; capture bodies, capsules, truth and owner score leaves are not
inputs.  Legacy/synthetic v1 receipts cannot be promoted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

import privacy_acceptance as gate
import privacy_actual_capture_launch as capture_launcher
import privacy_launch as diagnostic_launcher
import privacy_source_closure as source_closure


PUBLIC_BASE = Path('/var/tmp/kpi-private-batch-bootstrap-20261028')
REPO_ROOT = Path(__file__).absolute().parents[3]
METHOD_PATH = REPO_ROOT / (
    'research/next-session/local-private-payment/private-batch-2026-10-28/'
    'PRIVACY-METHOD-FREEZE.md')
MEASUREMENT_FREEZE_PATH = REPO_ROOT / (
    'research/next-session/local-private-payment/private-batch-2026-10-28/'
    'PRIVACY-ACCEPTANCE-GATE-FREEZE-2026-10-28.md')
WORKLOAD_PATH = REPO_ROOT / (
    'research/next-session/local-private-payment/private-batch-2026-10-28/'
    'PRIVACY-WORKLOAD-FREEZE-2026-10-28.json')
CLASSIFICATIONS = (
    'ACTUAL_TRANSPARENT_BASELINE',
    'ACTUAL_HIDDEN_MAPPING_CANDIDATE',
)
DIAGNOSTIC_SOURCE_NAMES = source_closure.ROLE_MEMBERS[
    'diagnostic-launcher']
COMPARISON_SCHEMA = 'kpb-privacy-comparison-selection/v2'
DIAGNOSTIC_SCHEMA = 'kpb-private-diagnostic-launch-selection/v2'
DIAGNOSTIC_FIELDS = (
    'schema', 'binding', 'expected_classification', 'run_selection',
    'bootstrap_trial', 'source_members', 'source_closure_sha256',
    'runtime_identity_sha256', 'capture_producer_receipt',
    'financial_rounds', 'rounds', 'corrupt_server_view',
)
FINANCIAL_ROUND_FIELDS = (
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
    'host_runtime_trust_boundary',
    'capture_identity', 'diagnostic_selection', 'public_root',
    'capture_producer_receipt', 'financial_rounds',
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
CAPTURE_FIELDS = (
    'schema', 'comparison_selection_sha256', 'run_selection_sha256',
    'classification', 'binding', 'method_sha256', 'workload_sha256',
    'observer_source_sha256', 'capture_source_sha256',
    'coverage_policy_sha256', 'capture_identity',
    'capture_manifest_seal_sha256',
    'construction_classification_receipt_sha256', 'terminal_scope',
    'step3_terminal_gate', 'capture_producer_receipt_sha256',
    'source_closure_sha256', 'runtime_identity_sha256',
    'views', 'capture_roots_closed',
    'exact_union_derived', 'predictions_or_truth_mounted',
    'private_artifact_paths_hashes_or_bodies_exported',
)
CAPTURE_VIEW_FIELDS = ('view', 'categories', 'rounds', 'coverage')
CAPTURE_ROUND_FIELDS = (
    'round', 'artifact_count', 'artifact_bytes', 'category_counts',
    'category_coverage',
    'modeled_artifacts', 'unmodeled_artifacts', 'missing_artifacts',
    'terminal_modeled',
)
OBSERVATION_FIELDS = (
    'schema', 'binding', 'comparison_selection_sha256',
    'run_selection_sha256', 'capture_receipt_sha256',
    'capture_manifest_seal_sha256',
    'construction_classification_receipt_sha256',
    'capture_producer_receipt_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'terminal_scope', 'step3_terminal_gate',
    'views',
    'predictions_frozen_before_truth',
    'private_view_or_prediction_records_exported',
)
OBSERVATION_VIEW_FIELDS = (
    'view', 'capsule_seal_sha256', 'capsule_bytes', 'rounds', 'coverage',
    'category_coverage', 'workload', 'lattice_attestation',
)
OBSERVATION_WORKLOAD_FIELDS = (
    'full_workload_candidates', 'cross_round_constraints_modeled',
    'terminal_constraints_modeled', 'candidate_set_commitment_sha256',
)
BARRIER_FIELDS = (
    'schema', 'binding', 'comparison_selection_sha256',
    'run_selection_sha256', 'capture_receipt_sha256',
    'capture_manifest_seal_sha256',
    'construction_classification_receipt_sha256',
    'capture_producer_receipt_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'terminal_scope', 'step3_terminal_gate',
    'observation_receipt_sha256',
    'capsules',
)
SCORE_FIELDS = (
    'schema', 'binding', 'comparison_selection_sha256',
    'run_selection_sha256', 'barrier_sha256', 'owner_component',
    'source_closure_sha256', 'runtime_identity_sha256',
    'step3_terminal_gate',
    'per_owner_counts_or_truth_exported',
)
AGGREGATE_FIELDS = (
    'schema', 'binding', 'comparison_selection_sha256',
    'run_selection_sha256', 'capture_receipt_sha256', 'barrier_sha256',
    'capture_producer_receipt_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'step3_terminal_gate',
    'lattice_attestation', 'views',
    'private_records_masks_or_per_owner_counts_exported',
)
LAUNCH_FIELDS = (
    'schema', 'operation', 'binding', 'selection_sha256',
    'public_result', 'public_result_sha256', 'persistent_query_consumed',
    'private_bodies_read_or_hashed', 'network_enabled',
    'source_closure_sha256', 'runtime_identity_sha256',
    'python_runtime_sha256', 'namespace_tool_sha256',
    'root_guard_helper_sha256', 'host_runtime_trust_boundary',
)
CONSTRUCTION_FIELDS = (
    'schema', 'comparison_selection_sha256', 'run_selection_sha256',
    'classification', 'capture_source_sha256',
    'capture_producer_receipt_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'financial_run_id', 'projection_sha256',
    'terminal_grouping_mode', 'direct_owner_mapping_exposed',
    'caller_overlay', 'private_owner_or_slot_identifiers_exported',
    'terminal_scope', 'step3_terminal_gate',
)
PRODUCER_RECEIPT_FIELDS = (
    'schema', 'binding', 'classification', 'capture_identity',
    'producer_source_sha256', 'producer_build_sha256',
    'producer_role_launch_sha256', 'financial_rounds', 'rounds',
    'append_only_roots_closed', 'unknown_record_count',
    'role_hooks_integrated', 'fixed_fd_inheritance_selected',
    'launcher_selected', 'launch_authorized', 'actual_receipt_emitted',
)
PRODUCER_ROUND_FIELDS = (
    'round', 'attempt_id', 'cohort_sha256', 'artifacts',
)
PRODUCER_ARTIFACT_FIELDS = (
    'kind', 'producer_record_count', 'capture_record_count',
    'producer_payload_bytes', 'capture_payload_bytes',
    'record_chain_sha256', 'capture_root_closed', 'producer_fd_closed',
)
CAPTURE_ARTIFACT_ORDER = (
    'public-projection', 'terminal-history', 'dispatcher-capture',
    'corrupt-server-capture', 'colluder-wallet-capture',
)
ACTUAL_RUN_SCHEMA = 'kpb-privacy-actual-run-selection/v2'
CAPTURE_LAUNCH_SCHEMA = 'kpb-actual-capture-launch/v2'
CAPTURE_LAUNCH_FIELDS = (
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
        raise ValueError('privacy-capture-bundle-' + category)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'exact-fields')


def word(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         'canonical-word')
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
            ValueError('privacy-capture-bundle-nonfinite-number')))
    need(encoded(value) == raw, 'canonical-json')
    return value


def checked(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute-nonsymlink-path')
    return path


def read_leaf(path, expected=None):
    path = checked(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.getuid()
             and stat.S_IMODE(before.st_mode) == 0o400,
             'owned-single-link-public-leaf')
        raw = handle.read()
        after = os.fstat(handle.fileno())
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
            'st_mode', 'st_nlink', 'st_uid')
    need(all(getattr(before, key) == getattr(after, key) for key in keys)
         and len(raw) == before.st_size, 'stable-public-leaf')
    digest = hashlib.sha256(raw).hexdigest()
    if expected is not None:
        need(digest == word(expected), 'selected-public-leaf-hash')
    return raw, digest


def read_public(path, expected=None):
    raw, digest = read_leaf(path, expected)
    return parse(raw), raw, digest


def write_new(path, value):
    path = checked(path); raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(raw).hexdigest()


def reference(value):
    fields(value, ('path', 'sha256'))
    return read_public(value['path'], value['sha256'])


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def file_sha256(name):
    return hashlib.sha256((Path(__file__).absolute().parent / name)
                          .read_bytes()).hexdigest()


def coverage_policy_sha256():
    policy = {
        'schema': 'kpb-privacy-coverage-policy/v1',
        'required_categories': {
            view: list(gate.REQUIRED_CATEGORIES[view])
            for view in gate.VIEWS
        },
        'rounds': list(gate.ROUNDS),
        'terminal_scope': gate.TERMINAL_SCOPE,
        'step3_terminal_gate': gate.STEP3_TERMINAL_GATE,
        'nonempty_retry_or_reorg': 'UNQUALIFIED',
        'public_individual_amount_join_fields': 0,
    }
    return hashlib.sha256(encoded(policy)).hexdigest()


def expected_common_security():
    runtime = source_closure.runtime_identity()
    capture_launcher = Path(__file__).absolute().parent / \
        'privacy_actual_capture_launch.py'
    need(capture_launcher.is_file(), 'capture-launcher-source-present')
    return {
        'method_sha256': hashlib.sha256(METHOD_PATH.read_bytes()).hexdigest(),
        'measurement_freeze_sha256': hashlib.sha256(
            MEASUREMENT_FREEZE_PATH.read_bytes()).hexdigest(),
        'workload_sha256': hashlib.sha256(WORKLOAD_PATH.read_bytes()).hexdigest(),
        'observer_source_sha256': source_closure.digest('observer'),
        'capture_source_sha256': file_sha256('privacy_actual_capture.py'),
        'coverage_policy_sha256': coverage_policy_sha256(),
        'bundle_producer_source_sha256': source_sha256(),
        'owner_comparison_source_sha256':
            file_sha256('privacy_owner_comparison.py'),
        'owner_comparison_launcher_source_sha256':
            file_sha256('privacy_owner_comparison_launch.py'),
        'capture_producer_source_sha256':
            file_sha256('privacy_capture_producer.py'),
        'capture_launcher_source_sha256': hashlib.sha256(
            capture_launcher.read_bytes()).hexdigest(),
        'source_closure_sha256': source_closure.all_digests(),
        'runtime_identity_sha256': source_closure.runtime_digest(),
        'python_runtime_sha256': runtime['python_runtime_sha256'],
        'namespace_tool_sha256': runtime['namespace_tool_sha256'],
        'root_guard_helper_sha256': runtime['root_guard_helper_sha256'],
        'host_runtime_trust_boundary':
            runtime['host_runtime_trust_boundary'],
    }


def validate_run(value, expected_classification, common):
    fields(value, RUN_FIELDS)
    need(value['schema'] == ACTUAL_RUN_SCHEMA
         and value['scope'] == 'FRESH_UNFUNDED_ACTUAL_PRIVATE_BATCH'
         and value['classification'] == expected_classification,
         'actual-run-selection')
    for name in ('method_sha256', 'measurement_freeze_sha256',
                 'workload_sha256', 'observer_source_sha256',
                 'capture_source_sha256', 'coverage_policy_sha256',
                 'bundle_producer_source_sha256',
                 'owner_comparison_source_sha256',
                 'owner_comparison_launcher_source_sha256',
                 'capture_producer_source_sha256',
                 'capture_launcher_source_sha256',
                 'runtime_identity_sha256', 'python_runtime_sha256',
                 'namespace_tool_sha256', 'root_guard_helper_sha256'):
        word(value[name]); need(value[name] == common[name], 'common-' + name)
    # No actual producer build or launcher is selected yet.  These remain
    # syntactically present so a future reviewed schema can bind them, but are
    # never treated as authority merely because they are digest-shaped.
    word(value['capture_producer_build_sha256'])
    word(value['capture_producer_launcher_source_sha256'])
    need(value['source_closure_sha256'] ==
            common['source_closure_sha256']
         and value['host_runtime_trust_boundary'] ==
            common['host_runtime_trust_boundary'],
         'common-source-runtime-closure')
    gate.validate_binding(value['binding'])
    need(value['binding']['method_sha256'] == value['method_sha256'],
         'binding-method')
    need(type(value['trial_label']) is str
         and re.fullmatch('[a-z][a-z0-9-]{0,63}', value['trial_label']),
         'trial-label')
    public_root = checked(value['public_root'])
    need(public_root == PUBLIC_BASE / value['trial_label'] /
         'privacy-diagnostics', 'fixed-actual-public-root')
    need(type(value['capture_identity']) is str
         and str(uuid.UUID(value['capture_identity'])) ==
             value['capture_identity'], 'capture-identity')
    need(checked(value['capture_producer_receipt']['path']) ==
         public_root / 'capture-producer' / 'PUBLIC.json',
         'fixed-capture-producer-receipt-path')
    producer_receipt, _, producer_receipt_sha = reference(
        value['capture_producer_receipt'])
    fields(producer_receipt, PRODUCER_RECEIPT_FIELDS)
    need(producer_receipt['schema'] ==
            'kpb-capture-producer-receipt/v1'
         and producer_receipt['binding'] == value['binding']
         and producer_receipt['classification'] == expected_classification
         and producer_receipt['capture_identity'] ==
            value['capture_identity']
         and producer_receipt['append_only_roots_closed'] is True
         and producer_receipt['unknown_record_count'] == 0
         and all(producer_receipt[name] is True for name in (
             'role_hooks_integrated', 'fixed_fd_inheritance_selected',
             'launcher_selected', 'launch_authorized',
             'actual_receipt_emitted')),
         'source-produced-capture-receipt')
    for name in ('producer_source_sha256', 'producer_build_sha256',
                 'producer_role_launch_sha256'):
        word(producer_receipt[name])
    need(producer_receipt['producer_source_sha256'] ==
            value['capture_producer_source_sha256']
         and producer_receipt['producer_build_sha256'] ==
            value['capture_producer_build_sha256']
         and producer_receipt['producer_role_launch_sha256'] ==
            value['capture_producer_launcher_source_sha256'],
         'selected-capture-producer-authority')
    need(type(value['financial_rounds']) is list
         and len(value['financial_rounds']) == 2,
         'selected-two-financial-rounds')
    flattened_financial = []
    for number, selected in zip((1, 2), value['financial_rounds']):
        fields(selected, FINANCIAL_ROUND_FIELDS)
        need(selected['round'] == number, 'selected-financial-round-order')
        word(selected['financial_run_id'])
        _, _, artifacts_sha = reference(selected['financial_artifacts'])
        _, _, result_sha = reference(selected['financial_result'])
        projection_path = checked(selected['retained_projection']['path'])
        projection_raw, projection_sha = read_leaf(
            projection_path, selected['retained_projection']['sha256'])
        need(len(projection_raw) == 10685,
             'selected-financial-projection-width')
        flattened_financial.append({
            'round': number,
            'financial_run_id': selected['financial_run_id'],
            'financial_artifacts_sha256': artifacts_sha,
            'financial_result_sha256': result_sha,
            'retained_projection_sha256': projection_sha,
        })
    need(flattened_financial[0]['financial_run_id'] !=
            flattened_financial[1]['financial_run_id']
         and flattened_financial[0]['retained_projection_sha256'] !=
            flattened_financial[1]['retained_projection_sha256'],
         'fresh-selected-financial-rounds')
    need(producer_receipt['financial_rounds'] == flattened_financial,
         'producer-financial-round-binding')
    need(type(producer_receipt['rounds']) is list
         and len(producer_receipt['rounds']) == 2,
         'producer-two-rounds')
    producer_attempts = []
    for number, row in zip((1, 2), producer_receipt['rounds']):
        fields(row, PRODUCER_ROUND_FIELDS)
        need(row['round'] == number
             and type(row['attempt_id']) is str
             and str(uuid.UUID(row['attempt_id'])) == row['attempt_id']
             and type(row['artifacts']) is list
             and [artifact.get('kind') for artifact in row['artifacts']] ==
                list(CAPTURE_ARTIFACT_ORDER),
             'producer-round-identity')
        producer_attempts.append(row['attempt_id'])
        word(row['cohort_sha256'])
        for artifact in row['artifacts']:
            fields(artifact, PRODUCER_ARTIFACT_FIELDS)
            for name in ('producer_record_count', 'capture_record_count',
                         'producer_payload_bytes', 'capture_payload_bytes'):
                nonnegative(artifact[name], 'producer-' + name,
                            positive=False)
            need(artifact['producer_record_count'] ==
                    artifact['capture_record_count']
                 and artifact['producer_payload_bytes'] ==
                    artifact['capture_payload_bytes']
                 and artifact['capture_root_closed'] is True
                 and artifact['producer_fd_closed'] is True,
                 'producer-artifact-closure')
            word(artifact['record_chain_sha256'])
    need(len(set(producer_attempts)) == 2,
         'producer-distinct-round-attempts')
    diagnostic, diagnostic_raw, diagnostic_sha = reference(
        value['diagnostic_selection'])
    fields(diagnostic, DIAGNOSTIC_FIELDS)
    need(diagnostic['schema'] ==
            DIAGNOSTIC_SCHEMA
         and diagnostic['binding'] == value['binding']
         and diagnostic['expected_classification'] ==
            expected_classification
         and diagnostic['source_closure_sha256'] ==
            common['source_closure_sha256']
         and diagnostic['runtime_identity_sha256'] ==
            common['runtime_identity_sha256']
         and diagnostic['capture_producer_receipt'] ==
            value['capture_producer_receipt']
         and diagnostic['financial_rounds'] == value['financial_rounds']
         and len(diagnostic_raw) > 0,
         'diagnostic-selection-binding')
    need(type(diagnostic['source_members']) is list
         and [row.get('name') for row in diagnostic['source_members']] ==
            list(DIAGNOSTIC_SOURCE_NAMES),
         'diagnostic-exact-source-member-order')
    for row, name in zip(diagnostic['source_members'],
                         DIAGNOSTIC_SOURCE_NAMES):
        fields(row, ('name', 'sha256'))
        need(row['name'] == name and row['sha256'] == file_sha256(name),
             'diagnostic-executing-source-' + name)
    need(type(diagnostic['rounds']) is list
         and len(diagnostic['rounds']) == 2
         and [row.get('round') for row in diagnostic['rounds']] == [1, 2],
         'diagnostic-two-round-selection')
    for row, financial in zip(diagnostic['rounds'],
                              value['financial_rounds']):
        fields(row, ('round', 'pay_result', 'financial_round'))
        reference(row['pay_result'])
        need(row['financial_round'] == financial,
             'diagnostic-financial-round-binding')
    need(diagnostic['corrupt_server_view'] == {
        'owner_component': 1,
        'capture_kind': 'corrupt-server-capture',
    }, 'diagnostic-required-one-corrupt-server')
    _, _, diagnostic_run_sha = reference(diagnostic['run_selection'])
    need(diagnostic_run_sha == value['binding']['selection_sha256'],
         'diagnostic-inner-run-selection-binding')
    return {**value,
            '_diagnostic_selection_sha256': diagnostic_sha,
            '_diagnostic_run_selection_sha256': diagnostic_run_sha,
            '_capture_producer_receipt_sha256': producer_receipt_sha,
            '_financial_rounds': flattened_financial}


def load_comparison(path, expected_sha256):
    comparison, _, digest = read_public(path, expected_sha256)
    fields(comparison, COMPARISON_FIELDS)
    need(comparison['schema'] == COMPARISON_SCHEMA,
         'comparison-schema')
    need({name: comparison[name] for name in
          expected_common_security()} == expected_common_security(),
         'executing-common-source-freeze-runtime-pins')
    for name in ('capture_producer_build_sha256',
                 'capture_producer_launcher_source_sha256'):
        word(comparison[name])
    # privacy_capture_producer.py currently has no selected role hooks,
    # inherited-FD launcher, or actual receipt schema.  Refuse before reading
    # either run so a synthetic/self-authored receipt cannot acquire "actual"
    # status from the downstream observer chain.  Activation requires a
    # reviewed source change and a new adversarial control.
    need(False, 'actual-capture-producer-launch-authority-absent')
    need(type(comparison['runs']) is list and len(comparison['runs']) == 2,
         'two-actual-run-selections')
    runs = []
    for expected, selected in zip(CLASSIFICATIONS, comparison['runs']):
        fields(selected, ('classification', 'path', 'sha256'))
        need(selected['classification'] == expected,
             'fixed-run-classification-order')
        run, _, run_sha = read_public(selected['path'], selected['sha256'])
        runs.append((run_sha, validate_run(run, expected, comparison)))
    baseline, candidate = [row[1] for row in runs]
    need(runs[0][0] != runs[1][0]
         and baseline['binding']['selection_sha256'] !=
             candidate['binding']['selection_sha256']
         and baseline['binding']['trial_id'] != candidate['binding']['trial_id']
         and baseline['binding']['attempt_id'] !=
             candidate['binding']['attempt_id']
         and baseline['capture_identity'] != candidate['capture_identity']
         and baseline['public_root'] != candidate['public_root'],
         'distinct-fresh-actual-runs')
    need(not ({row['financial_run_id'] for row in
               baseline['_financial_rounds']} &
              {row['financial_run_id'] for row in
               candidate['_financial_rounds']})
         and not ({row['retained_projection_sha256'] for row in
                   baseline['_financial_rounds']} &
                  {row['retained_projection_sha256'] for row in
                   candidate['_financial_rounds']}),
         'distinct-baseline-candidate-financial-evidence')
    return digest, comparison, runs


def nonnegative(value, category, positive=False):
    need(type(value) is int and value >= int(positive), category)
    return value


def coverage(value):
    fields(value, ('modeled_artifacts', 'unmodeled_artifacts',
                   'missing_artifacts', 'terminal_modeled'))
    for name in ('modeled_artifacts', 'unmodeled_artifacts',
                 'missing_artifacts'):
        nonnegative(value[name], 'coverage-' + name)
    need(type(value['terminal_modeled']) is bool, 'terminal-modeled-boolean')
    return value


def validate_capture(value, comparison_sha, run_sha, run):
    fields(value, CAPTURE_FIELDS)
    need(value['schema'] == 'kpb-privacy-actual-capture-receipt/v2'
         and value['comparison_selection_sha256'] == comparison_sha
         and value['run_selection_sha256'] == run_sha
         and value['classification'] == run['classification']
         and value['binding'] == run['binding']
         and value['capture_identity'] == run['capture_identity'],
         'capture-selection-binding')
    for name in ('method_sha256', 'workload_sha256',
                 'observer_source_sha256', 'capture_source_sha256',
                 'coverage_policy_sha256'):
        need(value[name] == run[name], 'capture-' + name)
    word(value['capture_manifest_seal_sha256'])
    word(value['construction_classification_receipt_sha256'])
    need(value['capture_producer_receipt_sha256'] ==
            run['_capture_producer_receipt_sha256']
         and value['source_closure_sha256'] ==
            run['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
            run['runtime_identity_sha256'],
         'capture-source-producer-runtime-chain')
    need(value['capture_roots_closed'] is True
         and value['exact_union_derived'] is True
         and value['predictions_or_truth_mounted'] is False
         and value['private_artifact_paths_hashes_or_bodies_exported'] is False,
         'capture-pretruth-no-private-export')
    need(value['terminal_scope'] == gate.TERMINAL_SCOPE,
         'bounded-terminal-scope')
    need(value['step3_terminal_gate'] == gate.STEP3_TERMINAL_GATE,
         'separate-step3-terminal-gate')
    need(type(value['views']) is list and len(value['views']) == 4,
         'capture-four-views')
    result = {}
    for expected_view, row in zip(gate.VIEWS, value['views']):
        fields(row, CAPTURE_VIEW_FIELDS)
        need(row['view'] == expected_view
             and row['categories'] ==
                list(gate.REQUIRED_CATEGORIES[expected_view]),
             'capture-exact-categories-' + expected_view)
        need(type(row['rounds']) is list and len(row['rounds']) == 2,
             'capture-two-rounds')
        totals = {'modeled_artifacts': 0, 'unmodeled_artifacts': 0,
                  'missing_artifacts': 0}
        category_totals = {category: {
            'modeled_artifacts': 0, 'unmodeled_artifacts': 0,
            'missing_artifacts': 0, 'constraint_modeled_fields': 0,
            'source_assumption_covered_fields': 0,
            'unmodeled_fields': 0}
            for category in gate.REQUIRED_CATEGORIES[expected_view]}
        terminals = []
        for expected_round, observed in zip((1, 2), row['rounds']):
            fields(observed, CAPTURE_ROUND_FIELDS)
            need(observed['round'] == expected_round,
                 'capture-round-order')
            nonnegative(observed['artifact_count'], 'artifact-count', True)
            nonnegative(observed['artifact_bytes'], 'artifact-bytes', True)
            categories = observed['category_coverage']
            need(type(categories) is dict
                 and set(categories) ==
                    set(gate.REQUIRED_CATEGORIES[expected_view]),
                 'capture-round-category-set')
            need(type(observed['category_counts']) is dict
                 and set(observed['category_counts']) == set(categories),
                 'capture-round-category-count-set')
            for category in gate.REQUIRED_CATEGORIES[expected_view]:
                item = categories[category]
                fields(item, ('modeled_artifacts', 'unmodeled_artifacts',
                              'missing_artifacts',
                              'constraint_modeled_fields',
                              'source_assumption_covered_fields',
                              'unmodeled_fields'))
                nonnegative(item['modeled_artifacts'],
                            'category-modeled-' + category, True)
                for name in ('unmodeled_artifacts', 'missing_artifacts',
                             'constraint_modeled_fields',
                             'source_assumption_covered_fields',
                             'unmodeled_fields'):
                    nonnegative(item[name], 'category-' + name)
                need(type(observed['category_counts'][category]) is int
                     and observed['category_counts'][category] ==
                        item['modeled_artifacts'] + item['missing_artifacts']
                     and item['unmodeled_artifacts'] <=
                        item['modeled_artifacts']
                     and ((item['unmodeled_fields'] > 0) ==
                          (item['unmodeled_artifacts'] > 0))
                     and item['constraint_modeled_fields'] +
                        item['source_assumption_covered_fields'] +
                        item['unmodeled_fields'] > 0,
                     'category-count-reconciled-' + category)
                for name in category_totals[category]:
                    category_totals[category][name] += item[name]
            for name in totals:
                totals[name] += nonnegative(observed[name], name)
            need(type(observed['terminal_modeled']) is bool,
                 'round-terminal-modeled')
            terminals.append(observed['terminal_modeled'])
        expected_coverage = {**totals,
                             'terminal_modeled': all(terminals)}
        need(coverage(row['coverage']) == expected_coverage,
             'capture-view-coverage-total')
        result[expected_view] = {**row,
                                 '_category_coverage': category_totals}
    return result


def validate_construction(value, comparison_sha, run_sha, run,
                          capture_value, construction_sha):
    fields(value, CONSTRUCTION_FIELDS)
    expected_hidden = run['classification'] == \
        'ACTUAL_HIDDEN_MAPPING_CANDIDATE'
    need(value['schema'] ==
            'kpb-financial-construction-classification/v1'
         and value['comparison_selection_sha256'] == comparison_sha
         and value['run_selection_sha256'] == run_sha
         and value['classification'] == run['classification']
         and value['capture_source_sha256'] == run['capture_source_sha256']
         and value['capture_producer_receipt_sha256'] ==
            run['_capture_producer_receipt_sha256']
         and value['source_closure_sha256'] ==
            run['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
            run['runtime_identity_sha256']
         and value['financial_run_id'] == [row['financial_run_id']
             for row in run['_financial_rounds']]
         and value['projection_sha256'] == [
             row['retained_projection_sha256']
             for row in run['_financial_rounds']]
         and value['terminal_grouping_mode'] ==
            ('ONE_UNLABELLED_3NF_6TUPLE_GROUP' if expected_hidden else
             'THREE_OWNER_LABELLED_1NF_2TUPLE_GROUPS')
         and value['direct_owner_mapping_exposed'] is not expected_hidden
         and value['caller_overlay'] is False
         and value['private_owner_or_slot_identifiers_exported'] is False
         and value['terminal_scope'] == gate.TERMINAL_SCOPE
         and value['step3_terminal_gate'] == gate.STEP3_TERMINAL_GATE
         and construction_sha == capture_value[
             'construction_classification_receipt_sha256'],
         'source-derived-construction-classification')
    return value


def validate_capture_launch(value, comparison_sha, run_sha, run,
                            capture_path, capture_sha, capture_value,
                            construction_sha):
    # The selected v2 launcher is deliberately hard-disabled until a genuine
    # five-role build/supervisor/outer-launch authority exists. Field-shaped
    # self-authored LAUNCH.json cannot bypass that executable policy.
    capture_launcher.validate_launch_receipt(value)
    fields(value, CAPTURE_LAUNCH_FIELDS)
    runtime = source_closure.runtime_identity()
    need(value['schema'] == CAPTURE_LAUNCH_SCHEMA
         and value['operation'] == 'actual-capture'
         and value['binding'] == run['binding']
         and value['comparison_selection_sha256'] == comparison_sha
         and value['run_selection_sha256'] == run_sha
         and value['diagnostic_selection_sha256'] ==
            run['_diagnostic_selection_sha256']
         and value['classification'] == run['classification']
         and value['capture_identity'] == run['capture_identity']
         and value['capture_launcher_source_sha256'] ==
            run['capture_launcher_source_sha256']
         and value['source_closure_sha256'] ==
            run['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
            run['runtime_identity_sha256']
         and value['python_runtime_sha256'] ==
            runtime['python_runtime_sha256']
         and value['namespace_tool_sha256'] ==
            runtime['namespace_tool_sha256']
         and value['root_guard_helper_sha256'] ==
            runtime['root_guard_helper_sha256']
         and value['host_runtime_trust_boundary'] ==
            runtime['host_runtime_trust_boundary']
         and value['capture_producer_receipt_sha256'] ==
            run['_capture_producer_receipt_sha256']
         and value['financial_rounds'] == run['_financial_rounds']
         and value['construction_classification_receipt_sha256'] ==
            construction_sha == capture_value[
                'construction_classification_receipt_sha256']
         and value['capture_receipt_sha256'] == capture_sha
         and value['capture_manifest_seal_sha256'] ==
            capture_value['capture_manifest_seal_sha256']
         and checked(value['public_result']) == capture_path
         and value['public_result_sha256'] == capture_sha
         and value['persistent_capture_consumed'] is True
         and value['capture_roots_closed'] is True
         and value['financial_host_crypto_rechecked'] is True
         and value['network_enabled'] is False
         and value['predictions_or_truth_mounted'] is False
         and value['private_capture_bodies_read_inside_namespace'] is True
         and value['private_artifact_paths_hashes_or_bodies_exported']
            is False
         and value['terminal_scope'] == gate.TERMINAL_SCOPE
         and value['step3_terminal_gate'] == gate.STEP3_TERMINAL_GATE,
         'exact-selected-actual-capture-launch')
    return value


def validate_observation(value, comparison_sha, run_sha, run,
                         capture_sha, capture_value, capture_views):
    fields(value, OBSERVATION_FIELDS)
    need(value['schema'] == 'kpb-direct-observation-receipt/v2'
         and value['binding'] == run['binding']
         and value['comparison_selection_sha256'] == comparison_sha
         and value['run_selection_sha256'] == run_sha
         and value['capture_receipt_sha256'] == capture_sha
         and value['capture_manifest_seal_sha256'] ==
             capture_value['capture_manifest_seal_sha256']
         and value['construction_classification_receipt_sha256'] ==
             capture_value['construction_classification_receipt_sha256']
         and value['capture_producer_receipt_sha256'] ==
             capture_value['capture_producer_receipt_sha256']
         and value['source_closure_sha256'] ==
             run['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
             run['runtime_identity_sha256']
         and value['terminal_scope'] == capture_value['terminal_scope']
         and value['step3_terminal_gate'] ==
             capture_value['step3_terminal_gate']
         and value['predictions_frozen_before_truth'] is True
         and value['private_view_or_prediction_records_exported'] is False,
         'observation-pretruth-chain')
    need(type(value['views']) is list and len(value['views']) == 4,
         'observation-four-views')
    for expected, row in zip(gate.VIEWS, value['views']):
        fields(row, OBSERVATION_VIEW_FIELDS)
        need(row['view'] == expected, 'observation-view-order')
        word(row['capsule_seal_sha256'])
        nonnegative(row['capsule_bytes'], 'capsule-bytes', True)
        need(type(row['rounds']) is list and len(row['rounds']) == 2,
             'observation-two-rounds')
        need(coverage(row['coverage']) ==
             capture_views[expected]['coverage'],
             'observation-capture-coverage')
        gate.validate_category_coverage(row['category_coverage'], expected)
        need(row['category_coverage'] ==
             capture_views[expected]['_category_coverage'],
             'observation-capture-category-reconciliation')
        fields(row['workload'], OBSERVATION_WORKLOAD_FIELDS)
        nonnegative(row['workload']['full_workload_candidates'],
                    'observation-full-workload-candidates')
        need(row['workload']['full_workload_candidates'] <= 291600
             and type(row['workload']['cross_round_constraints_modeled'])
                is bool
             and type(row['workload']['terminal_constraints_modeled'])
                is bool,
             'observation-workload-model')
        word(row['workload']['candidate_set_commitment_sha256'])
        fields(row['lattice_attestation'], gate.LATTICE_FIELDS)
        need(all(row['lattice_attestation'][name] is True
                 for name in gate.LATTICE_FIELDS),
             'observation-lattice-attestation')
    need(len({row['capsule_seal_sha256'] for row in value['views']}) == 4,
         'distinct-observation-capsules')
    return value


def validate_barrier(value, comparison_sha, run_sha, run, capture_sha,
                     capture_value, observation_sha, observation):
    fields(value, BARRIER_FIELDS)
    expected_capsules = [
        {'view': row['view'],
         'capsule_seal_sha256': row['capsule_seal_sha256']}
        for row in observation['views']
    ]
    need(value == {
        'schema': 'kpb-direct-prediction-barrier/v2',
        'binding': run['binding'],
        'comparison_selection_sha256': comparison_sha,
        'run_selection_sha256': run_sha,
        'capture_receipt_sha256': capture_sha,
        'capture_manifest_seal_sha256':
            capture_value['capture_manifest_seal_sha256'],
        'construction_classification_receipt_sha256':
            capture_value['construction_classification_receipt_sha256'],
        'capture_producer_receipt_sha256':
            capture_value['capture_producer_receipt_sha256'],
        'source_closure_sha256': run['source_closure_sha256'],
        'runtime_identity_sha256': run['runtime_identity_sha256'],
        'terminal_scope': capture_value['terminal_scope'],
        'step3_terminal_gate': capture_value['step3_terminal_gate'],
        'observation_receipt_sha256': observation_sha,
        'capsules': expected_capsules,
    }, 'exact-pretruth-barrier')


def validate_launch(value, operation, run, result_path, result_sha):
    diagnostic_launcher.validate_launch_receipt(value, operation)
    fields(value, LAUNCH_FIELDS)
    need(value['schema'] == 'kpb-private-diagnostic-launch-result/v1'
         and value['operation'] == operation
         and value['binding'] == run['binding']
         and value['selection_sha256'] ==
             run['diagnostic_selection']['sha256']
         and checked(value['public_result']) == result_path
         and value['public_result_sha256'] == result_sha
         and value['persistent_query_consumed'] is True
         and value['private_bodies_read_or_hashed'] is False
         and value['network_enabled'] is False,
         'actual-' + operation + '-launch')
    runtime = source_closure.runtime_identity()
    need(value['source_closure_sha256'] == run['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
            run['runtime_identity_sha256']
         and value['python_runtime_sha256'] ==
            runtime['python_runtime_sha256']
         and value['namespace_tool_sha256'] ==
            runtime['namespace_tool_sha256']
         and value['root_guard_helper_sha256'] ==
            runtime['root_guard_helper_sha256']
         and value['host_runtime_trust_boundary'] ==
            runtime['host_runtime_trust_boundary'],
         'actual-launch-source-runtime-closure')


def validate_score(value, owner, comparison_sha, run_sha, run, barrier_sha):
    fields(value, SCORE_FIELDS)
    need(value['schema'] == 'kpb-private-score-completed/v2'
         and value['binding'] == run['binding']
         and value['comparison_selection_sha256'] == comparison_sha
         and value['run_selection_sha256'] == run_sha
         and value['barrier_sha256'] == barrier_sha
         and value['owner_component'] == owner
         and value['source_closure_sha256'] ==
            run['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
            run['runtime_identity_sha256']
         and value['step3_terminal_gate'] == gate.STEP3_TERMINAL_GATE
         and value['per_owner_counts_or_truth_exported'] is False,
         'actual-one-owner-score')


def validate_aggregate(value, comparison_sha, run_sha, run, capture_sha,
                       barrier_sha, observation, capture_views):
    fields(value, AGGREGATE_FIELDS)
    need(value['schema'] == 'kpb-public-all-view-direct-counts/v2'
         and value['binding'] == run['binding']
         and value['comparison_selection_sha256'] == comparison_sha
         and value['run_selection_sha256'] == run_sha
         and value['capture_receipt_sha256'] == capture_sha
         and value['barrier_sha256'] == barrier_sha
         and value['capture_producer_receipt_sha256'] ==
            run['_capture_producer_receipt_sha256']
         and value['source_closure_sha256'] ==
            run['source_closure_sha256']
         and value['runtime_identity_sha256'] ==
            run['runtime_identity_sha256']
         and value['step3_terminal_gate'] == gate.STEP3_TERMINAL_GATE
         and value['private_records_masks_or_per_owner_counts_exported']
            is False
         and type(value['views']) is list and len(value['views']) == 4,
         'actual-aggregate-chain')
    fields(value['lattice_attestation'], gate.LATTICE_FIELDS)
    need(all(value['lattice_attestation'][name] is True
             for name in gate.LATTICE_FIELDS),
         'aggregate-lattice-attestation')
    result = []
    for expected, row, observed in zip(gate.VIEWS, value['views'],
                                       observation['views']):
        checked_view = gate.validate_view(row, expected)
        need(row['binding'] == run['binding']
             and row['capsule_seal_sha256'] ==
                 observed['capsule_seal_sha256']
             and row['coverage'] == observed['coverage']
             and row['coverage'] == capture_views[expected]['coverage']
             and row['category_coverage'] ==
                 observed['category_coverage']
             and all(row['workload'][name] == observed['workload'][name]
                     for name in OBSERVATION_WORKLOAD_FIELDS),
             'aggregate-observation-capture-' + expected)
        result.append(row)
    need(gate.union_is_monotone({view: row for view, row in
         zip(gate.VIEWS, result)}), 'aggregate-candidate-subset-lattice')
    return result


def produce(comparison_path, comparison_sha256, run_index):
    need(type(run_index) is int and run_index in (0, 1), 'run-index')
    comparison_sha, _, runs = load_comparison(comparison_path,
                                              comparison_sha256)
    run_sha, run = runs[run_index]
    root = checked(run['public_root'])

    capture_path = root / 'capture' / 'PUBLIC.json'
    capture_value, _, capture_sha = read_public(capture_path)
    capture_views = validate_capture(capture_value, comparison_sha,
                                     run_sha, run)
    construction_value, _, construction_sha = read_public(
        root / 'capture' / 'CONSTRUCTION.json')
    validate_construction(construction_value, comparison_sha, run_sha, run,
                          capture_value, construction_sha)
    capture_launch_value, _, capture_launch_sha = read_public(
        root / 'capture' / 'LAUNCH.json')
    validate_capture_launch(capture_launch_value, comparison_sha, run_sha,
                            run, capture_path, capture_sha, capture_value,
                            construction_sha)

    observation_path = root / 'observe' / 'PUBLIC.json'
    observation_value, _, observation_sha = read_public(observation_path)
    observation = validate_observation(
        observation_value, comparison_sha, run_sha, run, capture_sha,
        capture_value, capture_views)

    barrier_path = root / 'observe' / 'BARRIER.json'
    barrier_value, _, barrier_sha = read_public(barrier_path)
    validate_barrier(barrier_value, comparison_sha, run_sha, run,
                     capture_sha, capture_value, observation_sha,
                     observation)

    observation_launch, _, observation_launch_sha = read_public(
        root / 'observe' / 'LAUNCH.json')
    validate_launch(observation_launch, 'observe', run,
                    observation_path, observation_sha)

    score_receipts, score_launches = [], []
    for owner in (0, 1, 2):
        score_root = root / ('score-owner-' + str(owner))
        score_path = score_root / 'PUBLIC.json'
        score, _, score_sha = read_public(score_path)
        validate_score(score, owner, comparison_sha, run_sha, run,
                       barrier_sha)
        score_launch, _, score_launch_sha = read_public(
            score_root / 'LAUNCH.json')
        validate_launch(score_launch, 'score', run, score_path, score_sha)
        score_receipts.append(score_sha); score_launches.append(score_launch_sha)

    aggregate_path = root / 'aggregate' / 'PUBLIC.json'
    aggregate, _, aggregate_sha = read_public(aggregate_path)
    views = validate_aggregate(aggregate, comparison_sha, run_sha, run,
                               capture_sha, barrier_sha, observation,
                               capture_views)
    aggregate_launch, _, aggregate_launch_sha = read_public(
        root / 'aggregate' / 'LAUNCH.json')
    validate_launch(aggregate_launch, 'aggregate', run, aggregate_path,
                    aggregate_sha)

    bundle = {
        'schema': 'kpb-privacy-all-view-bundle/v2',
        'classification': run['classification'],
        'comparison_selection_sha256': comparison_sha,
        'run_selection_sha256': run_sha,
        'diagnostic_selection_sha256':
            run['diagnostic_selection']['sha256'],
        'diagnostic_run_selection_sha256':
            run['_diagnostic_run_selection_sha256'],
        'binding': run['binding'],
        'method_sha256': run['method_sha256'],
        'measurement_freeze_sha256': run['measurement_freeze_sha256'],
        'workload_sha256': run['workload_sha256'],
        'observer_source_sha256': run['observer_source_sha256'],
        'capture_source_sha256': run['capture_source_sha256'],
        'coverage_policy_sha256': run['coverage_policy_sha256'],
        'bundle_producer_source_sha256':
            run['bundle_producer_source_sha256'],
        'owner_comparison_source_sha256':
            run['owner_comparison_source_sha256'],
        'owner_comparison_launcher_source_sha256':
            run['owner_comparison_launcher_source_sha256'],
        'capture_producer_source_sha256':
            run['capture_producer_source_sha256'],
        'capture_producer_build_sha256':
            run['capture_producer_build_sha256'],
        'capture_producer_launcher_source_sha256':
            run['capture_producer_launcher_source_sha256'],
        'capture_launcher_source_sha256':
            run['capture_launcher_source_sha256'],
        'source_closure_sha256': run['source_closure_sha256'],
        'runtime_identity_sha256': run['runtime_identity_sha256'],
        'python_runtime_sha256': run['python_runtime_sha256'],
        'namespace_tool_sha256': run['namespace_tool_sha256'],
        'root_guard_helper_sha256': run['root_guard_helper_sha256'],
        'host_runtime_trust_boundary':
            run['host_runtime_trust_boundary'],
        'capture_identity': run['capture_identity'],
        'capture_receipt_sha256': capture_sha,
        'capture_manifest_seal_sha256':
            capture_value['capture_manifest_seal_sha256'],
        'construction_classification_receipt_sha256':
            capture_value['construction_classification_receipt_sha256'],
        'capture_producer_receipt_sha256':
            run['_capture_producer_receipt_sha256'],
        'capture_launch_receipt_sha256': capture_launch_sha,
        'financial_rounds': run['_financial_rounds'],
        'terminal_scope': capture_value['terminal_scope'],
        'step3_terminal_gate': capture_value['step3_terminal_gate'],
        'observation_receipt_sha256': observation_sha,
        'observation_launch_sha256': observation_launch_sha,
        'barrier_sha256': barrier_sha,
        'score_receipt_sha256': score_receipts,
        'score_launch_sha256': score_launches,
        'aggregate_result_sha256': aggregate_sha,
        'aggregate_launch_sha256': aggregate_launch_sha,
        'coverage_categories': {
            view: list(gate.REQUIRED_CATEGORIES[view])
            for view in gate.VIEWS
        },
        'lattice_attestation': aggregate['lattice_attestation'],
        'views': views,
    }
    gate.validate_bundle(bundle, run['classification'])
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--comparison', required=True)
    parser.add_argument('--comparison-sha256', required=True)
    parser.add_argument('--run-index', required=True, type=int, choices=(0, 1))
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_new(args.output, produce(args.comparison,
        args.comparison_sha256, args.run_index))


if __name__ == '__main__':
    main()
