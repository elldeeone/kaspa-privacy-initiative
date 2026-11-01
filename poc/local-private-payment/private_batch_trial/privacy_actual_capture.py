#!/usr/bin/env python3
"""Validate/model one pre-truth two-round observer-capture receipt.

The CLI worker is deliberately hard-disabled before namespace or private
input access because no genuine producer build receipt and outer-supervisor
completion authority are selected.  Pure validation/model functions remain
available for synthetic controls, but their result is not actual authority.
A future selected launcher must run this worker in a network-off namespace,
retain the salted private manifest and models, and emit a separate immutable
launch receipt. `privacy_capture_bundle.py` must join that launch receipt.

The worker accepts exactly five typed artifacts per round, derives every view
and the union internally, and binds both rounds to completed public financial
handoffs.  It never accepts caller-provided coverage, categories, constraints,
view membership, construction classification, or a success Boolean.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import uuid

import privacy_capture_model as capture
import privacy_codec as codec
import privacy_observer as observer
import privacy_source_closure as source_closure


VIEWS = ('public', 'dispatcher', 'corrupt-server-plus-wallet', 'union')
CLASSIFICATIONS = (
    'ACTUAL_TRANSPARENT_BASELINE',
    'ACTUAL_HIDDEN_MAPPING_CANDIDATE',
)
TERMINAL_SCOPE = 'PRIVATE_BATCH_TERMINAL_ONLY_EXIT_LINKABILITY_UNMEASURED'
STEP3_TERMINAL_GATE = \
    'REQUIRED_SEPARATE_EXIT_LINKABILITY_GATE_BEFORE_STEP3'
MANIFEST_TAG = b'KPBACM01'
SOURCE_MEMBERS = source_closure.ROLE_MEMBERS['actual-capture']
HOST_RUNTIME_TRUST_BOUNDARY = source_closure.HOST_RUNTIME_TRUST_BOUNDARY
# These identities are embedded in the selected public verifier host/profile
# and remain common to Source05 and its successor-head generalization.  The
# qualifier source itself is selected per financial round because that source
# must change before a genuine successor-head round can qualify.
FINANCIAL_AUTHORITY = {
    'component_profile':
        '2598cd4baa438e6fb5c95bc4d1f6b8f1f7db607879f428c43f82a5247aca7f36',
    'outer_selection':
        'c44ac47b38bc80602b8d986e7c36527a0b139470fc5e32e00f94c59069f3d93d',
    'public_host':
        'b367575f9989dc2433357402c459249f8549c8b5ea9e9b78cdc6da94b6789068',
    'namespace_tool':
        '523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6',
    'aggregate_vk':
        '2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102',
    'output_vk':
        '8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119',
    'native_tail':
        '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d',
}
CAPTURE_FILES = {
    'public-projection': 'projection.bin',
    'dispatcher-capture': 'dispatcher.json',
    'corrupt-server-capture': 'corrupt-server.json',
    'colluder-wallet-capture': 'colluder-wallet.json',
    'terminal-history': 'terminal.json',
}
VIEW_KINDS = {
    'public': ('public-projection', 'terminal-history'),
    'dispatcher': ('public-projection', 'terminal-history',
                   'dispatcher-capture'),
    'corrupt-server-plus-wallet': (
        'public-projection', 'terminal-history',
        'corrupt-server-capture', 'colluder-wallet-capture'),
    'union': ('public-projection', 'terminal-history',
              'dispatcher-capture', 'corrupt-server-capture',
              'colluder-wallet-capture'),
}
CONFIG_FIELDS = (
    'schema', 'comparison_selection_sha256', 'run_selection_sha256',
    'classification', 'binding', 'method_sha256', 'workload_sha256',
    'observer_source_sha256', 'capture_source_sha256',
    'coverage_policy_sha256', 'capture_identity',
    'capture_producer_receipt_sha256', 'step3_terminal_gate',
    'capture_producer_source_sha256',
    'capture_producer_build_sha256',
    'capture_producer_role_launch_sha256',
    'capture_producer_role_launch_closure',
    'capture_launcher_source_sha256', 'source_closure_sha256',
    'runtime_identity_sha256', 'python_runtime_sha256', 'namespace_tool_sha256',
    'root_guard_helper_sha256', 'host_runtime_trust_boundary',
    'source_members', 'financial_rounds',
)
FINANCIAL_SELECTION_FIELDS = (
    'round', 'financial_run_id', 'financial_artifacts_sha256',
    'financial_result_sha256', 'retained_projection_sha256',
)
ARTIFACT_RECORD_FIELDS = ('path', 'sha256', 'bytes')
PUBLIC_ARTIFACT_NAMES = (
    'financial_result', 'released_core', 'released_proof',
    'released_projection', 'native_tail', 'retained_projection', 'journal',
    'host_cross_check', 'component_profile', 'outer_selection',
    'public_host', 'namespace_tool', 'qualifier_source',
)
PRODUCER_FIELDS = (
    'schema', 'binding', 'classification', 'capture_identity',
    'producer_source_sha256', 'producer_build_sha256',
    'producer_role_launch_sha256', 'financial_rounds', 'rounds',
    'append_only_roots_closed', 'unknown_record_count',
    'role_hooks_integrated', 'fixed_fd_inheritance_selected',
    'launcher_selected', 'launch_authorized', 'actual_receipt_emitted',
)
PRODUCER_ROUND_FIELDS = (
    'round', 'attempt_id', 'cohort_sha256', 'p1_capture_authority',
    'artifacts',
)
PRODUCER_ARTIFACT_FIELDS = (
    'kind', 'producer_record_count', 'capture_record_count',
    'producer_payload_bytes', 'capture_payload_bytes',
    'record_chain_sha256', 'capture_root_closed', 'producer_fd_closed',
)
PRODUCER_ARTIFACT_ORDER = (
    'public-projection', 'terminal-history', 'dispatcher-capture',
    'corrupt-server-capture', 'colluder-wallet-capture',
)
CONSUMED_FIELDS = (
    'schema', 'comparison_selection_sha256', 'run_selection_sha256',
    'capture_identity',
)
ARTIFACTS_FIELDS = (
    'schema', 'status', 'run_id', 'component_profile_sha256', 'head',
    'successor', 'artifacts', 'effects_sha256', 'core_sha256',
    'aggregate_proof_sha256', 'projection_sha256',
    'egress_binding_sha256', 'successor_state_sha256',
    'successor_script_public_key_hex37', 'accepted_head_authority',
    'R0_or_native_VM_executed', 'R0_receipt_verified',
    'full_native_candidate_validated', 'native_settlement_performed',
)
HANDOFF_FIELDS = (
    'schema', 'status', 'run_id', 'source_scope', 'construction_sha256',
    'validation_sha256', 'effects_sha256', 'core_sha256',
    'aggregate_proof_sha256', 'projection_sha256',
    'egress_binding_sha256', 'financial_result_sha256',
    'component_profile_sha256', 'aggregate_vk_sha256', 'output_vk_sha256',
    'host_sha256', 'namespace_tool_sha256', 'qualifier_source_sha256',
    'outer_selection_sha256', 'outer_image_id_hex32',
    'fixed_old_point_sha256', 'fixed_old_state_sha256',
    'native_tail_sha256', 'fixed_old_spk_sha256',
    'successor_state_sha256', 'successor_spk_sha256', 'journal_sha256',
    'all_three_financial_results_agreed',
    'aggregate_and_six_Output_G16_verified',
    'independent_arkworks_reference_checked',
    'public_state_and_global_balance_verified',
    'fixed_unfunded_head_and_state_matched', 'registered_financial_service',
    'accepted_head_authority', 'R0_or_native_VM_executed',
    'R0_receipt_verified', 'full_native_candidate_validated',
    'native_settlement_performed', 'payment_privacy_qualified',
    'creator_partition_read', 'private_owner_files_or_keys_read_or_hashed',
    'raw_party_diagnostics_read', 'outer_selection_changed',
    'host_namespace_isolated', 'host_network_namespace_unshared',
    'wallet_or_owner_or_host_home_mounted',
)


def need(condition, category):
    if not condition:
        raise ValueError('privacy-actual-capture-' + category)


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
            ValueError('privacy-actual-capture-nonfinite-number')))
    need(encoded(value) == raw, 'canonical-json')
    return value


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def validate_source_closure(value, config):
    closure = {
        'schema': 'kpb-transitive-source-closure/v1',
        'role': 'actual-capture',
        'members': value,
    }
    source_closure.validate_manifest(closure, 'actual-capture')
    actual = {row['name']: row['sha256'] for row in value}
    need(actual['privacy_actual_capture.py'] ==
            config['capture_source_sha256']
         and type(config['source_closure_sha256']) is dict
         and config['source_closure_sha256'].get('actual-capture') ==
            source_closure.digest('actual-capture')
         and config['observer_source_sha256'] ==
            config['source_closure_sha256']['observer']
         and word(config['capture_launcher_source_sha256']) ==
            config['capture_launcher_source_sha256'],
         'selected-executing-source-identities')
    return closure


def _signature(value):
    return tuple(getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
        'st_mode', 'st_nlink', 'st_uid'))


def open_directory(path):
    """Open every component without following a caller-raced symlink."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts,
         'absolute-directory')
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY |
                      os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            following = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY |
                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            os.close(current); current = following
        info = os.fstat(current)
        need(stat.S_ISDIR(info.st_mode), 'opened-directory')
        return current
    except BaseException:
        os.close(current)
        raise


def _relative_parent(root_fd, relative):
    relative = Path(relative)
    need(not relative.is_absolute() and '..' not in relative.parts
         and relative.parts, 'finite-relative-leaf')
    current = os.dup(root_fd)
    try:
        for component in relative.parts[:-1]:
            following = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY |
                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            os.close(current); current = following
        return current, relative.parts[-1]
    except BaseException:
        os.close(current)
        raise


def stable_read_at(root_fd, relative, maximum, *, exact_bytes=None,
                   private=False, expected_mode=None):
    parent, name = _relative_parent(root_fd, relative)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid()
             and 0 <= before.st_size <= maximum,
             'owned-single-link-bounded-input')
        if exact_bytes is not None:
            need(before.st_size == exact_bytes, 'exact-input-width')
        mode = stat.S_IMODE(before.st_mode)
        need((not private or mode in (0o400, 0o600))
             and (expected_mode is None or mode == expected_mode)
             and not mode & 0o022, 'input-mode')
        chunks, remaining = [], before.st_size
        while remaining:
            block = os.read(fd, min(remaining, 1 << 20))
            need(block, 'complete-input-read')
            chunks.append(block); remaining -= len(block)
        after = os.fstat(fd)
        need(_signature(before) == _signature(after), 'stable-input-read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def stable_read(path, maximum, *, exact_bytes=None, private=False):
    """Read one selected leaf once, without aliases or mutable hard links."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts,
         'absolute-nonsymlink-input')
    parent = open_directory(path.parent)
    try:
        return stable_read_at(parent, path.name, maximum,
                              exact_bytes=exact_bytes, private=private)
    finally:
        os.close(parent)


def write_new_at(root_fd, relative, raw, mode):
    parent, name = _relative_parent(root_fd, relative)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            at = 0
            while at < len(raw):
                count = os.write(fd, raw[at:])
                need(count > 0, 'complete-output-write'); at += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def write_new(path, raw, mode):
    path = Path(path)
    need(path.is_absolute(), 'fresh-output-path')
    parent = open_directory(path.parent)
    try:
        write_new_at(parent, path.name, raw, mode)
    finally:
        os.close(parent)


def validate_binding(value):
    codec.binding(value)
    return value


def validate_config(value):
    exact(value, CONFIG_FIELDS)
    need(value['schema'] == 'kpb-actual-capture-worker-config/v1'
         and value['classification'] in CLASSIFICATIONS,
         'worker-config-schema')
    for name in ('comparison_selection_sha256', 'run_selection_sha256',
                 'method_sha256', 'workload_sha256',
                 'observer_source_sha256', 'capture_source_sha256',
                 'coverage_policy_sha256',
                 'capture_producer_receipt_sha256',
                 'capture_producer_source_sha256',
                 'capture_producer_build_sha256',
                 'capture_producer_role_launch_sha256',
                 'capture_launcher_source_sha256',
                 'runtime_identity_sha256', 'python_runtime_sha256',
                 'namespace_tool_sha256', 'root_guard_helper_sha256'):
        word(value[name], name)
    validate_binding(value['binding'])
    need(value['binding']['method_sha256'] == value['method_sha256']
         and value['capture_source_sha256'] == source_sha256()
         and value['capture_producer_source_sha256'] == hashlib.sha256(
             Path(__file__).with_name(
                 'privacy_capture_producer.py').read_bytes()).hexdigest(),
         'method-and-executing-capture-source')
    capture.c03_role_launch_closure(
        value['capture_producer_role_launch_closure'],
        value['capture_producer_role_launch_sha256'])
    need(value['step3_terminal_gate'] == STEP3_TERMINAL_GATE
         and value['host_runtime_trust_boundary'] ==
             HOST_RUNTIME_TRUST_BOUNDARY,
         'terminal-gate-and-runtime-boundary')
    need(type(value['capture_identity']) is str
         and str(uuid.UUID(value['capture_identity'])) ==
             value['capture_identity']
         and value['capture_identity'] != value['binding']['trial_id'],
         'fresh-capture-identity')
    validate_source_closure(value['source_members'], value)
    rounds = value['financial_rounds']
    need(type(rounds) is list and len(rounds) == 2,
         'two-financial-rounds')
    for number, row in zip((1, 2), rounds):
        exact(row, FINANCIAL_SELECTION_FIELDS,
              'financial-selection-fields')
        need(row['round'] == number, 'financial-round-order')
        for name in FINANCIAL_SELECTION_FIELDS[1:]:
            word(row[name], 'financial-' + name)
    need(rounds[0]['financial_run_id'] != rounds[1]['financial_run_id']
         and rounds[0]['retained_projection_sha256'] !=
             rounds[1]['retained_projection_sha256'],
         'distinct-financial-rounds')
    return value


def validate_producer(raw, config):
    need(hashlib.sha256(raw).hexdigest() ==
         config['capture_producer_receipt_sha256'],
         'selected-producer-receipt-hash')
    value = parse(raw)
    need(value.get('schema') != 'kpb-capture-producer-source-only/v1'
         and value.get('status') != 'UNQUALIFIED_SOURCE_ONLY',
         'source-only-producer-is-not-actual-authority')
    exact(value, PRODUCER_FIELDS, 'producer-receipt-fields')
    need(value['schema'] == 'kpb-capture-producer-receipt/v1'
         and value['binding'] == config['binding']
         and value['classification'] == config['classification']
         and value['capture_identity'] == config['capture_identity']
         and value['financial_rounds'] == config['financial_rounds']
         and value['append_only_roots_closed'] is True
         and value['unknown_record_count'] == 0
         and all(value[name] is True for name in (
             'role_hooks_integrated', 'fixed_fd_inheritance_selected',
             'launcher_selected', 'launch_authorized',
             'actual_receipt_emitted')),
         'selected-source-produced-capture-authority')
    for name in ('producer_source_sha256', 'producer_build_sha256',
                 'producer_role_launch_sha256'):
        word(value[name], 'producer-' + name)
    need(value['producer_source_sha256'] ==
            config['capture_producer_source_sha256']
         and value['producer_build_sha256'] ==
            config['capture_producer_build_sha256']
         and value['producer_role_launch_sha256'] ==
            config['capture_producer_role_launch_sha256'],
         'selected-producer-source-build-launch-closure')
    need(type(value['rounds']) is list and len(value['rounds']) == 2,
         'producer-two-rounds')
    attempts = []; cohorts = []
    for number, row in zip((1, 2), value['rounds']):
        exact(row, PRODUCER_ROUND_FIELDS, 'producer-round-fields')
        need(row['round'] == number
             and type(row['attempt_id']) is str
             and str(uuid.UUID(row['attempt_id'])) == row['attempt_id'],
             'producer-fresh-round-attempt')
        attempts.append(row['attempt_id'])
        word(row['cohort_sha256'], 'producer-round-cohort')
        cohorts.append(row['cohort_sha256'])
        need(type(row['artifacts']) is list
             and [item.get('kind') for item in row['artifacts']] ==
                list(PRODUCER_ARTIFACT_ORDER),
             'producer-exact-artifact-order')
        for artifact in row['artifacts']:
            exact(artifact, PRODUCER_ARTIFACT_FIELDS,
                  'producer-artifact-fields')
            for name in ('producer_record_count', 'capture_record_count',
                         'producer_payload_bytes', 'capture_payload_bytes'):
                need(type(artifact[name]) is int and artifact[name] >= 0,
                     'producer-artifact-count')
            need(artifact['producer_record_count'] ==
                    artifact['capture_record_count']
                 and artifact['producer_payload_bytes'] ==
                    artifact['capture_payload_bytes']
                 and word(artifact['record_chain_sha256'])
                 and artifact['capture_root_closed'] is True
                 and artifact['producer_fd_closed'] is True,
                 'producer-artifact-closed-root')
        p1 = row['p1_capture_authority']
        exact(p1, capture.C03_AUTHORITY_FIELDS,
              'producer-p1-authority-fields')
        need(p1['round'] == number
             and p1['attempt_id'] == row['attempt_id']
             and p1['cohort_sha256'] == row['cohort_sha256']
             and p1['financial_run_id'] ==
                value['financial_rounds'][number - 1]['financial_run_id']
             and p1['capture_identity'] == value['capture_identity']
             and type(p1['server_component']) is int
             and p1['server_component'] == 1
             and type(p1['fixed_fd']) is int
             and p1['fixed_fd'] == (23 if number == 1 else 28),
             'producer-p1-authority-context')
        for name in ('source_sha256', 'build_sha256', 'launch_sha256',
                     'model_preimage_sha256',
                     'query_store_preimage_sha256',
                     'scalar_capture_manifest_sha256'):
            word(p1[name], 'producer-p1-' + name)
        need(p1['scalar_capture_manifest_sha256'] ==
             capture.C03_SCALAR_CAPTURE_MANIFEST_SHA256,
             'producer-p1-scalar-manifest')
        selected_roles = [role for role in
                          config['capture_producer_role_launch_closure']
                          if role['round'] == number
                          and role['kind'] == 'corrupt-server-capture']
        need(len(selected_roles) == 1
             and selected_roles[0]['role'] == 'server-P1'
             and selected_roles[0]['fixed_fd'] == p1['fixed_fd']
             and all(selected_roles[0][name] == p1[name]
                     for name in ('source_sha256', 'build_sha256',
                                  'launch_sha256',
                                  'model_preimage_sha256',
                                  'query_store_preimage_sha256',
                                  'scalar_capture_manifest_sha256')),
             'producer-p1-authority-role-launch-join')
        closure = p1['closure']
        exact(closure, capture.C03_CLOSURE_FIELDS,
              'producer-p1-closure-fields')
        corrupt = next(artifact for artifact in row['artifacts']
                       if artifact['kind'] == 'corrupt-server-capture')
        need(closure['schema'] == 'kpb-capture-source-closure/v2'
             and closure['attempt_id'] == row['attempt_id']
             and closure['cohort_sha256'] == row['cohort_sha256']
             and closure['unknown_record_count'] == 0
             and closure['capture_root_closed'] is True
             and closure['producer_fd_closed'] is True
             and type(closure['producer_stream_counts']) is dict
             and closure['producer_stream_counts'] ==
                closure['capture_stream_counts']
             and set(closure['producer_stream_counts']) ==
                set(capture.C03_SEMANTICS.values())
             and all(type(count) is int and count > 0
                     for count in
                     closure['producer_stream_counts'].values())
             and type(closure['raw_wire_bytes']) is int
             and closure['raw_wire_bytes'] > 0
             and all(word(closure[name]) for name in (
                 'raw_wire_sha256', 'end_frame_identity', 'eof_identity'))
             and all(corrupt[name] == closure[name]
                     for name in PRODUCER_ARTIFACT_FIELDS[1:]),
             'producer-p1-authority-artifact-join')
    need(len(set(attempts)) == 2 and len(set(cohorts)) == 2,
         'producer-distinct-round-attempts-and-cohorts')
    return value


def reconcile_producer_round(produced, raws):
    """Join the selected producer root to each independently parsed body."""
    by_kind = {row['kind']: row for row in produced['artifacts']}
    projection_raw = raws['public-projection']
    projection_records = [{
        'stream': 'projection',
        'value': {
            'bytes': len(projection_raw),
            'sha256': hashlib.sha256(projection_raw).hexdigest(),
        },
    }]
    expected = {
        'kind': 'public-projection',
        'producer_record_count': 1,
        'capture_record_count': 1,
        'producer_payload_bytes': len(projection_raw),
        'capture_payload_bytes': len(projection_raw),
        'record_chain_sha256': hashlib.sha256(
            encoded(projection_records)).hexdigest(),
        'capture_root_closed': True,
        'producer_fd_closed': True,
    }
    need(by_kind['public-projection'] == expected,
         'producer-public-projection-root')
    for kind in PRODUCER_ARTIFACT_ORDER[1:]:
        closure = (produced['p1_capture_authority']['closure']
                   if kind == 'corrupt-server-capture'
                   else parse(raws[kind]).get('closure'))
        need(type(closure) is dict
             and closure.get('attempt_id') == produced['attempt_id']
             and closure.get('cohort_sha256') == produced['cohort_sha256'],
             'producer-attempt-cohort-' + kind)
        expected = {'kind': kind}
        for name in PRODUCER_ARTIFACT_FIELDS[1:]:
            expected[name] = closure.get(name)
        need(by_kind[kind] == expected,
             'producer-body-root-reconciliation-' + kind)


def _validate_record(value, name):
    exact(value, ARTIFACT_RECORD_FIELDS, 'artifact-record-' + name)
    need(type(value['path']) is str and value['path'].startswith('/'),
         'artifact-absolute-path-' + name)
    word(value['sha256'], 'artifact-hash-' + name)
    need(type(value['bytes']) is int and value['bytes'] >= 0,
         'artifact-bytes-' + name)
    return value


def _hex_bytes(value, size, category):
    need(type(value) is str and len(value) == 2 * size
         and re.fullmatch('[0-9a-f]+', value), category)
    return bytes.fromhex(value)


def selected_qualifier_sha256():
    manifest = source_closure.manifest('actual-capture')
    matches = [row['sha256'] for row in manifest['members']
               if row['name'].endswith('/qualify_public_release.py')]
    need(len(matches) == 1, 'selected-qualifier-source-member')
    return matches[0]


def read_financial_leaves(root_fd, round_number, records):
    leaves = {}
    maximums = {
        'financial_result': 8 << 20,
        'released_core': 10364,
        'released_proof': 128,
        'released_projection': 10685,
        'native_tail': 65535,
        'retained_projection': 10685,
        'journal': 104,
        'host_cross_check': 2 << 20,
        'component_profile': 2 << 20,
        'outer_selection': 2 << 20,
        'public_host': 256 << 20,
        'namespace_tool': 2 << 20,
        'qualifier_source': 2 << 20,
    }
    exact_widths = {
        'released_core': 10364, 'released_proof': 128,
        'released_projection': 10685, 'retained_projection': 10685,
        'journal': 104,
    }
    for name in PUBLIC_ARTIFACT_NAMES:
        raw = stable_read_at(
            root_fd, 'round-' + str(round_number) + '/leaves/' + name,
            maximums[name], exact_bytes=exact_widths.get(name))
        need(hashlib.sha256(raw).hexdigest() == records[name]['sha256']
             and len(raw) == records[name]['bytes'],
             'financial-opened-leaf-' + name)
        leaves[name] = raw
    return leaves


def validate_financial(round_number, selected, artifacts_raw, result_raw,
                       projection_raw, leaves):
    """Join a round to a completed Source05 public cryptographic handoff."""
    artifacts = parse(artifacts_raw); result = parse(result_raw)
    exact(artifacts, ARTIFACTS_FIELDS, 'financial-artifacts-fields')
    exact(result, HANDOFF_FIELDS, 'financial-result-fields')
    need(hashlib.sha256(artifacts_raw).hexdigest() ==
            selected['financial_artifacts_sha256']
         and hashlib.sha256(result_raw).hexdigest() ==
            selected['financial_result_sha256']
         and hashlib.sha256(projection_raw).hexdigest() ==
            selected['retained_projection_sha256'],
         'selected-financial-leaf-hashes')
    need(artifacts['schema'] ==
            'kpb-qualified-public-financial-artifacts/v1'
         and artifacts['status'] ==
            'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED'
         and result['schema'] == 'kpi-financial-public-crypto-handoff/v1'
         and result['status'] ==
            'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED'
         and artifacts['run_id'] == result['run_id'] ==
            selected['financial_run_id'],
         'financial-completed-run-identity')
    exact(artifacts['head'], ('outpoint_hex36', 'state_hex112',
                             'reserve_sompi', 'script_public_key_hex37'),
          'financial-head-fields')
    exact(artifacts['successor'], ('state_hex112', 'reserve_sompi',
                                  'script_public_key_hex37'),
          'financial-successor-fields')
    need(type(artifacts['head']['outpoint_hex36']) is str
         and len(artifacts['head']['outpoint_hex36']) == 72
         and type(artifacts['head']['state_hex112']) is str
         and len(artifacts['head']['state_hex112']) == 224
         and type(artifacts['successor']['state_hex112']) is str
         and len(artifacts['successor']['state_hex112']) == 224
         and all(type(artifacts[name]['reserve_sompi']) is int
                 and artifacts[name]['reserve_sompi'] >= 0
                 for name in ('head', 'successor'))
         and all(type(artifacts[name]['script_public_key_hex37']) is str
                 and len(artifacts[name]['script_public_key_hex37']) == 74
                 for name in ('head', 'successor')),
         'financial-head-successor-shape')
    need(type(artifacts['artifacts']) is dict
         and set(artifacts['artifacts']) == set(PUBLIC_ARTIFACT_NAMES),
         'financial-exact-public-artifact-set')
    records = {name: _validate_record(row, name)
               for name, row in artifacts['artifacts'].items()}
    need(set(leaves) == set(PUBLIC_ARTIFACT_NAMES)
         and all(hashlib.sha256(leaves[name]).hexdigest() ==
                 records[name]['sha256']
                 and len(leaves[name]) == records[name]['bytes']
                 for name in PUBLIC_ARTIFACT_NAMES),
         'financial-all-selected-leaf-bodies')
    projection_sha = hashlib.sha256(projection_raw).hexdigest()
    need(len(projection_raw) == 10685
         and leaves['retained_projection'] == projection_raw
         and leaves['released_projection'] == projection_raw
         and len(leaves['released_core']) == 10364
         and len(leaves['released_proof']) == 128
         and records['retained_projection']['sha256'] == projection_sha
         and records['retained_projection']['bytes'] == 10685
         and records['released_projection']['sha256'] == projection_sha
         and records['released_projection']['bytes'] == 10685
         and artifacts['projection_sha256'] == result['projection_sha256']
             == projection_sha
         and artifacts['core_sha256'] == result['core_sha256']
             == records['released_core']['sha256']
         and artifacts['aggregate_proof_sha256'] ==
             result['aggregate_proof_sha256'] ==
             records['released_proof']['sha256']
         and artifacts['effects_sha256'] == result['effects_sha256']
         and artifacts['egress_binding_sha256'] ==
             result['egress_binding_sha256']
         and result['financial_result_sha256'] ==
             records['financial_result']['sha256']
         and result['qualifier_source_sha256'] ==
             records['qualifier_source']['sha256'] ==
             selected_qualifier_sha256()
         and artifacts['component_profile_sha256'] ==
             result['component_profile_sha256'] ==
             records['component_profile']['sha256'],
         'financial-public-artifact-joins')
    need(records['released_core']['bytes'] == 10364
         and records['released_proof']['bytes'] == 128,
         'financial-core-proof-widths')
    for name in HANDOFF_FIELDS:
        if name.endswith('_sha256') or name in ('run_id',
                                                'outer_image_id_hex32'):
            word(result[name], 'financial-result-' + name)
    for name in ('effects_sha256', 'core_sha256',
                 'aggregate_proof_sha256', 'projection_sha256',
                 'egress_binding_sha256', 'successor_state_sha256'):
        word(artifacts[name], 'financial-artifacts-' + name)
    old_point = _hex_bytes(artifacts['head']['outpoint_hex36'], 36,
                           'financial-old-point')
    old_state = _hex_bytes(artifacts['head']['state_hex112'], 112,
                           'financial-old-state')
    old_spk = _hex_bytes(artifacts['head']['script_public_key_hex37'], 37,
                         'financial-old-spk')
    successor_state = _hex_bytes(artifacts['successor']['state_hex112'], 112,
                                 'financial-successor-state')
    successor_spk = _hex_bytes(
        artifacts['successor']['script_public_key_hex37'], 37,
        'financial-successor-spk')
    need(hashlib.sha256(old_point).hexdigest() ==
            result['fixed_old_point_sha256']
         and hashlib.sha256(old_state).hexdigest() ==
            result['fixed_old_state_sha256']
         and hashlib.sha256(old_spk).hexdigest() ==
            result['fixed_old_spk_sha256']
         and hashlib.sha256(successor_state).hexdigest() ==
            result['successor_state_sha256'] ==
            artifacts['successor_state_sha256']
         and hashlib.sha256(successor_spk).hexdigest() ==
            result['successor_spk_sha256']
         and artifacts['successor_script_public_key_hex37'] ==
            artifacts['successor']['script_public_key_hex37']
         and result['native_tail_sha256'] ==
            records['native_tail']['sha256'] ==
            FINANCIAL_AUTHORITY['native_tail']
         and result['journal_sha256'] == records['journal']['sha256']
         and result['outer_selection_sha256'] ==
            records['outer_selection']['sha256'] ==
            FINANCIAL_AUTHORITY['outer_selection']
         and result['host_sha256'] == records['public_host']['sha256'] ==
            FINANCIAL_AUTHORITY['public_host']
         and result['namespace_tool_sha256'] ==
            records['namespace_tool']['sha256'] ==
            FINANCIAL_AUTHORITY['namespace_tool']
         and result['component_profile_sha256'] ==
            records['component_profile']['sha256'] ==
            FINANCIAL_AUTHORITY['component_profile']
         and result['aggregate_vk_sha256'] ==
            FINANCIAL_AUTHORITY['aggregate_vk']
         and result['output_vk_sha256'] ==
            FINANCIAL_AUTHORITY['output_vk'],
         'financial-complete-authority-joins')
    need(result['source_scope'] ==
            'PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY',
         'financial-unfunded-source-scope')
    true_fields = (
        'all_three_financial_results_agreed',
        'aggregate_and_six_Output_G16_verified',
        'independent_arkworks_reference_checked',
        'public_state_and_global_balance_verified',
        'fixed_unfunded_head_and_state_matched',
        'host_namespace_isolated', 'host_network_namespace_unshared',
    )
    false_fields = (
        'registered_financial_service', 'accepted_head_authority',
        'R0_or_native_VM_executed', 'R0_receipt_verified',
        'full_native_candidate_validated', 'native_settlement_performed',
        'payment_privacy_qualified', 'creator_partition_read',
        'private_owner_files_or_keys_read_or_hashed',
        'raw_party_diagnostics_read', 'outer_selection_changed',
        'wallet_or_owner_or_host_home_mounted',
    )
    need(all(result[name] is True for name in true_fields)
         and all(result[name] is False for name in false_fields)
         and artifacts['accepted_head_authority'] is False
         and artifacts['R0_or_native_VM_executed'] is False
         and artifacts['R0_receipt_verified'] is False
         and artifacts['full_native_candidate_validated'] is False
         and artifacts['native_settlement_performed'] is False,
         'financial-scope-and-direct-checks')
    return {
        'round': round_number,
        'financial_run_id': artifacts['run_id'],
        'financial_artifacts_sha256': hashlib.sha256(
            artifacts_raw).hexdigest(),
        'financial_result_sha256': hashlib.sha256(result_raw).hexdigest(),
        'projection_sha256': projection_sha,
        'core_sha256': artifacts['core_sha256'],
        'aggregate_proof_sha256': artifacts['aggregate_proof_sha256'],
        'egress_binding_sha256': artifacts['egress_binding_sha256'],
        'head': artifacts['head'],
        'successor': artifacts['successor'],
    }


def _adapter(kind, raw, public, projection_raw, p1_authority=None,
             p1_role_launch_closure=None, p1_role_launch_sha256=None):
    if kind == 'public-projection':
        need(p1_authority is None and p1_role_launch_closure is None
             and p1_role_launch_sha256 is None,
             'p1-authority-only-for-corrupt-server')
        return capture.public_projection(raw, public)
    if kind == 'dispatcher-capture':
        need(p1_authority is None and p1_role_launch_closure is None
             and p1_role_launch_sha256 is None,
             'p1-authority-only-for-corrupt-server')
        return capture.dispatcher(raw, public)
    if kind == 'corrupt-server-capture':
        need(p1_authority is not None
             and p1_role_launch_closure is not None
             and p1_role_launch_sha256 is not None,
             'p1-c03-authority-required')
        return capture.corrupt_server_c03(
            raw, public, projection_raw, p1_authority,
            p1_role_launch_closure, p1_role_launch_sha256)
    if kind == 'colluder-wallet-capture':
        need(p1_authority is None and p1_role_launch_closure is None
             and p1_role_launch_sha256 is None,
             'p1-authority-only-for-corrupt-server')
        return capture.colluder_wallet(raw, public)
    if kind == 'terminal-history':
        need(p1_authority is None and p1_role_launch_closure is None
             and p1_role_launch_sha256 is None,
             'p1-authority-only-for-corrupt-server')
        return capture.terminal(raw, public)
    raise AssertionError(kind)


def _construction_grouping(classification, terminal_raw, dispatcher_raw,
                           public):
    terminal = parse(terminal_raw)
    dispatcher = parse(dispatcher_raw)
    groups = terminal.get('groups')
    need(type(groups) is list, 'terminal-groups-for-classification')
    if classification == 'ACTUAL_TRANSPARENT_BASELINE':
        need(len(groups) == 3
             and sorted(group.get('owner_component', -1)
                        for group in groups) == [0, 1, 2]
             and all(len(group.get('nfs_hex32', [])) == 1
                     and len(group.get('tuple_sha256', [])) == 2
                     for group in groups),
             'actual-transparent-construction-grouping')
        need(dispatcher.get('release_order_policy') ==
             'EXPLICIT_OWNER_PUBLIC_EFFECTS',
             'actual-transparent-dispatcher-mapping')
        mode = 'THREE_OWNER_LABELLED_1NF_2TUPLE_GROUPS'
        mapping_exported = True
    else:
        need(len(groups) == 1
             and groups[0].get('owner_component') is None
             and len(groups[0].get('nfs_hex32', [])) == 3
             and len(groups[0].get('tuple_sha256', [])) == 6
             and sorted(groups[0]['nfs_hex32']) ==
                sorted(public['nfs_hex32'])
             and sorted(groups[0]['tuple_sha256']) ==
                sorted(public['tuple_sha256']),
             'actual-hidden-construction-grouping')
        need(dispatcher.get('release_order_policy') ==
                'SECRET_PERMUTATION_INDEPENDENT'
             and dispatcher.get('direct_exports') == [],
             'actual-hidden-secret-independent-dispatch')
        mode = 'ONE_UNLABELLED_3NF_6TUPLE_GROUP'
        mapping_exported = False
    return mode, mapping_exported, dispatcher['release_order_policy']


def _category_coverage(view, kinds, modeled):
    counts = modeled['category_counts']
    leakage = modeled['leakage_coverage']
    result = {}
    for category in modeled['categories']:
        expected = sum(category in capture.ARTIFACT_CATEGORIES[kind]
                       for kind in kinds)
        need(counts[category] == expected and expected > 0
             and category in leakage,
             'category-manifest-reconciliation-' + view + '-' + category)
        result[category] = {
            'modeled_artifacts': expected,
            'unmodeled_artifacts': leakage[category][
                'unmodeled_artifacts'],
            'missing_artifacts': 0,
            'constraint_modeled_fields': leakage[category][
                'constraint_modeled_fields'],
            'source_assumption_covered_fields': leakage[category][
                'source_assumption_covered_fields'],
            'unmodeled_fields': leakage[category]['unmodeled_fields'],
        }
    return result


def _nonoverlapping(paths):
    normalized = [os.path.normpath(str(path)) for path in paths]
    for index, left in enumerate(normalized):
        for right in normalized[index + 1:]:
            need(os.path.commonpath((left, right)) not in (left, right),
                 'nonoverlapping-root-paths')


def produce(config, capture_root, evidence_root, state_root, output_root,
            *, salt=None):
    """Produce private manifest/models and the count-only public receipt."""
    config = validate_config(config)
    # Three owner-labelled groups in a terminal JSON body are evidence bytes,
    # not authority that the genuine owners disclosed their own mapping.  The
    # source-only baseline collector has no verified owner-private factory,
    # dispatcher integration or completion receipt yet.  Refuse before opening
    # any capture root until that nonforgeable chain is selected end to end.
    if config['classification'] == 'ACTUAL_TRANSPARENT_BASELINE':
        need(False, 'transparent-baseline-source-authority-unavailable')
    capture_root = Path(capture_root); evidence_root = Path(evidence_root)
    state_root = Path(state_root); output_root = Path(output_root)
    paths = (capture_root, evidence_root, state_root, output_root)
    need(all(path.is_absolute() for path in paths), 'fixed-existing-roots')
    _nonoverlapping(paths)
    root_fds = [open_directory(path) for path in paths]
    try:
        identities = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                      for fd in root_fds]
        need(len(set(identities)) == 4, 'distinct-root-inodes')
        need(os.listdir(root_fds[3]) == [], 'fresh-empty-output-root')
        need(os.listdir(root_fds[2]) == ['CAPTURE-CONSUMED.json'],
             'capture-consumed-before-worker')
        consumed = parse(stable_read_at(
            root_fds[2], 'CAPTURE-CONSUMED.json', 4096,
            expected_mode=0o400))
        exact(consumed, CONSUMED_FIELDS, 'capture-consumed-fields')
        need(consumed == {
            'schema': 'kpb-actual-capture-consumed/v1',
            'comparison_selection_sha256':
                config['comparison_selection_sha256'],
            'run_selection_sha256': config['run_selection_sha256'],
            'capture_identity': config['capture_identity'],
        }, 'capture-consumed-binding')
        producer_raw = stable_read_at(root_fds[0], 'PRODUCER.json',
                                      8 << 20, expected_mode=0o400)
        producer = validate_producer(producer_raw, config)
        return _produce_open(
            config, capture_root, evidence_root, state_root, output_root,
            root_fds, producer, salt=salt)
    finally:
        for fd in root_fds:
            os.close(fd)


def _produce_open(config, capture_root, evidence_root, state_root,
                  output_root, root_fds, producer, *, salt):
    capture_fd, evidence_fd, state_fd, output_fd = root_fds

    financial, private_rounds, construction_modes, mapping_exports = [], [], [], []
    release_policies = []
    public_views = {view: [] for view in VIEWS}
    for number, selected in zip((1, 2), config['financial_rounds']):
        round_name = 'round-' + str(number)
        raws = {}
        for kind, filename in CAPTURE_FILES.items():
            maximum = (10685 if kind == 'public-projection' else
                       (1 << 30) if kind == 'corrupt-server-capture' else
                       8 << 20)
            raws[kind] = stable_read_at(
                capture_fd, round_name + '/' + filename, maximum,
                exact_bytes=10685 if kind == 'public-projection' else None,
                private=kind != 'public-projection')
        reconcile_producer_round(producer['rounds'][number - 1], raws)
        artifacts_raw = stable_read_at(
            evidence_fd, round_name + '/ARTIFACTS.json', 8 << 20)
        result_raw = stable_read_at(
            evidence_fd, round_name + '/RESULT.json', 8 << 20)
        artifacts_value = parse(artifacts_raw)
        need(type(artifacts_value.get('artifacts')) is dict,
             'financial-artifact-record-map')
        records = {name: _validate_record(row, name)
                   for name, row in artifacts_value['artifacts'].items()}
        need(set(records) == set(PUBLIC_ARTIFACT_NAMES),
             'financial-leaf-record-set')
        leaves = read_financial_leaves(evidence_fd, number, records)
        financial.append(validate_financial(
            number, selected, artifacts_raw, result_raw,
            raws['public-projection'], leaves))
        public = observer.batch_from_projection(number,
                                                raws['public-projection'])
        p1_authority = producer['rounds'][number - 1][
            'p1_capture_authority']
        typed = [_adapter(
                    kind, raws[kind], public, raws['public-projection'],
                    p1_authority if kind == 'corrupt-server-capture'
                    else None,
                    config['capture_producer_role_launch_closure']
                    if kind == 'corrupt-server-capture' else None,
                    config['capture_producer_role_launch_sha256']
                    if kind == 'corrupt-server-capture' else None)
                 for kind in CAPTURE_FILES]
        derived = capture.derive_view_artifacts(public, typed)
        need(derived['schema'] == 'kpb-derived-four-view-inventory/v1'
             and derived['round'] == number
             and set(derived['views']) == set(VIEWS)
             and derived['attempt_id'] ==
                producer['rounds'][number - 1]['attempt_id']
             and derived['cohort_sha256'] ==
                producer['rounds'][number - 1]['cohort_sha256'],
             'derived-four-view-inventory')
        mode, mapping_exported, release_policy = _construction_grouping(
            config['classification'], raws['terminal-history'],
            raws['dispatcher-capture'], public)
        construction_modes.append(mode); mapping_exports.append(mapping_exported)
        release_policies.append(release_policy)
        private_rounds.append({
            'round': number,
            'public': public,
            'typed_artifacts': typed,
            'derived': derived,
        })
        sizes = {kind: len(raw) for kind, raw in raws.items()}
        for view in VIEWS:
            kinds = VIEW_KINDS[view]
            modeled = derived['views'][view]
            category_coverage = _category_coverage(view, kinds, modeled)
            row = {
                'round': number,
                'artifact_count': len(kinds),
                'artifact_bytes': sum(sizes[kind] for kind in kinds),
                'category_counts': modeled['category_counts'],
                'category_coverage': category_coverage,
                'modeled_artifacts': len(kinds),
                'unmodeled_artifacts':
                    modeled['unmodeled_artifact_count'],
                'missing_artifacts': 0,
                'terminal_modeled': True,
            }
            public_views[view].append(row)

    need(financial[0]['financial_run_id'] != financial[1]['financial_run_id']
         and financial[0]['projection_sha256'] !=
             financial[1]['projection_sha256']
         and financial[1]['head']['state_hex112'] ==
             financial[0]['successor']['state_hex112']
         and financial[1]['head']['reserve_sompi'] ==
             financial[0]['successor']['reserve_sompi']
         and financial[1]['head']['script_public_key_hex37'] ==
             financial[0]['successor']['script_public_key_hex37'],
         'fresh-distinct-financial-evidence')
    expected_mode = ('THREE_OWNER_LABELLED_1NF_2TUPLE_GROUPS'
        if config['classification'] == 'ACTUAL_TRANSPARENT_BASELINE'
        else 'ONE_UNLABELLED_3NF_6TUPLE_GROUP')
    expected_mapping = config['classification'] == \
        'ACTUAL_TRANSPARENT_BASELINE'
    need(construction_modes == [expected_mode, expected_mode]
         and mapping_exports == [expected_mapping, expected_mapping],
         'same-construction-classification-both-rounds')
    expected_policy = ('EXPLICIT_OWNER_PUBLIC_EFFECTS'
        if config['classification'] == 'ACTUAL_TRANSPARENT_BASELINE'
        else 'SECRET_PERMUTATION_INDEPENDENT')
    if config['classification'] == 'ACTUAL_TRANSPARENT_BASELINE':
        need(release_policies == [expected_policy, expected_policy],
             'transparent-release-policy-both-rounds')
    else:
        need(release_policies == [expected_policy, expected_policy],
             'hidden-release-policy-both-rounds')

    construction = {
        'schema': 'kpb-financial-construction-classification/v1',
        'comparison_selection_sha256':
            config['comparison_selection_sha256'],
        'run_selection_sha256': config['run_selection_sha256'],
        'classification': config['classification'],
        'capture_source_sha256': config['capture_source_sha256'],
        'capture_producer_receipt_sha256':
            config['capture_producer_receipt_sha256'],
        'source_closure_sha256': config['source_closure_sha256'],
        'runtime_identity_sha256': config['runtime_identity_sha256'],
        'financial_run_id': [row['financial_run_id'] for row in financial],
        'projection_sha256': [row['projection_sha256'] for row in financial],
        'terminal_grouping_mode': expected_mode,
        'direct_owner_mapping_exposed': expected_mapping,
        'caller_overlay': False,
        'private_owner_or_slot_identifiers_exported': False,
        'terminal_scope': TERMINAL_SCOPE,
        'step3_terminal_gate': STEP3_TERMINAL_GATE,
    }
    construction_raw = encoded(construction)
    construction_sha = hashlib.sha256(construction_raw).hexdigest()

    manifest = {
        'schema': 'kpb-private-actual-capture-manifest/v1',
        'comparison_selection_sha256':
            config['comparison_selection_sha256'],
        'run_selection_sha256': config['run_selection_sha256'],
        'capture_identity': config['capture_identity'],
        'classification': config['classification'],
        'terminal_scope': TERMINAL_SCOPE,
        'step3_terminal_gate': STEP3_TERMINAL_GATE,
        'capture_producer_receipt_sha256':
            config['capture_producer_receipt_sha256'],
        'producer_authority': producer,
        'financial_rounds': financial,
        'construction_classification_sha256': construction_sha,
        'rounds': private_rounds,
        'truth_or_predictions_mounted': False,
    }
    if salt is None:
        salt = secrets.token_bytes(32)
    need(type(salt) is bytes and len(salt) == 32 and salt != bytes(32),
         'fresh-manifest-salt')
    sealed_manifest = MANIFEST_TAG + salt + encoded(manifest)
    manifest_seal = hashlib.sha256(sealed_manifest).hexdigest()

    views = []
    for view in VIEWS:
        rounds = public_views[view]
        categories = sorted(rounds[0]['category_coverage'])
        need(categories == sorted(rounds[1]['category_coverage']),
             'same-category-set-both-rounds-' + view)
        totals = {
            'modeled_artifacts': sum(row['modeled_artifacts']
                                     for row in rounds),
            'unmodeled_artifacts': sum(row['unmodeled_artifacts']
                                       for row in rounds),
            'missing_artifacts': 0,
            'terminal_modeled': True,
        }
        views.append({
            'view': view,
            'categories': categories,
            'rounds': rounds,
            'coverage': totals,
        })

    receipt = {
        'schema': 'kpb-privacy-actual-capture-receipt/v2',
        'comparison_selection_sha256':
            config['comparison_selection_sha256'],
        'run_selection_sha256': config['run_selection_sha256'],
        'classification': config['classification'],
        'binding': config['binding'],
        'method_sha256': config['method_sha256'],
        'workload_sha256': config['workload_sha256'],
        'observer_source_sha256': config['observer_source_sha256'],
        'capture_source_sha256': config['capture_source_sha256'],
        'coverage_policy_sha256': config['coverage_policy_sha256'],
        'capture_identity': config['capture_identity'],
        'capture_producer_receipt_sha256':
            config['capture_producer_receipt_sha256'],
        'source_closure_sha256': config['source_closure_sha256'],
        'runtime_identity_sha256': config['runtime_identity_sha256'],
        'capture_manifest_seal_sha256': manifest_seal,
        'construction_classification_receipt_sha256': construction_sha,
        'terminal_scope': TERMINAL_SCOPE,
        'step3_terminal_gate': STEP3_TERMINAL_GATE,
        'views': views,
        'capture_roots_closed': True,
        'exact_union_derived': True,
        'predictions_or_truth_mounted': False,
        'private_artifact_paths_hashes_or_bodies_exported': False,
    }
    write_new_at(state_fd, 'MANIFEST.bin', sealed_manifest, 0o600)
    write_new_at(state_fd, 'MODELS.json', encoded({
        'schema': 'kpb-private-actual-capture-models/v1',
        'binding': config['binding'],
        'rounds': private_rounds,
    }), 0o600)
    write_new_at(output_fd, 'CONSTRUCTION.json', construction_raw, 0o400)
    # Durable completion marker written last.
    write_new_at(output_fd, 'PUBLIC.json', encoded(receipt), 0o400)
    return receipt


def require_namespace():
    raw = stable_read(Path('/NAMESPACE.json'), 4096)
    marker = parse(raw)
    exact(marker, ('schema', 'operation', 'network', 'truth_mounted',
                   'predictions_mounted', 'rounds', 'artifact_kinds'),
          'namespace-marker-fields')
    need(marker == {
        'schema': 'kpb-actual-capture-namespace/v2',
        'operation': 'capture',
        'network': 'disabled',
        'truth_mounted': False,
        'predictions_mounted': False,
        'rounds': 2,
        'artifact_kinds': list(PRODUCER_ARTIFACT_ORDER),
    }, 'exact-network-off-capture-namespace')
    interfaces = [line.split(':', 1)[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo']
         and not any(Path(path).exists() for path in (
             '/truth', '/predictions', '/original', '/home/luke/.ssh',
             '/home/luke/.codex')),
         'network-off-no-truth-or-host-home')
    mount_ids = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        parts = line.split()
        if len(parts) > 5 and parts[4] in (
                '/captures', '/evidence', '/state', '/out'):
            mount_ids[parts[4]] = parts[0]
    need(set(mount_ids) == {'/captures', '/evidence', '/state', '/out'}
         and len(set(mount_ids.values())) == 4,
         'distinct-selected-root-mounts')


def runtime_sha256(path, *, follow_proc=False):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if not follow_proc:
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), 'runtime-regular-file')
        digest = hashlib.sha256(); remaining = before.st_size
        while remaining:
            block = os.read(fd, min(remaining, 1 << 20))
            need(block, 'runtime-complete-read')
            digest.update(block); remaining -= len(block)
        need(_signature(before) == _signature(os.fstat(fd)),
             'runtime-stable-read')
        return digest.hexdigest()
    finally:
        os.close(fd)


def validate_runtime(config,
                     root_guard_source='/software/root_guard_helper.py'):
    runtime = source_closure.runtime_identity(root_guard_source)
    need(runtime_sha256('/proc/self/exe', follow_proc=True) ==
            runtime['python_runtime_sha256'] ==
            config['python_runtime_sha256']
         and runtime_sha256('/usr/bin/bwrap') ==
            runtime['namespace_tool_sha256'] ==
            config['namespace_tool_sha256']
         and runtime['root_guard_helper_sha256'] ==
            config['root_guard_helper_sha256']
         and hashlib.sha256(source_closure.encoded(runtime)).hexdigest() ==
            config['runtime_identity_sha256']
         and runtime['host_runtime_trust_boundary'] ==
            config['host_runtime_trust_boundary'],
         'selected-runtime-identities')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    need(args.worker, 'worker-only-entry')
    # There is deliberately no selected producer build receipt or one-shot
    # outer-supervisor completion authority in the source-only tree. Refuse
    # before inspecting the namespace or reading any private capture. The
    # pure validation/model functions above remain usable by synthetic unit
    # controls, but cannot make their output authoritative.
    source_closure.require_selected_actual_closure()
    need(False, 'source-only-no-outer-supervisor-completion-authority')
    require_namespace()
    config = parse(stable_read(Path('/CONFIG.json'), 1 << 20, private=True))
    validate_runtime(config)
    produce(config, Path('/captures'), Path('/evidence'), Path('/state'),
            Path('/out'))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # No private exception, path, hash, count or body is exported.
        raise SystemExit(2)
