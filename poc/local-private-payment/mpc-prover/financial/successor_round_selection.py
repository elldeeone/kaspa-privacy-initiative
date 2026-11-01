#!/usr/bin/env python3
"""Compile a public, non-authorizing successor financial-round selection.

This is deliberately not a launcher and cannot create accepted-head authority.
It binds a completed predecessor native candidate, a fresh registered trial, a
configured registered build, and the dynamic accepted-head source closure.
The compiled receipt keeps execution blocked until the C++ driver directly
acquires and later re-acquires its one-use AcceptedFinancialHead capability.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid


REQUIRED_SOURCE = (
    'financial/registered_service.cpp',
    'financial/accepted_head.cpp',
    'financial/registered_selection.cpp',
    'financial/registered_construction.cpp',
    'financial/registered_gate_main.cpp',
    'financial/construction.cpp',
    'history/epoch_journal.cpp',
)
REGISTRATION_TAG = b'KPB/REGISTERED-UNFUNDED-TRIAL/REGISTRATION/v1\0'


def need(value, category):
    if not value:
        raise ValueError('successor-round-selection-' + category)


def fields(value, names, category='fields'):
    need(type(value) is dict and set(value) == set(names), category)


def requires(value, names, category='required-fields'):
    need(type(value) is dict and set(names).issubset(value), category)


def word(value, category='word'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         category)
    return value


def fixed_hex(value, size, category):
    need(type(value) is str and len(value) == 2 * size and
         re.fullmatch('[0-9a-f]+', value), category)
    return value


def bare(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def canonical(value):
    return bare(value) + b'\n'


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError('successor-round-selection-nonfinite-number')))
    need(canonical(value) == raw, 'canonical-json')
    return value


def _signature(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_nlink, value.st_uid)


def read_leaf(path, maximum=16 << 20):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute-nonsymlink-leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == os.geteuid() and
             not mode & 0o022 and 0 < before.st_size <= maximum,
             'owned-single-link-readonly-bounded-leaf')
        chunks, remaining = [], before.st_size
        while remaining:
            block = os.read(fd, min(remaining, 1 << 20))
            need(block, 'complete-read')
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(fd)
        need(_signature(before) == _signature(after), 'stable-read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def read_ref(value, category, maximum=16 << 20):
    fields(value, ('path', 'sha256'), category + '-reference-fields')
    word(value['sha256'], category + '-reference-hash')
    need(type(value['path']) is str, category + '-reference-path')
    raw = read_leaf(value['path'], maximum)
    need(hashlib.sha256(raw).hexdigest() == value['sha256'],
         category + '-reference-changed')
    return raw


def _predecessor(candidate):
    selected = candidate['predecessor']
    fields(selected, ('artifacts', 'result', 'native_successor'),
           'predecessor-selection-fields')
    artifacts_raw = read_ref(selected['artifacts'], 'predecessor-artifacts')
    result_raw = read_ref(selected['result'], 'predecessor-result')
    native_raw = read_ref(selected['native_successor'],
                          'predecessor-native-successor')
    artifacts, result, native = map(parse,
                                    (artifacts_raw, result_raw, native_raw))
    requires(artifacts, (
        'schema', 'status', 'run_id', 'projection_sha256', 'successor',
        'successor_state_sha256', 'successor_script_public_key_hex37',
        'R0_or_native_VM_executed', 'R0_receipt_verified',
        'full_native_candidate_validated', 'native_settlement_performed'),
        'predecessor-artifacts-fields')
    requires(result, (
        'schema', 'status', 'run_id', 'projection_sha256',
        'successor_state_sha256', 'successor_spk_sha256',
        'R0_or_native_VM_executed', 'R0_receipt_verified',
        'full_native_candidate_validated', 'native_settlement_performed'),
        'predecessor-result-fields')
    fields(native, (
        'schema', 'status', 'predecessor_run_id',
        'predecessor_result_sha256', 'successor_outpoint_hex36',
        'successor_state_hex112', 'successor_reserve_sompi',
        'successor_script_public_key_hex37', 'R0_receipt_verified',
        'full_native_candidate_validated',
        'native_settlement_performed'), 'native-successor-fields')
    fields(artifacts['successor'], (
        'state_hex112', 'reserve_sompi', 'script_public_key_hex37'),
        'predecessor-successor-fields')
    run_id = word(artifacts['run_id'], 'predecessor-run-id')
    projection = word(artifacts['projection_sha256'],
                      'predecessor-projection')
    state = fixed_hex(artifacts['successor']['state_hex112'], 112,
                      'predecessor-successor-state')
    spk = fixed_hex(artifacts['successor']['script_public_key_hex37'], 37,
                    'predecessor-successor-spk')
    reserve = artifacts['successor']['reserve_sompi']
    need(type(reserve) is int and reserve >= 0,
         'predecessor-successor-reserve')
    state_sha = hashlib.sha256(bytes.fromhex(state)).hexdigest()
    spk_sha = hashlib.sha256(bytes.fromhex(spk)).hexdigest()
    need(artifacts['schema'] ==
             'kpb-qualified-public-financial-artifacts/v1' and
         result['schema'] == 'kpi-financial-public-crypto-handoff/v1' and
         artifacts['status'] == result['status'] ==
             'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED' and
         result['run_id'] == native['predecessor_run_id'] == run_id and
         result['projection_sha256'] == projection and
         artifacts['successor_state_sha256'] ==
             result['successor_state_sha256'] == state_sha and
         artifacts['successor_script_public_key_hex37'] == spk and
         result['successor_spk_sha256'] == spk_sha,
         'predecessor-cross-document-join')
    true_names = ('R0_or_native_VM_executed', 'R0_receipt_verified',
                  'full_native_candidate_validated')
    need(all(artifacts[name] is True and result[name] is True
             for name in true_names) and
         artifacts['native_settlement_performed'] is False and
         result['native_settlement_performed'] is False and
         native['R0_receipt_verified'] is True and
         native['full_native_candidate_validated'] is True and
         native['native_settlement_performed'] is False and
         native['schema'] == 'kpb-r0-native-successor-receipt/v1' and
         native['status'] ==
             'FULL_NATIVE_CANDIDATE_VALIDATED_UNBROADCAST' and
         native['predecessor_result_sha256'] ==
             hashlib.sha256(result_raw).hexdigest(),
         'predecessor-native-validation')
    point = fixed_hex(native['successor_outpoint_hex36'], 36,
                      'successor-outpoint')
    need(native['successor_state_hex112'] == state and
         native['successor_reserve_sompi'] == reserve and
         native['successor_script_public_key_hex37'] == spk,
         'native-successor-facts')
    return {
        'run_id': run_id, 'projection_sha256': projection,
        'artifacts_sha256': hashlib.sha256(artifacts_raw).hexdigest(),
        'result_sha256': hashlib.sha256(result_raw).hexdigest(),
        'native_successor_sha256': hashlib.sha256(native_raw).hexdigest(),
        'outpoint_hex36': point, 'state_hex112': state,
        'reserve_sompi': reserve, 'script_public_key_hex37': spk,
    }


def _trial(candidate):
    selected = candidate['trial']
    fields(selected, ('selection', 'registration'), 'trial-reference-fields')
    selection_raw = read_ref(selected['selection'], 'trial-selection')
    registration_raw = read_ref(selected['registration'],
                                'trial-registration')
    selection, registration = parse(selection_raw), parse(registration_raw)
    fields(selection, (
        'schema', 'scope', 'status', 'trial_id', 'trial_root',
        'registration_file', 'registration_file_sha256',
        'registration_sha256', 'epoch_key', 'certificates',
        'certificate_authority', 'private_ca_key_path', 'state',
        'source_selection_sha256', 'source_closure', 'initializer',
        'registered_driver_configured', 'network_node_contacted',
        'owner_input_or_mpc_executed',
        'native_broadcast_or_settlement_executed'),
        'trial-selection-fields')
    fields(registration, ('schema', 'registration_sha256', 'registration'),
           'registration-envelope-fields')
    body = registration['registration']
    fields(body, ('scope', 'status', 'trial_id',
                  'registration_nonce_hex32', 'epoch_key', 'certificates',
                  'certificate_authority', 'source_selection_sha256',
                  'registered_financial_service_identity',
                  'registered_driver_configured', 'testnet_research_only',
                  'network_or_owner_input_executed'),
           'registration-body-fields')
    trial_id = selection['trial_id']
    need(type(trial_id) is str and str(uuid.UUID(trial_id)) == trial_id,
         'trial-id')
    root = Path(selection['trial_root'])
    need(root.is_absolute() and
         selection['registration_file'] ==
             str(root / 'public/registration/REGISTRATION.json') and
         selection['registration_file'] == selected['registration']['path'],
         'trial-fixed-registration-path')
    registration_sha = hashlib.sha256(
        REGISTRATION_TAG + bare(body)).hexdigest()
    need(selection['schema'] ==
             'kpb-registered-financial-trial-selection-candidate/v1' and
         selection['status'] == 'UNCONFIGURED_BOOTSTRAPPED' and
         registration['schema'] ==
             'kpb-registered-unfunded-trial-registration/v1' and
         selection['trial_id'] == body['trial_id'] == trial_id and
         selection['registration_sha256'] ==
             registration['registration_sha256'] == registration_sha and
         selection['registration_file_sha256'] ==
             hashlib.sha256(registration_raw).hexdigest() and
         body['status'] == 'BOOTSTRAP_ONLY_UNCONFIGURED' and
         body['scope'] == selection['scope'] and
         body['source_selection_sha256'] ==
             selection['source_selection_sha256'] and
         body['registered_financial_service_identity'] is True and
         body['testnet_research_only'] is True and
         selection['registered_driver_configured'] is False and
         body['registered_driver_configured'] is False and
         selection['network_node_contacted'] is False and
         selection['owner_input_or_mpc_executed'] is False and
         selection['native_broadcast_or_settlement_executed'] is False and
         body['network_or_owner_input_executed'] is False,
         'fresh-unexecuted-trial-join')
    word(body['registration_nonce_hex32'], 'registration-nonce')
    certs = selection['certificates']
    body_certs = body['certificates']
    need(type(certs) is list and type(body_certs) is list and
         len(certs) == len(body_certs) == 3 and
         type(body['epoch_key']) is dict and
         'server_certificate_sha256' in body['epoch_key'],
         'trial-certificate-shape')
    pins = []
    for party, (left, right) in enumerate(zip(certs, body_certs)):
        fields(left, ('party', 'role', 'certificate_path',
                      'certificate_pem_sha256',
                      'certificate_der_sha256', 'private_key_path',
                      'private_key_body_exported_or_hashed_in_public_receipts'),
               'trial-certificate-fields')
        fields(right, ('party', 'role', 'certificate_pem_sha256',
                       'certificate_der_sha256'),
               'registration-certificate-fields')
        need({name: left[name] for name in right} == right and
             left['party'] == party and
             left['role'] == 'P' + str(party) and
             left['certificate_path'] == str(
                 root / 'public/certificates' / ('P' + str(party) + '.pem'))
             and left['private_key_path'] == str(
                 root / 'private' / ('party-' + str(party)) / 'tls' /
                 ('P' + str(party) + '.key')),
             'trial-certificate-order')
        need(left['private_key_body_exported_or_hashed_in_public_receipts']
             is False, 'no-public-private-key-body-hash')
        pins.append(word(left['certificate_der_sha256'],
                         'trial-certificate-pin'))
    requires(selection['epoch_key'], ('server_certificate_sha256',),
             'selected-epoch-key-fields')
    need(selection['epoch_key'] == body['epoch_key'] and
         len(set(pins)) == 3 and
         body['epoch_key']['server_certificate_sha256'] == pins,
         'trial-distinct-roster-pins')
    return {
        'trial_id': trial_id,
        'selection_sha256': hashlib.sha256(selection_raw).hexdigest(),
        'registration_file_sha256':
            hashlib.sha256(registration_raw).hexdigest(),
        'registration_sha256': selection['registration_sha256'],
        'server_certificate_sha256': pins,
    }


def _source_and_driver(candidate):
    fields(candidate['driver'], ('build', 'binary'), 'driver-fields')
    build_raw = read_ref(candidate['driver']['build'], 'driver-build')
    binary_raw = read_ref(candidate['driver']['binary'], 'driver-binary',
                          1 << 30)
    build = parse(build_raw)
    fields(build, ('schema', 'success', 'configured',
                   'proof_or_private_input_executed', 'source_sha256',
                   'compile', 'link', 'controls', 'vendor_artifacts',
                   'zlib_binary', 'zlib_headers_sha256'),
           'driver-build-fields')
    need(build['schema'] == 'kpi-registered-financial-gate-build/v1' and
         build['success'] is True and build['configured'] is True and
         build['proof_or_private_input_executed'] is False and
         type(build['source_sha256']) is dict and
         type(build['link']) is list and len(build['link']) == 1,
         'configured-unexecuted-driver-build')
    link = build['link'][0]
    fields(link, ('binary', 'exit_code', 'sha256'), 'driver-link-fields')
    binary_sha = hashlib.sha256(binary_raw).hexdigest()
    need(link == {'binary': 'mpc-registered-financial-gate',
                  'exit_code': 0, 'sha256': binary_sha},
         'driver-linked-binary')
    need(candidate['source_mode'] == 'REGISTERED_ACCEPTED_HEAD_ONLY' and
         'financial/run_financial.py' not in build['source_sha256'] and
         not any(name.endswith('/run_financial.py')
                 for name in build['source_sha256']),
         'no-source05-or-fixed-genesis-fallback')
    closure = candidate['source_closure']
    need(type(closure) is list and
         tuple(row.get('logical_path') for row in closure) == REQUIRED_SOURCE,
         'exact-ordered-dynamic-source-closure')
    for row in closure:
        fields(row, ('logical_path', 'path', 'sha256', 'bytes'),
               'source-closure-record-fields')
        word(row['sha256'], 'source-closure-hash')
        need(type(row['bytes']) is int and row['bytes'] > 0 and
             build['source_sha256'].get(row['logical_path']) ==
                 row['sha256'], 'source-closure-build-join')
        source = read_leaf(row['path'])
        need(len(source) == row['bytes'] and
             hashlib.sha256(source).hexdigest() == row['sha256'],
             'source-closure-leaf-changed')
    closure_sha = hashlib.sha256(canonical(closure)).hexdigest()
    return {
        'build_sha256': hashlib.sha256(build_raw).hexdigest(),
        'binary_sha256': binary_sha,
        'source_closure_sha256': closure_sha,
    }


def _identities(candidate, trial, predecessor):
    fresh = candidate['fresh_identity']
    fields(fresh, ('trial_id', 'run_id', 'attempt_id', 'cohort_id',
                   'accepted_head_identity_sha256',
                   'owner_contract_sha256'), 'fresh-identity-fields')
    need(fresh['trial_id'] == trial['trial_id'], 'fresh-selected-trial')
    for name in ('run_id', 'attempt_id', 'cohort_id',
                 'accepted_head_identity_sha256'):
        word(fresh[name], 'fresh-' + name)
    owners = fresh['owner_contract_sha256']
    need(type(owners) is list and len(owners) == 3 and
         all(word(value, 'fresh-owner-contract') for value in owners) and
         len(set(owners)) == 3, 'fresh-distinct-owner-contracts')
    prior = candidate['prior_identities']
    need(type(prior) is list and prior, 'prior-identity-history')
    all_prior_owners = set()
    for row in prior:
        fields(row, ('trial_id', 'run_id', 'attempt_id', 'cohort_id',
                     'accepted_head_identity_sha256', 'projection_sha256',
                     'owner_contract_sha256'), 'prior-identity-fields')
        need(type(row['trial_id']) is str and
             str(uuid.UUID(row['trial_id'])) == row['trial_id'],
             'prior-trial-id')
        for name in ('run_id', 'attempt_id', 'cohort_id',
                     'accepted_head_identity_sha256', 'projection_sha256'):
            word(row[name], 'prior-' + name)
        need(type(row['owner_contract_sha256']) is list and
             len(row['owner_contract_sha256']) == 3 and
             all(word(value, 'prior-owner-contract')
                 for value in row['owner_contract_sha256']),
             'prior-owner-contracts')
        all_prior_owners.update(row['owner_contract_sha256'])
    for name in ('trial_id', 'run_id', 'attempt_id', 'cohort_id',
                 'accepted_head_identity_sha256'):
        need(fresh[name] not in {row[name] for row in prior},
             'reused-' + name)
    need(not set(owners) & all_prior_owners, 'reused-owner-contract')
    need(predecessor['run_id'] in {row['run_id'] for row in prior} and
         predecessor['projection_sha256'] in
             {row['projection_sha256'] for row in prior},
         'predecessor-in-prior-history')
    return copy_json(fresh), copy_json(prior)


def copy_json(value):
    return json.loads(json.dumps(value))


def compile_selection(candidate_path):
    candidate_raw = read_leaf(candidate_path)
    candidate = parse(candidate_raw)
    fields(candidate, ('schema', 'round', 'predecessor', 'trial', 'driver',
                       'source_mode', 'source_closure', 'fresh_identity',
                       'prior_identities', 'head_policy', 'execution'),
           'candidate-fields')
    need(candidate['schema'] ==
             'kpb-successor-financial-round-candidate/v1' and
         candidate['round'] == 2, 'candidate-schema-and-round')
    predecessor = _predecessor(candidate)
    trial = _trial(candidate)
    driver = _source_and_driver(candidate)
    fresh, prior = _identities(candidate, trial, predecessor)
    policy = candidate['head_policy']
    fields(policy, ('expected_outpoint_hex36', 'expected_state_hex112',
                    'expected_reserve_sompi',
                    'expected_script_public_key_hex37', 'authority',
                    'serialized_receipt_is_authority',
                    'fresh_current_utxo_recheck_before_lock',
                    'fixed_genesis_fallback'), 'head-policy-fields')
    need(policy == {
        'expected_outpoint_hex36': predecessor['outpoint_hex36'],
        'expected_state_hex112': predecessor['state_hex112'],
        'expected_reserve_sompi': predecessor['reserve_sompi'],
        'expected_script_public_key_hex37':
            predecessor['script_public_key_hex37'],
        'authority': 'DIRECT_CPP_ACCEPTED_FINANCIAL_HEAD_CAPABILITY',
        'serialized_receipt_is_authority': False,
        'fresh_current_utxo_recheck_before_lock': True,
        'fixed_genesis_fallback': False,
    }, 'exact-successor-head-policy')
    execution = candidate['execution']
    fields(execution, ('network_contacted', 'private_owner_input_read',
                       'mpc_or_proof_executed',
                       'native_broadcast_or_settlement_executed'),
           'execution-fields')
    need(all(value is False for value in execution.values()),
         'source-selection-before-execution')
    return {
        'schema': 'kpb-successor-financial-round-source-selection/v1',
        'status': 'SOURCE_SELECTION_READY_EXECUTION_NOT_RUN',
        'round': 2,
        'selection_sha256': hashlib.sha256(candidate_raw).hexdigest(),
        'predecessor': predecessor,
        'head': {
            'outpoint_hex36': predecessor['outpoint_hex36'],
            'state_hex112': predecessor['state_hex112'],
            'reserve_sompi': predecessor['reserve_sompi'],
            'script_public_key_hex37':
                predecessor['script_public_key_hex37'],
        },
        'trial': trial,
        'driver': driver,
        'fresh_identity': fresh,
        'prior_identities': prior,
        'head_execution_authority':
            'DIRECT_NON_SERIALIZABLE_CPP_CAPABILITY_ONLY',
        'accepted_head_receipt_is_authority': False,
        'fresh_current_utxo_recheck_before_lock_required': True,
        'fixed_genesis_fallback': False,
        'launch_authorized': False,
        'network_contacted': False,
        'private_owner_input_read': False,
        'mpc_or_proof_executed': False,
        'native_broadcast_or_settlement_executed': False,
    }


def validate_completed_pair(selection, completed):
    fields(selection, (
        'schema', 'status', 'round', 'selection_sha256', 'predecessor',
        'head', 'trial', 'driver', 'fresh_identity', 'prior_identities',
        'head_execution_authority', 'accepted_head_receipt_is_authority',
        'fresh_current_utxo_recheck_before_lock_required',
        'fixed_genesis_fallback', 'launch_authorized',
        'network_contacted', 'private_owner_input_read',
        'mpc_or_proof_executed',
        'native_broadcast_or_settlement_executed'),
        'compiled-selection-fields')
    fields(completed, ('schema', 'run_id', 'projection_sha256',
                       'accepted_head_identity_sha256',
                       'selection_sha256'), 'completion-fields')
    need(selection['schema'] ==
             'kpb-successor-financial-round-source-selection/v1' and
         selection['status'] == 'SOURCE_SELECTION_READY_EXECUTION_NOT_RUN' and
         completed['schema'] ==
             'kpb-successor-financial-round-completion/v1' and
         completed['selection_sha256'] == selection['selection_sha256'],
         'completion-selection-join')
    for name in ('run_id', 'projection_sha256',
                 'accepted_head_identity_sha256'):
        word(completed[name], 'completion-' + name)
    fresh = selection['fresh_identity']
    need(completed['run_id'] == fresh['run_id'] and
         completed['accepted_head_identity_sha256'] ==
             fresh['accepted_head_identity_sha256'],
         'completion-selected-identities')
    prior = selection['prior_identities']
    need(completed['run_id'] not in {row['run_id'] for row in prior},
         'duplicate-completed-run')
    need(completed['projection_sha256'] not in
             {row['projection_sha256'] for row in prior},
         'duplicate-completed-projection')
    need(completed['accepted_head_identity_sha256'] not in
             {row['accepted_head_identity_sha256'] for row in prior},
         'duplicate-completed-head')
    return {
        'schema': 'kpb-successor-financial-round-pair-check/v1',
        'selection_sha256': selection['selection_sha256'],
        'predecessor_run_id': selection['predecessor']['run_id'],
        'successor_run_id': completed['run_id'],
        'distinct_round_pair': True,
        'privacy_or_native_settlement_qualified': False,
    }


def write_new(path, value):
    path = Path(path)
    need(path.is_absolute() and path.parent.is_dir() and not path.exists(),
         'fresh-absolute-output')
    data = canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        at = 0
        while at < len(data):
            count = os.write(fd, data[at:])
            need(count > 0, 'complete-output-write')
            at += count
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = compile_selection(args.candidate)
    write_new(args.output, result)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
