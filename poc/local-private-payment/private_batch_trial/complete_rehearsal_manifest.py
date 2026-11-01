#!/usr/bin/env python3
"""Fail-closed public evidence join for one complete unfunded lifecycle.

This does not prove, verify NativeFull, or grant readiness. It binds the fresh
Original trial, exact owner operations, registered hidden-mapping releases, R0
final-candidate evidence, independent Exit releases, and terminal scans into the
manifest that ``rehearsal_gate`` reexecutes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import uuid

import exit_wire
import private_lifecycle
import private_worker
import privacy_acceptance
import privacy_capture_bundle
import wallet_history


SOURCE_SCHEMA = 'kpb-complete-unfunded-native-lifecycle-source/v1'
MANIFEST_SCHEMA = 'kpb-complete-unfunded-native-lifecycle/v2'
EXPECTED_KINDS = ['genesis', 'payment', 'payment'] + ['exit'] * 9
CURRENT_HARD_STOPS = (
    'hardened-real-release-bound-privacy-authority-not-implemented',
    'registered-hidden-mapping-selected-configured-driver-result-not-executed',
    'direct-selected-host-r0-receipt-reexecution-not-implemented',
    'ordered-service-loss-producer-and-exit-binding-not-implemented',
    'terminal-nine-exit-service-loss-scan-privacy-gate-not-implemented',
)
QUALIFIER_PATH = (Path(__file__).resolve().parent.parent /
                  'mpc-prover/financial/qualify_public_release.py')
QUALIFIER = runpy.run_path(str(QUALIFIER_PATH))
ARTIFACT_NAMES = tuple(QUALIFIER['PUBLIC_ARTIFACT_NAMES'])


def need(value, category):
    if not value:
        raise ValueError('complete-rehearsal-' + category)


def fields(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='canonical-sha256'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, category)
    return value


def record(value, *, sized=False):
    fields(value, ('path', 'sha256', 'bytes') if sized else ('path', 'sha256'),
           'exact-public-record')
    path = Path(value['path'])
    need(path.is_absolute() and '..' not in path.parts, 'absolute-public-record')
    word(value['sha256'])
    if sized:
        need(type(value['bytes']) is int and value['bytes'] >= 0, 'public-record-byte-count')
    return value


def load_raw(read, value, *, sized=False):
    value = record(value, sized=sized)
    raw = read(Path(value['path']), value['sha256'])
    if sized:
        need(len(raw) == value['bytes'], 'public-record-exact-byte-count')
    return raw


def load_json(read, value):
    return private_worker.parse(load_raw(read, value))


def exact_trial(value):
    fields(value, ('schema', 'trial_id', 'label', 'network_id', 'domain_hex32',
        'profile_id_hex32', 'original_backup_schema', 'owner_count',
        'genuine_initial_Output_proofs', 'one_Original_only_recovery_probes',
        'independent_public_Output_verification_without_PK_mount',
        'initial_public_files', 'recovery_public_files', 'private_original_parent',
        'controller_read_or_hashed_private_bodies',
        'setup_mining_funding_broadcast_or_accepted_backing',
        'privacy_qualification', 'testnet_readiness', 'wall_seconds'), 'exact-fresh-trial')
    need(value['schema'] == 'kpb-fresh-unfunded-private-original-trial/v1'
         and value['network_id'] == 'testnet-10' and value['owner_count'] == 3
         and value['genuine_initial_Output_proofs'] == 3
         and value['one_Original_only_recovery_probes'] == 3
         and value['independent_public_Output_verification_without_PK_mount'] is True
         and value['controller_read_or_hashed_private_bodies'] is False
         and value['setup_mining_funding_broadcast_or_accepted_backing'] is False
         and value['privacy_qualification'] is False and value['testnet_readiness'] is False,
         'fresh-unfunded-original-trial')
    uuid.UUID(value['trial_id'])
    word(value['domain_hex32']); word(value['profile_id_hex32'])
    return value


PRIVACY_REFS = ('acceptance_result', 'baseline_bundle', 'candidate_bundle',
    'comparison_selection', 'candidate_run_selection',
    'candidate_diagnostic_selection', 'measurement_freeze')


def recompute_actual_privacy(refs, baseline, candidate):
    actual_baseline = privacy_capture_bundle.produce(
        refs['comparison_selection']['path'],
        refs['comparison_selection']['sha256'], 0)
    actual_candidate = privacy_capture_bundle.produce(
        refs['comparison_selection']['path'],
        refs['comparison_selection']['sha256'], 1)
    need(baseline == actual_baseline and candidate == actual_candidate,
         'privacy-bundles-reproduced-from-actual-capture-chain')
    owner_comparison = privacy_acceptance.read_owner_comparison_chain(
        actual_baseline, actual_candidate)
    return privacy_acceptance.evaluate(actual_baseline, actual_candidate,
                                       owner_comparison)


def exact_privacy_acceptance(read, refs, trial_ref, trial, payment_links):
    """Recompute v2 acceptance and bind it to these exact two payments.

    The acceptance result is not a caller PASS flag.  Its baseline and
    candidate bundles are re-evaluated, and the candidate's pre-truth run and
    diagnostic selections must name this fresh trial and the exact pay-result
    and projection records admitted by the lifecycle bridge.
    """
    fields(refs, PRIVACY_REFS, 'exact-privacy-gate-records')
    for name in PRIVACY_REFS:
        record(refs[name])
    baseline = load_json(read, refs['baseline_bundle'])
    candidate = load_json(read, refs['candidate_bundle'])
    result = load_json(read, refs['acceptance_result'])
    expected = recompute_actual_privacy(refs, baseline, candidate)
    need(result == expected
         and result['schema'] == 'kpb-privacy-acceptance-result/v2'
         and result['status'] == 'PASS_BOUNDED_ACTUAL_PRIVACY_IMPROVEMENT'
         and result['candidate_trial_id'] == trial['trial_id']
         and result['baseline_bundle_sha256'] == refs['baseline_bundle']['sha256']
         and result['candidate_bundle_sha256'] == refs['candidate_bundle']['sha256']
         and result['comparison_selection_sha256'] == refs['comparison_selection']['sha256']
         and result['candidate_run_selection_sha256'] == refs['candidate_run_selection']['sha256']
         and result['candidate_diagnostic_selection_sha256'] == refs['candidate_diagnostic_selection']['sha256']
         and result['candidate_diagnostic_run_selection_sha256'] ==
             candidate['diagnostic_run_selection_sha256']
         and result['measurement_freeze_sha256'] == refs['measurement_freeze']['sha256'],
         'recomputed-four-view-v2-privacy-pass')

    comparison = load_json(read, refs['comparison_selection'])
    fields(comparison, privacy_capture_bundle.COMPARISON_FIELDS,
           'exact-privacy-comparison-selection')
    need(comparison['schema'] == privacy_capture_bundle.COMPARISON_SCHEMA
         and type(comparison['runs']) is list and len(comparison['runs']) == 2,
         'privacy-two-run-comparison')
    for name in privacy_capture_bundle.COMPARISON_FIELDS[1:-1]:
        word(comparison[name], 'privacy-comparison-' + name)
    for selected, classification, bundle in zip(comparison['runs'],
            privacy_capture_bundle.CLASSIFICATIONS, (baseline, candidate)):
        fields(selected, ('classification', 'path', 'sha256'),
               'exact-privacy-comparison-run')
        need(selected['classification'] == classification
             and selected['sha256'] == bundle['run_selection_sha256'],
             'privacy-comparison-run-and-bundle')
    selected_candidate = comparison['runs'][1]
    need({'path': selected_candidate['path'], 'sha256': selected_candidate['sha256']}
         == refs['candidate_run_selection'], 'privacy-exact-candidate-run-reference')

    run = load_json(read, refs['candidate_run_selection'])
    fields(run, privacy_capture_bundle.RUN_FIELDS,
           'exact-candidate-privacy-run-selection')
    privacy_acceptance.validate_binding(run['binding'])
    need(run['schema'] == privacy_capture_bundle.ACTUAL_RUN_SCHEMA
         and run['scope'] == 'FRESH_UNFUNDED_ACTUAL_PRIVATE_BATCH'
         and run['classification'] == 'ACTUAL_HIDDEN_MAPPING_CANDIDATE'
         and run['binding'] == candidate['binding']
         and run['binding']['trial_id'] == trial['trial_id']
         and run['diagnostic_selection'] == refs['candidate_diagnostic_selection'],
         'privacy-candidate-run-fresh-trial-and-diagnostic')
    for name in ('method_sha256', 'measurement_freeze_sha256',
                 'workload_sha256', 'observer_source_sha256',
                 'capture_source_sha256', 'coverage_policy_sha256',
                 'bundle_producer_source_sha256',
                 'owner_comparison_source_sha256',
                 'owner_comparison_launcher_source_sha256'):
        need(run[name] == comparison[name] == candidate[name],
             'privacy-common-' + name)
    load_raw(read, refs['measurement_freeze'])
    diagnostic = load_json(read, refs['candidate_diagnostic_selection'])
    fields(diagnostic, privacy_capture_bundle.DIAGNOSTIC_FIELDS,
        'exact-candidate-diagnostic-selection')
    privacy_acceptance.validate_binding(diagnostic['binding'])
    need(diagnostic['schema'] == privacy_capture_bundle.DIAGNOSTIC_SCHEMA
         and diagnostic['binding'] == run['binding']
         and diagnostic['expected_classification'] ==
            'ACTUAL_HIDDEN_MAPPING_CANDIDATE'
         and diagnostic['bootstrap_trial'] == trial_ref
         and diagnostic['source_closure_sha256'] ==
            run['source_closure_sha256']
         and diagnostic['runtime_identity_sha256'] ==
            run['runtime_identity_sha256']
         and diagnostic['capture_producer_receipt'] ==
            run['capture_producer_receipt']
         and diagnostic['financial_rounds'] == run['financial_rounds']
         and type(diagnostic['rounds']) is list and len(diagnostic['rounds']) == 2,
         'privacy-exact-diagnostic-trial-and-run')
    diagnostic_run = diagnostic['run_selection']
    record(diagnostic_run); load_raw(read, diagnostic_run)
    need(diagnostic_run['sha256'] == run['binding']['selection_sha256']
         and diagnostic_run['sha256'] ==
             candidate['diagnostic_run_selection_sha256'],
         'privacy-diagnostic-inner-run-selection')
    observed_links = []
    for expected_round, row, financial in zip(
            (1, 2), diagnostic['rounds'], run['financial_rounds']):
        fields(row, ('round', 'pay_result', 'financial_round'),
               'exact-privacy-diagnostic-round')
        need(row['round'] == expected_round
             and row['financial_round'] == financial,
             'privacy-diagnostic-round-order')
        observed_links.append({'pay_result_sha256': row['pay_result']['sha256'],
                               'projection_sha256': financial[
                                   'retained_projection']['sha256']})
    need(observed_links == payment_links,
         'privacy-pass-same-two-pay-results-and-projections')
    need(False, CURRENT_HARD_STOPS[0])
    return result


def lifecycle_source_paths(operation):
    here = private_lifecycle.HERE
    paths = [here / name for name in ('private_lifecycle.py', 'new_private_trial.py',
        'component_run.py', 'lifecycle_worker.py', 'wallet_history.py',
        'private_worker.py', 'wallet_profile.py', 'output_producer.py',
        'output_verifier.py', 'owner_authority.mjs', 'exit_wire.py')]
    paths += [here.parent / 'private_batch/intent.py',
        here.parent / 'integration/trees.py', here.parent / 'verification/wire.py',
        here.parents[1] / 'future-recipient/v2/recipient.py']
    if operation == 'pay':
        paths += [here / 'privacy_owner.py', here / 'privacy_codec.py',
                  here / 'owner_record.py']
    if operation in ('scan', 'exit'):
        paths += [here / 'fresh_self_payout.py']
    return paths


def exact_lifecycle_pair(read, selection_ref, result_ref, trial, operation, round_number,
                         history_sha, tail_sha, owners):
    selection = load_json(read, selection_ref)
    fields(selection, ('schema', 'scope', 'operation_id', 'bootstrap_trial_id', 'operation',
        'source_members', 'runtime_members', 'round', 'owner_components',
        'private_originals_read_by_controller', 'creator_tuple_or_private_witness_public_exports',
        'funded_or_broadcast_entry_available', 'profile_sha256', 'history_sha256',
        'tail_sha256'), 'exact-lifecycle-selection')
    need(type(round_number) is int and type(selection['round']) is int
         and type(selection['owner_components']) is list
         and all(type(owner) is int for owner in selection['owner_components'])
         and selection['schema'] == 'kpb-original-lifecycle-selection/v1'
         and selection['scope'] == wallet_history.SCOPE
         and selection['bootstrap_trial_id'] == trial['trial_id']
         and selection['operation'] == operation and selection['round'] == round_number
         and selection['owner_components'] == owners
         and selection['private_originals_read_by_controller'] is False
         and selection['creator_tuple_or_private_witness_public_exports'] is False
         and selection['funded_or_broadcast_entry_available'] is False
         and selection['profile_sha256'] == private_lifecycle.bootstrap.PROFILE_SHA
         and selection['history_sha256'] == history_sha
         and selection['tail_sha256'] == tail_sha, 'selected-original-operation')
    expected_paths = lifecycle_source_paths(operation)
    need(type(selection['source_members']) is list
         and len(selection['source_members']) == len(expected_paths),
         'complete-owner-source-selection')
    for index, (member, expected_path) in enumerate(zip(
            selection['source_members'], expected_paths)):
        fields(member, ('index', 'path', 'sha256', 'bytes'), 'exact-owner-source-member')
        raw = read(expected_path, member['sha256'])
        need(type(member['index']) is int and member['index'] == index
             and member['path'] == str(expected_path)
             and type(member['bytes']) is int and member['bytes'] == len(raw),
             'current-owner-source-member')
    expected_runtime = [
        {'path': alias, 'sha256': pin}
        for alias, _, pin in private_lifecycle.selected_runtime(read, operation)
    ]
    need(selection['runtime_members'] == expected_runtime,
         'exact-current-owner-runtime-selection')
    result = load_json(read, result_ref)
    fields(result, ('schema', 'scope', 'operation', 'operation_id', 'bootstrap_trial_id',
        'round', 'owners', 'controller_read_or_hashed_private_bodies',
        'native_settlement_or_privacy_qualification', 'wall_seconds'),
        'exact-lifecycle-controller-result')
    need(type(result['round']) is int
         and result['schema'] == 'kpb-original-lifecycle-controller-result/v1'
         and result['scope'] == wallet_history.SCOPE and result['operation'] == operation
         and result['operation_id'] == selection['operation_id']
         and result['bootstrap_trial_id'] == trial['trial_id']
         and result['round'] == round_number
         and result['controller_read_or_hashed_private_bodies'] is False
         and result['native_settlement_or_privacy_qualification'] is False
         and type(result['owners']) is list
         and [row['owner_component'] for row in result['owners']] == owners
         and all(type(row['owner_component']) is int for row in result['owners']),
         'same-original-operation-result')
    original_parent = Path(trial['private_original_parent'])
    for row in result['owners']:
        fields(row, ('owner_component', 'private_output_directory', 'public_receipt', 'status'),
               'exact-owner-controller-row')
        private_output = Path(row['private_output_directory'])
        public_receipt = Path(row['public_receipt'])
        need(private_output.is_absolute()
             and private_output.is_relative_to(original_parent / 'operations')
             and private_output.name == 'owner-' + str(row['owner_component'])
             and public_receipt.is_absolute()
             and public_receipt.name == 'PUBLIC.json'
             and public_receipt.parent.name == 'owner-' + str(row['owner_component'])
             and private_worker.parse(read(public_receipt)) == row['status'],
             'current-same-trial-owner-public-receipt')
        private_lifecycle.public_receipt(row['status'], operation)
    return selection, result


def exact_input_history(value, final, transition_count):
    need(type(transition_count) is int and transition_count >= 0,
         'input-history-integer-transition-count')
    for name in ('schema', 'scope', 'chain_hex32', 'pool_hex32', 'profile_hex32',
                 'domain_hex32', 'service_hex32', 'genesis'):
        need(value.get(name) == final.get(name), 'input-history-same-' + name)
    need(value.get('transitions') == final['transitions'][:transition_count],
         'input-history-exact-prefix')
    if transition_count == 0:
        expected = {'outpoint_hex36': final['genesis']['outpoint_hex36'],
            'state_hex112': final['genesis']['state_hex112'],
            'reserve_sompi': final['genesis']['reserve_sompi']}
    else:
        event = final['transitions'][transition_count - 1]
        raw = bytes.fromhex(event['projection_hex'])
        if event['kind'] == 'payment':
            body = raw[193:]
            state = (b'KPBAST01' + body[104:136] + body[284:316] + body[348:352]
                     + body[316:348] + body[352:356])
            reserve = int.from_bytes(body[356:364], 'little')
        else:
            effect = exit_wire.validate_public(raw)
            state, reserve = effect.next_state(), effect.new_reserve
        expected = {'outpoint_hex36': event['successor_outpoint_hex36'],
                    'state_hex112': state.hex(), 'reserve_sompi': reserve}
    need(value.get('head') == expected, 'input-history-exact-current-head')


FR_MODULUS = ('21888242871839275222246405745257275088548364400416034343698204186575808495617')


def owner_contract(raw):
    need(type(raw) is bytes and raw.endswith(b'\n'), 'owner-contract-canonical-file')
    try:
        lines = raw.decode('ascii').splitlines()
    except UnicodeDecodeError:
        need(False, 'owner-contract-ascii')
    names = ('run_nonce', 'model', 'source', 'pk', 'vk', 'trace', 'layout',
             'cohort', 'owner_id', 'input_count', 'server_certificate_0',
             'server_certificate_1', 'server_certificate_2', 'owner_certificate')
    need(len(lines) == 16 and lines[0] == 'KPI_OWNER_CONTRACT_V2'
         and lines[-1] == 'END', 'owner-contract-exact-v2-lines')
    result = {}
    for line, name in zip(lines[1:-1], names):
        pieces = line.split(' ')
        need(len(pieces) == 2 and pieces[0] == name,
             'owner-contract-field-order')
        result[name] = pieces[1]
    for name in names:
        if name in ('owner_id', 'input_count'):
            need(result[name].isdigit()
                 and (result[name] == '0' or not result[name].startswith('0')),
                 'owner-contract-canonical-count')
        else:
            word(result[name], 'owner-contract-' + name)
    result['owner_id'] = int(result['owner_id'])
    result['input_count'] = int(result['input_count'])
    servers = [result['server_certificate_' + str(index)] for index in range(3)]
    need(len(set(servers)) == 3 and result['owner_certificate'] not in servers,
         'owner-contract-distinct-certificates')
    canonical = ('KPI_MASCOT_OWNER_INPUT_V2\nBN254\nFr\n' + FR_MODULUS
        + '\nDDNNT_ACTIVE_3N\n' + result['run_nonce'] + '\n' + result['model']
        + '\n' + result['source'] + '\n' + result['pk'] + '\n' + result['vk']
        + '\n' + result['trace'] + '\n' + result['layout'] + '\n'
        + result['cohort'] + '\n' + str(result['owner_id']) + '\n'
        + str(result['input_count']) + '\nP0\n' + servers[0] + '\nP1\n'
        + servers[1] + '\nP2\n' + servers[2] + '\nC'
        + str(result['owner_id']) + '\n' + result['owner_certificate'] + '\n')
    return result, canonical.encode('ascii')


def owner_contracts_identity(rows):
    body = bytearray(b'KPB_FINANCIAL_OWNER_CONTRACT_SET_V1\n')
    for _, canonical in rows:
        body += len(canonical).to_bytes(8, 'little') + canonical
    return hashlib.sha256(body).hexdigest()


def exact_intake_binding(read, value, trial, round_number, history_sha,
                         selection_ref, result_ref, operation_id,
                         component_profile_sha, head):
    fields(value, ('schema', 'trial_id', 'round', 'input_history_sha256',
        'lifecycle_operation_id', 'financial_run_id', 'owner_contracts_sha256',
        'owner_contracts', 'lifecycle_selection_sha256',
        'lifecycle_result_sha256', 'component_profile_sha256', 'head', 'owner_components',
        'bound_before_private_intake', 'controller_read_or_hashed_owner_private_bodies'),
        'exact-owner-intake-binding')
    fields(value['head'], ('outpoint_hex36', 'state_hex112', 'reserve_sompi'),
           'exact-owner-intake-head')
    need(type(value['round']) is int and type(round_number) is int
         and value['schema'] == 'kpb-owner-intake-financial-binding/v1'
         and value['trial_id'] == trial['trial_id'] and value['round'] == round_number
         and value['input_history_sha256'] == history_sha
         and value['lifecycle_operation_id'] == operation_id
         and value['lifecycle_selection_sha256'] == selection_ref['sha256']
         and value['lifecycle_result_sha256'] == result_ref['sha256']
         and value['component_profile_sha256'] == component_profile_sha
         and value['head'] == head and value['owner_components'] == [0, 1, 2]
         and value['bound_before_private_intake'] is True
         and value['controller_read_or_hashed_owner_private_bodies'] is False,
         'pre-private-intake-lifecycle-binding')
    word(value['financial_run_id']); word(value['owner_contracts_sha256'])
    need(type(value['owner_contracts']) is list and len(value['owner_contracts']) == 3,
         'three-owner-contract-records')
    parsed = [owner_contract(load_raw(read, item, sized=True))
              for item in value['owner_contracts']]
    contracts = [row[0] for row in parsed]
    common = ('run_nonce', 'model', 'source', 'pk', 'vk', 'trace', 'layout',
              'cohort', 'server_certificate_0', 'server_certificate_1',
              'server_certificate_2', 'input_count')
    need([row['owner_id'] for row in contracts] == [0, 1, 2]
         and all(type(row['owner_id']) is int and row['input_count'] == 2_635_409
                 for row in contracts)
         and len({row['owner_certificate'] for row in contracts}) == 3
         and all(all(row[name] == contracts[0][name] for name in common)
                 for row in contracts)
         and contracts[0]['run_nonce'] == value['financial_run_id']
         and owner_contracts_identity(parsed) == value['owner_contracts_sha256'],
         'exact-three-financial-owner-contracts')
    return value


def exact_public_financial_artifacts(read, ref, component_profile_sha, tail_sha):
    value = load_json(read, ref)
    fields(value, ('schema', 'status', 'run_id', 'component_profile_sha256', 'head', 'successor',
        'artifacts', 'effects_sha256', 'core_sha256', 'aggregate_proof_sha256',
        'projection_sha256', 'egress_binding_sha256', 'successor_state_sha256',
        'successor_script_public_key_hex37', 'accepted_head_authority',
        'R0_or_native_VM_executed', 'R0_receipt_verified',
        'full_native_candidate_validated', 'native_settlement_performed'),
        'exact-public-financial-artifacts')
    fields(value['head'], ('outpoint_hex36', 'state_hex112', 'reserve_sompi',
                           'script_public_key_hex37'), 'exact-public-financial-head')
    fields(value['successor'], ('state_hex112', 'reserve_sompi', 'script_public_key_hex37'),
           'exact-public-financial-successor')
    need(value['schema'] == 'kpb-qualified-public-financial-artifacts/v1'
         and value['status'] == 'AGGREGATE_AND_SIX_OUTPUT_PROOFS_VERIFIED'
         and value['component_profile_sha256'] == component_profile_sha
         and value['accepted_head_authority'] is False
         and value['R0_or_native_VM_executed'] is False
         and value['R0_receipt_verified'] is False
         and value['full_native_candidate_validated'] is False
         and value['native_settlement_performed'] is False,
         'public-financial-handoff-only')
    word(value['run_id'])
    for name in ('effects_sha256', 'core_sha256', 'aggregate_proof_sha256',
                 'projection_sha256', 'egress_binding_sha256'):
        word(value[name], 'financial-' + name)
    need(type(value['artifacts']) is dict and set(value['artifacts']) == set(ARTIFACT_NAMES),
         'exact-public-financial-artifacts')
    raw = {name: load_raw(read, value['artifacts'][name], sized=True)
           for name in ARTIFACT_NAMES}
    core, proof = raw['released_core'], raw['released_proof']
    released_projection, projection = (raw['released_projection'],
                                       raw['retained_projection'])
    tail, journal, profile_raw = (raw['native_tail'], raw['journal'],
                                  raw['component_profile'])
    need(raw['qualifier_source'] == QUALIFIER_PATH.read_bytes()
         and hashlib.sha256(raw['public_host']).hexdigest() == QUALIFIER['HOST_SHA256']
         and hashlib.sha256(raw['namespace_tool']).hexdigest() == QUALIFIER['BWRAP_SHA256'],
         'current-qualified-public-source-host-and-namespace')
    profile = QUALIFIER['admit_profile'](profile_raw)
    QUALIFIER['admit_unselected_outer'](raw['outer_selection'])
    financial = QUALIFIER['admit_release'](raw['financial_result'], core, proof,
        released_projection, profile, tail)
    direct_report, direct_journal = QUALIFIER['run_host'](
        raw['public_host'], released_projection, profile,
        Path(value['artifacts']['namespace_tool']['path']))
    retained_report = QUALIFIER['strict_json'](raw['host_cross_check'])
    expected_journal = (b'KPBAJR01' + bytes.fromhex(profile['domain_hex32'])
                        + bytes.fromhex(component_profile_sha)
                        + hashlib.sha256(projection).digest())
    successor_state = QUALIFIER['successor_state'](core)
    successor_spk = QUALIFIER['reserve_spk'](successor_state, tail)
    party = financial['parties'][0]
    need(financial['run_id'] == value['run_id']
         and direct_report == retained_report and direct_journal == journal
         and len(core) == 10364 and len(proof) == 128 and len(projection) == 10685
         and len(journal) == 104 and projection[193:10557] == core
         and projection[10557:] == proof and released_projection == projection
         and value['artifacts']['component_profile']['sha256'] == component_profile_sha
         and value['artifacts']['native_tail']['sha256'] == tail_sha
         and journal == expected_journal
         and value['head']['script_public_key_hex37']
             == exit_wire.state_spk(bytes.fromhex(value['head']['state_hex112']), tail).hex()
         and value['successor'] == {'state_hex112': successor_state.hex(),
             'reserve_sompi': int.from_bytes(core[356:364], 'little'),
             'script_public_key_hex37': successor_spk.hex()}
         and value['successor_state_sha256'] == hashlib.sha256(successor_state).hexdigest()
         and value['successor_script_public_key_hex37'] == successor_spk.hex()
         and hashlib.sha256(core).hexdigest() == value['core_sha256'] == value['effects_sha256']
             == party['core_sha256'] == party['effects_sha256']
         and hashlib.sha256(proof).hexdigest() == value['aggregate_proof_sha256']
             == party['proof_sha256']
         and hashlib.sha256(projection).hexdigest() == value['projection_sha256']
             == party['projection_sha256']
         and value['egress_binding_sha256'] == party['egress_binding_sha256']
         and hashlib.sha256(journal).hexdigest() == value['artifacts']['journal']['sha256'],
         'actual-public-financial-artifact-join')
    return value, projection, journal


def exact_registered_driver_result(read, selection_ref, result_ref, binding, artifacts):
    """Refuse until the built driver is selected, configured, run and verified.

    A standalone JSON with success booleans cannot create registered authority.
    The available driver source/build remains unconfigured and unexecuted. A
    selected producer must bind an exact source/build/config selection, this
    owner-intake record, all-three agreed party outputs, durable EGRESS, and the
    same accepted head/history.  The driver source/build and default-refusal
    controls exist; no selected configuration or executed result satisfies
    REGISTERED-DRIVER-REQUIREMENTS.json yet.
    """
    record(selection_ref); record(result_ref)
    load_raw(read, selection_ref); load_raw(read, result_ref)
    need(False, CURRENT_HARD_STOPS[1])


def witness_proof(case):
    raw = bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])
    need(raw[:2] == b'\x4c\x80' and len(raw) >= 130, 'fixed-native-proof-witness')
    return raw[2:130]


def case_projection(case, kind):
    body, entries = case['transaction'], case['entries']
    need(kind in ('payment', 'exit') and type(body['version']) is int and body['version'] == 1
         and len(body['inputs']) == len(entries) == 1 and body['lockTime'] == 0
         and body['gas'] == 0 and body['subnetworkId'] == '00' * 20,
         'exact-native-case-frame')
    source, entry = body['inputs'][0], entries[0]
    need(type(source['sequence']) is int and source['sequence'] == (1 << 64) - 1
         and entry['isCoinbase'] is False and entry['covenantId'] is None,
         'exact-native-case-input')
    point = source['previousOutpoint']
    need(type(point['index']) is int and 0 <= point['index'] < 1 << 32
         and type(entry['amount']) is int and 0 < entry['amount'] <= exit_wire.MAX,
         'exact-native-integer-input')
    raw_point = bytes.fromhex(point['transactionId']) + point['index'].to_bytes(4, 'little')
    payload = bytes.fromhex(body['payload'])
    need(len(payload) == (10492 if kind == 'payment' else 1604), 'exact-native-payload-width')
    prefix = (b'KPBAFX01' if kind == 'payment' else b'KPBXFX01') + b'\x01\0\x01\0'
    prefix += raw_point + b'\xff' * 8 + entry['amount'].to_bytes(8, 'little')
    script = bytes.fromhex(entry['scriptPublicKey'])
    prefix += len(script).to_bytes(2, 'little') + script + len(body['outputs']).to_bytes(2, 'little')
    for output in body['outputs']:
        need(output['covenant'] is None and type(output['value']) is int
             and 0 < output['value'] <= exit_wire.MAX, 'native-output-covenant')
        output_script = bytes.fromhex(output['scriptPublicKey'])
        prefix += output['value'].to_bytes(8, 'little') + len(output_script).to_bytes(2, 'little')
        prefix += output_script + b'\0'
    return prefix + bytes(36) + len(payload).to_bytes(4, 'little') + payload


def exact_final_chain(read, spec, artifacts, registered, case, projection, tail_sha):
    selection = load_json(read, spec['final_selection'])
    fields(selection, ('schema', 'selected', 'classification',
        'registered_history_sha256', 'source_members', 'tools',
        'component_profile', 'outer_selection', 'parameters'),
        'exact-offline-final-selection')
    need(selection['schema'] == 'kpb-offline-final-selection/v1'
         and selection['selected'] is True
         and selection['classification'] == 'RESEARCH_TESTNET_ONLY'
         and selection['registered_history_sha256'] == registered['registered_history_sha256']
         and selection['component_profile']['sha256'] == artifacts['component_profile_sha256'],
         'selected-offline-final-source')
    need(type(selection['source_members']) is list and selection['source_members'],
         'complete-offline-final-source-closure')
    selected_files = {}
    for item in selection['source_members']:
        record(item); load_raw(read, item); selected_files[item['path']] = item
    fields(selection['tools'], ('codec', 'host', 'native_validator'),
           'exact-offline-final-tools')
    for item in (*selection['tools'].values(), selection['component_profile'],
                 selection['outer_selection'], selection['parameters']):
        record(item); load_raw(read, item)
    final_root = QUALIFIER_PATH.parents[1] / 'history/final_candidate'
    settlement_root = QUALIFIER_PATH.parents[1] / 'history/settlement'
    for required in (final_root / 'finalize.py', final_root / 'offline_protocol.py',
                     settlement_root / 'launch.py', settlement_root / 'protocol.py'):
        need(str(required) in selected_files
             and selected_files[str(required)]['sha256']
                 == hashlib.sha256(required.read_bytes()).hexdigest(),
             'current-offline-final-source-closure')
    outer = private_worker.parse(load_raw(read, selection['outer_selection']))
    fields(outer, ('schema', 'selected', 'classification',
        'component_profile_sha256', 'image_id_hex32', 'program_sha256'),
        'exact-selected-outer')
    need(outer['schema'] == 'private-batch-outer-selection/v1'
         and outer['selected'] is True
         and outer['classification'] == 'RESEARCH_TESTNET_ONLY'
         and outer['component_profile_sha256'] == artifacts['component_profile_sha256'],
         'actual-selected-r0-outer')
    r0_raw = load_raw(read, spec['r0_receipt'])
    need(len(r0_raw) > 0, 'retained-nonempty-r0-receipt')
    request = load_json(read, spec['final_request'])
    fields(request, ('schema', 'nonce_hex32', 'history_key_hex32', 'registered_history_sha256',
        'server_certificates_hex32', 'attempt_id_hex32', 'locked_binding_sha256',
        'prepared_core_sha256', 'context', 'head', 'native_policy', 'egress_record',
        'egress', 'candidate'), 'exact-offline-final-request')
    need(request['schema'] == 'kpb-offline-final-request/v1'
         and request['registered_history_sha256'] == registered['registered_history_sha256']
         and request['prepared_core_sha256'] == artifacts['core_sha256'],
         'same-registered-egress-final-request')
    for name in ('nonce_hex32', 'history_key_hex32', 'registered_history_sha256',
                 'attempt_id_hex32', 'locked_binding_sha256', 'prepared_core_sha256'):
        word(request[name], 'final-request-' + name)
    fields(request['context'], ('chain_hex32', 'pool_hex32', 'profile_hex32',
        'domain_hex32', 'service_hex32', 'epoch_hex32'), 'exact-final-context')
    for value in request['context'].values():
        word(value, 'final-context-word')
    need(request['context']['chain_hex32'] ==
         'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
         'final-request-selected-testnet-genesis')
    certs = request['server_certificates_hex32']
    need(type(certs) is list and len(certs) == len(set(certs)) == 3,
         'final-request-three-distinct-server-certificates')
    for certificate in certs:
        word(certificate, 'final-request-server-certificate')
    history_key = b'KPBHKEY1' + b''.join(bytes.fromhex(request['context'][name])
        for name in ('chain_hex32', 'pool_hex32', 'domain_hex32',
                     'profile_hex32', 'service_hex32', 'epoch_hex32'))
    history_key += b''.join(bytes.fromhex(certificate) for certificate in certs)
    need(hashlib.sha256(history_key).hexdigest() == request['history_key_hex32'],
         'final-request-actual-history-key-and-roster')
    fields(request['head'], ('outpoint', 'state_hex112', 'reserve_sompi'), 'exact-final-head')
    fields(request['head']['outpoint'], ('transactionId', 'index'), 'exact-final-outpoint')
    raw_point = (bytes.fromhex(request['head']['outpoint']['transactionId'])
                 + request['head']['outpoint']['index'].to_bytes(4, 'little'))
    need(raw_point.hex() == artifacts['head']['outpoint_hex36']
         and request['head']['state_hex112'] == artifacts['head']['state_hex112']
         and request['head']['reserve_sompi'] == str(artifacts['head']['reserve_sompi']),
         'final-request-same-financial-head')
    state = bytes.fromhex(request['head']['state_hex112'])
    need(state[:8] == b'KPBAST01'
         and state[8:40].hex() == request['context']['domain_hex32'],
         'final-request-head-domain')
    fields(request['egress'], ('core_sha256', 'aggregate_proof_sha256',
        'projection_sha256', 'nfs_hex32'), 'exact-final-egress')
    need(request['egress']['core_sha256'] == artifacts['core_sha256']
         and request['egress']['aggregate_proof_sha256'] == artifacts['aggregate_proof_sha256']
         and request['egress']['projection_sha256'] == artifacts['projection_sha256']
         and type(request['egress']['nfs_hex32']) is list
         and len(request['egress']['nfs_hex32']) == 3
         and request['egress']['nfs_hex32'] == sorted(set(request['egress']['nfs_hex32'])),
         'final-request-same-public-egress')
    for name in ('core_sha256', 'aggregate_proof_sha256', 'projection_sha256'):
        word(request['egress'][name], 'final-egress-' + name)
    for value in request['egress']['nfs_hex32']:
        word(value, 'final-egress-nf')
    fields(request['egress_record'], ('sequence', 'checkpoint_sha256'), 'exact-final-egress-record')
    need(type(request['egress_record']['sequence']) is int
         and request['egress_record']['sequence'] > 0, 'final-egress-sequence')
    word(request['egress_record']['checkpoint_sha256'])
    fields(request['candidate'], ('case', 'r0_receipt'), 'exact-final-candidate-inputs')
    need(request['candidate']['case'] == spec['case']
         and request['candidate']['r0_receipt'] == spec['r0_receipt'],
         'final-request-exact-case-and-r0')
    fields(request['native_policy'], ('old_script_public_key_hex37',
        'immutable_tail_sha256', 'native_parameters_sha256'), 'exact-final-native-policy')
    need(request['native_policy']['immutable_tail_sha256'] == tail_sha
         and request['native_policy']['old_script_public_key_hex37']
             == artifacts['head']['script_public_key_hex37']
         and request['native_policy']['native_parameters_sha256']
             == selection['parameters']['sha256'], 'final-request-native-policy')
    word(request['native_policy']['immutable_tail_sha256'])
    word(request['native_policy']['native_parameters_sha256'])
    result = load_json(read, spec['final_result'])
    fields(result, ('schema', 'classification', 'nonce_hex32', 'request_sha256',
        'adapter_selection_sha256', 'locked_binding_sha256', 'egress_record',
        'final_candidate', 'candidate_sha256', 'network_or_chain_acceptance',
        'settlement_or_unlock_authority', 'funding_or_broadcast', 'journal_modified',
        'replay_result_sha256'), 'exact-direct-offline-final-result')
    fields(result['final_candidate'], ('raw_case', 'canonical_case', 'projection',
        'selection', 'image', 'journal', 'outer_receipt', 'native_proof'),
        'exact-final-candidate-identities')
    final = result['final_candidate']
    for value in final.values():
        word(value, 'final-candidate-identity')
    for name in ('nonce_hex32', 'request_sha256', 'adapter_selection_sha256',
                 'locked_binding_sha256', 'candidate_sha256', 'replay_result_sha256'):
        word(result[name], 'final-result-' + name)
    canonical_case = hashlib.sha256(private_worker.encoded(case)).hexdigest()
    candidate_encoding = b'KPBHFIN1' + b''.join(bytes.fromhex(final[name]) for name in (
        'raw_case', 'canonical_case', 'projection', 'selection', 'image',
        'journal', 'outer_receipt', 'native_proof'))
    replay = load_json(read, spec['final_replay_result'])
    expected_replay = dict(result)
    expected_replay['schema'] = 'kpb-offline-final-replay/v1'
    expected_replay.pop('replay_result_sha256')
    need(replay == expected_replay
         and spec['final_replay_result']['sha256'] == result['replay_result_sha256'],
         'exact-retained-offline-final-replay')
    need(result['schema'] == 'kpb-direct-offline-final-result/v1'
         and result['classification'] == 'OFFLINE_FINAL_CANDIDATE_NOT_CHAIN_ACCEPTANCE'
         and result['request_sha256'] == spec['final_request']['sha256']
         and result['adapter_selection_sha256'] == spec['final_selection']['sha256']
         and result['egress_record'] == request['egress_record']
         and result['nonce_hex32'] == request['nonce_hex32']
         and result['locked_binding_sha256'] == request['locked_binding_sha256']
         and result['network_or_chain_acceptance'] is False
         and result['settlement_or_unlock_authority'] is False
         and result['funding_or_broadcast'] is False and result['journal_modified'] is False
         and final['raw_case'] == spec['case']['sha256']
         and final['canonical_case'] == canonical_case
         and final['projection'] == artifacts['projection_sha256']
         and final['outer_receipt'] == spec['r0_receipt']['sha256']
         and hashlib.sha256(r0_raw).hexdigest() == final['outer_receipt']
         and final['selection'] == selection['parameters']['sha256']
         and final['image'] == outer['image_id_hex32']
         and final['journal'] == artifacts['artifacts']['journal']['sha256']
         and final['native_proof'] == hashlib.sha256(witness_proof(case)).hexdigest()
         and result['candidate_sha256'] == hashlib.sha256(candidate_encoding).hexdigest()
         and hashlib.sha256(projection).hexdigest() == final['projection'],
         'genuine-r0-final-native-candidate-chain')
    need(False, CURRENT_HARD_STOPS[2])


def exact_genesis(read, source, trial, history):
    case = load_json(read, source['genesis_case'])
    result = load_json(read, source['genesis_result'])
    need(result.get('schema') == 'kpb-real-GEN3-signed-NativeFull/v1'
         and result.get('trial_id') == trial['trial_id']
         and result.get('case_sha256') == source['genesis_case']['sha256']
         and result.get('component_profile_sha256') == source['component_profile_sha256']
         and result.get('all_three_Original_ALL_signatures_and_actual_native_Full') is True
         and result.get('SDK_lossless_roundtrip') is True
         and result.get('genesis_reserve_sompi') == 6_000_000_000
         and result.get('accepted_chain_funding_or_broadcast') is False,
         'exact-signed-native-genesis-result')
    payload = bytes.fromhex(case['transaction']['payload'])
    need(len(payload) == 1648 and str(uuid.UUID(bytes=payload[72:88])) == trial['trial_id']
         and case['transaction']['id'] + '00000000' == history['genesis']['outpoint_hex36'],
         'genesis-same-fresh-trial-and-history')
    return case


def exact_exit(read, spec, trial, final_history, tail_sha, ordinal):
    need(type(ordinal) is int and type(spec['ordinal']) is int
         and type(spec['owner_component']) is int
         and spec['ordinal'] == ordinal and spec['owner_component'] in (0, 1, 2),
         'ordered-independent-exit')
    input_history = load_json(read, spec['input_history'])
    exact_input_history(input_history, final_history, 2 + ordinal)
    selection, result = exact_lifecycle_pair(read, spec['lifecycle_selection'],
        spec['lifecycle_result'], trial, 'exit', 2, spec['input_history']['sha256'], tail_sha,
        [spec['owner_component']])
    release = load_json(read, spec['release_selection'])
    fields(release, ('schema', 'scope', 'bootstrap_trial_id', 'prepared_operation_id',
        'owner_component', 'history_sha256', 'tail_sha256', 'source_members',
        'runtime_members', 'private_candidate_path',
        'controller_read_or_hashed_private_bodies', 'native_or_chain_acceptance'),
        'exact-exit-release-selection')
    need(type(release['owner_component']) is int
         and release['schema'] == 'kpb-explicit-owner-exit-release-selection/v1'
         and release['scope'] == wallet_history.SCOPE
         and release['bootstrap_trial_id'] == trial['trial_id']
         and release['prepared_operation_id'] == result['operation_id']
         and release['owner_component'] == spec['owner_component']
         and release['history_sha256'] == spec['input_history']['sha256']
         and release['tail_sha256'] == tail_sha
         and release['controller_read_or_hashed_private_bodies'] is False
         and release['native_or_chain_acceptance'] is False, 'same-independent-exit-release')
    expected_release_sources = [
        Path(__file__).resolve().parent / 'exit_release.py',
        Path(__file__).resolve().parent / 'exit_wire.py',
        Path(__file__).resolve().parent.parent / 'verification/wire.py',
    ]
    need(type(release['source_members']) is list
         and len(release['source_members']) == len(expected_release_sources),
         'complete-exit-release-source-selection')
    for item, path in zip(release['source_members'], expected_release_sources):
        fields(item, ('path', 'sha256'), 'exact-exit-release-source')
        need(item['path'] == str(path)
             and hashlib.sha256(read(path, item['sha256'])).hexdigest() == item['sha256'],
             'current-exit-release-source')
    expected_release_runtime = [
        {'path': '/runtime/prover', 'sha256': private_lifecycle.bootstrap.BINARY_SHA},
        {'path': '/parameters/MANIFEST.json',
         'sha256': private_lifecycle.EXIT_MANIFEST_SHA},
    ]
    need(release['runtime_members'] == expected_release_runtime,
         'exact-exit-release-runtime-selection')
    owner_row = result['owners'][0]
    need(release['private_candidate_path'] ==
         str(Path(owner_row['private_output_directory']) / 'EXIT-CANDIDATE.json'),
         'exit-release-same-original-prepared-private-candidate')
    candidate = load_json(read, spec['released_candidate'])
    fields(candidate, ('schema', 'scope', 'projection_hex', 'proof_hex128',
        'statement_hex152', 'native_or_chain_acceptance'), 'exact-released-exit')
    receipt = load_json(read, spec['release_receipt'])
    fields(receipt, ('schema', 'scope', 'candidate_sha256', 'AuthExit_proof_verified',
        'Original_or_openings_exported', 'native_or_chain_acceptance',
        'privacy_qualification'), 'exact-exit-release-receipt')
    need(candidate['schema'] == 'kpb-owner-prepared-independent-exit/v1'
         and candidate['scope'] == wallet_history.SCOPE
         and candidate['native_or_chain_acceptance'] is False
         and receipt['schema'] == 'kpb-explicit-owner-exit-release/v1'
         and receipt['scope'] == wallet_history.SCOPE
         and receipt['candidate_sha256'] == spec['released_candidate']['sha256']
         and receipt['AuthExit_proof_verified'] is True
         and receipt['Original_or_openings_exported'] is False
         and receipt['native_or_chain_acceptance'] is False
         and receipt['privacy_qualification'] is False, 'genuine-independent-exit-release')
    case = load_json(read, spec['case'])
    projection = case_projection(case, 'exit')
    event = final_history['transitions'][2 + ordinal]
    need(candidate['projection_hex'] == projection.hex() == event['projection_hex']
         and candidate['proof_hex128'] == event['proof_hex128']
         and candidate['statement_hex152'] == exit_wire.statement(projection).hex()
         and witness_proof(case).hex() == event['proof_hex128'],
         'same-exit-candidate-history-and-native-witness')
    return case, selection['operation_id']


def exact_service_loss(value, trial, round2_history_sha, run_ids):
    fields(value, ('schema', 'trial_id', 'after_round2_history_sha256',
        'financial_run_ids', 'process_identities_checked',
        'active_financial_service_processes', 'active_financial_service_listeners',
        'private_service_state_mounted_to_exit', 'owner_exit_service_dependency',
        'controller_read_or_hashed_private_service_state'), 'exact-service-loss-receipt')
    need(value['schema'] == 'kpb-unfunded-financial-service-loss/v1'
         and value['trial_id'] == trial['trial_id']
         and value['after_round2_history_sha256'] == round2_history_sha
         and value['financial_run_ids'] == run_ids
         and type(value['process_identities_checked']) is list
         and len(value['process_identities_checked']) >= 3
         and len(value['process_identities_checked']) ==
             len(set(value['process_identities_checked']))
         and all(type(item) is int and item > 0 for item in value['process_identities_checked'])
         and type(value['active_financial_service_processes']) is int
         and value['active_financial_service_processes'] == 0
         and type(value['active_financial_service_listeners']) is int
         and value['active_financial_service_listeners'] == 0
         and value['private_service_state_mounted_to_exit'] is False
         and value['owner_exit_service_dependency'] is False
         and value['controller_read_or_hashed_private_service_state'] is False,
         'financial-service-absent-before-independent-exits')
    need(False, CURRENT_HARD_STOPS[3])


def assemble(source, source_ref, read):
    fields(source, ('schema', 'scope', 'bootstrap_trial', 'component_profile_sha256',
        'tail_sha256', 'privacy_gate', 'genesis_case', 'genesis_result',
        'history', 'payment_rounds', 'service_loss_receipt', 'exits',
        'terminal_scan_selection', 'terminal_scan_controller'),
        'exact-complete-source-contract')
    need(source['schema'] == SOURCE_SCHEMA and source['scope'] == wallet_history.SCOPE,
         'source-contract-schema')
    word(source['component_profile_sha256']); word(source['tail_sha256'])
    trial = exact_trial(load_json(read, source['bootstrap_trial']))
    history = load_json(read, source['history'])
    need(history.get('schema') == 'kpb-private-batch-public-history/v1'
         and history.get('scope') == wallet_history.SCOPE
         and history.get('domain_hex32') == trial['domain_hex32']
         and history.get('profile_hex32') == trial['profile_id_hex32']
         and [row.get('kind') for row in history.get('transitions', [])] == EXPECTED_KINDS[1:]
         and history.get('head', {}).get('outpoint_hex36') is None
         and history.get('head', {}).get('reserve_sompi') == 0,
         'complete-two-payment-nine-exit-history')
    exact_genesis(read, source, trial, history)
    need(type(source['payment_rounds']) is list and len(source['payment_rounds']) == 2,
         'exact-two-payment-rounds')
    payment_links = []
    for spec in source['payment_rounds']:
        artifacts_header = load_json(read, spec['financial_public_artifacts'])
        payment_links.append({
            'pay_result_sha256': spec['lifecycle_result']['sha256'],
            'projection_sha256': artifacts_header['projection_sha256'],
        })
    exact_privacy_acceptance(read, source['privacy_gate'], source['bootstrap_trial'],
                             trial, payment_links)
    cases = [{'kind': 'genesis', **record(source['genesis_case'])}]
    operation_ids = set()
    financial_run_ids = []
    for index, spec in enumerate(source['payment_rounds']):
        fields(spec, ('round', 'input_history', 'lifecycle_selection', 'lifecycle_result',
            'owner_intake_binding', 'financial_public_artifacts',
            'registered_driver_selection', 'registered_driver_result',
            'final_selection', 'final_request', 'final_result',
            'final_replay_result', 'r0_receipt', 'case'), 'exact-payment-round-spec')
        round_number = index + 1
        need(type(spec['round']) is int and spec['round'] == round_number,
             'ordered-payment-round')
        input_history = load_json(read, spec['input_history'])
        exact_input_history(input_history, history, index)
        selection, _ = exact_lifecycle_pair(read, spec['lifecycle_selection'],
            spec['lifecycle_result'], trial, 'pay', round_number,
            spec['input_history']['sha256'], source['tail_sha256'], [0, 1, 2])
        binding = exact_intake_binding(read,
            load_json(read, spec['owner_intake_binding']), trial, round_number,
            spec['input_history']['sha256'], spec['lifecycle_selection'],
            spec['lifecycle_result'], selection['operation_id'],
            source['component_profile_sha256'], input_history['head'])
        artifacts, projection, _ = exact_public_financial_artifacts(
            read, spec['financial_public_artifacts'], source['component_profile_sha256'],
            source['tail_sha256'])
        need(artifacts['run_id'] == binding['financial_run_id']
             and {key: artifacts['head'][key] for key in
                  ('outpoint_hex36', 'state_hex112', 'reserve_sompi')} == binding['head'],
             'financial-artifacts-same-preintake-head')
        financial_run_ids.append(artifacts['run_id'])
        registered = exact_registered_driver_result(read,
            spec['registered_driver_selection'], spec['registered_driver_result'],
            binding, artifacts)
        case = load_json(read, spec['case'])
        actual_projection = case_projection(case, 'payment')
        need(actual_projection == projection
             and actual_projection.hex() == history['transitions'][index]['projection_hex'],
             'same-financial-projection-case-and-history')
        exact_final_chain(read, spec, artifacts, registered, case, projection,
                          source['tail_sha256'])
        need(selection['operation_id'] not in operation_ids, 'unique-owner-operation-identities')
        operation_ids.add(selection['operation_id'])
        cases.append({'kind': 'payment', **record(spec['case'])})
    need(type(source['exits']) is list and len(source['exits']) == 9,
         'exact-nine-independent-exits')
    need(False, CURRENT_HARD_STOPS[4])
    exact_service_loss(load_json(read, source['service_loss_receipt']), trial,
        source['exits'][0]['input_history']['sha256'], financial_run_ids)
    exit_owners = []
    for ordinal, spec in enumerate(source['exits']):
        fields(spec, ('ordinal', 'owner_component', 'input_history',
            'lifecycle_selection', 'lifecycle_result', 'release_selection',
            'release_receipt', 'released_candidate', 'case'), 'exact-exit-spec')
        _, operation_id = exact_exit(read, spec, trial, history,
                                     source['tail_sha256'], ordinal)
        need(operation_id not in operation_ids, 'unique-owner-operation-identities')
        operation_ids.add(operation_id); exit_owners.append(spec['owner_component'])
        cases.append({'kind': 'exit', **record(spec['case'])})
    need(sorted(exit_owners) == [0, 0, 0, 1, 1, 1, 2, 2, 2],
         'three-independent-exits-per-owner')
    scan_selection, scans = exact_lifecycle_pair(read, source['terminal_scan_selection'],
        source['terminal_scan_controller'], trial, 'scan', 2,
        source['history']['sha256'], source['tail_sha256'], [0, 1, 2])
    need(scan_selection['operation_id'] not in operation_ids,
         'unique-terminal-scan-operation-identity')
    for row in scans['owners']:
        status = private_lifecycle.public_receipt(row['status'], 'scan')
        need(status['terminal_reconciled'] is True
             and status['history_sha256'] == source['history']['sha256'],
             'terminal-scan-same-history')
    need([row['kind'] for row in cases] == EXPECTED_KINDS, 'complete-case-order')
    return {'schema': MANIFEST_SCHEMA, 'scope': wallet_history.SCOPE,
        'bootstrap_trial_id': trial['trial_id'],
        'bootstrap_trial': source['bootstrap_trial'],
        'component_profile_sha256': source['component_profile_sha256'],
        'tail_sha256': source['tail_sha256'], 'source_contract': source_ref,
        'history': source['history'], 'cases': cases,
        'terminal_scan_controller': source['terminal_scan_controller']}


def rebuild(read, source_ref):
    source_ref = record(source_ref)
    return assemble(load_json(read, source_ref), source_ref, read)


def write_new(path, value):
    raw = private_worker.encoded(value)
    path = Path(path).absolute()
    need(not path.exists() and path.parent.is_dir(), 'fresh-manifest-output')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    source = {'path': str(Path(args.source).absolute()), 'sha256': args.source_sha256}
    result = rebuild(read, source)
    pin = write_new(args.output, result)
    print(json.dumps({'status': 'COMPLETE_UNFUNDED_LIFECYCLE_MANIFEST_ASSEMBLED',
        'manifest': str(Path(args.output).absolute()), 'manifest_sha256': pin,
        'funding_broadcast_or_readiness': False}, sort_keys=True))


if __name__ == '__main__':
    main()
