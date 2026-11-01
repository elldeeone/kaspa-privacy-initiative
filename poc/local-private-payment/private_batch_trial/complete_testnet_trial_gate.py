#!/usr/bin/env python3
"""Post-terminal evidence gate for one complete Testnet research trial.

This is not a launcher. It joins audit-only preflight evidence, exact activation,
accepted whole CASEs, actual double-spend refusal, service loss, nine payouts,
terminal scans and terminal-privacy authority only after they exist.  Current
source intentionally cannot emit a completion receipt because the actual
terminal Exit capture/acceptance authority has no reviewed immutable schema.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

import private_worker


SOURCE_SCHEMA = 'kpb-complete-testnet-native-lifecycle-source/v1'
RESULT_SCHEMA = 'kpb-complete-testnet-native-lifecycle/v1'
CONFIRMATION_SCHEMA = 'kpb-complete-testnet-case-confirmation/v1'
DOUBLE_SPEND_SCHEMA = 'kpb-current-head-double-spend-refusal/v1'
EXPECTED_KINDS = ('genesis', 'payment', 'payment') + ('exit',) * 9
CONFIRMATION_FIELDS = (
    'schema', 'trial_id', 'ordinal', 'kind', 'case_sha256',
    'transaction_id_hex32', 'accepted_whole_case', 'submission_attempts',
    'automatic_resubmission_permitted', 'native_payout_observed',
    'terminal_reserve_sompi',
)


def need(value, category):
    if not value:
        raise ValueError('complete-testnet-trial-' + category)


def fields(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def word(value, category='canonical-word'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), category)
    return value


def validate_case_confirmations(cases, confirmations, trial_id):
    """Join all twelve accepted CASEs without accepting a summary Boolean."""
    need(type(trial_id) is str and str(uuid.UUID(trial_id)) == trial_id,
         'canonical-trial-id')
    need(type(cases) is list and len(cases) == 12
         and tuple(row.get('kind') for row in cases) == EXPECTED_KINDS,
         'exact-lifecycle-case-order')
    need(type(confirmations) is list and len(confirmations) == 12,
         'twelve-case-confirmations')
    transaction_ids = []
    for ordinal, (case, receipt, kind) in enumerate(
            zip(cases, confirmations, EXPECTED_KINDS)):
        fields(case, ('kind', 'path', 'sha256'), 'case-reference-fields')
        word(case['sha256'], 'case-sha256')
        fields(receipt, CONFIRMATION_FIELDS, 'confirmation-fields')
        need(receipt['schema'] == CONFIRMATION_SCHEMA
             and receipt['trial_id'] == trial_id
             and type(receipt['ordinal']) is int
             and receipt['ordinal'] == ordinal
             and receipt['kind'] == case['kind'] == kind
             and receipt['case_sha256'] == case['sha256']
             and receipt['accepted_whole_case'] is True
             and type(receipt['submission_attempts']) is int
             and receipt['submission_attempts'] == 1
             and receipt['automatic_resubmission_permitted'] is False,
             'exact-once-accepted-case')
        word(receipt['transaction_id_hex32'], 'transaction-id')
        transaction_ids.append(receipt['transaction_id_hex32'])
        need(type(receipt['native_payout_observed']) is bool
             and receipt['native_payout_observed'] is (kind == 'exit'),
             'nine-native-payout-observations')
        expected_reserve = 0 if ordinal == 11 else None
        need(receipt['terminal_reserve_sompi'] == expected_reserve,
             'terminal-zero-reserve-only-after-last-exit')
    need(len(set(transaction_ids)) == 12,
         'distinct-accepted-transaction-identities')
    return confirmations


def validate_confirmed_case_bytes(cases, confirmations, read):
    """Reopen each selected CASE; a confirmation cannot supply its own txid."""
    need(type(cases) is list and type(confirmations) is list
         and len(cases) == len(confirmations), 'case-confirmation-count')
    for case_ref, receipt in zip(cases, confirmations):
        case = private_worker.parse(
            read(Path(case_ref['path']), case_ref['sha256']))
        transaction = case.get('transaction')
        need(type(transaction) is dict
             and transaction.get('id') == receipt['transaction_id_hex32'],
             'exact-case-transaction-identity')
    return confirmations


def assemble(source, source_ref, read):
    """Join all currently defined public evidence, then stop at terminal privacy."""
    fields(source, ('schema', 'classification', 'activation_preflight_result',
        'activation_handoff', 'lifecycle_manifest',
        'lifecycle_rehearsal_result', 'case_confirmations',
        'double_spend_refusal', 'service_loss_receipt',
        'terminal_privacy_acceptance'), 'source-fields')
    need(source['schema'] == SOURCE_SCHEMA
         and source['classification'] == 'RESEARCH_TESTNET_ONLY',
         'source-schema-classification')
    for name in ('activation_preflight_result', 'activation_handoff',
                 'lifecycle_manifest', 'lifecycle_rehearsal_result',
                 'double_spend_refusal', 'service_loss_receipt',
                 'terminal_privacy_acceptance'):
        record(source[name])
    need(type(source['case_confirmations']) is list,
         'case-confirmation-references')
    for item in source['case_confirmations']:
        record(item)

    def load(reference):
        return private_worker.parse(
            read(Path(reference['path']), reference['sha256']))

    preflight = load(source['activation_preflight_result'])
    preflight_fields = (
        'schema', 'scope', 'preflight_receipt_sha256',
        'bootstrap_trial_id', 'funding_identity_sha256',
        'component_profile_sha256', 'tail_sha256',
        'privacy_acceptance_sha256', 'registered_driver_result_sha256',
        'cases', 'case_count', 'launch_authorized', 'authority_admitted',
        'serialized_receipt_is_authority',
        'complete_terminal_lifecycle_observed',
        'testnet_trial_readiness_claimed', 'mainnet_or_production_authorized',
        'network_funding_or_broadcast_performed')
    fields(preflight, preflight_fields, 'preflight-result-fields')
    trial_id = preflight['bootstrap_trial_id']
    need(preflight['schema'] ==
            'kpb-verified-testnet-preflight-audit-evidence/v1'
         and preflight['launch_authorized'] is False
         and preflight['authority_admitted'] is False
         and preflight['serialized_receipt_is_authority'] is False
         and preflight['complete_terminal_lifecycle_observed'] is False
         and preflight['testnet_trial_readiness_claimed'] is False
         and preflight['mainnet_or_production_authorized'] is False
         and preflight['network_funding_or_broadcast_performed'] is False
         and preflight['case_count'] == 3,
         'preflight-audit-only')
    word(preflight['preflight_receipt_sha256'])
    drivers = preflight['registered_driver_result_sha256']
    need(type(drivers) is list and len(drivers) == 2
         and len(set(drivers)) == 2, 'two-preflight-driver-results')
    for item in drivers:
        word(item)

    # The old activation handoff is serialized caller data. A future version
    # must reexecute a parent completion proving live consumption of both
    # move-only authorities; no Boolean or receipt hash can substitute.
    need(False, 'live-parent-activation-completion-not-implemented')

    activation = load(source['activation_handoff'])
    need(activation.get('schema') ==
            'kpb-research-GEN3-activation-handoff/v1'
         and activation.get('status') ==
            'EXACT_NEW_GEN3_CONFIRMED_PRIVATE_PAYMENT_LIFECYCLE_PENDING'
         and activation.get('trial_id') == trial_id
         and activation.get('component_profile_sha256') ==
            preflight['component_profile_sha256']
         and activation.get('native_tail_sha256') == preflight['tail_sha256']
         and activation.get('activation_preflight_sha256') ==
            preflight['preflight_receipt_sha256']
         and activation.get(
            'R1_R2_nine_exits_and_testnet_terminal_recovery_still_required')
            is True
         and activation.get('complete_terminal_lifecycle_observed') is False
         and activation.get('testnet_trial_readiness_claimed') is False
         and activation.get('mainnet_or_production_authorized') is False,
         'exact-pending-activation-handoff')

    manifest = load(source['lifecycle_manifest'])
    need(manifest.get('schema') ==
            'kpb-complete-unfunded-native-lifecycle/v2'
         and manifest.get('bootstrap_trial_id') == trial_id
         and manifest.get('component_profile_sha256') ==
            preflight['component_profile_sha256']
         and manifest.get('tail_sha256') == preflight['tail_sha256'],
         'same-trial-lifecycle-manifest')
    cases = manifest.get('cases')
    need(type(cases) is list and cases[:3] == preflight['cases']
         and activation.get('genesis_case_sha256') == cases[0]['sha256'],
         'same-preflight-and-activated-cases')
    rehearsal = load(source['lifecycle_rehearsal_result'])
    checks = rehearsal.get('actual_native_CASE_checks')
    need(rehearsal.get('schema') ==
            'kpb-executed-complete-native-rehearsal-gate/v1'
         and rehearsal.get('manifest_sha256') ==
            source['lifecycle_manifest']['sha256']
         and rehearsal.get('component_profile_sha256') ==
            preflight['component_profile_sha256']
         and rehearsal.get('tail_sha256') == preflight['tail_sha256']
         and type(checks) is list and len(checks) == 12
         and [(row.get('kind'), row.get('raw_case_sha256'),
               row.get('actual_native_Full_all_inputs')) for row in checks]
             == [(row['kind'], row['sha256'], True) for row in cases]
         and rehearsal.get(
            'actual_history_payment_and_exit_replay_rejections') == 2
         and rehearsal.get(
            'actual_public_tree_replay_terminal_reserve_sompi') == 0
         and rehearsal.get('original_terminal_scan_statuses') == 3
         and rehearsal.get(
            'testnet_terminal_broadcast_confirmation_or_readiness') is False
         and rehearsal.get(
            'controller_Original_private_truth_or_wallet_body_read') is False,
         'complete-offline-native-recheck')
    confirmations = [load(item) for item in source['case_confirmations']]
    validate_case_confirmations(cases, confirmations, trial_id)
    validate_confirmed_case_bytes(cases, confirmations, read)

    double_spend = load(source['double_spend_refusal'])
    fields(double_spend, ('schema', 'trial_id',
        'after_round2_case_sha256', 'registered_driver_result_sha256',
        'current_head_duplicate_nullifier_refused',
        'durable_final_candidate_created', 'network_submission_attempted',
        'accepted_chain_changed'), 'double-spend-fields')
    need(double_spend['schema'] == DOUBLE_SPEND_SCHEMA
         and double_spend['trial_id'] == trial_id
         and double_spend['after_round2_case_sha256'] == cases[2]['sha256']
         and double_spend['registered_driver_result_sha256'] == drivers[1]
         and double_spend['current_head_duplicate_nullifier_refused'] is True
         and double_spend['durable_final_candidate_created'] is False
         and double_spend['network_submission_attempted'] is False
         and double_spend['accepted_chain_changed'] is False,
         'actual-current-head-double-spend-refusal')

    service = load(source['service_loss_receipt'])
    fields(service, ('schema', 'trial_id', 'after_round2_history_sha256',
        'financial_run_ids', 'process_identities_checked',
        'active_financial_service_processes',
        'active_financial_service_listeners',
        'private_service_state_mounted_to_exit',
        'owner_exit_service_dependency',
        'controller_read_or_hashed_private_service_state'),
        'service-loss-fields')
    pids = service['process_identities_checked']
    need(service['schema'] == 'kpb-unfunded-financial-service-loss/v1'
         and service['trial_id'] == trial_id
         and type(service['financial_run_ids']) is list
         and len(service['financial_run_ids']) == 2
         and type(pids) is list and len(pids) >= 3
         and len(set(pids)) == len(pids)
         and all(type(pid) is int and pid > 0 for pid in pids)
         and service['active_financial_service_processes'] == 0
         and service['active_financial_service_listeners'] == 0
         and service['private_service_state_mounted_to_exit'] is False
         and service['owner_exit_service_dependency'] is False
         and service['controller_read_or_hashed_private_service_state'] is False,
         'ordered-service-loss-before-exits')
    terminal = load(source['terminal_privacy_acceptance'])
    need(terminal.get('schema') ==
            'kpb-terminal-exit-source-only-acceptance/v1'
         and terminal.get('privacy_status') == 'UNQUALIFIED_SOURCE_ONLY'
         and terminal.get('actual_capture_and_private_score_executed') is False
         and terminal.get('rehearsal_authorized') is False,
         'current-terminal-privacy-remains-source-only')
    need(False, 'actual-terminal-exit-privacy-authority-not-implemented')


def record(value):
    fields(value, ('path', 'sha256'), 'reference-fields')
    need(Path(value['path']).is_absolute() and '..' not in Path(value['path']).parts,
         'absolute-reference')
    word(value['sha256'])
    return value


def rebuild(read, source_ref):
    source_ref = record(source_ref)
    source = private_worker.parse(
        read(Path(source_ref['path']), source_ref['sha256']))
    return assemble(source, source_ref, read)


def read_guarded(path, expected=None):
    raw = Path(path).read_bytes()
    if expected is not None:
        need(hashlib.sha256(raw).hexdigest() == expected, 'selected-input')
    return raw


def write_new(path, value):
    raw = private_worker.encoded(value)
    fd = os.open(Path(path).absolute(), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    source_ref = {'path': str(Path(args.source).absolute()),
                  'sha256': word(args.source_sha256)}
    result = rebuild(read_guarded, source_ref)
    print(json.dumps({'schema': RESULT_SCHEMA,
                      'sha256': write_new(args.output, result)}, sort_keys=True))


if __name__ == '__main__':
    main()
