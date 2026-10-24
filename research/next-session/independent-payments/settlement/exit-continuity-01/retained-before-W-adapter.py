#!/usr/bin/env python3
"""Join public actual-W -> two owner exits -> R0; no VM/prover/private inputs."""
import argparse
import copy
import json
from pathlib import Path
import sys

from native_gate import encoded, save, selected
from policy import Head, Policy, auth_fields, public_material, state
from selected import child_profile, parse
from wire import h, hexbytes, need, validate_case

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from capacity_g16 import verify
from public_native import normalize

PROFILE_SHA = '492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd'
OUTER_CANONICAL_CASE_SHA = '0f6644bbb7c30f18bc1ab2d3dbc0bc7e5fc455b26d5d1ff990ecf86ccffb0cb1'
OUTER_ID = '14a3ec5f3215b8186740584496a8762b02a916cccdf14be60925765e7b6c8d52'
W_TAIL_SHA = '5c9e15357f07f092e25f272ea40bb92f1c0335574e37e0e4e687297db4e56559'
PROVER_SHA = '4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621'
SOURCE = 4_000_000_000
USEFUL = 2_000_000_000


def accepted(bundle, expected_budget):
    case, report, metrics = (bundle[k] for k in ('case', 'native_report', 'metrics'))
    body, _ = validate_case(case)
    actual = normalize(case)
    need(actual['transaction'] == body and actual['metrics'] == metrics,
         'exact_official_canonical_ID_storage_and_all_metrics')
    need(body['inputs'][0]['computeBudget'] == expected_budget, 'selected_action_compute_budget')
    need(report['isolation'] == 'PASS' and report['Full']['accepted'] is True
         and report['all_input_engines_accepted'] is True
         and len(report['per_input_ScriptEngine']) == 1, 'selected_actual_native_Full_report')
    engine = report['per_input_ScriptEngine'][0]
    need(engine['accepted'] is True and engine['input_index'] == 0
         and engine['allowed_script_units'] == expected_budget * 10000 + 9999
         and type(engine['units']) is int and 0 < engine['units'] <= engine['allowed_script_units'],
         'native_engine_meter_and_budget')
    fee = case['entries'][0]['amount'] - sum(x['value'] for x in body['outputs'])
    need(type(report['Full']['fee_sompi']) is int
         and fee == report['Full']['fee_sompi'] == metrics['actual_fee_sompi']
         and fee == 100 * metrics['mining_mass'], 'exact_recorded_native_fee_and_reference100')
    return body, fee


def join(bundles, owners, profile_path, *, verifier=verify):
    need(type(bundles) is list and len(bundles) == 3
         and type(owners) is list and len(owners) == 2, 'one_W_and_two_private_owner_exits')
    child, metadata = child_profile(profile_path, PROFILE_SHA, allow_no_append_exit=True)
    profile_data = parse(selected(Path(profile_path), PROFILE_SHA))
    outer = bundles[0]['case']
    need(h(encoded(outer)).hex() == OUTER_CANONICAL_CASE_SHA, 'exact_previously_accepted_genuine_W_case')
    body, outer_fee = accepted(bundles[0], 1600)
    need(body['id'] == OUTER_ID and outer['entries'][0]['amount'] == SOURCE
         and len(body['outputs']) == 1, 'constructed_source_and_actual_W_head')
    frame = hexbytes(body['inputs'][0]['signatureScript'])
    policy = Policy(frame[313:], hexbytes(profile_data['child_vk_hex328'], 328), domain=child.domain,
                    expected_tail_sha256=W_TAIL_SHA, allow_no_append_exit=True)
    payload = hexbytes(body['payload'])
    # The exact first case was already independently verified by SDK/native.
    # Reuse its byte identity, not a newly supplied aggregate success flag.
    last_auth = payload[4060:4588]
    final = auth_fields(last_auth, 'compact2', child.domain, allow_no_append_exit=True)
    head = Head(body['id'], 0, last_auth[364:476], final['remaining'], domain=child.domain)
    need(head.reserve == body['outputs'][0]['value'] == SOURCE - outer_fee, 'actual_W_reserve')
    initial_cm = state(head.state, child.domain)
    need(initial_cm['n'] == 6 and initial_cm['m'] == 5, 'selected_four_output_note_state')
    all_nfs = set()
    for off in (12, 4060):
        all_nfs.update((payload[off + 204:off + 236], payload[off + 236:off + 268]))
    need(len(all_nfs) == 4, 'already_spent_original_and_dummy_NFs')
    rows, payouts, fees, consumed = [], 0, outer_fee, 0
    for ordinal, (bundle, owner) in enumerate(zip(bundles[1:], owners), 1):
        need(head is not None, 'no_action_after_terminal')
        body, actual_fee = accepted(bundle, 1500)
        auth, proof = public_material(bundle['case'])
        fields = auth_fields(auth, 'compact2', child.domain, allow_no_append_exit=True)
        need(fields['mode'] == 0 and fields['payout'] > 0, 'positive_private_noappend_exit')
        next_head, effects = policy.apply(bundle['case'], head, 'compact2')
        crypto = verifier('compact2', auth, proof)
        need(crypto['verified'] is True, 'fresh_public_current_VK_private_proof')
        need(not all_nfs.intersection(fields['nfs']), 'cross_action_NF_reuse')
        all_nfs.update(fields['nfs'])
        need(fields['new']['cm'] == initial_cm['cm'] and fields['new']['n'] == 6
             and fields['new']['m'] == 5 + 2 * ordinal, 'noappend_CM_and_sequential_NF_counts')
        need(owner['schema'] == 'kpx5-one-backup-owner-result/v1'
             and owner['op'] == 'prepare-full-cashout'
             and owner['selected_child_domain_hex32'] == child.domain.hex()
             and owner['selected_owner_ELF_sha256'] == PROVER_SHA
             and owner['new_compact_whole_PK_READY_before_backup'] is True
             and owner['native_Full_all_engines_with_supplied_contexts'] is True
             and owner['seed_witness_receipt_map_or_private_input_hash_exported'] is False,
             'selected_isolated_owner_execution_receipt')
        need(owner['recognized_unspent_claim_count_before'] == owner['consumed_same_backup_claim_count'] == 2
             and owner['recognized_unspent_claim_count_after'] == 0,
             'two_claims_per_backup_with_no_remaining_claim')
        need(owner['transaction_id'] == body['id']
             and owner['authorization_sha256'] == h(auth).hex() and owner['proof_sha256'] == h(proof).hex()
             and owner['fee_sompi'] == actual_fee == effects['fee_sompi']
             and owner['native_payout_sompi'] == effects['native_payout_sompi']
             and owner['reserve_after_sompi'] == effects['reserve_after_sompi'],
             'owner_receipt_matches_exact_public_crypto_and_native_effects')
        consumed += owner['consumed_same_backup_claim_count']
        payouts += effects['native_payout_sompi']; fees += actual_fee
        rows.append({'ordinal': ordinal, 'actual_input_point': head.point(),
                     'canonical_public_case_sha256': h(encoded(bundle['case'])).hex(),
                     'transaction_id': body['id'], **effects,
                     'current_VK_public_G16_verified': True,
                     'two_same_backup_claims_from_isolated_execution_receipt': True})
        need((next_head is not None) == (ordinal == 1), 'continuing_then_terminal_exit')
        head = next_head
    need(head is None and consumed == 4 and len(all_nfs) == 8
         and SOURCE == payouts + fees, 'complete_four_claim_R0_native_money_closure')
    return {'schema': 'kpx5-ordered-public-W-private-exit-closure/v1',
        'classification': 'CONSTRUCTED_SOURCE_SUPPLIED_CONTEXT_FINANCIAL_CONTINUITY_ONLY',
        'child_profile': metadata, 'initial_source_sompi': SOURCE,
        'actual_W_outpoint': {'transactionId': OUTER_ID, 'index': 0},
        'outer_fee_sompi': outer_fee, 'private_exit_fees_sompi': fees - outer_fee,
        'all_three_fees_sompi': fees, 'all_native_payouts_sompi': payouts, 'final_reserve_sompi': 0,
        'final_CM_cursor': 6, 'final_NF_count': 9, 'selected_owner_claims_consumed': consumed,
        'same_backup_two_real_counts_are_isolated_execution_evidence_not_public_owner_identity_proof': True,
        'ordered_exits': rows, 'useful_requested_invoice_principal_sompi': USEFUL,
        'change_and_returned_fee_credit_are_not_additional_useful_payments': True,
        'entry_performed_or_entry_fees_included': False,
        'new_native_VM_or_proof_generation': False, 'private_backup_seed_witness_or_PK_read': False,
        'accepted_chain_backing_currentness_complete_fee_privacy_or_trial_readiness_qualified': False}


def acquire(selection):
    def value(row):
        need(type(row) is dict and set(row) == {'path', 'sha256'}, 'finite_public_file_reference')
        return parse(selected(Path(row['path']), row['sha256']))
    need(type(selection) is dict and set(selection) == {'schema', 'cases', 'owner_results'}
         and selection['schema'] == 'kpx5-public-exit-join-selection/v1', 'finite_public_join_selection')
    bundles = []
    for refs in selection['cases']:
        need(type(refs) is dict and set(refs) == {'case', 'native_report', 'metrics'}, 'public_case_report_metrics')
        bundles.append({key: value(row) for key, row in refs.items()})
    return bundles, [value(row) for row in selection['owner_results']]


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--selection', type=Path, required=True); p.add_argument('--selection-sha256', required=True)
    p.add_argument('--profile', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); need(not a.output.exists(), 'fresh_public_closure_result')
    bundles, owners = acquire(parse(selected(a.selection, a.selection_sha256)))
    result = join(bundles, owners, a.profile)
    save(a.output, result)
    print(json.dumps({'ordered_native_financial_closure': True, 'selected_claims_consumed': 4,
                      'final_reserve_sompi': 0, 'fees_sompi': result['all_three_fees_sompi'],
                      'accepted_chain_or_complete_fee_qualified': False}))
