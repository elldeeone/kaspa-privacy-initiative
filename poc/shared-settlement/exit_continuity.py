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
from wire import Invalid, h, hexbytes, need, validate_case

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from capacity_g16 import verify
from public_native import normalize

PROFILE_SHA = '492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd'
OUTER_CANONICAL_CASE_SHA = '0f6644bbb7c30f18bc1ab2d3dbc0bc7e5fc455b26d5d1ff990ecf86ccffb0cb1'
OUTER_ID = '14a3ec5f3215b8186740584496a8762b02a916cccdf14be60925765e7b6c8d52'
W_TAIL_SHA = '5c9e15357f07f092e25f272ea40bb92f1c0335574e37e0e4e687297db4e56559'
PROVER_SHA = '4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621'
VK_SHA = '074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987'
SOURCE = 4_000_000_000
USEFUL = 2_000_000_000


class WrapperPolicy(Policy):
    """Use the old public transition checker with the exact installed W tail.

    The child constructor expects one copy of each distinct role VK. This
    wrapper forbids wide32 but its existing private branch contains two equal
    compact operands. Pin that precise byte identity here; do not alter the
    frozen child constructor or substitute a caller-selected program/key.
    """
    def __init__(self, tail, vk, domain):
        need(type(tail) is bytes and h(tail).hex() == W_TAIL_SHA
             and len(tail) + 114 < 65536 and type(vk) is bytes and len(vk) == 328
             and h(vk).hex() == VK_SHA and tail.count(vk) == 2,
             'exact_installed_W_tail_and_two_equal_compact_operands')
        need(domain == hexbytes('d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb', 32),
             'installed_W_child_domain')
        self.tail, self.domain, self.tail_sha256 = tail, domain, W_TAIL_SHA
        self.allow_no_append_exit = True


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
    need(engine['accepted'] is True and type(engine['input_index']) is int and engine['input_index'] == 0
         and engine['allowed_script_units'] == expected_budget * 10000 + 9999
         and type(engine['units']) is int and 0 < engine['units'] <= engine['allowed_script_units'],
         'native_engine_meter_and_budget')
    fee = case['entries'][0]['amount'] - sum(x['value'] for x in body['outputs'])
    need(type(report['Full']['fee_sompi']) is int
         and fee == report['Full']['fee_sompi'] == metrics['actual_fee_sompi']
         and fee == 100 * metrics['mining_mass'], 'exact_recorded_native_fee_and_reference100')
    return body, fee


def join(bundles, owners, recoveries, profile_path, *, verifier=verify):
    need(type(bundles) is list and len(bundles) == 3
         and type(owners) is list and len(owners) == 2
         and type(recoveries) is list and len(recoveries) == 2, 'one_W_and_two_private_owner_exits')
    child, metadata = child_profile(profile_path, PROFILE_SHA, allow_no_append_exit=True)
    profile_data = parse(selected(Path(profile_path), PROFILE_SHA))
    outer = bundles[0]['case']
    need(h(encoded(outer)).hex() == OUTER_CANONICAL_CASE_SHA, 'exact_previously_accepted_genuine_W_case')
    body, outer_fee = accepted(bundles[0], 1600)
    need(body['id'] == OUTER_ID and outer['entries'][0]['amount'] == SOURCE
         and len(body['outputs']) == 1, 'constructed_source_and_actual_W_head')
    frame = hexbytes(body['inputs'][0]['signatureScript'])
    policy = WrapperPolicy(frame[313:], hexbytes(profile_data['child_vk_hex328'], 328), child.domain)
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
             and owner['classification'] == 'CONSTRUCTED_START_AND_SUPPLIED_NATIVE_CASES_NOT_ACCEPTED_OR_CURRENT'
             and owner['op'] == 'prepare-full-cashout'
             and owner['selected_child_domain_hex32'] == child.domain.hex()
             and owner['selected_owner_ELF_sha256'] == PROVER_SHA
             and owner['new_compact_whole_PK_READY_before_backup'] is True
             and owner['native_Full_all_engines_with_supplied_contexts'] is True
             and owner['accepted_chain_backing_verified'] is False
             and owner['currentness_verified'] is False and owner['spend_authorized'] is False
             and owner['seed_witness_receipt_map_or_private_input_hash_exported'] is False,
             'selected_isolated_owner_execution_receipt')
        need(all(type(owner[k]) is int for k in ('recognized_unspent_claim_count_before',
                 'consumed_same_backup_claim_count', 'recognized_unspent_claim_count_after',
                 'fee_sompi', 'native_payout_sompi', 'reserve_after_sompi'))
             and owner['recognized_unspent_claim_count_before'] == owner['consumed_same_backup_claim_count'] == 2
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
    for recovered in recoveries:
        counts = {'recognized_historical_receipt_count': 3, 'recognized_spent_receipt_count': 3,
                  'recognized_unspent_claim_count_before': 0, 'historical_native_payout_key_control_match_count': 1,
                  'bounded_two_real_group_reconstruction_count': 1, 'unresolved_owned_NF_payout_records': 0}
        need(recovered['schema'] == 'kpx5-one-backup-owner-result/v1' and recovered['op'] == 'recover'
             and recovered['selected_child_domain_hex32'] == child.domain.hex()
             and recovered['selected_owner_ELF_sha256'] == PROVER_SHA
             and recovered['accepted_chain_backing_verified'] is False
             and recovered['currentness_verified'] is False and recovered['spend_authorized'] is False
             and recovered['seed_witness_receipt_map_or_private_input_hash_exported'] is False
             and all(type(recovered[k]) is int and recovered[k] == value for k, value in counts.items()),
             'two_selected_postdrain_backup_recovery_receipts')
    return {'schema': 'kpx5-ordered-public-W-private-exit-closure/v1',
        'classification': 'CONSTRUCTED_SOURCE_SUPPLIED_CONTEXT_FINANCIAL_CONTINUITY_ONLY',
        'child_profile': metadata, 'initial_source_sompi': SOURCE,
        'actual_W_outpoint': {'transactionId': OUTER_ID, 'index': 0},
        'outer_fee_sompi': outer_fee, 'private_exit_fees_sompi': fees - outer_fee,
        'all_three_fees_sompi': fees, 'all_native_payouts_sompi': payouts, 'final_reserve_sompi': 0,
        'final_CM_cursor': 6, 'final_NF_count': 9, 'selected_owner_claims_consumed': consumed,
        'same_backup_two_real_counts_are_isolated_execution_evidence_not_public_owner_identity_proof': True,
        'two_postdrain_receipts_each_show_all_claims_spent_and_one_controlled_payout_key': True,
        'ordered_exits': rows, 'useful_requested_invoice_principal_sompi': USEFUL,
        'change_and_returned_fee_credit_are_not_additional_useful_payments': True,
        'entry_performed_or_entry_fees_included': False,
        'new_native_VM_or_proof_generation': False, 'private_backup_seed_witness_or_PK_read': False,
        'accepted_chain_backing_currentness_complete_fee_privacy_or_trial_readiness_qualified': False}


def acquire(selection):
    def value(row):
        need(type(row) is dict and set(row) == {'path', 'sha256'}, 'finite_public_file_reference')
        return parse(selected(Path(row['path']), row['sha256']))
    need(type(selection) is dict and set(selection) == {'schema', 'cases', 'owner_results', 'final_recoveries'}
         and selection['schema'] == 'kpx5-public-exit-join-selection/v1', 'finite_public_join_selection')
    bundles = []
    for refs in selection['cases']:
        need(type(refs) is dict and set(refs) == {'case', 'native_report', 'metrics'}, 'public_case_report_metrics')
        bundles.append({key: value(row) for key, row in refs.items()})
    return (bundles, [value(row) for row in selection['owner_results']],
            [value(row) for row in selection['final_recoveries']])


def controls(bundles, owners, recoveries, profile_path):
    """Counterfactual public joins; never describe copied reports as new VM runs."""
    rows = []

    def reject(label, operation, expected):
        cases, people = copy.deepcopy(bundles), copy.deepcopy(owners)
        operation(cases, people)
        try:
            join(cases, people, recoveries, profile_path)
        except Invalid as error:
            need(error.code == expected, 'expected_public_join_negative_' + label)
            rows.append({'label': label, 'rejected_by': error.code})
        else:
            need(False, 'public_join_negative_unexpectedly_accepted_' + label)

    def reverse(cases, people):
        cases[1], cases[2] = cases[2], cases[1]
        people.reverse()

    def repeat(cases, people):
        cases[2], people[1] = copy.deepcopy(cases[1]), copy.deepcopy(people[0])

    def changed_destination(cases, _):
        case = cases[1]['case']; out = case['transaction']['outputs'][1]
        spk = bytearray.fromhex(out['scriptPublicKey']); spk[3] ^= 1
        out['scriptPublicKey'] = spk.hex()
        normalized = normalize(case)
        case['transaction'] = normalized['transaction']; cases[1]['metrics'] = normalized['metrics']

    def crossed_proofs(cases, _):
        first = hexbytes(cases[1]['case']['transaction']['inputs'][0]['signatureScript'])
        second = bytearray.fromhex(cases[2]['case']['transaction']['inputs'][0]['signatureScript'])
        second[68:196] = first[68:196]
        cases[2]['case']['transaction']['inputs'][0]['signatureScript'] = second.hex()

    reject('reversed_actual_exits', reverse, 'exact_current_outpoint')
    reject('repeat_first_exit', repeat, 'exact_current_outpoint')
    reject('native_rejection_cannot_become_closure',
           lambda c, _: c[1]['native_report']['Full'].__setitem__('accepted', False),
           'selected_actual_native_Full_report')
    reject('owner_fee_receipt_tampering', lambda _, o: o[0].__setitem__('fee_sompi', o[0]['fee_sompi'] + 1),
           'owner_receipt_matches_exact_public_crypto_and_native_effects')
    reject('unclosed_own_claim', lambda _, o: o[0].__setitem__('recognized_unspent_claim_count_after', 1),
           'two_claims_per_backup_with_no_remaining_claim')
    reject('boolean_is_not_zero_claim_count',
           lambda _, o: o[0].__setitem__('recognized_unspent_claim_count_after', False),
           'two_claims_per_backup_with_no_remaining_claim')
    reject('missing_terminal_exit', lambda c, _: c.pop(), 'one_W_and_two_private_owner_exits')
    reject('coherent_ID_wrong_native_destination', changed_destination, 'exact_authorized_native_outputs')
    reject('genuine_private_proof_from_other_state', crossed_proofs, 'fresh_public_current_VK_private_proof')
    return {'schema': 'kpx5-public-exit-join-controls/v1', 'public_negative_controls': rows,
            'new_native_VM_or_private_proof_generation': False,
            'copied_reports_for_mutated_cases_are_not_actual_native_results': True}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--selection', type=Path, required=True); p.add_argument('--selection-sha256', required=True)
    p.add_argument('--profile', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--controls-output', type=Path)
    a = p.parse_args(); need(not a.output.exists(), 'fresh_public_closure_result')
    need(a.controls_output is None or not a.controls_output.exists(), 'fresh_public_closure_controls')
    bundles, owners, recoveries = acquire(parse(selected(a.selection, a.selection_sha256)))
    result = join(bundles, owners, recoveries, a.profile)
    save(a.output, result)
    if a.controls_output is not None:
        save(a.controls_output, controls(bundles, owners, recoveries, a.profile))
    print(json.dumps({'ordered_native_financial_closure': True, 'selected_claims_consumed': 4,
                      'final_reserve_sompi': 0, 'fees_sompi': result['all_three_fees_sompi'],
                      'accepted_chain_or_complete_fee_qualified': False}))
