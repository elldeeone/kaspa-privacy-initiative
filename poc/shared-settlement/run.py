#!/usr/bin/env python3
"""Execute finite PUBLIC proof/transcript controls; no native VM or proving."""
import argparse
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from public_g16 import verify
from fixtures import CASES, given_head, install, public_inventory
from policy import Head, inspect
from transcript import check, summarize, unchanged_effects_fee_claim
from wire import Invalid, hexbytes, need, transaction_id


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def mutate(case, area, offset, change=1, rehash=True):
    result = copy.deepcopy(case)
    body = result['transaction']
    if area == 'payload':
        raw = bytearray(hexbytes(body['payload']))
        raw[offset] ^= change
        body['payload'] = raw.hex()
    else:
        raw = bytearray(hexbytes(body['inputs'][0]['signatureScript']))
        raw[offset] ^= change
        body['inputs'][0]['signatureScript'] = raw.hex()
    if rehash:
        body['id'] = transaction_id(body, result['entries'][0])
    return result


def body_change(case, operation, rehash=True):
    result = copy.deepcopy(case)
    operation(result)
    if rehash:
        result['transaction']['id'] = transaction_id(result['transaction'], result['entries'][0])
    return result


def evaluate():
    policy, cases = install()
    first_head = given_head(cases['wide'])
    ordered = check(policy, first_head, [('wide32', cases['wide']), ('compact2', cases['compact'])], verify)
    need(ordered['accepted'], 'ordered_existing_wide_then_compact_must_pass')
    need(ordered['authorized_inner_fees_sompi'] == 2000 and ordered['final_reserve_sompi'] == 31999999000,
         'two_action_exact_financial_effects')
    after_wide = inspect(policy, cases['wide'], first_head, 'wide32', verify)['successor']
    after_alternative = inspect(policy, cases['wide_alternative'], after_wide, 'wide32', verify)['successor']
    need(after_wide is not None and after_alternative is not None, 'known_public_successors')
    controls = []

    def add(label, case, head, role='compact2', expected_crypto=True, accepted=False,
            public_error=None, profile_error=None, require_live=False):
        result = inspect(policy, case, head, role, verify, require_live)
        actual_crypto = result['cryptographic']['verified'] if result['cryptographic'] is not None else None
        need(result['accepted'] is accepted and actual_crypto is expected_crypto, 'control_outcome_' + label)
        if public_error:
            need(result['public_error'] == public_error, 'isolated_public_guard_' + label)
        if profile_error:
            need(result['profile_error'] == profile_error, 'isolated_profile_guard_' + label)
        result.pop('successor')
        controls.append({'label': label, 'expected_accepted': accepted, 'expected_crypto': expected_crypto,
                         'public_case_sha256': hashlib.sha256(encoded(case)).hexdigest(), **result})

    add('wide_role_alternative_from_same_head', cases['wide_alternative'], after_wide, 'wide32', accepted=True)
    add('terminal_individual_private_proof', cases['terminal'], given_head(cases['terminal']), accepted=True)
    add('fresh_private_valid_occupied_NF', cases['occupied'], given_head(cases['occupied']),
        public_error='NF_strict_predecessor')
    add('fresh_private_valid_wrong_successor_CM_root', cases['wrong_next_CM_root'], given_head(cases['wrong_next_CM_root']),
        public_error='CM_successor_root')
    add('stale_Auth_rebased_body', cases['stale_compact'], after_alternative,
        public_error='exact_current_outpoint')
    add('synthetic_head_cannot_claim_live_currentness', cases['compact'], after_wide,
        require_live=True, public_error='accepted_current_head_authority_unavailable')
    add('wrong_external_head_point', cases['compact'], replace(after_wide, transaction_id='01' * 32),
        public_error='exact_current_outpoint')
    wrong_state = bytearray(after_wide.state); wrong_state[76] ^= 1
    add('wrong_external_head_state', cases['compact'], replace(after_wide, state=bytes(wrong_state)),
        public_error='exact_current_state_reserve')
    add('wrong_external_head_reserve', cases['compact'], replace(after_wide, reserve=after_wide.reserve + 1),
        public_error='exact_current_state_reserve')
    add('role_VK_cannot_follow_untrusted_mode', cases['wide'], first_head, expected_crypto=False,
        public_error='trusted_role_mode')

    # These keep Auth/proof unchanged. Actual canonical IDs are recomputed, so
    # each negative reaches the intended public guard instead of a stale cache.
    for label, offset, error in [
        ('first_NF_predecessor_path', 528 + 72, 'NF_current_predecessor_root'),
        ('first_NF_append_empty_path', 528 + 616, 'NF_empty_append'),
        ('second_NF_sequential_predecessor_path', 1688 + 72, 'NF_current_predecessor_root'),
        ('ordered_CM_list_byte', 2848, 'CM_ordered_array_digest'),
        ('delivery_CF_byte', 2848 + 64, 'CF_array_digest'),
        ('CM_empty_boundary_path', 2848 + 296 * 2, 'CM_empty_subtree'),
    ]:
        add(label, mutate(cases['compact'], 'payload', offset), after_wide, public_error=error)
    swapped = body_change(cases['compact'], lambda c: c['transaction'].__setitem__('payload',
        (hexbytes(c['transaction']['payload'])[:2848]
         + hexbytes(c['transaction']['payload'])[2880:2912]
         + hexbytes(c['transaction']['payload'])[2848:2880]
         + hexbytes(c['transaction']['payload'])[2912:]).hex()))
    add('physical_CM_order_swap', swapped, after_wide, public_error='CM_ordered_array_digest')
    add('immutable_program_tail_byte', mutate(cases['compact'], 'frame', -1), after_wide,
        public_error='canonical_private_frame_and_selected_program')
    add('inactive_native_signature_byte', mutate(cases['compact'], 'frame', 1), after_wide,
        public_error='canonical_private_frame_and_selected_program')
    add('proof_point_byte', mutate(cases['compact'], 'frame', 68), after_wide, expected_crypto=False)
    changed = body_change(cases['compact'], lambda c: c['transaction']['outputs'][0].__setitem__('value',
        c['transaction']['outputs'][0]['value'] - 1))
    add('coherent_body_reserve_output', changed, after_wide, public_error='exact_authorized_native_outputs')
    changed = body_change(cases['compact'], lambda c: c['transaction']['outputs'][0].__setitem__(
        'scriptPublicKey', '0000aa20' + '11' * 32 + '87'))
    add('coherent_body_successor_SPK', changed, after_wide, public_error='exact_authorized_native_outputs')
    changed = body_change(cases['terminal'], lambda c: c['transaction']['outputs'][0].__setitem__(
        'scriptPublicKey', '000020' + '11' * 32 + 'ac'))
    add('coherent_native_payout_destination', changed, given_head(cases['terminal']),
        public_error='exact_authorized_native_outputs')
    changed = body_change(cases['compact'], lambda c: c['transaction']['inputs'][0]['previousOutpoint'].__setitem__(
        'transactionId', '11' * 32))
    add('coherent_body_previous_point', changed, after_wide, public_error='exact_current_outpoint')
    changed = body_change(cases['compact'], lambda c: c['entries'][0].__setitem__('amount', after_wide.reserve + 1))
    add('actual_input_amount_mismatch', changed, after_wide, public_error='exact_input_UTXO_context')
    changed = body_change(cases['compact'], lambda c: c['transaction'].__setitem__('id', '00' * 32), False)
    add('cached_ID_not_authority', changed, after_wide, public_error='canonical_v1_body_id')
    for label, operation in [
        ('locktime', lambda c: c['transaction'].__setitem__('lockTime', 1)),
        ('gas', lambda c: c['transaction'].__setitem__('gas', 1)),
        ('subnetwork', lambda c: c['transaction'].__setitem__('subnetworkId', '01' + '00' * 19)),
        ('sequence', lambda c: c['transaction']['inputs'][0].__setitem__('sequence', (1 << 64) - 2)),
    ]:
        add('coherent_native_header_' + label, body_change(cases['compact'], operation), after_wide,
            public_error='native_fixed_header_and_sequence')

    # Auth changes must fail actual statement binding as well as any applicable
    # public guards. These are not confused with a fresh genuine invalid-state proof.
    for label, offset in [('domain', 8), ('prior_root', 116), ('reserved', 301),
                          ('aligned_start', 304), ('output_digest', 268), ('real_NF', 204)]:
        add('Auth_' + label, mutate(cases['compact'], 'payload', offset), after_wide, expected_crypto=False)
    changed = body_change(cases['compact'], lambda c: c['transaction'].__setitem__('mass',
        c['transaction']['mass'] + 1), False)
    add('storage_mass_is_not_ID_bound', changed, after_wide, profile_error='official_storage_mass_commitment')
    changed = body_change(cases['compact'], lambda c: c['transaction']['inputs'][0].__setitem__('computeBudget', 1601), False)
    add('larger_budget_is_profile_change_not_Auth_retargeting', changed, after_wide,
        profile_error='selected_B1600_profile')
    changed = body_change(cases['compact'], lambda c: c['entries'][0].__setitem__('blockDaaScore', 1), False)
    add('synthetic_context_DAA_scope', changed, after_wide, profile_error='supplied_synthetic_DAA0_profile')
    for label, operation in [
        ('reported_acceptance_boolean_is_not_authority', lambda c: c.__setitem__('accepted', True)),
        ('coinbase_context_flag', lambda c: c['entries'][0].__setitem__('isCoinbase', True)),
        ('covenant_context_flag', lambda c: c['entries'][0].__setitem__('covenantId', '11' * 32)),
        ('float_native_amount', lambda c: c['transaction']['outputs'][0].__setitem__('value', 1.5)),
    ]:
        add(label, body_change(cases['compact'], operation, False), after_wide, expected_crypto=None)

    sequences = []
    for label, head, actions in [
        ('mutually_exclusive_same_NF_alternatives', after_wide,
            [('compact2', cases['compact']), ('wide32', cases['wide_alternative'])]),
        ('duplicate_private_action', after_wide, [('compact2', cases['compact'])] * 2),
        ('reversed_wide_then_compact', first_head,
            [('compact2', cases['compact']), ('wide32', cases['wide'])]),
    ]:
        result = check(policy, head, actions, verify)
        need(result['accepted'] is False and all(row['cryptographic']['verified'] for row in result['outcomes']),
             'individually_genuine_but_invalid_combination_' + label)
        sequences.append({'label': label, **result})
    unchanged = unchanged_effects_fee_claim(ordered, 2000)
    try:
        unchanged_effects_fee_claim(ordered, 1000)
    except Invalid as error:
        need(error.code == 'different_outer_fee_needs_new_authorized_reserve_rebate_or_output_policy',
             'precise_fee_savings_boundary')
        fee_negative = {'claimed_outer_fee_sompi': 1000, 'rejected': True, 'reason': error.code}
    else:
        raise ValueError('silent_outer_fee_reduction_accepted')
    return {'schema': 'kpx5-two-action-public-settlement-experiment/v1',
            'classification': 'PUBLIC_EXISTING_PROOFS_AND_SUPPLIED_HEAD_SEMANTICS_ONLY',
            'ordered_positive': ordered, 'individual_controls': controls, 'sequence_negatives': sequences,
            'public_future_summary': summarize(ordered), 'unchanged_fee_equation': unchanged,
            'fee_savings_without_new_authority_negative': fee_negative,
            'existing_public_input_inventory': public_inventory(),
            'new_aggregate_proof_native_VM_or_settlement_accepted_or_privacy_qualified': False,
            'private_note_witness_backup_PK_hidden_truth_or_main_data_read': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists(), 'new_result_path')
    result = evaluate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as output:
        output.write(encoded(result) + b'\n')
    print(json.dumps({'ordered_positive': result['ordered_positive']['accepted'],
        'individual_controls': len(result['individual_controls']),
        'sequence_negatives': len(result['sequence_negatives']), 'native_VM_calls': 0,
        'actual_existing_G16_predicates': True,
        'new_settlement_or_fee_savings_claimed': False}))
