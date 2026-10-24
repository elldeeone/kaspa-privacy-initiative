"""Ordered public transition checker; no aggregate/native authorization implied."""
import hashlib
import json

from policy import TAIL_SHA256, inspect, public_material
from wire import Invalid, need


def head_view(head):
    return {'point': head.point(), 'state_hex112': head.state.hex(),
            'reserve_sompi': head.reserve, 'scope': head.scope}


def check(policy, head, actions, verifier, require_live=False):
    need(type(actions) is list and actions, 'complete_nonempty_public_action_list')
    current, outcomes, seen, all_valid = head, [], set(), True
    for sequence, (role, case) in enumerate(actions, 1):
        if current is None:
            result = {'accepted': False, 'cryptographic': None, 'public_error': 'no_action_after_terminal',
                      'profile_error': None, 'effects': None, 'successor': None}
        else:
            result = inspect(policy, case, current, role, verifier, require_live)
        overlap = False
        try:
            auth, _ = public_material(case)
            nfs = [auth[204:236], auth[236:268]]
            overlap = any(nf in seen for nf in nfs)
            seen.update(nfs)
        except Invalid:
            pass
        accepted = result['accepted'] and not overlap and all_valid
        event = {key: value for key, value in result.items() if key != 'successor'}
        event.update(sequence=sequence, cross_action_NF_overlap=overlap,
                     accepted=accepted, prior_prefix_valid=all_valid,
                     canonical_public_case_sha256=hashlib.sha256(json.dumps(case,
                         sort_keys=True, separators=(',', ':')).encode()).hexdigest())
        outcomes.append(event)
        if accepted:
            current = result['successor']
        else:
            all_valid = False
            # Later actions cannot manufacture a valid prefix after rejection.
            # Continue predicates for diagnostics against the last proven head.
    fees = sum(row['effects']['fee_sompi'] for row in outcomes if row['accepted'])
    payouts = sum(row['effects']['native_payout_sompi'] for row in outcomes if row['accepted'])
    if all_valid:
        remaining = current.reserve if current else 0
        need(head.reserve == remaining + fees + payouts, 'whole_transcript_exact_native_equation')
    else:
        remaining = None
    return {'schema': 'kpx5-public-ordered-transcript/v1', 'accepted': all_valid,
            'classification': 'PUBLIC_PROOF_AND_SUPPLIED_HEAD_SEMANTICS_ONLY',
            'outcomes': outcomes, 'action_count': len(actions), 'old_native_call_count_if_individually_settled': len(actions),
            'initial_reserve_sompi': head.reserve, 'final_reserve_sompi': remaining,
            'externally_selected_starting_head': head_view(head),
            'derived_final_head': head_view(current) if all_valid and current else None,
            'derived_final_state_hex112': public_material(actions[-1][1])[0][364:476].hex() if all_valid else None,
            'authorized_inner_fees_sompi': fees if all_valid else None,
            'authorized_native_payout_sompi': payouts if all_valid else None,
            'genuine_aggregate_proof_new_native_acceptance_or_fee_saving': False,
            'accepted_chain_currentness_or_private_owner_recovery_proved': False,
            'PK_backup_private_note_witness_or_hidden_truth_read': False}


def summarize(value):
    """Public future journal candidate; it is not a proof or spending authority."""
    need(value['accepted'] is True, 'only_valid_public_transcripts_have_summaries')
    rows = []
    for row in value['outcomes']:
        rows.append({'sequence': row['sequence'], **row['effects'],
                     'role_VK_sha256': row['cryptographic']['vk_sha256'],
                     'authorization_sha256': row['cryptographic']['authorization_sha256'],
                     'proof_sha256': row['cryptographic']['proof_sha256'],
                     'canonical_public_case_sha256': row['canonical_public_case_sha256']})
    content = {'schema': 'kpx5-public-settlement-requirements-summary/v1',
               'ordered_actions': rows, 'initial_reserve_sompi': value['initial_reserve_sompi'],
               'selected_child_policy_tail_sha256': TAIL_SHA256,
               'externally_selected_starting_head': value['externally_selected_starting_head'],
               'derived_final_head': value['derived_final_head'],
               'derived_final_state_hex112': value['derived_final_state_hex112'],
               'final_reserve_sompi': value['final_reserve_sompi'],
               'authorized_native_payout_sompi': value['authorized_native_payout_sompi'],
               'authorized_inner_fees_sompi': value['authorized_inner_fees_sompi'],
               'native_verification_calls_if_current_policy_settled': value['action_count'],
               'new_settlement_authorization_or_aggregate_proof': False}
    raw = json.dumps(content, sort_keys=True, separators=(',', ':')).encode()
    return {'content': content, 'canonical_public_summary_sha256': hashlib.sha256(raw).hexdigest()}


def unchanged_effects_fee_claim(value, claimed_outer_fee):
    """Falsify naive savings while preserving every old authorized native effect."""
    need(value['accepted'] is True and type(claimed_outer_fee) is int and claimed_outer_fee >= 0,
         'valid_transcript_and_nonnegative_claimed_fee')
    need(value['initial_reserve_sompi'] == value['final_reserve_sompi']
         + value['authorized_native_payout_sompi'] + claimed_outer_fee,
         'different_outer_fee_needs_new_authorized_reserve_rebate_or_output_policy')
    return {'financial_equation_only': True, 'aggregate_native_authority': False,
            'claimed_outer_fee_sompi': claimed_outer_fee}
