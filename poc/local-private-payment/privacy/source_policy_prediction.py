#!/usr/bin/env python3
"""Prospective, source-conditional actor1 prediction from final public grosses.

No realized private plan, owner mapping, seed, state or truth input exists.
This is not a generic NF-preimage or cryptographic break.
"""
from functools import lru_cache
import hashlib
import itertools
import json
from pathlib import Path

from economic_linkage import MAX_VALUE, parse, validate_ledger, uint, need

POLICY_SHA256 = 'ae95c9a4c058069298aeef1030dcc4d8392a469148949e95340bd6c7aed1c709'
FEE_CAP = 50_000_000
NOTE_FLOOR = 60_000_000


def queue_profiles(fees):
    """All36 actor permutation pairs; both hidden cycles have these same values."""
    profiles = set()
    for first in itertools.permutations(range(3)):
        for second in itertools.permutations(range(3)):
            f = {actor: fees[index] for index, actor in enumerate(first)}
            g = {actor: fees[3 + index] for index, actor in enumerate(second)}
            queues = []
            for actor in range(3):
                values = ([1_300_000_000 - f[actor] - g[actor], 500_000_000, 200_000_000]
                          if actor == 1 else [1_500_000_000 - f[actor], 300_000_000 - g[actor], 200_000_000])
                queues.append(tuple(sorted(values, reverse=True)))
            profiles.add(tuple(queues))
    return profiles


def actor1_masks(queues, gross_exits):
    """Nine globally shuffled actor requests; each actor exits its largest note."""
    @lru_cache(maxsize=None)
    def visit(counts):
        at = sum(counts)
        if at == 9:
            return frozenset({0}) if counts == (3, 3, 3) else frozenset()
        result = set()
        for actor in range(3):
            consumed = counts[actor]
            if consumed >= 3 or queues[actor][consumed] != gross_exits[at]:
                continue
            following = list(counts); following[actor] += 1
            for future in visit(tuple(following)):
                result.add(future | ((1 << at) if actor == 1 else 0))
        return frozenset(result)
    return set(visit((0, 0, 0)))


def gross_bands(gross):
    return (sum(value == 200_000_000 for value in gross) == 3
            and sum(250_000_000 <= value < 300_000_000 for value in gross) == 2
            and sum(value == 500_000_000 for value in gross) == 1
            and sum(1_200_000_000 <= value < 1_300_000_000 for value in gross) == 1
            and sum(1_450_000_000 <= value < 1_500_000_000 for value in gross) == 2)


def predict(fees, gross_exits):
    need(type(fees) in (list, tuple) and len(fees) == 6
         and type(gross_exits) in (list, tuple) and len(gross_exits) == 9, 'fixed-public-source-workload-shape')
    for fee in fees: uint(fee, 1, MAX_VALUE, 'positive-exact-payment-fee')
    for gross in gross_exits: uint(gross, NOTE_FLOOR, MAX_VALUE, 'exact-gross-exit-note')
    qualified = all(fee <= FEE_CAP for fee in fees)
    masks, profiles, feasible = set(), set(), 0
    if qualified:
        profiles = queue_profiles(fees)
        for profile in profiles:
            support = actor1_masks(profile, tuple(gross_exits))
            if support:
                feasible += 1; masks.update(support)
    possible, must = 0, None
    for mask in masks:
        possible |= mask; must = mask if must is None else must & mask
    def positions(mask):
        return [i for i in range(9) if mask & (1 << i)]
    retained = [i for i, gross in enumerate(gross_exits) if gross == 500_000_000]
    changed = [i for i, gross in enumerate(gross_exits) if 1_200_000_000 <= gross < 1_300_000_000]
    multiset_matches = gross_bands(gross_exits)
    predicted_pair = sorted(retained + changed) if len(retained) == len(changed) == 1 else []
    if masks:
        need(multiset_matches and len(predicted_pair) == 2
             and all((0 if must is None else must) & (1 << index) for index in predicted_pair),
             'prospective-actor1-band-prediction-must-hold-in-every-source-model')
    return {'status': 'SOURCE_POLICY_PREDICTION_SUPPORTED' if masks else
                'SOURCE_POLICY_ASSUMPTIONS_NOT_QUALIFIED' if not qualified else 'INCONSISTENT_SOURCE_POLICY_MODEL_OR_INPUT',
        'fee_cap_qualified': qualified, 'prospective_gross_multiset_matches': multiset_matches,
        'source_payment_schedules': 72, 'distinct_value_queue_profiles': len(profiles),
        'feasible_distinct_value_queue_profiles': feasible,
        'actor1_exit_position_masks': [positions(mask) for mask in sorted(masks)],
        'distinct_actor1_exit_position_mask_count': len(masks),
        'possible_actor1_exit_indices': positions(possible),
        'must_actor1_exit_indices': positions(0 if must is None else must),
        'predicted_actor1_unique_gross500M_exit_index': retained[0] if masks and len(retained) == 1 else None,
        'predicted_actor1_unique_change_band_exit_index': changed[0] if masks and len(changed) == 1 else None,
        'predicted_pair_supported_by_every_consistent_source_model': bool(masks)}


def analyze(value):
    validate_ledger(value)
    need([p['event_index'] for p in value['payments']] == list(range(6))
         and [e['event_index'] for e in value['exits']] == list(range(6, 15)),
         'source-policy-requires-six-payments-before-nine-exits')
    result = predict([p['fee_sompi'] for p in value['payments']],
                     [e['payout_sompi'] + e['fee_sompi'] for e in value['exits']])
    result.update({'schema': 'kpxa-public-source-policy-prediction-result/v1',
        'classification': 'CONDITIONAL_SELECTED_PUBLIC_SOURCE_POLICY_OWNERSHIP_FINGERPRINT',
        'gross_definition': 'native_payout_plus_its_exact_exit_fee_once',
        'conditional_funding_input_index_and_GEN3_CM_slot_if_order_bridge_holds': 1,
        'funding_association_conditional_on_selected_source_and_input_order_provenance': True,
        'contemporaneous_activation_argv_receipt_independently_verified': False,
        'funding_mapping_independently_verified_by_this_analysis': False,
        'selected_source_honest_execution_is_an_assumption': True,
        'realized_private_PLAN_state_owner_files_or_truth_used': False,
        'owner_verified_accuracy_or_probability_claim': False, 'generic_crypto_or_NF_preimage_break': False,
        'received500M_claim_and_original_change_same_asset_root_claimed': False,
        'prior_frozen_economic_arms_modified': False, 'privacy_PASS_verdict': 'NOT_DEFINED'})
    result['public_actor1_exit_predictions'] = [
        {'exit_index': index, 'event_index': value['exits'][index]['event_index'],
         'action_id_hex32': value['exits'][index]['action_id_hex32'],
         'nf_hex32': value['exits'][index]['nf_hex32'],
         'gross_sompi': value['exits'][index]['payout_sompi'] + value['exits'][index]['fee_sompi']}
        for index in result['must_actor1_exit_indices']]
    return result


def main():
    import argparse
    import runpy
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True); parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--policy', type=Path, required=True); parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(args.policy_sha256 == POLICY_SHA256, 'exact-prospective-source-policy-pin')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    policy = read(str(args.policy), args.policy_sha256); raw = read(str(args.input), args.input_sha256)
    result = analyze(parse(raw))
    result.update({'public_input_sha256': hashlib.sha256(raw).hexdigest(),
                   'frozen_policy_sha256': hashlib.sha256(policy).hexdigest()})
    with args.output.open('x') as out:
        json.dump(result, out, sort_keys=True, indent=2); out.write('\n')
    print(json.dumps({'status': result['status'], 'public_result': str(args.output),
                     'distinct_actor1_exit_masks': result['distinct_actor1_exit_position_mask_count']}))


if __name__ == '__main__':
    main()
