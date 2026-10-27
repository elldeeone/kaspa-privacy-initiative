#!/usr/bin/env python3
"""Separate conditional published-workload arm; no owner/action schedule input."""
from functools import lru_cache
import hashlib
import itertools
import json
import math
from pathlib import Path

from economic_linkage import ForestDP, Inside, bits, subsets, need, parse, validate_ledger

POLICY_SHA256 = '2d019b9fe86a2255b3e35bf6467edf74fadea6bc2b7147b0e5de6d2da28d6ddd'
BASE_POLICY_SHA256 = '134447928e820b7a143f5d02991b5cf9f1aeea72632a2b337c69c9270888309b'


def sumsets(left, right):
    """Minkowski sum of small integer sets, represented by bit positions."""
    result = 0
    for number in bits(left):
        result |= right << number
    return result


class WorkloadDP(ForestDP):
    def __init__(self, *args, advertised_values=(200_000_000, 500_000_000), high_count=3, **kwargs):
        super().__init__(*args, **kwargs)
        need(not self.masked, 'stronger-arm-requires-exact-public-exit-grosses')
        need(type(advertised_values) in (list, tuple) and len(advertised_values) == 2
             and all(type(value) is int and self.floor <= value <= self.maximum for value in advertised_values)
             and advertised_values[0] < advertised_values[1], 'two-increasing-advertised-values')
        need(type(high_count) is int and 0 <= high_count <= self.m, 'advertised-global-high-count')
        self.low, self.high = advertised_values
        self.high_count = high_count
        self.signature_buckets = 0

    @lru_cache(maxsize=None)
    def workload_inside(self, exits, payments):
        self.state_evaluations += 1
        if not exits or exits.bit_count() != payments.bit_count() + 1:
            return {}
        if not self.floor <= self.value(exits, payments) <= self.maximum:
            return {}
        consumers = [*bits(payments), *(self.m + j for j in bits(exits))]
        consumer = min(consumers, key=self.times.__getitem__)
        if not payments:
            self.signature_buckets += 1
            return {1: Inside(1, 0, 0, consumer)}  # Signature {0 high-value roles}.
        if consumer >= self.m:
            return {}
        remaining, anchor = payments ^ (1 << consumer), exits & -exits
        own = 0
        for descendant in consumers:
            if descendant != consumer:
                own |= self.feature('ancestor', consumer, descendant)
        result = {}
        for left_exits in subsets(exits):
            if not left_exits & anchor or left_exits == exits:
                continue
            right_exits = exits ^ left_exits
            desired = left_exits.bit_count() - 1
            for left_payments in subsets(remaining):
                if left_payments.bit_count() != desired:
                    continue
                self.split_candidates += 1
                right_payments = remaining ^ left_payments
                child_values = (self.value(left_exits, left_payments), self.value(right_exits, right_payments))
                own_roles = (1 if self.low in child_values else 0) | (2 if self.high in child_values else 0)
                if not own_roles:
                    continue
                left = self.workload_inside(left_exits, left_payments)
                right = self.workload_inside(right_exits, right_payments)
                for left_signature, a in left.items():
                    for right_signature, b in right.items():
                        signature = sumsets(sumsets(left_signature, right_signature), own_roles)
                        parent = self.feature('parent', consumer, a.consumer) | self.feature('parent', consumer, b.consumer)
                        possible, must = own | parent | a.possible | b.possible, own | parent | a.must | b.must
                        count = a.count * b.count
                        if signature in result:
                            previous = result[signature]
                            result[signature] = Inside(previous.count + count, previous.possible | possible,
                                                       previous.must & must, consumer)
                        else:
                            result[signature] = Inside(count, possible, must, consumer)
        self.signature_buckets += len(result)
        return result

    def solve(self):
        all_exits, all_payments = (1 << self.n) - 1, (1 << self.m) - 1
        partitions = set()
        count, covers, possible, must = 0, 0, 0, None

        def finish(parts):
            nonlocal count, covers, possible, must
            self.cover_candidates += 1
            accepted = False
            for selected in itertools.product(*(list(buckets.items()) for _, _, buckets in parts)):
                signature = 1
                for current, _ in selected:
                    signature = sumsets(signature, current)
                if not signature & (1 << self.high_count):
                    continue
                accepted = True
                total, union, intersection = 1, 0, 0
                for (exits, _, _), (_, node) in zip(parts, selected):
                    total *= node.count
                    relation = self.feature('parent', -1, node.consumer)
                    selected_exits = list(bits(exits))
                    for at, a in enumerate(selected_exits):
                        for b in selected_exits[at + 1:]:
                            relation |= self.feature('co_root_exit', a, b)
                    union |= node.possible | relation
                    intersection |= node.must | relation
                count += total; possible |= union
                must = intersection if must is None else must & intersection
            if accepted:
                covers += 1
                partitions.add(tuple(sorted(exits for exits, _, _ in parts)))

        def cover(exits, payments, remaining, parts):
            if remaining == 1:
                if self.root_eligible(exits, payments):
                    buckets = self.workload_inside(exits, payments)
                    if buckets:
                        finish(parts + [(exits, payments, buckets)])
                return
            anchor = exits & -exits
            for selected_exits in subsets(exits):
                if not selected_exits & anchor or (exits ^ selected_exits).bit_count() < remaining - 1:
                    continue
                desired = selected_exits.bit_count() - 1
                for selected_payments in subsets(payments):
                    if selected_payments.bit_count() != desired or not self.root_eligible(selected_exits, selected_payments):
                        continue
                    buckets = self.workload_inside(selected_exits, selected_payments)
                    if buckets:
                        cover(exits ^ selected_exits, payments ^ selected_payments, remaining - 1,
                              parts + [(selected_exits, selected_payments, buckets)])

        cover(all_exits, all_payments, self.k, [])
        def decoded(mask):
            result = {'parent': set(), 'ancestor': set(), 'co_root_exit': set()}
            for i in bits(mask):
                kind, a, b = self.features[i]
                result[kind].add((a, b))
            return result
        return {'forest_count': count, 'joint_root_cover_count': covers, 'exit_partition_count': len(partitions),
            'labeled_output_slot_forest_count': count * (1 << self.m),
            'labeled_root_and_output_position_forest_count': count * (1 << self.m) * math.factorial(self.k),
            'possible': decoded(possible), 'must': decoded(0 if must is None else must),
            'work': {'evaluated_states': self.state_evaluations, 'signature_buckets': self.signature_buckets,
                     'split_candidates': self.split_candidates, 'considered_root_covers': self.cover_candidates}}


def analyze(value):
    validate_ledger(value)
    args = ([g['value_sompi'] for g in value['genesis']], [p['fee_sompi'] for p in value['payments']],
        [e['payout_sompi'] + e['fee_sompi'] for e in value['exits']],
        [p['event_index'] for p in value['payments']], [e['event_index'] for e in value['exits']])
    base, stronger = ForestDP(*args).solve(), WorkloadDP(*args).solve()
    need(stronger['forest_count'] <= base['forest_count'], 'stronger-count-contained-in-chain-only')
    if stronger['forest_count']:
        for kind in stronger['possible']:
            need(stronger['possible'][kind] <= base['possible'][kind]
                 and base['must'][kind] <= stronger['must'][kind], 'stronger-relations-contained-in-chain-only')
    def public(result):
        return {**{key: item for key, item in result.items() if key not in ('possible', 'must')},
            'possible': {kind: [list(pair) for pair in sorted(pairs)] for kind, pairs in result['possible'].items()},
            'must': {kind: [list(pair) for pair in sorted(pairs)] for kind, pairs in result['must'].items()}}
    candidates = []
    events = [('payment', p) for p in value['payments']] + [('exit', e) for e in value['exits']]
    for consumer, (kind, event) in enumerate(events):
        origins = sorted(a for a, b in stronger['possible']['parent'] if b == consumer)
        notes = []
        for origin in origins:
            notes.extend(value['genesis'] if origin == -1 else value['payments'][origin]['outputs'])
        candidates.append({'consumer_index': consumer, 'kind': kind, 'event_index': event['event_index'],
            'action_id_hex32': event['action_id_hex32'], 'possible_parent_payment_indices_or_minus1_genesis': origins,
            'possible_consumed_notes': [{'cm_hex32': n['cm_hex32'], 'position': n['position']} for n in notes]})
    return {'schema': 'kpxa-public-workload-economic-linkage-result/v1',
        'status': 'FEASIBLE_PUBLIC_MODEL' if stronger['forest_count'] else 'INCONSISTENT_PUBLIC_WORKLOAD_MODEL_OR_INPUT',
        'classification': 'CONDITIONAL_PUBLISHED_WORKLOAD_SIDE_INFORMATION_NO_PRIVACY_PASS',
        'chain_only_exact': public(base), 'workload_known_exact': public(stronger),
        'candidate_consumed_notes': candidates,
        'new_must_relations_beyond_chain_only': {kind: [list(pair) for pair in sorted(stronger['must'][kind] - base['must'][kind])]
            if stronger['forest_count'] else [] for kind in stronger['must']},
        'advertised_amount_multiset_sompi': [{'value': 200_000_000, 'count': 3}, {'value': 500_000_000, 'count': 3}],
        'owner_or_action_amount_mapping_used': False, 'role_assignments_multiply_forest_count': False,
        'public_source_publication_is_conditional': True, 'public_CM_slot_role_assumed': False,
        'root_cm_label_permutations_preserved': 6, 'root_owner_identity_inferred': False,
        'common_ownership_inferred_from_asset_ancestry': False, 'posterior_or_privacy_pass': False,
        'cryptographic_or_chain_acceptance_verified_by_this_analysis': False}


def main():
    import argparse
    import runpy
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True); parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--policy', type=Path, required=True); parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(args.policy_sha256 == POLICY_SHA256, 'exact-frozen-stronger-policy')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    policy = read(str(args.policy), args.policy_sha256)
    raw = read(str(args.input), args.input_sha256)
    result = analyze(parse(raw))
    result.update({'public_input_sha256': hashlib.sha256(raw).hexdigest(),
        'frozen_policy_sha256': hashlib.sha256(policy).hexdigest(), 'base_policy_sha256': BASE_POLICY_SHA256})
    with args.output.open('x') as out:
        json.dump(result, out, sort_keys=True, indent=2); out.write('\n')
    print(json.dumps({'status': result['status'], 'public_result': str(args.output),
                     'canonical_forest_count': result['workload_known_exact']['forest_count']}))


if __name__ == '__main__':
    main()
