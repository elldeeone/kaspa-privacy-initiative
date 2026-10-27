#!/usr/bin/env python3
"""Frozen, public-only economic/chronological ancestry model; no privacy verdict.

No wallet, payment intent, owner map, original, private log or truth input exists.
The CLI requires an externally selected terminal public ledger through guard09.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re

NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
MAX_VALUE = 2_870_000_000_000_000_000
CM_EMPTY = hashlib.sha256(b'KPX1CME\0').hexdigest()
SCHEMA = 'kpxa-public-economic-ledger/v1'
POLICY_SHA256 = '134447928e820b7a143f5d02991b5cf9f1aeea72632a2b337c69c9270888309b'


def need(condition, code):
    if not condition:
        raise ValueError(code)


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)


def uint(value, minimum, maximum, code):
    need(type(value) is int and minimum <= value <= maximum, code)
    return value


def word(value, code, *, cm=False):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
         and value != '0' * 64 and (not cm or value != CM_EMPTY), code)


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate-json-key')
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('nonfinite-json')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    validate_ledger(value)
    return value


def validate_ledger(value):
    fields(value, ('schema', 'terminal', 'terminal_reserve_sompi', 'genesis', 'payments', 'exits'),
           'exact-public-ledger-fields-no-owner-or-intent')
    need(value['schema'] == SCHEMA and value['terminal'] is True,
         'externally-selected-terminal-public-ledger-required')
    uint(value['terminal_reserve_sompi'], 0, 0, 'terminal-zero-reserve')
    need(type(value['genesis']) is list and len(value['genesis']) == 3
         and type(value['payments']) is list and len(value['payments']) == 6
         and type(value['exits']) is list and len(value['exits']) == 9, 'exact-three-six-nine-profile')
    for position, row in enumerate(value['genesis']):
        fields(row, ('cm_hex32', 'position', 'value_sompi'), 'public-genesis-fields')
        word(row['cm_hex32'], 'genesis-CM', cm=True)
        uint(row['position'], position, position, 'genesis-public-position')
        uint(row['value_sompi'], 2_000_000_000, 2_000_000_000, 'three-public-twenty-KAS-notes')
    times, nfs = [], []
    for index, row in enumerate(value['payments']):
        fields(row, ('action_id_hex32', 'event_index', 'nf_hex32', 'outputs', 'fee_sompi'),
               'public-payment-fields-no-hidden-amount')
        word(row['action_id_hex32'], 'public-action-ID'); word(row['nf_hex32'], 'public-NF')
        times.append(uint(row['event_index'], 0, 14, 'public-total-event-index')); nfs.append(row['nf_hex32'])
        uint(row['fee_sompi'], 1, MAX_VALUE, 'public-payment-fee-sompi')
        need(type(row['outputs']) is list and len(row['outputs']) == 2, 'two-public-output-slots')
        for slot, output in enumerate(row['outputs']):
            fields(output, ('cm_hex32', 'position'), 'public-output-fields')
            word(output['cm_hex32'], 'output-CM', cm=True)
            uint(output['position'], 3 + 2 * index + slot, 3 + 2 * index + slot, 'public-append-position')
        need(row['outputs'][0]['cm_hex32'] != row['outputs'][1]['cm_hex32'], 'distinct-within-payment-CMs')
    for row in value['exits']:
        fields(row, ('action_id_hex32', 'event_index', 'nf_hex32', 'payout_sompi', 'fee_sompi'),
               'public-exit-fields-no-owner-map')
        word(row['action_id_hex32'], 'public-action-ID'); word(row['nf_hex32'], 'public-NF')
        times.append(uint(row['event_index'], 0, 14, 'public-total-event-index')); nfs.append(row['nf_hex32'])
        payout = uint(row['payout_sompi'], PAYOUT_FLOOR, MAX_VALUE, 'public-exit-payout-sompi')
        fee = uint(row['fee_sompi'], 1, MAX_VALUE, 'public-exit-fee-sompi')
        uint(payout + fee, NOTE_FLOOR, MAX_VALUE, 'full-exit-note-gross-sompi')
    need(len(set(times)) == 15 and set(times) == set(range(15)), 'unique-complete-public-event-order')
    need([p['event_index'] for p in value['payments']] == sorted(p['event_index'] for p in value['payments'])
         and [e['event_index'] for e in value['exits']] == sorted(e['event_index'] for e in value['exits']),
         'canonical-event-array-order')
    need(len(set(nfs)) == 15, 'accepted-single-spend-NFs')
    total = sum(e['payout_sompi'] + e['fee_sompi'] for e in value['exits'])
    total += sum(p['fee_sompi'] for p in value['payments'])
    need(total == sum(g['value_sompi'] for g in value['genesis']), 'exact-terminal-public-conservation')


def bits(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length() - 1
        mask ^= bit


def subsets(mask):
    current = mask
    while True:
        yield current
        if not current:
            return
        current = (current - 1) & mask


def sums(values):
    result = [0] * (1 << len(values))
    for mask in range(1, len(result)):
        low = mask & -mask
        result[mask] = result[mask ^ low] + values[low.bit_length() - 1]
    return result


@dataclass(frozen=True)
class Inside:
    count: int
    possible: int
    must: int
    consumer: int


class ForestDP:
    """Exact bounded inside/cover DP; a semiring tracks all/must relations."""
    def __init__(self, root_values, payment_fees, exit_gross, payment_times, exit_times,
                 *, note_floor=NOTE_FLOOR, leaf_minimums=None, masked=False, max_value=MAX_VALUE):
        for values in (root_values, payment_fees, exit_gross, payment_times, exit_times):
            need(type(values) in (list, tuple), 'public-numeric-sequences')
        self.k, self.m, self.n = len(root_values), len(payment_fees), len(exit_gross)
        need(1 <= self.k <= 3 and self.m <= 6 and self.n == self.k + self.m and self.n <= 9,
             'finite-public-forest-shape')
        uint(note_floor, 1, MAX_VALUE, 'positive-note-floor'); uint(max_value, note_floor, MAX_VALUE, 'maximum-note-value')
        need(len(set(root_values)) == 1, 'equal-valued-roots-only')
        for value in root_values: uint(value, note_floor, max_value, 'root-value-range')
        for value in payment_fees: uint(value, 1, max_value, 'payment-fee-range')
        for value in exit_gross: uint(value, note_floor, max_value, 'exit-gross-range')
        need(len(payment_times) == self.m and len(exit_times) == self.n, 'event-time-counts')
        self.times = tuple(payment_times) + tuple(exit_times)
        need(all(type(t) is int and t >= 0 for t in self.times) and len(set(self.times)) == len(self.times),
             'strict-total-public-event-order')
        need(sum(exit_gross) + sum(payment_fees) == sum(root_values), 'terminal-conservation')
        self.root_value, self.floor, self.maximum = root_values[0], note_floor, max_value
        self.masked, self.fee_sums = masked, sums(payment_fees)
        minimums = [note_floor] * self.n if leaf_minimums is None else list(leaf_minimums)
        need(len(minimums) == self.n, 'masked-leaf-minimum-count')
        for value in minimums: uint(value, note_floor, max_value, 'masked-leaf-minimum-range')
        self.exit_sums = sums(minimums if masked else exit_gross)
        self.features = []
        self.features += [('parent', origin, consumer) for origin in range(-1, self.m)
                          for consumer in range(self.m + self.n)]
        self.features += [('ancestor', origin, consumer) for origin in range(self.m)
                          for consumer in range(self.m + self.n) if origin != consumer]
        self.features += [('co_root_exit', a, b) for a in range(self.n) for b in range(a + 1, self.n)]
        self.feature_bits = {feature: 1 << i for i, feature in enumerate(self.features)}
        self.state_evaluations = self.split_candidates = self.cover_candidates = 0

    def feature(self, kind, a, b):
        return self.feature_bits[(kind, a, b)]

    def value(self, exits, payments):
        return self.exit_sums[exits] + self.fee_sums[payments]

    @lru_cache(maxsize=None)
    def inside(self, exits, payments):
        self.state_evaluations += 1
        if not exits or exits.bit_count() != payments.bit_count() + 1:
            return Inside(0, 0, 0, -1)
        if not self.floor <= self.value(exits, payments) <= self.maximum:
            return Inside(0, 0, 0, -1)
        consumers = [*bits(payments), *(self.m + j for j in bits(exits))]
        consumer = min(consumers, key=self.times.__getitem__)
        if not payments:
            return Inside(1, 0, 0, consumer)
        if consumer >= self.m:
            return Inside(0, 0, 0, consumer)
        remaining = payments ^ (1 << consumer)
        anchor = exits & -exits
        own = 0
        for descendant in consumers:
            if descendant != consumer:
                own |= self.feature('ancestor', consumer, descendant)
        count, possible, must = 0, 0, None
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
                left, right = self.inside(left_exits, left_payments), self.inside(right_exits, right_payments)
                if not left.count or not right.count:
                    continue
                parent = self.feature('parent', consumer, left.consumer) | self.feature('parent', consumer, right.consumer)
                branch_possible = own | parent | left.possible | right.possible
                branch_must = own | parent | left.must | right.must
                count += left.count * right.count
                possible |= branch_possible
                must = branch_must if must is None else must & branch_must
        return Inside(count, possible, 0 if must is None else must, consumer)

    def root_eligible(self, exits, payments):
        if exits.bit_count() != payments.bit_count() + 1:
            return False
        value = self.value(exits, payments)
        return (value <= self.root_value if self.masked else value == self.root_value)

    def solve(self):
        all_exits, all_payments = (1 << self.n) - 1, (1 << self.m) - 1
        exit_partitions = set()
        count, cover_count, possible, must = 0, 0, 0, None

        def finish(parts):
            nonlocal count, cover_count, possible, must
            self.cover_candidates += 1
            total, union, intersection = 1, 0, 0
            for exits, payments, node in parts:
                total *= node.count
                relation = self.feature('parent', -1, node.consumer)
                selected = list(bits(exits))
                for at, a in enumerate(selected):
                    for b in selected[at + 1:]:
                        relation |= self.feature('co_root_exit', a, b)
                union |= node.possible | relation
                intersection |= node.must | relation
            count += total; cover_count += 1; possible |= union
            must = intersection if must is None else must & intersection
            exit_partitions.add(tuple(sorted(part[0] for part in parts)))

        def cover(exits, payments, remaining, parts):
            if remaining == 1:
                if self.root_eligible(exits, payments):
                    node = self.inside(exits, payments)
                    if node.count:
                        finish(parts + [(exits, payments, node)])
                return
            anchor = exits & -exits
            for selected_exits in subsets(exits):
                if not selected_exits & anchor or (exits ^ selected_exits).bit_count() < remaining - 1:
                    continue
                desired = selected_exits.bit_count() - 1
                for selected_payments in subsets(payments):
                    if selected_payments.bit_count() != desired or not self.root_eligible(selected_exits, selected_payments):
                        continue
                    node = self.inside(selected_exits, selected_payments)
                    if node.count:
                        cover(exits ^ selected_exits, payments ^ selected_payments, remaining - 1,
                              parts + [(selected_exits, selected_payments, node)])

        cover(all_exits, all_payments, self.k, [])
        def decoded(mask):
            result = {'parent': set(), 'ancestor': set(), 'co_root_exit': set()}
            for i in bits(mask):
                kind, a, b = self.features[i]
                result[kind].add((a, b))
            return result
        return {'forest_count': count, 'joint_root_cover_count': cover_count,
            'exit_partition_count': len(exit_partitions),
            'labeled_output_slot_forest_count': count * (1 << self.m),
            'labeled_root_and_output_position_forest_count': count * (1 << self.m) * math.factorial(self.k),
            'possible': decoded(possible), 'must': decoded(0 if must is None else must),
            'work': {'evaluated_states': self.state_evaluations, 'split_candidates': self.split_candidates,
                     'feasible_root_covers': self.cover_candidates}}


def analyze(value):
    validate_ledger(value)
    roots = [g['value_sompi'] for g in value['genesis']]
    fees = [p['fee_sompi'] for p in value['payments']]
    gross = [e['payout_sompi'] + e['fee_sompi'] for e in value['exits']]
    pt, et = [p['event_index'] for p in value['payments']], [e['event_index'] for e in value['exits']]
    exact = ForestDP(roots, fees, gross, pt, et).solve()
    masked = ForestDP(roots, fees, gross, pt, et, masked=True,
        leaf_minimums=[max(NOTE_FLOOR, PAYOUT_FLOOR + e['fee_sompi']) for e in value['exits']]).solve()
    need(exact['forest_count'] <= masked['forest_count'], 'exact-model-count-contained-in-masked-control')
    if exact['forest_count']:
        for kind in exact['possible']:
            need(exact['possible'][kind] <= masked['possible'][kind]
                 and masked['must'][kind] <= exact['must'][kind], 'exact-relations-contained-in-masked-control')
    def public_metrics(result):
        return {**{key: item for key, item in result.items() if key not in ('possible', 'must')},
            'possible': {kind: [list(pair) for pair in sorted(pairs)] for kind, pairs in result['possible'].items()},
            'must': {kind: [list(pair) for pair in sorted(pairs)] for kind, pairs in result['must'].items()}}
    candidates = []
    events = [('payment', p) for p in value['payments']] + [('exit', e) for e in value['exits']]
    for consumer, (kind, event) in enumerate(events):
        origins = sorted(a for a, b in exact['possible']['parent'] if b == consumer)
        notes = []
        for origin in origins:
            notes.extend(value['genesis'] if origin == -1 else value['payments'][origin]['outputs'])
        candidates.append({'consumer_index': consumer, 'kind': kind, 'event_index': event['event_index'],
            'action_id_hex32': event['action_id_hex32'], 'possible_parent_payment_indices_or_minus1_genesis': origins,
            'possible_consumed_notes': [{'cm_hex32': n['cm_hex32'], 'position': n['position']} for n in notes]})
    added = {kind: [list(pair) for pair in sorted(exact['must'][kind] - masked['must'][kind])]
             for kind in exact['must']} if exact['forest_count'] else {kind: [] for kind in exact['must']}
    return {'schema': 'kpxa-public-economic-linkage-result/v1',
        'status': 'FEASIBLE_PUBLIC_MODEL' if exact['forest_count'] else 'INCONSISTENT_PUBLIC_MODEL_OR_INPUT',
        'classification': 'BOUNDED_PUBLIC_ASSET_ANCESTRY_MODEL_NO_PRIVACY_PASS',
        'exact': public_metrics(exact), 'payout_masked_control': public_metrics(masked),
        'new_must_relations_beyond_payout_masked_control': added, 'candidate_consumed_notes': candidates,
        'consumer_index_encoding': 'payments0..5_then_exits6..14; use event_index for chronology',
        'public_payment_two_output_grouping_scored_as_new_inference': False,
        'root_cm_label_permutations_preserved': 6,
        'root_identity_inferred_from_economics': False, 'common_ownership_inferred_from_asset_ancestry': False,
        'slot_symmetry_model': 'BOTH_PUBLIC_CM_SLOTS_FOR_EACH_POSSIBLE_PARENT_PAYMENT',
        'posterior_probability_or_uniform_prior_claim': False, 'private_inputs_or_truth_used': False,
        'cryptographic_or_chain_acceptance_verified_by_this_analysis': False}


def main():
    import argparse
    import runpy
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(args.policy_sha256 == POLICY_SHA256, 'exact-prospectively-frozen-policy')
    read_public = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    policy_raw = read_public(str(args.policy), args.policy_sha256)
    policy = json.loads(policy_raw)
    need(policy['schema'] == 'kpxa-public-economic-linkage-policy/v1'
         and policy['status'] == 'FROZEN_BEFORE_FINAL_PUBLIC_PAYOUT_INPUT', 'selected-frozen-observer-policy')
    raw = read_public(str(args.input), args.input_sha256)
    result = analyze(parse(raw))
    result.update({'public_input_sha256': hashlib.sha256(raw).hexdigest(),
                   'frozen_policy_sha256': hashlib.sha256(policy_raw).hexdigest()})
    with args.output.open('x') as out:
        json.dump(result, out, sort_keys=True, indent=2); out.write('\n')
    print(json.dumps({'status': result['status'], 'public_result': str(args.output),
        'canonical_forest_count': result['exact']['forest_count'],
        'exit_only_root_partition_count': result['exact']['exit_partition_count']}))


if __name__ == '__main__':
    main()
