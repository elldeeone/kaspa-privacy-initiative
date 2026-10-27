#!/usr/bin/env python3
"""Public synthetic policy controls; accepts no ledger, payout or private input."""
import argparse
import ast
from functools import lru_cache
import hashlib
import itertools
import json
import os
from pathlib import Path
import runpy

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
SPEC = HERE / 'WALLET-POLICY-COUNTERFACTUAL-CONTROLS-01.json'
PRED = ('poc/local-private-payment/privacy/source_policy_prediction.py',
        'b05e413b5b328795c5d9f7be56608f74cd31168284528bc17ee9da68fbb5838b')
TEST = ('poc/local-private-payment/privacy/test_source_policy_prediction.py',
        '1910e7e454a1299c7e0fef88ba2250e33481c2f1f00e0e961bc387df96009159')
FLOOR, CAP = 60_000_000, 50_000_000


def fragments(read, item, names, namespace):
    raw = read(str(REPO / item[0]), item[1])
    tree = ast.parse(raw)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in nodes} == set(names)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), item[0], 'exec'), namespace)
    return namespace


def fees_checked(fees):
    if len(fees) != 6 or any(type(x) is not int or not 1 <= x <= CAP for x in fees):
        raise ValueError('public-synthetic-fees-must-be-exact-positive-cap-bounded-integers')


def forward(policy, first, second, direction, fees, coins=(0, 0, 0)):
    fees_checked(fees)
    owned = [[(2_000_000_000, 'initial')] for _ in range(3)]
    selected = []
    for rnd, order in enumerate((first, second)):
        payment = (500_000_000, 200_000_000)[rnd]
        for at, actor in enumerate(order):
            fee = fees[rnd * 3 + at]
            available = [n for n in owned[actor] if n[0] >= payment + fee + FLOOR]
            if rnd:
                if policy == 'private_random_eligible_support':
                    assert len(available) == 2
                    available = [sorted(available)[coins[actor]]]
                else:
                    change = policy == 'uniform_change_first' or (policy == 'current_actor1_special' and actor == 1)
                    wanted = 'change' if change else 'received'
                    preferred = [n for n in available if n[1] == wanted]
                    if policy == 'current_actor1_special' and actor == 1:
                        available = preferred  # Current source's strict change-only branch.
                    else:
                        fallback = 'received' if change else 'change'
                        available = preferred or [n for n in available if n[1] == fallback]
            assert available
            note = max(available)
            selected.append((rnd, actor, note[0], note[1]))
            owned[actor].remove(note)
            owned[actor].append((note[0] - payment - fee, 'change'))
            owned[(actor + direction) % 3].append((payment, 'received'))
    queues = tuple(tuple(sorted((n[0] for n in notes), reverse=True)) for notes in owned)
    assert all(len(q) == 3 and min(q) >= FLOOR for q in queues)
    assert sum(map(sum, queues)) + sum(fees) == 6_000_000_000
    return queues, selected


def assignments(queues, gross):
    @lru_cache(None)
    def visit(counts):
        at = sum(counts)
        if at == 9:
            return frozenset({(0, 0, 0)})
        found = set()
        for actor, used in enumerate(counts):
            if used == 3 or queues[actor][used] != gross[at]:
                continue
            nxt = list(counts)
            nxt[actor] += 1
            for later in visit(tuple(nxt)):
                masks = list(later)
                masks[actor] |= 1 << at
                found.add(tuple(masks))
        return frozenset(found)
    return visit((0, 0, 0))


def observe(profiles, gross):
    profiles = set(profiles)
    worlds = set()
    for q in profiles:
        worlds.update(assignments(q, tuple(gross)))
    partitions = {tuple(sorted(w)) for w in worlds}
    masks = {w[1] for w in worlds}
    must = 511
    for mask in masks:
        must &= mask
    if not masks:
        must = 0
    pairs = []
    for i, j in itertools.combinations(range(9), 2):
        if partitions and all(any(m & (1 << i) and m & (1 << j) for m in p) for p in partitions):
            pairs.append([i, j])
    positions = lambda m: [i for i in range(9) if m & (1 << i)]
    return {'consistent': bool(worlds), 'distinct_profiles': len(profiles),
            'compatible_unlabeled_owner_partitions': len(partitions),
            'script_actor1_exit_mask_count': len(masks),
            'script_actor1_exit_masks': [positions(m) for m in sorted(masks)],
            'script_actor1_must_indices': positions(must), 'always_same_owner_pairs': pairs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frozen-spec-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    raw = read(str(SPEC), args.frozen_spec_sha256)
    spec = json.loads(raw)
    assert spec['schema'] == 'kpxa-wallet-policy-counterfactual-public-controls/v1'
    assert spec['note_floor_sompi'] == FLOOR and spec['fee_cap_sompi'] == CAP
    frozen = fragments(read, PRED, ('queue_profiles', 'actor1_masks'),
                       {'itertools': itertools, 'lru_cache': lru_cache})
    independent = fragments(read, TEST, ('forward_wallet', 'interleavings', 'gross_order'),
                            {'NOTE_FLOOR': FLOOR, 'combinations': itertools.combinations})
    assert len(list(independent['interleavings']())) == 1680
    controls, results = [], []
    baseline_count = 0
    for fees in spec['fee_cases']:
        profiles = {policy: set() for policy in spec['policies']}
        for first in itertools.permutations(range(3)):
            for second in itertools.permutations(range(3)):
                for direction in (1, 2):
                    for policy in spec['policies']:
                        branches = itertools.product((0, 1), repeat=3) if policy == 'private_random_eligible_support' else [(0, 0, 0)]
                        for coins in branches:
                            q, chosen = forward(policy, first, second, direction, fees, coins)
                            profiles[policy].add(q)
                            if policy == 'current_actor1_special':
                                expected, selected = independent['forward_wallet'](first, second, direction, fees)
                                assert q == expected and chosen == selected
                                baseline_count += 1
        assert profiles['current_actor1_special'] == frozen['queue_profiles'](fees)
        for policy, universe in profiles.items():
            symmetry = all(tuple(q[i] for i in order) in universe for q in universe for order in itertools.permutations(range(3)))
            assert symmetry == (policy != 'current_actor1_special')
            branches = itertools.product((0, 1), repeat=3) if policy == 'private_random_eligible_support' else [(0, 0, 0)]
            for coins in branches:
                q, _ = forward(policy, (0, 1, 2), (0, 1, 2), 1, fees, coins)
                for order in spec['public_observation_orders']:
                    gross = independent['gross_order'](q, order)
                    finding = observe(universe, gross)
                    assert finding['consistent']
                    if symmetry:
                        assert finding['script_actor1_must_indices'] == []
                    results.append({'fees_sompi': fees, 'policy': policy, 'synthetic_choice_vector': list(coins),
                                    'synthetic_exit_order': order, 'synthetic_gross_notes_sompi': gross,
                                    'actor_label_permutation_closed': symmetry, **finding})
            controls.append({'fees_sompi': fees, 'policy': policy, 'profiles': len(universe),
                             'actor_label_permutation_closed': symmetry})
    fees = spec['fee_cases'][0]
    q, _ = forward('current_actor1_special', (0, 1, 2), (0, 1, 2), 1, fees)
    gross = independent['gross_order'](q, spec['public_observation_orders'][0])
    brute = {sum(1 << i for i, actor in enumerate(order) if actor == 1)
             for order in independent['interleavings']() if independent['gross_order'](q, order) == gross}
    assert {w[1] for w in assignments(q, gross)} == brute == frozen['actor1_masks'](q, gross)
    assert observe([q, q], gross) == observe([q], gross)
    equal = observe({((500_000_000,) * 3,) * 3}, (500_000_000,) * 9)
    assert equal['compatible_unlabeled_owner_partitions'] == 280 and equal['script_actor1_exit_mask_count'] == 84
    assert not equal['always_same_owner_pairs'] and not equal['script_actor1_must_indices']
    failures = []
    for bad in (True, 1.0, CAP + 1):
        try:
            forward('uniform_received_first', (0, 1, 2), (0, 1, 2), 1, [bad] + fees[1:])
        except ValueError as error:
            failures.append({'input': repr(bad), 'retained_expected_rejection': str(error)})
        else:
            raise AssertionError('invalid fee accepted')
    impossible = list(independent['gross_order'](q, spec['public_observation_orders'][1]))
    impossible[0], impossible[1] = impossible[1], impossible[0]
    empty = observe(frozen['queue_profiles'](fees), impossible)
    assert not empty['consistent'] and not empty['script_actor1_must_indices'] and not empty['always_same_owner_pairs']
    output = {'schema': 'kpxa-wallet-policy-counterfactual-public-result/v1',
              'classification': 'PUBLIC_SYNTHETIC_SOURCE_SEMANTICS_ONLY',
              'frozen_spec_sha256': hashlib.sha256(raw).hexdigest(), 'baseline_schedules_checked': baseline_count,
              'profile_controls': controls, 'observations': results, 'equal_queue_matcher_negative': equal,
              'retained_expected_failures': failures, 'retained_impossible_chronology': empty,
              'independent1680_matcher_control': 'MATCHED', 'duplicate_models_control': 'NO_ADDED_EVIDENCE',
              'actual_ledger_payout_private_plan_state_truth_or_owner_input_used': False,
              'privacy_pass_posterior_or_owner_verified_accuracy_claim': False,
              'runtime_or_current_trial_changed': False}
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'w') as handle:
        json.dump(output, handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(json.dumps({'output': str(args.output), 'baseline_schedules_checked': baseline_count,
                      'public_observations': len(results), 'profile_controls': controls}))


if __name__ == '__main__':
    main()
