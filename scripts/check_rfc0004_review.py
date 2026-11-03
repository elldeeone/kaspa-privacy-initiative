#!/usr/bin/env python3
"""Check public Q1 arithmetic and symbolic Q4/Q5/Q7 state obligations.

Not a protocol implementation: labels stand for commitments/markers, arithmetic
inputs are supplied, and cryptography, UTXOs, DAG ordering, roots, wire codecs,
storage, mempool policy, recovery and native integration are NOT validated.
"""
from copy import deepcopy
from fractions import Fraction
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_SOMPI = 29_000_000_000 * 100_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def privacy_arithmetic():
    data = json.loads((ROOT / 'research/rfc0004-privacy-feasibility-vectors-2026-11-03.json').read_text())
    prior = data['price_prior']
    guess = int(prior['guess_centi_tkas'])
    grid = range(int(prior['uniform_grid_first']), int(prior['uniform_grid_last']) + 1)
    wins = [amount for amount in grid if 10 * abs(guess - amount) <= amount]
    # This is the frozen public distribution, not an inferred private workload.
    invoice_wins = sum(10 * abs(guess - amount) <= amount for amount in [1000, 2000, 2500, 4000, 5000])
    probability = Fraction(3, 5) * Fraction(invoice_wins, 5) + Fraction(2, 5) * Fraction(len(wins), len(grid))
    expected = prior['success_probability']
    cap = prior['absolute_cap']
    require(len(grid) == prior['uniform_grid_count'] == 4001, 'public grid')
    require(len(wins) == prior['successful_grid_values'] == 910, 'public successful grid')
    require(wins[0] == int(prior['first_success']) and wins[-1] == int(prior['last_success']), 'public interval')
    require(probability == Fraction(expected['numerator'], expected['denominator']) == Fraction(21103, 100025), 'exact prior floor')
    require(probability > Fraction(cap['numerator'], cap['denominator']) == Fraction(1, 5), 'prior must exceed cap')
    require(prior['cap_is_achievable_for_this_population'] is False, 'qualification limit')
    boundary = data['one_edge_boundary_counterexample']
    a, b = boundary['A'], boundary['B']
    paid = int(a['deposit']) - int(a['withdrawal']) - int(a['known_fee'])
    received = int(b['withdrawal']) + int(b['known_fee']) - int(b['deposit'])
    require(paid == received == int(boundary['payment_inferred_from_each_owner']) == 40, 'boundary arithmetic')
    require(boundary['all_ledgers_uniquely_reconstructable'] is False, 'conditional inference only')
    return probability


def initial_state():
    # Supplied symbolic predecessor; no authenticated genesis or notes asserted.
    return dict(B=100, N=set(), C=['old0', 'old1'], D=['delivery0', 'delivery1'],
                A={'anchor0'}, accepted=[], fees=0, ordinary_delta=0)


def transition(state, *, tx, b, fee, markers, outputs, anchor='anchor0',
               transparent_in=0, transparent_out=0, verifier='repaired-v2'):
    """Assume an externally verified statement; model current effects only.

    Verifier version deliberately does not namespace immutable-pool spentness.
    Anchors are predecessor-eligible labels; outputs here create no new eligible
    anchor. Real ordinary input ownership and private totals are outside scope.
    """
    if anchor not in state['A']:
        raise ValueError('anchor')
    if len(markers) != 2 or len(outputs) != 2:
        raise ValueError('shape')
    if len(set(markers)) != 2 or set(markers) & state['N']:
        raise ValueError('spentness')
    if not (-MAX_SOMPI <= b <= MAX_SOMPI and 0 <= fee <= MAX_SOMPI
            and 0 <= transparent_in <= MAX_SOMPI and 0 <= transparent_out <= MAX_SOMPI):
        raise ValueError('range')
    if transparent_in + b != transparent_out + fee:
        raise ValueError('public_balance')
    if not 0 <= state['B'] - b <= MAX_SOMPI:
        raise ValueError('pool_balance')
    result = deepcopy(state)
    result['B'] -= b
    result['N'].update(markers)
    result['C'].extend(commitment for commitment, _ in outputs)
    result['D'].extend(delivery for _, delivery in outputs)
    result['accepted'].append(tx)
    result['fees'] += fee
    result['ordinary_delta'] += transparent_out - transparent_in
    require((result['B'] - state['B']) + (result['ordinary_delta'] - state['ordinary_delta']) == -fee, 'native stock')
    return result


def state_traces():
    start = initial_state()
    base = dict(tx='first', b=1, fee=1, markers=['real', 'padding'],
                outputs=[('new0', 'enc0'), ('new1', 'enc1')])
    cases = 0

    def rejected(state, expected, **changes):
        before = deepcopy(state)
        try:
            transition(state, **(base | changes))
        except ValueError as error:
            require(str(error) == expected, 'wrong rejection: ' + str(error))
        else:
            raise ValueError('missing rejection: ' + expected)
        require(state == before, 'rejection mutated predecessor')

    first = transition(start, **base)
    require(start == initial_state() and first['B'] == 99 and first['N'] == {'real', 'padding'}
            and first['C'] == ['old0', 'old1', 'new0', 'new1']
            and first['D'] == ['delivery0', 'delivery1', 'enc0', 'enc1']
            and first['fees'] == 1 and first['accepted'] == ['first'], 'complete first effect')
    cases += 1
    # A second accepted-order candidate has no ordinary inputs, yet conflicts.
    rejected(first, 'spentness', tx='second', markers=['real', 'other-padding'])
    cases += 1
    rejected(start, 'spentness', markers=['same-slot', 'same-slot'])
    cases += 1
    # Padding is also a consensus-unique published marker.
    rejected(first, 'spentness', markers=['other-real', 'padding'])
    cases += 1
    rejected(first, 'spentness', verifier='new-verifier-same-pool')
    cases += 1
    stale = deepcopy(start)
    stale['A'] = {'alternative-anchor'}
    rejected(stale, 'anchor')  # An external proof-cache hit does not change this.
    cases += 1
    rejected(start, 'pool_balance', b=101, fee=101)
    cases += 1
    rejected(start, 'public_balance', b=2)
    cases += 1
    rejected(start, 'shape', outputs=[('only-one', 'enc')])
    cases += 1
    rejected(start, 'range', b=-(2**63))
    cases += 1
    # A competing fee replacement uses the same real marker: at most one wins.
    replacement = base | dict(tx='replacement', b=2, fee=2,
                              markers=['real', 'replacement-padding'],
                              outputs=[('repriced0', 're-enc0'), ('repriced1', 're-enc1')])
    repriced = transition(start, **replacement)
    require(repriced['B'] == 98 and repriced['fees'] == 2, 'owner fee replacement')
    rejected(repriced, 'spentness')
    cases += 1
    # Abstract undo restores EVERY modeled component, then accepts an alternative.
    undo = deepcopy(start)
    restored = deepcopy(undo)
    require(restored == initial_state(), 'full modeled undo')
    require(transition(restored, **replacement) == repriced, 'deterministic reapply')
    require(restored['A'] == {'anchor0'} and restored['D'] == ['delivery0', 'delivery1']
            and restored['N'] == set() and restored['fees'] == 0, 'undo completeness')
    cases += 1
    return cases


if __name__ == '__main__':
    probability = privacy_arithmetic()
    count = state_traces()
    print(f'RFC-0004 review: exact public prior {probability} > 1/5; boundary example; {count} symbolic state traces OK.')
    print('No cryptography, authenticated history, DAG, storage/undo implementation, native acceptance or privacy qualification validated.')
