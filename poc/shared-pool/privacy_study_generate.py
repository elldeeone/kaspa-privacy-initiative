#!/usr/bin/env python3
"""H11 synthetic workload generator. This module is never mounted to observers."""
import copy
import hashlib
import random

FLOOR = 60_000_000
GRID = 10_000_000
FEES = {'bootstrap': 21_893_200, 'transfer': 21_893_200,
        'deposit': 22_005_200, 'exit': 21_934_400}


def generate(seed, regime, equal=False, singleton=False):
    rng = random.Random(seed)
    # Opaque public labels have no connection to hidden ownership/consumption.
    def label(kind, index):
        return hashlib.sha256(f'H11-public/{seed}/{kind}/{index}'.encode()).hexdigest()
    contributions = [1_000_000_000 if equal else rng.randint(80, 160)*GRID for _ in range(4)]
    if singleton:
        contributions = contributions[:1]
    initial = {'id': label('tx', 0), 'value': contributions[0], 'minute': -1,
               'funding_group': label('funding', 0)}
    notes = [{'value': contributions[0], 'owner': 0, 'source': initial['id'],
              'ancestor': initial['id'], 'born_count': 1, 'live': True}]
    events, truth = [], {}
    native_events = []
    reserve = contributions[0]
    dep_times = [0, 60, 120, 180] if regime == 'sparse' else [0, 5, 10, 15]
    pay_times = [] if singleton else ([195, 225] if regime == 'sparse' else [18, 24, 30, 36])

    def split(value, fee):
        high = (value-fee-FLOOR)//GRID
        first = rng.randint(FLOOR//GRID, high)*GRID
        return [first, value-fee-first]

    def append(kind, minute, owner, position=None, value=0, receiver=None):
        nonlocal reserve
        fee = FEES[kind]
        current = len(notes)
        txid = label('tx', len(events)+1)
        is_exit = kind == 'exit'
        input_value = value if kind == 'deposit' else notes[position]['value']
        values = [] if is_exit else split(input_value, fee)
        new = [] if is_exit else [current, current+1]
        anchor = 1 if kind == 'deposit' else notes[position]['born_count'] if is_exit else current
        payout = input_value-fee if is_exit else 0
        reserve += value-payout-fee
        event = {'id': txid, 'minute': minute, 'kind': kind, 'anchor_count': anchor,
                 'count_before': current, 'fee': fee, 'payout': payout, 'deposit': value,
                 'new': new, 'reserve_out': reserve,
                 'destination': label('destination', position) if is_exit else None,
                 'funding_group': label('funding', owner) if kind == 'deposit' else None}
        events.append(event)
        if kind == 'deposit':
            ancestor = txid
        else:
            assert notes[position]['live']
            ancestor = notes[position]['ancestor']
            notes[position]['live'] = False
            truth[txid] = {'position': position, 'source': notes[position]['source'],
                          'ancestor': ancestor, 'owner': owner}
        for i, amount in enumerate(values):
            notes.append({'value': amount, 'owner': receiver if i == 0 and receiver is not None else owner,
                          'source': txid, 'ancestor': ancestor, 'born_count': current+2, 'live': True})
        native_events.append({'kind': kind, 'minute': minute, 'owner': owner, 'position': position,
                              'deposit': value, 'values': values,
                              'owners': [notes[i]['owner'] for i in new]})

    for owner, value in enumerate(contributions):
        append('bootstrap' if owner == 0 else 'deposit', dep_times[owner], owner,
               position=0 if owner == 0 else None, value=0 if owner == 0 else value)
    for minute in pay_times:
        choices = [i for i, n in enumerate(notes) if n['live'] and n['value'] >= 2*FLOOR+FEES['transfer']]
        assert choices
        pos = rng.choice(choices); owner = notes[pos]['owner']
        receiver = rng.choice([w for w in range(4) if w != owner])
        append('transfer', minute, owner, pos, receiver=receiver)
    positions = [i for i, n in enumerate(notes) if n['live']]
    rng.shuffle(positions)
    start = 5 if singleton else 240 if regime == 'sparse' else 45
    for i, pos in enumerate(positions):
        append('exit', start+3*i, notes[pos]['owner'], pos)
    assert reserve == 0 and not any(n['live'] for n in notes)
    saved = {'schema': 'kpi-privacy-projection-v1', 'initial': initial, 'events': events}
    fresh = copy.deepcopy(saved)
    for e in fresh['events']:
        if e['kind'] == 'exit':
            e['anchor_count'] = e['count_before']
    waited = copy.deepcopy(fresh)
    for e in waited['events']:
        if e['kind'] == 'exit':
            e['minute'] += 20
    return {'arms': {'saved': saved, 'fresh': fresh, 'waited': waited},
            'truth': truth, 'notes': notes,
            'native_plan': {'initial_value': contributions[0], 'events': native_events},
            'seed': seed, 'regime': regime}


def shared_funding(chain):
    result = copy.deepcopy(chain)
    group = result['initial']['funding_group']
    for e in result['events']:
        if e['kind'] == 'deposit':
            e['funding_group'] = group
    return result
