"""H12 paired funding policies. Private generator; never mounted to observers."""
import copy
import random
import secrets

from privacy_study_generate import FEES, FLOOR, GRID

POLICIES = ('varied', 'gross', 'net')


def contributions(seed):
    rng = random.Random(f'H12/{seed}/contributions')
    varied = [rng.randint(80, 160)*GRID for _ in range(4)]
    fees = [FEES['bootstrap']]+[FEES['deposit']]*3
    total = sum(varied)
    assert total % 4 == 0 and (total-sum(fees)) % 4 == 0
    gross = [total//4]*4
    net = [(total-sum(fees))//4+fee for fee in fees]
    return dict(zip(POLICIES, [varied, gross, net], strict=True))


def generate(seed, regime, control=None):
    if regime not in ('sparse', 'burst') or control not in (None, 'singleton', 'early'):
        raise ValueError('workload regime/control')
    amounts = contributions(seed)
    if control == 'singleton':
        amounts = {p: [amounts['varied'][0]] for p in POLICIES}
    split_rng = random.Random(f'H12/{seed}/splits')
    payment_rng = random.Random(f'H12/{seed}/payments')
    order_rng = random.Random(f'H12/{seed}/order')
    labels = {}

    def label(kind, index):
        return labels.setdefault((kind, index), secrets.token_hex(32))

    ledgers = {}
    for policy, values in amounts.items():
        first = {'id': label('tx', 0), 'value': values[0], 'minute': -1,
                 'funding_group': label('funding', 0)}
        ledgers[policy] = {'initial': first, 'events': [], 'truth': {},
            'notes': [{'value': values[0], 'owner': 0, 'source': first['id'],
                       'ancestor': first['id'], 'born_count': 1, 'live': True}],
            'native_plan': {'initial_value': values[0], 'events': []}, 'reserve': values[0]}

    def append(kind, minute, owner, position=None, receiver=None):
        quantile = split_rng.getrandbits(64) if kind != 'exit' else None
        for policy, data in ledgers.items():
            notes, events = data['notes'], data['events']
            fee = FEES[kind]; current = len(notes)
            txid = label('tx', len(events)+1)
            added = amounts[policy][owner] if kind == 'deposit' else 0
            value = added if kind == 'deposit' else notes[position]['value']
            if kind == 'exit':
                values, new = [], []
            else:
                low, high = FLOOR//GRID, (value-fee-FLOOR)//GRID
                if high < low:
                    raise ValueError('insufficient common split value; retain this ledger')
                first = (low+(quantile*(high-low+1)//(1 << 64)))*GRID
                values, new = [first, value-fee-first], [current, current+1]
            anchor = 1 if kind == 'deposit' else notes[position]['born_count'] if kind == 'exit' else current
            payout = value-fee if kind == 'exit' else 0
            data['reserve'] += added-payout-fee
            events.append({'id': txid, 'minute': minute, 'kind': kind, 'anchor_count': anchor,
                'count_before': current, 'fee': fee, 'payout': payout, 'deposit': added,
                'new': new, 'reserve_out': data['reserve'],
                'destination': label('destination', position) if kind == 'exit' else None,
                'funding_group': label('funding', owner) if kind == 'deposit' else None})
            if kind == 'deposit':
                ancestor = txid
            else:
                note = notes[position]
                assert note['live'] and note['owner'] == owner
                note['live'] = False
                ancestor = note['ancestor']
                data['truth'][txid] = {'position': position, 'source': note['source'],
                                      'ancestor': ancestor, 'owner': owner}
            for index, amount in enumerate(values):
                assert amount >= FLOOR
                notes.append({'value': amount, 'owner': receiver if index == 0 and receiver is not None else owner,
                    'source': txid, 'ancestor': ancestor, 'born_count': current+2, 'live': True})
            data['native_plan']['events'].append({'kind': kind, 'minute': minute,
                'owner': owner, 'position': position, 'deposit': added, 'values': values,
                'owners': [notes[i]['owner'] for i in new]})

    dep_times = [0, 60, 120, 180] if regime == 'sparse' else [0, 5, 10, 15]
    for owner in range(len(amounts['varied'])):
        append('bootstrap' if owner == 0 else 'deposit', dep_times[owner], owner,
               position=0 if owner == 0 else None)
        if owner == 0 and control == 'early':
            append('exit', 1, 0, position=1)
    pay_times = [] if control else ([195, 225] if regime == 'sparse' else [18, 24, 30, 36])
    eligibility = []
    for minute in pay_times:
        per_arm = [[i for i, n in enumerate(d['notes'])
                    if n['live'] and n['value'] >= 2*FLOOR+FEES['transfer']] for d in ledgers.values()]
        choices = sorted(set.intersection(*(set(x) for x in per_arm)))
        if not choices:
            raise ValueError('no common eligible input; retain this ledger')
        position = payment_rng.choice(choices)
        owner = ledgers['varied']['notes'][position]['owner']
        receiver = payment_rng.choice([w for w in range(4) if w != owner])
        eligibility.append({'per_arm_counts': list(map(len, per_arm)), 'common_count': len(choices)})
        append('transfer', minute, owner, position, receiver)
    positions = [i for i, n in enumerate(ledgers['varied']['notes']) if n['live']]
    order_rng.shuffle(positions)
    start = 5 if control == 'singleton' else 240 if regime == 'sparse' else 45
    for index, position in enumerate(positions):
        append('exit', start+3*index, ledgers['varied']['notes'][position]['owner'], position)
    for policy, data in ledgers.items():
        assert data['reserve'] == 0 and not any(n['live'] for n in data['notes'])
        saved = {'schema': 'kpi-privacy-projection-v1', 'initial': data.pop('initial'),
                 'events': data.pop('events')}
        fresh = copy.deepcopy(saved)
        for event in fresh['events']:
            if event['kind'] == 'exit':
                event['anchor_count'] = event['count_before']
        data['arms'] = {'saved': saved, 'fresh': fresh}
    # Pairing is checked before any observer/scorer sees the work.
    base = ledgers['varied']
    for data in ledgers.values():
        assert data['truth'] == base['truth']
        if not control:
            assert {t['owner'] for e, t in data['truth'].items()
                    if any(x['id'] == e and x['kind'] == 'exit' for x in data['arms']['fresh']['events'])} == set(range(4))
    return {'seed': seed, 'regime': regime, 'control': control, 'policies': ledgers,
            'contributions': amounts, 'common_eligibility': eligibility}
