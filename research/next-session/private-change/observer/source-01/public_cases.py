"""Fixed public analytical controls. No generator truth or crypto witnesses."""
import copy
import itertools

from public_ledger import MAX, NOTE_FLOOR, PAYOUT_FLOOR


class PublicBuilder:
    def __init__(self, number, policy):
        self.labels = itertools.count(number * 1000 + 1)
        self.public = {
            'schema': 'kpx3-change-public-integer-ledger/v1',
            'classification': 'SYNTHETIC_PUBLIC_INTEGER_MODEL',
            'wallet_policy': policy, 'coverage_complete': True,
            'note_floor_sompi': NOTE_FLOOR, 'payout_floor_sompi': PAYOUT_FLOOR,
            'max_sompi': MAX, 'events': [],
        }
        self.reserve, self.cm_count, self.nf_count = 0, 0, 1

    def label(self):
        return f'{next(self.labels):064x}'

    def add(self, kind, *, value=None, payout=0, fee=1, cm_override=None):
        after = self.reserve + value if kind == 'ingress' else self.reserve - payout - fee
        terminal = kind == 'private' and after == 0
        cms = [cm_override or self.label()] if kind == 'ingress' else (
            [] if terminal else [self.label(), self.label()])
        nfs = [] if kind == 'ingress' else [self.label(), self.label()]
        event = {
            'ordinal': len(self.public['events']), 'tx_id': self.label(), 'kind': kind,
            'fee_sompi': fee, 'payout_sompi': payout,
            'payout_destination': '000020' + self.label() + 'ac' if payout else None,
            'prior_reserve_sompi': self.reserve, 'reserve_sompi': after,
            'prior_cm_count': self.cm_count, 'cm_count': self.cm_count + len(cms),
            'prior_nf_count': self.nf_count, 'nf_count': self.nf_count + len(nfs),
            'cms': cms, 'nfs': nfs, 'terminal': terminal,
            'ingress_value_sompi': value,
        }
        self.public['events'].append(event)
        self.reserve, self.cm_count, self.nf_count = after, event['cm_count'], event['nf_count']
        return event

    def request(self):
        return {'public': copy.deepcopy(self.public),
                'value_priors': {'schema': 'kpx3-change-value-priors/v1', 'facts': []}}


def analytic_cases():
    million = 1_000_000
    b = PublicBuilder(1, 'whole_claim')
    b.add('ingress', value=1000 * million)
    b.add('private', fee=20 * million)
    b.add('private', payout=961 * million, fee=19 * million)
    whole = b.request()
    b = PublicBuilder(2, 'change_capable')
    b.add('ingress', value=1000 * million)
    b.add('private', payout=400 * million, fee=19 * million)
    partial = b.request()
    b = PublicBuilder(3, 'change_capable')
    b.add('ingress', value=1000 * million)
    b.add('ingress', value=800 * million)
    b.add('private', fee=20 * million)
    b.add('private', payout=200 * million, fee=19 * million)
    multi = b.request()
    b = PublicBuilder(4, 'change_capable')
    b.add('ingress', value=1000 * million)
    event = b.add('private', fee=20 * million)
    all_but = b.request()
    all_but['value_priors']['facts'].append({
        'position': 1, 'cm': event['cms'][0],
        'minimum_sompi': 400 * million, 'maximum_sompi': 400 * million,
        'source': 'declared_legitimate_value_prior',
    })
    b = PublicBuilder(5, 'whole_claim')
    b.add('ingress', value=600 * million)
    b.add('ingress', value=400 * million)
    b.add('private', payout=581 * million, fee=19 * million)
    b.add('private', payout=381 * million, fee=19 * million)
    terminal = b.request()
    b = PublicBuilder(6, 'change_capable')
    b.add('ingress', value=600 * million)
    b.add('ingress', value=400 * million)
    b.add('private', payout=981 * million, fee=19 * million)
    leftover = b.request()
    b = PublicBuilder(7, 'change_capable')
    b.add('ingress', value=9007199254740993)
    b.add('private', payout=400 * million, fee=19 * million)
    large = b.request()
    b = PublicBuilder(8, 'whole_claim')
    first = b.add('ingress', value=600 * million)
    b.add('ingress', value=600 * million, cm_override=first['cms'][0])
    b.add('private', payout=581 * million, fee=19 * million)
    b.add('private', payout=581 * million, fee=19 * million)
    repeated = b.request()
    return {
        'WHOLE_CLAIM': whole, 'SINGLETON_PARTIAL': partial,
        'MULTI_INGRESS_CHANGE': multi, 'ALL_BUT_ONE': all_but,
        'TERMINAL_VALID': terminal, 'TERMINAL_LEFTOVER': leftover,
        'LARGE_INTEGER': large, 'REPEATED_CM': repeated,
    }


def negative_cases(cases):
    rows = {}
    r = copy.deepcopy(cases['TERMINAL_VALID'])
    r['public']['events'][3]['nfs'][0] = r['public']['events'][2]['nfs'][0]
    rows['NF_REPLAY'] = (r, 'REJECTED_INPUT')
    for field in ['operation_intent', 'selected_inputs', 'owner_map', 'change_slot']:
        for where in ['public', 'event']:
            r = copy.deepcopy(cases['SINGLETON_PARTIAL'])
            destination = r['public'] if where == 'public' else r['public']['events'][1]
            destination[field] = 'FORBIDDEN_PRIVATE_HINT'
            rows['PRIVATE_FIELDS/' + where + '/' + field] = (r, 'REJECTED_INPUT')
    for name, value in [('bool', True), ('float', 400000000.0), ('negative', -1), ('overflow', MAX + 1)]:
        r = copy.deepcopy(cases['SINGLETON_PARTIAL'])
        r['public']['events'][1]['payout_sompi'] = value
        rows['BAD_AMOUNTS/' + name] = (r, 'REJECTED_INPUT')
    for field in ['reserve_sompi', 'cm_count', 'nf_count']:
        r = copy.deepcopy(cases['SINGLETON_PARTIAL'])
        r['public']['events'][1][field] += 1
        rows['BAD_TOPOLOGY/' + field] = (r, 'REJECTED_INPUT')
    r = copy.deepcopy(cases['SINGLETON_PARTIAL'])
    r['public']['events'][1]['terminal'] = True
    rows['BAD_TOPOLOGY/terminal'] = (r, 'REJECTED_INPUT')
    r = copy.deepcopy(cases['SINGLETON_PARTIAL'])
    r['public']['coverage_complete'] = False
    rows['BAD_TOPOLOGY/coverage'] = (r, 'REJECTED_INPUT')
    b = PublicBuilder(9, 'change_capable')
    for _ in range(13):
        b.add('ingress', value=NOTE_FLOOR)
    rows['RESOURCE_SCOPE'] = (b.request(), 'INCOMPLETE_SCOPE')
    return rows
