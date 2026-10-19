#!/usr/bin/env python3
"""H11 public constraint attack. No generator, seed, private truth or wallet input.

This projection is NOT a signed transaction or a consensus validator. Feasible
integer histories are not posterior probabilities. Native calibration decodes
the same projection from genuine transaction bytes in a separate module.
"""
import argparse
import hashlib
import json
from pathlib import Path

FLOOR = 60_000_000
MAX = 2_900_000_000_000_000_000
FIELDS = {'id', 'minute', 'kind', 'anchor_count', 'count_before', 'fee', 'payout',
          'deposit', 'new', 'reserve_out', 'destination', 'funding_group'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def decode(chain, floor=FLOOR):
    need(set(chain) == {'schema', 'initial', 'events'}, 'public projection fields')
    need(chain['schema'] == 'kpi-privacy-projection-v1', 'projection schema')
    initial = chain['initial']
    need(set(initial) == {'id', 'value', 'minute', 'funding_group'}, 'initial fields')
    need(type(initial['value']) is int and floor <= initial['value'] <= MAX, 'initial range')
    notes = [{'source': initial['id'], 'born': -1, 'upper': initial['value']}]
    reserve, spent, roots = initial['value'], 0, {1}
    ids = {initial['id']}
    previous_time = initial['minute']
    for step, e in enumerate(chain['events']):
        need(set(e) == FIELDS, 'event fields')
        for key in ['minute', 'anchor_count', 'count_before', 'fee', 'payout', 'deposit', 'reserve_out']:
            need(type(e[key]) is int and -1 <= e[key] <= MAX, 'integer field '+key)
        need(e['id'] not in ids, 'duplicate event ID'); ids.add(e['id'])
        need(e['minute'] > previous_time, 'strict accepted order/clock'); previous_time = e['minute']
        need(e['count_before'] == len(notes) and len(notes) <= 65535, 'commitment count/history')
        need(0 < e['fee'] <= MAX and e['payout'] >= 0 and e['deposit'] >= 0, 'amount ranges')
        kind = e['kind']
        need(kind in ('bootstrap', 'deposit', 'transfer', 'exit'), 'operation kind')
        need((kind == 'bootstrap') == (step == 0), 'canonical bootstrap')
        if kind == 'deposit':
            need(spent > 0 and spent < len(notes) and e['anchor_count'] == 1, 'admission context')
            need(e['deposit'] >= 2*floor+e['fee'] and e['funding_group'], 'admission backing')
            upper = e['deposit']-e['fee']-floor
        else:
            need(e['deposit'] == 0 and e['funding_group'] is None, 'non-deposit funding')
            need(e['anchor_count'] in roots and e['anchor_count'] <= len(notes), 'historical root/count')
            upper = max(n['upper'] for n in notes[:e['anchor_count']])-e['fee']-floor
            spent += 1
        if kind != 'exit':
            need(e['new'] == [len(notes), len(notes)+1] and e['payout'] == 0 and
                 e['destination'] is None and upper >= floor, 'two-note relation')
            notes.extend({'source': e['id'], 'born': step, 'upper': upper} for _ in range(2))
            roots.add(len(notes))
        else:
            need(e['new'] == [] and e['payout'] > 0 and e['destination'], 'full-exit shape')
        need(reserve + e['deposit'] <= MAX, 'reserve sum range')
        reserve += e['deposit']-e['payout']-e['fee']
        need(reserve == e['reserve_out'] and reserve >= 0, 'public conservation')
        need(spent <= len(notes), 'spend count')
        need((reserve == 0) == (spent == len(notes)), 'terminal backing')
        need(reserve > 0 or step == len(chain['events'])-1, 'history after drain')
    need(chain['events'], 'missing bootstrap')
    return notes


def eligible(events, event):
    """Exact prefix matching (Hall) for single-spend/anchor constraints only."""
    others = sorted(e['anchor_count'] for e in events
                    if e['kind'] != 'deposit' and e['id'] != event['id'])
    need(all(bound >= k for k, bound in enumerate(others, 1)), 'impossible prefix matching')
    lower = max((bound for k, bound in enumerate(others, 1) if bound == k), default=0)
    result = list(range(lower, event['anchor_count']))
    need(result, 'empty matching domain')
    return result


class Z3Joint:
    def __init__(self, chain, events, floor=FLOOR):
        import z3
        self.z = z3
        self.s = z3.Solver()
        self.events = events
        self.notes = decode({**chain, 'events': events}, floor)
        self.values = [z3.Int(f'v{i}') for i in range(len(self.notes))]
        self.ancestors = [z3.Int(f'a{i}') for i in range(len(self.notes))]
        self.deposits = [chain['initial']['id']] + [e['id'] for e in events if e['kind'] == 'deposit']
        self.groups = [chain['initial']['funding_group']] + [e['funding_group'] for e in events if e['kind'] == 'deposit']
        self.choices = {}
        self.s.add(self.values[0] == chain['initial']['value'], self.ancestors[0] == 0)
        for i, v in enumerate(self.values):
            self.s.add(v >= floor, v <= self.notes[i]['upper'])
        indicators = [[] for _ in self.values]
        for e in events:
            if e['kind'] == 'deposit':
                a, b = e['new']
                self.s.add(self.values[a]+self.values[b] == e['deposit']-e['fee'])
                self.s.add(self.ancestors[a] == self.deposits.index(e['id']),
                           self.ancestors[b] == self.deposits.index(e['id']))
                continue
            c = z3.Int(f'choice{len(self.choices)}')
            self.choices[e['id']] = c
            domain = eligible(events, e)
            if e['kind'] == 'exit':
                domain = [i for i in domain if self.notes[i]['upper'] >= e['payout']+e['fee']]
            else:
                domain = [i for i in domain if self.notes[i]['upper'] >= 2*floor+e['fee']]
            self.s.add(z3.Or([c == i for i in domain]))
            cost = z3.Sum([self.values[i] for i in e['new']]+[e['payout']+e['fee']])
            for i in domain:
                indicators[i].append(c == i)
                self.s.add(z3.Implies(c == i, self.values[i] == cost))
                for out in e['new']:
                    self.s.add(z3.Implies(c == i, self.ancestors[out] == self.ancestors[i]))
        self.s.add(z3.Distinct(list(self.choices.values())))
        for column in indicators:
            if column:
                # Redundant inverse matching makes the implied bijection
                # explicit for Z3; no change to the feasible-history relation.
                self.s.add(z3.PbLe([(p, 1) for p in column], 1))
                if events[-1]['reserve_out'] == 0:
                    self.s.add(z3.Or(column))
        self.s.add(z3.Sum([z3.If(z3.And([c != i for c in self.choices.values()]), v, 0)
                              for i, v in enumerate(self.values)]) == events[-1]['reserve_out'])
        need(self.s.check() == z3.sat, 'inconsistent/unknown joint history')

    def possible(self, condition):
        self.s.push(); self.s.add(condition)
        answer = self.s.check()
        self.s.pop()
        need(answer != self.z.unknown, 'unknown solver result')
        return answer == self.z.sat

    def candidates(self, e):
        c, z = self.choices[e['id']], self.z
        positions = [i for i in eligible(self.events, e) if self.possible(c == i)]
        ancestors = [d for d in range(len(self.deposits)) if self.possible(
            z.Or([z.And(c == i, self.ancestors[i] == d) for i in positions]))]
        need(positions and ancestors, 'empty joint candidates')
        return positions, [self.deposits[d] for d in ancestors], sorted({self.groups[d] for d in ancestors})


class Joint:
    """Same integer relation using CP-SAT's explicit one-to-one matching.

    Z3Joint above remains an independent solver formulation for cross-checks.
    No floating monetary arithmetic, time limit, or unknown-as-feasible rule.
    """
    def __init__(self, chain, events, floor=FLOOR):
        from ortools.sat.python import cp_model
        self.cp = cp_model
        self.m = cp_model.CpModel()
        self.events = events
        self.notes = decode({**chain, 'events': events}, floor)
        self.deposits = [chain['initial']['id']]+[e['id'] for e in events if e['kind'] == 'deposit']
        self.groups = [chain['initial']['funding_group']]+[e['funding_group'] for e in events if e['kind'] == 'deposit']
        # This research adapter deliberately refuses native-range traces too
        # large for CP-SAT's intermediate signed sums, instead of narrowing
        # their feasible set or silently overflowing. H11 is far below this.
        need(sum(n['upper'] for n in self.notes) < 2**62, 'CP-SAT intermediate range unsupported')
        self.values = [self.m.new_int_var(floor, n['upper'], f'v{i}') for i,n in enumerate(self.notes)]
        self.ancestors = [self.m.new_int_var(0,len(self.deposits)-1,f'a{i}') for i in range(len(self.notes))]
        self.m.add(self.values[0] == chain['initial']['value']); self.m.add(self.ancestors[0] == 0)
        self.choices, self.taken_ancestors = {}, {}
        self.positive, self.ancestor_positive = {}, {}
        columns = [[] for _ in self.notes]
        for step,e in enumerate(events):
            if e['kind'] == 'deposit':
                a,b = e['new']
                self.m.add(self.values[a]+self.values[b] == e['deposit']-e['fee'])
                self.m.add(self.ancestors[a] == self.deposits.index(e['id']))
                self.m.add(self.ancestors[b] == self.deposits.index(e['id']))
                continue
            required = e['payout']+e['fee'] if e['kind'] == 'exit' else 2*floor+e['fee']
            domain = [i for i in eligible(events,e) if self.notes[i]['upper'] >= required]
            need(domain,'empty amount domain')
            choice = self.m.new_int_var_from_domain(cp_model.Domain.from_values(domain),f'c{step}')
            anc = self.m.new_int_var(0,len(self.deposits)-1,f'takea{step}')
            self.choices[e['id']], self.taken_ancestors[e['id']] = choice, anc
            cost = sum(self.values[i] for i in e['new'])+e['payout']+e['fee']
            row = []
            for i in domain:
                use = self.m.new_bool_var(f'use{step}_{i}')
                self.m.add(choice == i).only_enforce_if(use)
                self.m.add(choice != i).only_enforce_if(~use)
                self.m.add(self.values[i] == cost).only_enforce_if(use)
                self.m.add(anc == self.ancestors[i]).only_enforce_if(use)
                columns[i].append(use); row.append(use)
            self.m.add_exactly_one(row)
            for out in e['new']: self.m.add(self.ancestors[out] == anc)
        self.m.add_all_different(list(self.choices.values()))
        remainder = []
        for i,column in enumerate(columns):
            live = self.m.new_bool_var(f'live{i}')
            self.m.add(sum(column)+live == 1)
            value = self.m.new_int_var(0,self.notes[i]['upper'],f'rest{i}')
            self.m.add(value == self.values[i]).only_enforce_if(live)
            self.m.add(value == 0).only_enforce_if(~live)
            remainder.append(value)
        self.m.add(sum(remainder) == events[-1]['reserve_out'])
        need(self.possible(), 'inconsistent joint history')

    def possible(self, condition=None):
        model = self.m if condition is None else self.m.clone()
        if condition is not None: model.add(condition)
        solver = self.cp.CpSolver()
        solver.parameters.num_search_workers = 1
        status = solver.solve(model)
        need(status in (self.cp.OPTIMAL,self.cp.FEASIBLE,self.cp.INFEASIBLE),
             'unknown/invalid CP-SAT result: '+solver.status_name(status))
        if status != self.cp.INFEASIBLE:
            # Every SAT witness also certifies candidates for other withdrawals
            # in this same public history. Never import another arm's results.
            for txid, variable in self.choices.items():
                self.positive.setdefault(txid,set()).add(solver.value(variable))
                self.ancestor_positive.setdefault(txid,set()).add(solver.value(self.taken_ancestors[txid]))
        return status != self.cp.INFEASIBLE

    def candidates(self,e):
        c = self.choices[e['id']]
        groups = {}
        for i in eligible(self.events,e): groups.setdefault(self.notes[i]['source'],[]).append(i)
        positions = []
        for group in groups.values():
            # The two outputs have identical public constraints and can be
            # exchanged, including every later input choice. Query one
            # representative; the exhaustive oracle tests this symmetry.
            if any(i in self.positive.get(e['id'],set()) for i in group) or self.possible(c == group[0]):
                positions.extend(group)
        ancestors = [i for i in range(len(self.deposits)) if i in self.ancestor_positive.get(e['id'],set())
                     or self.possible(self.taken_ancestors[e['id']] == i)]
        need(positions and ancestors,'empty joint candidates')
        return positions,[self.deposits[i] for i in ancestors],sorted({self.groups[i] for i in ancestors})


def analyze(chain):
    from privacy_study_flow import Flow
    notes = decode(chain)
    events = chain['events']
    times = {chain['initial']['id']: chain['initial']['minute'], **{e['id']: e['minute'] for e in events}}
    full = Flow(chain,events,notes) if Flow.supports(events) else Joint(chain, events)
    rows = []

    def describe(positions):
        sources = sorted({notes[i]['source'] for i in positions})
        need(sources, 'no source candidates')
        return {'positions': positions, 'sources': sources,
                'prediction': sorted(sources, key=lambda s: (-times[s], s))[0],
                'uniform_expected': 1/len(sources)}

    for step, e in enumerate(events):
        if e['kind'] != 'exit':
            continue
        row = {'id': e['id']}
        own = (Flow(chain,events[:step+1],notes,structure=full.structure)
               if isinstance(full,Flow) else Joint(chain, events[:step+1]))
        for name, model in [('at_withdrawal', own), ('complete_drain', full)]:
            # Baselines use only the current exit's time/anchor and public upper
            # values. They deliberately do not silently inherit joint inference.
            domain = list(range(e['anchor_count']))
            amount = [i for i in domain if notes[i]['upper'] >= e['payout']+e['fee']]
            positions, ancestors, groups = model.candidates(e)
            row[name] = {'timing': describe(domain), 'amount': describe(amount),
                         'joint': {**describe(positions), 'deposit_ancestors': ancestors,
                                   'funding_groups': groups}}
        rows.append(row)
    return {'schema': 'kpi-privacy-observer-v1', 'rows': rows,
            'transactions': len(events)+1, 'pool_fees_sompi': sum(e['fee'] for e in events),
            'drained': events[-1]['reserve_out'] == 0,
            'scope': 'Integer histories of public fields; not consensus or anonymity probabilities'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args()
    raw = args.input.read_bytes()
    result = analyze(json.loads(raw))
    result['input_sha256'] = hashlib.sha256(raw).hexdigest()
    with args.output.open('x') as out:
        json.dump(result, out, separators=(',', ':'))
    print(json.dumps({'complete': True, 'withdrawals': len(result['rows'])}))


if __name__ == '__main__':
    main()
