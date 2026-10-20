#!/usr/bin/env python3
"""H14 public-only two-real-input/zero-padding reconstruction.

No generation, wallet ownership, hidden amount, workload manifest or truth input.
CP-SAT answers feasibility, not posterior probabilities. Unknown fails closed.
"""
import hashlib
import itertools
import json
import sys
import time
from pathlib import Path
from ortools.sat.python import cp_model

FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
MAX = 2_900_000_000_000_000_000


def need(condition, message):
    if not condition:
        raise ValueError(message)


def integer(x, lower=0, upper=MAX):
    need(type(x) is int and lower <= x <= upper, 'integer/range')
    return x


def decode(data, floor=FLOOR, payout_floor=PAYOUT_FLOOR):
    need(set(data) == {'schema', 'initial', 'events'} and data['schema'] == 'kpi-h14-public-v1', 'public schema')
    initial = data['initial']
    need(set(initial) == {'id', 'value', 'funding_group'}, 'initial fields')
    integer(initial['value'], floor)
    need(isinstance(data['events'], list) and data['events'], 'events')
    ids = [initial['id']]; count = 1; balance = initial['value']; minute = -1
    births = [-1]; upper = [balance]
    for i, e in enumerate(data['events']):
        need(set(e) == {'id', 'minute', 'mode', 'anchor_count', 'count_before', 'new', 'fee',
                       'deposit', 'payout', 'reserve_out', 'destination', 'funding_group'}, 'event fields')
        integer(e['minute']); need(e['minute'] >= minute, 'chronology'); minute = e['minute']
        need(balance > 0, 'operation after terminal')
        mode = integer(e['mode'], 0, 2)
        need(integer(e['count_before'], 1) == count, 'count continuity')
        anchor = integer(e['anchor_count'], 0, count)
        for field in ('fee', 'deposit', 'payout', 'reserve_out'):
            integer(e[field])
        need(e['fee'] > 0, 'fee positive')
        need(e['payout'] == 0 or e['payout'] >= payout_floor, 'payout floor')
        need((e['destination'] is not None) == (e['payout'] > 0), 'destination')
        if mode == 0:
            need(i > 0 and anchor == 0 and e['deposit'] >= floor and e['payout'] == 0 and e['funding_group'] is not None, 'admission')
            available = e['deposit']-e['fee']
        else:
            need(anchor > 0 and anchor % 2 == 1 and e['deposit'] == 0 and e['funding_group'] is None, 'spend anchor/funding')
            available = sum(sorted(upper[:anchor], reverse=True)[:2])-e['payout']-e['fee']
        balance += e['deposit']-e['payout']-e['fee']
        need(balance == e['reserve_out'] >= 0, 'native accounting')
        new = [] if mode == 2 else [count, count+1]
        need(e['new'] == new and all(type(p) is int for p in e['new']), 'output positions')
        need(balance > 0 or mode == 2, 'terminal mode')
        if mode == 2:
            need(e['payout'] > 0, 'drain payout')
        else:
            need(available >= 0, 'public value bound')
            # Remaining backing is an independent public upper bound for each new note.
            upper.extend([min(available, balance)]*2); births.extend([i]*2); count += 2
        ids.append(e['id'])
    need(all(isinstance(i, str) and i for i in ids) and len(ids) == len(set(ids)), 'public identifiers')
    return births, upper



def reverse_bounds(data, births, upper):
    """Entailed bounds, not wallet policy: every note is spent later or remains.

    A consumed note cannot exceed its consuming transaction's total input value.
    Traverse note creation backwards so each future spender's output bounds are
    already known. An unspent note cannot exceed the public remaining reserve.
    This is safe for zero slots, one/two inputs and incomplete prefixes.
    """
    bound=list(upper)
    for p in reversed(range(len(bound))):
        budgets=[data['events'][-1]['reserve_out']]
        for i,e in enumerate(data['events']):
            if i>births[p] and e['mode']!=0 and p<e['anchor_count']:
                budgets.append(sum(bound[q] for q in e['new'])+e['payout']+e['fee'])
        bound[p]=min(bound[p],max(budgets))
    return bound


def possibilities(e, upper=None):
    eligible = range(e['anchor_count'])
    for size in (1, 2):
        for combo in itertools.combinations(eligible, size):
            if upper is None or (all(upper[p] >= FLOOR for p in combo) and
                                 sum(upper[p] for p in combo) >= e['payout']+e['fee']):
                yield combo


def ranking(combo):
    # Compare the oldest input first; one input is represented once, not padded.
    return (min(combo), max(combo), tuple(combo))


def source_set(combo, births):
    return tuple(sorted({births[p] for p in combo}))


def summarize(combos, births):
    combos = sorted(combos)
    sources = sorted({source_set(c, births) for c in combos})
    best = max(combos, key=ranking) if combos else None
    return {'input_sets': [list(c) for c in combos], 'source_sets': [list(s) for s in sources],
            'prediction': list(best) if best is not None else None,
            'source_prediction': list(source_set(best, births)) if best is not None else None}


class Model:
    def __init__(self, data, floor=FLOOR, payout_floor=PAYOUT_FLOOR):
        self.births, self.upper = decode(data, floor, payout_floor)
        self.upper = reverse_bounds(data, self.births, self.upper)
        self.data = data; self.model = m = cp_model.CpModel()
        self.values, self.positive, self.select = [], [], {}
        for p, ub in enumerate(self.upper):
            v = m.new_int_var(0, ub, f'v{p}'); real = m.new_bool_var(f'positive{p}')
            m.add(v == 0).only_enforce_if(real.Not()); m.add(v >= floor).only_enforce_if(real)
            self.values.append(v); self.positive.append(real)
        m.add(self.values[0] == data['initial']['value'])
        uses = [[] for _ in self.values]
        for i, e in enumerate(data['events']):
            output = sum(self.values[p] for p in e['new'])
            if e['mode'] == 0:
                m.add(output == e['deposit']-e['fee'])
                continue
            selectors, picked = [], []
            for p in range(e['anchor_count']):
                sel = m.new_bool_var(f's{i}_{p}'); selectors.append(sel); uses[p].append(sel)
                m.add_implication(sel, self.positive[p])
                val = m.new_int_var(0, self.upper[p], f'picked{i}_{p}')
                m.add(val == self.values[p]).only_enforce_if(sel)
                m.add(val == 0).only_enforce_if(sel.Not()); picked.append(val)
            m.add(sum(selectors) >= 1); m.add(sum(selectors) <= 2)
            m.add(sum(picked) == output+e['payout']+e['fee'])
            self.select[i] = selectors
        for p, choices in enumerate(uses):
            m.add(sum(choices) <= 1)
            if data['events'][-1]['reserve_out'] == 0:
                m.add(sum(choices) == self.positive[p])
        self.solver = cp_model.CpSolver()
        self.solver.parameters.num_search_workers = 1
        self.solver.parameters.random_seed = 0
        # No timeout-based ambiguity. External interruption leaves an incomplete run.
        self.queries = 0

    def check(self, target=None, combo=None, fixed=None):
        # Explicit equalities let presolve eliminate fully fixed graph choices.
        # They are logically identical to the former assumption literals.
        model = self.model.clone()
        model.clear_assumptions()
        assignments = dict(fixed or {})
        if target is not None:
            assignments[target] = combo
        for i, choice in assignments.items():
            need(i in self.select and 1 <= len(choice) <= 2 and len(set(choice)) == len(choice), 'selection framing')
            need(all(type(p) is int and 0 <= p < len(self.select[i]) for p in choice), 'selection anchor')
            for p, selected in enumerate(self.select[i]):
                model.add(selected == int(p in choice))
        status = self.solver.solve(model); self.queries += 1
        need(status in (cp_model.OPTIMAL, cp_model.FEASIBLE, cp_model.INFEASIBLE),
             f'non-conclusive solver status {self.solver.status_name(status)}')
        return status != cp_model.INFEASIBLE

    def candidates(self, target, allowed=None):
        e = self.data['events'][target]
        return [c for c in (possibilities(e) if allowed is None else allowed) if self.check(target, c)]


def analyze(data):
    births, upper = decode(data)
    rows = []
    # All non-admissions are targets. The observer does not know which are private
    # payments rather than wallet self-transfers; that classification is scoring-only.
    for i, e in enumerate(data['events']):
        if e['mode'] != 0:
            rows.append(dict(event=i, structural=summarize(possibilities(e), births),
                amount=summarize(possibilities(e, upper), births), joint=[]))
    drain_indices = [i for i, e in enumerate(data['events']) if e['mode'] == 2]
    total_queries = 0
    for end in reversed(range(len(data['events']))):
        targets = [r for r in rows if r['event'] == end or end == len(data['events'])-1
                   or (end in drain_indices and r['event'] <= end and r['event'] > 0
                       and data['events'][r['event']]['mode'] == 1
                       and data['events'][r['event']]['payout'] == 0)]
        if not targets:
            continue
        prefix = dict(data, events=data['events'][:end+1])
        from two_input_privacy_exact import ExactModel
        model = ExactModel(prefix); need(model.check(), 'public history infeasible')
        for row in targets:
            # A witnessed full-history solution restricts to a valid prefix.
            # Seed only SAT answers; every other candidate is queried against
            # this prefix alone. This changes work order, not conditioning or
            # ranking, and uses no private truth.
            known = {tuple(c) for c in row['joint'][-1]['input_sets']} if row['joint'] else set()
            combos = [c for c in sorted(row['amount']['input_sets'], key=lambda c:(len(c),c))
                      if tuple(c) in known or model.check(row['event'], c)]
            need(combos, 'empty candidate set')
            row['joint'].append(dict(through=end, **summarize(combos, births)))
            print(f'prefix {end+1}, event {row["event"]}: {len(combos)} input sets', file=sys.stderr, flush=True)
        total_queries += model.queries
        print(f'observed prefix {end+1}/{len(data["events"])}: {model.queries} feasibility queries', file=sys.stderr, flush=True)
    for row in rows:
        row['joint'].sort(key=lambda r:r['through'])
    return {'rows':rows, 'feasibility_queries':total_queries,
            'funding_clusters':len({data['initial']['funding_group']} | {e['funding_group'] for e in data['events'] if e['mode']==0}),
            'common_funder_sensitivity_clusters':1,
            'meaning':'feasible source sets; no probability or user anonymity estimate'}


def main():
    raw = Path(sys.argv[1]).read_bytes(); start = time.monotonic()
    result = analyze(json.loads(raw))
    result.update(input_sha256=hashlib.sha256(raw).hexdigest(), seconds=time.monotonic()-start)
    with Path(sys.argv[2]).open('x') as out:
        json.dump(result,out,separators=(',',':'))


if __name__ == '__main__':
    main()
