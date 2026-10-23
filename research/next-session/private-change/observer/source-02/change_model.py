"""Exact bounded arithmetic observer, not a cryptographic or owner model."""
import z3

from certificate import check_certificate
from public_ledger import MAX, NOTE_FLOOR, InputError, ScopeLimit, decode, digest

TIMEOUT_MS = 60_000
MAX_QUERIES = 37
ASSUMPTIONS = [
    'complete synthetic public chronology and integer value priors',
    'one real earlier positive input per private action',
    'positioned single-spend and all-prefix reserve conservation',
    'declared whole-claim or change-capable wallet policy; no fixed change slot',
]
MISSING = [
    'hash-preimage existence and commitment-binding constraints',
    'actual note ownership or sender/receiver identity',
    'correct ciphertext delivery and undisclosed invoice history',
    'proof/setup soundness, accepted-chain membership and data availability',
    'network privacy, malicious-host protection and equal model probabilities',
]


def total(expressions):
    return z3.Sum(expressions) if expressions else z3.IntVal(0)


class IntegerModel:
    def __init__(self, ledger):
        self.ledger = ledger
        self.solver = z3.Solver()
        self.solver.set(timeout=TIMEOUT_MS, random_seed=0, threads=1)
        self.queries = 0
        self.values = [z3.Int(f'value_{n.position}') for n in ledger.notes]
        self.select = {}
        self.input_sums = {}
        self.output_sums = {}
        uses = [[] for _ in ledger.notes]
        for note, value in zip(ledger.notes, self.values, strict=True):
            self.solver.add(value <= MAX, z3.Or(value == 0, value >= NOTE_FLOOR))
            if note.known_value is not None:
                self.solver.add(value == note.known_value)
        for position, low, high in ledger.bounds:
            self.solver.add(self.values[position] >= low, self.values[position] <= high)
        for event in ledger.events:
            output = total([self.values[p] for p in event.new_positions])
            if event.kind == 'ingress':
                self.solver.add(output == event.ingress_value)
                continue
            selectors = [z3.Bool(f'select_{event.ordinal}_{p}') for p in range(event.prior_count)]
            self.select[event.ordinal] = selectors
            self.solver.add(z3.PbEq([(s, 1) for s in selectors], 1))
            for p, selected in enumerate(selectors):
                self.solver.add(z3.Implies(selected, self.values[p] >= NOTE_FLOOR))
                uses[p].append(selected)
            consumed = total([z3.If(s, self.values[p], 0) for p, s in enumerate(selectors)])
            self.input_sums[event.ordinal], self.output_sums[event.ordinal] = consumed, output
            self.solver.add(consumed == output + event.payout + event.fee)
            positive = total([z3.If(self.values[p] > 0, 1, 0) for p in event.new_positions])
            if event.payout:
                self.solver.add(positive == 0 if ledger.policy == 'whole_claim' else positive <= 1)
            else:
                self.solver.add(positive >= 1, positive <= 2)
        for used in uses:
            if used:
                self.solver.add(z3.PbLe([(s, 1) for s in used], 1))
        for event in ledger.events:
            remaining = []
            for note, value in zip(ledger.notes, self.values, strict=True):
                if note.birth > event.ordinal:
                    continue
                consumed = [ss[note.position] for ordinal, ss in self.select.items()
                            if ordinal <= event.ordinal and note.position < len(ss)]
                used = z3.Or(consumed) if consumed else z3.BoolVal(False)
                remaining.append(z3.If(used, 0, value))
            self.solver.add(total(remaining) == event.reserve)

    def _solve(self):
        if self.queries >= MAX_QUERIES:
            return 'UNKNOWN', None, 'query-bound'
        self.queries += 1
        result = self.solver.check()
        if result == z3.unknown:
            return 'UNKNOWN', None, self.solver.reason_unknown()
        if result == z3.unsat:
            return 'UNSAT', None, None
        if result != z3.sat:
            return 'UNKNOWN', None, 'unexpected-solver-result'
        model = self.solver.model()
        certificate = {
            'values': [model.eval(v, model_completion=True).as_long() for v in self.values],
            'selected_positions': [
                {'event': ordinal, 'position': next(p for p, s in enumerate(ss)
                                                    if z3.is_true(model.eval(s, model_completion=True)))}
                for ordinal, ss in self.select.items()
            ],
        }
        check_certificate(self.ledger, certificate)
        return 'SAT', certificate, None

    def alternate(self, predicate):
        self.solver.push()
        try:
            self.solver.add(predicate)
            return self._solve()
        finally:
            self.solver.pop()


def analyze(public, value_priors):
    report = {
        'schema': 'kpx3-change-public-integer-analysis/v1',
        'classification': 'SYNTHETIC_PUBLIC_INTEGER_MODEL',
        'owner_link': 'NOT_MODELLED', 'assumptions': ASSUMPTIONS,
        'missing_constraints': MISSING, 'financial_privacy_or_crypto_qualification': False,
        'solver_version': z3.get_full_version(),
    }
    try:
        ledger = decode(public, value_priors)
    except ScopeLimit as error:
        return dict(report, status='INCOMPLETE_SCOPE', reason=str(error), queries=0)
    except (InputError, TypeError, KeyError) as error:
        return dict(report, status='REJECTED_INPUT', reason=str(error), queries=0)
    report.update(public_sha256=digest(public), value_priors_sha256=digest(value_priors),
                  wallet_policy=ledger.policy, note_amounts=[], private_events=[])
    engine = IntegerModel(ledger)
    state, base, reason = engine._solve()
    report['baseline_status'] = state
    if state != 'SAT':
        return dict(report, status='INCONSISTENT' if state == 'UNSAT' else 'INCOMPLETE',
                    reason=reason, queries=engine.queries)
    report['baseline_arithmetic_certificate'] = base
    complete = True

    def amount(expression, baseline, evaluate):
        nonlocal complete
        if not complete:
            return {'status': 'NOT_EVALUATED'}
        state, other, reason = engine.alternate(expression != baseline)
        if state == 'UNSAT':
            return {'status': 'FORCED_VALUE', 'value_sompi': baseline, 'alternative_check': state}
        if state == 'UNKNOWN':
            complete = False
            return {'status': 'INCOMPLETE', 'reason': reason, 'alternative_check': state}
        alternative = evaluate(other)
        if alternative == baseline:
            from certificate import CertificateError
            raise CertificateError('certificate-missed-alternate-value')
        return {'status': 'ARITHMETIC_ALTERNATIVE_ONLY', 'baseline_value_sompi': baseline,
                'alternative_value_sompi': alternative,
                'alternative_arithmetic_certificate': other, 'alternative_check': state}

    for note in ledger.notes:
        report['note_amounts'].append({'position': note.position, 'cm': note.cm,
                                     'amount': amount(engine.values[note.position], base['values'][note.position],
                                                      lambda c, p=note.position: c['values'][p])})
    baseline_positions = {row['event']: row['position'] for row in base['selected_positions']}
    for event in ledger.events:
        if event.kind != 'private':
            continue
        selected = baseline_positions[event.ordinal]
        row = {
            'event': event.ordinal, 'tx_id': event.tx_id,
            'input_sum': amount(engine.input_sums[event.ordinal], base['values'][selected],
                                lambda c, i=event.ordinal: c['values'][next(r['position'] for r in
                                    c['selected_positions'] if r['event'] == i)]),
            'new_output_sum': amount(engine.output_sums[event.ordinal],
                                     sum(base['values'][p] for p in event.new_positions),
                                     lambda c, ps=event.new_positions: sum(c['values'][p] for p in ps)),
        }
        if not complete:
            row['selection'] = {'status': 'NOT_EVALUATED'}
        else:
            state, other, reason = engine.alternate(z3.Not(engine.select[event.ordinal][selected]))
            if state == 'UNSAT':
                row['selection'] = {'status': 'FORCED_POSITIONED_CM_TO_PAYOUT' if event.payout
                                    else 'FORCED_POSITIONED_CM_TO_EVENT', 'position': selected,
                                    'cm': ledger.notes[selected].cm, 'alternative_check': state}
            elif state == 'UNKNOWN':
                complete = False
                row['selection'] = {'status': 'INCOMPLETE', 'reason': reason, 'alternative_check': state}
            else:
                alternative = next(r['position'] for r in other['selected_positions']
                                   if r['event'] == event.ordinal)
                if alternative == selected:
                    from certificate import CertificateError
                    raise CertificateError('certificate-missed-alternate-selection')
                row['selection'] = {'status': 'ARITHMETIC_ALTERNATIVE_ONLY',
                                    'baseline_position': selected,
                                    'alternative_position': alternative,
                                    'alternative_arithmetic_certificate': other, 'alternative_check': state}
        report['private_events'].append(row)
    return dict(report, status='COMPLETE' if complete else 'INCOMPLETE', queries=engine.queries)
