"""Original Boolean relation plus entailed per-position monetary flow cuts.

For each position p the original model defines picked(i,p)=value[p] when the
selector is true and zero otherwise. At most one selector can be true, so
sum_i picked(i,p) <= value[p]. At terminal reserve zero, the original model
requires exactly one use of each positive position, giving equality instead.
Zero padding contributes zero; equal commitments remain distinct columns.
These cuts change propagation/LP strength, never the integer feasible set.

Original arithmetic, ownership and independent Z3 models are reused unchanged.
Existing variable names are explicitly checked before obtaining their handles.
Only hypothetical CP assignments cross to Z3; truth is scorer-only.
"""
import time

from ortools.sat.python import cp_model

import population_privacy_index as compact
import population_privacy_model as original
from population_privacy_model import Incomplete, digest, fields, prefix, validate
from two_input_privacy_observer import FLOOR, PAYOUT_FLOOR, integer, need

FEE = original.FEE


class FlowPair(original.Pair):
    # These methods depend on the public Pair/witness interface. The shared
    # witness adapter recognizes this as the original Boolean representation.
    smt_witness = compact.IndexPair.smt_witness
    proposition = compact.IndexPair.proposition
    field_value = compact.IndexPair.field_value

    def __init__(self, public, view, floor=FLOOR, payout_floor=PAYOUT_FLOOR, fee=FEE,
                 tiny=False, diagnostics=False):
        super().__init__(public, view, floor, payout_floor, fee, tiny, diagnostics)
        self.validated_witnesses, self.cp_witnesses = {}, {}
        model = self.cp.model
        names = {variable.name: i for i, variable in enumerate(model.proto.variables)}
        need(len(names) == len(model.proto.variables), "ambiguous original CP variable names")
        columns = [[] for _ in self.cp.values]
        expected = set()
        for event, selectors in self.cp.select.items():
            for position in range(len(selectors)):
                name = f"picked{event}_{position}"
                need(name in names, "original picked variable absent")
                index = names[name]
                domain = list(model.proto.variables[index].domain)
                need(domain == [0, self.cp.upper[position]], "unexpected original picked domain")
                columns[position].append(model.get_int_var_from_proto_index(index))
                expected.add(name)
        need({name for name in names if name.startswith("picked")} == expected,
             "unaccounted original picked variable")
        terminal = self.data["events"][-1]["reserve_out"] == 0
        for value, picked, upper in zip(self.cp.values, columns, self.cp.upper):
            if (len(picked) + 1) * upper >= 2**62:
                raise Incomplete("CP flow-column intermediate range unsupported")
            model.add(sum(picked) == value if terminal else sum(picked) <= value)
        self.flow_cut_count = len(columns)


def _analyze(public, view, targets=None, floor=FLOOR, payout_floor=PAYOUT_FLOOR, fee=FEE,
             tiny=False, diagnostics=False):
    # Keep this small orchestration local: frozen prior modules hardcode their
    # Pair constructor. No arithmetic or ownership constraints are duplicated.
    validate(public, view, floor, payout_floor, fee, tiny)
    events = public["algebra"]["events"]
    if targets is None:
        targets = [dict(event=i, through_event=len(events) - 1)
                   for i, e in enumerate(events) if i > 0 and e["mode"] == 1]
    need(isinstance(targets, list), "target list")
    seen = set()
    for target in targets:
        fields(target, {"event", "through_event"}, "target")
        i = integer(target["event"], 1, len(events) - 1)
        end = integer(target["through_event"], i, len(events) - 1)
        need(events[i]["mode"] == 1 and (i, end) not in seen, "ordinary unique target")
        seen.add((i, end))
    models, rows, error = {}, [], None
    try:
        for end in sorted({t["through_event"] for t in targets} or {len(events) - 1}, reverse=True):
            p, v = prefix(public, view, end)
            model = FlowPair(p, v, floor, payout_floor, fee, tiny, diagnostics)
            models[end] = model
            baseline = model.query("cp_sat")
            if baseline is None:
                if model.query("z3", kind="unrestricted_inconsistency_check") is not None:
                    raise Incomplete("CP UNSAT disagrees with unrestricted Z3")
                raise Incomplete("inconsistent prefix")
            model.smt_witness(baseline)
            for target in (t for t in targets if t["through_event"] == end):
                i = target["event"]
                model.progress(event="target_start", target_event=i)
                row = dict(event=i, through_event=end)
                for field in ("sender", "recipient", "amount"):
                    row[field] = model.proposition(i, field, baseline)
                row["relationship_forced"] = row["sender"]["forced"] and row["recipient"]["forced"]
                rows.append(row)
    except Incomplete as failure:
        error = str(failure)
    return dict(schema="kpi-population-predictions-v1", complete=error is None, error=error,
                rows=rows, requested_targets=targets,
                queries={engine: sum(m.queries[engine] for m in models.values())
                         for engine in ("cp_sat", "z3")},
                public_sha256=digest(public), view_sha256=digest(view),
                encoding="original-boolean-with-entailed-per-position-money-flow-cuts",
                meaning="Conditional exact propositions; witnesses are hypothetical assignments, not recovered truth or probabilities",
                assumptions=["Original population ownership/value relation is unchanged.",
                             "Complete records, closed role universe and current-wallet behavior.",
                             "Cryptographic hiding is assumed, not tested."],
                relaxations=["Automatic coin selection, payment distribution, timing/scheduling and admission-time recipient restrictions are not enforced."])


def analyze(public, view, targets=None):
    return _analyze(public, view, targets, diagnostics=True)


def validate_truth(public, view, truth):
    """Scorer-only; truth is never passed into analyze."""
    model = FlowPair(public, view)
    cp, smt = compact.witness_conditions(model, truth)
    answers = [model.query("cp_sat", cp), model.query("z3", smt)]
    return dict(complete=True, cp_sat="SAT" if answers[0] is not None else "UNSAT",
                z3="SAT" if answers[1] is not None else "UNSAT")


def _complete_set(model):
    """All tiny projections; latent owners of zero padding are not observations."""
    remaining, states = model.cp.model.clone(), set()
    while True:
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 8
        solver.parameters.random_seed = 0
        status = solver.solve(remaining)
        if status == cp_model.INFEASIBLE:
            return states
        assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
        values = tuple(solver.value(v) for v in model.cp.values)
        owners = tuple(solver.value(o) if v else None for o, v in zip(model.cp_owners, values))
        inputs = tuple((i, tuple(p for p, selected in enumerate(selectors) if solver.value(selected)))
                       for i, selectors in model.cp.select.items())
        state = (values, owners, inputs)
        assert state not in states
        states.add(state)
        variables = list(model.cp.values) + [
            owner for owner, value in zip(model.cp_owners, values) if value] + [
                selected for selectors in model.cp.select.values() for selected in selectors]
        different = []
        for index, variable in enumerate(variables):
            literal = remaining.new_bool_var(f"projection_{len(states)}_{index}")
            value = solver.value(variable)
            remaining.add(variable != value).only_enforce_if(literal)
            remaining.add(variable == value).only_enforce_if(literal.Not())
            different.append(literal)
        remaining.add_bool_or(different)


def controls():
    cases = [
        (6, [(1, 0, [0], [(0, 5), (None, 0)]),
             (0, 1, [], [(1, 5), (None, 0)]),
             (1, 0, [1], [(1, 2), (0, 2)])], 1, [], False),
        (7, [(1, 0, [0], [(0, 6), (None, 0)]),
             (0, 1, [], [(1, 2), (None, 0)]),
             (1, 0, [1], [(1, 2), (0, 3)]),
             (2, 1, [3, 5], [])], 2, [], False),
        (8, [(1, 0, [0], [(0, 7), (None, 0)]),
             (0, 1, [], [(1, 3), (None, 0)]),
             (1, 0, [1], [(1, 3), (0, 3)]),
             (2, 1, [3], []), (2, 1, [5], []), (2, 0, [6], [])], 1, [1], True),
    ]
    prefixes = solutions = witnesses = 0
    for initial, steps, floor, members, duplicate in cases:
        public, truth = original._fixture(initial, steps, roles=2, floor=floor)
        if duplicate:
            public["commitments"][5] = public["commitments"][3]
        view = original._view(public, truth, members)
        for end in range(len(steps)):
            p, v = prefix(public, view, end)
            oracle = original._enumerate(p, v, floor)
            expected = {
                (tuple(value for value, _ in state[0]), tuple(owner for _, owner in state[0]),
                 tuple((i, inputs) for i, inputs in enumerate(state[2])
                       if p["algebra"]["events"][i]["mode"] != 0)) for state in oracle}
            model = FlowPair(p, v, floor, 1, 1, tiny=True)
            assert _complete_set(model) == expected
            reference = original.Pair(p, v, floor, 1, 1, tiny=True)
            for state in oracle:
                witness = compact._witness(state)
                for target in (model, reference):
                    cp, smt = compact.witness_conditions(target, witness)
                    assert target.query("cp_sat", cp) is not None
                    assert target.query("z3", smt) is not None
                witnesses += 1
            prefixes += 1
            solutions += len(expected)
    # Incomplete prefixes must permit a positive, unspent receipt. Full terminal
    # coverage is already covered by the fully drained repeated-CM fixture above.
    p, t = original._fixture(6, cases[0][1], roles=2)
    result = _analyze(p, original._view(p, t), floor=1, payout_floor=1, fee=1, tiny=True)
    assert result["complete"] and all(not result["rows"][0][field]["forced"]
                                      for field in ("sender", "recipient", "amount"))
    m = FlowPair(p, original._view(p, t), 1, 1, 1, tiny=True)
    baseline = m.query("cp_sat")
    row = m.proposition(2, "sender", baseline)
    assert not row["forced"]
    before = dict(m.queries)
    assert not m.proposition(2, "sender", baseline)["forced"] and m.queries == before
    assert m.z.solver.num_scopes() == 0
    return dict(passed=True, complete=True, complete_prefix_set_comparisons=prefixes,
                projected_solutions_compared=solutions,
                witnesses_checked_in_original_cp_z3_and_flow_cp_z3=witnesses,
                controls=["complete-independent-oracle-projections",
                          "nonterminal-positive-unspent-notes", "terminal-complete-consumption",
                          "zero-padding-columns", "equal-commitments-separate-columns",
                          "two-input-exit", "verified-cache-reuse-and-temporary-pins"])


def development_benchmark():
    """Same explicit eight-role ring used by the index development benchmark."""
    steps = [(1, 0, [0], [(0, 20), (None, 0)])]
    steps.extend((0, owner, [], [(owner, 20), (None, 0)]) for owner in range(1, 8))
    live, position = {owner: [] for owner in range(8)}, 17
    for owner in range(8):
        recipient = (owner + 1) % 8
        steps.append((1, owner, [1 + 2 * owner], [(recipient, 3), (owner, 16)]))
        live[recipient].append(position)
        live[owner].append(position + 1)
        position += 2
    steps.extend((2, owner, sorted(live[owner]), []) for owner in range(8))
    public, truth = original._fixture(21, steps, roles=8)
    view = original._view(public, truth, [0, 1])
    timings, sizes = {}, {}
    for name, constructor in (("boolean", original.Pair), ("flow", FlowPair)):
        model = constructor(public, view, 1, 1, 1, tiny=True)
        sizes[name] = dict(variables=len(model.cp.model.proto.variables),
                           constraints=len(model.cp.model.proto.constraints))
        started = time.monotonic()
        witness = model.query("cp_sat")
        timings[name] = time.monotonic() - started
        assert witness is not None
        for target in (original.Pair(public, view, 1, 1, 1, tiny=True),
                       FlowPair(public, view, 1, 1, 1, tiny=True)):
            cp, smt = compact.witness_conditions(target, witness)
            assert target.query("cp_sat", cp) is not None and target.query("z3", smt) is not None
    return dict(passed=True, roles=8, events=len(steps), seconds=timings, model_sizes=sizes,
                meaning="Explicit development fixture; speed does not establish privacy or general scaling")
