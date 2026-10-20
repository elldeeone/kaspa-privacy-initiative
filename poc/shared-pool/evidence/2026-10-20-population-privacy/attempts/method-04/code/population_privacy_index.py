"""Equivalent compact CP input representation, with original Z3 certification.

Equivalence to the Boolean-input model:
* A real position p is represented by p+1. Every non-ADMIT has a real first
  index a and either b=0 (absent) or a<b (a second real input). This bijects
  unordered one/two-position sets; per-event bounds exclude unborn notes.
* Element constraints select the same positive values and common owner.
  AllDifferent covers every a and each real b. An absent b gets a distinct
  sentinel strictly above ALL positions in this prefix, so it creates no
  accidental collision, owner equality, value or spending opportunity.
* The same operation equations, note domains, owner/disclosure constraints
  and commitment equalities are retained. Positions are never deduplicated.
* At terminal reserve zero, conservation/nonnegative values imply all positive
  positions were consumed. The explicit terminal count equality below is also
  entailed: unique positive selections cover exactly the positive positions.

A CP satisfying assignment is checked against the original Z3 relation with
temporary value/positive-owner/input pins. These pins are popped after checking.
An UNSAT CP negation is accepted only if unrestricted Z3 also proves that
negation UNSAT. Neither solver receives experimental truth or a private hint.
"""
import json
import time
from types import SimpleNamespace

import z3
from ortools.sat.python import cp_model

import population_privacy_model as original
from population_privacy_model import Incomplete, digest, fields, prefix, validate
from two_input_privacy_observer import FLOOR, PAYOUT_FLOOR, integer, need, reverse_bounds
from two_input_privacy_z3 import Z3Model

FEE = original.FEE


class IndexPair(original.Pair):
    def __init__(self, public, view, floor=FLOOR, payout_floor=PAYOUT_FLOOR, fee=FEE,
                 tiny=False, diagnostics=False):
        self.facts = validate(public, view, floor, payout_floor, fee, tiny)
        self.public, self.view, self.data = public, view, public["algebra"]
        upper = reverse_bounds(self.data, self.facts["births"], self.facts["upper"])
        if sum(upper) + sum(e["fee"] + e["deposit"] + e["payout"]
                            for e in self.data["events"]) >= 2**62:
            raise Incomplete("CP intermediate range unsupported")
        self.cp = SimpleNamespace(model=cp_model.CpModel(), values=[], positive=[], upper=upper)
        self.z = Z3Model(self.data, floor, payout_floor)
        self.queries = {"cp_sat": 0, "z3": 0}
        self.diagnostics = diagnostics
        self.context = dict(through_event=len(self.data["events"]) - 1)
        self.indices, self.validated_witnesses, self.cp_witnesses = {}, {}, {}
        self._build_index(floor)
        # Keep the independently encoded original ownership/arithmetic model.
        self._z3_owners(floor)

    def _build_index(self, floor):
        m, events = self.cp.model, self.data["events"]
        n, count = len(self.public["roles"]), len(self.cp.upper)
        for p, upper in enumerate(self.cp.upper):
            value = m.new_int_var(0, upper, f"v{p}")
            positive = m.new_bool_var(f"positive{p}")
            m.add(value == 0).only_enforce_if(positive.Not())
            m.add(value >= floor).only_enforce_if(positive)
            self.cp.values.append(value)
            self.cp.positive.append(positive)
        self.cp_owners = [m.new_int_var(0, n - 1, f"owner{p}") for p in range(count)]
        self.cp_senders = [m.new_int_var(0, n - 1, f"sender{i}") for i in range(len(events))]
        founder = self.public["funding_owners"][self.data["initial"]["funding_group"]]
        m.add(self.cp.values[0] == self.data["initial"]["value"])
        m.add(self.cp_owners[0] == founder)
        distinct, second_inputs = [], []
        for i, e in enumerate(events):
            sender = self.cp_senders[i]
            output = sum(self.cp.values[p] for p in e["new"])
            if e["mode"] == 0:
                a, b = e["new"]
                m.add(output == e["deposit"] - e["fee"])
                m.add(self.cp.values[a] >= floor)
                m.add(self.cp.values[b] == 0)
                m.add(sender == self.public["funding_owners"][e["funding_group"]])
                m.add(self.cp_owners[a] == sender)
            else:
                anchor = e["anchor_count"]
                a = m.new_int_var(1, anchor, f"first{i}")
                b = m.new_int_var(0, anchor, f"second{i}")
                used = m.new_bool_var(f"second_used{i}")
                m.add(b == 0).only_enforce_if(used.Not())
                m.add(b > a).only_enforce_if(used)
                a_value = m.new_int_var(0, max(self.cp.upper[:anchor]), f"first_value{i}")
                b_value = m.new_int_var(0, max(self.cp.upper[:anchor]), f"second_value{i}")
                a_owner = m.new_int_var(0, n - 1, f"first_owner{i}")
                b_owner = m.new_int_var(0, n - 1, f"second_owner{i}")
                m.add_element(a, [0] + self.cp.values[:anchor], a_value)
                m.add_element(b, [0] + self.cp.values[:anchor], b_value)
                m.add_element(a, [0] + self.cp_owners[:anchor], a_owner)
                m.add_element(b, [0] + self.cp_owners[:anchor], b_owner)
                m.add(a_value >= floor)
                m.add(b_value >= floor).only_enforce_if(used)
                m.add(a_owner == sender)
                m.add(b_owner == sender).only_enforce_if(used)
                m.add(a_value + b_value == output + e["payout"] + e["fee"])
                code = m.new_int_var(1, count + len(events), f"second_unique{i}")
                m.add(code == b).only_enforce_if(used)
                m.add(code == count + i + 1).only_enforce_if(used.Not())
                distinct.extend([a, code])
                second_inputs.append(used)
                self.indices[i] = (a, b, used)
                if e["mode"] == 1:
                    first, change = e["new"]
                    m.add(self.cp.values[first] >= floor)
                    m.add(self.cp_owners[change] == sender).only_enforce_if(self.cp.positive[change])
            if e["destination"] in self.public.get("payout_owners", {}):
                m.add(sender == self.public["payout_owners"][e["destination"]])
        m.add_all_different(distinct)
        if events[-1]["reserve_out"] == 0:
            m.add(sum(self.cp.positive) == len(self.indices) + sum(second_inputs))
        first, padding = events[0]["new"]
        m.add(self.cp.values[padding] == 0)
        m.add(self.cp_owners[first] == founder)
        for p, owner in enumerate(self.cp_owners):
            receipt = self.facts["receipts"].get(p)
            if receipt is not None:
                m.add(owner == receipt["owner"])
                m.add(self.cp.values[p] == receipt["value"])
            else:
                for member in self.view["members"]:
                    m.add(owner != member).only_enforce_if(self.cp.positive[p])
        for i, sender in enumerate(self.cp_senders):
            row = self.facts["authors"].get(i)
            if row is None:
                for member in self.view["members"]:
                    m.add(sender != member)
                continue
            m.add(sender == row["owner"])
            if i in self.indices:
                a, b, _ = self.indices[i]
                m.add(a == row["inputs"][0] + 1)
                m.add(b == (row["inputs"][1] + 1 if len(row["inputs"]) == 2 else 0))
            for output in row["outputs"]:
                p = output["position"]
                m.add(self.cp.values[p] == output["value"])
                if output["value"]:
                    m.add(self.cp_owners[p] == output["recipient"])
        seen = {}
        for p, cm in enumerate(self.public["commitments"]):
            if cm in seen:
                q = seen[cm]
                m.add(self.cp.values[p] == self.cp.values[q])
                m.add(self.cp_owners[p] == self.cp_owners[q])
            seen[cm] = p

    def query(self, engine, conditions=(), kind="feasibility"):
        if engine != "cp_sat":
            return super().query(engine, conditions, kind)
        self.queries[engine] += 1
        started = time.monotonic()
        self.progress(engine=engine, kind=kind, event="query_start")
        model, solver = self.cp.model.clone(), cp_model.CpSolver()
        for condition in conditions:
            model.add(condition)
        solver.parameters.num_search_workers = 8
        solver.parameters.random_seed = 0
        status = solver.solve(model)
        label = solver.status_name(status)
        self.progress(engine=engine, kind=kind, event="query_end", status=label,
                      elapsed_seconds=time.monotonic() - started)
        if status == cp_model.INFEASIBLE:
            return None
        if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            raise Incomplete("CP-SAT unknown/nonconclusive: " + label)
        values = [solver.value(v) for v in self.cp.values]
        return dict(values=values,
                    owners=[solver.value(o) if v else None for o, v in zip(self.cp_owners, values)],
                    inputs={str(i): [solver.value(a) - 1] + (
                        [solver.value(b) - 1] if solver.value(used) else [])
                            for i, (a, b, used) in self.indices.items()},
                    senders={str(i): solver.value(v) for i, v in enumerate(self.cp_senders)})

    def smt_witness(self, witness):
        """Check a whole hypothetical CP assignment; all pins are temporary."""
        identity = digest(witness)
        if identity not in self.validated_witnesses:
            _, conditions = witness_conditions(self, witness)
            result = self.query("z3", conditions, "fixed_witness")
            if result is None:
                raise Incomplete("CP witness rejected by original Z3 relation")
            self.validated_witnesses[identity] = result
            self.cp_witnesses[identity] = witness
        return self.validated_witnesses[identity]

    def proposition(self, event, field, baseline):
        cp, smt = self.variables(event, field)
        candidate = self.field_value(baseline, event, field)
        self.context.update(target_event=event, field=field)
        verified = self.smt_witness(baseline)
        if self.field_value(verified, event, field) != candidate:
            raise Incomplete("candidate field differs in CP/Z3 witness handoff")
        # A complete assignment already checked by both engines is an exact SAT
        # certificate for every proposition it satisfies in this SAME prefix.
        # No witness or negative answer crosses a Pair/prefix boundary.
        other, alternative = None, None
        for identity, previous in self.cp_witnesses.items():
            checked = self.validated_witnesses[identity]
            previous_value = self.field_value(previous, event, field)
            if self.field_value(checked, event, field) != previous_value:
                raise Incomplete("cached CP/Z3 field disagreement")
            if previous_value != candidate:
                other, alternative = previous, checked
                break
        if other is None:
            other = self.query("cp_sat", [cp != candidate], "different")
        if other is not None:
            if alternative is None:
                alternative = self.smt_witness(other)
            other_value = self.field_value(other, event, field)
            if (other_value == candidate or
                    self.field_value(alternative, event, field) != other_value):
                raise Incomplete("alternative field differs in CP/Z3 witness handoff")
        else:
            # smt_witness used push/pop. This query is unrestricted apart from
            # the proposition's negation, never conditioned on a CP input graph.
            alternative = self.query("z3", [smt != candidate], "unrestricted_different")
            if alternative is not None:
                raise Incomplete("CP UNSAT disagrees with unrestricted Z3")
        return dict(forced=other is None, candidate=candidate,
                    certificates={engine: dict(candidate="SAT", different="UNSAT" if other is None else "SAT")
                                  for engine in ("cp_sat", "z3")},
                    hypothetical_witnesses=dict(cp_sat_candidate=baseline, z3_candidate=verified,
                                                cp_sat_alternative=other, z3_alternative=alternative))

    def field_value(self, witness, event, field):
        if field == "sender":
            return witness["senders"][str(event)]
        position = self.data["events"][event]["new"][0]
        return witness["owners" if field == "recipient" else "values"][position]


def witness_conditions(model, witness):
    """Pins values, positive owners and complete real-input sets in either CP form."""
    need(isinstance(witness, dict) and {"values", "owners", "inputs"} <= set(witness), "witness core")
    values, owners, inputs = witness["values"], witness["owners"], witness["inputs"]
    need(isinstance(values, list) and isinstance(owners, list)
         and len(values) == len(owners) == len(model.cp.values), "witness note vectors")
    real_events = set(model.z.select)
    need(isinstance(inputs, dict) and set(inputs) in (
        {str(i) for i in real_events}, {str(i) for i in range(len(model.data["events"]))}),
        "witness input events")
    cp, smt = [], []
    for p, (value, owner) in enumerate(zip(values, owners)):
        integer(value)
        need(owner is None if value == 0 else type(owner) is int and owner in model.public["roles"],
             "witness owner")
        cp.append(model.cp.values[p] == value)
        smt.append(model.z.values[p] == value)
        if value:
            cp.append(model.cp_owners[p] == owner)
            smt.append(model.z_owners[p] == owner)
    for key, positions in inputs.items():
        i = int(key)
        if i not in real_events:
            need(positions == [], "admission witness inputs")
            continue
        need(isinstance(positions, list) and all(type(p) is int for p in positions)
             and positions == sorted(set(positions)) and 1 <= len(positions) <= 2
             and all(0 <= p < model.data["events"][i]["anchor_count"] for p in positions),
             "witness real positions")
        if isinstance(model, IndexPair):
            a, b, _ = model.indices[i]
            cp.extend([a == positions[0] + 1, b == (positions[1] + 1 if len(positions) == 2 else 0)])
        else:
            cp.extend(selected == int(p in positions) for p, selected in enumerate(model.cp.select[i]))
        smt.extend(selected == (p in positions) for p, selected in enumerate(model.z.select[i]))
    return cp, smt


def _analyze(public, view, targets=None, floor=FLOOR, payout_floor=PAYOUT_FLOOR, fee=FEE,
             tiny=False, diagnostics=False):
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
            model = IndexPair(p, v, floor, payout_floor, fee, tiny, diagnostics)
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
                encoding="sorted-real-input-indices-with-unique-absent-sentinels",
                meaning="Conditional exact propositions; witnesses are hypothetical assignments, not recovered truth or probabilities",
                assumptions=[
                    "Same owner/value feasible relation as the original population model.",
                    "Complete disclosed records, closed role universe and current-wallet rules.",
                    "Cryptographic identifiers otherwise hide linkage; cryptography is not tested."],
                relaxations=["Automatic coin selection, payment distribution, timing/scheduling and admission-time recipient restrictions are not enforced."])


def analyze(public, view, targets=None):
    return _analyze(public, view, targets, diagnostics=True)


def validate_truth(public, view, truth):
    """Scorer-only; fixed truth is never used by analyze."""
    model = IndexPair(public, view)
    cp, smt = witness_conditions(model, truth)
    answers = [model.query("cp_sat", cp), model.query("z3", smt)]
    return dict(complete=True, cp_sat="SAT" if answers[0] is not None else "UNSAT",
                z3="SAT" if answers[1] is not None else "UNSAT")


def _witness(state):
    notes, _, history, senders = state
    return dict(values=[v for v, _ in notes], owners=[o for _, o in notes],
                inputs={str(i): list(positions) for i, positions in enumerate(history)},
                senders={str(i): sender for i, sender in enumerate(senders)})


def _complete_index_set(model):
    """Enumerate every tiny projected model, ignoring latent owners of padding."""
    remaining, states = model.cp.model.clone(), set()
    while True:
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 8
        solver.parameters.random_seed = 0
        status = solver.solve(remaining)
        if status == cp_model.INFEASIBLE:
            return states
        assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
        values = tuple(solver.value(x) for x in model.cp.values)
        owners = tuple(solver.value(o) if v else None for o, v in zip(model.cp_owners, values))
        inputs = tuple((i, tuple([solver.value(a) - 1] + (
            [solver.value(b) - 1] if solver.value(used) else [])))
                       for i, (a, b, used) in model.indices.items())
        state = (values, owners, inputs)
        assert state not in states
        states.add(state)
        # Exclude this complete projected assignment, not a hidden padding-owner
        # variant of it. Each inequality literal is equivalently reified.
        variables = list(model.cp.values) + [
            o for o, value in zip(model.cp_owners, values) if value] + [
                x for a, b, _ in model.indices.values() for x in (a, b)]
        different = []
        for index, variable in enumerate(variables):
            literal = remaining.new_bool_var(f"projection_{len(states)}_{index}")
            value = solver.value(variable)
            remaining.add(variable != value).only_enforce_if(literal)
            remaining.add(variable == value).only_enforce_if(literal.Not())
            different.append(literal)
        remaining.add_bool_or(different)


def controls():
    """Complete tiny projected-set comparisons; no held-out files are read."""
    cases = [
        (6, [(1, 0, [0], [(0, 5), (None, 0)]),
             (0, 1, [], [(1, 5), (None, 0)]),
             (1, 0, [1], [(1, 2), (0, 2)])], 2, 1, []),
        (7, [(1, 0, [0], [(0, 6), (None, 0)]),
             (0, 1, [], [(1, 3), (None, 0)]),
             (1, 0, [1], [(1, 2), (0, 3)]),
             (2, 1, [3, 5], [])], 2, 1, [1]),
        (7, [(1, 0, [0], [(0, 6), (None, 0)]),
             (0, 1, [], [(1, 2), (None, 0)]),
             (1, 0, [1], [(1, 2), (0, 3)]),
             (2, 1, [3, 5], [])], 2, 2, []),
        (6, [(1, 0, [0], [(0, 5), (None, 0)]),
             (0, 1, [], [(1, 7), (None, 0)]),
             (0, 2, [], [(2, 1), (None, 0)]),
             (1, 0, [1], [(2, 2), (0, 2)])], 3, 1, [2]),
    ]
    comparisons, witnessed, count = 0, 0, 0
    for initial, steps, roles, floor, members in cases:
        public, truth = original._fixture(initial, steps, roles, floor)
        view = original._view(public, truth, members)
        for end in range(len(steps)):
            p, v = prefix(public, view, end)
            oracle = original._enumerate(p, v, floor)
            expected = {
                (tuple(value for value, _ in s[0]), tuple(owner for _, owner in s[0]),
                 tuple((i, positions) for i, positions in enumerate(s[2])
                       if p["algebra"]["events"][i]["mode"] != 0)) for s in oracle}
            compact = IndexPair(p, v, floor, 1, 1, tiny=True)
            actual = _complete_index_set(compact)
            assert actual == expected, (end, len(actual), len(expected))
            comparisons += len(actual)
            reference = original.Pair(p, v, floor, 1, 1, tiny=True)
            for state in oracle:
                witness = _witness(state)
                for model in (compact, reference):
                    cp, smt = witness_conditions(model, witness)
                    assert model.query("cp_sat", cp) is not None
                    assert model.query("z3", smt) is not None
                witnessed += 1
            count += 1
    # Terminal, duplicate-CM, zero/dummy and sentinel-through-future-admission.
    p, t = original._fixture(8, [(1, 0, [0], [(0, 7), (None, 0)]),
                                 (0, 1, [], [(1, 3), (None, 0)]),
                                 (1, 0, [1], [(1, 3), (0, 3)]),
                                 (2, 1, [3], []), (2, 1, [5], []),
                                 (2, 0, [6], [])], roles=2)
    p["commitments"][5] = p["commitments"][3]
    v = original._view(p, t, [0, 1])
    m = IndexPair(p, v, 1, 1, 1, tiny=True)
    witness = m.query("cp_sat")
    assert witness is not None and witness["inputs"]["0"] == [0]
    assert m.smt_witness(witness) is not None
    assert m.query("cp_sat", [m.indices[3][0] == 3]) is None  # position2 is zero padding.
    assert m.query("cp_sat", [m.indices[3][0] == m.indices[4][0]]) is None
    assert len(_complete_index_set(m)) == 1
    # A nonzero sender using one input must not inherit dummy owner's zero.
    assert witness["senders"]["3"] == 1 and witness["inputs"]["3"] == [3]
    result = _analyze(p, v, floor=1, payout_floor=1, fee=1, tiny=True)
    assert result["complete"] and all(result["rows"][0][field]["forced"]
                                      for field in ("sender", "recipient", "amount"))
    # Ambiguity must survive cached SAT-witness pins; negations stay unrestricted.
    p, t = original._fixture(6, cases[0][1], roles=2)
    result = _analyze(p, original._view(p, t), floor=1, payout_floor=1, fee=1, tiny=True)
    assert result["complete"] and all(not result["rows"][0][field]["forced"]
                                      for field in ("sender", "recipient", "amount"))
    m = IndexPair(p, original._view(p, t), 1, 1, 1, tiny=True)
    witness = m.query("cp_sat")
    assert m.z.solver.num_scopes() == 0
    m.smt_witness(witness)
    assert m.z.solver.num_scopes() == 0
    candidate = m.field_value(witness, 2, "sender")
    assert m.query("z3", [m.z_senders[2] != candidate]) is not None
    # Deliberately simulate a leaked witness scope. CP still finds an alternative
    # and the handoff must reject it, never certify a spurious forced result.
    _, pins = witness_conditions(m, witness)
    m.z.solver.push()
    m.z.solver.add(*pins)
    try:
        try:
            m.proposition(2, "sender", witness)
        except Incomplete:
            pass
        else:
            raise AssertionError("persistent witness pins escaped detection")
    finally:
        m.z.solver.pop()
    # A cached alternative saves both queries, but cannot turn a separately
    # forced amount into ambiguity. This is a recipient-only disclosure.
    initial, steps, roles, floor, members = cases[3]
    p, t = original._fixture(initial, steps, roles, floor)
    m = IndexPair(p, original._view(p, t, members), floor, 1, 1, tiny=True)
    witness = m.query("cp_sat")
    sender = m.proposition(3, "sender", witness)
    assert not sender["forced"]
    queries = dict(m.queries)
    again = m.proposition(3, "sender", witness)
    assert not again["forced"] and m.queries == queries
    amount = m.proposition(3, "amount", witness)
    assert amount["forced"] and amount["candidate"] == 2
    return dict(passed=True, complete=True, complete_prefix_set_comparisons=count,
                projected_solutions_compared=comparisons,
                full_witnesses_checked_in_original_cp_z3_and_index_cp_z3=witnessed,
                controls=["complete-independent-oracle-projections", "all-fixed-witnesses-in-both-encodings",
                          "original-position-zero", "zero-padding-not-spendable",
                          "two-input-exit", "single-input-nonzero-owner",
                          "distinct-dummies-through-later-admissions",
                          "distinct-spends-of-equal-commitments", "terminal-complete-consumption",
                          "temporary-SAT-pins-do-not-constrain-negation",
                          "deliberately-leaked-witness-pins-rejected",
                          "same-prefix-witness-cache-saves-queries-without-hiding-forced-amount"])


def development_benchmark():
    """One explicit eight-role ring, never a held-out seed or private hint."""
    steps = [(1, 0, [0], [(0, 20), (None, 0)])]
    steps.extend((0, owner, [], [(owner, 20), (None, 0)]) for owner in range(1, 8))
    live = {owner: [] for owner in range(8)}
    position = 17
    for owner in range(8):
        recipient = (owner + 1) % 8
        steps.append((1, owner, [1 + 2 * owner], [(recipient, 3), (owner, 16)]))
        live[recipient].append(position)
        live[owner].append(position + 1)
        position += 2
    for owner in range(8):
        steps.append((2, owner, sorted(live[owner]), []))
    public, truth = original._fixture(21, steps, roles=8)
    view = original._view(public, truth, [0, 1])
    timings, sizes = {}, {}
    for name, constructor in (("boolean", original.Pair), ("index", IndexPair)):
        model = constructor(public, view, 1, 1, 1, tiny=True)
        sizes[name] = dict(variables=len(model.cp.model.proto.variables),
                           constraints=len(model.cp.model.proto.constraints))
        started = time.monotonic()
        witness = model.query("cp_sat")
        timings[name] = time.monotonic() - started
        assert witness is not None
        # The returned public-model assignment is checked in both CP forms and
        # original Z3; the fixture's intended truth is never a search hint.
        for target in (original.Pair(public, view, 1, 1, 1, tiny=True),
                       IndexPair(public, view, 1, 1, 1, tiny=True)):
            cp, smt = witness_conditions(target, witness)
            assert target.query("cp_sat", cp) is not None and target.query("z3", smt) is not None
    return dict(passed=True, roles=8, events=len(steps), seconds=timings, model_sizes=sizes,
                meaning="Explicit development fixture; speed does not establish privacy or general scaling")
