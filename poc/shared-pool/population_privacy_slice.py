"""A sound, deliberately incomplete relaxation of the frozen population model.

For each target retain the original prefix and every value/owner variable.
Keep all public/participant facts and wallet output rules, but input equations
only for bootstrap, disclosed authors, the target, and its first three later
DRAINs. Omit other hidden input equations and global terminal coverage.
Every full-model solution restricts to a slice solution: retained equations are
unchanged, single-use is weakened, and forward bounds already hold in the full
model. Thus dual SAT(claim)/UNSAT(not claim) proves a conditional forced fact.
Slice alternatives may be impossible full histories and are only inconclusive.

Public hypothetical CP witnesses are checked with temporary pins in the slice's
independent Z3 encoding. Checked SAT witnesses are cached only inside that exact
Slice instance. A forced claim still requires an unrestricted Z3 negation check;
neither witness pins nor caches cross targets or prefixes.

No files, private truth or held-out data are read here. controls() uses explicit
tiny fixtures and exhaustive full-ledger witnesses, never generated workloads.
"""
import copy
from types import SimpleNamespace

import z3
from ortools.sat.python import cp_model

import population_privacy_model as full
import population_privacy_index as compact

FLOOR, PAYOUT_FLOOR, FEE = full.FLOOR, full.PAYOUT_FLOOR, full.FEE
need, integer, fields = full.need, full.integer, full.fields


class Slice(full.Pair):
    """Independent CP-SAT/Z3 encodings; reuse only framing and query machinery."""
    # The reviewed adapter uses this class's Boolean select maps. It validates
    # assignments against our SLICE Z3 encoding, not the omitted full relation.
    smt_witness = compact.IndexPair.smt_witness
    field_value = compact.IndexPair.field_value

    def __init__(self, public, view, target, floor=FLOOR, payout_floor=PAYOUT_FLOOR,
                 fee=FEE, tiny=False, diagnostics=False):
        self.facts = full.validate(public, view, floor, payout_floor, fee, tiny)
        self.public, self.view = public, view
        self.target = target
        self.data = public["algebra"]
        events = self.data["events"]
        if target is not None:
            integer(target, 1, len(events) - 1)
            need(events[target]["mode"] == 1, "slice target must be ordinary SPEND")
        drains = [] if target is None else [
            i for i, event in enumerate(events) if i > target and event["mode"] == 2][:3]
        self.retained = {0} | set(self.facts["authors"]) | set(drains)
        if target is not None:
            self.retained.add(target)
        self.omitted = [i for i, e in enumerate(events)
                        if e["mode"] != 0 and i not in self.retained]
        self.queries = {"cp_sat": 0, "z3": 0}
        self.validated_witnesses, self.cp_witnesses = {}, {}
        self.diagnostics = diagnostics
        self.context = dict(through_event=len(events) - 1, target_event=target,
                            scope="local-constraint-relaxation")
        upper = self.facts["upper"]  # Forward public bounds, no future reverse cuts.
        need(sum(upper) + sum(e["fee"] + e["payout"] + e["deposit"] for e in events)
             < 2**62, "slice CP integer intermediate range unsupported")
        self._cp(upper, floor)
        self._smt(upper, floor)

    def _cp(self, upper, floor):
        m = cp_model.CpModel()
        n = len(self.public["roles"])
        values = [m.new_int_var(0, bound, f"v{p}") for p, bound in enumerate(upper)]
        positive = [m.new_bool_var(f"positive{p}") for p in range(len(values))]
        owners = [m.new_int_var(0, n - 1, f"owner{p}") for p in range(len(values))]
        senders = [m.new_int_var(0, n - 1, f"sender{i}")
                   for i in range(len(self.data["events"]))]
        select, uses = {}, [[] for _ in values]
        founder = self.public["funding_owners"][self.data["initial"]["funding_group"]]
        m.add(values[0] == self.data["initial"]["value"])
        m.add(owners[0] == founder)
        for p, value in enumerate(values):
            m.add(value == 0).only_enforce_if(positive[p].Not())
            m.add(value >= floor).only_enforce_if(positive[p])
        for i, e in enumerate(self.data["events"]):
            if e["mode"] == 0:
                a, b = e["new"]
                owner = self.public["funding_owners"][e["funding_group"]]
                m.add(senders[i] == owner)
                m.add(owners[a] == owner)
                m.add(values[a] == e["deposit"] - e["fee"])
                m.add(values[a] >= floor)
                m.add(values[b] == 0)
            elif e["mode"] == 1:
                a, b = e["new"]
                m.add(values[a] >= floor)
                m.add(owners[b] == senders[i]).only_enforce_if(positive[b])
            if e["destination"] in self.public.get("payout_owners", {}):
                m.add(senders[i] == self.public["payout_owners"][e["destination"]])
            if e["mode"] == 0 or i not in self.retained:
                continue
            selectors, picked = [], []
            for p in range(e["anchor_count"]):
                selected = m.new_bool_var(f"s{i}_{p}")
                selectors.append(selected)
                uses[p].append(selected)
                m.add_implication(selected, positive[p])
                m.add(owners[p] == senders[i]).only_enforce_if(selected)
                value = m.new_int_var(0, upper[p], f"picked{i}_{p}")
                m.add(value == values[p]).only_enforce_if(selected)
                m.add(value == 0).only_enforce_if(selected.Not())
                picked.append(value)
            m.add(sum(selectors) >= 1)
            m.add(sum(selectors) <= 2)
            m.add(sum(picked) == sum(values[p] for p in e["new"]) + e["payout"] + e["fee"])
            select[i] = selectors
        for choices in uses:
            m.add(sum(choices) <= 1)
        a, b = self.data["events"][0]["new"]
        m.add(owners[a] == founder)
        m.add(values[b] == 0)
        for p, owner in enumerate(owners):
            receipt = self.facts["receipts"].get(p)
            if receipt is not None:
                m.add(owner == receipt["owner"])
                m.add(values[p] == receipt["value"])
            else:
                for member in self.view["members"]:
                    m.add(owner != member).only_enforce_if(positive[p])
        for i, sender in enumerate(senders):
            authored = self.facts["authors"].get(i)
            if authored is None:
                for member in self.view["members"]:
                    m.add(sender != member)
            else:
                m.add(sender == authored["owner"])
                for p, selected in enumerate(select.get(i, [])):
                    m.add(selected == int(p in authored["inputs"]))
                for output in authored["outputs"]:
                    p = output["position"]
                    m.add(values[p] == output["value"])
                    if output["value"]:
                        m.add(owners[p] == output["recipient"])
        seen = {}
        for p, cm in enumerate(self.public["commitments"]):
            if cm in seen:
                q = seen[cm]
                m.add(values[p] == values[q])
                m.add(owners[p] == owners[q])
            seen[cm] = p
        self.cp = SimpleNamespace(model=m, values=values, positive=positive, select=select)
        self.cp_owners, self.cp_senders = owners, senders

    def _smt(self, upper, floor):
        solver = z3.Solver()
        values = [z3.Int(f"v{p}") for p in range(len(upper))]
        owners = [z3.Int(f"owner{p}") for p in range(len(upper))]
        senders = [z3.Int(f"sender{i}") for i in range(len(self.data["events"]))]
        select, uses = {}, [[] for _ in values]
        for variable in owners + senders:
            solver.add(variable >= 0, variable < len(self.public["roles"]))
        for value, bound in zip(values, upper, strict=True):
            solver.add(value <= bound, z3.Or(value == 0, value >= floor))
        founder = self.public["funding_owners"][self.data["initial"]["funding_group"]]
        solver.add(values[0] == self.data["initial"]["value"], owners[0] == founder)
        for i, e in enumerate(self.data["events"]):
            if e["mode"] == 0:
                a, b = e["new"]
                owner = self.public["funding_owners"][e["funding_group"]]
                solver.add(senders[i] == owner, owners[a] == owner,
                           values[a] == e["deposit"] - e["fee"],
                           values[a] >= floor, values[b] == 0)
            elif e["mode"] == 1:
                a, b = e["new"]
                solver.add(values[a] >= floor,
                           z3.Implies(values[b] > 0, owners[b] == senders[i]))
            if e["destination"] in self.public.get("payout_owners", {}):
                solver.add(senders[i] == self.public["payout_owners"][e["destination"]])
            if e["mode"] == 0 or i not in self.retained:
                continue
            selectors = [z3.Bool(f"s{i}_{p}") for p in range(e["anchor_count"])]
            select[i] = selectors
            solver.add(z3.PbGe([(x, 1) for x in selectors], 1),
                       z3.PbLe([(x, 1) for x in selectors], 2))
            for p, selected in enumerate(selectors):
                uses[p].append(selected)
                solver.add(z3.Implies(selected, values[p] >= floor),
                           z3.Implies(selected, owners[p] == senders[i]))
            solver.add(z3.Sum([z3.If(x, values[p], 0) for p, x in enumerate(selectors)]) ==
                       z3.Sum([values[p] for p in e["new"]]) + e["payout"] + e["fee"])
        for choices in uses:
            if choices:
                solver.add(z3.PbLe([(x, 1) for x in choices], 1))
        a, b = self.data["events"][0]["new"]
        solver.add(owners[a] == founder, values[b] == 0)
        for p, owner in enumerate(owners):
            receipt = self.facts["receipts"].get(p)
            if receipt is not None:
                solver.add(owner == receipt["owner"], values[p] == receipt["value"])
            else:
                solver.add(*[z3.Implies(values[p] > 0, owner != member)
                             for member in self.view["members"]])
        for i, sender in enumerate(senders):
            authored = self.facts["authors"].get(i)
            if authored is None:
                solver.add(*[sender != member for member in self.view["members"]])
            else:
                solver.add(sender == authored["owner"])
                solver.add(*[selected == (p in authored["inputs"])
                             for p, selected in enumerate(select.get(i, []))])
                for output in authored["outputs"]:
                    p = output["position"]
                    solver.add(values[p] == output["value"])
                    if output["value"]:
                        solver.add(owners[p] == output["recipient"])
        for p, cm in enumerate(self.public["commitments"]):
            for q in range(p):
                if self.public["commitments"][q] == cm:
                    solver.add(values[p] == values[q], owners[p] == owners[q])
                    break
        self.z = SimpleNamespace(solver=solver, values=values, select=select)
        self.z_owners, self.z_senders = owners, senders

    def proposition(self, event, field, baseline):
        need(event == self.target, "proposition differs from slice target")
        result = compact.IndexPair.proposition(self, event, field, baseline)
        result["interpretation"] = ("forced in the slice, hence in the full model"
                                    if result["forced"] else "slice inconclusive")
        result["witness_scope"] = "slice assignments; not necessarily valid full histories"
        return result


def _analyze(public, view, targets=None, floor=FLOOR, payout_floor=PAYOUT_FLOOR,
             fee=FEE, tiny=False, diagnostics=False):
    full.validate(public, view, floor, payout_floor, fee, tiny)
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
    model, rows, error = None, [], None
    queries = {"cp_sat": 0, "z3": 0}
    try:
        work = targets or [dict(event=None, through_event=len(events) - 1)]
        for target in work:
            # Certificates contain plain assignments, not solver objects. Release
            # each target's model/cache before constructing the next one.
            if model is not None:
                for engine in queries:
                    queries[engine] += model.queries[engine]
                model = None
            i, end = target["event"], target["through_event"]
            p, v = full.prefix(public, view, end)
            model = Slice(p, v, i, floor, payout_floor, fee, tiny, diagnostics)
            baseline = model.query("cp_sat")
            if baseline is None:
                if model.query("z3", kind="unrestricted_inconsistency_check") is not None:
                    raise full.Incomplete("slice CP UNSAT disagrees with unrestricted Z3")
                raise full.Incomplete("slice inconsistent; no disclosure/privacy conclusion")
            model.smt_witness(baseline)
            if i is None:
                continue
            row = dict(event=i, through_event=end,
                       retained_input_events=sorted(model.cp.select),
                       omitted_hidden_input_events=model.omitted)
            for field in ("sender", "recipient", "amount"):
                row[field] = model.proposition(i, field, baseline)
            row["relationship_forced"] = row["sender"]["forced"] and row["recipient"]["forced"]
            rows.append(row)
    except full.Incomplete as failure:
        error = str(failure)
    finally:
        if model is not None:
            for engine in queries:
                queries[engine] += model.queries[engine]
    return dict(
        schema="kpi-population-predictions-v1", complete=error is None, error=error,
        rows=rows, requested_targets=targets,
        queries=queries,
        public_sha256=full.digest(public), view_sha256=full.digest(view),
        scope="local constraint relaxation of the original full prefix; no deleted-event ledger",
        meaning="Forced facts are conditional exact deductions; alternatives are slice inconclusive",
        assumptions=[
            "Original public/participant validation, common input ownership and change order.",
            "Complete participant disclosures and commitment value/owner binding.",
            "Opaque identifiers hide other linkage; no cryptographic security claim."],
        relaxations=[
            "Input equations only for bootstrap, disclosed authors, target and first three later DRAINs.",
            "Other hidden input equations/selectors and global terminal coverage are omitted.",
            "Single-use is enforced only among retained input events.",
            "All original value/owner variables, forward public bounds and output rules are retained.",
            "Automatic coin selection, timing, distributions and admission-time recipients remain unmodeled.",
            "Slice witnesses may be impossible full histories; ambiguity is not evidence of privacy."])


def analyze(public, view, targets=None):
    return _analyze(public, view, targets, diagnostics=True)


def _pin_state(model, state):
    notes, _, inputs, senders = state
    cp, smt = [], []
    for p, (value, owner) in enumerate(notes):
        cp.append(model.cp.values[p] == value)
        smt.append(model.z.values[p] == value)
        if value:
            cp.append(model.cp_owners[p] == owner)
            smt.append(model.z_owners[p] == owner)
    for i, sender in enumerate(senders):
        cp.append(model.cp_senders[i] == sender)
        smt.append(model.z_senders[i] == sender)
    for i, selectors in model.cp.select.items():
        cp.extend(x == int(p in inputs[i]) for p, x in enumerate(selectors))
        smt.extend(x == (p in inputs[i]) for p, x in enumerate(model.z.select[i]))
    return cp, smt


def controls():
    """Check the implication full -> slice with an independent exhaustive walk."""
    tests, witness_checks, proposition_checks = [], 0, 0

    def check(name, public, truth, target, members=()):
        nonlocal witness_checks, proposition_checks
        view = full._view(public, truth, members)
        states = full._enumerate(public, view)
        need(bool(states), "empty exhaustive control")
        model = Slice(public, view, target, 1, 1, 1, tiny=True)
        for state in states:
            cp, smt = _pin_state(model, state)
            need(model.query("cp_sat", cp) is not None and model.query("z3", smt) is not None,
                 "full witness excluded by slice")
            witness_checks += 1
        baseline = model.query("cp_sat")
        need(baseline is not None and model.query("z3") is not None, "control slice infeasible")
        first = public["algebra"]["events"][target]["new"][0]
        for field in ("sender", "recipient", "amount"):
            expected = {s[3][target] if field == "sender" else
                        s[0][first][1 if field == "recipient" else 0] for s in states}
            result = model.proposition(target, field, baseline)
            if result["forced"]:
                need(expected == {result["candidate"]}, "slice forced fact contradicts full enumeration")
            else:
                need(result["interpretation"] == "slice inconclusive", "ambiguity overstated")
            proposition_checks += 1
        tests.append(name)
        return model, states, view

    p, t = full._fixture(6, [
        (1, 0, [0], [(0, 5), (None, 0)]),
        (0, 1, [], [(1, 7), (None, 0)]),
        (0, 2, [], [(2, 1), (None, 0)]),
        (1, 0, [1], [(2, 2), (0, 2)])])
    check("recipient-only-full-witness-containment", p, t, 3, [2])
    check("public-only-full-witness-containment", p, t, 3)
    check("complete-pooled-forced-facts", p, t, 3, [0, 1, 2])

    p, t = full._fixture(7, [
        (1, 0, [0], [(0, 6), (None, 0)]),
        (0, 1, [], [(1, 2), (None, 0)]),
        (1, 0, [1], [(1, 2), (0, 3)]),
        (2, 1, [3, 5], [])])
    p["commitments"][5] = p["commitments"][3]
    model, _, view = check("equal-commitments-distinct-two-input-exit", p, t, 2, [1])
    need(model.query("cp_sat", [sum(model.cp.select[3]) == 1]) is None and
         model.query("z3", [z3.PbEq([(x, 1) for x in model.z.select[3]], 1)]) is None,
         "two-input exit weakened to one")
    unshared = Slice(p, full._view(p, t), 2, 1, 1, 1, tiny=True)
    need(unshared.query("cp_sat", [unshared.cp.select[2][0] == 1]) is None and
         unshared.query("z3", [unshared.z.select[2][0]]) is None,
         "retained bootstrap input spent twice")
    need(unshared.query("cp_sat", [unshared.cp.select[2][1] == 1,
                                  unshared.cp.values[6] == 3,
                                  unshared.cp_owners[6] == 1]) is None and
         unshared.query("z3", [unshared.z.select[2][1], unshared.z.values[6] == 3,
                              unshared.z_owners[6] == 1]) is None,
         "retained sender change owner changed")
    tests.append("retained-single-use-and-positive-change-owner")
    pp, vv = full.prefix(p, view, 2)
    early = Slice(pp, vv, 2, 1, 1, 1, tiny=True)
    need(3 not in early.retained and len(early.cp.values) == 7, "future prefix equation leaked")
    tests.append("prefix-before-cashout-does-not-retain-future-inputs")

    p, t = full._fixture(6, [
        (1, 0, [0], [(0, 5), (None, 0)]),
        (0, 1, [], [(1, 10), (None, 0)]),
        (1, 0, [1], [(0, 2), (0, 2)]),
        (1, 0, [5, 6], [(0, 3), (None, 0)]),
        (2, 0, [7], []),
        (2, 1, [3], [])], roles=2)
    model, states, _ = check("omitted-equation-full-witness-containment", p, t, 3, [1])
    need(2 in model.omitted and 2 not in model.cp.select, "intended hidden equation retained")
    need(all(s[0][7][0] <= 3 for s in states), "exhaustive full bound")
    spurious = [model.query("cp_sat", [model.cp.values[7] == 4]),
                model.query("z3", [model.z.values[7] == 4])]
    need(all(w is not None for w in spurious), "omission did not expose spurious alternatives")
    result = model.proposition(3, "amount", spurious[0])
    need(not result["forced"] and result["interpretation"] == "slice inconclusive",
         "spurious alternative reported as privacy")
    tests.append("spurious-slice-alternative-is-not-full-history-or-privacy")
    view = full._view(p, t, [1])
    handoff = Slice(p, view, 3, 1, 1, 1, tiny=True)
    baseline = handoff.query("cp_sat")
    checked = handoff.smt_witness(baseline)
    need(handoff.z.solver.num_scopes() == 0, "witness pins were not popped")
    for field in ("sender", "recipient", "amount"):
        need(handoff.field_value(baseline, 3, field) == handoff.field_value(checked, 3, field),
             "checked candidate field differs")
    candidate = handoff.field_value(baseline, 3, "amount")
    need(handoff.query("z3", [handoff.z.values[7] != candidate]) is not None,
         "temporary witness pins leaked into a different query")
    row = handoff.proposition(3, "amount", baseline)
    need(not row["forced"] and row["interpretation"] == "slice inconclusive",
         "checked alternatives mislabeled")
    counts = dict(handoff.queries)
    need(not handoff.proposition(3, "amount", baseline)["forced"] and handoff.queries == counts,
         "checked same-slice cache not reused")
    another = Slice(p, view, 2, 1, 1, 1, tiny=True)
    need(not another.validated_witnesses and not another.cp_witnesses and
         another.validated_witnesses is not handoff.validated_witnesses,
         "witness cache crossed target-specific slice instances")
    pp, vv = full.prefix(p, view, 3)
    earlier = Slice(pp, vv, 3, 1, 1, 1, tiny=True)
    need(not earlier.validated_witnesses and not earlier.cp_witnesses,
         "witness cache crossed prefix")
    tests.append("checked-witness-handoff-popped-pins-and-per-slice-cache")
    wrong = copy.deepcopy(baseline)
    wrong["senders"]["3"] = 1 - wrong["senders"]["3"]
    disagreement = Slice(p, view, 3, 1, 1, 1, tiny=True)
    try:
        disagreement.proposition(3, "sender", wrong)
    except full.Incomplete:
        tests.append("candidate-sender-disagreement-rejected")
    else:
        raise ValueError("candidate disagreement accepted")
    query, calls = handoff.query, []

    def observed_query(engine, conditions=(), kind="feasibility"):
        calls.append((engine, kind, handoff.z.solver.num_scopes()))
        return query(engine, conditions, kind)

    handoff.query = observed_query
    forced = handoff.proposition(3, "sender", baseline)
    need(forced["forced"] and ("z3", "unrestricted_different", 0) in calls
         and handoff.z.solver.num_scopes() == 0, "forced negation inherited witness pins")
    tests.append("forced-negation-remains-unrestricted-in-z3")
    p, t = full._fixture(11, [
        (1, 0, [0], [(0, 10), (None, 0)]),
        (0, 1, [], [(1, 3), (None, 0)]),
        (0, 2, [], [(2, 3), (None, 0)]),
        (0, 3, [], [(3, 3), (None, 0)]),
        (1, 0, [1], [(1, 2), (0, 7)]),
        (2, 2, [5], []),
        (2, 3, [7], []),
        (2, 1, [3, 9], []),
        (2, 0, [10], [])], roles=4)
    public_slice = Slice(p, full._view(p, t), 4, 1, 1, 1, tiny=True)
    participant_slice = Slice(p, full._view(p, t, [0]), 4, 1, 1, 1, tiny=True)
    need(set(public_slice.cp.select) == {0, 4, 5, 6, 7} and
         set(participant_slice.cp.select) == {0, 4, 5, 6, 7, 8},
         "not exactly first three later DRAINs plus disclosed authors")
    tests.append("deterministic-three-cashout-selection-and-later-disclosed-author")
    return dict(passed=True, controls=tests, full_witnesses_checked=witness_checks,
                forced_propositions_compared=proposition_checks,
                scope="explicit tiny exhaustive controls; no held-out inference")
