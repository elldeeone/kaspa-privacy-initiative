"""Conditional owner/value inference over modeled v6 histories, not probabilities.

Only public fields and explicitly disclosed records enter inference. The scorer
may call validate_truth separately, after predictions are sealed. The arithmetic
encodings are H14's; no H15/H16 single-input exit or local-alias model is imported.
"""
import copy
import hashlib
import itertools
import json
import sys
import time

import z3
from ortools.sat.python import cp_model

from two_input_privacy_observer import FLOOR, PAYOUT_FLOOR, MAX, Model, decode, integer, need
from two_input_privacy_z3 import Z3Model

FEE = 40_000_000
PUBLIC_KEYS = {"schema", "roles", "adversaries", "algebra", "commitments",
               "funding_owners", "bootstrap_self", "modeled"}
VIEW_KEYS = {"schema", "public_sha256", "members", "receipts", "authored"}
META_KEYS = {"kind", "timing", "receive_contacts", "floor_sompi", "payout_floor_sompi",
             "fee_sompi", "cryptographic_identifiers", "selection_policy", "population"}


class Incomplete(RuntimeError):
    """An inconsistent/unknown/disagreeing query never counts as privacy."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fields(value, expected, label):
    need(isinstance(value, dict) and set(value) == expected, label + " fields")


def identities(value, roles, label):
    need(isinstance(value, list) and all(type(x) is int and x in roles for x in value)
         and value == sorted(set(value)), label)


def validate(public, view, floor=FLOOR, payout_floor=PAYOUT_FLOOR, fee=FEE, tiny=False):
    need(isinstance(public, dict) and
         set(public) in (PUBLIC_KEYS, PUBLIC_KEYS | {"payout_owners"}), "population public fields")
    need(public["schema"] == "kpi-population-public-v1" and public["bootstrap_self"] is True,
         "population schema/bootstrap")
    roles = public["roles"]
    need(isinstance(roles, list) and roles and
         all(type(x) is int for x in roles) and roles == list(range(len(roles))), "role universe")
    if not tiny:
        need(roles == list(range(32)) and public["adversaries"] == list(range(8)),
             "32 roles/eight adversaries")
    identities(public["adversaries"], roles, "adversary roles")
    meta = public["modeled"]
    fields(meta, META_KEYS, "modeled metadata")
    need(meta["kind"] == "synthetic-wallet-history" and meta["timing"] == "modeled-minute-slots"
         and meta["cryptographic_identifiers"] == "independent-opaque-random-labels"
         and meta["selection_policy"] == "least-excess-fewest-inputs-lexicographic",
         "modeled provenance")
    need(type(meta["population"]) is int and meta["population"] == len(roles), "population size")
    for key, value in (("floor_sompi", floor), ("payout_floor_sompi", payout_floor), ("fee_sompi", fee)):
        need(type(meta[key]) is int and meta[key] == value, "modeled " + key)
    contacts = meta["receive_contacts"]
    need(isinstance(contacts, dict) and len(contacts) == len(roles)
         and all(isinstance(k, str) and k and type(v) is int for k, v in contacts.items())
         and sorted(contacts.values()) == roles, "complete receive-contact directory")
    data = public["algebra"]
    births, upper = decode(data, floor, payout_floor)
    need(len(births) <= 65536 and len(data["events"]) <= 65535, "v6 finite capacity")
    commitments = public["commitments"]
    need(isinstance(commitments, list) and len(commitments) == len(births)
         and all(isinstance(c, str) and len(c) == 64 and c != "0" * 64
                 and all(x in "0123456789abcdef" for x in c) for c in commitments),
         "canonical nonzero commitment per position")
    funding = public["funding_owners"]
    groups = [data["initial"]["funding_group"]] + [
        e["funding_group"] for e in data["events"] if e["mode"] == 0]
    need(isinstance(funding, dict) and set(funding) == set(groups)
         and all(isinstance(k, str) and k and type(v) is int and v in roles
                 for k, v in funding.items()), "observed funding-owner directory")
    payout_owners = public.get("payout_owners", {})
    destinations = {e["destination"] for e in data["events"] if e["payout"]}
    need(isinstance(payout_owners, dict) and set(payout_owners) <= destinations
         and all(isinstance(k, str) and k and type(v) is int and v in roles
                 for k, v in payout_owners.items()), "declared payout-owner directory")
    need(data["events"][0]["mode"] == 1, "self-bootstrap is event zero")
    for e in data["events"]:
        need(e["fee"] == fee, "current fee")
        if e["mode"] != 0:
            need(e["anchor_count"] == e["count_before"], "current anchor policy")
        if e["mode"] == 1:
            need(e["payout"] == 0, "wallet payment has no native payout")
        if e["new"]:
            a, b = e["new"]
            need(commitments[a] != commitments[b], "equal sibling commitments")
    fields(view, VIEW_KEYS, "participant view")
    need(view["schema"] == "kpi-population-view-v1" and view["public_sha256"] == digest(public),
         "view/public digest")
    identities(view["members"], roles, "disclosed members")
    need(set(view["members"]) <= set(public["adversaries"]), "view members outside adversary set")
    need(isinstance(view["receipts"], list) and isinstance(view["authored"], list), "record lists")
    receipts, authors, values = {}, {}, {}
    for row in view["receipts"]:
        fields(row, {"owner", "position", "value"}, "receipt")
        p = integer(row["position"], 0, len(births) - 1)
        need(type(row["owner"]) is int and row["owner"] in view["members"], "receipt member")
        integer(row["value"], floor)
        need(p not in receipts, "duplicate receipt")
        receipts[p] = row
        values[p] = row["value"]
    used = set()
    for row in view["authored"]:
        fields(row, {"owner", "event", "inputs", "outputs"}, "authored")
        i = integer(row["event"], 0, len(data["events"]) - 1)
        need(type(row["owner"]) is int and row["owner"] in view["members"]
             and i not in authors, "author/member/event")
        e, ins = data["events"][i], row["inputs"]
        need(isinstance(ins, list) and all(type(p) is int for p in ins)
             and ins == sorted(set(ins)), "authored inputs")
        need(not ins if e["mode"] == 0 else 1 <= len(ins) <= 2, "one/two authored inputs")
        need(all(p in receipts and receipts[p]["owner"] == row["owner"]
                 and p < e["anchor_count"] for p in ins), "owned eligible authored inputs")
        need(not used.intersection(ins), "authored double spend")
        used.update(ins)
        need(isinstance(row["outputs"], list), "authored outputs")
        need([n.get("position") if isinstance(n, dict) else None for n in row["outputs"]] == e["new"],
             "authored output positions")
        for output in row["outputs"]:
            fields(output, {"position", "value", "recipient"}, "authored output")
            p, value, owner = output["position"], integer(output["value"]), output["recipient"]
            need(value == 0 or value >= floor, "authored output floor")
            need(owner is None if value == 0 else type(owner) is int and owner in roles,
                 "authored recipient")
            need(p not in values or values[p] == value, "contradictory amount records")
            values[p] = value
            own = value > 0 and owner in view["members"]
            need((p in receipts) == own, "complete pooled output receipts")
            if own:
                need(receipts[p]["owner"] == owner, "contradictory recipient records")
        authors[i] = row
    return dict(births=births, upper=upper, receipts=receipts, authors=authors)


def prefix(public, view, end):
    """Discard future events/records/equalities before constructing any solver."""
    integer(end, 0, len(public["algebra"]["events"]) - 1)
    p, v = copy.deepcopy(public), copy.deepcopy(view)
    p["algebra"]["events"] = p["algebra"]["events"][:end + 1]
    events = p["algebra"]["events"]
    count = events[-1]["count_before"] + len(events[-1]["new"])
    p["commitments"] = p["commitments"][:count]
    groups = {p["algebra"]["initial"]["funding_group"]} | {
        e["funding_group"] for e in events if e["mode"] == 0}
    p["funding_owners"] = {g: owner for g, owner in p["funding_owners"].items() if g in groups}
    if "payout_owners" in p:
        destinations = {e["destination"] for e in events if e["payout"]}
        p["payout_owners"] = {d: o for d, o in p["payout_owners"].items() if d in destinations}
    v["receipts"] = [r for r in v["receipts"] if r["position"] < count]
    v["authored"] = [r for r in v["authored"] if r["event"] <= end]
    v["public_sha256"] = digest(p)
    return p, v


class Pair:
    def __init__(self, public, view, floor=FLOOR, payout_floor=PAYOUT_FLOOR, fee=FEE,
                 tiny=False, diagnostics=False):
        self.facts = validate(public, view, floor, payout_floor, fee, tiny)
        self.public, self.view = public, view
        self.data = public["algebra"]
        self.cp, self.z = Model(self.data, floor, payout_floor), Z3Model(self.data, floor, payout_floor)
        if sum(self.cp.upper) + sum(e["fee"] + e["deposit"] + e["payout"]
                                   for e in self.data["events"]) >= 2**62:
            raise Incomplete("CP intermediate range unsupported")
        self.queries = {"cp_sat": 0, "z3": 0}
        self.diagnostics = diagnostics
        self.context = dict(through_event=len(self.data["events"]) - 1)
        self._cp_owners(floor)
        self._z3_owners(floor)

    def _cp_owners(self, floor):
        m, n = self.cp.model, len(self.public["roles"])
        self.cp_owners = [m.new_int_var(0, n - 1, f"owner{p}") for p in range(len(self.cp.values))]
        self.cp_senders = [m.new_int_var(0, n - 1, f"sender{i}")
                           for i in range(len(self.data["events"]))]
        initial_owner = self.public["funding_owners"][self.data["initial"]["funding_group"]]
        m.add(self.cp_owners[0] == initial_owner)
        for i, e in enumerate(self.data["events"]):
            sender = self.cp_senders[i]
            if e["mode"] == 0:
                m.add(sender == self.public["funding_owners"][e["funding_group"]])
                a, b = e["new"]
                m.add(self.cp.values[a] == e["deposit"] - e["fee"])
                m.add(self.cp.values[a] >= floor)
                m.add(self.cp.values[b] == 0)
                m.add(self.cp_owners[a] == sender)
            else:
                for p, selected in enumerate(self.cp.select[i]):
                    m.add(self.cp_owners[p] == sender).only_enforce_if(selected)
                if e["mode"] == 1:
                    a, b = e["new"]
                    m.add(self.cp.values[a] >= floor)
                    m.add(self.cp_owners[b] == sender).only_enforce_if(self.cp.positive[b])
            if e["destination"] in self.public.get("payout_owners", {}):
                m.add(sender == self.public["payout_owners"][e["destination"]])
        a, b = self.data["events"][0]["new"]
        m.add(self.cp.values[b] == 0)
        m.add(self.cp_owners[a] == initial_owner)
        for p, variable in enumerate(self.cp_owners):
            if p in self.facts["receipts"]:
                row = self.facts["receipts"][p]
                m.add(variable == row["owner"])
                m.add(self.cp.values[p] == row["value"])
            else:
                for member in self.view["members"]:
                    m.add(variable != member).only_enforce_if(self.cp.positive[p])
        for i, sender in enumerate(self.cp_senders):
            if i in self.facts["authors"]:
                row = self.facts["authors"][i]
                m.add(sender == row["owner"])
                for p, selected in enumerate(self.cp.select.get(i, [])):
                    m.add(selected == int(p in row["inputs"]))
                for output in row["outputs"]:
                    p = output["position"]
                    m.add(self.cp.values[p] == output["value"])
                    if output["value"]:
                        m.add(self.cp_owners[p] == output["recipient"])
            else:
                for member in self.view["members"]:
                    m.add(sender != member)
        seen = {}
        for p, cm in enumerate(self.public["commitments"]):
            if cm in seen:
                q = seen[cm]
                m.add(self.cp.values[p] == self.cp.values[q])
                m.add(self.cp_owners[p] == self.cp_owners[q])
            seen[cm] = p

    def _z3_owners(self, floor):
        # Independently express owner constraints; no CP constraint translation.
        s, roles = self.z.solver, self.public["roles"]
        self.z_owners = [z3.Int(f"owner{p}") for p in range(len(self.z.values))]
        self.z_senders = [z3.Int(f"sender{i}") for i in range(len(self.data["events"]))]
        for variable in self.z_owners + self.z_senders:
            s.add(variable >= 0, variable < len(roles))
        founder = self.public["funding_owners"][self.data["initial"]["funding_group"]]
        s.add(self.z_owners[0] == founder)
        for i, e in enumerate(self.data["events"]):
            if e["mode"] == 0:
                a, b = e["new"]
                s.add(self.z_senders[i] == self.public["funding_owners"][e["funding_group"]],
                      self.z_owners[a] == self.z_senders[i],
                      self.z.values[a] == e["deposit"] - e["fee"],
                      self.z.values[a] >= floor, self.z.values[b] == 0)
            else:
                for p, selected in enumerate(self.z.select[i]):
                    s.add(z3.Implies(selected, self.z_owners[p] == self.z_senders[i]))
                if e["mode"] == 1:
                    a, b = e["new"]
                    s.add(self.z.values[a] >= floor,
                          z3.Implies(self.z.values[b] > 0, self.z_owners[b] == self.z_senders[i]))
            if e["destination"] in self.public.get("payout_owners", {}):
                s.add(self.z_senders[i] == self.public["payout_owners"][e["destination"]])
        a, b = self.data["events"][0]["new"]
        s.add(self.z.values[b] == 0, self.z_owners[a] == founder)
        for p, owner in enumerate(self.z_owners):
            row = self.facts["receipts"].get(p)
            if row is not None:
                s.add(owner == row["owner"], self.z.values[p] == row["value"])
            else:
                s.add(*[z3.Implies(self.z.values[p] > 0, owner != member)
                        for member in self.view["members"]])
        for i, sender in enumerate(self.z_senders):
            row = self.facts["authors"].get(i)
            if row is None:
                s.add(*[sender != member for member in self.view["members"]])
                continue
            s.add(sender == row["owner"])
            s.add(*[selected == (p in row["inputs"])
                    for p, selected in enumerate(self.z.select.get(i, []))])
            for output in row["outputs"]:
                p = output["position"]
                s.add(self.z.values[p] == output["value"])
                if output["value"] > 0:
                    s.add(self.z_owners[p] == output["recipient"])
        for p, cm in enumerate(self.public["commitments"]):
            for q in range(p):
                if self.public["commitments"][q] == cm:
                    s.add(self.z.values[p] == self.z.values[q], self.z_owners[p] == self.z_owners[q])
                    break

    def progress(self, **fields_):
        if self.diagnostics:
            try:
                print(json.dumps({**self.context, **fields_, "runtime_only": True}),
                      file=sys.stderr, flush=True)
            except OSError:
                pass

    def query(self, engine, conditions=(), kind="feasibility"):
        self.queries[engine] += 1
        started = time.monotonic()
        self.progress(engine=engine, kind=kind, event="query_start")
        if engine == "cp_sat":
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
                        inputs={str(i): [p for p, x in enumerate(ss) if solver.value(x)]
                                for i, ss in self.cp.select.items()},
                        senders={str(i): solver.value(v) for i, v in enumerate(self.cp_senders)})
        need(engine == "z3", "query engine")
        self.z.solver.push()
        try:
            self.z.solver.add(*conditions)
            status = self.z.solver.check()
            self.progress(engine=engine, kind=kind, event="query_end", status=str(status),
                          elapsed_seconds=time.monotonic() - started)
            if status == z3.unsat:
                return None
            if status != z3.sat:
                raise Incomplete("Z3 unknown/nonconclusive: " + str(status))
            model = self.z.solver.model()
            value = lambda x: model.eval(x, model_completion=True).as_long()
            values = [value(v) for v in self.z.values]
            return dict(values=values,
                        owners=[value(o) if v else None for o, v in zip(self.z_owners, values)],
                        inputs={str(i): [p for p, x in enumerate(ss)
                                        if z3.is_true(model.eval(x, model_completion=True))]
                                for i, ss in self.z.select.items()},
                        senders={str(i): value(v) for i, v in enumerate(self.z_senders)})
        finally:
            self.z.solver.pop()

    def variables(self, event, field):
        if field == "sender":
            return self.cp_senders[event], self.z_senders[event]
        p = self.data["events"][event]["new"][0]
        return ((self.cp_owners[p], self.z_owners[p]) if field == "recipient"
                else (self.cp.values[p], self.z.values[p]))

    def proposition(self, event, field, baseline):
        cp, smt = self.variables(event, field)
        p = self.data["events"][event]["new"][0]
        candidate = (baseline["senders"][str(event)] if field == "sender" else
                     baseline["owners" if field == "recipient" else "values"][p])
        self.context.update(target_event=event, field=field)
        witnesses = {}
        for engine, variable in (("cp_sat", cp), ("z3", smt)):
            witnesses[engine + "_candidate"] = self.query(engine, [variable == candidate], "candidate")
            if witnesses[engine + "_candidate"] is None:
                raise Incomplete("candidate witness disagrees between models")
            witnesses[engine + "_alternative"] = self.query(engine, [variable != candidate], "different")
        forced = witnesses["cp_sat_alternative"] is None
        if forced != (witnesses["z3_alternative"] is None):
            raise Incomplete("CP-SAT/Z3 forced-proposition disagreement")
        return dict(forced=forced, candidate=candidate,
                    certificates={engine: dict(candidate="SAT", different="UNSAT" if forced else "SAT")
                                  for engine in ("cp_sat", "z3")},
                    hypothetical_witnesses=witnesses)


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
        # Validate a prefix even when there are no ordinary-payment targets.
        for end in sorted({t["through_event"] for t in targets} or {len(events) - 1}, reverse=True):
            p, v = prefix(public, view, end)
            model = Pair(p, v, floor, payout_floor, fee, tiny, diagnostics)
            models[end] = model
            baseline = model.query("cp_sat")
            smt = model.query("z3")
            if baseline is None or smt is None:
                raise Incomplete("inconsistent prefix or cross-model feasibility disagreement")
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
                meaning="Conditional exact propositions; witnesses are hypothetical assignments, not recovered truth or probabilities",
                assumptions=[
                    "Closed modeled role universe, current-wallet common inputs and recipient/change order.",
                    "Complete disclosed participant records; valid delivery and uncompromised keys.",
                    "Equal commitments bind equal value and owner but positions/spends stay distinct.",
                    "Only supplied funding/contact/payout associations identify roles.",
                    "Cryptographic identifiers otherwise hide linkage; cryptography is not tested."],
                relaxations=["Automatic coin selection, payment distribution, timing/scheduling and admission-time recipient restrictions are not enforced."])


def analyze(public, view, targets=None):
    return _analyze(public, view, targets, diagnostics=True)


def validate_truth(public, view, truth):
    """Scorer-only consistency check. Never called by analyze or its controls."""
    model = Pair(public, view)
    need(isinstance(truth, dict) and {"values", "owners", "inputs"} <= set(truth), "truth core")
    values, owners, inputs = truth["values"], truth["owners"], truth["inputs"]
    need(isinstance(values, list) and isinstance(owners, list)
         and len(values) == len(owners) == len(model.cp.values), "truth note vectors")
    need(isinstance(inputs, dict) and set(inputs) in (
        {str(i) for i in model.cp.select}, {str(i) for i in range(len(model.data["events"]))}),
        "truth input events")
    cp, smt = [], []
    for p, (v, o) in enumerate(zip(values, owners)):
        integer(v)
        need(o is None if v == 0 else type(o) is int and o in public["roles"], "truth owner")
        cp.append(model.cp.values[p] == v)
        smt.append(model.z.values[p] == v)
        if v:
            cp.append(model.cp_owners[p] == o)
            smt.append(model.z_owners[p] == o)
    for key, positions in inputs.items():
        if int(key) not in model.cp.select:
            need(positions == [], "admission truth inputs")
            continue
        need(isinstance(positions, list) and all(type(p) is int for p in positions)
             and positions == sorted(set(positions)) and 1 <= len(positions) <= 2
             and all(0 <= p < len(model.cp.select[int(key)]) for p in positions), "truth input positions")
        cp.extend(x == int(p in positions) for p, x in enumerate(model.cp.select[int(key)]))
        smt.extend(x == (p in positions) for p, x in enumerate(model.z.select[int(key)]))
    answers = [model.query("cp_sat", cp), model.query("z3", smt)]
    return dict(complete=True, cp_sat="SAT" if answers[0] is not None else "UNSAT",
                z3="SAT" if answers[1] is not None else "UNSAT")


def _fixture(initial, steps, roles=3, floor=1, fee=1):
    """Explicit development fixtures only, never a held-out workload generator."""
    notes, inputs, senders, events = [(initial, 0)], {}, [], []
    reserve, spent, funding = initial, set(), {"f0": 0}
    for i, (mode, owner, ins, outputs) in enumerate(steps):
        assert len(set(ins)) == len(ins) and not spent.intersection(ins)
        assert all(notes[p][1] == owner and notes[p][0] > 0 for p in ins)
        total = sum(notes[p][0] for p in ins)
        deposit = sum(v for _, v in outputs) + fee if mode == 0 else 0
        payout = total - fee if mode == 2 else 0
        assert total + deposit == sum(v for _, v in outputs) + payout + fee
        count = len(notes)
        new = [] if mode == 2 else [count, count + 1]
        assert len(outputs) == len(new)
        reserve += deposit - payout - fee
        funding_group = f"f{i}" if mode == 0 else None
        if mode == 0:
            funding[funding_group] = owner
        events.append(dict(id=f"e{i}", minute=i, mode=mode, anchor_count=0 if mode == 0 else count,
                           count_before=count, new=new, fee=fee, deposit=deposit, payout=payout,
                           reserve_out=reserve, destination=f"d{i}" if payout else None,
                           funding_group=funding_group))
        notes.extend((value, who if value else None) for who, value in outputs)
        inputs[str(i)] = list(ins)
        senders.append(owner)
        spent.update(ins)
    public = dict(schema="kpi-population-public-v1", roles=list(range(roles)),
                  adversaries=list(range(min(8, roles))), bootstrap_self=True,
                  funding_owners=funding, commitments=[f"{p + 1:064x}" for p in range(len(notes))],
                  algebra=dict(schema="kpi-h14-public-v1",
                               initial=dict(id="initial", value=initial, funding_group="f0"),
                               events=events),
                  modeled=dict(kind="synthetic-wallet-history", timing="modeled-minute-slots",
                               receive_contacts={f"contact{r}": r for r in range(roles)},
                               floor_sompi=floor, payout_floor_sompi=1, fee_sompi=fee,
                               cryptographic_identifiers="independent-opaque-random-labels",
                               selection_policy="least-excess-fewest-inputs-lexicographic",
                               population=roles))
    truth = dict(values=[n[0] for n in notes], owners=[n[1] for n in notes],
                 inputs=inputs, senders=senders)
    return public, truth


def _view(public, truth, members=()):
    members = sorted(members)
    return dict(schema="kpi-population-view-v1", public_sha256=digest(public), members=members,
                receipts=[dict(owner=o, position=p, value=v)
                          for p, (v, o) in enumerate(zip(truth["values"], truth["owners"]))
                          if v and o in members],
                authored=[dict(owner=owner, event=i, inputs=truth["inputs"][str(i)],
                               outputs=[dict(position=p, value=truth["values"][p],
                                             recipient=truth["owners"][p]) for p in e["new"]])
                          for i, (e, owner) in enumerate(zip(public["algebra"]["events"], truth["senders"]))
                          if owner in members])


def _enumerate(public, view, floor=1):
    """Independent tiny ledger walk, with no decode/reverse_bounds/model helpers.

    Enumerates concrete notes, owners and spent resources, then filters exactly
    the supplied records. It never copies the hidden fixture's intended ledger.
    """
    data, roles = public["algebra"], public["roles"]
    receipts = {r["position"]: (r["value"], r["owner"]) for r in view["receipts"]}
    authored = {r["event"]: r for r in view["authored"]}
    members = set(view["members"])
    cms = public["commitments"]

    def accepted_note(notes, p, note):
        value, owner = note
        if p in receipts:
            if note != receipts[p]:
                return False
        elif value and owner in members:
            return False
        for q in range(p):
            if cms[q] == cms[p] and (notes[q][0] != value or (value and notes[q][1] != owner)):
                return False
        return True

    initial = (data["initial"]["value"],
               public["funding_owners"][data["initial"]["funding_group"]])
    states = [([initial], frozenset(), [], [])] if accepted_note([], 0, initial) else []
    for i, e in enumerate(data["events"]):
        following = []
        for notes, spent, history, senders in states:
            live = [p for p, (value, _) in enumerate(notes)
                    if value and p not in spent and p < e["anchor_count"]]
            choices = [()] if e["mode"] == 0 else [
                combo for count in (1, 2) for combo in itertools.combinations(live, count)]
            for combo in choices:
                if e["mode"] == 0:
                    sender = public["funding_owners"][e["funding_group"]]
                    available = e["deposit"] - e["fee"]
                else:
                    owners = {notes[p][1] for p in combo}
                    if len(owners) != 1:
                        continue
                    sender = next(iter(owners))
                    available = sum(notes[p][0] for p in combo) - e["payout"] - e["fee"]
                row = authored.get(i)
                if (sender in members) != (row is not None):
                    continue
                if row is not None and (sender != row["owner"] or list(combo) != row["inputs"]):
                    continue
                if e["destination"] in public.get("payout_owners", {}) and (
                        sender != public["payout_owners"][e["destination"]]):
                    continue
                if e["mode"] == 2:
                    variants = [()] if available == 0 else []
                elif e["mode"] == 0 or i == 0:
                    variants = [((available, sender), (0, None))] if available >= floor else []
                else:
                    variants = [
                        ((first, recipient), (available - first, sender if available > first else None))
                        for first in range(floor, available + 1)
                        if available == first or available - first >= floor
                        for recipient in roles]
                for outputs in variants:
                    if row is not None:
                        disclosed = tuple((o["value"], o["recipient"]) for o in row["outputs"])
                        if outputs != disclosed:
                            continue
                    expanded = notes + list(outputs)
                    if any(not accepted_note(expanded, len(notes) + slot, note)
                           for slot, note in enumerate(outputs)):
                        continue
                    used = spent | set(combo)
                    if sum(value for p, (value, _) in enumerate(expanded) if p not in used) != e["reserve_out"]:
                        continue
                    following.append((expanded, used, history + [tuple(combo)], senders + [sender]))
        states = following
    return states


def _agree(public, view, floor=1):
    states = _enumerate(public, view, floor)
    model = Pair(public, view, floor, 1, public["modeled"]["fee_sompi"], tiny=True)
    answers = [model.query(engine) is not None for engine in ("cp_sat", "z3")]
    assert answers == [bool(states)] * 2
    comparisons = 1
    if not states:
        return model, states, comparisons
    for i, e in enumerate(public["algebra"]["events"]):
        if i == 0 or e["mode"] != 1:
            continue
        for field in ("sender", "recipient", "amount"):
            cp, smt = model.variables(i, field)
            expected = {s[3][i] if field == "sender" else
                        s[0][e["new"][0]][1 if field == "recipient" else 0] for s in states}
            domain = public["roles"] if field != "amount" else range(
                0, max(sum(v for v, _ in s[0]) for s in states) + 1)
            for value in domain:
                observed = [model.query("cp_sat", [cp == value]) is not None,
                            model.query("z3", [smt == value]) is not None]
                assert observed == [value in expected] * 2, (i, field, value, observed, expected)
                comparisons += 1
    return model, states, comparisons


def controls():
    """Explicit small controls only; this function reads no files or private views."""
    tests, comparisons = [], 0

    def agree(public, truth, members=(), floor=1):
        nonlocal comparisons
        view = _view(public, truth, members)
        model, states, count = _agree(public, view, floor)
        comparisons += count
        return model, states, view

    # A5/B7/C1: receiving C2 leaves both A and B as potential senders,
    # with different sibling amounts. Receipt knowledge is not author knowledge.
    public, truth = _fixture(6, [
        (1, 0, [0], [(0, 5), (None, 0)]),
        (0, 1, [], [(1, 7), (None, 0)]),
        (0, 2, [], [(2, 1), (None, 0)]),
        (1, 0, [1], [(2, 2), (0, 2)]),
    ])
    model, states, view = agree(public, truth, [2])
    assert {s[3][3] for s in states} == {0, 1}
    assert {s[0][8][0] for s in states} == {2, 4}
    ambiguous = model.proposition(3, "sender", model.query("cp_sat"))
    assert not ambiguous["forced"] and all(ambiguous["hypothetical_witnesses"].values())
    tests.append("recipient-only-keeps-sender-and-sibling-ambiguity")

    # Permute the entire identity directory and disclosures, including founder.
    permutation = {0: 2, 1: 0, 2: 1}
    permuted, shifted = copy.deepcopy(public), copy.deepcopy(truth)
    permuted["funding_owners"] = {k: permutation[v] for k, v in public["funding_owners"].items()}
    permuted["modeled"]["receive_contacts"] = {
        k: permutation[v] for k, v in public["modeled"]["receive_contacts"].items()}
    shifted["owners"] = [None if v is None else permutation[v] for v in truth["owners"]]
    shifted["senders"] = [permutation[v] for v in truth["senders"]]
    _, mapped, _ = agree(permuted, shifted, [permutation[2]])
    assert {s[3][3] for s in mapped} == {permutation[x] for x in (0, 1)}
    assert {s[0][7][0] for s in mapped} == {2}
    tests.append("stable-role-permutation")

    # Common ownership forbids 5+5 -> 9+fee even though arithmetic permits it.
    p, t = _fixture(6, [(1, 0, [0], [(0, 5), (None, 0)]),
                        (0, 1, [], [(1, 5), (None, 0)]),
                        (1, 0, [1], [(2, 2), (0, 2)])])
    m, ss, _ = agree(p, t)
    assert ss
    assert m.query("cp_sat", [m.cp.values[5] == 9]) is None
    assert m.query("z3", [m.z.values[5] == 9]) is None
    tests.append("different-owner-input-combination-rejected")

    # Genuine two-note exit and fixed sender change.
    p, t = _fixture(7, [(1, 0, [0], [(0, 6), (None, 0)]),
                        (0, 1, [], [(1, 3), (None, 0)]),
                        (1, 0, [1], [(1, 2), (0, 3)]),
                        (2, 1, [3, 5], [])])
    m, ss, _ = agree(p, t, [1])
    assert ss and all(s[2][3] == (3, 5) for s in ss)
    assert m.query("cp_sat", [sum(m.cp.select[3]) == 1]) is None
    assert m.query("z3", [z3.PbEq([(x, 1) for x in m.z.select[3]], 1)]) is None
    # No disclosed B receipt/absence may independently forbid the wrong change.
    m = Pair(p, _view(p, t), 1, 1, 1, tiny=True)
    assert m.query("cp_sat", [m.cp.select[2][1] == 1, m.cp.values[6] == 3,
                            m.cp_owners[6] == 1]) is None
    assert m.query("z3", [m.z.select[2][1], m.z.values[6] == 3, m.z_owners[6] == 1]) is None
    tests.append("two-input-drain-and-fixed-positive-change")

    # Pooled complete records remove both controlled senders; separate records
    # must not silently acquire the other participant's absence-of-spend facts.
    p, t = _fixture(6, [(1, 0, [0], [(0, 5), (None, 0)]),
                        (0, 1, [], [(1, 5), (None, 0)]),
                        (0, 2, [], [(2, 5), (None, 0)]),
                        (0, 3, [], [(3, 1), (None, 0)]),
                        (1, 2, [5], [(3, 1), (2, 3)])], roles=4)
    for members, expected in (([], {0, 1, 2}), ([0], {1, 2}), ([1], {0, 2}), ([0, 1], {2})):
        m, ss, _ = agree(p, t, members)
        assert {s[3][4] for s in ss} == expected
    result = m.proposition(4, "sender", m.query("cp_sat"))
    assert result["forced"] and result["candidate"] == 2
    tests.append("separate-and-pooled-complete-records-forced-sender")
    _, ss, _ = agree(p, t, [0, 1, 3])
    assert {s[3][4] for s in ss} == {2}
    tests.append("all-other-owners-disclosed")

    # A repeated CM across two batches is one opening, two separate resources.
    p, t = _fixture(8, [(1, 0, [0], [(0, 7), (None, 0)]),
                        (0, 1, [], [(1, 3), (None, 0)]),
                        (1, 0, [1], [(1, 3), (0, 3)]),
                        (2, 1, [3], []), (2, 1, [5], [])])
    p["commitments"][5] = p["commitments"][3]
    m, ss, _ = agree(p, t, [1])
    assert ss and all(s[2][3:5] == [(3,), (5,)] for s in ss)
    # Test the public equality itself, without receipts already fixing both.
    m = Pair(p, _view(p, t), 1, 1, 1, tiny=True)
    assert m.query("cp_sat", [m.cp_owners[5] != m.cp_owners[3]]) is None
    assert m.query("z3", [m.z.values[5] != m.z.values[3]]) is None
    tests.append("equal-commitments-distinct-position-spends")

    # Public future exit narrows the earlier amount; rebuilding the prefix
    # must discard both future constraints and reverse-bound consequences.
    p, t = _fixture(7, [(1, 0, [0], [(0, 6), (None, 0)]),
                        (0, 1, [], [(1, 2), (None, 0)]),
                        (1, 0, [1], [(1, 2), (0, 3)]),
                        (2, 1, [3, 5], [])], floor=2)
    v = _view(p, t)
    early, early_view = prefix(p, v, 2)
    _, before, count = _agree(early, early_view, 2)
    comparisons += count
    _, after, count = _agree(p, v, 2)
    comparisons += count
    assert {s[0][5][0] for s in before} == {2, 3, 5}
    assert {s[0][5][0] for s in after} == {2}
    tests.append("future-cashout-does-not-constrain-birth-prefix")

    p, t = _fixture(7, [(1, 0, [0], [(0, 6), (None, 0)]),
                        (0, 1, [], [(1, 1), (None, 0)]),
                        (0, 2, [], [(2, 1), (None, 0)]),
                        (1, 0, [1], [(1, 4), (0, 1)]),
                        (1, 1, [3, 7], [(2, 4), (None, 0)])])
    v = _view(p, t, [2])
    early, early_view = prefix(p, v, 3)
    before, ss, count = _agree(early, early_view)
    comparisons += count
    after, _, count = _agree(p, v)
    comparisons += count
    assert any(s[0][7] == (2, 1) for s in ss)
    for engine in ("cp_sat", "z3"):
        owners, values = ((before.cp_owners, before.cp.values) if engine == "cp_sat"
                          else (before.z_owners, before.z.values))
        assert before.query(engine, [owners[7] == 1, values[7] == 2]) is not None
        owners, values = ((after.cp_owners, after.cp.values) if engine == "cp_sat"
                          else (after.z_owners, after.z.values))
        assert after.query(engine, [owners[7] == 1, values[7] == 2]) is None
    tests.append("future-participant-receipt-removed-from-earlier-prefix")

    # A future admission reuses the earlier payment commitment. Its value and
    # owner must constrain the later horizon only, not the payment's birth.
    p, t = _fixture(8, [(1, 0, [0], [(0, 7), (None, 0)]),
                        (1, 0, [1], [(1, 3), (0, 3)]),
                        (0, 1, [], [(1, 3), (None, 0)])])
    p["commitments"][5] = p["commitments"][3]
    v = _view(p, t)
    early, early_view = prefix(p, v, 1)
    _, before, count = _agree(early, early_view)
    comparisons += count
    _, after, count = _agree(p, v)
    comparisons += count
    assert {s[0][3][0] for s in before} == set(range(1, 7))
    assert {s[0][3] for s in after} == {(3, 1)}
    tests.append("future-equal-commitment-does-not-label-earlier-prefix")

    # Strict poison/record checks use an ordinary tiny fixture.
    bad_public = copy.deepcopy(public)
    bad_public["private_truth"] = {}
    bad_view = copy.deepcopy(view)
    bad_view["receipts"][0]["sender"] = 0
    bad_digest = copy.deepcopy(view)
    bad_digest["public_sha256"] = "0" * 64
    for candidate_public, candidate_view in ((bad_public, view), (public, bad_view), (public, bad_digest)):
        try:
            validate(candidate_public, candidate_view, 1, 1, 1, tiny=True)
        except ValueError:
            pass
        else:
            raise AssertionError("schema poison accepted")
    tests.append("unknown-fields-and-wrong-binding-rejected")
    inconsistent = copy.deepcopy(view)
    inconsistent["receipts"][-1]["value"] = 100
    m = Pair(public, inconsistent, 1, 1, 1, tiny=True)
    assert m.query("cp_sat") is None and m.query("z3") is None
    assert not _analyze(public, inconsistent, floor=1, payout_floor=1, fee=1, tiny=True)["complete"]
    tests.append("inconsistent-records-are-incomplete")

    # A deliberately sparse 32-role control in actual integer sompi. All roles
    # start with 500 tKAS; honest8 pays honest9 100. This is an explicit known
    # fixture, not a draw from the frozen workload and not a qualification.
    unit, principal = 100_000_000, 50_000_000_000
    steps = [(1, 0, [0], [(0, principal), (None, 0)])]
    steps.extend((0, owner, [], [(owner, principal), (None, 0)]) for owner in range(1, 32))
    event, paid, change = len(steps), 65, 66
    steps.append((1, 8, [17], [(9, 100 * unit), (8, principal - 100 * unit - FEE)]))
    for owner in range(32):
        ins = [change] if owner == 8 else [19, paid] if owner == 9 else [1 + 2 * owner]
        steps.append((2, owner, ins, []))
    p, t = _fixture(principal + FEE, steps, roles=32, floor=FLOOR, fee=FEE)
    p["modeled"]["payout_floor_sompi"] = PAYOUT_FLOOR
    p["payout_owners"] = {e["destination"]: t["senders"][i]
                          for i, e in enumerate(p["algebra"]["events"]) if e["payout"]}
    linked = _analyze(p, _view(p, t))
    assert linked["complete"] and len(linked["rows"]) == 1
    row = linked["rows"][0]
    assert row["event"] == event
    for field, expected in (("sender", 8), ("recipient", 9), ("amount", 100 * unit)):
        assert row[field]["forced"] and row[field]["candidate"] == expected
    p.pop("payout_owners")
    unlinked = _analyze(p, _view(p, t))
    assert unlinked["complete"] and all(not unlinked["rows"][0][field]["forced"]
                                      for field in ("sender", "recipient"))
    # Amount may remain deducible without owner-labelled payouts; do not claim
    # removing the labels restores every kind of privacy.
    tests.append("32-role-sparse-linked-payout-and-unlinked-identity-control")

    return dict(passed=True, complete=True, tests=tests, controls=len(tests),
                exhaustive_proposition_comparisons=comparisons,
                pending=[],
                meaning="Explicit development controls; no held-out workload, proofs or chain acceptance")
