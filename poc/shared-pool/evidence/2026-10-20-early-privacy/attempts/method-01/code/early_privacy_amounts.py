"""Public-only integer amount extrema, using independent H14 CP-SAT/Z3 models.

No owner labels, note openings or actual private amounts are accepted. Extrema
are not a contiguous feasible set or probabilities. Cryptographic commitments
are assumed binding; equal nonzero bytes imply equal values, not one position.
"""
import itertools

import z3
from ortools.sat.python import cp_model

from two_input_privacy_observer import FLOOR, PAYOUT_FLOOR, Model, decode, need
from two_input_privacy_z3 import Z3Model

PROFILES = ("relation", "current_wallet_shape")


class Incomplete(RuntimeError):
    """A missing certificate must never be reported as greater privacy."""


def _validate(data, commitments, floor, payout_floor):
    births, upper = decode(data, floor, payout_floor)
    need(all(e["minute"] == 0 for e in data["events"]), "unused minute must be zero")
    need(isinstance(commitments, list) and len(commitments) == len(births),
         "one commitment per distinct position")
    need(all(isinstance(c, str) and len(c) == 64 and
             all(x in "0123456789abcdef" for x in c) for c in commitments),
         "canonical commitment hex")
    return births, upper


def _groups(commitments):
    positions = {}
    for p, cm in enumerate(commitments):
        if cm != "00" * 32:
            positions.setdefault(cm, []).append(p)
    return [p for p in positions.values() if len(p) > 1]


class Pair:
    def __init__(self, data, commitments, profile, floor, payout_floor):
        # Every horizon is reconstructed from that prefix only. Neither shared
        # reverse-bound calculation may see a later withdrawal or commitment.
        self.cp = Model(data, floor, payout_floor)
        self.z3 = Z3Model(data, floor, payout_floor)
        self.queries = {"cp_sat": 0, "z3": 0}
        # Refuse unsupported intermediate ranges rather than overflow or
        # silently narrow the feasible set. Native-range generality is not claimed.
        if sum(self.cp.upper) + sum(e["fee"] + e["payout"] + e["deposit"]
                                   for e in data["events"]) >= 2**62:
            raise Incomplete("CP-SAT intermediate range unsupported")
        for positions in _groups(commitments):
            for p in positions[1:]:
                self.add(self.cp.values[p] == self.cp.values[positions[0]],
                         self.z3.values[p] == self.z3.values[positions[0]])
        if profile == "current_wallet_shape":
            for e in data["events"]:
                if e["mode"] == 0:
                    a, b = e["new"]
                    self.add(self.cp.values[a] == e["deposit"] - e["fee"],
                             self.z3.values[a] == e["deposit"] - e["fee"])
                    self.add(self.cp.values[b] == 0, self.z3.values[b] == 0)
                    self.add(self.cp.values[a] >= floor, self.z3.values[a] >= floor)
                else:
                    current = e["anchor_count"] == e["count_before"]
                    self.add(current, current)
                    if e["mode"] == 1:
                        self.add(e["payout"] == 0, e["payout"] == 0)
                        self.add(self.cp.values[e["new"][0]] >= floor,
                                 self.z3.values[e["new"][0]] >= floor)
        elif profile != "relation":
            raise ValueError("unknown amount profile")

    def add(self, cp_condition, z3_condition):
        self.cp.model.add(cp_condition)
        self.z3.solver.add(z3_condition)

    def cp_query(self, condition=None, position=None, maximize=False):
        model = self.cp.model.clone()
        if condition is not None:
            model.add(condition)
        if position is not None:
            objective = self.cp.values[position]
            (model.maximize if maximize else model.minimize)(objective)
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 1
        solver.parameters.random_seed = 0
        status = solver.solve(model)
        self.queries["cp_sat"] += 1
        if status not in (cp_model.OPTIMAL, cp_model.INFEASIBLE):
            raise Incomplete("CP-SAT non-exact status: " + solver.status_name(status))
        if status == cp_model.INFEASIBLE:
            return None
        return {
            "values": [solver.value(v) for v in self.cp.values],
            "input_positions": {
                str(i): [p for p, v in enumerate(row) if solver.value(v)]
                for i, row in self.cp.select.items()
            },
        }

    def z3_query(self, condition):
        self.z3.solver.push()
        try:
            self.z3.solver.add(condition)
            status = self.z3.solver.check()
            self.queries["z3"] += 1
            if status not in (z3.sat, z3.unsat):
                raise Incomplete("Z3 non-conclusive status: " + str(status))
            return status == z3.sat
        finally:
            self.z3.solver.pop()

    def bounds(self, position):
        witnesses = [self.cp_query(position=position, maximize=high) for high in (False, True)]
        if any(w is None for w in witnesses):
            raise Incomplete("profile/prefix inconsistent; no privacy conclusion")
        low, high = (w["values"][position] for w in witnesses)
        value = self.z3.values[position]
        checks = [
            self.z3_query(value == low), not self.z3_query(value < low),
            self.z3_query(value == high), not self.z3_query(value > high),
        ]
        if not all(checks):
            raise Incomplete("CP-SAT/Z3 endpoint or outside-bound disagreement")
        zero_cp = self.cp_query(self.cp.values[position] == 0) is not None
        zero_z3 = self.z3_query(value == 0)
        if zero_cp != zero_z3:
            raise Incomplete("CP-SAT/Z3 zero-feasibility disagreement")
        return {
            "minimum_sompi": low, "maximum_sompi": high,
            "zero_possible": zero_cp, "forced": low == high,
            "certificates": {
                "cp_sat_minimum": "OPTIMAL", "cp_sat_maximum": "OPTIMAL",
                "z3_minimum_endpoint": "SAT", "z3_below_minimum": "UNSAT",
                "z3_maximum_endpoint": "SAT", "z3_above_maximum": "UNSAT",
                "z3_zero": "SAT" if zero_z3 else "UNSAT",
                "cp_sat_endpoint_witnesses": witnesses,
            },
        }


def _analyze(data, commitments, floor, payout_floor):
    births, _ = _validate(data, commitments, floor, payout_floor)
    events = data["events"]
    profiles = {}
    for profile in PROFILES:
        rows, models = [], {}
        error = None
        try:
            final = len(events) - 1
            models[final] = Pair(data, commitments, profile, floor, payout_floor)
            cp_feasible = models[final].cp_query() is not None
            z3_feasible = models[final].z3_query(True)
            if cp_feasible != z3_feasible:
                raise Incomplete("CP-SAT/Z3 final-prefix feasibility disagreement")
            if not cp_feasible:
                raise Incomplete("profile/prefix inconsistent; no privacy conclusion")
            for position, born in enumerate(births[1:], 1):
                horizons = {born: ["creation"]}
                for end in range(born + 1, len(events)):
                    if events[end]["mode"] == 2:
                        horizons.setdefault(end, []).append("later_drain")
                horizons.setdefault(len(events) - 1, []).append("final")
                for end, labels in sorted(horizons.items()):
                    if end not in models:
                        prefix = dict(data, events=events[:end + 1])
                        prefix_count = events[end]["count_before"] + len(events[end]["new"])
                        models[end] = Pair(prefix, commitments[:prefix_count],
                                           profile, floor, payout_floor)
                    rows.append({
                        "position": position, "created_event": born,
                        "output_slot": events[born]["new"].index(position),
                        "creation_mode": events[born]["mode"],
                        "bootstrap_diagnostic": born == 0,
                        "through_event": end, "horizons": labels,
                        **models[end].bounds(position),
                    })
        except Incomplete as failure:
            error = str(failure)
        profiles[profile] = {
            "complete": error is None, "rows": rows,
            "queries": {kind: sum(m.queries[kind] for m in models.values())
                        for kind in ("cp_sat", "z3")},
        }
        if error is not None:
            profiles[profile]["error"] = error
    return {
        "schema": "kpi-early-privacy-amounts-v1",
        "complete": all(p["complete"] for p in profiles.values()),
        "meaning": "Exact integer extrema and zero feasibility, not a contiguous set or probability",
        "initial_position": {"position": 0, "public_value_sompi": data["initial"]["value"]},
        "created_positions": len(births) - 1,
        "equal_nonzero_commitment_positions": _groups(commitments),
        "profiles": profiles,
        "assumptions": [
            "Commitments bind their note values; equal nonzero commitments imply equal values.",
            "Positions and spending opportunities remain distinct when commitment bytes repeat.",
            "Identifiers otherwise hide linkage; this is an assumption, not a cryptographic test.",
            "Current-wallet shape is a relaxation without common input ownership.",
            "Endpoint witnesses are feasible public models, not observed private state.",
            "Minute is constant zero and unused; destination, funding groups and event IDs do not reveal owners.",
            "Prefix data and native validity must be established by the separate native replay.",
        ],
    }


def analyze(data, commitments):
    return _analyze(data, commitments, FLOOR, PAYOUT_FLOOR)


def _fixture(initial, operations):
    """Tiny public ledgers only; no measured trace or private source is loaded."""
    count, reserve, events = 1, initial, []
    for i, (mode, deposit, payout, anchor) in enumerate(operations):
        reserve += deposit - payout - 1
        new = [] if mode == 2 else [count, count + 1]
        events.append(dict(id=f"tx{i}", minute=0, mode=mode, anchor_count=anchor,
                           count_before=count, new=new, fee=1, deposit=deposit,
                           payout=payout, reserve_out=reserve,
                           destination=f"destination{i}" if payout else None,
                           funding_group=f"funding{i}" if deposit else None))
        count += len(new)
    return dict(schema="kpi-h14-public-v1",
                initial=dict(id="initial", value=initial, funding_group="founding"),
                events=events), [f"{i + 1:064x}" for i in range(count)]


def _enumerate(data, commitments, profile, floor=1, one_input_drain=False):
    """Independent finite ledger traversal, without parser/solver bounds or code.

    Enumerates concrete coins, spent positions and every possible tiny split.
    This is an exponential known-answer oracle, never a real-trace method.
    """
    states = {((data["initial"]["value"],), frozenset(), ())}
    for event in data["events"]:
        following = set()
        for values, spent, history in states:
            live = [p for p in range(event["anchor_count"])
                    if p not in spent and values[p] >= floor]
            sizes = (1,) if one_input_drain and event["mode"] == 2 else (1, 2)
            choices = [()] if event["mode"] == 0 else [
                c for size in sizes for c in itertools.combinations(live, size)]
            for chosen in choices:
                budget = event["deposit"] + sum(values[p] for p in chosen) - event["fee"] - event["payout"]
                if budget < 0:
                    continue
                splits = [()] if event["mode"] == 2 and budget == 0 else []
                if event["mode"] != 2:
                    splits = [(a, budget - a) for a in range(budget + 1)]
                for outputs in splits:
                    if any(v != 0 and v < floor for v in outputs):
                        continue
                    if profile == "current_wallet_shape":
                        if event["mode"] == 0 and outputs != (budget, 0):
                            continue
                        if event["mode"] != 0 and event["anchor_count"] != len(values):
                            continue
                        if event["mode"] == 1 and (outputs[0] < floor or event["payout"] != 0):
                            continue
                    vv, ss = values + outputs, spent | set(chosen)
                    equal = all(commitments[a] == "00" * 32 or commitments[a] != commitments[b] or vv[a] == vv[b]
                                for a in range(len(vv)) for b in range(a))
                    if equal and sum(v for p, v in enumerate(vv) if p not in ss) == event["reserve_out"]:
                        following.add((vv, frozenset(ss), history + (chosen,)))
        states = following
    return states


def controls():
    cases = [
        ("split_ambiguity", *_fixture(5, [(1, 0, 0, 1)]), 1),
        ("later_withdrawal_forces_value", *_fixture(5, [(1, 0, 0, 1), (2, 0, 1, 3), (2, 0, 1, 3)]), 1),
        ("two_real_input_drain", *_fixture(5, [(1, 0, 0, 1), (2, 0, 3, 3)]), 1),
        ("admission_padding", *_fixture(5, [(1, 0, 0, 1), (0, 5, 0, 0)]), 1),
        ("equal_commitment_distinct_spends", *_fixture(9, [(1, 0, 0, 1), (0, 4, 0, 0),
                                                        (2, 0, 2, 5), (2, 0, 2, 5), (2, 0, 4, 5)]), 1),
        ("floor_gap_not_contiguous", *_fixture(9, [(1, 0, 0, 1)]), 2),
        ("future_equality_keeps_birth_horizon", *_fixture(9, [(1, 0, 0, 1), (1, 0, 0, 3)]), 1),
    ]
    summaries, compared = [], 0
    for name, data, commitments, floor in cases:
        if name == "equal_commitment_distinct_spends":
            # Equal across batches, never the two outputs of one transaction.
            commitments[3] = commitments[1]
        if name == "future_equality_keeps_birth_horizon":
            commitments[3] = commitments[1]
        for end in range(1, len(data["events"]) + 1):
            prefix = dict(data, events=data["events"][:end])
            count = prefix["events"][-1]["count_before"] + len(prefix["events"][-1]["new"])
            for profile in PROFILES:
                oracle = _enumerate(prefix, commitments[:count], profile, floor)
                need(oracle, "empty independent control ledger")
                pair = Pair(prefix, commitments[:count], profile, floor, 1)
                for position in range(1, count):
                    expected = {values[position] for values, _, _ in oracle}
                    bounds = pair.bounds(position)
                    need((bounds["minimum_sompi"], bounds["maximum_sompi"], bounds["zero_possible"])
                         == (min(expected), max(expected), 0 in expected), "oracle bound disagreement")
                    # Check gaps as well as extrema: bounds are not interval sets.
                    for value in range(max(expected) + 1):
                        cp = pair.cp_query(pair.cp.values[position] == value) is not None
                        zz = pair.z3_query(pair.z3.values[position] == value)
                        need(cp == zz == (value in expected), "oracle feasible-value disagreement")
                        compared += 1
        oracle = _enumerate(data, commitments, "relation", floor)
        wallet_oracle = _enumerate(data, commitments, "current_wallet_shape", floor)
        if name == "split_ambiguity":
            need({v[1] for v, _, _ in oracle} == {0, 1, 2, 3, 4} and
                 {v[1] for v, _, _ in wallet_oracle} == {1, 2, 3, 4},
                 "split ambiguity fixture changed")
        if name == "later_withdrawal_forces_value":
            birth = _enumerate(dict(data, events=data["events"][:1]), commitments[:3], "relation")
            need(len({v[1] for v, _, _ in birth}) > 1 and
                 {v[1] for v, _, _ in oracle} == {2}, "later forcing fixture changed")
        if name == "admission_padding":
            need({v[4] for v, _, _ in oracle} == {0, 1, 2, 3, 4} and
                 {v[4] for v, _, _ in wallet_oracle} == {0}, "padding profile distinction lost")
        if name == "equal_commitment_distinct_spends":
            need(all(v[1] == v[3] == 3 and set(h[2]) | set(h[3]) == {1, 3}
                     and set(h[2]).isdisjoint(h[3]) for v, _, h in oracle),
                 "equal commitments were merged or not spent independently")
        if name == "floor_gap_not_contiguous":
            need({v[1] for v, _, _ in oracle} == {0, 2, 3, 4, 5, 6, 8},
                 "noncontiguous floor fixture changed")
        if name == "future_equality_keeps_birth_horizon":
            result = _analyze(data, commitments, floor, 1)
            need(result["complete"], "tiny horizon analysis incomplete")
            for profile in PROFILES:
                rows = result["profiles"][profile]["rows"]
                birth = next(r for r in rows if r["position"] == 1 and r["through_event"] == 0)
                final = next(r for r in rows if r["position"] == 1 and r["through_event"] == 1)
                need(birth["maximum_sompi"] == 8 and final["maximum_sompi"] == 7,
                     "future equality leaked into creation horizon")
        summaries.append({"name": name, "passed": True})
    # The 5 -> 4 -> (payout 3 + fee 1) case admits two real inputs 2+2.
    data, commitments = _fixture(5, [(1, 0, 0, 1), (2, 0, 3, 3)])
    for profile in PROFILES:
        oracle = _enumerate(data, commitments, profile)
        need(any(v[1:3] == (2, 2) and h[-1] == (1, 2) for v, _, h in oracle),
             "two-real-input witness missing")
        need(not any(v[1] == 2 for v, _, _ in _enumerate(data, commitments, profile, one_input_drain=True)),
             "single-input mutation did not remove witness")
        pair = Pair(data, commitments, profile, 1, 1)
        for i, e in enumerate(data["events"]):
            if e["mode"] == 2:
                pair.add(sum(pair.cp.select[i]) == 1,
                         z3.PbEq([(s, 1) for s in pair.z3.select[i]], 1))
        need(pair.cp_query(pair.cp.values[1] == 2) is None and
             not pair.z3_query(pair.z3.values[1] == 2), "single-input solver mutation accepted witness")
    summaries.append({"name": "single_input_drain_mutation_detected", "passed": True})
    impossible, commitments = _fixture(5, [(2, 0, 1, 1)])
    result = _analyze(impossible, commitments, 1, 1)
    need(not result["complete"] and all(not p["complete"] for p in result["profiles"].values()),
         "inconsistent zero-output history reported complete")
    summaries.append({"name": "inconsistent_zero_output_history_incomplete", "passed": True})
    return {"passed": True, "complete": True, "controls": summaries, "tiny_feasible_value_comparisons": compared,
            "oracle": "independent exhaustive concrete-ledger traversal",
            "scope": "method calibration controls only; no measured or private trace input"}
