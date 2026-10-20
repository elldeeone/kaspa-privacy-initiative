"""H17 observer. Only public history and at most one participant view enter here.

Common-change provenance is inferred in complete feasible graphs. It is never
looked up in a private leg map. Single-input positive-change Q payouts are a
declared client assumption, not a property of the v6 circuit.
"""
import hashlib
import json
from pathlib import Path
import sys
import time

import z3

from common_payout_bounds import add_suffix_domains
from participant_privacy_observer import (
    ParticipantModel, ParticipantZ3Model, prefix_view, view_facts,
)
from two_input_privacy_observer import FLOOR, PAYOUT_FLOOR, decode, need, summarize
from wallet_policy_observer import PolicyModel, PolicyZ3Model, eligible

PAYOUT = 200_000_000


def is_common(event, payout=PAYOUT):
    return event["mode"] == 1 and event["payout"] == payout


def origin_map(data, graph, payout=PAYOUT):
    """Deterministic provenance in one graph; also checks one-input policy."""
    origins = [-1]
    for i, event in enumerate(data["events"]):
        if is_common(event, payout):
            need(len(graph[i]) == 1, "common payout is not single-input")
            source = origins[graph[i][0]]
        else:
            source = i
        origins.extend([source]*len(event["new"]))
    return origins


def add_policy(model, data, payout, floor, smt):
    """Two independently typed constraints share only the public policy predicate."""
    for i, event in enumerate(data["events"]):
        if not is_common(event, payout):
            continue
        selectors = model.select[i]
        if smt:
            model.solver.add(z3.PbEq([(s, 1) for s in selectors], 1),
                             model.values[event["new"][0]] >= floor)
        else:
            model.model.add(sum(selectors) == 1)
            model.model.add(model.values[event["new"][0]] >= floor)
    if smt:
        origins = [z3.Int(f"origin{p}") for p in range(len(model.values))]
        model.solver.add(origins[0] == -1)
    else:
        origins = [model.model.new_int_var(-1, len(data["events"]), f"origin{p}")
                   for p in range(len(model.values))]
        model.model.add(origins[0] == -1)
    for i, event in enumerate(data["events"]):
        for out in event["new"]:
            if is_common(event, payout):
                for p, selected in enumerate(model.select[i]):
                    if smt:
                        model.solver.add(z3.Implies(selected, origins[out] == origins[p]))
                    else:
                        model.model.add(origins[out] == origins[p]).only_enforce_if(selected)
            elif smt:
                model.solver.add(origins[out] == i)
            else:
                model.model.add(origins[out] == i)
    model.origins = origins


class CommonModel:
    def __init__(self, data, view=None, payout=PAYOUT, floor=FLOOR,
                 payout_floor=PAYOUT_FLOOR):
        if view is None:
            self.integer = PolicyModel(data, "wallet", floor, payout_floor)
            self.relaxed = PolicyZ3Model(data, "wallet", floor, payout_floor, relaxed=True)
        else:
            self.integer = ParticipantModel(data, view, "wallet", floor, payout_floor)
            self.relaxed = ParticipantZ3Model(data, view, "wallet", floor, payout_floor, relaxed=True)
        add_policy(self.integer, data, payout, floor, False)
        add_policy(self.relaxed, data, payout, floor, True)
        # Entailed even over rational amounts: every remaining one-input chain
        # ends in a visible full payout. Keep the independent integer relation
        # unchanged so every returned graph still passes the original check.
        self.suffix_domains = add_suffix_domains(self.relaxed, data, payout)
        self.data, self.payout = data, payout
        self.births, self.upper = self.integer.births, self.integer.upper
        self.feasible = {i: set() for i in self.integer.select}
        self.origins = {i: set() for i in self.integer.select}
        self.queries = self.integer_certificates = self.rejected_relaxations = 0

    def check(self, target=None, combo=None, origin=None):
        need(origin is None or combo is None, "mixed query")
        if target is not None:
            if origin is not None and origin in self.origins[target]:
                return True
            if combo is not None and tuple(combo) in self.feasible[target]:
                return True
        assumptions = []
        if combo is not None:
            assumptions = [s if p in combo else z3.Not(s)
                           for p, s in enumerate(self.relaxed.select[target])]
        if origin is not None:
            assumptions = [z3.Or([z3.And(s, self.relaxed.origins[p] == origin)
                                  for p, s in enumerate(self.relaxed.select[target])])]
            event = self.data["events"][target]
            need(event["mode"] == 2 or is_common(event, self.payout),
                 "origin query needs a single-input cashout")
        while True:
            self.queries += 1
            answer = self.relaxed.solver.check(*assumptions)
            if answer == z3.unsat:
                return False
            need(answer == z3.sat, "inconclusive exact search")
            witness = self.relaxed.solver.model()
            graph = {i: tuple(p for p, s in enumerate(ss)
                              if z3.is_true(witness.eval(s, model_completion=True)))
                     for i, ss in self.relaxed.select.items()}
            if self.integer.check(fixed=graph):
                provenance = origin_map(self.data, graph, self.payout)
                if origin is not None:
                    need(len(graph[target]) == 1 and provenance[graph[target][0]] == origin,
                         "certified graph does not satisfy origin query")
                self.integer_certificates += 1
                for i, c in graph.items():
                    self.feasible[i].add(c)
                    if len(c) == 1:
                        self.origins[i].add(provenance[c[0]])
                return True
            self.rejected_relaxations += 1
            self.relaxed.solver.add(z3.Or([
                z3.Not(s) if p in graph[i] else s
                for i, ss in self.relaxed.select.items() for p, s in enumerate(ss)]))


def analyze(data, view):
    decode(data)
    if view is not None:
        view_facts(data, view)
    # Horizons are derived solely from visible payouts, never a hidden cut index.
    commons = [i for i, e in enumerate(data["events"]) if is_common(e)]
    need(len(commons) == 4, "frozen policy has four common payouts")
    ends = sorted({commons[-1], len(data["events"])-1}, reverse=True)
    output = []
    queries = certificates = rejected = 0
    for end in ends:
        prefix = dict(data, events=data["events"][:end+1])
        model = CommonModel(prefix, prefix_view(data, view, end) if view is not None else None)
        need(model.check(), "history/view inconsistent with client policy")
        for i, event in enumerate(prefix["events"]):
            if event["mode"] == 0:
                continue
            if is_common(event) or event["mode"] == 2:
                possibilities = sorted({b for b in model.births if b < i
                                        and (b == -1 or not is_common(prefix["events"][b]))})
                candidates = [b for b in possibilities if model.check(i, origin=b)]
                need(candidates, "empty original source set")
                row = dict(event=i, through=end, kind="cashout", sources=candidates)
            elif event["payout"] == 0 and i > 0:
                candidates = [c for c in eligible(prefix, i, "wallet", model.upper)
                              if model.check(i, combo=c)]
                need(candidates, "empty payment input set")
                row = dict(event=i, through=end, kind="payment",
                           **summarize(candidates, model.births))
            else:
                continue
            output.append(row)
            print(f"through {end}, target {i}: complete", file=sys.stderr, flush=True)
        queries += model.queries
        certificates += model.integer_certificates
        rejected += model.rejected_relaxations
    return dict(rows=output, queries=queries, integer_certificates=certificates,
                rejected_relaxations=rejected,
                meaning="conditional feasible sources, not people, probabilities or anonymity")


if __name__ == "__main__":
    raw = Path(sys.argv[1]).read_bytes()
    raw_view = Path(sys.argv[2]).read_bytes() if sys.argv[2] != "-" else None
    view = json.loads(raw_view) if raw_view is not None else None
    if view is not None:
        need(view["public_sha256"] == hashlib.sha256(raw).hexdigest(), "view identity")
    started = time.monotonic()
    result = analyze(json.loads(raw), view)
    result.update(input_sha256=hashlib.sha256(raw).hexdigest(),
                  view_sha256=hashlib.sha256(raw_view).hexdigest() if raw_view is not None else None,
                  seconds=time.monotonic()-started)
    with Path(sys.argv[3]).open("x") as out:
        json.dump(result, out, separators=(",", ":"))
