"""Enumerate the same feasible candidates with disjunctive queries.

An accepted graph still needs the unchanged integer certificate. A single
UNSAT answer can eliminate all remaining candidates for a target; neither
timeouts nor partial enumeration produce an output.
"""
import hashlib
import json
from pathlib import Path
import sys
import time

import z3

from common_payout_observer import (
    CommonModel, decode, eligible, is_common, need, prefix_view, summarize,
    view_facts,
)


class BatchModel(CommonModel):
    def candidates(self, target, allowed, origins=False):
        allowed = list(allowed)
        cache = self.origins[target] if origins else self.feasible[target]
        selectors = self.relaxed.select[target]
        if origins:
            event = self.data["events"][target]
            need(event["mode"] == 2 or is_common(event, self.payout),
                 "origin query needs a single-input cashout")
        while pending := [c for c in allowed if c not in cache]:
            if origins:
                choices = [
                    z3.And(s, z3.Or([self.relaxed.origins[p] == c for c in pending]))
                    for p, s in enumerate(selectors)
                ]
            else:
                choices = [z3.And([s if p in c else z3.Not(s)
                                   for p, s in enumerate(selectors)]) for c in pending]
            self.relaxed.solver.push()
            try:
                self.relaxed.solver.add(z3.Or(choices))
                found = self.check()
            finally:
                self.relaxed.solver.pop()
            if not found:
                break
            # Independently derived from the integer-certified graph, rather
            # than trusting an origin variable's SMT model assignment.
            need(any(c in cache for c in pending), "batch witness missed query")
        return [c for c in allowed if c in cache]


def analyze(data, view):
    decode(data)
    if view is not None:
        view_facts(data, view)
    commons = [i for i, e in enumerate(data["events"]) if is_common(e)]
    need(len(commons) == 4, "frozen policy has four common payouts")
    rows = []
    queries = certificates = rejected = 0
    for end in sorted({commons[-1], len(data["events"])-1}, reverse=True):
        prefix = dict(data, events=data["events"][:end+1])
        model = BatchModel(prefix, prefix_view(data, view, end) if view is not None else None)
        need(model.check(), "history/view inconsistent with client policy")
        for i, event in enumerate(prefix["events"]):
            if event["mode"] == 0:
                continue
            if is_common(event) or event["mode"] == 2:
                allowed = sorted({b for b in model.births if b < i
                                  and (b == -1 or not is_common(prefix["events"][b]))})
                candidates = model.candidates(i, allowed, origins=True)
                need(candidates, "empty original source set")
                row = dict(event=i, through=end, kind="cashout", sources=candidates)
            elif event["payout"] == 0 and i > 0:
                candidates = model.candidates(i, eligible(prefix, i, "wallet", model.upper))
                need(candidates, "empty payment input set")
                row = dict(event=i, through=end, kind="payment",
                           **summarize(candidates, model.births))
            else:
                continue
            rows.append(row)
            print(f"through {end}, target {i}: complete", file=sys.stderr, flush=True)
        queries += model.queries
        certificates += model.integer_certificates
        rejected += model.rejected_relaxations
    return dict(rows=rows, queries=queries, integer_certificates=certificates,
                rejected_relaxations=rejected,
                meaning="conditional feasible sources, not people, probabilities or anonymity")


if __name__ == "__main__":
    raw = Path(sys.argv[1]).read_bytes()
    raw_view = Path(sys.argv[2]).read_bytes() if sys.argv[2] != "-" else None
    view = json.loads(raw_view) if raw_view is not None else None
    if view is not None:
        need(view["public_sha256"] == hashlib.sha256(raw).hexdigest(), "view identity")
    start = time.monotonic()
    result = analyze(json.loads(raw), view)
    result.update(input_sha256=hashlib.sha256(raw).hexdigest(),
                  view_sha256=hashlib.sha256(raw_view).hexdigest() if raw_view else None,
                  seconds=time.monotonic()-start)
    with Path(sys.argv[3]).open("x") as out:
        json.dump(result, out, separators=(",", ":"))
