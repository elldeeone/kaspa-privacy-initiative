"""Direct integer search of the same H17 relation, with exact certificates."""
import hashlib
import json
from pathlib import Path
import sys
import time

from ortools.sat.python import cp_model
import common_payout_batch_impl as implementation
from common_payout_bounds import suffix_domains
from common_payout_observer import is_common, need, origin_map


class BatchModel(implementation.BatchModel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Preserve the original integer model for independent fixed-graph
        # certification. Only this search clone receives the redundant cuts.
        self.search = self.integer.model.clone()
        self.source_keys = {}
        for i, event in enumerate(self.data["events"]):
            if event["mode"] != 2 and not is_common(event, self.payout):
                continue
            key = self.search.new_int_var(-1, len(self.data["events"]), f"query_origin_{i}")
            self.source_keys[i] = key
            debit = sum(self.integer.values[p] for p in event["new"])
            debit += event["payout"] + event["fee"]
            for p, selected in enumerate(self.integer.select[i]):
                self.search.add(self.integer.values[p] == debit).only_enforce_if(selected)
                self.search.add(key == self.integer.origins[p]).only_enforce_if(selected)
        derived = suffix_domains(self.data, self.births, self.payout)
        if derived is not None:
            start, domains = derived
            for p, amounts in enumerate(domains):
                used = [ss[p] for i, ss in self.integer.select.items()
                        if i < start and p < len(ss)]
                cut = self.search.add_linear_expression_in_domain(
                    self.integer.values[p], cp_model.Domain.from_values(amounts))
                if used:
                    before = self.search.new_bool_var(f"used_before_suffix_{p}")
                    self.search.add_max_equality(before, used)
                    cut.only_enforce_if(before.Not())

    def _ask(self, target=None, allowed=None, origins=False):
        model = self.search.clone()
        if target is not None:
            if origins:
                need(target in self.source_keys, "origin query needs a single-input cashout")
                model.add_linear_expression_in_domain(
                    self.source_keys[target], cp_model.Domain.from_values(allowed))
            else:
                selectors = self.integer.select[target]
                model.add_allowed_assignments(selectors, [
                    [int(p in combo) for p in range(len(selectors))] for combo in allowed])
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 4
        solver.parameters.random_seed = 0
        self.queries += 1
        answer = solver.solve(model)
        if answer == cp_model.INFEASIBLE:
            return False
        need(answer in (cp_model.OPTIMAL, cp_model.FEASIBLE), "inconclusive integer search")
        graph = {i: tuple(p for p, s in enumerate(ss) if solver.value(s))
                 for i, ss in self.integer.select.items()}
        need(self.integer.check(fixed=graph), "integer graph certificate failed")
        provenance = origin_map(self.data, graph, self.payout)
        if target is not None:
            if origins:
                need(len(graph[target]) == 1 and provenance[graph[target][0]] in allowed,
                     "integer source witness missed query")
            else:
                need(graph[target] in allowed, "integer input witness missed query")
        self.integer_certificates += 1
        for i, combo in graph.items():
            self.feasible[i].add(combo)
            if len(combo) == 1:
                self.origins[i].add(provenance[combo[0]])
        return True

    def check(self, target=None, combo=None, origin=None):
        need(origin is None or combo is None, "mixed query")
        if target is None:
            return self._ask()
        if origin is not None:
            return origin in self.origins[target] or self._ask(target, [origin], True)
        need(combo is not None, "missing input query")
        return tuple(combo) in self.feasible[target] or self._ask(target, [tuple(combo)])

    def candidates(self, target, allowed, origins=False):
        allowed = list(allowed)
        cache = self.origins[target] if origins else self.feasible[target]
        while pending := [c for c in allowed if c not in cache]:
            print(f"integer target {target}: {len(pending)} candidates unclassified",
                  file=sys.stderr, flush=True)
            if not self._ask(target, pending, origins):
                break
            need(any(c in cache for c in pending), "integer enumeration made no progress")
        return [c for c in allowed if c in cache]


implementation.BatchModel = BatchModel


if __name__ == "__main__":
    raw = Path(sys.argv[1]).read_bytes()
    raw_view = Path(sys.argv[2]).read_bytes() if sys.argv[2] != "-" else None
    view = json.loads(raw_view) if raw_view is not None else None
    if view is not None:
        need(view["public_sha256"] == hashlib.sha256(raw).hexdigest(), "view identity")
    start = time.monotonic()
    result = implementation.analyze(json.loads(raw), view)
    result.update(input_sha256=hashlib.sha256(raw).hexdigest(),
                  view_sha256=hashlib.sha256(raw_view).hexdigest() if raw_view else None,
                  seconds=time.monotonic()-start, search_backend="CP-SAT integer, four workers")
    with Path(sys.argv[3]).open("x") as out:
        json.dump(result, out, separators=(",", ":"))
