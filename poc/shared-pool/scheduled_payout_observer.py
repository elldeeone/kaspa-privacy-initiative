"""H18 public/one-record observer. No generator, workload seed or true leg map."""
import hashlib
import itertools
import json
import math
from pathlib import Path
import sys
import time

from ortools.sat.python import cp_model

from common_payout_bounds import suffix_domains
from common_payout_observer import CommonModel, is_common, origin_map
from participant_privacy_observer import view_facts
from two_input_privacy_observer import decode, need

Q = 200_000_000
SERVICE = 2
DELAYS = tuple(range(5, 16))
WEIGHTS = (1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1)


def weight(data, born, end):
    """Necessary delay/queue compatibility, deliberately not a posterior."""
    events = data["events"]
    gap = events[end]["minute"] - events[born]["minute"]
    count = end - born  # one service for this tail, plus each intervening event
    return sum(w for d, w in zip(DELAYS, WEIGHTS, strict=True)
               if d + SERVICE <= gap <= d + SERVICE * count)


def timing_graph_valid(data, graph, payout=Q, floor=60_000_000, payout_floor=10_000_000):
    births, _ = decode(data, floor, payout_floor)
    for i, inputs in graph.items():
        for p in inputs:
            born = births[p]
            if born >= 0 and is_common(data["events"][born], payout):
                if data["events"][i]["mode"] != 2 or weight(data, born, i) == 0:
                    return False
    return True


def source_code(sources):
    return sum(1 << (s + 1) for s in set(sources))


def unpack(code):
    return [i - 1 for i in range(code.bit_length()) if code & (1 << i)]


def tie(event_id, candidate):
    return int.from_bytes(hashlib.sha256(
        f"{event_id}:{candidate}".encode()).digest()[:4], "big")


class ScheduledModel:
    def __init__(self, data, view=None, timed=True, payout=Q,
                 floor=60_000_000, payout_floor=10_000_000):
        self.data, self.timed = data, timed
        self.payout, self.floor, self.payout_floor = payout, floor, payout_floor
        self.base = CommonModel(data, view, payout, floor, payout_floor)
        self.integer = self.base.integer
        self.births, self.upper = self.base.births, self.base.upper
        self.search = self.integer.model.clone()
        self.keys, self.allowed, self.cashouts = {}, {}, set()
        self.cache = {i: set() for i in self.integer.select}
        self.queries = self.certificates = 0
        timing_terms, tie_terms = [], []
        for i, selectors in self.integer.select.items():
            e = data["events"][i]
            cashout = e["mode"] == 2 or is_common(e, payout)
            if cashout:
                self.cashouts.add(i)
                key = self.search.new_int_var(-1, len(data["events"]), f"query_origin_{i}")
                for p, s in enumerate(selectors):
                    self.search.add(key == self.integer.origins[p]).only_enforce_if(s)
                    # Entailed single-input equation helps finite-domain search.
                    self.search.add(self.integer.values[p] == sum(
                        self.integer.values[o] for o in e["new"]) + e["payout"] + e["fee"]
                    ).only_enforce_if(s)
                self.allowed[i] = sorted({b for b in self.births if b < i and
                                          (b == -1 or not is_common(data["events"][b], payout))})
            elif e["payout"] == 0:
                born = sorted({self.births[p] for p in range(e["anchor_count"])
                               if self.upper[p] >= floor})
                flags = []
                for b in born:
                    used = self.search.new_bool_var(f"source_{i}_{b}")
                    self.search.add_max_equality(
                        used, [s for p, s in enumerate(selectors) if self.births[p] == b])
                    flags.append(used * (1 << (b + 1)))
                key = self.search.new_int_var(0, (1 << (i + 1)) - 1, f"source_set_{i}")
                self.search.add(key == sum(flags))
                self.allowed[i] = sorted(source_code(c) for size in (1, 2)
                                         for c in itertools.combinations(born, size))
            else:
                key = None
            if key is not None:
                self.keys[i] = key
            for p, selected in enumerate(selectors):
                tie_terms.append(selected * (tie(e["id"], p) % 1000))
                born = self.births[p]
                if born >= 0 and is_common(data["events"][born], payout):
                    w = weight(data, born, i) if e["mode"] == 2 else 0
                    if timed and w == 0:
                        self.search.add(selected == 0)
                    elif w:
                        timing_terms.append(selected * round(1000 * math.log(w)))
        self.objective = sum(timing_terms) * (2000 * len(self.integer.select) + 1) + sum(tie_terms)
        derived = suffix_domains(data, self.births, payout)
        if derived:
            start, domains = derived
            for p, amounts in enumerate(domains):
                cut = self.search.add_linear_expression_in_domain(
                    self.integer.values[p], cp_model.Domain.from_values(amounts))
                used = [ss[p] for i, ss in self.integer.select.items() if i < start and p < len(ss)]
                if used:
                    before = self.search.new_bool_var(f"spent_before_suffix_{p}")
                    self.search.add_max_equality(before, used)
                    cut.only_enforce_if(before.Not())

    def ask(self, target=None, candidates=None, optimize=False):
        model = self.search.clone()
        if target is not None:
            model.add_linear_expression_in_domain(
                self.keys[target], cp_model.Domain.from_values(candidates))
        if optimize:
            model.maximize(self.objective)
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 2
        solver.parameters.random_seed = 0
        self.queries += 1
        status = solver.solve(model)
        if status == cp_model.INFEASIBLE:
            return None
        need(status in (cp_model.OPTIMAL, cp_model.FEASIBLE), "inconclusive integer inference")
        need(not optimize or status == cp_model.OPTIMAL, "incomplete timing optimum")
        graph = {i: tuple(p for p, s in enumerate(ss) if solver.value(s))
                 for i, ss in self.integer.select.items()}
        need(self.integer.check(fixed=graph), "unchanged integer graph certificate failed")
        need(not self.timed or timing_graph_valid(self.data, graph, self.payout,
                                                 self.floor, self.payout_floor),
             "timing graph certificate failed")
        origins = origin_map(self.data, graph, self.payout)
        predictions = {}
        for i, key in self.keys.items():
            actual = origins[graph[i][0]] if i in self.cashouts else source_code(
                self.births[p] for p in graph[i])
            need(actual == solver.value(key), "source expression differs from graph")
            self.cache[i].add(actual)
            predictions[i] = actual
        if target is not None:
            need(predictions[target] in candidates, "query certificate mismatch")
        self.certificates += 1
        self.last_graph = graph
        self.last_objective = round(solver.objective_value) if optimize else None
        return predictions

    def candidates(self, target):
        while pending := sorted(set(self.allowed[target]) - self.cache[target]):
            if self.ask(target, pending) is None:
                break
        result = sorted(self.cache[target])
        need(result, "empty feasible source set")
        return result

    def check_truth(self, private):
        """Called only by the scorer after the complete blinded prediction matrix."""
        model = self.search.clone()
        for p, n in private["notes"].items():
            model.add(self.integer.values[int(p)] == n["value"])
        for i, record in enumerate(private["records"]):
            if i not in self.integer.select:
                continue
            for p, chosen in enumerate(self.integer.select[i]):
                model.add(chosen == int(p in record["inputs"]))
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 1
        status = solver.solve(model)
        need(status in (cp_model.OPTIMAL, cp_model.FEASIBLE), "actual amount/input graph excluded")


def rank(data, model, event, candidates):
    uniform = min(candidates, key=lambda c: (tie(data["events"][event]["id"], c), c))
    if event in model.cashouts:
        recent = max(candidates)
    else:
        recent = max(candidates, key=lambda c: (min(unpack(c)), max(unpack(c)), unpack(c)))
    return dict(uniform=uniform, recent=recent)


def analyze(data, view):
    decode(data)
    if view is not None:
        view_facts(data, view)
    results = {}
    for timed in (False, True):
        model = ScheduledModel(data, view, timed)
        optimum = model.ask(optimize=timed)
        need(optimum is not None, "inconsistent public history/participant/policy")
        rows = []
        for event in sorted(model.keys):
            candidates = model.candidates(event)
            guesses = rank(data, model, event, candidates)
            if timed:
                guesses["timing_graph"] = optimum[event]
            rows.append(dict(event=event, kind="cashout" if event in model.cashouts else "payment",
                             candidates=candidates, guesses=guesses))
        results["timed" if timed else "untimed"] = dict(
            rows=rows, queries=model.queries, integer_certificates=model.certificates)
    untimed = {r["event"]: r for r in results["untimed"]["rows"]}
    for row in results["timed"]["rows"]:
        need(set(row["candidates"]) <= set(untimed[row["event"]]["candidates"]),
             "timing increased exact candidates")
    return results


def main():
    raw = Path(sys.argv[1]).read_bytes()
    raw_view = Path(sys.argv[2]).read_bytes() if sys.argv[2] != "-" else None
    view = json.loads(raw_view) if raw_view is not None else None
    digest = hashlib.sha256(raw).hexdigest()
    if view is not None:
        need(view["public_sha256"] == digest, "view/public identity mismatch")
    start = time.monotonic()
    result = analyze(json.loads(raw), view)
    result.update(input_sha256=digest,
                  view_sha256=hashlib.sha256(raw_view).hexdigest() if raw_view else None,
                  seconds=time.monotonic() - start,
                  meaning="conditional feasible sources and fixed heuristics; not posterior/anonymity")
    with Path(sys.argv[3]).open("x") as out:
        json.dump(result, out, separators=(",", ":"))
        out.write("\n")


if __name__ == "__main__":
    main()
