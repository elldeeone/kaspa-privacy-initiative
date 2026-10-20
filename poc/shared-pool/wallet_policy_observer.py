"""H15 public-only observer, conditional on the known prototype wallet profile.

The protocol relation and H14 results remain unchanged. Policy assumptions are
not consensus rules, and no arm label or private workload is an observer input.
"""
import hashlib
import json
from pathlib import Path
import sys
import time

import z3

from two_input_privacy_exact import ExactModel
from two_input_privacy_observer import (
    FLOOR, PAYOUT_FLOOR, Model, decode, need, possibilities, summarize,
)
from two_input_privacy_z3 import Z3Model

PROFILES = ("shape", "wallet")


def padding_positions(data):
    return {
        e["new"][1]
        for e in data["events"]
        if e["mode"] == 0 or (e["mode"] == 1 and e["payout"] > 0)
    }


def receipt_counts(data, births):
    return [1 if b == -1 else data["events"][b]["count_before"] + 2 for b in births]


def eligible(data, target, profile, upper=None):
    """Public shape/anchor filter; no future amounts or secret choices."""
    need(profile in PROFILES, "unknown wallet profile")
    births, _ = decode(data)
    born = receipt_counts(data, births)
    padding = padding_positions(data)
    event = data["events"][target]
    for combo in possibilities(event, upper):
        if padding.intersection(combo):
            continue
        if event["mode"] == 2:
            if len(combo) != 1:
                continue
            if (profile == "wallet"
                    and event["anchor_count"] < event["count_before"]
                    and born[combo[0]] != event["anchor_count"]):
                continue
        yield combo


class PolicyModel(Model):
    """Original integer CP-SAT relation with explicit client assumptions."""

    def __init__(self, data, profile, floor=FLOOR, payout_floor=PAYOUT_FLOOR):
        need(profile in PROFILES, "unknown wallet profile")
        super().__init__(data, floor, payout_floor)
        self.profile = profile
        for p in padding_positions(data):
            self.model.add(self.values[p] == 0)
        born = receipt_counts(data, self.births)
        for i, selectors in self.select.items():
            event = data["events"][i]
            if event["mode"] != 2:
                continue
            self.model.add(sum(selectors) == 1)
            if profile == "wallet" and event["anchor_count"] < event["count_before"]:
                for p, selected in enumerate(selectors):
                    if born[p] != event["anchor_count"]:
                        self.model.add(selected == 0)


class PolicyZ3Model(Z3Model):
    """Separate SMT encoding of the same additional assumptions."""

    def __init__(self, data, profile, floor=FLOOR, payout_floor=PAYOUT_FLOOR,
                 relaxed=False):
        need(profile in PROFILES, "unknown wallet profile")
        super().__init__(data, floor, payout_floor, relaxed=relaxed)
        for event in data["events"]:
            if event["mode"] == 0 or (event["mode"] == 1 and event["payout"]):
                self.solver.add(self.values[event["count_before"] + 1] == 0)
        for i, selectors in self.select.items():
            event = data["events"][i]
            if event["mode"] != 2:
                continue
            self.solver.add(z3.PbEq([(s, 1) for s in selectors], 1))
            if profile == "wallet" and event["anchor_count"] < event["count_before"]:
                # Derive the creation batch separately from CP-SAT's mapping.
                last_batch = ({0} if event["anchor_count"] == 1 else
                              {event["anchor_count"] - 2, event["anchor_count"] - 1})
                self.solver.add(*[z3.Not(s) for p, s in enumerate(selectors)
                                  if p not in last_batch])


class PolicyExactModel(ExactModel):
    """Rational graph search; every SAT graph gets integer policy validation."""

    def __init__(self, data, profile, floor=FLOOR, payout_floor=PAYOUT_FLOOR):
        self.relaxed = PolicyZ3Model(data, profile, floor, payout_floor, relaxed=True)
        self.integer = PolicyModel(data, profile, floor, payout_floor)
        self.data = data
        self.births = self.integer.births
        self.upper = self.integer.upper
        self.feasible = {i: set() for i in self.integer.select}
        self.queries = self.integer_certificates = self.rejected_relaxations = 0


def analyze(data, profile):
    births, upper = decode(data)
    rows = [
        dict(event=i,
             structural=summarize(eligible(data, i, profile), births),
             amount=summarize(eligible(data, i, profile, upper), births),
             joint=[])
        for i, event in enumerate(data["events"]) if event["mode"] != 0
    ]
    drains = [i for i, event in enumerate(data["events"]) if event["mode"] == 2]
    queries = certificates = rejected = 0
    for end in reversed(range(len(data["events"]))):
        targets = [
            row for row in rows
            if row["event"] == end or end == len(data["events"]) - 1
            or (end in drains and 0 < row["event"] <= end
                and data["events"][row["event"]]["mode"] == 1
                and data["events"][row["event"]]["payout"] == 0)
        ]
        if not targets:
            continue
        model = PolicyExactModel(dict(data, events=data["events"][:end + 1]), profile)
        need(model.check(), "public history violates assumed wallet policy")
        for row in targets:
            # Reuse only positive witnesses from a later prefix under the same
            # policy. Negative answers never cross an observation boundary.
            known = ({tuple(c) for c in row["joint"][-1]["input_sets"]}
                     if row["joint"] else set())
            candidates = [
                c for c in sorted(row["amount"]["input_sets"], key=lambda c: (len(c), c))
                if tuple(c) in known or model.check(row["event"], c)
            ]
            need(candidates, "empty policy candidate set")
            row["joint"].append(dict(through=end, **summarize(candidates, births)))
            print(f"prefix {end + 1}, event {row['event']}: "
                  f"{len(candidates)} input sets", file=sys.stderr, flush=True)
        queries += model.queries
        certificates += model.integer_certificates
        rejected += model.rejected_relaxations
    for row in rows:
        row["joint"].sort(key=lambda h: h["through"])
    return dict(
        profile=profile, rows=rows, feasibility_queries=queries,
        integer_certificates=certificates, rejected_relaxations=rejected,
        funding_clusters=len({data["initial"]["funding_group"]} | {
            e["funding_group"] for e in data["events"] if e["mode"] == 0}),
        common_funder_sensitivity_clusters=1,
        meaning="conditional on known wallet behavior; no probability or anonymity score",
    )


if __name__ == "__main__":
    raw = Path(sys.argv[1]).read_bytes()
    started = time.monotonic()
    result = analyze(json.loads(raw), sys.argv[3])
    result.update(input_sha256=hashlib.sha256(raw).hexdigest(),
                  seconds=time.monotonic() - started)
    with Path(sys.argv[2]).open("x") as output:
        json.dump(result, output, separators=(",", ":"))
