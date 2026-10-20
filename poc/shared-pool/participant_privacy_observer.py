"""H16 observer: public chain plus one explicitly bounded participant view.

No generator, full plan, truth, other participant view, key or policy-arm label
is imported. Known-client ownership rules are conditional, not consensus rules.
"""
import hashlib
import json
from pathlib import Path
import sys
import time

import z3

from two_input_privacy_observer import FLOOR, PAYOUT_FLOOR, decode, integer, need, summarize
from two_input_privacy_exact import ExactModel
from wallet_policy_observer import PolicyModel, PolicyZ3Model, eligible

PROFILES = ("records", "wallet")


def view_facts(data, view, floor=FLOOR, payout_floor=PAYOUT_FLOOR):
    births, _ = decode(data, floor, payout_floor)
    need(set(view) == {"schema", "public_sha256", "receipts", "authored"}
         and view["schema"] == "kpi-h16-participant-view-v1", "participant view schema")
    digest = view["public_sha256"]
    need(isinstance(digest, str) and len(digest) == 64
         and all(c in "0123456789abcdef" for c in digest), "public digest framing")
    need(isinstance(view["receipts"], list) and isinstance(view["authored"], list),
         "record lists")
    receipts, values, authors, recipients = {}, {}, {}, {}
    for row in view["receipts"]:
        need(set(row) == {"position", "value"}, "receipt fields")
        p = integer(row["position"], 0, len(births) - 1)
        value = integer(row["value"], floor)
        need(p not in receipts, "duplicate receipt")
        receipts[p] = values[p] = value
    used = set()
    for row in view["authored"]:
        need(set(row) == {"event", "inputs", "outputs"}, "author fields")
        i = integer(row["event"], 0, len(data["events"]) - 1)
        need(i not in authors, "duplicate authored event")
        event = data["events"][i]
        ins = row["inputs"]
        need(isinstance(ins, list) and all(type(p) is int for p in ins)
             and ins == sorted(set(ins)), "authored inputs")
        need((not ins) if event["mode"] == 0 else 1 <= len(ins) <= 2,
             "authored input count")
        need(all(p in receipts and p < event["anchor_count"] for p in ins),
             "author may disclose only its own eligible inputs")
        need(not used.intersection(ins), "disclosed input replay")
        used.update(ins)
        need(isinstance(row["outputs"], list), "authored outputs")
        need([n.get("position") for n in row["outputs"]] == event["new"], "output positions")
        for output in row["outputs"]:
            need(set(output) == {"position", "value", "recipient"}, "output fields")
            p = integer(output["position"], 0, len(births) - 1)
            value = integer(output["value"])
            need(value == 0 or value >= floor, "output floor")
            handle = output["recipient"]
            need(handle is None if value == 0 else type(handle) is int and 0 <= handle < len(births),
                 "recipient handle")
            need(p not in values or values[p] == value, "contradictory disclosed amount")
            need((p in receipts) == (value > 0 and handle == 0), "complete own receipt record")
            values[p] = value
            if value:
                recipients[p] = handle
        authors[i] = tuple(ins)
    return dict(receipts=receipts, values=values, authors=authors, recipients=recipients)


def prefix_view(data, view, end):
    """Discard knowledge that did not exist at this observation time."""
    event = data["events"][end]
    count = event["count_before"] + len(event["new"])
    return dict(view, receipts=[r for r in view["receipts"] if r["position"] < count],
                authored=[r for r in view["authored"] if r["event"] <= end])


class ParticipantModel(PolicyModel):
    def __init__(self, data, view, profile, floor=FLOOR, payout_floor=PAYOUT_FLOOR):
        need(profile in PROFILES, "unknown participant profile")
        super().__init__(data, "wallet", floor, payout_floor)
        facts = view_facts(data, view, floor, payout_floor)
        self.facts = facts
        m = self.model
        for p, value in facts["values"].items():
            m.add(self.values[p] == value)
        for i, selectors in self.select.items():
            if i in facts["authors"]:
                for p, selected in enumerate(selectors):
                    m.add(selected == int(p in facts["authors"][i]))
            else:
                for p in facts["receipts"]:
                    if p < len(selectors):
                        m.add(selectors[p] == 0)
        if profile == "records":
            return
        # Enough anonymous labels to realize any partition of the notes. This
        # is not a four-wallet bound. Known aliases are local to this view.
        limit = len(self.values) + max(facts["recipients"].values(), default=0)
        owners = [m.new_int_var(0, limit, f"owner{p}") for p in range(len(self.values))]
        for p, owner in enumerate(owners):
            if p in facts["receipts"]:
                m.add(owner == 0)
            else:
                m.add(owner >= 1).only_enforce_if(self.positive[p])
        for p, handle in facts["recipients"].items():
            m.add(owners[p] == handle)
        for i, selectors in self.select.items():
            sender = m.new_int_var(0, limit, f"sender{i}")
            if i in facts["authors"]:
                m.add(sender == 0)
            else:
                m.add(sender >= 1)
            for p, selected in enumerate(selectors):
                m.add(owners[p] == sender).only_enforce_if(selected)
            event = data["events"][i]
            if event["mode"] == 1:
                change = event["new"][0 if event["payout"] else 1]
                m.add(owners[change] == sender).only_enforce_if(self.positive[change])


class ParticipantZ3Model(PolicyZ3Model):
    def __init__(self, data, view, profile, floor=FLOOR, payout_floor=PAYOUT_FLOOR,
                 relaxed=False):
        need(profile in PROFILES, "unknown participant profile")
        super().__init__(data, "wallet", floor, payout_floor, relaxed=relaxed)
        facts = view_facts(data, view, floor, payout_floor)
        s = self.solver
        for p, value in facts["values"].items():
            s.add(self.values[p] == value)
        for i, selectors in self.select.items():
            for p, selected in enumerate(selectors):
                if i in facts["authors"]:
                    s.add(selected == (p in facts["authors"][i]))
                elif p in facts["receipts"]:
                    s.add(z3.Not(selected))
        if profile == "records":
            return
        limit = len(self.values) + max(facts["recipients"].values(), default=0)
        owners = [z3.Int(f"owner{p}") for p in range(len(self.values))]
        for p, owner in enumerate(owners):
            s.add(owner >= 0, owner <= limit)
            if p in facts["receipts"]:
                s.add(owner == 0)
            else:
                s.add(z3.Implies(self.values[p] > 0, owner != 0))
        for p, handle in facts["recipients"].items():
            s.add(owners[p] == handle)
        for i, selectors in self.select.items():
            sender = z3.Int(f"sender{i}")
            s.add(sender >= 0, sender <= limit)
            s.add(sender == 0 if i in facts["authors"] else sender > 0)
            for p, selected in enumerate(selectors):
                s.add(z3.Implies(selected, owners[p] == sender))
            event = data["events"][i]
            if event["mode"] == 1:
                change = event["count_before"] + (0 if event["payout"] else 1)
                s.add(z3.Implies(self.values[change] > 0, owners[change] == sender))


class ParticipantExactModel(ExactModel):
    def __init__(self, data, view, profile, floor=FLOOR, payout_floor=PAYOUT_FLOOR):
        self.relaxed = ParticipantZ3Model(data, view, profile, floor, payout_floor, relaxed=True)
        self.integer = ParticipantModel(data, view, profile, floor, payout_floor)
        self.data = data
        self.births = self.integer.births
        self.upper = self.integer.upper
        self.feasible = {i: set() for i in self.integer.select}
        self.queries = self.integer_certificates = self.rejected_relaxations = 0


def analyze(data, view, profile):
    births, upper = decode(data)
    view_facts(data, view)
    rows = [dict(event=i,
                 structural=summarize(eligible(data, i, "wallet"), births),
                 amount=summarize(eligible(data, i, "wallet", upper), births), joint=[])
            for i, e in enumerate(data["events"]) if e["mode"] != 0]
    drains = [i for i, e in enumerate(data["events"]) if e["mode"] == 2]
    queries = certificates = rejected = 0
    for end in reversed(range(len(data["events"]))):
        targets = [r for r in rows if r["event"] == end or end == len(data["events"]) - 1
                   or (end in drains and 0 < r["event"] <= end
                       and data["events"][r["event"]]["mode"] == 1
                       and data["events"][r["event"]]["payout"] == 0)]
        if not targets:
            continue
        prefix = dict(data, events=data["events"][:end + 1])
        model = ParticipantExactModel(prefix, prefix_view(data, view, end), profile)
        need(model.check(), "public history and participant records are inconsistent")
        for row in targets:
            # Later SAT witnesses restrict to this earlier public+view prefix.
            # No later UNSAT answer or future receipt is carried backwards.
            known = ({tuple(c) for c in row["joint"][-1]["input_sets"]}
                     if row["joint"] else set())
            candidates = [c for c in sorted(row["amount"]["input_sets"], key=lambda c: (len(c), c))
                          if tuple(c) in known or model.check(row["event"], c)]
            need(candidates, "empty participant candidate set")
            row["joint"].append(dict(through=end, **summarize(candidates, births)))
            print(f"prefix {end + 1}, event {row['event']}: {len(candidates)} input sets",
                  file=sys.stderr, flush=True)
        queries += model.queries
        certificates += model.integer_certificates
        rejected += model.rejected_relaxations
    for row in rows:
        row["joint"].sort(key=lambda h: h["through"])
    return dict(profile=profile, rows=rows, feasibility_queries=queries,
                integer_certificates=certificates, rejected_relaxations=rejected,
                meaning="conditional public chain plus one participant; not anonymity or probability")


if __name__ == "__main__":
    public = Path(sys.argv[1]).read_bytes()
    raw_view = Path(sys.argv[2]).read_bytes()
    view = json.loads(raw_view)
    need(view["public_sha256"] == hashlib.sha256(public).hexdigest(), "view/public identity")
    started = time.monotonic()
    result = analyze(json.loads(public), view, sys.argv[4])
    result.update(input_sha256=hashlib.sha256(public).hexdigest(),
                  view_sha256=hashlib.sha256(raw_view).hexdigest(),
                  seconds=time.monotonic() - started)
    with Path(sys.argv[3]).open("x") as output:
        json.dump(result, output, separators=(",", ":"))
