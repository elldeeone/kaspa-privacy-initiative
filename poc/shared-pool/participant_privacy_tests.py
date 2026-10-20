"""Independent tiny-ledger oracle and disclosure-boundary controls for H16."""
import contextlib
import copy
import io
import itertools
import unittest

from participant_privacy_observer import (
    ParticipantModel, ParticipantZ3Model, ParticipantExactModel, analyze,
    prefix_view, view_facts,
)
from participant_privacy_view import eligible_targets, project
from two_input_privacy_tests import fixture
from wallet_policy_observer import PolicyModel

CLASSES = (ParticipantModel, ParticipantZ3Model, ParticipantExactModel)
DIGEST = "0" * 64


def sample():
    data = fixture(11, [(1, 0, 0, 1), (0, 6, 0, 0), (1, 0, 0, 5),
                        (1, 0, 0, 7), (2, 0, 3, 9), (2, 0, 1, 9),
                        (2, 0, 3, 9), (2, 0, 2, 9)])
    steps = []
    for i, (inputs, owners, values, depositor) in enumerate([
        ([0], [0, 0], [6, 4], None),
        ([], [1, 1], [5, 0], 1),
        ([1], [1, 0], [3, 2], None),
        ([3, 5], [2, 1], [4, 3], None),
    ]):
        steps.append(dict(inputs=inputs, owners=owners, values=values,
                          depositor=depositor, mode=data["events"][i]["mode"],
                          count_before=data["events"][i]["count_before"]))
    plan = dict(initial=11, steps=steps, drains=[
        dict(position=2, owner=0, value=4), dict(position=6, owner=0, value=2),
        dict(position=7, owner=2, value=4), dict(position=8, owner=1, value=3),
    ])
    return data, plan


def ownership_possible(data, view, values, history):
    """Equality components with fixed labels, not solver variables/domains."""
    parent = list(range(len(values)))

    def root(p):
        while parent[p] != p:
            p = parent[p]
        return p

    def join(a, b):
        parent[root(a)] = root(b)

    for i, inputs in history.items():
        for p in inputs[1:]:
            join(inputs[0], p)
        event = data["events"][i]
        if event["mode"] == 1:
            change = event["new"][0 if event["payout"] else 1]
            if values[change]:
                join(inputs[0], change)
    own = {r["position"] for r in view["receipts"]}
    labels = {p: 0 for p in own}
    for record in view["authored"]:
        labels.update({n["position"]: n["recipient"] for n in record["outputs"] if n["value"]})
    components = {}
    for p, label in labels.items():
        components.setdefault(root(p), set()).add(label)
    if any(len(labels) > 1 for labels in components.values()):
        return False
    for p, value in enumerate(values):
        if value and p not in own and components.get(root(p)) == {0}:
            return False
    return True


def enumerate_view(data, view, profile):
    """Exhaustive small integer ledger walk; no parser/model helper reuse."""
    own = {n["position"] for n in view["receipts"]}
    known = {n["position"]: n["value"] for n in view["receipts"]}
    authored = {r["event"]: r["inputs"] for r in view["authored"]}
    for record in view["authored"]:
        known.update({n["position"]: n["value"] for n in record["outputs"]})
    states = [([data["initial"]["value"]], frozenset(), {})]
    if 0 in known and known[0] != data["initial"]["value"]:
        states = []
    for i, e in enumerate(data["events"]):
        following = []
        for values, spent, history in states:
            available = [p for p in range(e["anchor_count"])
                         if p not in spent and values[p] > 0]
            if e["mode"] == 2 and e["anchor_count"] < e["count_before"]:
                a = e["anchor_count"]
                available = [p for p in available if p == 0 and a == 1
                             or a > 1 and a - 2 <= p < a]
            if i in authored:
                choices = [tuple(authored[i])] if set(authored[i]) <= set(available) else []
            elif e["mode"] == 0:
                choices = [()]
            else:
                choices = [c for size in ((1,) if e["mode"] == 2 else (1, 2))
                           for c in itertools.combinations([p for p in available if p not in own], size)]
            for inputs in choices:
                remaining = e["deposit"] + sum(values[p] for p in inputs) - e["payout"] - e["fee"]
                if remaining < 0:
                    continue
                if e["mode"] == 2:
                    outputs = [[]] if remaining == 0 else []
                elif e["mode"] == 0 or e["payout"]:
                    outputs = [[remaining, 0]]
                else:
                    outputs = [[v, remaining - v] for v in range(remaining + 1)]
                for output in outputs:
                    if any(known[p] != v for p, v in zip(e["new"], output) if p in known):
                        continue
                    vv, ss, hh = values + output, spent | set(inputs), dict(history)
                    if inputs:
                        hh[i] = inputs
                    if sum(v for p, v in enumerate(vv) if p not in ss) == e["reserve_out"]:
                        following.append((vv, ss, hh))
        states = following
    if profile == "wallet":
        states = [(v, s, h) for v, s, h in states if ownership_possible(data, view, v, h)]
    return {i: {h[i] for _, _, h in states}
            for i, e in enumerate(data["events"]) if e["mode"] != 0}


class ParticipantControls(unittest.TestCase):
    def test_oracle_all_prefixes_and_profiles(self):
        data, plan = sample()
        for participant in (0, 1, 2):
            view = project(plan, participant, DIGEST)
            for end in range(len(data["events"])):
                prefix = dict(data, events=data["events"][:end + 1])
                records = prefix_view(data, view, end)
                for profile in ("records", "wallet"):
                    oracle = enumerate_view(prefix, records, profile)
                    for cls in CLASSES:
                        model = cls(prefix, records, profile, 1, 1)
                        for target, expected in oracle.items():
                            self.assertEqual(set(model.candidates(target)), expected,
                                             (participant, end, profile, cls.__name__, target))

    def test_received_note_does_not_disclose_sender_inputs_or_change(self):
        data, plan = sample()
        view = project(plan, 1, DIGEST)
        prefix = dict(data, events=data["events"][:3])
        records = prefix_view(data, view, 2)
        facts = view_facts(prefix, records, 1, 1)
        self.assertNotIn(2, facts["authors"])
        self.assertEqual(facts["values"][5], 3)
        self.assertNotIn(6, facts["values"])
        for cls in CLASSES:
            model = cls(prefix, records, "wallet", 1, 1)
            self.assertTrue(model.check(2, (1,)))
            self.assertTrue(model.check(2, (2,)))

    def test_sender_records_do_not_supply_recipients_later_spend(self):
        data, plan = sample()
        facts = view_facts(data, project(plan, 0, DIGEST), 1, 1)
        self.assertIn(5, facts["values"])  # output Alice sent to Bob
        self.assertNotIn(5, facts["receipts"])
        self.assertNotIn(3, facts["authors"])  # Bob's subsequent payment
        self.assertIn(3, eligible_targets(plan, 0))
        self.assertNotIn(2, eligible_targets(plan, 0))  # Alice's payment excluded
        self.assertNotIn(2, eligible_targets(plan, 1))  # Bob's receipt excluded

    def test_projection_ignores_unrelated_amounts_and_inputs(self):
        _, plan = sample()
        original = project(plan, 0, DIGEST)
        changed = copy.deepcopy(plan)
        changed["steps"][3]["inputs"] = [3]
        changed["steps"][3]["values"] = [3, 4]
        changed["drains"][2]["value"] = 3
        changed["drains"][3]["value"] = 4
        self.assertEqual(project(changed, 0, DIGEST), original)

    def test_zero_padding_is_not_a_wallet_receipt(self):
        data, plan = sample()
        view = project(plan, 1, DIGEST)
        self.assertNotIn(4, {n["position"] for n in view["receipts"]})
        admission = next(r for r in view["authored"] if r["event"] == 1)
        self.assertEqual(admission["outputs"][1], dict(position=4, value=0, recipient=None))
        for cls in CLASSES:
            self.assertFalse(cls(data, view, "wallet", 1, 1).check(3, (4, 5)))

    def test_no_disclosure_recovers_h15_without_population_bound(self):
        # A participant with no activity supplies no owner labels. Anonymous
        # authority equalities cannot exclude any H15 history here.
        data = fixture(5, [(1, 0, 0, 1), (0, 5, 0, 0),
                           (2, 0, 3, 5), (2, 0, 3, 5)])
        view = dict(schema="kpi-h16-participant-view-v1", public_sha256=DIGEST,
                    receipts=[], authored=[])
        for cls in CLASSES:
            for target in (0, 2, 3):
                self.assertEqual(set(cls(data, view, "wallet", 1, 1).candidates(target)),
                                 set(PolicyModel(data, "wallet", 1, 1).candidates(target)))

    def test_address_alias_symmetry(self):
        data, plan = sample()
        view = project(plan, 0, DIGEST)
        renamed = copy.deepcopy(view)
        for record in renamed["authored"]:
            for output in record["outputs"]:
                if output["recipient"] == 1:
                    output["recipient"] = 7
        for cls in CLASSES:
            a, b = [cls(data, v, "wallet", 1, 1) for v in (view, renamed)]
            self.assertEqual(set(a.candidates(3)), set(b.candidates(3)))

    def test_owner_change_rule_is_conditional(self):
        # Bob receives output slot 1 from an undisclosed sender, while knowing
        # he authored no spend. This is possible for another client, but it
        # violates the assumed "slot 1 is sender change" rule.
        data = fixture(5, [(1, 0, 0, 1)])
        view = dict(schema="kpi-h16-participant-view-v1", public_sha256=DIGEST,
                    receipts=[dict(position=2, value=2)], authored=[])
        for cls in CLASSES:
            self.assertTrue(cls(data, view, "records", 1, 1).check())
            self.assertFalse(cls(data, view, "wallet", 1, 1).check())

    def test_known_distinct_recipients_cannot_be_merged_by_single_author(self):
        data = fixture(9, [(1, 0, 0, 1), (1, 0, 0, 3),
                           (1, 0, 0, 5), (1, 0, 0, 7)])
        view = dict(schema="kpi-h16-participant-view-v1", public_sha256=DIGEST,
                    receipts=[dict(position=p, value=v) for p, v in [(0, 9), (1, 4), (2, 4)]],
                    authored=[
                        dict(event=0, inputs=[0], outputs=[
                            dict(position=1, value=4, recipient=0), dict(position=2, value=4, recipient=0)]),
                        dict(event=1, inputs=[1], outputs=[
                            dict(position=3, value=3, recipient=1), dict(position=4, value=0, recipient=None)]),
                        dict(event=2, inputs=[2], outputs=[
                            dict(position=5, value=3, recipient=2), dict(position=6, value=0, recipient=None)]),
                    ])
        for cls in CLASSES:
            self.assertTrue(cls(data, view, "records", 1, 1).check(3, (3, 5)))
            self.assertFalse(cls(data, view, "wallet", 1, 1).check(3, (3, 5)))
            for profile in ("records", "wallet"):
                self.assertEqual(set(cls(data, view, profile, 1, 1).candidates(3)),
                                 enumerate_view(data, view, profile)[3])

    def test_contradictory_missing_and_replayed_records_fail(self):
        data, plan = sample()
        good = project(plan, 0, DIGEST)
        mutations = []
        bad = copy.deepcopy(good); bad["receipts"][0]["value"] += 1; mutations.append(bad)
        bad = copy.deepcopy(good); bad["receipts"].pop(0); mutations.append(bad)
        bad = copy.deepcopy(good); bad["authored"][-1]["inputs"] = [2]; mutations.append(bad)
        bad = copy.deepcopy(good); bad["truth"] = {}; mutations.append(bad)
        bad = copy.deepcopy(good); bad["receipts"][0]["value"] = True; mutations.append(bad)
        bad = copy.deepcopy(good); bad["authored"].pop(0); mutations.append(bad)
        for bad in mutations:
            for cls in CLASSES:
                try:
                    possible = cls(data, bad, "wallet", 1, 1).check()
                except ValueError:
                    possible = False
                self.assertFalse(possible)

    def test_earlier_horizons_do_not_use_future_records(self):
        data, plan = sample()
        scale = 60_000_000
        data["initial"]["value"] *= scale
        for e in data["events"]:
            for k in ("fee", "deposit", "payout", "reserve_out"):
                e[k] *= scale
        view = project(plan, 1, DIGEST)
        for row in view["receipts"]:
            row["value"] *= scale
        for row in view["authored"]:
            for output in row["outputs"]:
                output["value"] *= scale
        for profile in ("records", "wallet"):
            with contextlib.redirect_stderr(io.StringIO()):
                result = analyze(data, view, profile)
            for row in result["rows"]:
                for horizon in row["joint"]:
                    end = horizon["through"]
                    prefix = dict(data, events=data["events"][:end + 1])
                    model = ParticipantModel(prefix, prefix_view(data, view, end), profile)
                    self.assertEqual(set(model.candidates(row["event"])),
                                     {tuple(c) for c in horizon["input_sets"]})

    def test_profile_validation_and_wrong_anchor(self):
        data, plan = sample()
        view = project(plan, 1, DIGEST)
        for cls in CLASSES:
            with self.assertRaises(ValueError):
                cls(data, view, "unknown", 1, 1)
            model = cls(data, view, "wallet", 1, 1)
            with self.assertRaises((ValueError, IndexError)):
                model.check(2, (5,))  # future note


if __name__ == "__main__":
    unittest.main()
