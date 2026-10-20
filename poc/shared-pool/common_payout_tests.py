"""Independent small integer/provenance oracle and frozen-policy controls."""
import copy
import itertools
import json
from pathlib import Path
import unittest

from common_payout_generate import build, accounting
from common_payout_bounds import suffix_domains
from common_payout_observer import CommonModel, origin_map
from common_payout_score import claim_metric, costs
from participant_privacy_observer import prefix_view
from participant_privacy_tests import ownership_possible
from participant_privacy_view import project
from two_input_privacy_generate import build as original_build
from two_input_privacy_tests import fixture
from wallet_policy_observer import PolicyModel

HERE = Path(__file__).resolve().parent


def sample():
    data = fixture(14, [(1, 0, 0, 1), (0, 8, 0, 0), (1, 0, 2, 5),
                        (1, 0, 2, 7), (2, 0, 4, 9), (2, 0, 4, 9), (2, 0, 3, 9)])
    steps = []
    for i, (inputs, owners, values, depositor) in enumerate([
        ([0], [0, 0], [8, 5], None), ([], [1, 1], [7, 0], 1),
        ([1], [0, 0], [5, 0], None), ([3], [1, 1], [4, 0], None),
    ]):
        steps.append(dict(inputs=inputs, owners=owners, values=values, depositor=depositor,
                          mode=data["events"][i]["mode"],
                          count_before=data["events"][i]["count_before"]))
    plan = dict(initial=14, steps=steps, drains=[
        dict(position=2, owner=0, value=5), dict(position=5, owner=0, value=5),
        dict(position=7, owner=1, value=4)])
    return data, plan


def enumerate_small(data, view=None, q=2):
    """Walk integer balances and provenance, without SMT/CP or origin_map."""
    own = {r["position"] for r in view["receipts"]} if view else set()
    known = {r["position"]: r["value"] for r in view["receipts"]} if view else {}
    authored = {r["event"]: tuple(r["inputs"]) for r in view["authored"]} if view else {}
    if view:
        for record in view["authored"]:
            known.update({o["position"]: o["value"] for o in record["outputs"]})
    states = [([data["initial"]["value"]], set(), {}, [-1])]
    for i, event in enumerate(data["events"]):
        after = []
        common = event["mode"] == 1 and event["payout"] == q
        for values, spent, history, sources in states:
            available = [p for p in range(event["anchor_count"])
                         if values[p] > 0 and p not in spent]
            if event["mode"] == 0:
                combos = [()]
            elif i in authored:
                combos = [authored[i]] if set(authored[i]) <= set(available) else []
            else:
                combos = [c for size in ((1,) if common or event["mode"] == 2 else (1, 2))
                          for c in itertools.combinations([p for p in available if p not in own], size)]
            for combo in combos:
                if common and len(combo) != 1:
                    continue
                remaining = event["deposit"] + sum(values[p] for p in combo)-event["payout"]-event["fee"]
                if remaining < 0 or common and remaining == 0:
                    continue
                if event["mode"] == 2:
                    outputs = [[]] if remaining == 0 else []
                elif event["mode"] == 0 or event["payout"]:
                    outputs = [[remaining, 0]]
                else:
                    outputs = [[v, remaining-v] for v in range(remaining+1)]
                for output in outputs:
                    if any(known[p] != v for p, v in zip(event["new"], output) if p in known):
                        continue
                    vv, ss, hh = values+output, spent | set(combo), dict(history)
                    if combo:
                        hh[i] = combo
                    oo = sources + ([sources[combo[0]] if common else i]*len(output))
                    if sum(v for p, v in enumerate(vv) if p not in ss) == event["reserve_out"]:
                        after.append((vv, ss, hh, oo))
        states = after
    if view:
        states = [s for s in states if ownership_possible(data, view, s[0], s[2])]
    return states


class CommonPayoutControls(unittest.TestCase):
    def test_suffix_domains_contain_every_enumerated_state(self):
        # Includes repeated cashouts from the same chain, varied earlier
        # splits, and interleaved terminal cashouts; no hidden one-per-owner rule.
        for initial in range(9, 16):
            for middle in range(1, 4):
                last = initial-8-middle
                if last <= 0:
                    continue
                data = fixture(initial, [(1, 0, 0, 1), (1, 0, 2, 3),
                                         (2, 0, middle, 5), (1, 0, 1, 5),
                                         (2, 0, last, 7)])
                # Only the final drain is a supported suffix because the
                # previous partial has a different payout. Earlier Q still
                # follows the one-input policy in this small model.
                states = enumerate_small(data)
                model = CommonModel(data, payout=2, floor=1, payout_floor=1)
                derived = suffix_domains(data, model.births, 2)
                self.assertIsNotNone(derived)
                start, domains = derived
                for values, _, history, _ in states:
                    used = {p for i, c in history.items() if i < start for p in c}
                    for p, value in enumerate(values):
                        if p not in used:
                            self.assertIn(value, domains[p])
                self.assertEqual(model.check(), bool(states))
        data, _ = sample()
        model = CommonModel(data, payout=2, floor=1, payout_floor=1)
        start, domains = suffix_domains(data, model.births, 2)
        for values, _, history, _ in enumerate_small(data):
            used = {p for i, c in history.items() if i < start for p in c}
            for p, value in enumerate(values):
                if p not in used:
                    self.assertIn(value, domains[p])
        repeated = fixture(14, [(1, 0, 0, 1), (1, 0, 2, 3),
                                (1, 0, 2, 5), (2, 0, 6, 7)])
        states = enumerate_small(repeated)
        self.assertTrue(states)
        model = CommonModel(repeated, payout=2, floor=1, payout_floor=1)
        for target in (1, 2, 3):
            expected = {origins[h[target][0]] for _, _, h, origins in states}
            self.assertEqual({o for o in (-1, 0) if model.check(target, origin=o)}, expected)

    def test_suffix_shortcut_disabled_before_drain_and_with_variable_fees(self):
        data, _ = sample()
        partial = dict(data, events=data["events"][:4])
        model = CommonModel(partial, payout=2, floor=1, payout_floor=1)
        self.assertEqual(model.suffix_domains, 0)
        varied = copy.deepcopy(data)
        varied["events"][2]["fee"] += 1
        for e in varied["events"][2:]:
            e["reserve_out"] -= 1
        varied["events"][-1]["payout"] -= 1
        varied["events"][-1]["reserve_out"] += 1
        self.assertIsNone(suffix_domains(varied, model.births, 2))

    def test_independent_integer_and_provenance_oracle(self):
        data, plan = sample()
        for end in (3, 6):
            prefix = dict(data, events=data["events"][:end+1])
            for participant in (None, 0, 1):
                view = prefix_view(data, project(plan, participant, "0"*64), end) if participant is not None else None
                states = enumerate_small(prefix, view)
                self.assertTrue(states)
                model = CommonModel(prefix, view, payout=2, floor=1, payout_floor=1)
                for target in (2, 3, *range(4, end+1)):
                    expected = {origins[h[target][0]] for _, _, h, origins in states}
                    inferred = {origin for origin in (-1, 0, 1)
                                if model.check(target, origin=origin)}
                    self.assertEqual(inferred, expected, (end, participant, target))
                for target in model.integer.select:
                    expected = {h[target] for _, _, h, _ in states}
                    for size in (1, 2):
                        for combo in itertools.combinations(range(prefix["events"][target]["anchor_count"]), size):
                            self.assertEqual(model.check(target, combo=combo), combo in expected)

    def test_one_input_is_client_rule_not_consensus(self):
        data = fixture(5, [(1, 0, 0, 1), (1, 0, 2, 3)])
        graph = {0: (0,), 1: (1, 2)}
        self.assertTrue(PolicyModel(data, "wallet", 1, 1).check(fixed=graph))
        model = CommonModel(data, payout=2, floor=1, payout_floor=1)
        self.assertFalse(model.integer.check(fixed=graph))

    def test_positive_change_floor(self):
        data = fixture(4, [(1, 0, 0, 1), (0, 4, 0, 0), (1, 0, 2, 5)])
        model = CommonModel(data, payout=2, floor=1, payout_floor=1)
        self.assertFalse(model.check())  # each eligible note is <= Q+fee

    def test_common_provenance_cannot_be_reset_by_change(self):
        data, _ = sample()
        graph = {0: (0,), 2: (1,), 3: (3,), 4: (2,), 5: (5,), 6: (7,)}
        origins = origin_map(data, graph, 2)
        self.assertEqual(origins[5], 0)
        self.assertEqual(origins[7], 1)
        wrong = dict(graph)
        wrong[2] = (1, 2)
        with self.assertRaises(ValueError):
            origin_map(data, wrong, 2)

    def test_hidden_leg_matching_does_not_intersect(self):
        # Intersection {1} must not be presented as an observed forced link.
        result = claim_metric([dict(sources=[0, 1]), dict(sources=[1, 2])])
        self.assertFalse(result["linked"])
        self.assertEqual(result["min_leg_candidates"], 2)
        self.assertTrue(claim_metric([dict(sources=[0, 1]), dict(sources=[1])])["linked"])

    def test_future_view_removed_and_bad_receipt_rejected(self):
        data, plan = sample()
        view = project(plan, 1, "0"*64)
        early = prefix_view(data, view, 2)
        self.assertNotIn(7, [r["position"] for r in early["receipts"]])
        self.assertNotIn(3, [r["event"] for r in early["authored"]])
        bad = copy.deepcopy(view)
        bad["receipts"][0]["value"] += 1
        with self.assertRaises(ValueError):
            CommonModel(data, bad, payout=2, floor=1, payout_floor=1)

    def test_frozen_all_fees_prefixes_delay_and_drainage(self):
        manifest = json.loads((HERE / "two-input-privacy-workloads.json").read_text())
        config = json.loads((HERE / "common-payout-freeze.json").read_text())
        self.assertEqual(config["payout_sompi"], 200_000_000)
        for a, s in itertools.product(range(2), repeat=2):
            old_plan, arms, truth = original_build(manifest, a, s)
            plan, data, new_truth, claims = build(old_plan, arms["fresh"],
                                                {str(i): t for i, t in truth.items()}, config)
            self.assertEqual(data["events"][:12], arms["fresh"]["events"][:12])
            self.assertEqual(plan["steps"][:12], old_plan["steps"])
            self.assertEqual(accounting(plan, data)["fees_sompi"], 920_000_000)
            self.assertEqual(len(data["events"]), 23)
            self.assertEqual(len(plan["drains"]), 7)
            self.assertEqual([s["payout"] for s in plan["steps"][12:]], [200_000_000]*4)
            measured = costs(old_plan, arms["fresh"], plan, data, claims)
            self.assertEqual(measured["added_fee_sompi"], 160_000_000)
            self.assertEqual(measured["p95_added_completion_minutes"], 40)
            self.assertEqual(len(new_truth), 20)  # 23 operations minus three admissions

    def test_oversize_policy_fails_without_subsidy(self):
        manifest = json.loads((HERE / "two-input-privacy-workloads.json").read_text())
        config = json.loads((HERE / "common-payout-freeze.json").read_text())
        config["payout_sompi"] = 5_000_000_000
        plan, arms, truth = original_build(manifest, 0, 0)
        with self.assertRaises(ValueError):
            build(plan, arms["fresh"], {str(i): t for i, t in truth.items()}, config)


if __name__ == "__main__":
    unittest.main()
