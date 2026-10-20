"""H15 oracle and negative controls. No economic workload or truth is imported."""
import contextlib
import io
import itertools
import unittest

import z3

from two_input_privacy_observer import Model
from two_input_privacy_tests import fixture
from wallet_policy_observer import (
    PolicyModel, PolicyZ3Model, PolicyExactModel, analyze,
)


def enumerate_policy(data, profile):
    """Independent small integer ledger walk, without SAT/policy helper reuse."""
    states = [([data["initial"]["value"]], frozenset(), {})]
    for i, event in enumerate(data["events"]):
        following = []
        for values, spent, history in states:
            available = [p for p in range(event["anchor_count"])
                         if p not in spent and values[p] > 0]
            if (profile == "wallet" and event["mode"] == 2
                    and event["anchor_count"] < event["count_before"]):
                a = event["anchor_count"]
                available = [p for p in available if p == 0 and a == 1
                             or a > 1 and a - 2 <= p < a]
            choices = ([()] if event["mode"] == 0 else [
                c for size in ((1,) if event["mode"] == 2 else (1, 2))
                for c in itertools.combinations(available, size)
            ])
            for selected in choices:
                remaining = (event["deposit"] + sum(values[p] for p in selected)
                             - event["payout"] - event["fee"])
                if remaining < 0:
                    continue
                if event["mode"] == 2:
                    outputs = [[]] if remaining == 0 else []
                elif event["mode"] == 0 or event["payout"] > 0:
                    outputs = [[remaining, 0]]
                else:
                    outputs = [[v, remaining - v] for v in range(remaining + 1)]
                for output in outputs:
                    vv = values + output
                    used = spent | set(selected)
                    hh = dict(history)
                    if selected:
                        hh[i] = selected
                    if sum(v for p, v in enumerate(vv) if p not in used) == event["reserve_out"]:
                        following.append((vv, used, hh))
        states = following
    return {i: {h[i] for _, _, h in states}
            for i, e in enumerate(data["events"]) if e["mode"] != 0}


class PolicyControls(unittest.TestCase):
    def test_oracle_agreement_all_prefixes(self):
        cases = [
            fixture(5, [(1, 0, 0, 1), (0, 5, 0, 0), (2, 0, 3, 5), (2, 0, 3, 5)]),
            fixture(7, [(1, 0, 0, 1), (0, 5, 0, 0), (1, 0, 2, 5), (2, 0, 3, 7)]),
            fixture(7, [(1, 0, 0, 1), (0, 5, 0, 0), (1, 0, 0, 5), (2, 0, 2, 5)]),
        ]
        for case, data in enumerate(cases):
            for profile in ("shape", "wallet"):
                for end in range(1, len(data["events"]) + 1):
                    prefix = dict(data, events=data["events"][:end])
                    oracle = enumerate_policy(prefix, profile)
                    for cls in (PolicyModel, PolicyZ3Model, PolicyExactModel):
                        model = cls(prefix, profile, 1, 1)
                        for target, expected in oracle.items():
                            self.assertEqual(set(model.candidates(target)), expected,
                                             (case, profile, end, cls.__name__, target))

    def test_current_anchor_keeps_older_note_and_symmetry(self):
        data = fixture(5, [(1, 0, 0, 1), (0, 5, 0, 0),
                           (2, 0, 3, 5), (2, 0, 3, 5)])
        for cls in (PolicyModel, PolicyZ3Model, PolicyExactModel):
            model = cls(data, "wallet", 1, 1)
            self.assertTrue(model.check(2, (1,)))  # born at count 3, current 5
            self.assertTrue(model.check(2, (3,)))  # born at count 5
            self.assertFalse(model.check(2, (4,)))  # known padding
            self.assertFalse(model.check(2, (1, 3)))  # two-note full exit

    def test_stale_anchor_is_conditional_rule(self):
        data = fixture(7, [(1, 0, 0, 1), (0, 5, 0, 0),
                           (1, 0, 0, 5), (2, 0, 2, 5)])
        self.assertTrue(Model(data, 1, 1).check())
        for cls in (PolicyModel, PolicyZ3Model, PolicyExactModel):
            self.assertTrue(cls(data, "shape", 1, 1).check())
            self.assertFalse(cls(data, "wallet", 1, 1).check())

    def test_policy_violation_is_protocol_valid(self):
        # Admission split into two 2-unit notes can drain; default 4+0 cannot.
        data = fixture(5, [(1, 0, 0, 1), (0, 5, 0, 0),
                           (2, 0, 3, 3), (2, 0, 1, 5), (2, 0, 1, 5)])
        self.assertTrue(Model(data, 1, 1).check())
        for profile in ("shape", "wallet"):
            for cls in (PolicyModel, PolicyZ3Model, PolicyExactModel):
                self.assertFalse(cls(data, profile, 1, 1).check())

    def test_fixed_partial_padding(self):
        data = fixture(8, [(1, 0, 2, 1)])
        base = Model(data, 1, 1)
        base.model.add(base.values[2] == 2)
        self.assertTrue(base.check())
        cp = PolicyModel(data, "shape", 1, 1)
        cp.model.add(cp.values[2] == 2)
        self.assertFalse(cp.check())
        smt = PolicyZ3Model(data, "shape", 1, 1)
        smt.solver.add(smt.values[2] == 2)
        self.assertFalse(smt.check())
        self.assertTrue(PolicyExactModel(data, "shape", 1, 1).check())

    def test_singleton_replay_and_wrong_anchor(self):
        data = fixture(5, [(1, 0, 0, 1), (2, 0, 3, 3)])
        for cls in (PolicyModel, PolicyZ3Model, PolicyExactModel):
            model = cls(data, "wallet", 1, 1)
            self.assertFalse(model.check(1, (0,)))
            self.assertTrue(model.check(1, (1,)))
            with self.assertRaises(ValueError):
                model.check(1, (1, 1))
            with self.assertRaises((ValueError, IndexError)):
                model.check(1, (3,))

    def test_reverse_horizons_use_only_prefix_information(self):
        data = fixture(5, [(1, 0, 0, 1), (0, 5, 0, 0),
                           (2, 0, 3, 5), (2, 0, 3, 5)])
        scale = 60_000_000
        data["initial"]["value"] *= scale
        for event in data["events"]:
            for key in ("fee", "deposit", "payout", "reserve_out"):
                event[key] *= scale
        for profile in ("shape", "wallet"):
            with contextlib.redirect_stderr(io.StringIO()):
                result = analyze(data, profile)
            for row in result["rows"]:
                for horizon in row["joint"]:
                    prefix = dict(data, events=data["events"][:horizon["through"] + 1])
                    expected = PolicyModel(prefix, profile).candidates(row["event"])
                    self.assertEqual({tuple(c) for c in horizon["input_sets"]}, set(expected))

    def test_profile_and_input_validation(self):
        data = fixture(5, [(2, 0, 4, 1)])
        for cls in (PolicyModel, PolicyZ3Model, PolicyExactModel):
            with self.assertRaises(ValueError):
                cls(data, "unknown", 1, 1)
            with self.assertRaises(ValueError):
                cls(dict(data, truth={}), "wallet", 1, 1)


if __name__ == "__main__":
    unittest.main()
