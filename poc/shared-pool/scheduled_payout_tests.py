"""H18 controls: independent enumeration, queue boundaries and honest accounting."""
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import tempfile
import unittest

from common_payout_tests import enumerate_small, sample
from participant_privacy_view import project as tiny_view
from scheduled_payout_generate import accounting, generate, project
from scheduled_payout_observer import (
    ScheduledModel, source_code, timing_graph_valid, unpack, weight,
)
from scheduled_payout_score import family_summary
from two_input_privacy_observer import decode
from two_input_privacy_tests import fixture

HERE = Path(__file__).resolve().parent


def configuration():
    return json.loads((HERE / "scheduled-payout-freeze.json").read_text())


def oracle_timed(data, graph):
    # Independent traversal and explicit queue-delay enumeration. No observer
    # helper or model encoding is called to filter the brute-force graph set.
    births = {-1: -1}
    for i, e in enumerate(data["events"]):
        for p in e["new"]:
            births[p] = i
    for i, inputs in graph.items():
        for p in inputs:
            born = births.get(p, -1)
            if born >= 0 and data["events"][born]["payout"] == 2 and data["events"][born]["mode"] == 1:
                if data["events"][i]["mode"] != 2:
                    return False
                gap = data["events"][i]["minute"] - data["events"][born]["minute"]
                possibilities = {delay + 2 * services for delay in range(5, 16)
                                 for services in range(1, i - born + 1)}
                if gap not in possibilities:
                    return False
    return True


class ScheduledControls(unittest.TestCase):
    def test_timing_and_source_candidates_match_independent_enumeration(self):
        data, plan = sample()
        for e, minute in zip(data["events"], (0, 2, 4, 6, 8, 15, 17), strict=True):
            e["minute"] = minute
        births = [-1] + [i for i, e in enumerate(data["events"]) for _ in e["new"]]
        for who in (None, 0, 1):
            view = tiny_view(plan, who, "0" * 64) if who is not None else None
            all_states = enumerate_small(data, view)
            for timed in (False, True):
                states = [s for s in all_states if not timed or oracle_timed(data, s[2])]
                self.assertTrue(states)
                model = ScheduledModel(data, view, timed, payout=2, floor=1, payout_floor=1)
                self.assertIsNotNone(model.ask(optimize=timed))
                if timed:
                    # Independently compute the full objective on every brute-force
                    # graph, including the smaller public-hash tie objective.
                    def objective(graph):
                        likelihood, tie_score = 0, 0
                        for i, inputs in graph.items():
                            for p in inputs:
                                raw = hashlib.sha256(f"{data['events'][i]['id']}:{p}".encode()).digest()
                                tie_score += int.from_bytes(raw[:4], "big") % 1000
                                b = births[p]
                                if b >= 0 and data["events"][b]["payout"] == 2:
                                    gap = data["events"][i]["minute"] - data["events"][b]["minute"]
                                    weights = [6 - abs(d - 10) for d in range(5, 16)
                                               if d + 2 <= gap <= d + 2 * (i - b)]
                                    likelihood += round(1000 * math.log(sum(weights)))
                        return likelihood * (2000 * len(graph) + 1) + tie_score
                    self.assertEqual(model.last_objective, max(objective(s[2]) for s in states))
                for event in model.keys:
                    expected = {origins[graph[event][0]] if event in model.cashouts else
                                source_code(births[p] for p in graph[event])
                                for _, _, graph, origins in states}
                    self.assertEqual(set(model.candidates(event)), expected)
                    self.assertEqual(set(model.candidates(event)), expected)

    def test_timing_boundary_and_queue_allowance(self):
        data, _ = sample()
        data["events"][2]["minute"] = 10
        end = data["events"][3]
        end["minute"] = 16
        self.assertEqual(weight(data, 2, 3), 0)
        end["minute"] = 17
        self.assertEqual(weight(data, 2, 3), 1)  # d=5 + one service
        end["minute"] = 22
        self.assertEqual(weight(data, 2, 3), 6)  # modal d=10
        end["minute"] = 27
        self.assertEqual(weight(data, 2, 3), 1)
        end["minute"] = 28
        self.assertEqual(weight(data, 2, 3), 0)
        data["events"][4]["minute"] = 29
        self.assertEqual(weight(data, 2, 4), 1)  # d=15 + two services
        data["events"][4]["minute"] = 30
        self.assertEqual(weight(data, 2, 4), 0)

    def test_repeated_common_change_is_rejected_only_by_policy(self):
        data = fixture(14, [(1, 0, 0, 1), (1, 0, 2, 3), (1, 0, 2, 5),
                            (2, 0, 6, 7)])
        for e, minute in zip(data["events"], (0, 2, 9, 18), strict=True):
            e["minute"] = minute
        old = ScheduledModel(data, timed=False, payout=2, floor=1, payout_floor=1)
        new = ScheduledModel(data, timed=True, payout=2, floor=1, payout_floor=1)
        self.assertIsNotNone(old.ask())
        # An ordinary split could supply two independent Q inputs. The timed
        # relation must reject specifically the repeated chain, not all histories.
        graph = {0: (0,), 1: (1,), 2: (3,), 3: (5,)}
        self.assertTrue(old.integer.check(fixed=graph))
        self.assertFalse(timing_graph_valid(data, graph, 2, 1, 1))
        self.assertIsNone(new.ask())  # only this funded chain can support both Qs

    def test_two_positive_inputs_stay_available(self):
        data = fixture(14, [(1, 0, 0, 1), (0, 8, 0, 0), (1, 0, 0, 5),
                            (1, 0, 2, 7), (2, 0, 7, 9), (2, 0, 7, 9)])
        for e, minute in zip(data["events"], (0, 2, 4, 6, 13, 15), strict=True):
            e["minute"] = minute
        for timed in (False, True):
            model = ScheduledModel(data, timed=timed, payout=2, floor=1, payout_floor=1)
            self.assertIsNotNone(model.ask(2, [source_code((0, 1))]))
        self.assertEqual(unpack(source_code((-1, 0, 2))), [-1, 0, 2])

    def test_new_workload_accounting_and_truth(self):
        cfg = configuration()
        template = json.loads((HERE / "two-input-privacy-workloads.json").read_text())
        for regime in ("overlap", "sparse"):
            pair = generate(cfg, template, b"unit-control-not-the-study-seed", regime, regime)
            costs = accounting(cfg, pair)
            self.assertEqual(costs["full"]["transactions"], 19)
            self.assertEqual(costs["scheduled"]["transactions"], 23)
            self.assertEqual(costs["full"]["fees_sompi"], 760_000_000)
            self.assertEqual(costs["scheduled"]["fees_sompi"], 920_000_000)
            for arm, bundle in pair.items():
                public, private = bundle["public"], bundle["private"]
                decode(public)
                self.assertEqual(public["events"][-1]["reserve_out"], 0)
                for who in (None, 0, 1, 2, 3):
                    view = project(private, who, "0" * 64) if who is not None else None
                    for timed in (False, True):
                        ScheduledModel(public, view, timed).check_truth(private)
                bad = copy.deepcopy(private)
                bad["notes"][0]["value"] += 1
                with self.assertRaises(ValueError):
                    ScheduledModel(public).check_truth(bad)

    def test_immediate_exit_and_floor_fallback(self):
        cfg = configuration()
        template = json.loads((HERE / "two-input-privacy-workloads.json").read_text())
        pair = generate(cfg, template, b"immediate-unit", "control", "overlap", "immediate")
        for bundle in pair.values():
            private = bundle["private"]
            for c in private["claims"]:
                if c["owner"] == 0:
                    self.assertFalse(c["shaped"])
                    event = bundle["public"]["events"][c["legs"][0]]
                    self.assertEqual(event["anchor_count"], private["notes"][c["original_position"]]["born"])
            ScheduledModel(bundle["public"]).check_truth(private)
        cfg["payout_sompi"] = 10**12
        pair = generate(cfg, template, b"floor-unit", "control", "overlap")
        self.assertFalse(any(c["shaped"] for c in pair["scheduled"]["private"]["claims"]))
        self.assertEqual(accounting(cfg, pair)["extra_fee_sompi"], 0)

    def test_malformed_range_chronology_and_backing(self):
        cfg = configuration()
        template = json.loads((HERE / "two-input-privacy-workloads.json").read_text())
        public = generate(cfg, template, b"parse-unit", "control", "overlap")["full"]["public"]
        for key, value in (("fee", 0.4), ("reserve_out", -1), ("minute", -1), ("anchor_count", 2)):
            bad = copy.deepcopy(public)
            bad["events"][0][key] = value
            with self.assertRaises(ValueError):
                decode(bad)

    def test_family_comparison_bootstraps_whole_ledgers(self):
        cfg = configuration()
        row = lambda successes: dict(correct=dict(zip(cfg["attacks"], successes)),
                                     unique=False, minimum_candidates=3)
        # Different attacks win in different arms. No per-target oracle choice.
        cases = [dict(full=[row((1, 0, 0)), row((1, 0, 0))],
                      scheduled=[row((0, 1, 0)), row((0, 0, 0))]) for _ in range(12)]
        result = family_summary(cases, cfg)
        self.assertEqual(result["family_accuracy"], {"full": 1, "scheduled": .5})
        self.assertEqual(result["relative_reduction"], .5)
        self.assertEqual(result["paired_improvement_95ci"], [.5, .5])
        self.assertTrue(result["passes"])
        zero = [dict(full=[row((0, 0, 0))], scheduled=[row((0, 0, 0))]) for _ in range(12)]
        self.assertFalse(family_summary(zero, cfg)["passes"])

    def test_incomplete_matrix_cannot_open_private_truth(self):
        spec = importlib.util.spec_from_file_location("h18_controller", HERE / "scheduled-payout.py")
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            controller.save(root / "execution-pins.json", dict(sources={}))
            with self.assertRaises(FileNotFoundError):
                controller.score_all(root)
            self.assertFalse((root / "observation-matrix.json").exists())
            self.assertFalse((root / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
