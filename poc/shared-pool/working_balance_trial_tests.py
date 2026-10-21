#!/usr/bin/env python3
"""Public handmade controls for the prospective working-balance runner.

No retained attempt, private artifact, random seed, wallet, proof or network
access is used. Temporary files, where needed, contain explicit public fixtures.
Run directly with ``python3 -B working_balance_trial_tests.py``.
"""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import working_balance_trial as trial


CELLS = ("overlap-independent", "sparse-independent",
         "overlap-correlated", "sparse-correlated")
ARMS = ("whole", "partial")
PROFILES = ("C+D", "pooled")


def gate_input(targets=20, amount=10, prior=9, sender=2, recipient=2,
               relationship=2):
    return dict(targets=targets,
                family_max=dict(amount_within_10pct=amount, sender=sender,
                                recipient=recipient, relationship=relationship),
                prior=dict(amount_within_10pct=prior))


def public_fixture():
    """Both withdrawal modes and a merge-shaped target, with no hidden data."""
    events, position, reserve = [], 0, 0
    for i, (mode, payout, group) in enumerate(((0, 0, "initial-0"),
                                             (1, 0, None), (1, 100, None),
                                             (2, 200, None), (0, 0, "later-8"),
                                             (1, 0, None), (1, 0, None),
                                             (2, 300, None))):
        new = [] if mode == 2 else [position, position + 1]
        deposit = 1_000_000_000 if mode == 0 else 0
        reserve += deposit - payout - 40_000_000
        events.append(dict(event=i, event_id=f"public-event-{i}", minute=i,
                           mode=mode, fee=40_000_000, deposit=deposit,
                           payout=payout, reserve=reserve, anchor_count=position,
                           count_before=position, new=new,
                           nullifiers=[f"public-nf-{i}-0", f"public-nf-{i}-1"],
                           destination=None, funding_group=group, bridge=None))
        position += len(new)
    public = dict(schema="kpi-working-balance-public-v1", roles=list(range(32)),
                  adversaries=list(range(8)), events=events,
                  commitments=[f"public-commitment-{i}" for i in range(position)])
    directory = dict(schema="kpi-working-balance-directory-v1",
                     initial_funding_owners={"initial-0": 0, "later-8": 8})
    view = dict(schema="kpi-working-balance-view-v1", members=list(range(8)),
                receipts=[dict(position=i, value=100_000_000, owner=0) for i in (0, 2, 6, 8)],
                authored=[dict(event=i, owner=0, inputs=[], outputs=[]) for i in (0, 2, 4, 6)])
    return public, directory, view


def prediction_fixture(public, profile, end, amount=100, targets=None):
    rows = []
    for event in public["events"][:end + 1]:
        if event["mode"] == 1 and event["payout"] == 0 and (targets is None or event["event"] in targets):
            rows.append(dict(event=event["event"], event_id=event["event_id"],
                             guesses={variant: dict(sender=8, recipient=9, amount=amount,
                                                     relationship_rank=[0, 0, 0, 0])
                                      for variant in trial.variants(profile)}))
    prefix = {**public, "events": public["events"][:end + 1]}
    last = prefix["events"][-1]
    prefix["commitments"] = public["commitments"][:last["count_before"] + len(last["new"])]
    public_hash = hashlib.sha256(json.dumps(prefix, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return dict(schema="kpi-working-balance-predictions-v1", complete=True, profile=profile,
                through_event=end, public_sha256=public_hash, directory_sha256="0" * 64,
                view_sha256="0" * 64, target_events_sha256=trial.canonical([row["event"] for row in rows]), rows=rows,
                boundary="finite arithmetic hypotheses; not exhaustive inference or native evidence")


class PrefixAndPredictionTests(unittest.TestCase):
    def setUp(self):
        self.public, self.directory, self.view = public_fixture()

    def test_positive_payout_spend_is_a_cutoff_not_a_payment_target(self):
        expected = {1: dict(creation=1, next_payout=2, final=7),
                    5: dict(creation=5, next_payout=7, final=7),
                    6: dict(creation=6, next_payout=7, final=7)}
        self.assertEqual(trial.horizons(self.public), expected)
        self.assertEqual(trial.points(self.public), [1, 2, 5, 6, 7])

    def test_missing_later_payout_uses_final_public_prefix(self):
        public = copy.deepcopy(self.public)
        public["events"].pop()
        self.assertEqual(trial.horizons(public)[5]["next_payout"], 6)
        self.assertEqual(trial.horizons(public)[6], dict(creation=6, next_payout=6, final=6))

    def test_targeted_prefix_roster_is_public_and_exactly_bound(self):
        expected = {1: [1], 2: [1], 5: [5], 6: [6], 7: [1, 5, 6]}
        self.assertEqual({end: trial.targets_at(self.public, end) for end in trial.points(self.public)}, expected)
        prediction = prediction_fixture(self.public, "C+D", 6, targets=[6])
        trial.validate_prediction(prediction, self.public, "C+D", 6, targets=[6])
        for mutation in ("missing", "extra-visible", "wrong-hash"):
            bad = copy.deepcopy(prediction)
            if mutation == "missing":
                bad["rows"] = []
            elif mutation == "extra-visible":
                bad["rows"].insert(0, prediction_fixture(self.public, "C+D", 6, targets=[5])["rows"][0])
            else:
                bad["target_events_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                trial.validate_prediction(bad, self.public, "C+D", 6, targets=[6])

    def test_cut_excludes_future_funding_receipts_and_authorship_together(self):
        p, d, v = trial.cut(self.public, self.directory, self.view, 2)
        self.assertEqual(p["events"], self.public["events"][:3])
        self.assertEqual(p["commitments"], self.public["commitments"][:6])
        self.assertEqual(d["initial_funding_owners"], {"initial-0": 0})
        self.assertEqual([r["position"] for r in v["receipts"]], [0, 2])
        self.assertEqual([r["event"] for r in v["authored"]], [0, 2])

    def test_final_cut_preserves_all_declared_public_records(self):
        self.assertEqual(trial.cut(self.public, self.directory, self.view, 7),
                         (self.public, self.directory, self.view))

    def test_all_visible_targets_and_variants_are_required(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                prediction = prediction_fixture(self.public, profile, 6)
                trial.validate_prediction(prediction, self.public, profile, 6)
                for mutation in ("missing-target", "extra-target", "duplicate-target",
                                 "wrong-event-id", "missing-variant", "unknown-variant"):
                    bad = copy.deepcopy(prediction)
                    if mutation == "missing-target":
                        bad["rows"].pop()
                    elif mutation == "extra-target":
                        bad["rows"].append({**copy.deepcopy(bad["rows"][0]), "event": 2,
                                            "event_id": "public-event-2"})
                    elif mutation == "duplicate-target":
                        bad["rows"][-1] = copy.deepcopy(bad["rows"][0])
                    elif mutation == "wrong-event-id":
                        bad["rows"][0]["event_id"] = "public-other-event"
                    elif mutation == "missing-variant":
                        bad["rows"][0]["guesses"].pop(next(iter(bad["rows"][0]["guesses"])))
                    else:
                        bad["rows"][0]["guesses"]["unfrozen-strategy"] = copy.deepcopy(
                            next(iter(bad["rows"][0]["guesses"].values())))
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                        trial.validate_prediction(bad, self.public, profile, 6)

    def test_wrong_profile_or_prefix_rejects(self):
        for field, value in (("profile", "pooled"), ("through_event", 7)):
            bad = prediction_fixture(self.public, "C+D", 6)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                trial.validate_prediction(bad, self.public, "C+D", 6)

    def test_failed_observer_is_not_a_completed_prediction(self):
        bad = prediction_fixture(self.public, "C+D", 6)
        bad["complete"] = False
        with self.assertRaises(ValueError):
            trial.validate_prediction(bad, self.public, "C+D", 6)

    def test_guess_types_ranges_and_rank_shape_reject(self):
        for field, value in (("sender", 32), ("recipient", -1), ("amount", -1),
                             ("amount", True), ("sender", False),
                             ("relationship_rank", [0, 0, 0]),
                             ("relationship_rank", [0, 0, False, 0])):
            bad = prediction_fixture(self.public, "C+D", 6)
            guess = next(iter(bad["rows"][0]["guesses"].values()))
            guess[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                trial.validate_prediction(bad, self.public, "C+D", 6)

    def test_final_retains_both_earlier_guesses_without_reranking(self):
        for profile in PROFILES:
            indexed = {}
            for end, amount in ((1, 111), (2, 222), (7, 777)):
                prediction = prediction_fixture(self.public, profile, end, amount)
                indexed[profile, end] = {row["event"]: row["guesses"] for row in prediction["rows"]}
            ends = dict(creation=1, next_payout=2, final=7)
            guesses = trial.selected_guesses(indexed, profile, 1, ends, "final")
            base = set(trial.variants(profile))
            self.assertEqual(set(guesses), base | {"creation__" + v for v in base}
                             | {"next_payout__" + v for v in base})
            for variant in base:
                self.assertEqual(guesses[variant]["amount"], 777)
                self.assertEqual(guesses["creation__" + variant]["amount"], 111)
                self.assertEqual(guesses["next_payout__" + variant]["amount"], 222)

    def test_pooled_roster_retains_every_unchanged_public_strategy(self):
        public = set(trial.variants("C+D"))
        self.assertEqual(len(public), 13)
        self.assertEqual(set(trial.variants("pooled")), public | {"C_" + v for v in public})


class DecisionBoundaryTests(unittest.TestCase):
    def test_exact_five_percentage_point_boundaries_pass(self):
        whole = gate_input(amount=11)
        partial = gate_input(amount=10, sender=3, recipient=3, relationship=3)
        self.assertTrue(trial.gate_row(whole, partial)["passed"])

    def test_insufficient_amount_reduction_fails(self):
        self.assertFalse(trial.gate_row(gate_input(amount=10), gate_input(amount=10))["passed"])

    def test_prior_advantage_above_five_points_fails(self):
        self.assertFalse(trial.gate_row(gate_input(amount=12), gate_input(amount=11))["passed"])

    def test_each_identity_metric_independently_blocks_regression(self):
        for metric in ("sender", "recipient", "relationship"):
            with self.subTest(metric=metric):
                partial = gate_input(amount=10)
                partial["family_max"][metric] = 4
                self.assertFalse(trial.gate_row(gate_input(amount=11), partial)["passed"])

    def test_thirty_six_targets_need_two_fewer_successes(self):
        whole = gate_input(targets=36, amount=12, prior=9)
        self.assertFalse(trial.gate_row(whole, gate_input(targets=36, amount=11, prior=10))["passed"])
        self.assertTrue(trial.gate_row(whole, gate_input(targets=36, amount=10, prior=9))["passed"])

    def test_thirty_six_targets_allow_one_not_two_prior_excesses(self):
        whole = gate_input(targets=36, amount=12, prior=9)
        self.assertTrue(trial.gate_row(whole, gate_input(targets=36, amount=10, prior=9))["passed"])
        self.assertFalse(trial.gate_row(whole, gate_input(targets=36, amount=10, prior=8))["passed"])

    def test_stress_amount_can_worsen_but_identity_cannot(self):
        whole = gate_input(amount=4, prior=3)
        partial = gate_input(amount=18, prior=3, sender=3, recipient=3, relationship=3)
        self.assertTrue(trial.gate_row(whole, partial, primary=False)["passed"])
        partial["family_max"]["relationship"] = 4
        self.assertFalse(trial.gate_row(whole, partial, primary=False)["passed"])

    def test_unpaired_or_empty_denominators_are_invalid(self):
        for whole_n, partial_n in ((36, 37), (0, 0)):
            with self.subTest(whole=whole_n, partial=partial_n), self.assertRaises(ValueError):
                trial.gate_row(gate_input(targets=whole_n), gate_input(targets=partial_n))


class PredictionMatrixTests(unittest.TestCase):
    def setUp(self):
        # Different arm prefix counts are legitimate; every declared cell is
        # still required. These IDs and indices are all public made-up values.
        self.expected = {(cell, arm, profile, end)
                         for cell in CELLS for arm in ARMS for profile in PROFILES
                         for end in ((32, 34, 40) if arm == "whole" else (32, 35, 41, 43))}
        self.records = [dict(case=c, arm=a, profile=p, through_event=e)
                        for c, a, p, e in sorted(self.expected)]

    def test_complete_case_arm_profile_prefix_matrix_accepts(self):
        trial.sealed_batch_complete(self.expected, self.records)

    def test_every_matrix_dimension_is_mandatory(self):
        for field, value in (("case", CELLS[-1]), ("arm", "partial"),
                             ("profile", "pooled"), ("through_event", 43)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                trial.sealed_batch_complete(self.expected,
                                            [row for row in self.records if row[field] != value])

    def test_duplicate_seal_does_not_replace_a_missing_seal(self):
        records = copy.deepcopy(self.records)
        records[-1] = copy.deepcopy(records[0])
        with self.assertRaises(ValueError):
            trial.sealed_batch_complete(self.expected, records)

    def test_extra_unknown_case_arm_profile_or_prefix_rejects(self):
        for field, value in (("case", "unknown"), ("arm", "third-arm"),
                             ("profile", "P8"), ("through_event", 999)):
            records = copy.deepcopy(self.records)
            records.append({**records[0], field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                trial.sealed_batch_complete(self.expected, records)


def economic_scoring_fixture(extra_merges=0):
    """64 explicit payments, 36 honest pairs, and optional observer-only merges."""
    events, targets, position = [], [], 0

    def append(mode, payout=0):
        nonlocal position
        number = len(events)
        new = [] if mode == 2 else [position, position + 1]
        events.append(dict(event=number, event_id=f"public-score-{number}", mode=mode,
                           payout=payout, count_before=position, new=new))
        position += len(new)
        return number

    for _ in range(32):
        append(0)
    for obligation in range(64):
        number = append(1)
        targets.append(dict(event=number, obligation=obligation,
                            sender=0 if obligation < 14 else 8,
                            recipient=0 if 14 <= obligation < 28 else 9, amount=100))
        if obligation < extra_merges:
            append(1)  # Publicly indistinguishable zero-payout self-merge.
    append(2, payout=100)
    public = dict(events=events, commitments=[f"public-score-cm-{i}" for i in range(position)])
    truth = dict(plan={"public_economic_fixture": 64}, targets=targets)
    predictions = []
    for end in trial.points(public):
        for profile in PROFILES:
            predictions.append(dict(profile=profile, through_event=end,
                                    prediction=prediction_fixture(public, profile, end)))
    return public, truth, predictions


class PairedScoringTests(unittest.TestCase):
    def test_extra_merge_targets_do_not_change_the_36_economic_denominators(self):
        identities = []
        for merges in (0, 7):
            public, truth, predictions = economic_scoring_fixture(merges)
            self.assertEqual(len(trial.horizons(public)), 64 + merges)
            profiles, _, selected = trial.score_arm(public, truth, predictions)
            identities.append(selected)
            self.assertEqual(len(selected), 36)
            for profile in PROFILES:
                for horizon in trial.HORIZONS:
                    result = profiles[profile][horizon]
                    self.assertEqual(result["targets"], 36)
                    for strategy in result["variants"].values():
                        for metric in trial.METRICS:
                            self.assertEqual(strategy[metric]["eligible"], 36)
        self.assertEqual(identities[0], identities[1])

    def test_family_maximum_is_one_aggregate_strategy_not_a_target_oracle(self):
        public, truth, predictions = economic_scoring_fixture()
        primary = {target["event"]: offset for offset, target in enumerate(truth["targets"][28:])}
        for entry in predictions:
            for row in entry["prediction"]["rows"]:
                for name, guess in row["guesses"].items():
                    guess["amount"] = 200
                    if row["event"] in primary and ((name == "residual" and primary[row["event"]] < 18)
                                                    or (name == "coinput" and primary[row["event"]] >= 18)):
                        guess["amount"] = 100
        profiles, _, _ = trial.score_arm(public, truth, predictions)
        for profile in PROFILES:
            for horizon in trial.HORIZONS:
                self.assertEqual(profiles[profile][horizon]["family_max"]["amount_within_10pct"], 18)
                self.assertEqual(profiles[profile][horizon]["prior"]["amount_within_10pct"], 0)

    def test_pooled_family_cannot_hide_success_of_an_unchanged_public_strategy(self):
        public, truth, predictions = economic_scoring_fixture()
        for entry in predictions:
            if entry["profile"] == "pooled":
                for row in entry["prediction"]["rows"]:
                    for name, guess in row["guesses"].items():
                        guess["amount"] = 100 if name.startswith("C_") else 200
        profiles, _, _ = trial.score_arm(public, truth, predictions)
        for horizon in trial.HORIZONS:
            result = profiles["pooled"][horizon]
            self.assertEqual(result["family_max"]["amount_within_10pct"], 36)
            self.assertEqual(result["variants"]["prior"]["amount_within_10pct"]["correct"], 0)

    def test_same_count_but_different_economic_obligation_ids_rejects(self):
        bundles, predictions = {}, []
        for cell in CELLS:
            bundles[cell] = {}
            for arm, merges in (("whole", 0), ("partial", 7)):
                public, truth, entries = economic_scoring_fixture(merges)
                truth.update(cell=cell, arm=arm)
                bundles[cell][arm] = dict(public=public, truth=truth, directory={}, cost={})
                predictions.extend(dict(case=cell, arm=arm, **entry) for entry in entries)
        # Same size and same public obligations; the opened target mapping is
        # wrong in one arm and must not silently compare unrelated successes.
        bundles[CELLS[0]]["partial"]["truth"]["targets"][-1]["obligation"] = 999
        with mock.patch.object(trial, "validate_bundle", return_value={"public_fixture": True}, create=True), \
             self.assertRaises(ValueError):
            trial.score_all(bundles, predictions)

    def test_wrong_truth_cell_or_arm_rejects_before_validation(self):
        for field, wrong in (("cell", CELLS[1]), ("arm", "partial")):
            with self.subTest(field=field):
                truth = dict(cell=CELLS[0], arm="whole", plan={})
                truth[field] = wrong
                bundles = {CELLS[0]: {
                    "whole": {"truth": truth},
                    "partial": {"truth": dict(cell=CELLS[0], arm="partial", plan={})},
                }}
                with mock.patch.object(trial, "validate_bundle") as validate, \
                     self.assertRaisesRegex(ValueError, "truth case and arm binding"):
                    trial.score_all(bundles, [])
                validate.assert_not_called()


def write_public_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def sealed_public_fixture(root):
    """Create a complete seal matrix containing only the handmade public ledger."""
    public, directory, pooled = public_fixture()
    empty = dict(schema="kpi-working-balance-view-v1", members=[], authored=[], receipts=[])
    write_public_json(root / "freeze.json", dict(public_handmade_fixture=True,
                                               frozen_utc="2025-12-31T23:59:50+00:00"))
    generation = dict(complete=True, freeze_sha256=trial.sha(root / "freeze.json"),
                      completed_utc="2026-01-01T00:00:00+00:00", records=[])
    for cell in CELLS:
        for arm in ARMS:
            prefix = f"{cell}-{arm}"
            record = dict(case=cell, arm=arm, views={}, pins={})
            for key, value in (("public", public), ("directory", directory), ("cost", {}),
                               ("truth", {"public_handmade_marker": True})):
                name = ("private/" if key == "truth" else "public/") + prefix + "-" + key + ".json"
                write_public_json(root / name, value)
                record[key] = name
                record["pins"][name] = trial.sha(root / name)
            for profile, view in (("C+D", empty), ("pooled", pooled)):
                name = "public/" + prefix + "-" + ("C" if profile == "C+D" else "pooled") + ".json"
                write_public_json(root / name, view)
                record["views"][profile] = name
                record["pins"][name] = trial.sha(root / name)
            generation["records"].append(record)
    # These are made-up public receipts. No seed file is created or read.
    for stage, start, end in (("controls", 51, 52), ("generate", 55, 56)):
        write_public_json(root / "runs" / stage / "process.json",
                          dict(started_utc=f"2025-12-31T23:59:{start}+00:00",
                               ended_utc=f"2025-12-31T23:59:{end}+00:00", returncode=0))
        write_public_json(root / "runs" / stage / "isolation.json",
                          dict(no_home=True, no_proc=True, interfaces=["lo"], nested_userns_denied=True,
                               mode=stage, mounts=[] if stage == "controls" else ["/seed.json"],
                               truth_mounted=False, seed_mounted=stage == "generate"))
        write_public_json(root / "runs" / stage / "inputs.json",
                          {} if stage == "controls" else {"/seed.json": "1" * 64})
    write_public_json(root / "runs/controls/result.json", dict(passed=True, tests=1))
    controls = dict(passed=True, freeze_sha256=trial.sha(root / "freeze.json"),
                    completed_utc="2025-12-31T23:59:53+00:00",
                    **{name + "_sha256": trial.sha(root / f"runs/controls/{name}.json")
                       for name in ("result", "process", "isolation")})
    write_public_json(root / "controls.json", controls)
    write_public_json(root / "seed-commitment.json",
                      dict(sampled_utc="2025-12-31T23:59:54+00:00",
                           freeze_sha256=trial.sha(root / "freeze.json"),
                           controls_sha256=trial.sha(root / "controls.json"), seed_sha256="1" * 64))
    write_public_json(root / "runs/generate/result.json", dict(complete=True, records=generation["records"]))
    generation.update(seed_commitment_sha256=trial.sha(root / "seed-commitment.json"),
                      **{name + "_sha256": trial.sha(root / f"runs/generate/{name}.json")
                         for name in ("result", "process", "isolation")})
    write_public_json(root / "generation.json", generation)
    records, predictions = [], []
    for source in generation["records"]:
        for end in trial.points(public):
            for profile in PROFILES:
                number = len(records)
                p, d, v = trial.cut(public, directory, empty if profile == "C+D" else pooled, end)
                targets = trial.targets_at(public, end)
                prediction = prediction_fixture(public, profile, end, targets=targets)
                prediction.update(public_sha256=trial.canonical(p), directory_sha256=trial.canonical(d),
                                  view_sha256=trial.canonical(v))
                inputs = {}
                for key, value in (("public", p), ("directory", d), ("view", v), ("targets", targets)):
                    name = f"inputs/observe-{number:04d}/{key}.json"
                    write_public_json(root / name, value)
                    inputs[name] = trial.sha(root / name)
                run_dir = f"runs/observe-{number:04d}"
                result_name, seal_name = run_dir + "/result.json", run_dir + "/seal.json"
                write_public_json(root / result_name, prediction)
                write_public_json(root / run_dir / "inputs.json",
                                  {"/" + Path(name).name: pin for name, pin in inputs.items()})
                write_public_json(root / run_dir / "process.json",
                                  dict(started_utc="2026-01-01T00:00:01+00:00",
                                       ended_utc="2026-01-01T00:00:02+00:00", returncode=0))
                write_public_json(root / run_dir / "isolation.json",
                                  dict(no_home=True, no_proc=True, interfaces=["lo"], nested_userns_denied=True,
                                       mode="observe", mounts=["/public.json", "/directory.json", "/view.json", "/targets.json"],
                                       truth_mounted=False, seed_mounted=False))
                seal = dict(sealed_utc="2026-01-01T00:00:03+00:00",
                            freeze_sha256=trial.sha(root / "freeze.json"),
                            generation_sha256=trial.sha(root / "generation.json"),
                            prediction_file=result_name, prediction_sha256=trial.sha(root / result_name),
                            process_sha256=trial.sha(root / run_dir / "process.json"),
                            isolation_sha256=trial.sha(root / run_dir / "isolation.json"),
                            input_manifest_sha256=trial.sha(root / run_dir / "inputs.json"),
                            inputs=inputs)
                write_public_json(root / seal_name, seal)
                identity = dict(case=source["case"], arm=source["arm"], profile=profile, through_event=end)
                records.append(dict(**identity, seal=seal_name, seal_sha256=trial.sha(root / seal_name)))
                predictions.append(dict(**identity, prediction=prediction))
    write_public_json(root / "predictions.json", predictions)
    batch = dict(complete=True, sealed_utc="2026-01-01T00:00:04+00:00",
                 freeze_sha256=trial.sha(root / "freeze.json"),
                 generation_sha256=trial.sha(root / "generation.json"),
                 predictions_sha256=trial.sha(root / "predictions.json"), records=records)
    write_public_json(root / "prediction-batch.json", batch)
    return generation, batch


class SealBarrierTests(unittest.TestCase):
    def test_score_stage_contains_exact_allowed_files_and_excludes_seed_marker(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            generation, batch = sealed_public_fixture(root)
            write_public_json(root / "private/seed.json", {"public_handmade_marker": True})
            write_public_json(root / "extra-public-marker.json", {"public_handmade_marker": True})
            truth_names = {record["truth"] for record in generation["records"]}
            self.assertEqual(len(truth_names), 8)
            expected = set(trial.public_artifacts(generation, batch)) | truth_names

            stage = trial.stage_score_inputs(root)

            self.assertEqual(stage, root / "score-inputs")
            self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
            actual = {str(path.relative_to(stage)) for path in stage.rglob("*") if path.is_file()}
            self.assertEqual(actual, expected)
            self.assertFalse((stage / "private/seed.json").exists())
            self.assertFalse((stage / "extra-public-marker.json").exists())
            for name in actual:
                self.assertTrue((stage / name).samefile(root / name), name)
            with self.assertRaises(FileExistsError):
                trial.stage_score_inputs(root)

    def test_missing_seal_rejects_before_score_stage_is_created(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            _, batch = sealed_public_fixture(root)
            (root / batch["records"][-1]["seal"]).unlink()

            with self.assertRaisesRegex(ValueError, "missing regular artifact"):
                trial.stage_score_inputs(root)

            self.assertFalse((root / "score-inputs").exists())

    def test_complete_public_seal_matrix_verifies(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            generation, batch = sealed_public_fixture(root)
            verified, predictions = trial.verify_batch(root, generation)
            self.assertEqual(verified, batch)
            self.assertEqual(len(predictions), 4 * 2 * 2 * 5)

    def exercise_internal_score(self, root, generation, should_pass):
        """Use the real verifier; redirect only its fixed sandbox mount paths."""
        original_load, original_sha, original_relative = trial.load, trial.sha, trial.relative
        original_verify, original_read = trial.verify_batch, Path.read_bytes
        events = []
        truth_paths = {root / row["truth"] for row in generation["records"]}

        def mounted(path):
            path = Path(path)
            return root / path.name if str(path) in ("/generation.json", "/prediction-batch.json", "/predictions.json") else path

        def verify(_, source):
            result = original_verify(root, source)
            events.append("all-seals-verified")
            return result

        def read(path):
            if path in truth_paths:
                self.assertIn("all-seals-verified", events)
                events.append("public-fixture-truth-read")
            return original_read(path)

        with mock.patch.object(trial, "load", side_effect=lambda p: original_load(mounted(p))), \
             mock.patch.object(trial, "sha", side_effect=lambda p: original_sha(mounted(p))), \
             mock.patch.object(trial, "relative", side_effect=lambda base, name: original_relative(root if Path(base) == Path("/data") else base, name)), \
             mock.patch.object(trial, "verify_batch", side_effect=verify), \
             mock.patch.object(Path, "read_bytes", read), \
             mock.patch.object(trial, "score_all", return_value={"public_fixture_checked": True}), \
             mock.patch.object(trial, "save"):
            if should_pass:
                trial.internal("score")
            else:
                with self.assertRaises(ValueError):
                    trial.internal("score")
        self.assertEqual(events.count("public-fixture-truth-read"), 8 if should_pass else 0)

    def test_every_truth_read_follows_the_complete_public_seal_barrier(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            generation, _ = sealed_public_fixture(root)
            self.exercise_internal_score(root, generation, True)

    def test_missing_seal_or_changed_result_or_input_blocks_every_truth_read(self):
        for mutation in ("missing-seal", "changed-result", "changed-input"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
                root = Path(folder)
                generation, batch = sealed_public_fixture(root)
                if mutation == "missing-seal":
                    batch["records"].pop()
                    write_public_json(root / "prediction-batch.json", batch)
                else:
                    seal = trial.load(root / batch["records"][-1]["seal"])
                    name = seal["prediction_file"] if mutation == "changed-result" else next(iter(seal["inputs"]))
                    with (root / name).open("a") as output:
                        output.write(" ")
                self.exercise_internal_score(root, generation, False)

    def test_private_path_in_public_metadata_rejects_before_any_truth_bytes(self):
        for mutation in ("generation-public-path", "seal-input-path"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
                root = Path(folder)
                generation, batch = sealed_public_fixture(root)
                source = generation["records"][0]
                if mutation == "generation-public-path":
                    source["public"] = source["truth"]
                    write_public_json(root / "runs/generate/result.json", dict(complete=True, records=generation["records"]))
                    generation["result_sha256"] = trial.sha(root / "runs/generate/result.json")
                    write_public_json(root / "generation.json", generation)
                    batch["generation_sha256"] = trial.sha(root / "generation.json")
                else:
                    record = batch["records"][-1]
                    seal_path = root / record["seal"]
                    seal = trial.load(seal_path)
                    seal["inputs"][source["truth"]] = source["pins"][source["truth"]]
                    write_public_json(seal_path, seal)
                    record["seal_sha256"] = trial.sha(seal_path)
                write_public_json(root / "prediction-batch.json", batch)
                self.exercise_internal_score(root, generation, False)

    def test_sampling_before_completed_controls_rejects_without_truth_or_seed_bytes(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            generation, batch = sealed_public_fixture(root)
            commitment = trial.load(root / "seed-commitment.json")
            commitment["sampled_utc"] = "2025-12-31T23:59:52+00:00"
            write_public_json(root / "seed-commitment.json", commitment)
            generation["seed_commitment_sha256"] = trial.sha(root / "seed-commitment.json")
            write_public_json(root / "generation.json", generation)
            batch["generation_sha256"] = trial.sha(root / "generation.json")
            write_public_json(root / "prediction-batch.json", batch)
            self.exercise_internal_score(root, generation, False)
            self.assertFalse((root / "private/seed.json").exists())

    def test_wrong_generator_seed_mount_or_unexpected_control_input_blocks_truth(self):
        for stage in ("generate", "controls"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
                root = Path(folder)
                generation, _ = sealed_public_fixture(root)
                write_public_json(root / "runs" / stage / "inputs.json", {"/seed.json": "2" * 64})
                self.exercise_internal_score(root, generation, False)
                self.assertFalse((root / "private/seed.json").exists())

    def test_changed_pooled_public_guess_rejects_even_after_resealing(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            generation, batch = sealed_public_fixture(root)
            record = batch["records"][-1]
            self.assertEqual(record["profile"], "pooled")
            seal = trial.load(root / record["seal"])
            predictions = trial.load(root / "predictions.json")
            changed = predictions[-1]["prediction"]
            changed["rows"][0]["guesses"]["C_prior"]["amount"] += 1
            write_public_json(root / seal["prediction_file"], changed)
            write_public_json(root / "predictions.json", predictions)
            seal["prediction_sha256"] = trial.sha(root / seal["prediction_file"])
            write_public_json(root / record["seal"], seal)
            record["seal_sha256"] = trial.sha(root / record["seal"])
            batch["predictions_sha256"] = trial.sha(root / "predictions.json")
            write_public_json(root / "prediction-batch.json", batch)
            self.exercise_internal_score(root, generation, False)

    def test_late_individual_seal_rejects_before_truth_even_with_updated_hash(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            generation, batch = sealed_public_fixture(root)
            record = batch["records"][-1]
            seal = trial.load(root / record["seal"])
            seal["sealed_utc"] = "2026-01-01T00:00:05+00:00"
            write_public_json(root / record["seal"], seal)
            record["seal_sha256"] = trial.sha(root / record["seal"])
            write_public_json(root / "prediction-batch.json", batch)
            self.exercise_internal_score(root, generation, False)

    def test_source_and_runtime_drift_reject_before_execution(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-control-") as folder:
            root = Path(folder)
            for name in (*trial.SOURCES, trial.SPEC):
                path = root / "code" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("public source identity fixture: " + name)
            frozen = dict(schema="kpi-working-balance-freeze-v1",
                          sources={name: trial.sha(root / "code" / name) for name in (*trial.SOURCES, trial.SPEC)},
                          cells=list(trial.CELLS), arms=list(trial.ARMS), profiles=list(trial.PROFILES),
                          horizons=list(trial.HORIZONS), variants={p: list(trial.variants(p)) for p in trial.PROFILES},
                          qualification_pass=False,
                          runtime={"public_runtime_fixture": True})
            write_public_json(root / "freeze.json", frozen)
            with mock.patch.object(trial, "__file__", str(root / "code" / trial.RUNNER)), \
                 mock.patch.object(trial, "runtime_manifest", return_value=frozen["runtime"]):
                self.assertEqual(trial.check(root), frozen)
                with mock.patch.object(trial, "runtime_manifest", return_value={"public_runtime_fixture": False}), \
                     self.assertRaises(ValueError):
                    trial.check(root)
                with (root / "code" / trial.SOURCES[-1]).open("a") as output:
                    output.write(" changed")
                with self.assertRaises(ValueError):
                    trial.check(root)


class ExportStorageTests(unittest.TestCase):
    def manifest(self, root, files):
        write_public_json(root / "manifest.json",
                          dict(schema="kpi-working-balance-export-v1", qualification_pass=False, files=files))

    def test_empty_manifest_is_not_a_verified_export(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-export-control-") as folder:
            root = Path(folder)
            self.manifest(root, {})
            with self.assertRaisesRegex(ValueError, "missing export metadata"):
                trial.verify_export(root)

    def test_wrong_stored_hash_rejects_before_roster_validation(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-export-control-") as folder:
            root = Path(folder)
            blob = b"public handmade export bytes\n"
            (root / "public-fixture.txt").write_bytes(blob)
            self.manifest(root, {"public-fixture.txt": dict(path="public-fixture.txt", encoding="identity",
                          bytes=len(blob), sha256=trial.digest(blob), stored_bytes=len(blob), stored_sha256="0" * 64)})
            with self.assertRaisesRegex(ValueError, "stored export drift"):
                trial.verify_export(root)

    def test_invalid_gzip_rejects_even_with_correct_stored_hash(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-export-control-") as folder:
            root = Path(folder)
            blob = b"public handmade bytes that are not gzip\n"
            (root / "public-fixture.txt.gz").write_bytes(blob)
            self.manifest(root, {"public-fixture.txt": dict(path="public-fixture.txt.gz", encoding="gzip",
                          bytes=len(blob), sha256=trial.digest(blob), stored_bytes=len(blob), stored_sha256=trial.digest(blob))})
            with self.assertRaises(gzip.BadGzipFile):
                trial.verify_export(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
