#!/usr/bin/env python3
"""Public handmade controls for the prospective runner and truth barrier."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import shutil

import price_leakage_trial as trial
import working_balance_trial_tests as fixtures


TIME = "2026-10-22T00:00:00+00:00"


def write(root, name, value):
    path = root/name
    path.parent.mkdir(parents=True, exist_ok=True)
    trial.save(path, value)
    return path


def barrier_fixture(root):
    """Synthetic fixed public receipts; no seed or truth file is ever made."""
    frozen = dict(ledgers=trial.REHEARSAL_COUNT, rehearsal=True, frozen_utc=TIME)
    write(root, "freeze.json", frozen)
    process = dict(started_utc=TIME, ended_utc=TIME, returncode=0)
    for mode in ("controls", "generate"):
        write(root, "runs/"+mode+"/process.json", process)
        write(root, "runs/"+mode+"/isolation.json", trial.isolation_receipt(mode))
    write(root, "runs/controls/result.json", dict(passed=True, tests=1))
    write(root, "runs/controls/inputs.json", {})
    write(root, "controls.json", dict(passed=True, completed_utc=TIME, freeze_sha256=trial.sha(root/"freeze.json"),
        result_sha256=trial.sha(root/"runs/controls/result.json"), process_sha256=trial.sha(root/"runs/controls/process.json"),
        isolation_sha256=trial.sha(root/"runs/controls/isolation.json")))
    write(root, "seed-commitment.json", dict(sampled_utc=TIME, freeze_sha256=trial.sha(root/"freeze.json"),
        controls_sha256=trial.sha(root/"controls.json"), ledgers=trial.REHEARSAL_COUNT, public_seed=True, seed_sha256="a"*64))
    write(root, "runs/generate/inputs.json", {"/seed.json": "a"*64})
    records = []
    for case in trial.ledger_ids(trial.REHEARSAL_COUNT):
        public, directory, pooled = fixtures.public_fixture()
        values = dict(public=public, directory=directory, cost={}, truth=None,
            C=dict(schema="kpi-working-balance-view-v1", members=[], authored=[], receipts=[]), pooled=pooled)
        row = dict(case=case, files=trial.paths(case), pins={})
        for key, name in row["files"].items():
            if key == "truth":
                row["pins"][name] = "b"*64
            else:
                write(root, name, values[key]); row["pins"][name] = trial.sha(root/name)
        records.append(row)
        write(root, "inputs/"+case+"-targets.json", list(trial.base.horizons(public)))
    origin = dict(complete=True, records=records)
    write(root, "runs/generate/result.json", origin)
    write(root, "generation.json", dict(**origin, completed_utc=TIME, freeze_sha256=trial.sha(root/"freeze.json"),
        seed_commitment_sha256=trial.sha(root/"seed-commitment.json"), result_sha256=trial.sha(root/"runs/generate/result.json"),
        process_sha256=trial.sha(root/"runs/generate/process.json"), isolation_sha256=trial.sha(root/"runs/generate/isolation.json")))
    observations, predictions = [], []
    for serial, (case, profile) in enumerate(trial.expected_matrix(frozen)):
        inputs = trial.observer_inputs(root, case, profile)
        public, directory, view, targets = [trial.load(path) for path, _ in inputs]
        prediction = fixtures.prediction_fixture(public, profile, len(public["events"])-1, targets=targets)
        prediction["directory_sha256"] = trial.canonical(directory)
        prediction["view_sha256"] = trial.canonical(view)
        prefix = f"runs/observe-{serial:04d}/"
        write(root, prefix+"result.json", prediction)
        write(root, prefix+"process.json", process)
        write(root, prefix+"isolation.json", trial.isolation_receipt("observe"))
        write(root, prefix+"inputs.json", {mount: trial.sha(path) for path, mount in inputs})
        seal = dict(sealed_utc=TIME, freeze_sha256=trial.sha(root/"freeze.json"), generation_sha256=trial.sha(root/"generation.json"),
            prediction_file=prefix+"result.json", prediction_sha256=trial.sha(root/(prefix+"result.json")),
            process_sha256=trial.sha(root/(prefix+"process.json")), isolation_sha256=trial.sha(root/(prefix+"isolation.json")),
            input_manifest_sha256=trial.sha(root/(prefix+"inputs.json")),
            inputs={str(path.relative_to(root)): trial.sha(path) for path, _ in inputs})
        write(root, prefix+"seal.json", seal)
        observations.append(dict(case=case, profile=profile, seal=prefix+"seal.json", seal_sha256=trial.sha(root/(prefix+"seal.json"))))
        predictions.append(dict(case=case, profile=profile, prediction=prediction))
    write(root, "predictions.json", predictions)
    write(root, "prediction-batch.json", dict(complete=True, sealed_utc=TIME, freeze_sha256=trial.sha(root/"freeze.json"),
        generation_sha256=trial.sha(root/"generation.json"), predictions_sha256=trial.sha(root/"predictions.json"), records=observations))
    return frozen


def replace(path, value):
    path.write_text(json.dumps(value)+"\n")


class FixedDesignTests(unittest.TestCase):
    def test_real_isolated_observer_with_public_handmade_history(self):
        # Controls themselves run inside a namespace forbidding nested userns.
        # The standalone public controls exercise the real bwrap invocation;
        # the complete public rehearsal separately covers it end to end.
        if not Path("/proc").exists():
            self.skipTest("already inside the no-proc, no-nested-userns sandbox")
        from working_balance_observer_tests import Fixture
        fixture = Fixture(); fixture.add(1); fixture.add(2, payout=3_960_000_000)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("code", "runs", "inputs"): (root/name).mkdir()
            shutil.copyfile(trial.HERE/"working_balance_observer.py", root/"code/working_balance_observer.py")
            values = (fixture.public, fixture.directory, fixture.view, list(trial.base.horizons(fixture.public)))
            for name, value in zip(("public", "directory", "view", "targets"), values, strict=True):
                write(root, "inputs/"+name+".json", value)
            folder, prediction = trial.isolated(root, "public-handmade", "observe",
                [(root/"inputs"/(name+".json"), "/"+name+".json") for name in ("public", "directory", "view", "targets")])
            trial.base.validate_prediction(prediction, fixture.public, "C+D", len(fixture.public["events"])-1,
                                           fixture.directory, fixture.view, values[-1])
            self.assertEqual(trial.load(folder/"isolation.json"), trial.isolation_receipt("observe"))

    def test_fixed_counts_and_final_profile_matrix(self):
        self.assertEqual(trial.COUNT, 512)
        self.assertEqual(len(trial.expected_matrix(dict(ledgers=512))), 1024)
        self.assertEqual(len(trial.expected_matrix(dict(ledgers=4))), 8)
        for value in (0, 1, 256, 511, 513, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                trial.ledger_ids(value)

    def test_closed_case_paths(self):
        self.assertTrue(trial.paths("ledger-0000")["truth"].startswith("private/"))
        for case in ("../seed", "ledger-0512", "/private/seed.json", "ledger-0"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                trial.paths(case)

    def test_observer_and_scorer_have_closed_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mode, bad in (("observe", [(root/"truth", "/truth.json")]),
                              ("score", [(root/"seed", "/seed.json")]),
                              ("generate", [(root/"truth", "/truth.json")])):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    trial.isolated(root, "never", mode, bad)
            self.assertFalse((root/"runs").exists())

    def test_prepare_requires_rehearsal_before_new_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)/"fresh"
            with mock.patch.object(trial, "sha", return_value="a"*64), \
                 mock.patch.object(trial, "ROOT", Path(temporary)/"public-repository-fixture"), \
                 mock.patch.object(trial, "plain", side_effect=lambda path, directory=False: Path(path)), \
                 mock.patch.object(trial.base, "runtime_manifest", return_value={}):
                with self.assertRaisesRegex(ValueError, "complete public rehearsal"):
                    trial.prepare(destination)
            self.assertFalse(destination.exists())


class CompleteBarrierTests(unittest.TestCase):
    def test_score_receipt_must_follow_complete_barrier_with_truth_only_at_score(self):
        for mutation in (None, "before-barrier", "wrong-isolation"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); frozen = barrier_fixture(root)
                write(root, "runs/score/result.json", dict(complete=True, qualification_pass=False, rehearsal=True))
                process = dict(started_utc=TIME, ended_utc=TIME, returncode=0)
                isolation = trial.isolation_receipt("score")
                if mutation == "before-barrier":
                    process.update(started_utc="2026-10-21T00:00:00+00:00", ended_utc="2026-10-21T00:00:00+00:00")
                if mutation == "wrong-isolation": isolation["seed_mounted"] = True
                write(root, "runs/score/process.json", process); write(root, "runs/score/isolation.json", isolation)
                write(root, "completion.json", dict(complete=True, completed_utc=TIME, rehearsal=True,
                    ledgers=trial.REHEARSAL_COUNT, qualification_pass=False, freeze_sha256=trial.sha(root/"freeze.json"),
                    score_sha256=trial.sha(root/"runs/score/result.json"), prediction_batch_sha256=trial.sha(root/"prediction-batch.json"),
                    score_process_sha256=trial.sha(root/"runs/score/process.json"), score_isolation_sha256=trial.sha(root/"runs/score/isolation.json")))
                if mutation:
                    with self.assertRaisesRegex(ValueError, "score after barrier"): trial.verify_completion(root, frozen)
                else:
                    completed, batch = trial.verify_completion(root, frozen)
                    self.assertTrue(completed["complete"] and batch["complete"])

    def test_verified_export_rejects_drift_omission_and_private_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/"attempt"; root.mkdir()
            frozen = barrier_fixture(root)
            frozen["sources"] = {}
            for name in (*trial.SOURCES, trial.SPEC):
                write(root, "code/"+name, {"public-source-fixture": name})
                frozen["sources"][name] = trial.sha(root/"code"/name)
            replace(root/"freeze.json", frozen)
            completed = dict(freeze_sha256=trial.sha(root/"freeze.json"))
            write(root, "completion.json", completed)
            for name in ("result", "cases", "process", "isolation", "inputs"):
                write(root, "runs/score/"+name+".json", {})
            batch = trial.load(root/"prediction-batch.json")
            destination = Path(temporary)/"public-export"
            with mock.patch.object(trial, "check", return_value=frozen), \
                 mock.patch.object(trial, "verify_completion", return_value=(completed, batch)):
                result = trial.export(root, destination)
            self.assertTrue(result["exported"])
            receipt = trial.load(root/"export-receipt.json")
            self.assertEqual(receipt["manifest_sha256"], trial.sha(destination/"manifest.json"))
            self.assertTrue(trial.verify_export(destination)["storage_verified"])
            manifest = trial.load(destination/"manifest.json")
            tampered = copy.deepcopy(manifest); tampered["files"].pop("runs/score/cases.json")
            replace(destination/"manifest.json", tampered)
            with self.assertRaisesRegex(ValueError, "complete public export roster"): trial.verify_export(destination)
            tampered = copy.deepcopy(manifest)
            tampered["files"]["private/seed.json"] = dict(next(iter(manifest["files"].values())))
            tampered["files"]["private/seed.json"]["path"] = "private/seed.json"
            replace(destination/"manifest.json", tampered)
            with self.assertRaisesRegex(ValueError, "closed public export paths"): trial.verify_export(destination)
            replace(destination/"manifest.json", manifest)
            (destination/manifest["files"]["runs/score/cases.json"]["path"]).write_bytes(b"drift")
            with self.assertRaisesRegex(ValueError, "stored export drift"): trial.verify_export(destination)

    def test_resume_reuses_all_seals_and_never_samples_again(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); frozen = barrier_fixture(root)
            (root/"predictions.json").unlink(); (root/"prediction-batch.json").unlink()
            stage = root/"score-inputs"
            def score_only(root, label, mode, inputs):
                self.assertEqual((label, mode), ("score", "score"))
                folder = root/"runs/score"; folder.mkdir()
                value = dict(complete=True, qualification_pass=False)
                trial.save(folder/"result.json", value)
                trial.save(folder/"process.json", dict(started_utc=TIME, ended_utc=TIME, returncode=0))
                trial.save(folder/"isolation.json", trial.isolation_receipt("score"))
                return folder, value
            def barrier_then_stage(root, frozen):
                trial.verify_batch(root, frozen)
                return stage
            with mock.patch.object(trial, "check", return_value=frozen), \
                 mock.patch.object(trial.secrets, "token_hex", side_effect=AssertionError("resampled")) as sample, \
                 mock.patch.object(trial, "isolated", side_effect=score_only) as isolated, \
                 mock.patch.object(trial, "stage_score_inputs", side_effect=barrier_then_stage):
                result = trial.run(root, workers=1, resume=True)
            self.assertTrue(result["complete"])
            sample.assert_not_called(); self.assertEqual(isolated.call_count, 1)
            self.assertFalse((root/"private/seed.json").exists())

    def test_complete_public_batch_verifies_without_truth_or_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); frozen = barrier_fixture(root)
            self.assertFalse((root/"private").exists())
            batch, predictions = trial.verify_batch(root, frozen)
            self.assertEqual(len(batch["records"]), 8)
            self.assertEqual(len(predictions), 8)

    def test_missing_duplicate_and_reordered_observations_reject(self):
        for mutation in ("missing", "duplicate", "reordered"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); frozen = barrier_fixture(root)
                batch = trial.load(root/"prediction-batch.json")
                if mutation == "missing": batch["records"].pop()
                elif mutation == "duplicate": batch["records"][-1] = batch["records"][0]
                else: batch["records"].reverse()
                replace(root/"prediction-batch.json", batch)
                with self.assertRaisesRegex(ValueError, "complete sealed"):
                    trial.verify_batch(root, frozen)

    def test_incomplete_barrier_cannot_link_or_mount_truth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); frozen = barrier_fixture(root)
            batch = trial.load(root/"prediction-batch.json"); batch["complete"] = False
            replace(root/"prediction-batch.json", batch)
            with mock.patch.object(trial.os, "link", side_effect=AssertionError("truth link before barrier")) as linked:
                with self.assertRaises(ValueError): trial.stage_score_inputs(root, frozen)
                linked.assert_not_called()
            self.assertFalse((root/"score-inputs").exists())

    def test_truth_substitution_rejects_before_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); frozen = barrier_fixture(root)
            batch = trial.load(root/"prediction-batch.json")
            sealpath = root/batch["records"][0]["seal"]
            seal = trial.load(sealpath)
            name = next(iter(seal["inputs"])); seal["inputs"]["private/seed.json"] = seal["inputs"].pop(name)
            replace(sealpath, seal); batch["records"][0]["seal_sha256"] = trial.sha(sealpath)
            replace(root/"prediction-batch.json", batch)
            with self.assertRaisesRegex(ValueError, "closed observer input"):
                trial.verify_batch(root, frozen)

    def test_wrong_public_strategy_copy_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); frozen = barrier_fixture(root)
            predictions = trial.load(root/"predictions.json")
            predictions[1]["prediction"]["rows"][0]["guesses"]["C_prior"]["amount"] += 1
            prefix = "runs/observe-0001/"
            replace(root/(prefix+"result.json"), predictions[1]["prediction"])
            seal = trial.load(root/(prefix+"seal.json")); seal["prediction_sha256"] = trial.sha(root/(prefix+"result.json"))
            replace(root/(prefix+"seal.json"), seal)
            batch = trial.load(root/"prediction-batch.json"); batch["records"][1]["seal_sha256"] = trial.sha(root/(prefix+"seal.json"))
            replace(root/"predictions.json", predictions); batch["predictions_sha256"] = trial.sha(root/"predictions.json")
            replace(root/"prediction-batch.json", batch)
            with self.assertRaisesRegex(ValueError, "public strategy copies"):
                trial.verify_batch(root, frozen)

    def test_truth_path_cannot_replace_public_generation_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); frozen = barrier_fixture(root)
            generation = trial.load(root/"generation.json")
            generation["records"][0]["files"]["public"] = "private/seed.json"
            with self.assertRaisesRegex(ValueError, "closed generated"):
                trial.generation_sources(root, generation, frozen)

    def test_export_roster_excludes_private_truth_seed_and_score_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); barrier_fixture(root)
            names = trial.public_artifacts(trial.load(root/"generation.json"), trial.load(root/"prediction-batch.json"))
            self.assertEqual(len(names), len(set(names)))
            self.assertTrue(all(not name.startswith(("private/", "score-inputs/")) for name in names))
            self.assertNotIn("private/seed.json", names)
            self.assertIn("seed-commitment.json", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
