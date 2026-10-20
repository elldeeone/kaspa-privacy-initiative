#!/usr/bin/env python3
"""Freeze eight public guessing runs, seal the whole batch, then score separately.

The observer sees one public history and its pooled participant view. Only the
separate scorer can read that history's truth. No seeds are read or generated.
All artifacts are create-only: failed attempts remain evidence, not retries.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import early_privacy_surface as surface
import population_privacy_trial as original
from early_privacy_surface import dependency_manifest, need, read, sandbox, save, sha

HERE = Path(__file__).resolve().parent
RUNNER = "population_privacy_heuristic_trial.py"
SOURCES = original.SOURCES + ("population_privacy_heuristic.py", RUNNER)
NOTES = ("POPULATION-PRIVACY-SPEC.md", "POPULATION-PRIVACY-METHOD-05.md")
VARIANTS = ("baseline", "cashout_total", "cashout_half", "known_note_residual")
STRATA = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
METRICS = ("sender", "recipient", "amount_within_10pct", "amount_exact")


def cases(generation):
    expected = [(f"set-{i:02}-{arm}", regime, arm)
                for i, regime in enumerate(original.REGIMES, 1)
                for arm in ("persistent", "prompt")]
    need(generation["complete"] is True and generation["independent_request_sets"] == 4,
         "source histories incomplete or request sets changed")
    records = generation["cases"]
    need([(c["name"], c["regime"], c["arm"]) for c in records] == expected,
         "must preserve all eight original histories in original order")
    need(all(c["complete"] is True and c["ordinary_payments"] == 64 for c in records),
         "incomplete or changed payment workload")
    return records


def prepare(output, source):
    need(not output.is_relative_to(HERE.parents[1]), "attempt must be outside Git")
    previous = original.check(source)
    cases(read(source / "generation.json"))
    output.mkdir(mode=0o700)
    (output / "code").mkdir(mode=0o700)
    (output / "runs").mkdir(mode=0o700)
    for name in SOURCES + NOTES:
        # Reuse the original frozen specification/model/workload bytes exactly.
        origin = source / "code" / name if name in previous["sources"] else HERE / name
        shutil.copyfile(origin, output / "code" / name)
    save(output / "freeze.json", dict(
        schema="kpi-population-heuristic-freeze-v1", observer="heuristic",
        source_attempt=str(source), source_freeze_sha256=sha(source / "freeze.json"),
        generation_sha256=sha(source / "generation.json"),
        sources={name: sha(output / "code" / name) for name in SOURCES + NOTES},
        dependency_root=previous["dependency_root"], dependencies=previous["dependencies"],
        scope="All eight original histories, pooled view, final horizon; deterministic guesses",
        scoring_barrier="Seal all eight predictions and the batch manifest before any scorer",
        new_seeds_generated=False, qualification_pass=False))
    return dict(prepared=True, source_attempt=str(source),
                freeze_sha256=sha(output / "freeze.json"))


def check(output):
    frozen = read(output / "freeze.json")
    need(frozen["schema"] == "kpi-population-heuristic-freeze-v1" and
         frozen["observer"] == "heuristic", "unknown frozen observer")
    need(set(frozen["sources"]) == set(SOURCES + NOTES), "source closure changed")
    for module in (surface, original):
        path = Path(module.__file__).resolve()
        need(sha(path) == frozen["sources"][path.name], "loaded host helper changed")
    need(sha(Path(__file__).resolve()) == frozen["sources"][RUNNER], "loaded runner changed")
    for name, expected in frozen["sources"].items():
        need(sha(output / "code" / name) == expected, "frozen source changed: " + name)
    source = Path(frozen["source_attempt"])
    need(sha(source / "freeze.json") == frozen["source_freeze_sha256"] and
         sha(source / "generation.json") == frozen["generation_sha256"], "source attempt changed")
    previous = read(source / "freeze.json")
    for name in original.SOURCES + (original.SPEC,):
        need(frozen["sources"][name] == previous["sources"][name], "original frozen bytes changed")
    need(dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
         "dependency bytes changed")
    return frozen


def isolated(output, frozen, label, mode, inputs=()):
    allowed = {"_controls": (), "_observe": ("/public.json", "/view.json"),
               "_score": ("/public.json", "/view.json", "/prediction.json", "/truth.json")}
    mounts = tuple(mount for _, mount in inputs)
    need(mode in allowed and mounts == allowed[mode], "unexpected isolated input mounts")
    need(frozen["observer"] == "heuristic", "unknown observer")
    destination = output / "runs" / label
    destination.mkdir(mode=0o700)
    command = sandbox() + ["--setenv", "KPI_OBSERVER_MODULE", "heuristic",
                           "--ro-bind", frozen["dependency_root"], "/venv",
                           "--bind", str(destination), "/output"]
    for name in SOURCES:
        command += ["--ro-bind", str(output / "code" / name), "/" + name]
    for path, mount in inputs:
        command += ["--ro-bind", str(path), mount]
    probe = ("import pathlib,json;assert not pathlib.Path('/home').exists();"
             "interfaces=[x.split(':')[0].strip() for x in "
             "pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x];"
             "assert interfaces==['lo'];print(json.dumps({'interfaces':interfaces,"
             "'home_accessible':False}))")
    tested = subprocess.run(command + ["--", "/venv/bin/python", "-c", probe],
                            capture_output=True, text=True, check=True)
    isolation = json.loads(tested.stdout)
    isolation.update(mode=mode, inputs=mounts, private_truth_mounted="/truth.json" in mounts)
    save(destination / "isolation.json", isolation)
    save(destination / "inputs.json", {mount: sha(path) for path, mount in inputs})
    with (destination / "stdout.log").open("x") as out, (destination / "stderr.log").open("x") as err:
        result = subprocess.run(command + ["--", "/venv/bin/python", "/" + RUNNER, mode],
                                stdout=out, stderr=err)
    save(destination / "process.json", dict(returncode=result.returncode))
    need(result.returncode == 0, "process failed; preserve " + str(destination))
    return destination, read(destination / "result.json")


def controls(output):
    frozen = check(output)
    directory, result = isolated(output, frozen, "controls", "_controls")
    need(all(result[k]["passed"] is True for k in ("model", "workload", "observer")),
         "controls failed")
    need(result["model"]["complete"] is True and result["observer"]["complete"] is True,
         "controls incomplete")
    check(output)
    save(output / "controls.json", dict(passed=True, result=result,
                                       result_sha256=sha(directory / "result.json")))
    return result


def checked_inputs(source, case):
    directory = source / "public" / case["name"]
    expected = {"public.json", "pooled.json", "C.json"} | {f"P-{i}.json" for i in range(8)}
    need(set(case["pins"]) == expected, "source view roster changed")
    for name, digest in case["pins"].items():
        need(sha(directory / name) == digest, "public/view input changed")
    truth = source / "private" / (case["name"] + ".json")
    # Hash opaque bytes here; parse truth only inside the isolated scorer.
    need(sha(truth) == case["truth_sha256"], "generated truth changed")
    public, view = read(directory / "public.json"), read(directory / "pooled.json")
    need("payout_owners" not in public, "undeclared payout-owner mapping")
    need(view["members"] == list(range(8)), "pooled members changed")
    return [(directory / "public.json", "/public.json"),
            (directory / "pooled.json", "/view.json")], truth, public, view


def validate_prediction(public, view, prediction):
    need(prediction["schema"] == "kpi-population-heuristic-predictions-v1" and
         prediction["complete"] is True, "incomplete heuristic prediction")
    need(prediction["public_sha256"] == original.canonical(public) and
         prediction["view_sha256"] == original.canonical(view), "prediction input identity")
    final = len(public["algebra"]["events"]) - 1
    expected = [dict(event=i, through_event=final) for i, event in
                enumerate(public["algebra"]["events"]) if i > 0 and event["mode"] == 1]
    need(len(expected) == 64 and prediction["requested_targets"] == expected,
         "changed final-horizon target coverage")
    need([dict(event=r["event"], through_event=r["through_event"])
          for r in prediction["rows"]] == expected, "missing/duplicate/reordered prediction rows")
    need(all(set(r["variants"]) == set(VARIANTS) for r in prediction["rows"]),
         "changed heuristic variants")


def summary(case, result):
    need(result["complete"] is True and result["qualification_pass"] is False and
         result["arm"] == case["arm"], "incomplete or incorrect score")
    need(result["truth_consistency"] == dict(complete=True, cp_sat="SAT", z3="SAT"),
         "full-model truth checks did not pass")
    need(type(result["tested_primary_targets"]) is int and
         0 <= result["tested_primary_targets"] <= 64, "invalid primary denominator")
    need(set(result["variants"]) == set(VARIANTS), "changed scored variants")
    variants = {}
    for variant in VARIANTS:
        need(set(result["variants"][variant]) == set(STRATA), "changed score strata")
        variants[variant] = {}
        for stratum in STRATA:
            metrics = result["variants"][variant][stratum]
            need(set(metrics) == set(METRICS), "changed score metrics")
            variants[variant][stratum] = {}
            for metric in METRICS:
                counts = metrics[metric]
                need(set(counts) == {"correct", "eligible"} and
                     all(type(counts[k]) is int for k in counts) and
                     0 <= counts["correct"] <= counts["eligible"] <= 64,
                     "invalid score counts")
                variants[variant][stratum][metric] = dict(counts)
    return dict(case=case["name"], arm=case["arm"], view="pooled", complete=True,
                tested_primary_targets=result["tested_primary_targets"], variants=variants,
                qualification_pass=False)


def run_all(output):
    frozen = check(output)
    controls_ = read(output / "controls.json")
    need(controls_["passed"] is True and controls_["result_sha256"] ==
         sha(output / "runs/controls/result.json"), "controls must pass first")
    source = Path(frozen["source_attempt"])
    records = cases(read(source / "generation.json"))
    freeze_sha = sha(output / "freeze.json")
    for case in records:
        checked_inputs(source, case)
    predictions, results = [], []
    phase, current = "predict", None
    try:
        # No scorer is reachable until every prediction and the batch are sealed.
        for case in records:
            current = case["name"]
            inputs, _, public, view = checked_inputs(source, case)
            label = current + "-pooled-final"
            directory, prediction = isolated(output, frozen, label, "_observe", inputs)
            validate_prediction(public, view, prediction)
            seal = dict(case=current, prediction_sha256=sha(directory / "result.json"),
                        public_sha256=case["pins"]["public.json"],
                        view_sha256=case["pins"]["pooled.json"], truth_sha256=case["truth_sha256"],
                        freeze_sha256=freeze_sha)
            save(directory / "prediction-seal.json", seal)
            predictions.append(dict(case=current, label=label, prediction_seal=seal,
                                    seal_sha256=sha(directory / "prediction-seal.json")))
        check(output)
        batch = dict(schema="kpi-population-heuristic-batch-v1", complete=True,
                     freeze_sha256=freeze_sha, generation_sha256=frozen["generation_sha256"],
                     predictions=predictions, scoring_started=False)
        save(output / "prediction-batch.json", batch)
        batch_sha = sha(output / "prediction-batch.json")

        def verify_batch():
            need(sha(output / "prediction-batch.json") == batch_sha and
                 sha(output / "freeze.json") == freeze_sha, "sealed batch/freeze changed")
            for case, entry in zip(records, predictions, strict=True):
                checked_inputs(source, case)
                directory = output / "runs" / entry["label"]
                need(sha(directory / "prediction-seal.json") == entry["seal_sha256"] and
                     sha(directory / "result.json") == entry["prediction_seal"]["prediction_sha256"],
                     "sealed prediction changed")

        phase = "score"
        for case, entry in zip(records, predictions, strict=True):
            current = case["name"]
            verify_batch()
            inputs, truth, _, _ = checked_inputs(source, case)
            observed = output / "runs" / entry["label"]
            scored, result = isolated(output, frozen, entry["label"] + "-score", "_score", inputs + [
                (observed / "result.json", "/prediction.json"), (truth, "/truth.json")])
            verify_batch()
            results.append(summary(case, result))
            save(observed / "completion.json", dict(
                complete=True, prediction_batch_sha256=batch_sha,
                prediction_seal_sha256=entry["seal_sha256"],
                score_sha256=sha(scored / "result.json"), qualification_pass=False))
        check(output)
        result = dict(complete=True, cases=results, prediction_batch_sha256=batch_sha,
                      qualification_pass=False,
                      scope="Deterministic guessing accuracy on eight fixed modeled histories only")
        save(output / "completion.json", result)
        return result
    except Exception as error:
        save(output / "failure.json", dict(complete=False, phase=phase, case=current,
                                           exception_type=type(error).__name__,
                                           predictions_sealed=len(predictions), cases_scored=len(results),
                                           qualification_pass=False))
        raise


def main():
    os.umask(0o077)
    if len(sys.argv) == 2 and sys.argv[1].startswith("_"):
        need(os.environ.get("KPI_OBSERVER_MODULE") == "heuristic", "unknown observer")
        import population_privacy_heuristic as heuristic
        mode = sys.argv[1]
        if mode == "_controls":
            import population_privacy_model as model
            import population_privacy_workload as workload
            result = dict(model=model.controls(), workload=workload.controls(), observer=heuristic.controls())
        elif mode == "_observe":
            result = heuristic.analyze(read(Path("/public.json")), read(Path("/view.json")))
        else:
            need(mode == "_score", "unknown internal mode")
            result = heuristic.score(*(read(Path("/" + name + ".json")) for name in
                                       ("public", "view", "prediction", "truth")))
        save(Path("/output/result.json"), result)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "controls", "run_all"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--source", type=Path, default=Path("/tmp/kpi-32-role-20261020-method-01"))
    args = parser.parse_args()
    output = args.output.resolve()
    if args.command == "prepare":
        result = prepare(output, args.source.resolve())
    elif args.command == "controls":
        result = controls(output)
    else:
        result = run_all(output)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
