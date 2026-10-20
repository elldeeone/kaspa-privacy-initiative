#!/usr/bin/env python3
"""Frozen observer replay on existing histories; never samples new seeds."""
import argparse
import json
import importlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

import early_privacy_surface as surface
import population_privacy_trial as original
from early_privacy_surface import dependency_manifest, need, read, sandbox, save, sha

HERE = Path(__file__).resolve().parent
SOURCES = original.SOURCES + ("population_privacy_index.py", "population_privacy_slice.py",
                              "population_privacy_slice_trial.py")
NOTES = ("POPULATION-PRIVACY-SPEC.md", "POPULATION-PRIVACY-METHOD-02.md",
         "POPULATION-PRIVACY-METHOD-04.md")


def prepare(output, source, observer):
    need(not output.is_relative_to(HERE.parents[1]), "attempt must be outside Git")
    previous = original.check(source)
    generation = read(source / "generation.json")
    need(generation["complete"], "source histories incomplete")
    output.mkdir(mode=0o700)
    (output / "code").mkdir(mode=0o700)
    (output / "runs").mkdir(mode=0o700)
    for name in SOURCES + NOTES:
        origin = source / "code" / name if name in previous["sources"] else HERE / name
        shutil.copyfile(origin, output / "code" / name)
    save(output / "freeze.json", dict(
        schema="kpi-population-observer-replay-v1", observer=observer, source_attempt=str(source),
        source_freeze_sha256=sha(source / "freeze.json"),
        generation_sha256=sha(source / "generation.json"),
        sources={name: sha(output / "code" / name) for name in SOURCES + NOTES},
        dependency_root=previous["dependency_root"], dependencies=previous["dependencies"],
        scope="Local constraint relaxation; forced disclosures only, alternatives are slice inconclusive",
        new_seeds_generated=False, qualification_pass=False))
    return dict(prepared=True, source_attempt=str(source), freeze_sha256=sha(output / "freeze.json"))


def check(output):
    frozen = read(output / "freeze.json")
    for module in (surface, original):
        need(sha(Path(module.__file__).resolve()) == frozen["sources"][Path(module.__file__).name],
             "loaded host helper changed")
    need(sha(Path(__file__).resolve()) == frozen["sources"]["population_privacy_slice_trial.py"],
         "loaded method runner changed")
    for name, expected in frozen["sources"].items():
        need(sha(output / "code" / name) == expected, "frozen source changed: " + name)
    source = Path(frozen["source_attempt"])
    need(sha(source / "freeze.json") == frozen["source_freeze_sha256"] and
         sha(source / "generation.json") == frozen["generation_sha256"], "source attempt changed")
    need(dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
         "dependency bytes changed")
    return frozen


def isolated(output, frozen, label, mode, inputs=()):
    destination = output / "runs" / label
    destination.mkdir(mode=0o700)
    need(frozen["observer"] == "slice", "unknown frozen observer")
    command = sandbox() + ["--setenv", "KPI_OBSERVER_MODULE", frozen["observer"],
                           "--ro-bind", frozen["dependency_root"], "/venv",
                           "--bind", str(destination), "/output"]
    for name in SOURCES:
        command += ["--ro-bind", str(output / "code" / name), "/" + name]
    for path, mount in inputs:
        command += ["--ro-bind", str(path), mount]
    mounts = [mount for _, mount in inputs]
    need(mode == "_score" or not any(p in mounts for p in ("/truth.json", "/seeds.json")),
         "private input in observer")
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
        result = subprocess.run(command + [
            "--", "/venv/bin/python", "/population_privacy_slice_trial.py", mode],
            stdout=out, stderr=err)
    save(destination / "process.json", dict(returncode=result.returncode))
    need(result.returncode == 0, "process failed; preserve " + str(destination))
    return destination, read(destination / "result.json")


def controls(output):
    frozen = check(output)
    directory, result = isolated(output, frozen, "controls", "_controls")
    need(all(result[k]["passed"] for k in ("model", "workload", "observer")), "controls failed")
    check(output)
    save(output / "controls.json", dict(passed=True, result=result,
                                       result_sha256=sha(directory / "result.json")))
    return result


def run(output, case_name, view_name):
    frozen = check(output)
    controls_ = read(output / "controls.json")
    need(controls_["passed"] and controls_["result_sha256"] ==
         sha(output / "runs/controls/result.json"), "controls must pass first")
    source = Path(frozen["source_attempt"])
    generation = read(source / "generation.json")
    case = next((c for c in generation["cases"] if c["name"] == case_name), None)
    need(case is not None, "unknown case")
    directory = source / "public" / case_name
    truth = source / "private" / (case_name + ".json")
    need(sha(truth) == case["truth_sha256"], "generated truth changed")
    for name, expected in case["pins"].items():
        need(sha(directory / name) == expected, "public/view input changed")
    need(view_name + ".json" in case["pins"] and view_name != "public", "unknown view")
    need("payout_owners" not in read(directory / "public.json"), "undeclared payout-owner mapping")
    inputs = [(directory / "public.json", "/public.json"),
              (directory / (view_name + ".json"), "/view.json")]
    label = case_name + "-" + view_name + "-final"
    observed, prediction = isolated(output, frozen, label, "_observe", inputs)
    seal = dict(prediction_sha256=sha(observed / "result.json"),
                public_sha256=sha(directory / "public.json"),
                view_sha256=sha(directory / (view_name + ".json")),
                truth_sha256=case["truth_sha256"], freeze_sha256=sha(output / "freeze.json"))
    save(observed / "prediction-seal.json", seal)
    scored, result = isolated(output, frozen, label + "-score", "_score", inputs + [
        (observed / "result.json", "/prediction.json"), (truth, "/truth.json")])
    need(sha(observed / "result.json") == seal["prediction_sha256"] and
         sha(truth) == case["truth_sha256"], "predictions/truth changed during scoring")
    check(output)
    save(observed / "completion.json", dict(
        complete=result["complete"], prediction_seal=seal,
        score_sha256=sha(scored / "result.json"), qualification_pass=False,
        persistent_counterexample_requires_review=result["persistent_counterexample_requires_review"],
        scope="One case and view at final horizon only"))
    return dict(case=case_name, view=view_name, complete=result["complete"],
                tested_primary_targets=result["tested_primary_targets"],
                forced_primary_disclosures=result["forced_primary_disclosures"],
                qualification_pass=False)


def main():
    os.umask(0o077)
    if len(sys.argv) == 2 and sys.argv[1].startswith("_"):
        mode = sys.argv[1]
        if mode == "_controls":
            import population_privacy_model as model
            import population_privacy_workload as workload
            module = os.environ["KPI_OBSERVER_MODULE"]
            need(module == "slice", "unknown observer")
            observer = importlib.import_module("population_privacy_" + module)
            result = dict(model=model.controls(), workload=workload.controls(), observer=observer.controls())
        elif mode == "_observe":
            module = os.environ["KPI_OBSERVER_MODULE"]
            need(module == "slice", "unknown observer")
            observer = importlib.import_module("population_privacy_" + module)
            result = observer.analyze(read(Path("/public.json")), read(Path("/view.json")))
        else:
            need(mode == "_score", "unknown internal mode")
            result = original.score(*(read(Path("/" + name + ".json")) for name in
                                      ("public", "view", "prediction", "truth")))
        save(Path("/output/result.json"), result)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "controls", "run"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--source", type=Path, default=Path("/tmp/kpi-32-role-20261020-method-01"))
    parser.add_argument("--observer", choices=("slice",), default="slice")
    parser.add_argument("--case", default="set-01-persistent")
    parser.add_argument("--view", default="pooled")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.command == "prepare":
        result = prepare(output, args.source.resolve(), args.observer)
    elif args.command == "controls":
        result = controls(output)
    else:
        result = run(output, args.case, args.view)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
