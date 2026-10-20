#!/usr/bin/env python3
"""Isolate one native arm per observer, seal both predictions, then score.

Constructed offline diagnostic only. Native secrets and truth are never mounted
in an observer. Combined exports must not be reused as a single control view.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone

import early_privacy_surface as surface
from early_privacy_surface import need, read, save, sha

HERE = Path(__file__).resolve().parent
SOURCES = (
    "address_reuse_evaluate.py", "address_reuse_observer.py",
    "address_reuse_trial.py", "early_privacy_surface.py",
    "population_privacy_model.py", "population_privacy_index.py",
    "two_input_privacy_observer.py", "two_input_privacy_z3.py",
    "ADDRESS-REUSE-SPEC.md",
)
PUBLIC_FILES = surface.FILES + ("funding_owner_directory.json",)
OBSERVER_SOURCES = (
    "address_reuse_observer.py", "early_privacy_surface.py",
    "population_privacy_model.py", "population_privacy_index.py",
    "two_input_privacy_observer.py", "two_input_privacy_z3.py",
)


def now():
    return datetime.now(timezone.utc).isoformat()


def check(output):
    frozen = read(output / "freeze.json")
    need(frozen["schema"] == "kpi-address-reuse-evaluation-freeze-v1", "freeze schema")
    need(set(frozen["sources"]) == set(SOURCES), "frozen source closure")
    for name, digest in frozen["sources"].items():
        need(sha(output / "code" / name) == digest, "changed frozen source: " + name)
    for module in (surface,):
        path = Path(module.__file__)
        need(sha(path) == frozen["sources"][path.name], "loaded helper changed")
    need(sha(Path(__file__)) == frozen["sources"][Path(__file__).name], "runner changed")
    need(sha(output / "replay") == frozen["replay_sha256"], "replay binary changed")
    need(surface.dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
         "dependency bytes changed")
    return frozen


def isolated(output, frozen, name, args, inputs=None, prediction=None, truth=None):
    directory = output / "runs" / name
    directory.mkdir(mode=0o700)
    command = surface.sandbox() + ["--ro-bind", frozen["dependency_root"], "/venv"]
    for source in OBSERVER_SOURCES:
        command += ["--ro-bind", str(output / "code" / source), "/" + source]
    mounts = {}
    if inputs is not None:
        for filename in PUBLIC_FILES:
            path = inputs / filename
            command += ["--ro-bind", str(path), "/input/" + filename]
            mounts["/input/" + filename] = sha(path)
    for path, dest in ((prediction, "/prediction.json"), (truth, "/truth.json")):
        if path is not None:
            command += ["--ro-bind", str(path), dest]
            mounts[dest] = sha(path)
    need((truth is not None) == (args[0] == "score"), "truth may only enter scorer")
    need((prediction is not None) == (args[0] == "score"), "prediction mount mode")
    probe = (
        "import pathlib,json;assert not pathlib.Path('/home').exists();"
        "interfaces=[x.split(':')[0].strip() for x in "
        "pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x];"
        "assert interfaces==['lo'];print(json.dumps({'interfaces':interfaces,"
        "'home_accessible':False}))")
    audit = subprocess.run(command + ["--", "/venv/bin/python", "-c", probe],
                           capture_output=True, text=True, check=True)
    save(directory / "isolation.json", dict(
        **json.loads(audit.stdout), mode=args[0], inputs=list(mounts),
        private_truth_mounted=truth is not None, other_arm_mounted=False))
    save(directory / "inputs.json", mounts)
    started = now()
    with (directory / "result.json").open("x") as out, (directory / "stderr.log").open("x") as err:
        process = subprocess.run(command + ["--", "/venv/bin/python",
                                 "/address_reuse_observer.py", *args], stdout=out, stderr=err)
    save(directory / "process.json", dict(started_utc=started, finished_utc=now(),
                                          returncode=process.returncode))
    need(process.returncode == 0, "isolated process failed; preserve " + str(directory))
    return directory, read(directory / "result.json")


def prepare(output, venv, binary):
    need(not output.is_relative_to(HERE.parents[1]), "evidence attempt must be outside Git")
    output.mkdir(mode=0o700)
    (output / "code").mkdir(mode=0o700)
    (output / "runs").mkdir(mode=0o700)
    for name in SOURCES:
        shutil.copyfile(HERE / name, output / "code" / name)
    shutil.copyfile(binary, output / "replay")
    (output / "replay").chmod(0o700)
    save(output / "freeze.json", dict(
        schema="kpi-address-reuse-evaluation-freeze-v1", created_utc=now(),
        sources={name: sha(output / "code" / name) for name in SOURCES},
        replay_sha256=sha(output / "replay"), dependency_root=str(venv),
        dependencies=surface.dependency_manifest(venv),
        scope="Constructed native address-reuse diagnostic; one isolated arm per observer"))
    frozen = check(output)
    directory, result = isolated(output, frozen, "controls", ["controls"])
    need(result["passed"] is True, "observer controls failed")
    save(output / "controls.json", dict(passed=True, result_sha256=sha(directory / "result.json")))
    check(output)
    return dict(prepared=True, controls_passed=True, freeze_sha256=sha(output / "freeze.json"))


def run(output, native):
    frozen = check(output)
    control = read(output / "controls.json")
    need(control["passed"] and control["result_sha256"] == sha(output / "runs/controls/result.json"),
         "controls must pass")
    result_path = native / "native-result.json"
    result = read(result_path)
    need(result["complete"] is True and result["proof_count"] == 7
         and result["chain_acceptance_verified"] is False, "native experiment incomplete")
    need([a["name"] for a in result["arms"]] == ["matched", "different-index"], "paired arms")
    # The native driver freezes these exact sources before creating any wallet.
    for name, digest in frozen["sources"].items():
        need(sha(native / "software/code/poc/shared-pool" / name) == digest,
             "native/evaluation source mismatch")
    records = []
    for arm in result["arms"]:
        inputs, truth = native / arm["public_dir"], native / arm["truth_file"]
        need(set(arm["public_files"]) == set(PUBLIC_FILES) | {"head.json", "checked.json"},
             "native public input pin closure")
        need(all(sha(inputs / name) == digest for name, digest in arm["public_files"].items()),
             "native public input changed")
        need(sha(truth) == arm["truth_sha256"], "private truth bytes changed")
        replay = surface.native_replay(output / "replay", inputs)
        save(output / (arm["name"] + "-replay-process.json"), dict(returncode=replay.returncode))
        (output / (arm["name"] + "-replay-stderr.log")).write_text(replay.stderr)
        need(replay.returncode == 0, "independent native replay failed")
        replayed = json.loads(replay.stdout)
        need([r["transaction"] for r in replayed["records"]] == read(inputs / "lineage.json")
             and replayed["chain_acceptance_verified"] is False, "replay identity")
        save(output / (arm["name"] + "-replay.json"), replayed)
        directory, prediction = isolated(output, frozen, arm["name"] + "-observe",
                                         ["observe", "/input"], inputs)
        need(prediction["complete"] is True, "incomplete observer")
        seal = dict(arm=arm["name"], sealed_utc=now(),
                    prediction_sha256=sha(directory / "result.json"),
                    truth_sha256=arm["truth_sha256"], public_files=arm["public_files"],
                    native_result_sha256=sha(result_path), freeze_sha256=sha(output / "freeze.json"))
        save(directory / "prediction-seal.json", seal)
        records.append(dict(arm=arm, directory=str(directory), seal=seal,
                            seal_sha256=sha(directory / "prediction-seal.json")))
    save(output / "prediction-batch.json", dict(sealed_utc=now(), scoring_started=False,
                                                records=records))
    batch_sha = sha(output / "prediction-batch.json")
    scores = []
    for record in records:
        need(sha(output / "prediction-batch.json") == batch_sha, "batch changed")
        arm, directory = record["arm"], Path(record["directory"])
        need(sha(directory / "result.json") == record["seal"]["prediction_sha256"], "prediction changed")
        inputs, truth = native / arm["public_dir"], native / arm["truth_file"]
        need(sha(truth) == arm["truth_sha256"] and
             all(sha(inputs / name) == digest for name, digest in arm["public_files"].items()),
             "scoring inputs changed")
        _, score = isolated(output, frozen, arm["name"] + "-score",
                            ["score", "/input", "/prediction.json", "/truth.json"],
                            inputs, directory / "result.json", truth)
        need(score["complete"] is True, "incomplete score")
        scores.append(dict(arm=arm["name"], result=score))
    check(output)
    need(sha(output / "prediction-batch.json") == batch_sha, "final batch changed")
    for record in records:
        arm, directory = record["arm"], Path(record["directory"])
        need(sha(result_path) == record["seal"]["native_result_sha256"] and
             sha(directory / "prediction-seal.json") == record["seal_sha256"] and
             sha(directory / "result.json") == record["seal"]["prediction_sha256"] and
             sha(native / arm["truth_file"]) == arm["truth_sha256"] and
             all(sha(native / arm["public_dir"] / name) == digest
                 for name, digest in arm["public_files"].items()), "final evidence changed")
    summary = dict(complete=True, scores=scores, prediction_batch_sha256=batch_sha,
                   chain_acceptance_verified=False, privacy_qualification=False)
    save(output / "completion.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("output", type=Path)
    prepare_parser.add_argument("--venv", type=Path, default=surface.VENV)
    prepare_parser.add_argument("--replay", type=Path, default=HERE / "target/release/kpi-two-input-replay")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("output", type=Path)
    run_parser.add_argument("native", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    result = (prepare(args.output.resolve(), args.venv.resolve(), args.replay.resolve())
              if args.command == "prepare" else run(args.output.resolve(), args.native.resolve()))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
