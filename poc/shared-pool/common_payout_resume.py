#!/usr/bin/env python3
"""Reuse completed blinded work and retain active searches, without rescoring early.

Both engines implement the frozen relation. The bounded variant adds only the
public suffix theorem tested by the integer oracle. Record per-job source pins;
do not pretend old predictions came from a newly edited executable.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("h17", HERE / "common-payout.py")
h17 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h17)
read, save, sha = h17.read, h17.save, h17.sha
VERSIONS = {"plain": "1a9ad37", "bounded": "fabead4"}


def copy_prediction(source, root, case, name, variants):
    prediction = read(source / "predictions.json")
    public = root / case / "public.json"
    view = root / case / f"view-{name.split('-')[-1]}.json" if name != "chain" else None
    if prediction["input_sha256"] != sha(public) or prediction["view_sha256"] != (sha(view) if view else None):
        raise ValueError("reused observation has different inputs")
    pins = read(source / "pins.json")
    engines = [engine for engine, hashes in variants.items()
               if all(hashes.get(n) == digest for n, digest in pins["sources"].items())]
    if len(engines) != 1:
        raise ValueError("reused observation has unrecognized source")
    if read(source / "isolation.json")["interfaces"] != ["lo"]:
        raise ValueError("missing isolated observation")
    target = root / case / name
    target.mkdir()
    for file in ("predictions.json", "pins.json", "isolation.json", "observer.log"):
        shutil.copyfile(source / file, target / file)
    if sha(target / "predictions.json") != sha(source / "predictions.json"):
        raise ValueError("prediction changed while copying")
    return dict(case=case, observer=name, engine=engines[0], reused=True,
                seconds=prediction["seconds"], queries=prediction["queries"],
                original_prediction_sha256=sha(source / "predictions.json"))


def run(root, original, active_run, workers):
    config = h17.freeze()
    root.mkdir(mode=0o700)
    preparation = read(original / "preparation.json")
    for name, digest in preparation["files"].items():
        source = original / name
        if sha(source) != digest or sha(active_run / name) != digest:
            raise ValueError("attempt input bytes differ")
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source, dest)
    shutil.copyfile(original / "preparation.json", root / "preparation.json")
    variants = {}
    for engine, commit in VERSIONS.items():
        directory = root / "observer-code" / engine
        directory.mkdir(parents=True, mode=0o700)
        for name in h17.OBSERVER_FILES:
            # The plain program never imports bounds, but keeping the same
            # generic module mount list avoids a separate observer interface.
            ref = "fabead4" if name == "common_payout_bounds.py" else commit
            raw = subprocess.check_output(["git", "show", f"{ref}:poc/shared-pool/{name}"], cwd=HERE)
            (directory / name).write_bytes(raw)
        variants[engine] = {n: sha(directory / n) for n in h17.OBSERVER_FILES}
    save(root / "execution-pins.json", dict(
        freeze=h17.FREEZE, sources={n: sha(HERE / n) for n in h17.SOURCES},
        observer_source_variants=variants, observer_commits=VERSIONS,
        note="same frozen integer relation; public suffix cuts are optional acceleration",
        versions=subprocess.check_output([str(h17.h16.h14.VENV / "bin/python"), "-c",
            "import sys,z3,ortools,json;print(json.dumps(dict(python=sys.version,z3=z3.get_version_string(),ortools=ortools.__version__)))"
        ], text=True).strip()))
    with (root / "controls.log").open("x") as log:
        subprocess.run([str(h17.h16.h14.VENV / "bin/python"), "-m", "unittest",
                        "common_payout_tests", "-v"], cwd=HERE, stdout=log, stderr=log, check=True)
    resumption = read(active_run / "resumption.json")
    active = {row["label"]: row for row in resumption["active"]}
    jobs = [(c, p, "chain" if p is None else f"participant-{p}")
            for c in config["cases"] for p in [None, *config["participants"]]]
    complete, pending, crosschecks = [], [], []
    for case, participant, name in jobs:
        candidates = [r / case / name for r in (original, active_run)
                      if (r / case / name / "predictions.json").exists()]
        if candidates:
            if len(candidates) == 2:
                if read(candidates[0] / "predictions.json")["rows"] != read(candidates[1] / "predictions.json")["rows"]:
                    raise ValueError("complete engines disagree")
                crosschecks.append(f"{case}/{name}")
            complete.append(copy_prediction(candidates[-1], root, case, name, variants))
        else:
            pending.append((case, participant, name))
    save(root / "resumption-pins.json", dict(
        complete_reused=len(complete), active_retained=list(active),
        matched_complete_predictions=crosschecks,
        original_execution_pins_sha256=sha(original / "execution-pins.json"),
        active_execution_pins_sha256=sha(active_run / "execution-pins.json")))

    def execute(job):
        case, participant, name = job
        label = f"{case}/{name}"
        if label in active:
            source = active_run / case / name
            while not (source / "predictions.json").exists():
                status = Path(f"/proc/{active[label]['pid']}/stat")
                if not status.exists() or status.read_text().split(") ", 1)[1].startswith("Z "):
                    raise ValueError("retained observer exited without a prediction")
                time.sleep(2)
            # A syntactically complete JSON document is required, not mere existence.
            while True:
                try:
                    read(source / "predictions.json")
                    break
                except json.JSONDecodeError:
                    time.sleep(.1)
            result = copy_prediction(source, root, case, name, variants)
        else:
            # Select the equivalent search strategy using an already disclosed
            # fact. No hidden participant identity becomes observer knowledge.
            own_initial = participant is not None and any(
                r["position"] == 0 for r in read(root / case / f"view-{participant}.json")["receipts"])
            engine = "bounded" if own_initial else "plain"
            script = (
                "import importlib.util,pathlib,sys;"
                "p=pathlib.Path(sys.argv[1]);s=importlib.util.spec_from_file_location('h17',p/'common-payout.py');"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "m.HERE=pathlib.Path(sys.argv[2]);"
                "m.observe(pathlib.Path(sys.argv[3]),sys.argv[4],None if sys.argv[5]=='chain' else int(sys.argv[5]))"
            )
            subprocess.run([str(h17.h16.h14.VENV / "bin/python"), "-c", script, str(HERE),
                            str(root / "observer-code" / engine), str(root), case,
                            "chain" if participant is None else str(participant)], cwd=HERE, check=True)
            prediction = read(root / case / name / "predictions.json")
            pins = read(root / case / name / "pins.json")
            if pins["sources"] != variants[engine]:
                raise ValueError("new observer source identity")
            result = dict(case=case, observer=name, engine=engine, reused=False,
                          seconds=prediction["seconds"], queries=prediction["queries"])
        print(f"{label}: retained or complete", flush=True)
        return result

    # Start the longer initial-owner searches first; this changes scheduling only.
    pending.sort(key=lambda j: (j[1] != 0, f"{j[0]}/{j[2]}" not in active))
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        complete.extend(pool.map(execute, pending))
    # The stopped original controller must never resume and score a partial mix.
    os.kill(resumption["controller_pid"], signal.SIGKILL)
    h17.score_run(root, workers, started, complete, config)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument("active", type=Path)
    parser.add_argument("--workers", type=int, default=10)
    args = parser.parse_args()
    run(args.root.resolve(), args.original.resolve(), args.active.resolve(), args.workers)
