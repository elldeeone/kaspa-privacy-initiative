#!/usr/bin/env python3
"""Collect complete, source-pinned observations before opening scoring truth."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("h17", HERE / "common-payout.py")
h17 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h17)
read, save, sha = h17.read, h17.save, h17.sha
EXTRA = ("common_payout_collect.py", "common_payout_batch_observer.py",
         "common_payout_batch_run.py", "common_payout_batch_tests.py",
         "common_payout_propagating_observer.py", "common_payout_propagating_run.py",
         "common_payout_propagating_tests.py", "common_payout_integer_observer.py",
         "common_payout_integer_tests.py")


def git_sha(commit, name):
    return hashlib.sha256(subprocess.check_output(
        ["git", "show", f"{commit}:poc/shared-pool/{name}"], cwd=HERE)).hexdigest()


def collect(root, original, alternatives):
    config = h17.freeze()
    base_pins = read(original / "execution-pins.json")
    variants = dict(base_pins["observer_source_variants"])
    variants["batch"] = dict(variants["bounded"])
    variants["batch"]["common_payout_batch_observer.py"] = git_sha(
        "f7c93c8", "common_payout_batch_observer.py")
    for engine, commit in (("propagating", "03fa94d"), ("integer", "28b9419")):
        variants[engine] = dict(variants["bounded"])
        variants[engine]["common_payout_batch_impl.py"] = variants["batch"]["common_payout_batch_observer.py"]
        variants[engine]["common_payout_batch_observer.py"] = git_sha(
            commit, f"common_payout_{engine}_observer.py")

    def inspect(folder, case, name):
        prediction, pins = read(folder / "predictions.json"), read(folder / "pins.json")
        expected = dict(input_sha256=sha(original / case / "public.json"),
                        view_sha256=None if name == "chain" else
                        sha(original / case / f"view-{name.split('-')[-1]}.json"))
        for field, digest in expected.items():
            if prediction[field] != digest or pins[field] != digest:
                raise ValueError("observation input identity")
        engines = []
        for engine, hashes in variants.items():
            keys = set(hashes)
            permitted = [keys]
            if engine == "plain":
                permitted.append(keys - {"common_payout_bounds.py"})
            if set(pins["sources"]) in permitted and all(
                    hashes[n] == digest for n, digest in pins["sources"].items()):
                engines.append(engine)
        if len(engines) != 1:
            raise ValueError("unknown or ambiguous observer implementation")
        isolation = read(folder / "isolation.json")
        if isolation["interfaces"] != ["lo"] or not isolation["nested_user_namespace_denied"]:
            raise ValueError("missing observer isolation")
        return engines[0], prediction

    extra, crosschecks, checked_engines = {}, [], set()
    for alternative in alternatives:
        pins = read(alternative / "execution-pins.json")
        case, name = pins["case"], pins["observer"]
        folder = alternative / "output"
        engine, prediction = inspect(folder, case, name)
        extra.setdefault((case, name), []).append((folder, engine, prediction))
        old = original / case / name / "predictions.json"
        if old.exists():
            if prediction["rows"] != read(old)["rows"]:
                raise ValueError("complete same-input observations disagree")
            crosschecks.append(dict(case=case, observer=name, engine=engine,
                                    reference_sha256=sha(old),
                                    candidate_sha256=sha(folder / "predictions.json"),
                                    rows=len(prediction["rows"])))
            checked_engines.add(engine)

    chosen = []
    for case in config["cases"]:
        for name in ["chain", *[f"participant-{p}" for p in config["participants"]]]:
            folder = original / case / name
            if (folder / "predictions.json").exists():
                engine, prediction = inspect(folder, case, name)
            else:
                candidates = extra.get((case, name), [])
                if not candidates:
                    raise ValueError(f"incomplete observation matrix: {case}/{name}")
                if any(p["rows"] != candidates[0][2]["rows"] for _, _, p in candidates[1:]):
                    raise ValueError("complete alternative observations disagree")
                folder, engine, prediction = candidates[0]
                if engine not in checked_engines:
                    raise ValueError("alternative engine lacks a complete-case crosscheck")
            chosen.append((case, name, folder, engine, prediction))
    if len(chosen) != 20:
        raise ValueError("incomplete observation matrix")

    # No truth contents are read until the full matrix and program identities
    # have passed. Copy only the previously pinned prepared files.
    preparation = read(original / "preparation.json")
    root.mkdir(mode=0o700)
    for name, digest in preparation["files"].items():
        if sha(original / name) != digest:
            raise ValueError("prepared input changed")
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(original / name, dest)
    shutil.copyfile(original / "preparation.json", root / "preparation.json")
    shutil.copyfile(original / "controls.log", root / "controls.log")
    save(root / "execution-pins.json", dict(
        freeze=h17.FREEZE, sources={n: sha(HERE / n) for n in (*h17.SOURCES, *EXTRA)},
        source_scope="host collection/scoring sources; each observer has its own actual source pins",
        observer_source_variants=variants, versions=base_pins["versions"],
        original_execution_pins_sha256=sha(original / "execution-pins.json")))
    executions = []
    for case, name, source, engine, prediction in chosen:
        dest = root / case / name
        dest.mkdir()
        for file in ("predictions.json", "pins.json", "isolation.json", "observer.log"):
            shutil.copyfile(source / file, dest / file)
        if sha(source / "predictions.json") != sha(dest / "predictions.json"):
            raise ValueError("prediction changed while copying")
        executions.append(dict(case=case, observer=name, engine=engine, reused=True,
                               seconds=prediction["seconds"], queries=prediction["queries"],
                               original_prediction_sha256=sha(source / "predictions.json")))
    save(root / "collection-checks.json", dict(
        complete_observations=20, same_input_crosschecks=crosschecks,
        original_preparation_sha256=sha(original / "preparation.json"),
        scores_opened_only_after_complete_matrix=True))
    h17.score_run(root, 1, time.monotonic(), executions, config)
    save(root / "resource-scope.json", dict(
        wall_scope="truth validation and scoring only; excludes observation and collection time",
        child_counters_scope="children of the collection process, including source-pin queries",
        observation_runtime="per-job seconds in summary.json; not an end-to-end benchmark"))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    p.add_argument("original", type=Path)
    p.add_argument("--alternative", type=Path, action="append", default=[])
    a = p.parse_args()
    collect(a.root.resolve(), a.original.resolve(), [p.resolve() for p in a.alternative])
