#!/usr/bin/env python3
"""Hash-frozen, stdlib-only runner. A complete search has no depth/state cutoff."""
import argparse
import hashlib
import json
import multiprocessing
import pathlib
import time
import resource
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from model import configs
from search import explore
from controls import controls

ROOT = pathlib.Path(__file__).resolve().parent
SOURCE_FILES = ("model.py", "oracle.py", "search.py", "controls.py", "run.py", "README.md", "configurations.json")


def identities():
    return {name: {"bytes": (ROOT / name).stat().st_size,
                   "sha256": hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}
            for name in SOURCE_FILES}


def write(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def worker(job):
    cid, conditional = job
    start = time.monotonic()
    result = explore(configs()[cid], conditional)
    result["wall_seconds"] = time.monotonic() - start
    usage = resource.getrusage(resource.RUSAGE_SELF)
    result["worker_cumulative_cpu_seconds"] = usage.ru_utime + usage.ru_stime
    result["worker_cumulative_max_rss_kib"] = usage.ru_maxrss
    return cid, conditional, result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--freeze", type=pathlib.Path, help="create source/config freeze, no model execution")
    p.add_argument("--selection", type=pathlib.Path)
    p.add_argument("--out", type=pathlib.Path)
    p.add_argument("--mode", choices=("base", "conditional", "both", "controls"), default="both")
    p.add_argument("--config", type=int, action="append")
    p.add_argument("--workers", type=int, default=1)
    args = p.parse_args()
    if args.freeze:
        assert args.selection is None and args.out is None
        write(args.freeze, {"format": "exit-liability-source-config-freeze-v1", "sources": identities(),
                            "initial_configurations": 128, "search_depth_cutoff": None,
                            "python_version": sys.version,
                            "base_and_conditional_runs_separate": True,
                            "expected_safe_accounting_not_complete_liveness": True,
                            "must_detect_mutants": __import__("model").MUTANTS})
        return
    assert args.selection and args.out and 1 <= args.workers <= 8
    freeze = json.loads(args.selection.read_text())
    assert identities() == freeze["sources"], "source/config drift before execution"
    assert json.loads((ROOT / "configurations.json").read_text()) == [json.loads(json.dumps(asdict(c))) for c in configs()]
    args.out.mkdir(parents=True, exist_ok=False)
    write(args.out / "identities-before.json", identities())
    snapshot = args.out / "source-snapshot"
    snapshot.mkdir()
    for name in SOURCE_FILES:
        with (snapshot / name).open("xb") as f:
            f.write((ROOT / name).read_bytes())
    selection_hash = hashlib.sha256(args.selection.read_bytes()).hexdigest()
    write(args.out / "selection.json", {"selection_sha256": selection_hash, "selection": freeze,
                                      "mode": args.mode, "workers": args.workers,
                                      "requested_configs": args.config})
    start = time.monotonic()
    completed = []
    if args.mode == "controls":
        write(args.out / "controls.json", controls())
    else:
        ids = sorted(set(args.config)) if args.config is not None else list(range(128))
        assert all(0 <= i < 128 for i in ids)
        modes = (False, True) if args.mode == "both" else (args.mode == "conditional",)
        jobs = [(i, conditional) for conditional in modes for i in ids]
        with ProcessPoolExecutor(max_workers=args.workers, mp_context=multiprocessing.get_context("spawn")) as pool:
            futures = [pool.submit(worker, job) for job in jobs]
            for future in as_completed(futures):
                cid, conditional, result = future.result()
                name = ("conditional" if conditional else "base") + f"-{cid:03}"
                write(args.out / (name + ".json"), result)
                completed.append({"case": name, "complete": result["complete"],
                                  "safety_violation": result["safety_violation"],
                                  "financial_states": result["counts"]["financial_states"],
                                  "wall_seconds": result["wall_seconds"]})
                print(json.dumps(completed[-1]), flush=True)
        assert len(completed) == len(jobs)
    after = identities()
    write(args.out / "identities-after.json", after)
    assert after == freeze["sources"], "source/config drift after execution"
    full = args.config is None and args.mode in ("base", "conditional", "both")
    summary = {"source_selection_sha256": selection_hash, "mode": args.mode,
               "complete_initial_enumeration": full,
               "completed": sorted(completed, key=lambda x: x["case"]),
               "elapsed_seconds": time.monotonic() - start,
               "all_completed_searches_exhausted": all(x["complete"] for x in completed),
               "safety_violations": [x for x in completed if x["safety_violation"]],
               "complete_protocol_liveness_established": False,
               "native_proof_or_fee_validation": False,
               "existing_format_revealing_authority": "UNRESOLVED",
               "all_source_config_hashes_unchanged": True}
    write(args.out / "summary.json", summary)
    if summary["safety_violations"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
