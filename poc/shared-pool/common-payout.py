#!/usr/bin/env python3
"""H17 private controller. It is never mounted in the blinded observer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import resource
import shutil
import subprocess
import time

from common_payout_generate import build
from common_payout_score import costs, score, validate_truth
from participant_privacy_view import project

HERE = Path(__file__).resolve().parent
FREEZE = "71d2aca"
spec = importlib.util.spec_from_file_location("h16", HERE / "participant-privacy.py")
h16 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h16)
read, save, sha = h16.read, h16.save, h16.sha
OBSERVER_FILES = ("common_payout_observer.py", "common_payout_bounds.py", *h16.OBSERVER_FILES)
SOURCES = (*OBSERVER_FILES, "common_payout_generate.py", "common_payout_score.py",
           "common_payout_tests.py", "common-payout.py", "participant_privacy_view.py",
           "src/two_input/harness.rs", "src/two_input/harness/study.rs")
BASE = HERE / "evidence/2026-10-20-participant-reconstruction"
CHAIN = HERE / "evidence/2026-10-20-wallet-policy-reconstruction"


def freeze():
    for name in ("COMMON-PAYOUT-SPEC.md", "common-payout-freeze.json"):
        expected = subprocess.check_output(["git", "show", f"{FREEZE}:poc/shared-pool/{name}"], cwd=HERE)
        if expected != (HERE / name).read_bytes():
            raise ValueError("H17 freeze changed")
    config = read(HERE / "common-payout-freeze.json")
    for name, digest in config["unchanged_sources"].items():
        if sha(HERE / name) != digest:
            raise ValueError(f"unchanged source changed: {name}")
    for manifest, digest in config["baseline_manifests"].items():
        path = HERE / manifest
        if sha(path) != digest:
            raise ValueError("baseline manifest changed")
        for name, expected in read(path).items():
            if sha(path.parent / name) != expected:
                raise ValueError("baseline evidence changed")
    return config


def prepare(root, original):
    config = freeze()
    root.mkdir(mode=0o700)
    for case in config["cases"]:
        source, folder = original / case, root / case
        for name in ("plan.json", "truth.json"):
            if sha(source / name) != config["private_source_hashes"][f"{case}/{name}"]:
                raise ValueError("private baseline changed")
        if sha(source / "fresh.json") != config["public_input_hashes"][f"{case}/fresh"]:
            raise ValueError("public baseline changed")
        old_plan, old, truth = [read(source / f"{n}.json") for n in ("plan", "fresh", "truth")]
        plan, public, truth, claims = build(old_plan, old, truth, config)
        if plan["steps"][:12] != old_plan["steps"] or public["events"][:12] != old["events"][:12]:
            raise ValueError("original prefix changed")
        for name, data in (("plan", plan), ("public", public), ("truth", truth), ("claims", claims),
                           ("baseline-plan", old_plan), ("baseline-public", old)):
            save(folder / f"{name}.json", data)
        save(folder / "costs.json", costs(old_plan, old, plan, public, claims))
        for participant in config["participants"]:
            save(folder / f"view-{participant}.json", project(plan, participant, sha(folder / "public.json")))
    save(root / "preparation.json", dict(
        freeze=FREEZE, files={str(p.relative_to(root)): sha(p)
                             for p in sorted(root.rglob("*.json"))}))


def observe(root, case, participant):
    folder = root / case
    public = folder / "public.json"
    view = folder / f"view-{participant}.json" if participant is not None else None
    out = folder / ("chain" if participant is None else f"participant-{participant}")
    out.mkdir(mode=0o700)
    pins = dict(input_sha256=sha(public), view_sha256=sha(view) if view else None,
                sources={n: sha(HERE / n) for n in OBSERVER_FILES})
    save(out / "pins.json", pins)
    command = h16.sandbox() + ["--ro-bind", str(h16.h14.VENV), "/venv"]
    for name in OBSERVER_FILES:
        command += ["--ro-bind", str(HERE / name), f"/{name}"]
    command += ["--ro-bind", str(public), "/input.json", "--bind", str(out), "/output"]
    if view:
        command += ["--ro-bind", str(view), "/view.json"]
    probe = (
        "import pathlib,json,socket,subprocess;"
        "paths=['/home','/plan.json','/truth.json','/claims.json','/other-view.json',"
        "'/common_payout_generate.py','/common_payout_score.py','/controller.py',"
        "'/proc/1/cmdline','/proc/self/mountinfo'];"
        "denied=[p for p in paths if not pathlib.Path(p).exists()];assert denied==paths;"
        "net=[name for index,name in socket.if_nameindex()];assert net==['lo'];"
        "u=subprocess.run(['/usr/bin/unshare','--user','--map-root-user','true'],capture_output=True);"
        "assert u.returncode!=0;"
        "print(json.dumps(dict(inaccessible=denied,interfaces=net,nested_user_namespace_denied=True)))"
    )
    receipt = subprocess.run(command + ["--", "/usr/bin/python3", "-c", probe],
                             capture_output=True, text=True, check=True)
    save(out / "isolation.json", json.loads(receipt.stdout))
    with (out / "observer.log").open("x") as log:
        subprocess.run(command + ["--", "/venv/bin/python", "/common_payout_observer.py",
                                  "/input.json", "/view.json" if view else "-",
                                  "/output/predictions.json"],
                       stdout=log, stderr=log, check=True)
    prediction = read(out / "predictions.json")
    for field in ("input_sha256", "view_sha256"):
        if prediction[field] != pins[field]:
            raise ValueError("observer input identity changed")
    print(f"{case} {out.name}: complete in {prediction['seconds']:.2f}s", flush=True)
    return dict(case=case, observer=out.name, seconds=prediction["seconds"],
                queries=prediction["queries"])


def run(root, workers):
    config = freeze()
    for name, digest in read(root / "preparation.json")["files"].items():
        if sha(root / name) != digest:
            raise ValueError("prepared input changed")
    save(root / "execution-pins.json", dict(
        freeze=FREEZE, sources={n: sha(HERE / n) for n in SOURCES},
        versions=subprocess.check_output([
            str(h16.h14.VENV / "bin/python"), "-c",
            "import sys,z3,ortools,json;print(json.dumps(dict(python=sys.version,z3=z3.get_version_string(),ortools=ortools.__version__)))"
        ], text=True).strip()))
    with (root / "controls.log").open("x") as log:
        subprocess.run([str(h16.h14.VENV / "bin/python"), "-m", "unittest",
                        "common_payout_tests", "-v"], cwd=HERE, stdout=log, stderr=log, check=True)
    started = time.monotonic()
    jobs = [(case, participant) for case in config["cases"]
            for participant in [None, *config["participants"]]]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        executions = list(pool.map(lambda args: observe(root, *args), jobs))
    # Open scoring truth only when all isolated jobs have committed predictions.
    all_scores, all_costs, checks = [], {}, 0
    for case in config["cases"]:
        folder = root / case
        plan, public, truth, claims = [read(folder / f"{n}.json")
                                      for n in ("plan", "public", "truth", "claims")]
        checks += validate_truth(plan, public, [read(folder / f"view-{p}.json") for p in config["participants"]])
        all_costs[case] = read(folder / "costs.json")
        for participant in [None, *config["participants"]]:
            out = folder / ("chain" if participant is None else f"participant-{participant}")
            baseline = (CHAIN / case / "fresh/wallet/predictions.json" if participant is None
                        else BASE / case / "fresh" / str(participant) / "wallet/predictions.json")
            result = score(plan, public, truth, claims, read(out / "predictions.json"),
                           read(baseline), participant)
            save(out / "score.json", result)
            all_scores.append(dict(case=case, observer=out.name, **result))
    summaries = {}
    for profile in ("chain", "participant"):
        subset = [s for s in all_scores if (s["observer"] == "chain") == (profile == "chain")]
        claims = [r for s in subset for r in s["claims"]]
        payments = [r for s in subset for r in s["payments"]]
        summaries[profile] = dict(
            observations=len(claims),
            baseline_linked=sum(r["baseline_linked"] for r in claims),
            linked=sum(r["linked"] for r in claims),
            baseline_distinct_linked=len({(s["case"], r["claim"]) for s in subset for r in s["claims"] if r["baseline_linked"]}),
            distinct_linked=len({(s["case"], r["claim"]) for s in subset for r in s["claims"] if r["linked"]}),
            no_pair_regression=all(sum(r["linked"] for r in s["claims"]) <=
                                   sum(r["baseline_linked"] for r in s["claims"]) for s in subset),
            new_payment_links=sum(r["newly_linked"] for r in payments),
            payment_observations=len(payments),
            baseline_payment_linked=sum(r["baseline_linked"] for r in payments),
            payment_linked=sum(r["linked"] for r in payments),
            singleton_precision=1 if any(r["linked"] for r in claims) else None,
            coverage=sum(r["linked"] for r in claims)/len(claims),
            remaining_min_leg_candidates=[r["min_leg_candidates"] for r in claims],
        )
    primary = summaries["participant"]
    if primary["baseline_distinct_linked"] != config["baseline_distinct_linked_claims"]:
        raise ValueError("baseline target matching differs")
    clauses = dict(reduces_linked_claims=primary["distinct_linked"] <= config["maximum_distinct_linked_claims"],
                   no_pair_regression=primary["no_pair_regression"],
                   no_new_payment_links=primary["new_payment_links"] == 0)
    save(root / "costs.json", all_costs)
    save(root / "summary.json", dict(
        observations=len(executions), all_truth_survives=True, exact_truth_prefix_checks=checks,
        summaries=summaries, privacy_clauses=clauses, privacy_screen_passes=all(clauses.values()),
        fee_screen_passes=all(c["added_fee_fraction"] <= .25 for c in all_costs.values()),
        delay_screen_passes=all(c["p95_added_completion_minutes"] <= 30 for c in all_costs.values()),
        real_world_anonymity_established=False, actual_tkas_spent=0, executions=executions))
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    save(root / "resources.json", dict(wall_seconds=time.monotonic()-started, workers=workers,
                                      max_child_rss_kib=usage.ru_maxrss,
                                      rss_meaning="largest child high-water, not aggregate RAM",
                                      child_user_seconds=usage.ru_utime, child_system_seconds=usage.ru_stime))
    print(json.dumps(dict(summaries=summaries, privacy_clauses=clauses)), flush=True)


def export(root, dest):
    freeze()
    summary = read(root / "summary.json")
    if summary["observations"] != 20 or not summary["all_truth_survives"]:
        raise ValueError("incomplete observations")
    for name, digest in read(root / "execution-pins.json")["sources"].items():
        if sha(HERE / name) != digest:
            raise ValueError("source changed after observations")
    dest.mkdir()
    for name in ("summary.json", "costs.json", "resources.json", "execution-pins.json", "controls.log"):
        shutil.copyfile(root / name, dest / name)
    for execution in summary["executions"]:
        source = root / execution["case"] / execution["observer"]
        target = dest / execution["case"] / execution["observer"]
        target.mkdir(parents=True)
        result = read(source / "score.json")
        prediction = read(source / "predictions.json")
        prediction["rows"] = [r for r in prediction["rows"] if r["event"] in result["eligible_events"]]
        prediction["complete_prediction_sha256"] = sha(source / "predictions.json")
        prediction["export_boundary"] = "eligible targets only; no participant records or openings"
        save(target / "predictions.json", prediction)
        for name in ("score.json", "isolation.json", "pins.json"):
            shutil.copyfile(source / name, target / name)
    save(dest / "SHA256SUMS.json", {str(p.relative_to(dest)): sha(p)
                                  for p in sorted(dest.rglob("*")) if p.is_file()})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("root", type=Path)
    prep.add_argument("original", type=Path)
    runner = sub.add_parser("run")
    runner.add_argument("root", type=Path)
    runner.add_argument("--workers", type=int, default=4)
    exporter = sub.add_parser("export")
    exporter.add_argument("root", type=Path)
    exporter.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.root, args.original)
    elif args.command == "run":
        run(args.root, args.workers)
    else:
        export(args.root, args.destination)
