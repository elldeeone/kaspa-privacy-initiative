#!/usr/bin/env python3
"""H18 private controller. Freeze, isolate predictions, then score and export."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time

from scheduled_payout_generate import accounting, generate, project
from scheduled_payout_score import score, summarize

HERE = Path(__file__).resolve().parent
FREEZE = "b3fe70e"
spec = importlib.util.spec_from_file_location("h16", HERE / "participant-privacy.py")
h16 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h16)
read, save, sha = h16.read, h16.save, h16.sha
OBSERVERS = ("scheduled_payout_observer.py", "common_payout_observer.py",
             "common_payout_bounds.py", *h16.OBSERVER_FILES)
SOURCES = (*OBSERVERS, "scheduled_payout_generate.py", "scheduled_payout_score.py",
           "scheduled_payout_tests.py", "scheduled-payout.py")


def freeze():
    for name in ("SCHEDULED-PAYOUT-SPEC.md", "scheduled-payout-freeze.json"):
        need = subprocess.check_output(["git", "show", f"{FREEZE}:poc/shared-pool/{name}"], cwd=HERE)
        if need != (HERE / name).read_bytes():
            raise ValueError("H18 freeze changed")
    cfg = read(HERE / "scheduled-payout-freeze.json")
    for name, digest in cfg["unchanged_sources"].items():
        if sha(HERE / name) != digest:
            raise ValueError(f"pinned original source changed: {name}")
    for name, digest in cfg["prior_manifests"].items():
        if sha(HERE / name) != digest:
            raise ValueError("earlier manifest changed")
        for p, expected in read(HERE / name).items():
            if sha((HERE / name).parent / p) != expected:
                raise ValueError("earlier evidence changed")
    return cfg


def cases(cfg):
    return [(f"{r}-{i:02}", r, None) for r in cfg["regimes"] for i in range(cfg["cases_per_regime"])] + [
        ("control-singleton", "sparse", "singleton"), ("control-immediate", "overlap", "immediate")]


def jobs(cfg):
    for name, _, control in cases(cfg):
        for arm in ("full", "scheduled"):
            for who in ([None] if control == "singleton" else [None, 0, 1, 2, 3]):
                yield name, arm, who


def observer_name(who):
    return "chain" if who is None else f"participant-{who}"


def prepare(root):
    cfg = freeze()
    if sha(root / "master-seed.bin") != cfg["master_seed_sha256"]:
        raise ValueError("master seed commitment differs")
    master = (root / "master-seed.bin").read_bytes()
    template = read(HERE / "two-input-privacy-workloads.json")
    for name, regime, control in cases(cfg):
        paired = generate(cfg, template, master, name, regime, control)
        folder = root / name
        save(folder / "costs.json", accounting(cfg, paired))
        for arm, bundle in paired.items():
            base = folder / arm
            save(base / "public.json", bundle["public"])
            save(base / "private.json", bundle["private"])
            if control != "singleton":
                for who in range(4):
                    save(base / f"view-{who}.json", project(
                        bundle["private"], who, sha(base / "public.json")))
    save(root / "preparation.json", dict(
        freeze=FREEZE, files={str(p.relative_to(root)): sha(p) for p in sorted(root.rglob("*.json"))}))
    print(f"Prepared {len(cases(cfg))} new paired ledgers; no observations scored.", flush=True)


def observe(root, name, arm, who):
    folder = root / name / arm
    public = folder / "public.json"
    view = folder / f"view-{who}.json" if who is not None else None
    out = folder / observer_name(who)
    out.mkdir(mode=0o700)
    source = root / "source"
    pins = dict(input_sha256=sha(public), view_sha256=sha(view) if view else None,
                sources={n: sha(source / n) for n in OBSERVERS})
    save(out / "pins.json", pins)
    command = h16.sandbox() + ["--ro-bind", str(h16.h14.VENV), "/venv"]
    for n in OBSERVERS:
        command += ["--ro-bind", str(source / n), f"/{n}"]
    command += ["--ro-bind", str(public), "/input.json", "--bind", str(out), "/output"]
    if view:
        command += ["--ro-bind", str(view), "/view.json"]
    probe = (
        "import pathlib,json,socket,subprocess;"
        "paths=['/home','/private.json','/master-seed.bin','/generator.py','/other-view.json',"
        "'/scheduled_payout_generate.py','/controller.py','/proc/1/cmdline','/proc/self/mountinfo'];"
        "denied=[p for p in paths if not pathlib.Path(p).exists()];assert denied==paths;"
        "net=[n for i,n in socket.if_nameindex()];assert net==['lo'];"
        "u=subprocess.run(['/usr/bin/unshare','--user','--map-root-user','true'],capture_output=True);"
        "assert u.returncode!=0;"
        "print(json.dumps(dict(inaccessible=denied,interfaces=net,nested_user_namespace_denied=True)))"
    )
    checked = subprocess.run(command + ["--", "/usr/bin/python3", "-c", probe],
                             capture_output=True, text=True, check=True)
    save(out / "isolation.json", json.loads(checked.stdout))
    with (out / "observer.log").open("x") as log:
        subprocess.run(command + ["--", "/venv/bin/python", "/scheduled_payout_observer.py",
                                  "/input.json", "/view.json" if view else "-",
                                  "/output/predictions.json"], stdout=log, stderr=log, check=True)
    prediction = read(out / "predictions.json")
    if (prediction["input_sha256"] != pins["input_sha256"] or
            prediction["view_sha256"] != pins["view_sha256"]):
        raise ValueError("observer input identity changed")
    return dict(case=name, arm=arm, observer=observer_name(who), seconds=prediction["seconds"])


def run(root, workers):
    cfg = freeze()
    preparation = read(root / "preparation.json")
    for name, digest in preparation["files"].items():
        if sha(root / name) != digest:
            raise ValueError("prepared input changed")
    snapshot = root / "source"
    snapshot.mkdir(mode=0o700)
    for name in SOURCES:
        shutil.copyfile(HERE / name, snapshot / name)
    save(root / "execution-pins.json", dict(
        freeze=FREEZE, git_head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=HERE,
                                                       text=True).strip(),
        sources={n: sha(snapshot / n) for n in SOURCES}, workers=workers,
        preparation_sha256=sha(root / "preparation.json"),
        versions=subprocess.check_output([str(h16.h14.VENV / "bin/python"), "-c",
                                          "import sys,ortools,z3; print(sys.version,ortools.__version__,z3.get_version_string())"],
                                         text=True).strip()))
    executions, failures = [], []
    pending = list(jobs(cfg))
    start = time.monotonic()
    with ThreadPoolExecutor(workers) as pool:
        futures = {pool.submit(observe, root, *j): j for j in pending}
        for future in as_completed(futures):
            try:
                result = future.result()
                executions.append(result)
                print(f"{len(executions)}/{len(pending)} observed: "
                      f"{result['case']} {result['arm']} {result['observer']} "
                      f"{result['seconds']:.1f}s", flush=True)
            except Exception as exc:
                failures.append(dict(job=futures[future], error=str(exc)))
                print(f"Observation failed: {futures[future]}: {exc}", flush=True)
    save(root / "execution.json", dict(executions=executions, failures=failures,
                                     elapsed_seconds=time.monotonic() - start))
    if failures:
        raise ValueError("incomplete matrix; truth scoring prohibited")


def score_all(root):
    cfg = freeze()
    pins = read(root / "execution-pins.json")
    for n, digest in pins["sources"].items():
        if sha(HERE / n) != digest or sha(root / "source" / n) != digest:
            raise ValueError("scoring/program sources changed")
    complete, matrix = [], {}
    # Finish all public identity checks before opening any private scoring file.
    for name, arm, who in jobs(cfg):
        folder = root / name / arm
        out = folder / observer_name(who)
        prediction = read(out / "predictions.json")
        observed = read(out / "pins.json")
        if observed["sources"] != {n: pins["sources"][n] for n in OBSERVERS}:
            raise ValueError("observer source identity")
        view = folder / f"view-{who}.json" if who is not None else None
        if (prediction["input_sha256"] != sha(folder / "public.json") or
                prediction["view_sha256"] != (sha(view) if view else None)):
            raise ValueError("observer input identity")
        matrix[f"{name}/{arm}/{observer_name(who)}"] = sha(out / "predictions.json")
        complete.append((name, arm, who, prediction))
    save(root / "observation-matrix.json", matrix)
    scores = {}
    for name, arm, who, prediction in complete:
        folder = root / name / arm
        result = score(read(folder / "public.json"), read(folder / "private.json"), prediction, who,
                       read(folder / f"view-{who}.json") if who is not None else None)
        save(folder / observer_name(who) / "score.json", result)
        scores[name, arm, observer_name(who)] = result
    costs = {n: read(root / n / "costs.json") for n, _, _ in cases(cfg)}
    summary = summarize(cfg, scores, costs)
    controls = {}
    for arm in ("full", "scheduled"):
        rows = scores["control-singleton", arm, "chain"]["timed"]["claims"]
        if not all(r["unique"] and all(r["correct"].values()) for r in rows):
            raise ValueError("singleton negative control failed")
        immediate = read(root / "control-immediate" / arm / "private.json")
        own = [c for c in immediate["claims"] if c["owner"] == 0]
        if not own or any(c["shaped"] for c in own):
            raise ValueError("immediate override failed")
        if not all(immediate["records"][c["legs"][0]]["saved"] for c in own):
            raise ValueError("immediate control did not use saved anchors")
        controls[arm] = dict(singleton_claims=len(rows), singleton_links=len(rows),
                             immediate_saved_claims=len(own), passed=True)
    summary["controls"] = controls
    save(root / "summary.json", summary)
    save(root / "costs.json", costs)
    print(json.dumps(summary, indent=2), flush=True)


def export(root, dest):
    cfg = freeze()
    summary = read(root / "summary.json")
    if summary["observations"] != len(list(jobs(cfg))):
        raise ValueError("incomplete export")
    dest.mkdir(mode=0o755)
    for n in ("summary.json", "execution-pins.json", "execution.json",
              "observation-matrix.json", "controls.log"):
        shutil.copyfile(root / n, dest / n)
    costs = read(root / "costs.json")
    for case in costs.values():
        for row in case["delays"]:
            row.pop("request_minute")  # hidden user intent is not public evidence
    save(dest / "costs.json", costs)
    for name, arm, who in jobs(cfg):
        folder, out = root / name / arm, dest / name / arm / observer_name(who)
        out.mkdir(parents=True)
        if who is None:
            shutil.copyfile(folder / "public.json", out.parent / "public.json")
        for n in ("score.json", "pins.json", "isolation.json"):
            shutil.copyfile(folder / observer_name(who) / n, out / n)
        raw = read(folder / observer_name(who) / "predictions.json")
        # Remove all participant-authored/received targets from published predictions.
        private = read(folder / "private.json")
        from scheduled_payout_score import eligible
        for p in ("untimed", "timed"):
            raw[p]["rows"] = [r for r in raw[p]["rows"] if eligible(private, r["event"], who)]
        raw["complete_prediction_sha256"] = sha(folder / observer_name(who) / "predictions.json")
        raw["export_boundary"] = "eligible targets only; no private records/requests/seed/keys"
        save(out / "predictions.json", raw)
    save(dest / "SHA256SUMS.json", {str(p.relative_to(dest)): sha(p) for p in sorted(dest.rglob("*"))
                                   if p.is_file()})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "run", "score", "export"))
    parser.add_argument("root", type=Path)
    parser.add_argument("destination", nargs="?", type=Path)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.command == "prepare":
        prepare(root)
    elif args.command == "run":
        run(root, args.workers)
    elif args.command == "score":
        score_all(root)
    else:
        export(root, args.destination.resolve())
