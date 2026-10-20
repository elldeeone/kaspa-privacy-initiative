#!/usr/bin/env python3
"""H16 controller, scorer and sanitized exporter. Never mount in an observer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import resource
import shutil
import subprocess
import time

from participant_privacy_view import eligible_targets, project

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "evidence/2026-10-20-wallet-policy-reconstruction"
FREEZE = "5c44c55"
spec = importlib.util.spec_from_file_location("h15_controller", HERE / "wallet-policy-privacy.py")
h15 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h15)
h14 = h15.h14
read, save, sha = h15.read, h15.save, h15.sha
OBSERVER_FILES = ("participant_privacy_observer.py", *h15.OBSERVER_FILES)
SOURCES = (*OBSERVER_FILES, "participant_privacy_view.py", "participant-privacy.py",
           "participant_privacy_tests.py", "wallet_policy_tests.py",
           "two_input_privacy_tests.py", "wallet-policy-privacy.py", "two-input-privacy.py")


def sandbox():
    command = h14.sandbox()
    # H14/H15's /proc also exposes bwrap's host mount paths (case/arm labels)
    # in supervisor argv and mountinfo. Neither observer reads them, but H16's
    # declared access boundary should not make them available at all.
    proc = command.index("--proc")
    del command[proc:proc + 2]
    return command + ["--unshare-user", "--as-pid-1", "--disable-userns", "--cap-drop", "ALL"]


def freeze():
    h15.freeze()  # Includes every retained H14 evidence digest.
    for name in ("PARTICIPANT-PRIVACY-SPEC.md", "participant-privacy-freeze.json"):
        pinned = subprocess.check_output(["git", "show", f"{FREEZE}:poc/shared-pool/{name}"],
                                         cwd=HERE)
        if pinned != (HERE / name).read_bytes():
            raise ValueError("H16 frozen specification changed")
    config = read(HERE / "participant-privacy-freeze.json")
    for name, digest in config["sources"].items():
        if sha(HERE / name) != digest:
            raise ValueError(f"frozen source changed: {name}")
    if sha(BASELINE / "SHA256SUMS.json") != config["baseline_manifest_sha256"]:
        raise ValueError("H15 manifest changed")
    for name, digest in read(BASELINE / "SHA256SUMS.json").items():
        if sha(BASELINE / name) != digest:
            raise ValueError(f"H15 evidence changed: {name}")
    return config


def prepare(root, original):
    config = freeze()
    root.mkdir(mode=0o700)
    views = {}
    for case in config["cases"]:
        folder = root / case
        folder.mkdir(mode=0o700)
        for name in ("plan.json", "truth.json"):
            source = original / case / name
            if sha(source) != config["private_source_hashes"][f"{case}/{name}"]:
                raise ValueError("original private source changed")
            shutil.copyfile(source, folder / name)
            (folder / name).chmod(0o600)
        plan = read(folder / "plan.json")
        for arm in config["arms"]:
            source = original / case / f"{arm}.json"
            digest = sha(source)
            if digest != config["public_input_hashes"][f"{case}/{arm}"]:
                raise ValueError("original public input changed")
            shutil.copyfile(source, folder / f"{arm}.json")
            for participant in config["participants"]:
                name = f"{arm}-participant-{participant}.json"
                save(folder / name, project(plan, participant, digest))
                views[f"{case}/{name}"] = sha(folder / name)
    save(root / "private-provenance.json", dict(original=str(original), freeze_commit=FREEZE,
                                               projected_views_sha256=views))


def observe(root, case, arm, participant, profile):
    public = root / case / f"{arm}.json"
    view = root / case / f"{arm}-participant-{participant}.json"
    out = root / case / f"{arm}-{participant}-{profile}"
    out.mkdir(mode=0o700)
    pins = dict(input_sha256=sha(public), view_sha256=sha(view),
                sources={n: sha(HERE / n) for n in OBSERVER_FILES})
    save(out / "pins.json", pins)
    command = sandbox() + ["--ro-bind", str(h14.VENV), "/venv"]
    for name in OBSERVER_FILES:
        command += ["--ro-bind", str(HERE / name), f"/{name}"]
    command += ["--ro-bind", str(public), "/input.json", "--ro-bind", str(view), "/view.json",
                "--bind", str(out), "/output"]
    probe = (
        "import pathlib,json,socket,subprocess;"
        "paths=['/home','/plan.json','/truth.json','/workload.json','/other-view.json',"
        "'/participant_privacy_view.py','/controller.py','/proc/1/cmdline','/proc/self/mountinfo'];"
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
        subprocess.run(command + [
            "--", "/venv/bin/python", "/participant_privacy_observer.py",
            "/input.json", "/view.json", "/output/predictions.json", profile,
        ], stdout=log, stderr=log, check=True)
    predictions = read(out / "predictions.json")
    if (predictions["input_sha256"] != pins["input_sha256"]
            or predictions["view_sha256"] != pins["view_sha256"]
            or predictions["profile"] != profile
            or sha(public) != pins["input_sha256"] or sha(view) != pins["view_sha256"]):
        raise ValueError("observer identity changed")
    print(f"{case} {arm} participant {participant} {profile}: "
          f"complete in {predictions['seconds']:.2f}s", flush=True)
    return dict(case=case, arm=arm, participant=participant, profile=profile,
                seconds=predictions["seconds"], queries=predictions["feasibility_queries"])


def metric(rows):
    total = {k: sum(r[k] for r in rows)
             for k in ("correct_sources", "correct_inputs", "unique_sources", "unique_inputs")}
    n = len(rows)
    counts = [r["source_candidates"] for r in rows]
    inputs = [r["input_candidates"] for r in rows]
    unique = [r for r in rows if r["unique_sources"]]
    total.update(targets=n, newly_unique_sources=sum(r["new_unique_sources"] for r in rows),
                 source_candidate_counts=counts, input_candidate_counts=inputs,
                 source_candidates_sum=sum(counts), source_candidates_min=min(counts, default=None),
                 source_candidates_max=max(counts, default=None),
                 coverage=len(unique) / n if n else None,
                 singleton_precision=sum(r["correct_sources"] for r in unique) / len(unique) if unique else None,
                 abstentions=n - len(unique))
    return total


def summarize_rows(rows, last):
    result = {}
    for category in ("payment", "partial", "exit"):
        for horizon in ("at_event", "after_drain"):
            subset = [r for r in rows if r["category"] == category and r["attack"] == "joint"
                      and r["through"] == (r["event"] if horizon == "at_event" else last)]
            result[f"{category}:{horizon}"] = metric(subset)
    return result


def filtered_score(score, eligible, baseline, last):
    before = {(r["event"], r["attack"], r["through"]): r for r in baseline["rows"]}
    rows = []
    for row in score["rows"]:
        if row["event"] not in eligible or row["category"] == "bootstrap":
            continue
        old = before[row["event"], row["attack"], row["through"]]
        rows.append(dict(row, baseline_source_candidates=old["source_candidates"],
                         new_unique_sources=row["unique_sources"] and not old["unique_sources"]))
    return dict(rows=rows, summaries=summarize_rows(rows, last), all_truth_survives=True,
                target_boundary="no input or positive output owned by the disclosing account")


def run(root, workers):
    config = freeze()
    started = time.monotonic()
    provenance = read(root / "private-provenance.json")
    for name, digest in provenance["projected_views_sha256"].items():
        if sha(root / name) != digest:
            raise ValueError("projected record changed")
    for name, digest in config["private_source_hashes"].items():
        if sha(root / name) != digest:
            raise ValueError("private scoring source changed")
    for name, digest in config["public_input_hashes"].items():
        case, arm = name.split("/")
        if sha(root / case / f"{arm}.json") != digest:
            raise ValueError("public trace changed")
    save(root / "execution-pins.json", dict(
        freeze_commit=FREEZE, frozen_config_sha256=sha(HERE / "participant-privacy-freeze.json"),
        sources={n: sha(HERE / n) for n in SOURCES},
        versions=subprocess.check_output([
            str(h14.VENV / "bin/python"), "-c",
            "import sys,z3,ortools,json;print(json.dumps(dict(python=sys.version,z3=z3.get_version_string(),ortools=ortools.__version__)))",
        ], text=True).strip()))
    with (root / "controls.log").open("x") as log:
        subprocess.run([str(h14.VENV / "bin/python"), "-m", "unittest",
                        "two_input_privacy_tests", "wallet_policy_tests", "participant_privacy_tests", "-v"],
                       cwd=HERE, stdout=log, stderr=log, check=True)
    jobs = [(case, arm, participant, profile) for case in config["cases"]
            for arm in config["arms"] for participant in config["participants"]
            for profile in config["profiles"]]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        executions = list(pool.map(lambda args: observe(root, *args), jobs))
    # All observations have finished. Only now open ground truth for scoring.
    scores, chain_scores, nesting = {}, {}, dict(records_in_chain=0, wallet_in_records=0,
                                               saved_in_fresh=0)
    for case in config["cases"]:
        plan, truth = [read(root / case / f"{name}.json") for name in ("plan", "truth")]
        for arm in config["arms"]:
            public = read(root / case / f"{arm}.json")
            baseline = read(BASELINE / case / arm / "wallet/score.json")
            base_prediction = read(BASELINE / case / arm / "wallet/predictions.json")
            for participant in config["participants"]:
                eligible = eligible_targets(plan, participant)
                chain_scores[case, arm, participant] = filtered_score(
                    baseline, eligible, baseline, len(public["events"]) - 1)
                previous = base_prediction
                for profile in config["profiles"]:
                    out = root / case / f"{arm}-{participant}-{profile}"
                    prediction = read(out / "predictions.json")
                    full_score = h14.score_result(truth, public, prediction)
                    score = filtered_score(full_score, eligible, baseline, len(public["events"]) - 1)
                    comparison = "records_in_chain" if profile == "records" else "wallet_in_records"
                    nesting[comparison] += h15.nested(prediction, previous)
                    save(out / "score.json", score)
                    scores[case, arm, participant, profile] = score
                    previous = prediction
    pairs = []
    for case in config["cases"]:
        for participant in config["participants"]:
            for profile in config["profiles"]:
                for arm in config["arms"]:
                    # This enforces the known fresh/saved relation in addition
                    # to comparing aggregate counts. The observer gets no label.
                    if arm != "saved":
                        continue
                    saved = read(root / case / f"saved-{participant}-{profile}/predictions.json")
                    fresh = read(root / case / f"fresh-{participant}-{profile}/predictions.json")
                    nesting["saved_in_fresh"] += h15.nested(saved, fresh)
                p = {arm: scores[case, arm, participant, profile]["summaries"]["payment:after_drain"]
                     for arm in config["arms"]}
                pairs.append(dict(case=case, participant=participant, profile=profile, **p,
                                  fresh_ambiguous=p["fresh"]["targets"] - p["fresh"]["unique_sources"],
                                  at_least_half_fresh_ambiguous=(2 * (p["fresh"]["targets"] - p["fresh"]["unique_sources"])
                                                                 >= p["fresh"]["targets"])))
    aggregates = {}
    for profile in ("chain", *config["profiles"]):
        aggregates[profile] = {}
        for arm in config["arms"]:
            rows = []
            for case in config["cases"]:
                for participant in config["participants"]:
                    source = (chain_scores[case, arm, participant] if profile == "chain"
                              else scores[case, arm, participant, profile])
                    rows.extend(source["rows"])
            aggregates[profile][arm] = summarize_rows(rows, 18)
    primary = [p for p in pairs if p["profile"] == config["primary_profile"]]
    clauses = dict(
        no_new_unique_uninvolved_fresh_payments=all(p["fresh"]["newly_unique_sources"] == 0 for p in primary),
        half_ambiguous_in_every_fresh_case_participant=all(p["at_least_half_fresh_ambiguous"] for p in primary),
        strictly_more_fresh_alternatives_in_some_pair=any(
            p["fresh"]["source_candidates_sum"] > p["saved"]["source_candidates_sum"] for p in primary))
    retroactive = []
    for (case, arm, participant, profile), score in scores.items():
        payments = [r for r in score["rows"] if r["category"] == "payment" and r["attack"] == "joint"]
        for event in sorted({r["event"] for r in payments}):
            snapshots = sorted([r for r in payments if r["event"] == event], key=lambda r: r["through"])
            before, after = snapshots[0]["source_candidates"], snapshots[-1]["source_candidates"]
            retroactive.append(dict(case=case, arm=arm, participant=participant, profile=profile,
                                    event=event, before=before, after=after, narrowed=after < before,
                                    became_unique=before > 1 and after == 1,
                                    horizons=[dict(through=r["through"], candidates=r["source_candidates"])
                                              for r in snapshots]))
    save(root / "aggregates.json", aggregates)
    save(root / "retroactive.json", retroactive)
    save(root / "matched-chain-scores.json", [
        dict(case=c, arm=a, participant=p, **score) for (c, a, p), score in chain_scores.items()])
    save(root / "summary.json", dict(
        pairs=pairs, hypothesis_clauses=clauses, frozen_screen_passes=all(clauses.values()),
        completed_observations=len(executions), all_truth_survives=True, nesting=nesting,
        general_privacy_established=False, actual_tkas_spent=0, new_proofs_generated=0,
        added_native_fee_sompi=0, added_wallet_delay_seconds=0,
        hypothetical_fee_sompi_per_unchanged_arm=760000000,
        counts_are="overlapping case/participant/target observations, not independent payments",
        mechanical_calibration="inherited from unchanged H14, not rerun", executions=executions))
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    save(root / "resources.json", dict(
        wall_seconds=time.monotonic() - started, workers=workers,
        max_child_rss_kib=usage.ru_maxrss,
        rss_meaning="largest child-process high-water value, not concurrent aggregate RAM",
        child_user_seconds=usage.ru_utime, child_system_seconds=usage.ru_stime))
    print(json.dumps(dict(completed_observations=len(executions), hypothesis_clauses=clauses)), flush=True)


def export(root, destination):
    config = freeze()
    summary = read(root / "summary.json")
    if summary["completed_observations"] != 64 or not summary["all_truth_survives"]:
        raise ValueError("incomplete study")
    pins = read(root / "execution-pins.json")
    if any(sha(HERE / n) != digest for n, digest in pins["sources"].items()):
        raise ValueError("source changed after execution")
    destination.mkdir()
    for name in ("summary.json", "aggregates.json", "retroactive.json", "matched-chain-scores.json",
                 "execution-pins.json", "controls.log", "resources.json"):
        shutil.copyfile(root / name, destination / name)
    for case in config["cases"]:
        for arm in config["arms"]:
            public = root / case / f"{arm}.json"
            if sha(public) != config["public_input_hashes"][f"{case}/{arm}"]:
                raise ValueError("public input changed after execution")
            for participant in config["participants"]:
                for profile in config["profiles"]:
                    source = root / case / f"{arm}-{participant}-{profile}"
                    target = destination / case / arm / str(participant) / profile
                    target.mkdir(parents=True)
                    score = read(source / "score.json")
                    eligible = {r["event"] for r in score["rows"]}
                    prediction = read(source / "predictions.json")
                    view = root / case / f"{arm}-participant-{participant}.json"
                    if prediction["view_sha256"] != sha(view):
                        raise ValueError("projected record changed after execution")
                    # Keep own/disclosed activity and raw participant records
                    # private. Export only the explicitly scored targets.
                    prediction["rows"] = [r for r in prediction["rows"] if r["event"] in eligible]
                    prediction["export_boundary"] = "only scored targets, no discloser-owned activity"
                    prediction["complete_prediction_sha256"] = sha(source / "predictions.json")
                    save(target / "predictions.json", prediction)
                    for name in ("score.json", "pins.json", "isolation.json"):
                        shutil.copyfile(source / name, target / name)
    hashes = {str(p.relative_to(destination)): sha(p) for p in sorted(destination.rglob("*")) if p.is_file()}
    save(destination / "SHA256SUMS.json", hashes)
    print(json.dumps(dict(exported_files=len(hashes) + 1)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("root", type=Path)
    prep.add_argument("original", type=Path)
    runner = commands.add_parser("run")
    runner.add_argument("root", type=Path)
    runner.add_argument("--workers", type=int, default=4)
    exporter = commands.add_parser("export")
    exporter.add_argument("root", type=Path)
    exporter.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.root, args.original)
    elif args.command == "run":
        run(args.root, args.workers)
    else:
        export(args.root, args.destination)
