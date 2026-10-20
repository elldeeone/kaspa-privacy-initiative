#!/usr/bin/env python3
"""H15 controller/scorer/exporter. Never mounted inside an observer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "evidence/2026-10-20-two-input-reconstruction"
FREEZE = "7bf197f"
OBSERVER_FILES = (
    "wallet_policy_observer.py", "two_input_privacy_observer.py",
    "two_input_privacy_z3.py", "two_input_privacy_exact.py",
)
spec = importlib.util.spec_from_file_location("h14_controller", HERE / "two-input-privacy.py")
h14 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h14)


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
    path.chmod(0o600)


def freeze():
    for name in ("WALLET-POLICY-PRIVACY-SPEC.md", "wallet-policy-privacy-freeze.json"):
        pinned = subprocess.check_output(
            ["git", "show", f"{FREEZE}:poc/shared-pool/{name}"], cwd=HERE)
        if pinned != (HERE / name).read_bytes():
            raise ValueError("frozen policy assumptions changed")
    config = read(HERE / "wallet-policy-privacy-freeze.json")
    for name, digest in config["sources"].items():
        if sha(HERE / name) != digest:
            raise ValueError(f"source policy or original relation changed: {name}")
    expected = subprocess.check_output([
        "git", "show",
        "fe5514b:poc/shared-pool/evidence/2026-10-20-two-input-reconstruction/SHA256SUMS.json",
    ], cwd=HERE)
    if expected != (BASELINE / "SHA256SUMS.json").read_bytes():
        raise ValueError("H14 evidence manifest changed")
    for name, digest in read(BASELINE / "SHA256SUMS.json").items():
        if sha(BASELINE / name) != digest:
            raise ValueError(f"H14 evidence changed: {name}")
    return config


def prepare(root, original):
    config = freeze()
    root.mkdir(mode=0o700)
    truth_hashes = {}
    for case in config["cases"]:
        folder = root / case
        folder.mkdir(mode=0o700)
        for arm in config["arms"]:
            source = original / case / f"{arm}.json"
            if sha(source) != config["public_input_hashes"][f"{case}/{arm}"]:
                raise ValueError("original input differs from frozen H14")
            shutil.copyfile(source, folder / f"{arm}.json")
        source = original / case / "truth.json"
        shutil.copyfile(source, folder / "truth.json")
        (folder / "truth.json").chmod(0o600)
        truth_hashes[case] = sha(source)
    save(root / "private-provenance.json",
         dict(original=str(original), truth_sha256=truth_hashes, freeze_commit=FREEZE))


def nested(stronger, weaker):
    before = {r["event"]: r for r in weaker["rows"]}
    after = {r["event"]: r for r in stronger["rows"]}
    if before.keys() != after.keys():
        raise ValueError("different inference targets")
    checked = 0
    for event, row in after.items():
        old = before[event]
        old_h = {h["through"]: h for h in old["joint"]}
        pairs = [(row[k], old[k]) for k in ("structural", "amount")]
        pairs += [(h, old_h[h["through"]]) for h in row["joint"]]
        for strong, weak in pairs:
            for key in ("input_sets", "source_sets"):
                if not {tuple(c) for c in strong[key]} <= {tuple(c) for c in weak[key]}:
                    raise ValueError("stronger model introduced a candidate")
            checked += 1
    return checked


def observe(root, case, arm, profile):
    public = root / case / f"{arm}.json"
    out = root / case / f"{profile}-{arm}-observation"
    out.mkdir(mode=0o700)
    save(out / "pins.json", dict(input_sha256=sha(public),
                                sources={n: sha(HERE / n) for n in OBSERVER_FILES}))
    command = h14.sandbox() + ["--ro-bind", str(h14.VENV), "/venv"]
    for name in OBSERVER_FILES:
        command += ["--ro-bind", str(HERE / name), f"/{name}"]
    command += ["--ro-bind", str(public), "/input.json",
                "--bind", str(out), "/output"]
    probe = (
        "import pathlib,json;"
        "paths=['/home','/workload.json','/truth.json','/generator.py','/controller.py'];"
        "denied=[p for p in paths if not pathlib.Path(p).exists()];assert denied==paths;"
        "net=[l.split(':')[0].strip() for l in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in l];"
        "assert net==['lo'];print(json.dumps(dict(inaccessible=denied,interfaces=net)))"
    )
    receipt = subprocess.run(command + ["--", "/usr/bin/python3", "-c", probe],
                             capture_output=True, text=True, check=True)
    save(out / "isolation.json", json.loads(receipt.stdout))
    with (out / "observer.log").open("x") as log:
        subprocess.run(command + [
            "--", "/venv/bin/python", "/wallet_policy_observer.py",
            "/input.json", "/output/predictions.json", profile,
        ], stdout=log, stderr=log, check=True)
    predictions = read(out / "predictions.json")
    if predictions["input_sha256"] != sha(public) or predictions["profile"] != profile:
        raise ValueError("observer input/profile identity")
    # Private truth is opened only after the isolated process completes.
    score = h14.score_result(read(root / case / "truth.json"), read(public), predictions)
    score["nested_in_protocol_comparisons"] = nested(
        predictions, read(BASELINE / case / arm / "predictions.json"))
    save(out / "score.json", score)
    print(f"{case} {arm} {profile}: complete in {predictions['seconds']:.2f}s", flush=True)
    return dict(case=case, arm=arm, profile=profile, score=score,
                seconds=predictions["seconds"], queries=predictions["feasibility_queries"])


def aggregates(executions):
    result = {}
    for profile in ("protocol", "shape", "wallet"):
        result[profile] = {}
        for arm in ("fresh", "saved"):
            scores = [r["score"] for r in executions if r["profile"] == profile and r["arm"] == arm]
            totals = {}
            for category in ("payment", "partial", "exit"):
                for key in scores[0]["summaries"][category]:
                    parts = [s["summaries"][category][key] for s in scores]
                    fields = ("targets", "correct_sources", "correct_inputs",
                              "unique_sources", "unique_inputs")
                    total = {f: sum(s[f] for s in parts) for f in fields}
                    counts = [n for s in parts for n in s["source_candidate_counts"]]
                    total.update(source_candidates_min=min(counts),
                                 source_candidates_max=max(counts),
                                 source_candidates_sum=sum(counts),
                                 unique_source_coverage=total["unique_sources"] / total["targets"],
                                 singleton_precision=1 if total["unique_sources"] else None)
                    totals[f"{category}:{key}"] = total
            result[profile][arm] = totals
    return result


def run(root, workers):
    config = freeze()
    sources = (*OBSERVER_FILES, "wallet-policy-privacy.py", "wallet_policy_tests.py",
               "two-input-privacy.py")
    save(root / "execution-pins.json", dict(
        freeze_commit=FREEZE, frozen_config_sha256=sha(HERE / "wallet-policy-privacy-freeze.json"),
        sources={n: sha(HERE / n) for n in sources},
        versions=subprocess.check_output([
            str(h14.VENV / "bin/python"), "-c",
            "import sys,z3,ortools,json;print(json.dumps(dict(python=sys.version,z3=z3.get_version_string(),ortools=ortools.__version__)))",
        ], text=True).strip(),
    ))
    with (root / "controls.log").open("x") as log:
        subprocess.run([str(h14.VENV / "bin/python"), "-m", "unittest",
                        "two_input_privacy_tests", "wallet_policy_tests", "-v"],
                       cwd=HERE, stdout=log, stderr=log, check=True)
    jobs = [(case, arm, profile) for case in config["cases"]
            for arm in config["arms"] for profile in config["profiles"]]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        executions = list(pool.map(lambda args: observe(root, *args), jobs))
    baseline = [dict(case=c, arm=a, profile="protocol",
                     score=read(BASELINE / c / a / "score.json"))
                for c in config["cases"] for a in config["arms"]]
    pairs = []
    nesting = 0
    retroactive = []
    for case in config["cases"]:
        for arm in config["arms"]:
            shape = read(root / case / f"shape-{arm}-observation/predictions.json")
            wallet = read(root / case / f"wallet-{arm}-observation/predictions.json")
            nesting += nested(wallet, shape)
        for profile in config["profiles"]:
            scores = {r["arm"]: r["score"]["summaries"]["payment"]["joint:after_drain"]
                      for r in executions if r["case"] == case and r["profile"] == profile}
            pairs.append(dict(case=case, profile=profile, **scores,
                              fresh_ambiguous=6 - scores["fresh"]["unique_sources"],
                              saved_ambiguous=6 - scores["saved"]["unique_sources"],
                              fresh_source_candidates=sum(scores["fresh"]["source_candidate_counts"]),
                              saved_source_candidates=sum(scores["saved"]["source_candidate_counts"])))
    for result in executions:
        rows = [s for s in result["score"]["rows"]
                if s["category"] == "payment" and s["attack"] == "joint"]
        for event in sorted({s["event"] for s in rows}):
            snapshots = sorted((s for s in rows if s["event"] == event), key=lambda s: s["through"])
            before, after = snapshots[0]["source_candidates"], snapshots[-1]["source_candidates"]
            retroactive.append(dict(case=result["case"], arm=result["arm"], profile=result["profile"],
                                    event=event, before=before, after=after,
                                    narrowed=after < before, became_unique=before > 1 and after == 1,
                                    counts=[s["source_candidates"] for s in snapshots]))
    primary = [p for p in pairs if p["profile"] == config["primary_profile"]]
    passes = (all(p["fresh_ambiguous"] >= 3 for p in primary)
              and any(p["fresh_source_candidates"] > p["saved_source_candidates"] for p in primary))
    save(root / "aggregates.json", aggregates(baseline + executions))
    save(root / "retroactive.json", retroactive)
    save(root / "summary.json", dict(
        pairs=pairs, primary_profile=config["primary_profile"], frozen_screen_passes=passes,
        general_privacy_established=False, conditional_on_known_wallet=True,
        completed_observations=len(executions), all_truth_survives=True,
        nested_wallet_shape_comparisons=nesting,
        actual_tkas_spent=0, new_proofs_generated=0,
        mechanical_calibration="inherited unchanged from H14; not rerun",
        executions=[{k: v for k, v in r.items() if k != "score"} for r in executions],
    ))
    print(json.dumps(dict(frozen_screen_passes=passes, completed_observations=len(executions))), flush=True)


def export(root, destination):
    config = freeze()
    summary = read(root / "summary.json")
    if summary["completed_observations"] != 16 or not summary["all_truth_survives"]:
        raise ValueError("incomplete study")
    pins = read(root / "execution-pins.json")
    if any(sha(HERE / n) != h for n, h in pins["sources"].items()):
        raise ValueError("source changed after observation")
    destination.mkdir()
    for name in ("summary.json", "aggregates.json", "retroactive.json",
                 "execution-pins.json", "controls.log"):
        shutil.copyfile(root / name, destination / name)
    for case in config["cases"]:
        for arm in config["arms"]:
            public = root / case / f"{arm}.json"
            if sha(public) != config["public_input_hashes"][f"{case}/{arm}"]:
                raise ValueError("public trace changed")
            target = destination / case / arm
            target.mkdir(parents=True)
            shutil.copyfile(public, target / "public.json")
            for profile in config["profiles"]:
                out = target / profile
                out.mkdir()
                source = root / case / f"{profile}-{arm}-observation"
                for name in ("predictions.json", "score.json", "pins.json",
                             "isolation.json", "observer.log"):
                    shutil.copyfile(source / name, out / name)
    hashes = {str(p.relative_to(destination)): sha(p)
              for p in sorted(destination.rglob("*")) if p.is_file()}
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
