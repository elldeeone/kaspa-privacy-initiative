#!/usr/bin/env python3
"""Freeze, sample, predict and separately score a bounded practical privacy screen.

All outputs are create-only. The observer sees one public history and one view;
all predictions are sealed before the first scorer can receive private truth.
No native transactions, wallet keys, funds, proofs or network access are used.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

import early_privacy_surface as surface
from early_privacy_surface import dependency_manifest, need, read, sandbox, save, sha

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RUNNER = "population_privacy_strong_trial.py"
SPEC = "POPULATION-PRIVACY-STRONG-SPEC.md"
SOURCES = (RUNNER, "population_privacy_strong.py", "population_privacy_strong_score.py",
           "population_privacy_strong_workload.py", "population_privacy_workload.py",
           "population_privacy_model.py", "two_input_privacy_observer.py",
           "two_input_privacy_z3.py", "early_privacy_surface.py")
REGIMES = ("overlap",) * 8 + ("sparse",) * 8
CANDIDATE = "52c209296184d880221432fcbf56bb20d3f64d10"
VENV = Path("/home/luke/.local/share/kpi-shared-pool-tools")


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def plain_file(path):
    need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
         "ordinary file without symlink ancestors required: " + str(path))
    return path


def prepare(output, venv):
    need(not output.is_relative_to(ROOT), "private attempt must be outside repository")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    need(head == CANDIDATE, "candidate changed; specify a new experiment")
    output.mkdir(mode=0o700)
    for name in ("code", "private", "runs", "notes"):
        (output / name).mkdir(mode=0o700)
    for name in SOURCES + (SPEC,):
        shutil.copyfile(plain_file(HERE / name), output / "code" / name)
    import population_privacy_strong_workload as workload
    save(output / "policy.json", workload.public_policy())
    notes = ("docs/rfc/0012-useful-privacy-requirements.md",
             "docs/rfc/0014-owner-aware-privacy-evaluation.md",
             "research/shielded-kas-strong-privacy-screen-2026-10-21.md")
    for name in notes:
        destination = output / "notes" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(plain_file(ROOT / name), destination)
    candidate_files = [*sorted((HERE / "src").rglob("*.rs")), HERE / "Cargo.toml", HERE / "Cargo.lock"]
    calibration = HERE / "evidence/2026-10-21-native-key-separation"
    freeze = dict(
        schema="kpi-strong-privacy-freeze-v1", frozen_utc=now(), candidate=CANDIDATE,
        policy_sha256=sha(output / "policy.json"),
        sources={name: sha(output / "code" / name) for name in SOURCES + (SPEC,)},
        notes={name: sha(output / "notes" / name) for name in notes},
        candidate_files={str(p.relative_to(ROOT)): sha(plain_file(p)) for p in candidate_files},
        calibration={name: sha(plain_file(calibration / name)) for name in
                     ("SHA256SUMS", "native/source-before.json", "review/integrity-review.json")},
        dependency_root=str(venv), dependencies=dependency_manifest(venv),
        ordered_regimes=list(REGIMES), independent_histories=16,
        scope="Synthetic persistent balances; pooled eight-member records; final horizon only",
        scoring_barrier="Every prediction and batch sealed before any private scoring",
        maximum_parallel_scorers=2,
        qualification_pass=False,
        runtime_trust="Author-written code and host/system runtime; isolation is not external assurance")
    save(output / "freeze.json", freeze)
    return dict(prepared=True, sampled=False, frozen_utc=freeze["frozen_utc"],
                freeze_sha256=sha(output / "freeze.json"))


def check(output):
    frozen = read(plain_file(output / "freeze.json"))
    need(frozen["schema"] == "kpi-strong-privacy-freeze-v1" and frozen["candidate"] == CANDIDATE,
         "unknown frozen candidate")
    need(set(frozen["sources"]) == set(SOURCES + (SPEC,)), "source closure changed")
    need(frozen["ordered_regimes"] == list(REGIMES), "regime order changed")
    need(sha(plain_file(output / "policy.json")) == frozen["policy_sha256"], "frozen policy changed")
    for module in (Path(__file__).resolve(), Path(surface.__file__).resolve()):
        need(sha(module) == frozen["sources"][module.name], "loaded source differs from freeze")
    for name, expected in frozen["sources"].items():
        need(sha(plain_file(output / "code" / name)) == expected, "frozen source changed: " + name)
    for name, expected in frozen["notes"].items():
        need(sha(plain_file(output / "notes" / name)) == expected, "frozen note changed")
    need(dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
         "dependency bytes changed")
    return frozen


def isolated(output, frozen, label, mode, inputs=()):
    allowed = {"_controls": (), "_generate": ("/seeds.json",),
               "_observe": ("/public.json", "/view.json", "/policy.json"),
               "_score": ("/public.json", "/view.json", "/policy.json", "/prediction.json", "/truth.json"),
               "_aggregate": ("/scores.json",)}
    mounts = tuple(mount for _, mount in inputs)
    need(mode in allowed and mounts == allowed[mode], "unexpected isolated inputs")
    destination = output / "runs" / label
    destination.mkdir(mode=0o700)
    command = sandbox() + ["--ro-bind", frozen["dependency_root"], "/venv",
                           "--bind", str(destination), "/output"]
    for name in SOURCES:
        command += ["--ro-bind", str(plain_file(output / "code" / name)), "/" + name]
    for path, mount in inputs:
        command += ["--ro-bind", str(plain_file(path)), mount]
    probe = ("import pathlib,json;assert not pathlib.Path('/home').exists();"
             "interfaces=[x.split(':')[0].strip() for x in "
             "pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x];"
             "assert interfaces==['lo'];print(json.dumps({'interfaces':interfaces,"
             "'home_accessible':False}))")
    checked = subprocess.run(command + ["--", "/venv/bin/python", "-c", probe],
                             capture_output=True, text=True, check=True)
    audit = json.loads(checked.stdout)
    audit.update(mode=mode, inputs=list(mounts), private_truth_mounted="/truth.json" in mounts,
                 private_seeds_mounted="/seeds.json" in mounts)
    save(destination / "isolation.json", audit)
    save(destination / "inputs.json", {mount: sha(path) for path, mount in inputs})
    started = now()
    with (destination / "stdout.log").open("x") as out, (destination / "stderr.log").open("x") as err:
        status = subprocess.run(command + ["--", "/venv/bin/python", "/" + RUNNER, mode],
                                stdout=out, stderr=err)
    save(destination / "process.json", dict(started_utc=started, ended_utc=now(), returncode=status.returncode))
    need(status.returncode == 0, "isolated process failed; preserve " + str(destination))
    return destination, read(plain_file(destination / "result.json"))


def controls(output):
    frozen = check(output)
    directory, result = isolated(output, frozen, "controls", "_controls")
    need(result["passed"] is True, "controls must all pass")
    check(output)
    save(output / "controls.json", dict(passed=True, completed_utc=now(),
                                       result_sha256=sha(directory / "result.json"), result=result))
    return result


def generate(output):
    frozen = check(output)
    control = read(output / "controls.json")
    need(control["passed"] is True and control["result_sha256"] ==
         sha(output / "runs/controls/result.json"), "controls must pass before sampling")
    need(not any((output / "private").iterdir()), "no replacement seeds or reused attempt")
    bundles = [dict(requests=secrets.token_hex(32), opaque=secrets.token_hex(32)) for _ in REGIMES]
    need(len({v for bundle in bundles for v in bundle.values()}) == 32, "seed collision")
    save(output / "private/seeds.json", bundles)
    save(output / "seed-commitments.json", dict(sampled_utc=now(), freeze_sha256=sha(output / "freeze.json"),
         commitments=[canonical(bundle) for bundle in bundles], independent_histories=16,
         seed_bundle_sha256=sha(output / "private/seeds.json")))
    directory, result = isolated(output, frozen, "generate", "_generate",
                                 [(output / "private/seeds.json", "/seeds.json")])
    need(result["complete"] is True, "incomplete generated history; preserve without resampling")
    need(sha(output / "private/seeds.json") == read(output / "seed-commitments.json")["seed_bundle_sha256"],
         "seed bundle changed during generation")
    check(output)
    save(output / "generation.json", dict(**result, completed_utc=now(),
         seed_commitments_sha256=sha(output / "seed-commitments.json"),
         result_sha256=sha(directory / "result.json")))
    return dict(generated=True, independent_histories=len(result["cases"]),
                ordinary_payments=sum(c["ordinary_payments"] for c in result["cases"]))


def generation(output):
    result = read(output / "generation.json")
    need(result["result_sha256"] == sha(output / "runs/generate/result.json") and
         result["seed_commitments_sha256"] == sha(output / "seed-commitments.json"), "generation changed")
    need(result["complete"] is True and len(result["cases"]) == len(REGIMES), "incomplete generation")
    seeds = read(output / "seed-commitments.json")
    need(seeds["freeze_sha256"] == sha(output / "freeze.json") and
         seeds["seed_bundle_sha256"] == sha(output / "private/seeds.json") and
         read(output / "runs/generate/inputs.json")["/seeds.json"] == seeds["seed_bundle_sha256"],
         "sampled seed identity changed")
    for i, (case, regime) in enumerate(zip(result["cases"], REGIMES, strict=True), 1):
        need(case["name"] == f"set-{i:02}-persistent" and case["regime"] == regime
             and case["ordinary_payments"] == 128 and case["complete"] is True, "case coverage changed")
    return result


def checked_inputs(output, case):
    directory = output / "runs/generate/public" / case["name"]
    expected = {"public.json", "pooled.json", "C.json"} | {f"P-{i}.json" for i in range(8)}
    need(set(case["pins"]) == expected, "public input roster changed")
    for name, digest in case["pins"].items():
        need(sha(plain_file(directory / name)) == digest, "public input changed")
    truth = output / "runs/generate/private" / (case["name"] + ".json")
    need(sha(plain_file(truth)) == case["truth_sha256"], "private truth changed")
    return [(directory / "public.json", "/public.json"), (directory / "pooled.json", "/view.json"),
            (output / "policy.json", "/policy.json")], truth


def run_all(output):
    frozen = check(output)
    cases = generation(output)["cases"]
    freeze_sha, generation_sha = sha(output / "freeze.json"), sha(output / "generation.json")
    predictions = []
    phase, current = "predict", None
    try:
        for case in cases:
            current = case["name"]
            inputs, _ = checked_inputs(output, case)
            label = current + "-pooled-final"
            directory, prediction = isolated(output, frozen, label, "_observe", inputs)
            need(prediction["complete"] is True, "incomplete prediction")
            seal = dict(case=current, sealed_utc=now(), freeze_sha256=freeze_sha,
                        prediction_sha256=sha(directory / "result.json"),
                        inputs={mount: sha(path) for path, mount in inputs}, truth_sha256=case["truth_sha256"])
            save(directory / "prediction-seal.json", seal)
            predictions.append(dict(case=current, label=label, prediction=seal,
                                    seal_sha256=sha(directory / "prediction-seal.json")))
            print(json.dumps(dict(phase="prediction-sealed", case=current)), flush=True)
        check(output)
        batch = dict(schema="kpi-strong-privacy-batch-v1", sealed_utc=now(), complete=True,
                     predictions=predictions, freeze_sha256=freeze_sha, generation_sha256=generation_sha,
                     scoring_started=False)
        save(output / "prediction-batch.json", batch)
        batch_sha = sha(output / "prediction-batch.json")

        def verify_batch():
            need(sha(output / "prediction-batch.json") == batch_sha and
                 sha(output / "freeze.json") == freeze_sha and sha(output / "generation.json") == generation_sha,
                 "sealed identity changed")
            for case, entry in zip(cases, predictions, strict=True):
                checked_inputs(output, case)
                d = output / "runs" / entry["label"]
                need(sha(d / "prediction-seal.json") == entry["seal_sha256"] and
                     sha(d / "result.json") == entry["prediction"]["prediction_sha256"], "sealed prediction changed")

        phase = "score"
        current = "sealed-batch"

        def score_one(pair):
            case, entry = pair
            name = case["name"]
            verify_batch()
            inputs, truth = checked_inputs(output, case)
            observed = output / "runs" / entry["label"]
            print(json.dumps(dict(phase="score-started", case=name)), flush=True)
            scored, result = isolated(output, frozen, entry["label"] + "-score", "_score", inputs + [
                (observed / "result.json", "/prediction.json"), (truth, "/truth.json")])
            need(result["complete"] is True, "incomplete score")
            verify_batch()
            save(observed / "completion.json", dict(complete=True, prediction_batch_sha256=batch_sha,
                 score_sha256=sha(scored / "result.json"), qualification_pass=False))
            print(json.dumps(dict(phase="scored", case=name)), flush=True)
            return dict(case=name, regime=case["regime"], score=result)

        with ThreadPoolExecutor(max_workers=2) as pool:
            scores = list(pool.map(score_one, zip(cases, predictions, strict=True)))
        save(output / "scores.json", scores)
        phase, current = "aggregate", None
        aggregated, result = isolated(output, frozen, "aggregate", "_aggregate",
                                      [(output / "scores.json", "/scores.json")])
        verify_batch()
        check(output)
        save(output / "completion.json", dict(complete=result["complete"], execution_completed=True, completed_utc=now(),
             prediction_batch_sha256=batch_sha, aggregate_sha256=sha(aggregated / "result.json"),
             scores_sha256=sha(output / "scores.json"), qualification_pass=False,
             independent_histories=len(cases), result=result))
        return dict(complete=result["complete"], execution_completed=True, independent_histories=len(cases), qualification_pass=False,
                    report=str(output / "completion.json"))
    except Exception as error:
        save(output / "failure.json", dict(complete=False, phase=phase, case=current,
             error_type=type(error).__name__, failed_utc=now(), qualification_pass=False,
             scope="Preserved incomplete computation, not privacy evidence"))
        raise


def generate_private():
    import population_privacy_strong_workload as workload
    import population_privacy_workload as original
    bundles = read(Path("/seeds.json"))
    need(len(bundles) == len(REGIMES), "seed bundle count")
    base = Path("/output")
    (base / "public").mkdir(mode=0o700)
    (base / "private").mkdir(mode=0o700)
    cases = []
    for index, (bundle, regime) in enumerate(zip(bundles, REGIMES, strict=True), 1):
        history = workload.generate(bundle, regime)["persistent"]
        name = f"set-{index:02}-persistent"
        public, truth = history["public"], history["truth"]
        directory = base / "public" / name
        directory.mkdir(mode=0o700)
        save(directory / "public.json", public)
        save(base / "private" / (name + ".json"), truth)
        for view_name, members in [("C", []), ("pooled", list(range(8)))] + [(f"P-{r}", [r]) for r in range(8)]:
            save(directory / (view_name + ".json"), original.make_view(public, truth, members))
        cases.append(dict(name=name, regime=regime, complete=history["complete"], error=history["error"],
             events=len(public["algebra"]["events"]),
             ordinary_payments=sum(e["kind"] == "payment" for e in truth["events"]),
             pins={p.name: sha(p) for p in sorted(directory.glob("*.json"))},
             truth_sha256=sha(base / "private" / (name + ".json")),
             accounting={k: v for k, v in truth["accounting"].items() if not k.startswith("role_")}))
    return dict(complete=all(c["complete"] for c in cases), cases=cases, independent_histories=len(cases))


def internal(mode):
    if mode == "_generate":
        return generate_private()
    if mode == "_controls":
        import population_privacy_model as model
        import population_privacy_strong_workload as workload
        import population_privacy_strong as observer
        import population_privacy_strong_score as scorer
        results = dict(model=model.controls(), workload=workload.controls(),
                       observer=observer.controls(), scorer=scorer.controls())
        return dict(passed=all(v["passed"] is True for v in results.values()), results=results)
    if mode == "_observe":
        import population_privacy_strong as observer
        return observer.analyze(read(Path("/public.json")), read(Path("/view.json")), read(Path("/policy.json")))
    if mode == "_score":
        import population_privacy_strong_score as scorer
        return scorer.score(*(read(Path("/" + n + ".json")) for n in
                              ("public", "view", "prediction", "truth", "policy")))
    need(mode == "_aggregate", "unknown internal command")
    import population_privacy_strong_score as scorer
    return scorer.aggregate(read(Path("/scores.json")))


def main():
    os.umask(0o077)
    if len(sys.argv) > 1 and sys.argv[1].startswith("_"):
        save(Path("/output/result.json"), internal(sys.argv[1]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "controls", "generate", "run"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--venv", type=Path, default=VENV)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.command == "prepare":
        result = prepare(output, args.venv.resolve())
    else:
        result = {"controls": controls, "generate": generate, "run": run_all}[args.command](output)
    print(json.dumps(result, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
