#!/usr/bin/env python3
"""Freeze and isolate a genuine offline native-transaction privacy experiment.

All paths are create-only. No network client or broadcast command is provided.
Generation sees fresh fixture wallets; observers see one declared public prefix
and participant view. Every prediction is sealed before private scoring.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import early_privacy_surface as surface

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BASE = "9ae5b3efeb1698cf45d35e064c95f91c1ac5a54e"
RUNNER = "native_usage_trial.py"
SPEC = "NATIVE-USAGE-PRIVACY-SPEC.md"
DEPENDENCIES = (
    "early_privacy_surface.py", "two_input_privacy_observer.py",
    "two_input_privacy_z3.py", "population_privacy_model.py",
    "population_privacy_workload.py", "two-input-lifecycle.py",
)
NOTES = (
    "SECURITY-INVARIANTS.md", "docs/rfc/0012-useful-privacy-requirements.md",
    "docs/rfc/0015-native-usage-privacy-screen.md",
    "research/shielded-kas-native-usage-privacy-2026-10-21.md",
    "poc/shared-pool/native-usage-build.json",
)
VENV = Path("/home/luke/.local/share/kpi-shared-pool-tools")
PARAMS = Path("/home/luke/kpi-private/two-input-h13/params-1")
PK_SHA = "6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593"
VK_SHA = "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    with Path(path).open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def sha(path):
    return surface.sha(Path(path))


def plain(path):
    path = Path(path)
    need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
         "expected regular file without symlink ancestors: " + str(path))
    return path


def normal_path(path):
    path = Path(path)
    need(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         "symlink ancestors and parent traversal are not allowed")
    return path.absolute()


def child(root, relative):
    need(isinstance(relative, str) and relative and not Path(relative).is_absolute()
         and ".." not in Path(relative).parts, "relative contained path required")
    path = normal_path(root / relative)
    need(path.is_relative_to(normal_path(root)), "path escapes experiment")
    return path


def prepare(args):
    import native_usage_generate as generator
    output = normal_path(args.output)
    need(not output.is_relative_to(ROOT), "private attempt must be outside Git")
    need(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                 text=True).strip() == BASE, "base checkpoint changed")
    need(sha(args.params / "pk.bin") == PK_SHA
         and (args.params / "pk.bin").stat().st_size == 962197520
         and sha(args.params / "vk.bin") == VK_SHA, "public parameter identity changed")
    build = read(plain(HERE / "native-usage-build.json"))
    need(build["base_commit"] == BASE and build["sources_unchanged_during_build"] is True,
         "reviewed build receipt identity changed")
    for name, digest in build["source_sha256"].items():
        need(sha(plain(child(ROOT, name))) == digest, "source changed after reviewed build: " + name)
    for name, binary in (("wallet", "wallet"), ("helper", "lifecycle"), ("replay", "replay")):
        need(sha(plain(getattr(args, name))) == build["binary_sha256"]["kpi-two-input-" + binary],
             "binary changed after reviewed build: " + name)
    output.mkdir(mode=0o700)
    for name in ("code", "bin", "notes", "private", "runs", "inputs"):
        (output / name).mkdir(mode=0o700)
    sources = sorted(set(DEPENDENCIES) | {p.name for p in HERE.glob("native_usage_*.py")} | {SPEC})
    for name in sources:
        shutil.copyfile(plain(HERE / name), output / "code" / name)
    for name in NOTES:
        path = output / "notes" / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(plain(ROOT / name), path)
    binaries = {}
    for name in ("wallet", "helper", "replay"):
        source = getattr(args, name)
        destination = output / "bin" / name
        shutil.copyfile(plain(source), destination)
        destination.chmod(0o500)
        binaries[name] = dict(sha256=sha(destination), bytes=destination.stat().st_size)
    candidate_paths = [*sorted((HERE / "src").rglob("*.rs")), HERE / "Cargo.toml", HERE / "Cargo.lock"]
    save(output / "policy.json", generator.public_policy())
    patch = subprocess.check_output(["git", "diff", "--binary", BASE, "--",
                                     "poc/shared-pool/src", "poc/shared-pool/Cargo.toml",
                                     "poc/shared-pool/Cargo.lock"], cwd=ROOT)
    (output / "native-source.patch").write_bytes(patch)
    frozen = dict(
        schema="kpi-native-usage-freeze-v1", frozen_utc=now(), base_commit=BASE,
        sources={name: sha(output / "code" / name) for name in sources},
        notes={name: sha(output / "notes" / name) for name in NOTES},
        candidate_files={str(p.relative_to(ROOT)): sha(p) for p in candidate_paths},
        native_source_patch_sha256=sha(output / "native-source.patch"), binaries=binaries,
        policy_sha256=sha(output / "policy.json"), parameter_root=str(args.params.resolve()),
        parameters=dict(pk_sha256=PK_SHA, pk_bytes=962197520, vk_sha256=VK_SHA),
        dependency_root=str(args.venv.resolve()), dependencies=surface.dependency_manifest(args.venv),
        scope="One varied native offline history; synthetic ancestry and modeled times; no funds or broadcasts",
        scoring_barrier="All profile/prefix predictions sealed before any private score",
        qualification_pass=False,
        trust="Same-host experiment generator holds fresh fixture wallets; isolated observers; author-team checks")
    save(output / "freeze.json", frozen)
    return dict(prepared=True, sampled=False, freeze_sha256=sha(output / "freeze.json"))


def check(output, dependencies=False):
    need(Path(__file__).absolute() == normal_path(output / "code" / RUNNER),
         "run controller from this attempt's frozen code directory")
    frozen = read(plain(output / "freeze.json"))
    need(frozen["schema"] == "kpi-native-usage-freeze-v1" and frozen["base_commit"] == BASE,
         "unknown experiment freeze")
    for name, digest in frozen["sources"].items():
        need(sha(plain(output / "code" / name)) == digest, "frozen source changed: " + name)
    for module in (Path(__file__).resolve(), Path(surface.__file__).resolve()):
        need(sha(module) == frozen["sources"][module.name], "loaded source differs from freeze")
    for name, digest in frozen["notes"].items():
        need(sha(plain(output / "notes" / name)) == digest, "frozen note changed: " + name)
    for name, pin in frozen["binaries"].items():
        need(sha(plain(output / "bin" / name)) == pin["sha256"], "frozen binary changed: " + name)
    need(sha(output / "native-source.patch") == frozen["native_source_patch_sha256"]
         and sha(output / "policy.json") == frozen["policy_sha256"], "frozen patch/policy changed")
    if dependencies:
        need(surface.dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
             "dependency files changed")
    return frozen


def isolated(output, frozen, label, mode, inputs):
    allowed = {
        "_controls": (),
        "_observe": ("/raw.json", "/directory.json", "/view.json", "/timing.json", "/policy.json"),
        "_score": ("/raw.json", "/directory.json", "/timing.json", "/policy.json",
                   "/truth.json", "/predictions.json"),
    }
    mounts = tuple(mount for _, mount in inputs)
    need(mode in allowed and mounts == allowed[mode], "unexpected isolated inputs")
    destination = output / "runs" / label
    destination.mkdir(mode=0o700)
    command = surface.sandbox() + ["--ro-bind", frozen["dependency_root"], "/venv",
                                   "--bind", str(destination), "/output"]
    for name in frozen["sources"]:
        if name.endswith(".py"):
            command += ["--ro-bind", str(output / "code" / name), "/" + name]
    for path, mount in inputs:
        command += ["--ro-bind", str(plain(path)), mount]
    probe = (
        "import pathlib,json; assert not pathlib.Path('/home').exists();"
        "interfaces=[x.split(':')[0].strip() for x in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x];"
        "assert interfaces==['lo']; print(json.dumps({'interfaces':interfaces,'home_accessible':False}))")
    result = subprocess.run(command + ["--", "/venv/bin/python", "-c", probe],
                            text=True, capture_output=True, check=True)
    audit = json.loads(result.stdout)
    audit.update(mode=mode, inputs=list(mounts), private_truth_mounted="/truth.json" in mounts,
                 private_seed_mounted=False, wallet_backup_mounted=False)
    save(destination / "isolation.json", audit)
    save(destination / "inputs.json", {mount: sha(path) for path, mount in inputs})
    started = now()
    with (destination / "stdout.log").open("x") as out, (destination / "stderr.log").open("x") as err:
        process = subprocess.run(command + ["--", "/venv/bin/python", "/" + RUNNER, mode],
                                 stdout=out, stderr=err)
    save(destination / "process.json", dict(started_utc=started, ended_utc=now(), returncode=process.returncode))
    need(process.returncode == 0, "isolated process failed; preserve " + str(destination))
    return destination, read(plain(destination / "result.json"))


def controls(output):
    frozen = check(output, dependencies=True)
    destination, result = isolated(output, frozen, "controls", "_controls", [])
    need(result["passed"] is True, "all controls must pass before generation")
    save(output / "controls.json", dict(passed=True, completed_utc=now(),
                                       result_sha256=sha(destination / "result.json"), result=result))
    return result


def runner_controls():
    checks = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "data").mkdir()
        (root / "data/regular.json").write_text("{}")
        (root / "alias").symlink_to(root / "data", target_is_directory=True)
        need(child(root, "data/regular.json") == root / "data/regular.json", "regular child control")
        for name, fn in (
            ("absolute-child-rejected", lambda: child(root, str(root / "data/regular.json"))),
            ("parent-traversal-rejected", lambda: child(root, "data/../data/regular.json")),
            ("symlink-ancestor-rejected-before-resolution", lambda: child(root, "alias/regular.json")),
        ):
            try:
                fn()
            except ValueError:
                checks.append(name)
            else:
                raise ValueError("runner control accepted " + name)
        try:
            check(root)
        except ValueError as error:
            need("frozen code directory" in str(error), "controller location must reject before any imports/inputs")
            checks.append("unfrozen-controller-rejected-before-inputs")
        else:
            raise ValueError("unfrozen controller accepted")
    return dict(passed=True, controls=checks)


def generate(output):
    frozen = check(output, dependencies=True)
    control = read(plain(output / "controls.json"))
    need(control["passed"] is True and control["result_sha256"] == sha(output / "runs/controls/result.json"),
         "controls incomplete or changed")
    need(not any((output / "private").iterdir()), "attempt already sampled; preserve original seed")
    parameters = Path(frozen["parameter_root"])
    need(sha(plain(parameters / "pk.bin")) == frozen["parameters"]["pk_sha256"]
         and sha(plain(parameters / "vk.bin")) == frozen["parameters"]["vk_sha256"],
         "parameters changed before generation")
    save(output / "private/seed.json", dict(seed=secrets.token_hex(32)))
    save(output / "seed-commitment.json", dict(sampled_utc=now(),
         freeze_sha256=sha(output / "freeze.json"), seed_file_sha256=sha(output / "private/seed.json")))
    started = now()
    process = subprocess.run([str(Path(frozen["dependency_root"]) / "bin/python"),
                              str(output / "code" / RUNNER), "_generate", str(output)])
    save(output / "generation-process.json", dict(started_utc=started, ended_utc=now(), returncode=process.returncode))
    need(process.returncode == 0, "native generation incomplete; preserve attempt and seed")
    result = read(plain(output / "native/native-result.json"))
    need(result.get("complete", result.get("completed")) is True, "native history incomplete")
    check(output, dependencies=True)
    save(output / "generation.json", dict(complete=True, completed_utc=now(),
         freeze_sha256=sha(output / "freeze.json"), native_result_sha256=sha(output / "native/native-result.json"),
         seed_commitment_sha256=sha(output / "seed-commitment.json")))
    return dict(generated=True, proof_count=result["proof_count"])


def native_inputs(output):
    generation = read(plain(output / "generation.json"))
    need(generation["complete"] is True
         and generation["freeze_sha256"] == sha(output / "freeze.json")
         and generation["native_result_sha256"] == sha(output / "native/native-result.json")
         and generation["seed_commitment_sha256"] == sha(output / "seed-commitment.json"),
         "native generation identity changed")
    sampled = read(output / "seed-commitment.json")
    need(sampled["freeze_sha256"] == sha(output / "freeze.json")
         and sampled["seed_file_sha256"] == sha(output / "private/seed.json"), "sampled seed changed")
    native = output / "native"
    result = read(native / "native-result.json")
    need(result["public_dir"] == "public/final" and result["truth_file"] == "private/truth.json"
         and result["views_dir"] == "private/views", "unexpected native artifact paths")
    need(result["native_ledger_file"] == "public/native-ledger.json"
         and sha(plain(native / "public/native-ledger.json")) == result["native_ledger_sha256"],
         "native UTXO validation ledger changed")
    need(result["genuine_proof_count"] == result["proof_count"]
         and result["original_backups_unchanged"] is True
         and result["chain_acceptance_verified"] is False, "native evidence scope/integrity changed")
    public = child(native, result["public_dir"])
    truth = child(native, result["truth_file"])
    views = child(native, result["views_dir"])
    need(set(result["public_files"]) == {"descriptor.json", "vk.bin", "lineage.json", "parents.json",
                                       "head.json", "checked.json", "directory.json", "timing.json"},
         "public native artifact roster changed")
    for name, digest in result["public_files"].items():
        need(sha(plain(child(public, name))) == digest, "native public file changed: " + name)
    need(sha(plain(truth)) == result["truth_sha256"]
         and result["policy_sha256"] == sha(output / "policy.json"), "native truth/policy identity changed")
    view_names = {"C.json", "pooled.json"} | {f"P{i}.json" for i in range(8)}
    need(set(result["views_sha256"]) == view_names, "declared view roster changed")
    for name, digest in result["views_sha256"].items():
        need(sha(plain(views / name)) == digest, "declared participant view changed: " + name)
    return result, public, truth, views


def evaluate(output):
    frozen = check(output, dependencies=True)
    import native_usage_observer as observer
    native, public, truth, views = native_inputs(output)
    raw = surface.load_raw(public)
    need(len(raw["lineage"]) - 1 == native["proof_count"], "native proof/operation count mismatch")
    replayed = surface.native_replay(output / "bin/replay", public)
    save(output / "replay-process.json", dict(returncode=replayed.returncode, completed_utc=now()))
    with (output / "replay-stderr.log").open("x") as stream:
        stream.write(replayed.stderr)
    need(replayed.returncode == 0, "independent native replay failed; preserve attempt")
    replay_result = json.loads(replayed.stdout)
    need([r["transaction"] for r in replay_result["records"]] == raw["lineage"]
         and replay_result["reserve"] is None and replay_result["chain_acceptance_verified"] is False,
         "native replay did not reproduce terminal history")
    save(output / "native-replay.json", replay_result)
    directory, timing = read(public / "directory.json"), read(public / "timing.json")
    profiles = ["C", *("P" + str(i) for i in range(8)), "pooled"]
    points = observer.observation_points(raw)
    need(isinstance(points, list) and points == sorted(set(points)) and points,
         "invalid observation prefix roster")
    predictions, seals = [], []
    for through in points:
        prefix = output / "inputs" / f"prefix-{through:04d}"
        prefix.mkdir(mode=0o700)
        for index, profile in enumerate(profiles):
            # These are the eight declared adversaries' records only. Full honest
            # truth is never parsed in this controller or any observer process.
            view = read(plain(views / (profile + ".json")))
            r, d, v, t = observer.prefix_inputs(raw, directory, view, timing, through)
            if index == 0:
                for name, value in (("raw", r), ("directory", d), ("timing", t)):
                    save(prefix / (name + ".json"), value)
            else:
                need(r == read(prefix / "raw.json") and d == read(prefix / "directory.json")
                     and t == read(prefix / "timing.json"), "public prefix varies by private profile")
            save(prefix / (profile + ".json"), v)
            inputs = [(prefix / "raw.json", "/raw.json"), (prefix / "directory.json", "/directory.json"),
                      (prefix / (profile + ".json"), "/view.json"), (prefix / "timing.json", "/timing.json"),
                      (output / "policy.json", "/policy.json")]
            label = f"observe-{through:04d}-{profile}"
            destination, prediction = isolated(output, frozen, label, "_observe", inputs)
            need(prediction["complete"] is True, "observer prediction incomplete")
            seal = dict(profile=profile, through_event=through, sealed_utc=now(),
                        freeze_sha256=sha(output / "freeze.json"),
                        generation_sha256=sha(output / "generation.json"),
                        prediction_sha256=sha(destination / "result.json"),
                        inputs={mount: sha(path) for path, mount in inputs})
            save(destination / "prediction-seal.json", seal)
            seals.append(dict(label=label, seal=seal, seal_sha256=sha(destination / "prediction-seal.json")))
            predictions.append(dict(profile=profile, through_event=through, prediction=prediction))
        print(json.dumps(dict(phase="prefix-predictions-sealed", through_event=through,
                              completed_prefixes=len(seals) // len(profiles), total_prefixes=len(points))), flush=True)
    check(output, dependencies=True)
    native_inputs(output)
    save(output / "predictions.json", predictions)
    save(output / "prediction-batch.json", dict(schema="kpi-native-usage-prediction-batch-v1", complete=True,
         sealed_utc=now(), scoring_started=False, freeze_sha256=sha(output / "freeze.json"),
         generation_sha256=sha(output / "generation.json"), predictions_sha256=sha(output / "predictions.json"),
         profiles=profiles, through_events=points, records=seals))
    batch_sha = sha(output / "prediction-batch.json")

    def verify_predictions():
        need(sha(output / "prediction-batch.json") == batch_sha, "batch seal changed")
        batch = read(output / "prediction-batch.json")
        need(sha(output / "predictions.json") == batch["predictions_sha256"], "combined predictions changed")
        for item in seals:
            destination = output / "runs" / item["label"]
            need(sha(destination / "prediction-seal.json") == item["seal_sha256"]
                 and sha(destination / "result.json") == item["seal"]["prediction_sha256"],
                 "sealed individual prediction changed")
        native_inputs(output)

    verify_predictions()
    final = output / "inputs/final"
    final.mkdir(mode=0o700)
    for name, value in (("raw", raw), ("directory", directory), ("timing", timing)):
        save(final / (name + ".json"), value)
    scored, score = isolated(output, frozen, "score", "_score", [
        (final / "raw.json", "/raw.json"), (final / "directory.json", "/directory.json"),
        (final / "timing.json", "/timing.json"), (output / "policy.json", "/policy.json"),
        (truth, "/truth.json"), (output / "predictions.json", "/predictions.json")])
    need(score["complete"] is True and score["qualification_pass"] is False, "score incomplete or out-of-scope pass")
    verify_predictions()
    check(output, dependencies=True)
    result = dict(complete=True, completed_utc=now(), status=score["status"],
                  prediction_batch_sha256=batch_sha, score_sha256=sha(scored / "result.json"),
                  native_replay_sha256=sha(output / "native-replay.json"),
                  proof_count=native["proof_count"], observed_prefixes=len(points),
                  observed_profiles=len(profiles), independent_histories=1, qualification_pass=False)
    save(output / "completion.json", result)
    return result


def internal(mode, output=None):
    if mode == "_generate":
        frozen = check(output)
        import native_usage_generate as generator
        args = SimpleNamespace(output=output / "native", seed_file=output / "private/seed.json",
                               wallet_binary=output / "bin/wallet", helper_binary=output / "bin/helper",
                               replay_binary=output / "bin/replay", params=Path(frozen["parameter_root"]),
                               policy=output / "policy.json")
        generator.generate(args)
        return
    if mode == "_controls":
        import native_usage_generate as generator
        import native_usage_observer as observer
        import native_usage_score as scorer
        results = {"runner": runner_controls(), "generator": generator.controls(),
                   "observer": observer.controls(), "scorer": scorer.controls()}
        result = dict(passed=all(x["passed"] is True for x in results.values()), results=results)
    elif mode == "_observe":
        import native_usage_observer as observer
        result = observer.observe(*(read(Path("/" + name + ".json"))
                                    for name in ("raw", "directory", "view", "timing", "policy")))
    elif mode == "_score":
        import native_usage_score as scorer
        result = scorer.score(*(read(Path("/" + name + ".json"))
                                for name in ("raw", "directory", "timing", "policy", "truth", "predictions")))
    else:
        raise ValueError("unknown internal mode")
    save(Path("/output/result.json"), result)


def main():
    os.umask(0o077)
    if len(sys.argv) > 1 and sys.argv[1].startswith("_"):
        internal(sys.argv[1], normal_path(sys.argv[2]) if len(sys.argv) > 2 else None)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("output", type=Path)
    prep.add_argument("--venv", type=Path, default=VENV)
    prep.add_argument("--params", type=Path, default=PARAMS)
    prep.add_argument("--wallet", type=Path, default=HERE / "target/release/kpi-two-input-wallet")
    prep.add_argument("--helper", type=Path, default=HERE / "target/release/kpi-two-input-lifecycle")
    prep.add_argument("--replay", type=Path, default=HERE / "target/release/kpi-two-input-replay")
    for name in ("controls", "generate", "evaluate"):
        cmd = sub.add_parser(name)
        cmd.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output = normal_path(args.output)
    if args.command != "prepare" and Path(__file__).absolute() != args.output / "code" / RUNNER:
        # Re-execute before importing controller helpers. A changed checkout
        # observer/projector can never shape a supposedly frozen input prefix.
        frozen = read(plain(args.output / "freeze.json"))
        entry = plain(args.output / "code" / RUNNER)
        need(sha(entry) == frozen["sources"][RUNNER], "frozen controller entry changed")
        python = str(Path(frozen["dependency_root"]) / "bin/python")
        os.execv(python, [python, str(entry), args.command, str(args.output)])
    if args.command == "prepare":
        result = prepare(args)
    elif args.command == "controls":
        result = controls(args.output)
    elif args.command == "generate":
        result = generate(args.output)
    else:
        result = evaluate(args.output)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
