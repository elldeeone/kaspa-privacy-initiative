#!/usr/bin/env python3
"""Keep the old observer fixed; seal three fresh predictions before scoring.

Preparation replays only an allowlisted historical public positive control.
No historical wallet or truth is opened. Fresh truth enters separate scorers
only after the complete three-arm prediction batch has been sealed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import early_privacy_surface as surface
from early_privacy_surface import need, read, save, sha

HERE = Path(__file__).resolve().parent
FREEZE_SCHEMA = "kpi-native-key-separation-evaluation-freeze-v1"
OBSERVER_HASHES = {
    "address_reuse_observer.py": "e157540aef57153909dd2558c853b8381a2bb1260d9e7fdc3ba613618a05a9a9",
    "early_privacy_surface.py": "95f87feb361f92f25dcbaa08d8a667a3bb809e60b11e857959929c1574a32ff6",
    "population_privacy_model.py": "c73561a75959783ffbfadbaf9dca0e85d4f0934479378621fd75a75d75b8f08f",
    "population_privacy_index.py": "807478b4cc58daa249b8175c4b1c47442495d31e2fcb80959afa27d58d67e9ed",
    "two_input_privacy_observer.py": "96ccf7f9899da8b02e6b1e43a542684e5c38c09d0a80b7554901f7982a74b35b",
    "two_input_privacy_z3.py": "e73b3d88403cd8bf219d21e7fab82b60760566eafbf34eaea87e758aacc1552e",
}
OBSERVER_SOURCES = tuple(OBSERVER_HASHES)
SOURCES = ("native_key_separation_evaluate.py", "native_key_separation_trial.py",
           "ADDRESS-KEY-SEPARATION-SPEC.md") + OBSERVER_SOURCES
PUBLIC_FILES = surface.FILES + ("funding_owner_directory.json",)
NATIVE_PUBLIC_FILES = PUBLIC_FILES + ("head.json", "checked.json")
HISTORICAL = HERE / "evidence/2026-10-20-address-reuse"
HISTORICAL_COMMIT = "b62cfd1910d77f9962882b1088d6cc718e7df1b2"
HISTORICAL_ANCHORS = {
    "SHA256SUMS": "063c0c4686276e8d63567686c92d88ae5fda7cb5f065c6cb40f627c7dab0a562",
    "evaluation/freeze.json": "6e298fc389cae3c9e1150ccc02fe0b28029194b842b8e587593f8c15739b3b20",
    "evaluation/runs/matched-observe/prediction-seal.json": "2e92b134920affe256816e2db9ddde2357dc445f92c7cf8981ee03c74b95b406",
}
HISTORICAL_INPUTS = {
    "descriptor.json": "58b57cf8273c5fc441adcad7d919bbd4054daf70e44cb575bb5e695794eef98e",
    "vk.bin": "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef",
    "lineage.json": "4b49a81bc941b7198a5b21497f728ccf348447570d1b476827b22f7c85fa492c",
    "parents.json": "79ac37232734458f40476fcf99ad362ba2763cfe424302dcba7b9cdbffeb8ea1",
    "funding_owner_directory.json": "98829cc4079ccccfb0e649d2566d45bbf6e014799a6f781c76bb36ce0f219ece",
}
ARMS = ("v2-same-index", "v2-different-index", "legacy-v1-same-index")
EXPECTED_MATCH = dict(zip(ARMS, (False, False, True), strict=True))
PAYMENT = dict(sender=0, recipient=1, amount=1_920_000_000)
PROFILES = (("creation", 2, False), ("creation", 2, True),
            ("final", 3, False), ("final", 3, True))


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def child(root, relative):
    need(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
         "native artifact path must be relative")
    path = (root / relative).resolve()
    need(path != root and path.is_relative_to(root), "native artifact escapes experiment")
    return path


def historical_identity():
    """Authenticate the five public files against fixed published anchors."""
    for name, expected in HISTORICAL_ANCHORS.items():
        need(sha(HISTORICAL / name) == expected, "historical anchor changed: " + name)
    manifest = {}
    for line in (HISTORICAL / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split(maxsplit=1)
        need(name not in manifest, "duplicate historical manifest entry")
        manifest[name] = checksum
    prior = read(HISTORICAL / "evaluation/freeze.json")
    seal = read(HISTORICAL / "evaluation/runs/matched-observe/prediction-seal.json")
    need(seal["freeze_sha256"] == HISTORICAL_ANCHORS["evaluation/freeze.json"],
         "historical seal/freeze disagreement")
    for name, expected in OBSERVER_HASHES.items():
        need(prior["sources"][name] == expected
             and manifest["evaluation/code/" + name] == expected
             and sha(HERE / name) == expected, "unchanged observer dependency required: " + name)
    for name, expected in HISTORICAL_INPUTS.items():
        need(manifest["native/matched/" + name] == seal["public_files"][name] == expected
             and sha(HISTORICAL / "native/matched" / name) == expected,
             "historical positive input changed: " + name)
    return dict(source_commit=HISTORICAL_COMMIT, anchors=HISTORICAL_ANCHORS,
                inputs=HISTORICAL_INPUTS,
                scope="Published matched public arm only; no historical truth or wallets")


def check(output):
    frozen = read(output / "freeze.json")
    need(frozen["schema"] == FREEZE_SCHEMA, "freeze schema")
    need(set(frozen["sources"]) == set(SOURCES), "frozen source closure")
    for name, expected in frozen["sources"].items():
        need(sha(output / "code" / name) == expected, "changed frozen source: " + name)
    need({name: frozen["sources"][name] for name in OBSERVER_SOURCES} == OBSERVER_HASHES,
         "historical observer/dependency identity changed")
    for module in (surface,):
        path = Path(module.__file__)
        need(sha(path) == frozen["sources"][path.name], "loaded helper changed")
    need(sha(Path(__file__)) == frozen["sources"][Path(__file__).name], "runner changed")
    need(frozen["historical_positive"]["source_commit"] == HISTORICAL_COMMIT
         and frozen["historical_positive"]["anchors"] == HISTORICAL_ANCHORS
         and frozen["historical_positive"]["inputs"] == HISTORICAL_INPUTS,
         "historical positive identity changed")
    for name, expected in HISTORICAL_INPUTS.items():
        need(sha(output / "historical-positive" / name) == expected,
             "copied historical positive changed: " + name)
    need(sha(output / "replay") == frozen["replay_sha256"], "replay binary changed")
    need(surface.dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
         "dependency bytes changed")
    return frozen


def isolated(output, frozen, name, mode, inputs=None, prediction=None, truth=None):
    need(mode in ("controls", "observe", "score"), "isolated mode")
    need((inputs is not None) == (mode != "controls"), "public input mount mode")
    need((truth is not None) == (mode == "score")
         and (prediction is not None) == (mode == "score"), "truth/prediction mount mode")
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
    probe = (
        "import pathlib,json;assert not pathlib.Path('/home').exists();"
        f"assert pathlib.Path('/truth.json').exists()=={mode == 'score'!r};"
        "interfaces=[x.split(':')[0].strip() for x in "
        "pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x];"
        "assert interfaces==['lo'];print(json.dumps({'interfaces':interfaces,"
        "'home_accessible':False}))")
    audit = subprocess.run(command + ["--", "/venv/bin/python", "-c", probe],
                           capture_output=True, text=True, check=True)
    save(directory / "isolation.json", dict(
        **json.loads(audit.stdout), mode=mode, inputs=list(mounts),
        private_truth_mounted=truth is not None, other_arm_mounted=False))
    save(directory / "inputs.json", mounts)
    args = [mode] + (["/input"] if inputs is not None else [])
    if mode == "score":
        args += ["/prediction.json", "/truth.json"]
    started = now()
    with (directory / "result.json").open("x") as out, (directory / "stderr.log").open("x") as err:
        process = subprocess.run(command + ["--", "/venv/bin/python",
                                 "/address_reuse_observer.py", *args], stdout=out, stderr=err)
    save(directory / "process.json", dict(started_utc=started, finished_utc=now(),
                                          returncode=process.returncode))
    need(process.returncode == 0, "isolated process failed; preserve " + str(directory))
    return directory, read(directory / "result.json")


def check_profiles(prediction, expected_match):
    need(prediction["schema"] == "kpi-address-reuse-predictions-v1"
         and prediction["complete"] is True and prediction["conditional_available"] is True,
         "incomplete observer prediction")
    need([(r["horizon"], r["through_event"], r["script_association_used"])
          for r in prediction["rows"]] == list(PROFILES), "missing/reordered profiles")
    for row in prediction["rows"]:
        need(row["event"] == 2 and type(row["script_association_used"]) is bool,
             "changed target/profile")
        forced = expected_match and row["horizon"] == "final" and row["script_association_used"]
        for field, expected in PAYMENT.items():
            claim = row[field]
            need(claim["forced"] is forced, "unexpected conditional inference: " + field)
            certificate = dict(candidate="SAT", different="UNSAT" if forced else "SAT")
            need(claim["certificates"] == {engine: certificate for engine in ("cp_sat", "z3")},
                 "missing dual candidate/alternative certificate")
            if forced:
                need(type(claim["candidate"]) is int and claim["candidate"] == expected,
                     "positive control forced a different fixture payment")


def check_prediction(inputs, prediction, expected_match):
    raw = surface.load_raw(inputs)
    directory = read(inputs / "funding_owner_directory.json")
    need(prediction["public_sha256"] == digest(raw)
         and prediction["directory_sha256"] == digest(directory), "observer input identity")
    owners = {(r["transaction_id"], r["index"]): r["owner"] for r in directory["entries"]}
    comparisons = prediction["boundary"]["comparisons"]
    need(len(owners) == len(comparisons) == 2 and set(owners.values()) == {0, 1},
         "funding comparison coverage")
    seen = set()
    for row in comparisons:
        point = row["funding_outpoint"]
        key = point["transaction_id"], point["index"]
        need(key in owners and key not in seen and row["payout_event"] == 3
             and row["payout_transaction_id"] == raw["lineage"][-1]["id"],
             "comparison is not the selected funding outpoint/terminal payout")
        seen.add(key)
        need(row["equal"] is (expected_match and owners[key] == 1),
             "script equality or wrong-owner control failed")
    check_profiles(prediction, expected_match)


def replay(output, inputs, name):
    result = surface.native_replay(output / "replay", inputs)
    save(output / (name + "-replay-process.json"), dict(returncode=result.returncode))
    with (output / (name + "-replay-stderr.log")).open("x") as stream:
        stream.write(result.stderr)
    need(result.returncode == 0, "independent native replay failed")
    replayed = json.loads(result.stdout)
    need([r["transaction"] for r in replayed["records"]] == read(inputs / "lineage.json")
         and len(replayed["records"]) == 5 and replayed["reserve"] is None
         and replayed["chain_acceptance_verified"] is False, "native replay identity/terminal state")
    for field, expected in dict(initial_reserve_sompi="2000000000", admitted_sompi="1200000000",
            paid_sompi="3040000000", pool_fees_sompi="160000000", remaining_reserve_sompi="0").items():
        need(replayed["accounting"][field] == expected, "native accounting: " + field)
    save(output / (name + "-replay.json"), replayed)


def prepare(output, venv, binary):
    need(not output.is_relative_to(HERE.parents[1]), "evidence attempt must be outside Git")
    historical = historical_identity()
    output.mkdir(mode=0o700)
    for directory in ("code", "runs", "historical-positive"):
        (output / directory).mkdir(mode=0o700)
    for name in SOURCES:
        shutil.copyfile(HERE / name, output / "code" / name)
    for name in PUBLIC_FILES:
        shutil.copyfile(HISTORICAL / "native/matched" / name, output / "historical-positive" / name)
    shutil.copyfile(binary, output / "replay")
    (output / "replay").chmod(0o700)
    save(output / "freeze.json", dict(
        schema=FREEZE_SCHEMA, created_utc=now(),
        sources={name: sha(output / "code" / name) for name in SOURCES},
        historical_positive=historical, replay_sha256=sha(output / "replay"),
        dependency_root=str(venv), dependencies=surface.dependency_manifest(venv),
        scope="Fixed historical observer, one public arm at a time; no privacy qualification"))
    frozen = check(output)
    directory, controls = isolated(output, frozen, "controls", "controls")
    need(controls["passed"] is True and controls["complete"] is True
         and len(controls["controls"]) == 7, "unchanged observer controls failed")
    replay(output, output / "historical-positive", "historical-positive")
    positive, prediction = isolated(output, frozen, "historical-positive-observe", "observe",
                                    output / "historical-positive")
    check_prediction(output / "historical-positive", prediction, True)
    check(output)
    prepared = dict(prepared=True, controls_passed=True, historical_positive_passed=True,
                    prepared_utc=now(), freeze_sha256=sha(output / "freeze.json"),
                    controls_result_sha256=sha(directory / "result.json"),
                    historical_positive_result_sha256=sha(positive / "result.json"),
                    historical_replay_sha256=sha(output / "historical-positive-replay.json"))
    save(output / "preparation.json", prepared)
    return prepared


def check_preparation(output):
    prepared = read(output / "preparation.json")
    need(prepared["prepared"] is True and prepared["controls_passed"] is True
         and prepared["historical_positive_passed"] is True
         and prepared["freeze_sha256"] == sha(output / "freeze.json"), "preparation incomplete/changed")
    for key, path in (
        ("controls_result_sha256", "runs/controls/result.json"),
        ("historical_positive_result_sha256", "runs/historical-positive-observe/result.json"),
        ("historical_replay_sha256", "historical-positive-replay.json"),
    ):
        need(sha(output / path) == prepared[key], "preparation evidence changed: " + key)
    return prepared


def check_arm_inputs(native, arm):
    inputs, truth = child(native, arm["public_dir"]), child(native, arm["truth_file"])
    need(set(arm["public_files"]) == set(NATIVE_PUBLIC_FILES), "native public input closure")
    need(all(sha(inputs / name) == checksum for name, checksum in arm["public_files"].items()),
         "native public inputs changed")
    # Hash only; parsing private truth is confined to the separate scorer.
    need(sha(truth) == arm["truth_sha256"], "fresh truth bytes changed")
    return inputs, truth


def run(output, native):
    frozen = check(output)
    prepared = check_preparation(output)
    preparation_sha = sha(output / "preparation.json")
    result_path = native / "native-result.json"
    native_result_sha = sha(result_path)
    result = read(result_path)
    need(result["schema"] == "kpi-native-key-separation-result-v1"
         and result["complete"] is True and result["proof_count"] == 10
         and result["chain_acceptance_verified"] is False
         and result["genuine_groth16_proofs"] is True
         and result["founder_original_backup_unchanged"] is True, "native experiment incomplete")
    need(result["evaluation_freeze_sha256"] == prepared["freeze_sha256"]
         and result["evaluation_preparation_sha256"] == preparation_sha,
         "native generation did not bind this prepared evaluation")
    need([arm["name"] for arm in result["arms"]] == list(ARMS), "three fresh arms required")
    for name, checksum in frozen["sources"].items():
        need(sha(native / "software/code/poc/shared-pool" / name) == checksum,
             "native/evaluation source mismatch: " + name)
    records = []
    for arm in result["arms"]:
        name = arm["name"]
        need(arm["expected_script_match"] is EXPECTED_MATCH[name]
             and all(arm[field] is True for field in (
                 "original_backup_unchanged", "recovery_fresh_process",
                 "terminal_payout_spend_native_validated")), "native arm recovery/spend controls failed")
        inputs, _ = check_arm_inputs(native, arm)
        replay(output, inputs, name)
        directory, prediction = isolated(output, frozen, name + "-observe", "observe", inputs)
        check_prediction(inputs, prediction, EXPECTED_MATCH[name])
        seal = dict(arm=name, sealed_utc=now(), prediction_sha256=sha(directory / "result.json"),
                    truth_sha256=arm["truth_sha256"], public_files=arm["public_files"],
                    native_result_sha256=native_result_sha, freeze_sha256=prepared["freeze_sha256"])
        save(directory / "prediction-seal.json", seal)
        records.append(dict(arm=arm, label=name + "-observe", seal=seal,
                            seal_sha256=sha(directory / "prediction-seal.json")))
    # This barrier is reached only after every fresh arm's prediction is complete.
    need(len(records) == 3, "all three predictions must be sealed before scoring")
    save(output / "prediction-batch.json", dict(
        schema="kpi-native-key-separation-prediction-batch-v1", complete=True,
        sealed_utc=now(), scoring_started=False, records=records,
        freeze_sha256=prepared["freeze_sha256"], preparation_sha256=preparation_sha))
    batch_sha = sha(output / "prediction-batch.json")
    scores = []
    for record in records:
        need(sha(output / "prediction-batch.json") == batch_sha, "batch changed")
        arm, directory = record["arm"], output / "runs" / record["label"]
        need(sha(directory / "result.json") == record["seal"]["prediction_sha256"]
             and sha(directory / "prediction-seal.json") == record["seal_sha256"], "prediction/seal changed")
        inputs, truth = check_arm_inputs(native, arm)
        scored, score = isolated(output, frozen, arm["name"] + "-score", "score",
                                 inputs, directory / "result.json", truth)
        need(score["complete"] is True and score["boundary_matches_setup"] is True
             and score["truth_consistency"] == dict(cp_sat=True, z3=True)
             and score["qualification_pass"] is False, "incomplete truth/score verification")
        expected_rows = [dict(horizon=horizon, script_association_used=linked,
            forced={field: EXPECTED_MATCH[arm["name"]] and horizon == "final" and linked
                    for field in PAYMENT}) for horizon, _, linked in PROFILES]
        need(score["rows"] == expected_rows, "score/profile disagreement")
        scores.append(dict(arm=arm["name"], result=score, score_sha256=sha(scored / "result.json")))
    check(output)
    check_preparation(output)
    need(sha(output / "preparation.json") == preparation_sha
         and sha(output / "prediction-batch.json") == batch_sha
         and sha(result_path) == native_result_sha, "final evidence identity changed")
    for name, checksum in frozen["sources"].items():
        need(sha(native / "software/code/poc/shared-pool" / name) == checksum,
             "final native/evaluation source mismatch: " + name)
    for record, scored in zip(records, scores, strict=True):
        directory = output / "runs" / record["label"]
        need(sha(directory / "prediction-seal.json") == record["seal_sha256"]
             and sha(directory / "result.json") == record["seal"]["prediction_sha256"]
             and sha(output / "runs" / (record["arm"]["name"] + "-score") / "result.json")
                 == scored["score_sha256"], "final prediction/score changed")
        check_arm_inputs(native, record["arm"])
    summary = dict(complete=True, scores=scores, prediction_batch_sha256=batch_sha,
                   historical_positive_passed=True, chain_acceptance_verified=False,
                   privacy_qualification=False,
                   scope="This script-equality inference is removed in fresh v2 arms; other privacy remains unqualified")
    save(output / "completion.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("prepare")
    setup.add_argument("output", type=Path)
    setup.add_argument("--venv", type=Path, default=surface.VENV)
    setup.add_argument("--replay", type=Path, default=HERE / "target/release/kpi-two-input-replay")
    execute = commands.add_parser("run")
    execute.add_argument("output", type=Path)
    execute.add_argument("native", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    result = (prepare(args.output.resolve(), args.venv.resolve(), args.replay.resolve())
              if args.command == "prepare" else run(args.output.resolve(), args.native.resolve()))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
