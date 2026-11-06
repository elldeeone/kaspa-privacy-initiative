#!/usr/bin/env python3
"""Run one fresh unfunded diagnostic; seal inference before reading truth."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
VIEWS = ("baseline", "candidate", "one-participant", "all-but-one", "known-payout-owners", "echoed-origin", "leaked-issuance-randomizer", "legacy-public-exits")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    args = parser.parse_args()
    target=ROOT / ".local/ci-target"
    binary=target / "release/kpi-payment-set-withdrawal"
    build_env=dict(os.environ,CARGO_TARGET_DIR=str(target))
    # A failed build must never fall through to a stale executable.
    subprocess.run(["cargo","+1.97.1","build","--locked","--release","--manifest-path",str(HERE/"Cargo.toml")],cwd=ROOT,env=build_env,check=True)
    parent = ROOT / ".local/payment-set-withdrawal"
    parent.mkdir(parents=True, exist_ok=True)
    run = parent / str(uuid.uuid4())
    source_files = sorted(HERE.glob("src/*.rs")) + [HERE / n for n in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "observe.py", "run.py")]
    source_files += [ROOT / "research/payment-set-withdrawal-2026-11-05/SELECTION.md", ROOT / "research/payment-set-withdrawal-2026-11-05/SOURCES.md", ROOT / "docs/adr/0108-real-wallet-common-set-integration.md", HERE / "REUSE.json"]
    source_files += sorted((ROOT / "poc/private-note-wallet/src").glob("*.rs")) + [ROOT / "poc/private-note-wallet/Cargo.toml"]
    freeze = {"schema": "finite-common-set-freeze-v1", "frozenAtUtc": datetime.now(timezone.utc).isoformat(), "baseCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "files": {str(p.relative_to(ROOT)): sha(p) for p in source_files}, "binarySha256": sha(binary)}
    freeze_path = parent / (run.name + "-freeze.json")
    write(freeze_path, freeze)
    print(f"Fresh runtime: {run}", flush=True)
    env = dict(os.environ, RAYON_NUM_THREADS="4", PYTHONDONTWRITEBYTECODE="1")
    with (parent / (run.name + "-execution.log")).open("x") as log:
        subprocess.run([str(binary), str(run)], cwd=ROOT, env=env, stderr=log, check=True)
    public = run / "public"
    write(public / "FREEZE.json", freeze)
    replay=subprocess.check_output([str(binary),"verify-public",str(public)],cwd=ROOT,env=env,text=True)
    write(public/"PUBLIC-REPLAY.json",json.loads(replay))
    seals = {}
    for name in VIEWS:
        observation = public / f"{name}.json"
        prediction = public / f"{name}-prediction.json"
        subprocess.run([sys.executable, str(HERE / "observe.py"), str(observation), str(prediction)], cwd=ROOT, env=env, check=True)
        seals[observation.name] = sha(observation)
        seals[prediction.name] = sha(prediction)
    write(public / "PREDICTION-SEAL.json", {"files": seals, "observerSha256": sha(HERE / "observe.py"), "truthRead": False})
    # Only now consult the synthetic controller's separate mapping.
    assert all(sha(public / name) == expected for name, expected in seals.items())
    truth = {v["owner"]: v["recipientKey"] for v in read(run / "private/truth.json")["ownerToRecipient"]}
    counts = {}
    for name in VIEWS:
        prediction = read(public / f"{name}-prediction.json")
        assert truth in prediction["completeOwnershipAssignments"], f"complete execution truth excluded: {name}"
        counts[name] = prediction["assignmentCount"]
    passed = counts["baseline"] == 1 and counts["candidate"] > 1 and counts["one-participant"] > 1
    assert all(counts[name] == 1 for name in VIEWS if name not in ("candidate", "one-participant"))
    assert all(sha(ROOT / name) == expected for name, expected in freeze["files"].items())
    execution = read(public / "execution.json")
    assert all(r["accepted"] == r["expectedAccept"] for r in execution["native"]["nativeCases"])
    assert execution["native"]["jointMassQuote"]["withinBlockComponentLimits"]
    write(public / "VALIDATION.json", {"schema": "finite-common-set-validation-v1", "predictionSealSha256": sha(public / "PREDICTION-SEAL.json"), "coupledTruthRetainedInEveryView": True, "counts": counts, "namedOwnershipChannelPass": passed, "completePaymentPrivacyQualified": False, "networkPrivacyQualified": False, "nativeFullValidation": False, "chainAcceptance": False})
    print(json.dumps({"publicDirectory": str(public), "counts": counts, "namedOwnershipChannelPass": passed}, indent=2), flush=True)


if __name__ == "__main__":
    main()
