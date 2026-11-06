#!/usr/bin/env python3
"""Reproduce saved observer results from public artifacts; never read .local."""
import hashlib
import json
from pathlib import Path

from observe import predict, read

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "research/common-set-withdrawal-2026-11-05/run"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check():
    manifest = read(PUBLIC / "MANIFEST.json")
    for name, expected in manifest["files"].items():
        path = (PUBLIC / name).resolve()
        assert path.is_relative_to(PUBLIC.resolve())
        assert path.stat().st_size == expected["bytes"] and sha(path) == expected["sha256"], name
    seal = read(PUBLIC / "PREDICTION-SEAL.json")
    freeze=read(PUBLIC / "FREEZE.json")
    for name,expected in freeze["files"].items():
        assert sha(ROOT/name)==expected, f"frozen experiment source changed: {name}"
    for name, expected in seal["files"].items():
        assert sha(PUBLIC / name) == expected
    assert sha(Path(__file__).with_name("observe.py")) == seal["observerSha256"]
    # Only the scorer sees both counterfactual worlds. Each prediction above
    # was produced in a separate process from its own single view.
    control = read(PUBLIC / "baseline.json")["identifiedOutputRegistrations"]
    expected_truth = {v["owner"]: v["recipientKey"] for v in control}
    counts = {}
    for path in sorted(PUBLIC.glob("*-prediction.json")):
        observation = path.with_name(path.name.replace("-prediction.json", ".json"))
        prediction = read(path)
        assert predict(read(observation)) == prediction
        assert expected_truth in prediction["completeOwnershipAssignments"], path.name
        counts[observation.stem] = prediction["assignmentCount"]
    validation = read(PUBLIC / "VALIDATION.json")
    assert counts == validation["counts"]
    assert validation["predictionSealSha256"] == sha(PUBLIC / "PREDICTION-SEAL.json")
    replay = read(PUBLIC / "PUBLIC-REPLAY.json")
    assert replay["nativeJointReverified"] and not replay["privateFilesRead"]
    execution = read(PUBLIC / "execution.json")
    assert all(c["accepted"] == c["expectedAccept"] for c in execution["native"]["nativeCases"])
    assert execution["native"]["jointMassQuote"]["withinBlockComponentLimits"]
    assert not execution["fullNodeValidation"] and not execution["chainAcceptance"]
    assert not validation["completePaymentPrivacyQualified"]
    print(json.dumps({"publicObserverResultsReproduced": counts, "completeCoupledTruthRetainedAgainstIdentifiedControl": True, "nativeFullOrChainQualification": False}, indent=2))


if __name__ == "__main__":
    check()
