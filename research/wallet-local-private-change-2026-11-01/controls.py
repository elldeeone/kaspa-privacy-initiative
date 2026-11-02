#!/usr/bin/env python3
"""Public regression and sensitivity controls for private-change inference."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

import observer


ORIGINAL_SHARED_MANIFEST = "1a9463269ef5647a1ce22b0af6b8e2121f236950fe2333873107c204f49677d9"
CORRECTION_MANIFEST = "f11471b8fc290194dd461445c9a83dec511c78e5fd81bd8acd1a1acf4ca6700f"


def load(path: Path):
    return json.loads(path.read_text())


def rewrite_token(path: Path):
    capture = load(path)
    capture["request"]["relayToken"] = "renamed-neutral-token"
    raw = json.dumps(capture["request"], separators=(",", ":")).encode()
    capture["requestRawHex"] = raw.hex()
    capture["requestBytes"] = len(raw)
    capture["requestSha256"] = hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: controls.py PUBLIC_DIR OUTPUT.json")
    root, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    predictions = load(root / "PREDICTIONS.json")
    score = load(root / "SCORE.json")
    joint = load(root / "JOINT-TRUTH-CHECK.json")
    prior_root = Path(__file__).resolve().parent.parent / "wallet-local-shared-history-2026-11-01"
    baseline = predictions["arms"][observer.ARMS[0]]["checkpoints"]["requested-withdrawal"]
    candidate_requested = predictions["arms"][observer.ARMS[1]]["checkpoints"]["requested-withdrawal"]
    candidate_remainder = predictions["arms"][observer.ARMS[1]]["checkpoints"]["remainder-withdrawal"]
    candidate_full = predictions["arms"][observer.ARMS[1]]["checkpoints"]["full-drainage"]
    checks = {
        "originalSharedManifestPreserved": hashlib.sha256((prior_root / "run/public/manifest.json").read_bytes()).hexdigest() == ORIGINAL_SHARED_MANIFEST,
        "falsePassCorrectionManifestPreserved": hashlib.sha256((prior_root / "run/correction-v2/manifest.json").read_bytes()).hexdigest() == CORRECTION_MANIFEST,
        "baselineKnownDirectExitAmountsUnique": (
            baseline["O-public-known"]["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1
            and baseline["O-public-known"]["withdrawingChain"]["onwardPaymentAmountSompi"]["count"] == 1
        ),
        "baselineKnownDirectExitRelationshipUnique": baseline["O-public-known"]["withdrawingChain"]["onwardRelationship"]["count"] == 1,
        "baselineUnmappedDirectExitP1Unique": baseline["O-public-unmapped"]["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1,
        "candidateRequestedP1StrictlyImprovesAllViews": all(item["P1StrictlyImproved"] for item in predictions["requestedWithdrawalComparison"].values()),
        "candidateRequestedP2StrictlyImprovesAllViews": all(item["P2StrictlyImproved"] for item in predictions["requestedWithdrawalComparison"].values()),
        "knownIdentityStillRevealsRequestedRelationship": candidate_requested["O-public-known"]["withdrawingChain"]["onwardRelationship"]["count"] == 1,
        "identityRemovalRestoresRequestedRelationshipAmbiguity": (
            candidate_requested["O-public-known"]["withdrawingChain"]["onwardRelationship"]["count"] == 1
            and candidate_requested["O-public-unmapped"]["withdrawingChain"]["onwardRelationship"]["count"] == 4
        ),
        "knownRemainderRevealsP1P2": (
            candidate_remainder["O-public-known"]["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1
            and candidate_remainder["O-public-known"]["withdrawingChain"]["onwardPaymentAmountSompi"]["count"] == 1
        ),
        "unmappedRemainderRevealsP1ButNotExactP2": (
            candidate_remainder["O-public-unmapped"]["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1
            and candidate_remainder["O-public-unmapped"]["withdrawingChain"]["onwardPaymentAmountSompi"]["count"] == 4
        ),
        "fullDrainageKnownRevealsBothChains": all(
            candidate_full["O-public-known"][role][field]["count"] == 1
            for role in ("withdrawingChain", "unrelatedChain")
            for field in ("originalFunder", "firstRelationship", "onwardRelationship", "earlierReceivedAmountSompi", "onwardPaymentAmountSompi")
        ),
        "allProjectedTruthRetained": score["allTruthRetained"],
        "allCoupledTruthRetained": joint["allPassed"],
        "privateTruthValuesNotPublished": not score["privateTruthValuesPublished"] and not joint["privateTruthValuesPublished"],
    }
    rename_cases = {}
    for arm in observer.ARMS:
        _, aux, _, credits, history, split_inputs, exits = observer.load_arm(root, arm)
        for checkpoint in ("pre-withdrawal", "requested-withdrawal", "remainder-withdrawal", "full-drainage"):
            for known in (True, False):
                records = observer.arm_records(arm, checkpoint, exits, aux, known)
                before = observer.project_checkpoint(arm, checkpoint, records, credits, history, split_inputs)
                after = observer.project_checkpoint(
                    arm,
                    checkpoint,
                    observer.rename_hidden_chains(records, arm, checkpoint),
                    credits,
                    history,
                    split_inputs,
                )
                rename_cases[f"{arm}/{checkpoint}/{'known' if known else 'unmapped'}"] = before == after
    checks["hiddenChainRenamingInvariant"] = all(rename_cases.values())
    checks["deterministicPredictionRebuild"] = observer.canonical(observer.predict(root)) == observer.canonical(predictions)
    checks["predictionSealMatches"] = hashlib.sha256(observer.canonical(predictions)).hexdigest() == (root / "PREDICTIONS.json.sha256").read_text().strip()
    checks["publicServiceViewsIdentical"] = all(
        views["O-public-known"] == views["O-service-known"]
        and views["O-public-unmapped"] == views["O-service-unmapped"]
        for arm in predictions["arms"].values()
        for views in arm["checkpoints"].values()
    )

    with tempfile.TemporaryDirectory(prefix="private-change-controls-") as temp:
        temp = Path(temp)
        renamed_root = temp / "renamed"
        shutil.copytree(root, renamed_root)
        for path in renamed_root.glob("*/*capture-*.json"):
            rewrite_token(path)
        checks["neutralRelayRenameInvariant"] = observer.canonical(observer.predict(renamed_root)) == observer.canonical(predictions)
        missing_root = temp / "missing"
        shutil.copytree(root, missing_root)
        (missing_root / observer.ARMS[1] / "event-19.json").unlink()
        (missing_root / observer.ARMS[1] / "capture-19.json").unlink()
        try:
            observer.predict(missing_root)
            checks["missingEventInvalidatesCoverage"] = False
        except (FileNotFoundError, ValueError):
            checks["missingEventInvalidatesCoverage"] = True

    result = {
        "schema": "wallet-local-private-change-controls-v1",
        "checks": checks,
        "hiddenChainRenameCases": rename_cases,
        "allPassed": all(checks.values()),
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["allPassed"]:
        raise SystemExit("one or more controls failed")
    print(json.dumps({"output": str(output), "checkCount": len(checks), "allPassed": True}))


if __name__ == "__main__":
    main()
