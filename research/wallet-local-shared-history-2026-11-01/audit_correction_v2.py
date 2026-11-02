#!/usr/bin/env python3
"""Check that correction artifacts are public-safe and source-bound."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import observer_correction_v2 as corrected


def load(path: Path):
    return json.loads(path.read_text())


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: audit_correction_v2.py ORIGINAL_PUBLIC CORRECTION_DIR PRIVATE_TRUTH OUTPUT.json")
    public_root, correction_root, truth_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    predictions = load(correction_root / "PREDICTIONS.json")
    score = load(correction_root / "SCORE.json")
    controls = load(correction_root / "CONTROLS.json")
    truth_raw = truth_path.read_bytes()
    correction_files = sorted(path for path in correction_root.rglob("*") if path.is_file())
    public_bytes = b"\n".join(path.read_bytes() for path in correction_files)
    result = {
        "schema": "wallet-local-shared-history-posthoc-correction-audit-v2",
        "status": "public-safe post-hoc reassessment",
        "originalManifestSha256": hashlib.sha256((public_root / "manifest.json").read_bytes()).hexdigest(),
        "originalManifestPreserved": hashlib.sha256((public_root / "manifest.json").read_bytes()).hexdigest()
        == corrected.ORIGINAL_MANIFEST_SHA,
        "correctionPredictionsSealed": hashlib.sha256(corrected.canonical(predictions)).hexdigest()
        == (correction_root / "PREDICTIONS.json.sha256").read_text().strip(),
        "predictionDeclaresNoTruthRead": predictions["observerBoundary"]["privateTruthRead"] is False,
        "scorePublishesPrivateTruthValues": score["privateTruthValuesPublished"],
        "rawPrivateTruthCopied": truth_raw in public_bytes,
        "controlsPassed": controls["allPassed"],
        "newProofOrWalletArtifactCount": len(
            [path for path in correction_files if path.name.startswith(("event-", "capture-", "wallet-"))]
        ),
        "networkOrFundingArtifactCreated": False,
    }
    result["passed"] = (
        result["originalManifestPreserved"]
        and result["correctionPredictionsSealed"]
        and result["predictionDeclaresNoTruthRead"]
        and not result["scorePublishesPrivateTruthValues"]
        and not result["rawPrivateTruthCopied"]
        and result["controlsPassed"]
        and result["newProofOrWalletArtifactCount"] == 0
    )
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise SystemExit("correction audit failed")
    print(json.dumps({"output": str(output), "passed": True}))


if __name__ == "__main__":
    main()
