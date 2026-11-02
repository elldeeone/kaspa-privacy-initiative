#!/usr/bin/env python3
"""Public controls for the versioned post-hoc scoring correction."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import observer
import observer_correction_v2 as corrected


def load(path: Path):
    return json.loads(path.read_text())


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: correction_controls_v2.py ORIGINAL_PUBLIC_DIR CORRECTION_DIR OUTPUT.json")
    public_root, correction_root, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    predictions = load(correction_root / "PREDICTIONS.json")
    score = load(correction_root / "SCORE.json")
    target = predictions["checkpoints"]["target-cashout"]
    known = target["O-public-known"]
    unmapped = target["O-public-unmapped"]

    checks = {
        "originalManifestPreserved": hashlib.sha256((public_root / "manifest.json").read_bytes()).hexdigest()
        == corrected.ORIGINAL_MANIFEST_SHA,
        "originalPredictionsPreserved": hashlib.sha256((public_root / "PREDICTIONS.json").read_bytes()).hexdigest()
        == corrected.ORIGINAL_PREDICTIONS_SHA,
        "originalScorePreserved": hashlib.sha256((public_root / "SCORE.json").read_bytes()).hexdigest()
        == corrected.ORIGINAL_SCORE_SHA,
        "knownTargetHasTwoHiddenLabels": known["diagnostics"]["hiddenTargetLabelCount"] == 2,
        "knownWithdrawalTupleUnique": known["withdrawingChain"]["withdrawalLinkedTuple"]["count"] == 1,
        "knownEarlierReceivedAmountUnique": known["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1,
        "knownOnwardAmountUnique": known["withdrawingChain"]["onwardPaymentAmountSompi"]["count"] == 1,
        "knownOnwardRelationshipUnique": known["withdrawingChain"]["onwardRelationship"]["count"] == 1,
        "unmappedEarlierReceivedAmountUnique": unmapped["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1,
        "unmappedOnwardAmountRetainsTwo": unmapped["withdrawingChain"]["onwardPaymentAmountSompi"]["count"] == 2,
        "unmappedWithdrawalTupleHasEight": unmapped["withdrawingChain"]["withdrawalLinkedTuple"]["count"] == 8,
        "identityRemovalRestoresTargetRelationshipAmbiguity": (
            known["withdrawingChain"]["onwardRelationship"]["count"] == 1
            and unmapped["withdrawingChain"]["onwardRelationship"]["count"] == 4
        ),
        "identityRemovalRestoresUnrelatedRelationshipAmbiguity": (
            known["unrelatedChain"]["onwardRelationship"]["count"] == 1
            and unmapped["unrelatedChain"]["onwardRelationship"]["count"] == 4
        ),
        "allTruthRetained": all(
            view["allTruthRetained"]
            for checkpoint in score["checkpoints"].values()
            for view in checkpoint.values()
        ),
        "privateTruthValuesNotPublished": score["privateTruthValuesPublished"] is False,
        "legacyBlanketPassExplicitlyInvalid": score["correctedHeadline"]["legacyTargetCashoutBlanketPassValid"] is False,
    }

    _, aux, events = observer.load_public(public_root)
    credits, history, exits = observer.public_material(aux, events)
    rename_results = {}
    for checkpoint in ("pre-cashout", "target-cashout", "full-cashout"):
        for known_identity in (True, False):
            if checkpoint == "pre-cashout":
                records = observer.pre_records()
            elif checkpoint == "target-cashout":
                records = observer.target_records(exits, aux, known_identity)
            else:
                records = observer.full_records(exits, aux, known_identity)
            before = corrected.project_checkpoint(checkpoint, records, credits, history)
            after = corrected.project_checkpoint(
                checkpoint, corrected.rename_hidden_chains(records, checkpoint), credits, history
            )
            rename_results[f"{checkpoint}/{'known' if known_identity else 'unmapped'}"] = before == after
    checks["hiddenChainRenamingInvariant"] = all(rename_results.values())

    for checkpoint in predictions["checkpoints"].values():
        checks.setdefault("publicServiceViewsIdentical", True)
        checks["publicServiceViewsIdentical"] &= (
            checkpoint["O-public-known"] == checkpoint["O-service-known"]
            and checkpoint["O-public-unmapped"] == checkpoint["O-service-unmapped"]
        )

    rebuilt = corrected.build_predictions(public_root)
    checks["deterministicPublicOnlyRebuild"] = corrected.canonical(rebuilt) == corrected.canonical(predictions)
    checks["sealedCorrectionMatches"] = hashlib.sha256(corrected.canonical(predictions)).hexdigest() == (
        correction_root / "PREDICTIONS.json.sha256"
    ).read_text().strip()

    result = {
        "schema": "wallet-local-shared-history-posthoc-correction-controls-v2",
        "status": "post-hoc reassessment controls",
        "checks": checks,
        "hiddenChainRenameCases": rename_results,
        "allPassed": all(checks.values()),
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["allPassed"]:
        raise SystemExit("one or more correction controls failed")
    print(json.dumps({"output": str(output), "allPassed": True, "checkCount": len(checks)}))


if __name__ == "__main__":
    main()
