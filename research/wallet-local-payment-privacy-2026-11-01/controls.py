#!/usr/bin/env python3
"""Run frozen scorer controls without reading private truth."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from observer import enumerate_trial, load, predict


HERE = Path(__file__).resolve().parent


def counts(result: dict, observer: str) -> dict:
    return {key: len(value) for key, value in result[observer].items()}


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: controls.py PUBLIC_DIR OUTPUT.json")
    public_root = Path(sys.argv[1])
    output = Path(sys.argv[2])
    if output.exists():
        raise SystemExit("control output already exists")

    baseline = json.loads(
        subprocess.check_output(["python3", str(HERE / "analyze.py")], text=True)
    )
    baseline_counts = baseline["candidate_counts_under_frozen_auxiliary_overlay"]
    baseline_unique = all(
        value == 1 for observer in baseline_counts.values() for value in observer.values()
    )

    original = predict(public_root)
    aux_index = load(public_root / "auxiliary.json")
    aux_by_trial = {item["trial"]: item for item in aux_index["trials"]}

    reversed_aux = copy.deepcopy(aux_index)
    reversed_aux["trials"].reverse()
    with tempfile.TemporaryDirectory(prefix="wallet-privacy-control-") as temp:
        variant_root = Path(temp) / "public"
        shutil.copytree(public_root, variant_root)
        (variant_root / "auxiliary.json").write_text(
            json.dumps(reversed_aux, indent=2, sort_keys=True) + "\n"
        )
        for capture_path in variant_root.glob("trial-*/capture-*.json"):
            capture = load(capture_path)
            capture["request"]["relayToken"] = "irrelevant-renamed-token"
            raw = json.dumps(
                capture["request"], sort_keys=True, separators=(",", ":")
            ).encode()
            capture["requestRawHex"] = raw.hex()
            capture["requestBytes"] = len(raw)
            capture["requestSha256"] = hashlib.sha256(raw).hexdigest()
            capture_path.write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n")
        renamed = predict(variant_root)
    order_alias_invariant = [
        {
            observer: counts(trial, observer)
            for observer in ("O-public", "O-service")
        }
        for trial in original["trials"]
    ] == [
        {
            observer: counts(trial, observer)
            for observer in ("O-public", "O-service")
        }
        for trial in renamed["trials"]
    ]

    trial0 = public_root / "trial-00"
    aux0 = aux_by_trial["trial-00"]
    mapped = enumerate_trial(trial0, aux0)
    unmapped_aux = copy.deepcopy(aux0)
    unmapped_aux["knownExitDestinationIdentity"] = {}
    unmapped = enumerate_trial(trial0, unmapped_aux)
    mapping_effect = (
        len(mapped["O-public"]["recipient"]) == 1
        and len(unmapped["O-public"]["recipient"]) == 2
    )

    with tempfile.TemporaryDirectory(prefix="wallet-privacy-missing-") as temp:
        missing_trial = Path(temp) / "trial-00"
        shutil.copytree(trial0, missing_trial)
        (missing_trial / "event-01.json").unlink()
        (missing_trial / "capture-01.json").unlink()
        missing = enumerate_trial(missing_trial, aux0, strict=False)
    full_historical = len(mapped["O-public"]["historicalNote"])
    missing_historical = len(missing["O-public"]["historicalNote"])
    missing_credit_effect = (
        full_historical == 2
        and missing_historical == 1
        and len(missing["O-public"]["sender"]) == 1
        and missing["coverage"]["complete"] is False
    )

    result = {
        "schema": "wallet-local-scorer-controls-v1",
        "publishedBaselineUniquelyRecovered": baseline_unique,
        "publishedBaselineCounts": baseline_counts,
        "irrelevantRelayAliasAndAuxOrderInvariant": order_alias_invariant,
        "exitIdentityEvidenceChangesRecipientCandidates": mapping_effect,
        "exitIdentityRecipientCounts": {
            "withMapping": len(mapped["O-public"]["recipient"]),
            "withoutMapping": len(unmapped["O-public"]["recipient"]),
        },
        "missingCreditChangesCandidatesAndInvalidatesCoverage": missing_credit_effect,
        "missingCreditHistoricalCounts": {
            "complete": full_historical,
            "missing": missing_historical,
        },
        "allPassed": all(
            [baseline_unique, order_alias_invariant, mapping_effect, missing_credit_effect]
        ),
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["allPassed"]:
        raise SystemExit("one or more scorer controls failed")
    print(json.dumps({"output": str(output), "allPassed": True}))


if __name__ == "__main__":
    main()
