#!/usr/bin/env python3
"""Run public-only controls for the frozen shared-history observer."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
OBSERVER = HERE / "observer.py"
PREVIOUS = HERE.parent / "wallet-local-private-spend-2026-11-01" / "run-v2" / "public" / "manifest.json"
PREVIOUS_SHA = "adb0da8835e82db929bcabf3d94ab7b189cb70df7b0f8eded4f41486138b0ce5"
OBSERVERS = ("O-public-known", "O-public-unmapped", "O-service-known", "O-service-unmapped")


def load(path: Path):
    return json.loads(path.read_text())


def run_observer(root: Path, output: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(OBSERVER), str(root), str(output)],
        text=True,
        capture_output=True,
        check=False,
    )


def rewrite_capture_token(path: Path) -> None:
    capture = load(path)
    capture["request"]["relayToken"] = "renamed-neutral-token"
    raw = json.dumps(capture["request"], separators=(",", ":")).encode()
    capture["requestRawHex"] = raw.hex()
    capture["requestBytes"] = len(raw)
    capture["requestSha256"] = hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: controls.py PUBLIC_DIR OUTPUT.json")
    root, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("control output exists")
    original = load(root / "PREDICTIONS.json")

    prior_hash = hashlib.sha256(PREVIOUS.read_bytes()).hexdigest()
    prior_preserved = prior_hash == PREVIOUS_SHA

    service_neutral = all(
        original["checkpoints"][checkpoint][public] == original["checkpoints"][checkpoint][service]
        for checkpoint in original["checkpoints"]
        for public, service in (
            ("O-public-known", "O-service-known"),
            ("O-public-unmapped", "O-service-unmapped"),
        )
    )

    mapping_monotonic = True
    mapping_strict = False
    for checkpoint in original["checkpoints"]:
        known = original["checkpoints"][checkpoint]["O-public-known"]["joint"]
        unmapped = original["checkpoints"][checkpoint]["O-public-unmapped"]["joint"]
        mapping_monotonic &= (
            unmapped["topologyCount"] >= known["topologyCount"]
            and unmapped["completeCompatibleHistoryCount"] >= known["completeCompatibleHistoryCount"]
        )
        mapping_strict |= unmapped != known

    with tempfile.TemporaryDirectory(prefix="shared-history-controls-") as temp:
        temp = Path(temp)
        alias_root = temp / "alias"
        shutil.copytree(root, alias_root)
        for path in alias_root.glob("capture-*.json"):
            rewrite_capture_token(path)
        alias_output = temp / "alias-predictions.json"
        alias_run = run_observer(alias_root, alias_output)
        alias_invariant = alias_run.returncode == 0 and load(alias_output)["checkpoints"] == original["checkpoints"]

        missing_exit_root = temp / "missing-exit"
        shutil.copytree(root, missing_exit_root)
        (missing_exit_root / "event-15.json").unlink()
        (missing_exit_root / "capture-15.json").unlink()
        missing_exit_invalid = run_observer(missing_exit_root, temp / "missing-exit.json").returncode != 0

        missing_chain_root = temp / "missing-chain"
        shutil.copytree(root, missing_chain_root)
        (missing_chain_root / "event-04.json").unlink()
        (missing_chain_root / "capture-04.json").unlink()
        unrelated_chain_required = run_observer(missing_chain_root, temp / "missing-chain.json").returncode != 0

    score = load(root / "SCORE.json")
    truth_retained = all(
        score["checkpoints"][checkpoint][observer]["completeTruthRetained"]
        for checkpoint in score["checkpoints"]
        for observer in OBSERVERS
    )
    result = {
        "schema": "wallet-local-shared-history-controls-v1",
        "previousPrivateSpendManifestSha256": prior_hash,
        "previousPrivateSpendEvidencePreserved": prior_preserved,
        "publicAndNeutralServiceViewsIdentical": service_neutral,
        "neutralRelayTokenRenameInvariant": alias_invariant,
        "payoutIdentityRemovalWeaklyIncreasesCandidates": mapping_monotonic and mapping_strict,
        "missingExitInvalidatesCoverage": missing_exit_invalid,
        "removingUnrelatedChainInvalidatesCoverage": unrelated_chain_required,
        "allTruthRetained": truth_retained,
    }
    result["allPassed"] = all(value for key, value in result.items() if key not in {"schema", "previousPrivateSpendManifestSha256"})
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["allPassed"]:
        raise SystemExit("one or more public controls failed")
    print(json.dumps({"output": str(output), "allPassed": True}))


if __name__ == "__main__":
    main()
