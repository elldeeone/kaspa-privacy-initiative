#!/usr/bin/env python3
"""Audit coverage, secret exclusion, modes, and zero-liability execution."""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path

import observer


def load(path: Path):
    return json.loads(path.read_text())


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: audit_run.py PUBLIC_DIR PRIVATE_DIR PRIVATE_WORKLOAD OUTPUT.json")
    public_root, private_root, workload_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("output exists")
    public_files = sorted(path for path in public_root.rglob("*") if path.is_file())
    public_bytes = b"\n".join(path.read_bytes() for path in public_files)
    backups = sorted(private_root.glob("*/*.backup"))
    leaks = []
    for backup in backups:
        raw = backup.read_bytes()
        for index, secret in enumerate((raw[:32], raw[32:])):
            if any(encoded in public_bytes for encoded in (secret, secret.hex().encode(), json.dumps(list(secret)).encode())):
                leaks.append(f"{backup.parent.name}/{backup.name}:half-{index}")
    events = sorted(public_root.glob("*/event-*.json"))
    captures = sorted(public_root.glob("*/capture-*.json"))
    operations_equal = all(
        load(capture)["request"]["operation"] == load(event)["operation"]
        for capture, event in zip(captures, events)
    )
    allowed = {"schema", "trial", "ordinal", "relayToken", "operation"}
    public_only = all(set(load(path)["request"]) == allowed for path in captures)
    workload_raw = workload_path.read_bytes()
    private_dirs = [private_root, *(private_root / arm for arm in observer.ARMS)]
    truth_files = [private_root / "truth-index.json", *(private_root / arm / "truth.json" for arm in observer.ARMS)]
    ledgers = [load(public_root / arm / "ledger.json") for arm in observer.ARMS]
    predictions = load(public_root / "PREDICTIONS.json")
    score = load(public_root / "SCORE.json")
    joint = load(public_root / "JOINT-TRUTH-CHECK.json")
    result = {
        "schema": "wallet-local-private-change-public-safety-audit-v1",
        "eventCount": len(events),
        "serviceCaptureCount": len(captures),
        "captureEventOperationsEqual": operations_equal,
        "serviceRequestsPublicOnly": public_only,
        "ownerLocalBackupCount": len(backups),
        "ownerLocalBackupEncodingLeaks": leaks,
        "privateWorkloadCopiedPublicly": workload_raw in public_bytes,
        "privateWorkloadSha256MatchesCommitment": hashlib.sha256(workload_raw).hexdigest() == observer.WORKLOAD_SHA,
        "privateModes": {
            "directories0700": all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in private_dirs),
            "backups0600": all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in backups),
            "truth0600": all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in truth_files),
            "workload0600": stat.S_IMODE(workload_path.stat().st_mode) == 0o600,
        },
        "predictionSealMatches": hashlib.sha256(observer.canonical(predictions)).hexdigest() == (public_root / "PREDICTIONS.json.sha256").read_text().strip(),
        "scorePublishesPrivateTruthValues": score["privateTruthValuesPublished"],
        "jointCheckPublishesPrivateTruthValues": joint["privateTruthValuesPublished"],
        "allProjectedTruthRetained": score["allTruthRetained"],
        "allCoupledTruthRetained": joint["allPassed"],
        "bothArmsZeroFinalReserveAndLiability": all(
            ledger["final"]["reserveSompi"] == 0 and ledger["final"]["privateLiabilitySompi"] == 0 for ledger in ledgers
        ),
        "candidateReachedExactlySixteenLeaves": ledgers[1]["final"]["treeLeaves"] == 16,
        "applicationFeeSompi": [ledger["applicationFeeSompi"] for ledger in ledgers],
        "nativeNetworkFee": [ledger["nativeNetworkFee"] for ledger in ledgers],
        "sameHostIndependentCustodyClaim": False,
    }
    result["passed"] = (
        len(events) == 36
        and len(captures) == 36
        and operations_equal
        and public_only
        and len(backups) == 16
        and not leaks
        and not result["privateWorkloadCopiedPublicly"]
        and result["privateWorkloadSha256MatchesCommitment"]
        and all(result["privateModes"].values())
        and result["predictionSealMatches"]
        and not result["scorePublishesPrivateTruthValues"]
        and not result["jointCheckPublishesPrivateTruthValues"]
        and result["allProjectedTruthRetained"]
        and result["allCoupledTruthRetained"]
        and result["bothArmsZeroFinalReserveAndLiability"]
        and result["candidateReachedExactlySixteenLeaves"]
        and result["applicationFeeSompi"] == [0, 0]
        and result["nativeNetworkFee"] == ["unmeasured-no-network", "unmeasured-no-network"]
    )
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise SystemExit("public safety audit failed")
    print(json.dumps({"output": str(output), "passed": True}))


if __name__ == "__main__":
    main()
