#!/usr/bin/env python3
"""Audit public coverage, private modes, and secret exclusion."""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path


WORKLOAD_SHA = "1a97a77c7a5bed42a71530b5b07deb6595ce72e822aa6307a28e4e419ea601f5"


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: audit_run.py PUBLIC_DIR PRIVATE_DIR PRIVATE_WORKLOAD OUTPUT.json")
    public_root, private_root, workload_path, output = map(Path, sys.argv[1:])
    if output.exists():
        raise SystemExit("audit output exists")

    public_files = sorted(path for path in public_root.rglob("*") if path.is_file())
    public_bytes = b"\n".join(path.read_bytes() for path in public_files)
    backups = sorted(private_root.glob("wallet-*.backup"))
    leaks = []
    for backup in backups:
        raw = backup.read_bytes()
        for index, secret in enumerate((raw[:32], raw[32:])):
            encodings = (secret, secret.hex().encode(), json.dumps(list(secret)).encode())
            if any(encoding in public_bytes for encoding in encodings):
                leaks.append(f"{backup.name}:half-{index}")

    captures = sorted(public_root.glob("capture-*.json"))
    events = sorted(public_root.glob("event-*.json"))
    allowed = {"schema", "trial", "ordinal", "relayToken", "operation"}
    service_public_only = all(set(load(path)["request"]) == allowed for path in captures)
    operations_equal = all(
        load(capture)["request"]["operation"] == load(event)["operation"]
        for capture, event in zip(captures, events)
    )
    workload_raw = workload_path.read_bytes()
    predictions = public_root / "PREDICTIONS.json"
    sealed = (public_root / "PREDICTIONS.json.sha256").read_text().strip()
    score = load(public_root / "SCORE.json")
    ledger = load(public_root / "ledger.json")
    private_modes = {
        "directory0700": stat.S_IMODE(private_root.stat().st_mode) == 0o700,
        "backups0600": all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in backups),
        "truth0600": stat.S_IMODE((private_root / "truth.json").stat().st_mode) == 0o600,
        "workload0600": stat.S_IMODE(workload_path.stat().st_mode) == 0o600,
    }
    result = {
        "schema": "wallet-local-shared-history-public-safety-audit-v1",
        "eventCount": len(events),
        "serviceCaptureCount": len(captures),
        "captureEventOperationsEqual": operations_equal,
        "serviceRequestsPublicOnly": service_public_only,
        "ownerLocalBackupCount": len(backups),
        "ownerLocalBackupEncodingLeaks": leaks,
        "privateWorkloadFileCopiedPublicly": workload_raw in public_bytes,
        "privateWorkloadSha256MatchesCommitment": hashlib.sha256(workload_raw).hexdigest() == WORKLOAD_SHA,
        "privateModes": private_modes,
        "sealedPredictionsHashMatches": hashlib.sha256(canonical(load(predictions))).hexdigest() == sealed,
        "scorePublishesPrivateTruthValues": score["privateTruthValuesPublished"],
        "zeroFinalReserveAndLiability": ledger["final"]["reserveSompi"] == 0 and ledger["final"]["privateLiabilitySompi"] == 0,
        "sameHostIndependentCustodyClaim": False,
    }
    result["passed"] = (
        len(events) == 16
        and len(captures) == 16
        and operations_equal
        and service_public_only
        and len(backups) == 8
        and not leaks
        and not result["privateWorkloadFileCopiedPublicly"]
        and result["privateWorkloadSha256MatchesCommitment"]
        and all(private_modes.values())
        and result["sealedPredictionsHashMatches"]
        and not result["scorePublishesPrivateTruthValues"]
        and result["zeroFinalReserveAndLiability"]
    )
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise SystemExit("public-safety audit failed")
    print(json.dumps({"output": str(output), "passed": True}))


if __name__ == "__main__":
    main()
