#!/usr/bin/env python3
"""Audit public coverage, private modes and secret exclusion."""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: audit_run.py PUBLIC_DIR PRIVATE_DIR PRIVATE_WORKLOAD OUTPUT.json")
    public_root = Path(sys.argv[1])
    private_root = Path(sys.argv[2])
    workload_path = Path(sys.argv[3])
    output = Path(sys.argv[4])
    if output.exists():
        raise SystemExit("audit output exists")

    public_files = sorted(path for path in public_root.rglob("*") if path.is_file())
    public_bytes = b"\n".join(path.read_bytes() for path in public_files)
    backups = sorted(private_root.glob("pair-*/*/wallet-*.backup"))
    leaks = []
    for backup in backups:
        raw = backup.read_bytes()
        for index, secret in enumerate((raw[:32], raw[32:])):
            if any(
                encoded in public_bytes
                for encoded in (secret, secret.hex().encode(), json.dumps(list(secret)).encode())
            ):
                leaks.append(f"{backup.parent.name}/{backup.name}:half-{index}")

    workload_raw = workload_path.read_bytes()
    workload_file_copied = workload_raw in public_bytes
    captures = sorted(public_root.glob("pair-*/*/capture-*.json"))
    events = sorted(public_root.glob("pair-*/*/event-*.json"))
    allowed = {"schema", "trial", "ordinal", "relayToken", "operation"}
    service_public_only = all(set(load(path)["request"]) == allowed for path in captures)
    operations_equal = all(
        load(capture)["request"]["operation"] == load(event)["operation"]
        for capture, event in zip(captures, events)
    )
    dirs = [private_root, *sorted(path for path in private_root.glob("pair-*/*") if path.is_dir())]
    private_modes = {
        "directories0700": all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in dirs),
        "backups0600": all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in backups),
        "truth0600": all(
            stat.S_IMODE(path.stat().st_mode) == 0o600
            for path in private_root.glob("**/truth*.json")
        ),
        "workload0600": stat.S_IMODE(workload_path.stat().st_mode) == 0o600,
    }
    predictions_path = public_root / "predictions.json"
    sealed = predictions_path.with_suffix(".json.sha256").read_text().strip()
    score = load(public_root / "score.json")
    result = {
        "schema": "wallet-local-private-spend-public-safety-audit-v1",
        "eventCount": len(events),
        "serviceCaptureCount": len(captures),
        "captureEventOperationsEqual": operations_equal,
        "serviceRequestsPublicOnly": service_public_only,
        "ownerLocalBackupCount": len(backups),
        "ownerLocalBackupEncodingLeaks": leaks,
        "privateWorkloadFileCopiedPublicly": workload_file_copied,
        "privateWorkloadSha256MatchesCommitment": hashlib.sha256(workload_raw).hexdigest()
        == "1259a46daf010dc8724cc6b390f0b0578faf34c6ccc073a0cabbd1027e501984",
        "privateModes": private_modes,
        "sealedPredictionsHashMatches": hashlib.sha256(canonical(load(predictions_path))).hexdigest()
        == sealed,
        "scorePublishesPrivateTruthValues": score["privateTruthValuesPublished"],
        "sameHostIndependentCustodyClaim": False,
    }
    result["passed"] = (
        len(events) == 28
        and len(captures) == 28
        and operations_equal
        and service_public_only
        and len(backups) == 24
        and not leaks
        and not workload_file_copied
        and result["privateWorkloadSha256MatchesCommitment"]
        and all(private_modes.values())
        and result["sealedPredictionsHashMatches"]
        and not result["scorePublishesPrivateTruthValues"]
    )
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise SystemExit("public-safety audit failed")
    print(json.dumps({"output": str(output), "passed": True}))


if __name__ == "__main__":
    main()
