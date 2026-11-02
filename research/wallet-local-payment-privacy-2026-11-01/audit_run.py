#!/usr/bin/env python3
"""Audit public coverage and absence of owner-local backup bytes."""

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
    if len(sys.argv) != 4:
        raise SystemExit("usage: audit_run.py PUBLIC_DIR PRIVATE_DIR OUTPUT.json")
    public_root = Path(sys.argv[1])
    private_root = Path(sys.argv[2])
    output = Path(sys.argv[3])
    if output.exists():
        raise SystemExit("audit output already exists")

    public_files = sorted(path for path in public_root.rglob("*") if path.is_file())
    public_bytes = b"\n".join(path.read_bytes() for path in public_files)
    backups = sorted(private_root.glob("trial-*/wallet-*.backup"))
    backup_leaks = []
    for backup in backups:
        raw = backup.read_bytes()
        for index, secret in enumerate((raw[:32], raw[32:])):
            encodings = [
                secret,
                secret.hex().encode(),
                json.dumps(list(secret)).encode(),
            ]
            if any(encoding in public_bytes for encoding in encodings):
                backup_leaks.append(f"{backup.name}:half-{index}")

    captures = sorted(public_root.glob("trial-*/capture-*.json"))
    events = sorted(public_root.glob("trial-*/event-*.json"))
    allowed_request_fields = {"schema", "trial", "ordinal", "relayToken", "operation"}
    service_public_only = all(
        set(load(path)["request"]) == allowed_request_fields for path in captures
    )
    capture_event_pairs = all(
        load(capture)["request"]["operation"] == load(event)["operation"]
        for capture, event in zip(captures, events)
    )
    private_modes = {
        "directories0700": all(
            stat.S_IMODE(path.stat().st_mode) == 0o700
            for path in [private_root, *sorted(private_root.glob("trial-*"))]
        ),
        "backups0600": all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in backups),
        "truth0600": all(
            stat.S_IMODE(path.stat().st_mode) == 0o600
            for path in private_root.glob("**/truth*.json")
        ),
    }
    predictions_path = public_root / "predictions.json"
    predictions_hash = hashlib.sha256(canonical(load(predictions_path))).hexdigest()
    sealed_hash = predictions_path.with_suffix(".json.sha256").read_text().strip()
    score = load(public_root / "score.json")
    result = {
        "schema": "wallet-local-public-safety-audit-v1",
        "publicFileCountBeforeAudit": len(public_files),
        "eventCount": len(events),
        "serviceCaptureCount": len(captures),
        "captureEventOperationsEqual": capture_event_pairs,
        "serviceRequestsPublicOnly": service_public_only,
        "ownerLocalBackupCount": len(backups),
        "ownerLocalBackupEncodingLeaks": backup_leaks,
        "privateModes": private_modes,
        "sealedPredictionsHashMatches": predictions_hash == sealed_hash,
        "scorePublishesPrivateTruthValues": score["privateTruthValuesPublished"],
        "sameHostIndependentCustodyClaim": False,
    }
    result["passed"] = (
        len(events) == 12
        and len(captures) == 12
        and capture_event_pairs
        and service_public_only
        and len(backups) == 12
        and not backup_leaks
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
