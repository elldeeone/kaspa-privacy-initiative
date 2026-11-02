#!/usr/bin/env python3
"""Build a finite public-result bundle from one private live TN10 run."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / ".local/ci-target/release/kpi-tn10-integration"
VALIDATOR_SHA = "1e0b13e2f686b86a2f0d3b76fd494e27413b963294bcd10ff7778599f33c5a64"
LANE = "0044454600000000000000000000000000000000"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def load(path: Path):
    return json.loads(path.read_text())


def write(path: Path, value: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: finalize-live-tn10.py PRIVATE_RUN NEW_PUBLIC_DIR")
    run = Path(sys.argv[1]).resolve()
    public = Path(sys.argv[2]).resolve()
    if stat.S_IMODE(run.stat().st_mode) != 0o700 or public.exists():
        raise RuntimeError("private run must be 0700 and output must be new")
    public.mkdir(mode=0o700)

    sources = {
        "FINAL-CORROBORATION.json": run / "final-corroboration.json",
        "FINAL-CHECKPOINT.json": run / "batch-07-checkpoint/checkpoint.json",
        "SCORE.json": run / "wallet-public/SCORE-TN10.json",
        "SERVICE-LOSS.json": run / "service-loss.json",
    }
    for name, source in sources.items():
        target = public / name
        shutil.copyfile(source, target)
        target.chmod(0o600)

    capture = run / "batch-07-settlement-recovery-capture.json"
    validator_bytes = VALIDATOR.read_bytes()
    if hashlib.sha256(validator_bytes).hexdigest() != VALIDATOR_SHA:
        raise RuntimeError("validator binary hash changed")
    validation = json.loads(
        subprocess.run(
            [str(VALIDATOR), "verify", LANE, str(capture)],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        ).stdout
    )
    capture_value = load(capture)
    pages = capture_value["paginationSourcePages"]
    if capture_value["failure"] is not None or len(pages) != 36:
        raise RuntimeError("terminal capture is incomplete")
    for page in pages:
        page_path = Path(page["file"])
        if digest(page_path) != page["gzipSha256"]:
            raise RuntimeError("retained native page hash mismatch")
    capture_summary = {
        "captureBytes": capture.stat().st_size,
        "captureSha256": digest(capture),
        "intervalBlocks": capture_value["intervalBlocks"],
        "retainedNativePages": len(pages),
        "retainedNativePageGzipSha256": [page["gzipSha256"] for page in pages],
        "validatorSha256": VALIDATOR_SHA,
        "validation": validation,
    }
    write(public / "TERMINAL-CAPTURE.json", capture_summary)

    corroboration = load(sources["FINAL-CORROBORATION.json"])
    checkpoint = load(sources["FINAL-CHECKPOINT.json"])
    score = load(sources["SCORE.json"])
    result = {
        "schema": "full-drainage-live-tn10-result-v1",
        "trial": checkpoint["trial"],
        "network": "testnet-10",
        "completedBatch": checkpoint["completed"],
        "finalSettlementTransactionId": checkpoint["stateOutpoint"]["transactionId"],
        "confirmedNativeOwnerOutputs": corroboration["confirmedNativeOwnerOutputs"],
        "corroboratingEndpoints": len(corroboration["endpoints"]),
        "permissionsSpent": corroboration["permissionsSpent"],
        "terminalAccounting": checkpoint["accounting"],
        "privacyDecision": score["decision"],
        "scope": "bounded TN10 implementation evidence; not cryptographic correctness, production safety, audit proof, or mainnet readiness",
    }
    write(public / "RESULT.json", result)

    private_files = [run / f"private/wallets/{label}.wallet" for label in ("A", "B", "M", "S")]
    private_files.extend([run / "private/truth.json", run / "trial/sponsor/native.key"])
    needles = []
    for source in private_files[:4]:
        raw = source.read_bytes()
        needles.extend((raw[:32], raw[32:], raw[:32].hex().encode(), raw[32:].hex().encode()))
    sponsor = private_files[-1].read_bytes().strip()
    needles.append(sponsor)
    public_files = sorted(path for path in public.iterdir() if path.is_file())
    leaked = [path.name for path in public_files if any(needle and needle in path.read_bytes() for needle in needles)]
    audit = {
        "schema": "full-drainage-live-tn10-public-audit-v1",
        "allowlistedFiles": sorted(path.name for path in public_files),
        "privateRunMode": oct(stat.S_IMODE(run.stat().st_mode)),
        "privateFileModes": {str(path.relative_to(run)): oct(stat.S_IMODE(path.stat().st_mode)) for path in private_files},
        "walletOrSponsorSecretMaterialFound": leaked,
        "scoreDeclaresPrivateTruthUnread": score["privateTruthRead"] is False,
        "terminalAccountingZero": all(checkpoint["accounting"][key] == 0 for key in (
            "reserve_principal", "private_liability", "pending_deposits", "unpaid_exits", "outstanding_permission_rent_excluded"
        )),
        "fivePayoutsCorroborated": corroboration["confirmedNativeOwnerOutputs"] == 5,
        "twoIndependentEndpoints": len(corroboration["endpoints"]) == 2,
        "allChecksPassed": not leaked,
    }
    audit["allChecksPassed"] = audit["allChecksPassed"] and all(
        audit[key] for key in (
            "scoreDeclaresPrivateTruthUnread", "terminalAccountingZero", "fivePayoutsCorroborated", "twoIndependentEndpoints"
        )
    )
    if not audit["allChecksPassed"]:
        raise RuntimeError("public-result audit failed")
    write(public / "AUDIT.json", audit)

    entries = {}
    for path in sorted(public.iterdir()):
        if path.is_file() and path.name != "MANIFEST.json":
            entries[path.name] = {"bytes": path.stat().st_size, "sha256": digest(path)}
    write(public / "MANIFEST.json", {"schema": "full-drainage-live-tn10-manifest-v1", "entries": entries})
    print(json.dumps({"audit": True, "files": len(entries), "manifestSha256": digest(public / "MANIFEST.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
