#!/usr/bin/env python3
"""Public-safety and regression audit for the executed lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat


PRIOR = {
    "sharedOriginal": (
        Path("research/wallet-local-shared-history-2026-11-01/run/public/manifest.json"),
        "1a9463269ef5647a1ce22b0af6b8e2121f236950fe2333873107c204f49677d9",
    ),
    "sharedCorrection": (
        Path("research/wallet-local-shared-history-2026-11-01/run/correction-v2/manifest.json"),
        "f11471b8fc290194dd461445c9a83dec511c78e5fd81bd8acd1a1acf4ca6700f",
    ),
    "privateChange": (
        Path("research/wallet-local-private-change-2026-11-01/run/public/manifest.json"),
        "807d5022e40f443d8c0d8d96b9046f20a7fc1ee75aa5d780afcf83e83c5baff4",
    ),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path):
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("output exists")
    summary = load(args.public_root / "summary.json")
    public_files = [path for path in args.public_root.rglob("*") if path.is_file()]
    public_blobs = [path.read_bytes() for path in public_files]
    stores = sorted(args.private_root.glob("trial-*/wallets/*.wallet"))
    truths = sorted(args.private_root.glob("trial-*/truth.json"))
    if len(stores) != 8 or len(truths) != 2:
        raise RuntimeError("private inventory")
    leaked = []
    for store in stores:
        raw = store.read_bytes()
        if len(raw) != 64:
            raise RuntimeError("wallet store size")
        needles = (raw[:32], raw[32:], raw[:32].hex().encode(), raw[32:].hex().encode())
        if any(needle in blob for needle in needles for blob in public_blobs):
            leaked.append(store.name)
    modes = {
        "privateRoot": stat.S_IMODE(args.private_root.stat().st_mode),
        "walletStores": sorted({stat.S_IMODE(path.stat().st_mode) for path in stores}),
        "truthFiles": sorted({stat.S_IMODE(path.stat().st_mode) for path in truths}),
    }
    if modes != {"privateRoot": 0o700, "walletStores": [0o600], "truthFiles": [0o600]}:
        raise RuntimeError(f"private permissions: {modes}")
    trials = []
    for alias in summary["trialAliases"]:
        trial = args.public_root / alias
        receipt = load(trial / "run-receipt.json")
        service = load(trial / "service-loss.json")
        trials.append(
            {
                "alias": alias,
                "events": len(list(trial.glob("event-*.json"))),
                "operations": len(list(trial.glob("operation-*.json"))),
                "payouts": len(list(trial.glob("payout-*.json"))),
                "finalAccounting": receipt["finalAccounting"],
                "walletRestores": service["walletBackupsRestored"],
                "commonExitAnchor": service["commonExitAnchor"],
                "sameHost": service["sameHost"],
            }
        )
    prior = {name: {"path": str(path), "expected": expected, "actual": digest(path), "unchanged": digest(path) == expected} for name, (path, expected) in PRIOR.items()}
    result = {
        "schema": "full-drainage-executed-public-safety-audit-v1",
        "publicFilesScanned": len(public_files),
        "walletStoresChecked": len(stores),
        "walletSecretHalvesOrHexFoundInPublic": leaked,
        "privatePermissions": {key: oct(value) if isinstance(value, int) else [oct(item) for item in value] for key, value in modes.items()},
        "trials": trials,
        "priorEvidence": prior,
        "scoreDeclaresPrivateTruthUnread": load(args.public_root / "SCORE.json")["privateTruthRead"] is False,
        "allChecksPassed": not leaked and all(item["unchanged"] for item in prior.values()),
    }
    if not result["allChecksPassed"]:
        raise RuntimeError("audit failed")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"allChecksPassed": True, "publicFilesScanned": len(public_files)}, sort_keys=True))


if __name__ == "__main__":
    main()

