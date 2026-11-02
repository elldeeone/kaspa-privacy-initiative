#!/usr/bin/env python3
"""Create the owner-local payment workload before any wallet or observation."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path


DEPOSITS = {
    "pair-00": [900_000_000, 700_000_000],
    "pair-01": [850_000_000, 650_000_000],
}


def draw(deposits: list[int]) -> tuple[int, int]:
    p1_min = 200_000_000
    p1_max = min(deposits) - 100_000_000
    p1 = p1_min + secrets.randbelow(p1_max - p1_min + 1)
    p2_min = 50_000_000
    p2_max = p1 - 50_000_000
    p2 = p2_min + secrets.randbelow(p2_max - p2_min + 1)
    return p1, p2


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: freeze_workload.py NEW_PRIVATE_DIRECTORY")
    directory = Path(sys.argv[1])
    if directory.exists():
        raise SystemExit("private workload directory already exists")
    directory.mkdir(mode=0o700, parents=True)
    first = draw(DEPOSITS["pair-00"])
    second = draw(DEPOSITS["pair-01"])
    while second == first:
        second = draw(DEPOSITS["pair-01"])
    workload = {
        "schema": "wallet-local-private-spend-workload-v1",
        "experiment": "wallet-local-private-spend-v2",
        "pairs": {
            "pair-00": {
                "depositsSompi": DEPOSITS["pair-00"],
                "p1Sompi": first[0],
                "p2Sompi": first[1],
            },
            "pair-01": {
                "depositsSompi": DEPOSITS["pair-01"],
                "p1Sompi": second[0],
                "p2Sompi": second[1],
            },
        },
    }
    path = directory / "workload.json"
    raw = (json.dumps(workload, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit("workload permissions")
    print(
        json.dumps(
            {
                "path": str(path),
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
