#!/usr/bin/env python3
"""Sample and commit the exact common-ledger workload before wallet creation."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import secrets
import stat
import sys
from pathlib import Path


def uniform(low: int, high: int) -> int:
    return low + secrets.randbelow(high - low + 1)


def shuffled(values: list):
    values = list(values)
    for index in range(len(values) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        values[index], values[other] = values[other], values[index]
    return values


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: freeze_workload.py NEW_PRIVATE_DIRECTORY")
    directory = Path(sys.argv[1])
    if directory.exists():
        raise SystemExit("private workload directory exists")
    directory.mkdir(mode=0o700, parents=True)

    p1_0 = uniform(220_000_000, 500_000_000)
    p2_0 = uniform(80_000_000, p1_0 - 80_000_000)
    p1_1 = uniform(180_000_000, 400_000_000)
    p2_1 = uniform(60_000_000, p1_1 - 60_000_000)
    first_recipients = shuffled(["E", "F"])
    second_recipients = shuffled(["G", "H"])
    schedules = []
    for zero_positions in itertools.combinations(range(4), 2):
        schedule = [1, 1, 1, 1]
        for position in zero_positions:
            schedule[position] = 0
        schedules.append(schedule)
    schedule = schedules[secrets.randbelow(len(schedules))]
    target_chain = secrets.randbelow(2)
    target_exit_roles = shuffled(["secondChange", "secondPayment"])
    remaining_roles = []
    for chain in (0, 1):
        for role in ("untouchedCredit", "firstChange", "secondChange", "secondPayment"):
            if chain == target_chain and role in {"secondChange", "secondPayment"}:
                continue
            remaining_roles.append({"chain": chain, "role": role})
    remaining_roles = shuffled(remaining_roles)
    workload = {
        "schema": "wallet-local-shared-history-workload-v1",
        "experiment": "wallet-local-shared-history-v1",
        "creditsSompi": {"A": 900_000_000, "B": 800_000_000, "C": 700_000_000, "D": 600_000_000},
        "chains": [
            {
                "sender": ["A", "B"][secrets.randbelow(2)],
                "firstRecipient": first_recipients[0],
                "secondRecipient": second_recipients[0],
                "p1Sompi": p1_0,
                "p2Sompi": p2_0,
                "paymentOutputIndices": [secrets.randbelow(2), secrets.randbelow(2)],
            },
            {
                "sender": ["C", "D"][secrets.randbelow(2)],
                "firstRecipient": first_recipients[1],
                "secondRecipient": second_recipients[1],
                "p1Sompi": p1_1,
                "p2Sompi": p2_1,
                "paymentOutputIndices": [secrets.randbelow(2), secrets.randbelow(2)],
            },
        ],
        "transferSchedule": schedule,
        "targetChain": target_chain,
        "targetExitRoles": target_exit_roles,
        "finalExitOrder": remaining_roles,
    }
    path = directory / "workload.json"
    raw = (json.dumps(workload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit("workload permissions")
    print(
        json.dumps(
            {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        )
    )


if __name__ == "__main__":
    main()
