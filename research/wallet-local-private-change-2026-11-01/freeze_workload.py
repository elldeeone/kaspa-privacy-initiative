#!/usr/bin/env python3
"""Sample both exact arm workloads before wallets or observations exist."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import secrets
import stat
import sys
from pathlib import Path


MIN_SPLIT = 10_000_000


def uniform(low: int, high: int) -> int:
    return low + secrets.randbelow(high - low + 1)


def shuffled(values):
    result = list(values)
    for index in range(len(result) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        result[index], result[other] = result[other], result[index]
    return result


def schedule() -> list[int]:
    choices = []
    for zero_positions in itertools.combinations(range(4), 2):
        item = [1, 1, 1, 1]
        for position in zero_positions:
            item[position] = 0
        choices.append(item)
    return choices[secrets.randbelow(len(choices))]


def final_order(target_chain: int):
    roles = []
    for chain in (0, 1):
        for role in ("untouchedCredit", "firstChange", "secondChange", "secondPayment"):
            if chain == target_chain and role in {"secondChange", "secondPayment"}:
                continue
            roles.append({"chain": chain, "role": role})
    return shuffled(roles)


def common_arm(name: str) -> dict:
    p1_0 = uniform(220_000_000, 500_000_000)
    p2_0 = uniform(80_000_000, p1_0 - 80_000_000)
    p1_1 = uniform(180_000_000, 400_000_000)
    p2_1 = uniform(60_000_000, p1_1 - 60_000_000)
    first = shuffled(["E", "F"])
    second = shuffled(["G", "H"])
    target = secrets.randbelow(2)
    arm = {
        "arm": name,
        "chains": [
            {
                "sender": ["A", "B"][secrets.randbelow(2)],
                "firstRecipient": first[0],
                "secondRecipient": second[0],
                "p1Sompi": p1_0,
                "p2Sompi": p2_0,
                "paymentOutputIndices": [secrets.randbelow(2), secrets.randbelow(2)],
            },
            {
                "sender": ["C", "D"][secrets.randbelow(2)],
                "firstRecipient": first[1],
                "secondRecipient": second[1],
                "p1Sompi": p1_1,
                "p2Sompi": p2_1,
                "paymentOutputIndices": [secrets.randbelow(2), secrets.randbelow(2)],
            },
        ],
        "transferSchedule": schedule(),
        "targetChain": target,
        "finalExitOrder": final_order(target),
    }
    return arm


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: freeze_workload.py NEW_PRIVATE_DIRECTORY")
    directory = Path(sys.argv[1])
    if directory.exists():
        raise SystemExit("private workload directory exists")
    directory.mkdir(mode=0o700, parents=True)

    baseline = common_arm("direct-exit-baseline")
    baseline["directExitOrder"] = shuffled(["secondChange", "secondPayment"])

    candidate = common_arm("private-change-candidate")
    target = candidate["chains"][candidate["targetChain"]]
    role_values = {
        "secondChange": target["p1Sompi"] - target["p2Sompi"],
        "secondPayment": target["p2Sompi"],
    }
    candidate["requestedWithdrawalSompi"] = {
        role: uniform(MIN_SPLIT, value - MIN_SPLIT) for role, value in role_values.items()
    }
    candidate["splitOrder"] = shuffled(["secondChange", "secondPayment"])
    candidate["splitWithdrawalOutputIndex"] = {
        "secondChange": secrets.randbelow(2),
        "secondPayment": secrets.randbelow(2),
    }
    candidate["requestedExitOrder"] = shuffled(["secondChange", "secondPayment"])
    candidate["remainderExitOrder"] = shuffled(["secondChange", "secondPayment"])

    workload = {
        "schema": "wallet-local-private-change-workload-v1",
        "experiment": "wallet-local-private-change-v1",
        "creditsSompi": {"A": 900_000_000, "B": 800_000_000, "C": 700_000_000, "D": 600_000_000},
        "minimumRequestedAndChangeSompi": MIN_SPLIT,
        "arms": [baseline, candidate],
    }
    path = directory / "workload.json"
    raw = (json.dumps(workload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit("workload permissions")
    print(json.dumps({"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}))


if __name__ == "__main__":
    main()
