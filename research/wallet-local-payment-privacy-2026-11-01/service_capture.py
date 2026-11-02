#!/usr/bin/env python3
"""Capture exactly what the replaceable public-operation processor receives."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: service_capture.py OUTPUT.json")
    output = Path(sys.argv[1])
    raw = sys.stdin.buffer.read()
    request = json.loads(raw)
    if set(request) != {"schema", "trial", "ordinal", "relayToken", "operation"}:
        raise SystemExit("unexpected service request fields")
    if request["schema"] != "wallet-local-public-operation-request-v1":
        raise SystemExit("unexpected service request schema")
    receipt = {
        "schema": "wallet-local-service-capture-v1",
        "classification": "actual same-host process input; not a network-anonymity claim",
        "receivedMonotonicNs": time.monotonic_ns(),
        "requestBytes": len(raw),
        "requestSha256": hashlib.sha256(raw).hexdigest(),
        "requestRawHex": raw.hex(),
        "request": request,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(output, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
