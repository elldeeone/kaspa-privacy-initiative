#!/usr/bin/env python3
"""Neutral public-operation relay used only to record its actual observer view."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: relay.py OUT_DIR SERVICE_INSTANCE")
    output = Path(sys.argv[1])
    instance = sys.argv[2]
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    started = time.monotonic_ns()
    for ordinal, line in enumerate(sys.stdin.buffer, 1):
        received = time.monotonic_ns()
        request = json.loads(line)
        raw = canonical(request)
        capture = {
            "schema": "full-drainage-relay-capture-v1",
            "serviceInstance": instance,
            "servicePid": os.getpid(),
            "ordinalWithinService": ordinal,
            "receivedMonotonicNs": str(received - started),
            "requestBytes": len(line),
            "canonicalRequestSha256": hashlib.sha256(raw).hexdigest(),
            "relayToken": request["relayToken"],
            "operation": request["operation"],
        }
        name = f"capture-{ordinal:02}.json"
        (output / name).write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n")
        response = {"capture": name, "acceptedByRelayMonotonicNs": str(time.monotonic_ns() - started)}
        print(json.dumps(response, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

