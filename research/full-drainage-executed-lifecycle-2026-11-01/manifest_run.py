#!/usr/bin/env python3
"""Create a deterministic public artifact manifest without self-inclusion."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if args.output.exists() and not args.replace:
        raise SystemExit("output exists")
    files = sorted(path for path in args.root.rglob("*") if path.is_file() and path != args.output)
    manifest = {
        "schema": "full-drainage-executed-public-manifest-v1",
        "root": str(args.root),
        "entries": {
            str(path.relative_to(args.root)): {"bytes": path.stat().st_size, "sha256": digest(path)}
            for path in files
        },
    }
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"entries": len(files), "manifestSha256": digest(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
