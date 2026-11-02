#!/usr/bin/env python3
"""Write a deterministic SHA-256 manifest for public-safe run artifacts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: manifest_run.py PUBLIC_DIR")
    root = Path(sys.argv[1])
    output = root / "manifest.json"
    if output.exists():
        raise SystemExit("manifest already exists")
    files = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        files[relative] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest = {
        "schema": "wallet-local-public-manifest-v1",
        "fileCount": len(files),
        "files": files,
    }
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"manifest": str(output), "fileCount": len(files)}))


if __name__ == "__main__":
    main()
