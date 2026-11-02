#!/usr/bin/env python3
"""Manifest the public correction artifacts without modifying the original run."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: manifest_correction_v2.py CORRECTION_DIR")
    root = Path(sys.argv[1])
    output = root / "manifest.json"
    if output.exists():
        raise SystemExit("manifest exists")
    files = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        raw = path.read_bytes()
        files[path.relative_to(root).as_posix()] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    output.write_text(json.dumps({
        "schema": "wallet-local-shared-history-posthoc-correction-manifest-v2",
        "status": "post-hoc reassessment; original evidence preserved separately",
        "fileCount": len(files),
        "files": files,
    }, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(output), "fileCount": len(files)}))


if __name__ == "__main__":
    main()
