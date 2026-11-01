#!/usr/bin/env python3
"""Create-new canonical local Cargo source closure for the Output axis generator."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[3]
EXCLUDED_PARTS = {"target", ".git", "evidence", "__pycache__"}
SOURCE_SUFFIXES = {".rs", ".toml", ".lock", ".py"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: freeze_source_closure.py NEW-SOURCE-CLOSURE.json")
    output = Path(sys.argv[1])
    if output.exists():
        raise SystemExit("source closure output already exists")
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"],
        cwd=HERE,
        check=True,
        capture_output=True,
        text=True,
    ).stdout)
    packages = []
    files: set[Path] = set()
    for package in metadata["packages"]:
        manifest = Path(package["manifest_path"]).resolve()
        try:
            relative_manifest = manifest.relative_to(REPOSITORY)
        except ValueError:
            continue
        package_root = manifest.parent
        packages.append({
            "name": package["name"],
            "version": package["version"],
            "manifest_path": relative_manifest.as_posix(),
        })
        for path in package_root.rglob("*"):
            if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.parts):
                continue
            if path.name in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"} or \
                    path.suffix in SOURCE_SUFFIXES:
                files.add(path.resolve())
    entries = [
        {"path": path.relative_to(REPOSITORY).as_posix(), "sha256": sha256(path)}
        for path in sorted(files)
    ]
    body = {
        "schema": "kpb-output-r1cs-local-source-closure/v1",
        "workspace_relative": True,
        "resolved_local_packages": sorted(packages, key=lambda value: value["name"]),
        "files": entries,
        "file_count": len(entries),
    }
    body["closure_identity"] = hashlib.sha256(canonical(body)).hexdigest()
    encoded = json.dumps(body, indent=2, sort_keys=True).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    descriptor = os.open(output, flags, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({
        "schema": body["schema"],
        "file_count": body["file_count"],
        "closure_identity": body["closure_identity"],
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
