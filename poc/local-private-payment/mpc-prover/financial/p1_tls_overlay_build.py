#!/usr/bin/env python3
"""Materialize the exact source-only passive-P1 TLS instrumentation overlay."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


SCHEMA = "kpb-p1-tls-source-overlay/v1"
PATCH_SHA256 = "dc984ecfcf8602cc7c20fda96d9798b4c08808f29756897e8b8208b2d9e4ff15"
PREIMAGE_SHA256 = {
    "Networking/CryptoPlayer.cpp":
        "919b6f44e9fa6730d3ab118c16d8eb52d1056027d64c7aa920dfbc0e8ec53bb3",
    "Networking/CryptoPlayer.h":
        "3c3545b9b483b93510e626bc433252a83417cad3bb6a6ef94f07aab99c02090d",
    # This is the pinned upstream file after the separately selected mutual
    # TLS client-certificate patch in DEPENDENCIES.json.
    "Networking/ssl_sockets.h":
        "49c2ec7c16b79206f48e6183529f40a06e7b2eb86d689eca763e987f8943320a",
}
POSTIMAGE_SHA256 = {
    "Networking/CryptoPlayer.cpp":
        "e43348a133dddebc025b0256755d10ae3a0c5ef9edac965e1594ffb81cea1d08",
    "Networking/CryptoPlayer.h":
        "cf8df4fcb8134ea7a74ef04c718a27f67e3808b8298d45118c95689a66e835b3",
    "Networking/ssl_sockets.h":
        "bcd3de7b07caabdc54864d6aad0318f1c611df7e2a199b04168888b79ec57017",
    "Networking/p1_tls_state_capture.h":
        "945c8c6b6c62ce3127bae71789b79d1666155e03f5283568bc31cef9e9f9b3e0",
}


class TlsOverlayRefused(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _need(value: bool, message: str) -> None:
    if not value:
        raise TlsOverlayRefused(message)


def _identity(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def materialize(
        *, vendor_mp: Path, patch_path: Path, output: Path,
        patch_tool: Path = Path("/usr/bin/patch")) -> dict:
    """Create one exact overlay without modifying the pinned vendor tree."""
    vendor_mp = vendor_mp.resolve()
    patch_path = patch_path.resolve()
    output = output.resolve()
    patch_tool = patch_tool.resolve()
    _need(vendor_mp.is_dir(), "missing-pinned-MP-SPDZ")
    _need(patch_path.is_file() and not patch_path.is_symlink(),
          "invalid-TLS-overlay-patch")
    _need(sha256(patch_path) == PATCH_SHA256, "TLS-overlay-patch-drift")
    _need(patch_tool.is_file() and not patch_tool.is_symlink(),
          "invalid-patch-tool")
    _need(not output.exists(), "TLS-overlay-output-already-exists")

    for relative, expected in PREIMAGE_SHA256.items():
        source = vendor_mp / relative
        _need(source.is_file() and not source.is_symlink(),
              "invalid-TLS-overlay-preimage:" + relative)
        _need(sha256(source) == expected,
              "TLS-overlay-preimage-drift:" + relative)

    (output / "Networking").mkdir(parents=True, mode=0o700)
    for relative in PREIMAGE_SHA256:
        source = vendor_mp / relative
        target = output / relative
        shutil.copyfile(source, target)
        target.chmod(0o600)

    command = [
        str(patch_tool), "--batch", "--fuzz=0", "-p1",
        "-d", str(output), "-i", str(patch_path),
    ]
    result = subprocess.run(
        command, capture_output=True, check=False,
        env={"PATH": "/usr/bin:/bin"}, timeout=30)
    _need(result.returncode == 0, "TLS-overlay-patch-application-refused")
    inventory = sorted(
        str(path.relative_to(output))
        for path in output.rglob("*") if path.is_file())
    _need(inventory == sorted(POSTIMAGE_SHA256),
          "TLS-overlay-output-inventory-drift")
    for relative, expected in POSTIMAGE_SHA256.items():
        target = output / relative
        _need(target.is_file() and not target.is_symlink(),
              "invalid-TLS-overlay-postimage:" + relative)
        _need(sha256(target) == expected,
              "TLS-overlay-postimage-drift:" + relative)
    header = (output / "Networking/CryptoPlayer.h").read_text(
        encoding="utf-8")
    source = (output / "Networking/CryptoPlayer.cpp").read_text(
        encoding="utf-8")
    _need("#define KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1 1" in header,
          "TLS-overlay-feature-macro-absent")
    _need("exit(1);" not in source,
          "TLS-overlay-raw-handshake-exit-retained")

    record = {
        "schema": SCHEMA,
        "patch_sha256": PATCH_SHA256,
        "preimage_sha256": PREIMAGE_SHA256,
        "postimage_sha256": POSTIMAGE_SHA256,
        "patch_tool": {
            "path": str(patch_tool),
            "sha256": sha256(patch_tool),
            "bytes": patch_tool.stat().st_size,
        },
        "patch_stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "patch_stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "complete_tls_process_view": False,
        "configured": False,
    }
    record["identity"] = _identity(record)
    return record

