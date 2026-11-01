#!/usr/bin/env python3
"""Freeze one exact local Rust tool build into an immutable evidence bundle.

This helper is build provenance only.  It never reads a proving key, fixture,
trial identity, network endpoint, or funds.  It snapshots the dep-info-derived
repository source set before and after one locked/offline Cargo invocation and
publishes only if both snapshots are byte-identical.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

import offline_w1_fixture as fixture


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RELATION = ROOT / "poc/local-private-payment/private-batch-relation"
TOOLCHAIN = Path(
    "/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin"
)
CARGO = TOOLCHAIN / "cargo"
RUSTC = TOOLCHAIN / "rustc"


def need(value, category):
    if not value:
        raise RuntimeError(category)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"))
            + "\n").encode()


def regular(path):
    path = Path(path).resolve(strict=True)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not path.is_symlink(),
         "regular-build-input")
    return path


def reference(path, *, displayed=None):
    path = regular(path)
    raw = path.read_bytes()
    return {
        "path": str(path if displayed is None else displayed),
        "sha256": sha(raw),
        "bytes": len(raw),
    }


def source_set(dep_info):
    paths = set(fixture._cargo_dep_info_sources(dep_info))
    for package in (
        RELATION,
        ROOT / "poc/local-private-payment/native-authority/native-core",
        ROOT / "poc/local-private-payment/native-authority/vendor/native-relation",
    ):
        for name in ("Cargo.toml", "Cargo.lock", "build.rs"):
            candidate = package / name
            if candidate.is_file():
                paths.add(candidate.resolve(strict=True))
    need(paths and all(path.is_relative_to(ROOT) for path in paths),
         "repository-source-set")
    return sorted(paths)


def snapshot(paths):
    return [reference(path) for path in paths]


def write(path, raw, mode=0o400):
    raw = raw if type(raw) is bytes else canonical(raw)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def copy(path, destination, mode):
    path = regular(path)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, mode)
    with path.open("rb") as source, os.fdopen(descriptor, "wb") as output:
        shutil.copyfileobj(source, output, 1024 * 1024)
        output.flush()
        os.fsync(output.fileno())


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    target = Path(args.target_dir).absolute()
    output = Path(args.output).absolute()
    need(target.is_dir() and not target.is_symlink(), "target-directory")
    need(not output.exists(), "fresh-build-bundle")
    binary = regular(target / "release/owner_aux")
    dep_info = regular(target / "release/owner_aux.d")
    paths_before = source_set(dep_info)
    snapshot_before = snapshot(paths_before)

    command = {
        "schema": "kpb-offline-w1-owner-aux-build-command/v1",
        "cwd": str(RELATION),
        "executable": str(CARGO),
        "argv": [
            str(CARGO), "build", "--locked", "--offline", "--release",
            "--bin", "owner_aux",
        ],
        "environment": {
            "PATH": f"{TOOLCHAIN}:/usr/bin:/bin",
            "CARGO_HOME": "/home/luke/.cargo",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(target),
            "LANG": "C.UTF-8",
            "TZ": "UTC",
        },
    }
    environment = dict(command["environment"])
    with tempfile.TemporaryDirectory(
            prefix=".owner-aux-freeze-", dir=output.parent) as temporary:
        staging = Path(temporary)
        time_path = staging / "BUILD-TIME.txt"
        argv = ["/usr/bin/time", "-v", "-o", str(time_path),
                *command["argv"]]
        result = subprocess.run(
            argv, cwd=RELATION, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        write(staging / "BUILD.stdout", result.stdout)
        write(staging / "BUILD.stderr", result.stderr)
        need(result.returncode == 0, "locked-offline-owner-aux-build")

        paths_after = source_set(dep_info)
        snapshot_after = snapshot(paths_after)
        need(paths_after == paths_before
             and snapshot_after == snapshot_before,
             "source-changed-during-build")
        need(all(path.stat().st_mtime_ns <= binary.stat().st_mtime_ns
                 for path in paths_after),
             "source-newer-than-built-binary")

        final = output
        copy(binary, staging / "owner_aux", 0o500)
        copy(dep_info, staging / "owner_aux.d", 0o400)
        source = {
            "schema": "kpb-offline-w1-owner-aux-source-closure/v1",
            "classification": fixture.CLASSIFICATION,
            "derivation": (
                "cargo-link-dep-info-plus-local-package-manifests-lockfiles-and-build-scripts"
            ),
            "dep_info_sha256": sha(dep_info.read_bytes()),
            "member_count": len(snapshot_after),
            "members_identity_sha256": sha(canonical(snapshot_after)),
            "members": snapshot_after,
        }
        write(staging / "SOURCE-CLOSURE.json", source)
        write(staging / "BUILD-COMMAND.json", command)
        rustc_vv = subprocess.run(
            [RUSTC, "-Vv"], check=True, capture_output=True,
            env=environment,
        ).stdout
        cargo_version = subprocess.run(
            [CARGO, "-V"], check=True, capture_output=True, text=True,
            env=environment,
        ).stdout.strip()

        def final_ref(name):
            current = reference(staging / name)
            current["path"] = str(final / name)
            return current

        receipt = {
            "schema": "kpb-offline-w1-owner-aux-build-receipt/v1",
            "classification": fixture.CLASSIFICATION,
            "build_profile": "release",
            "locked": True,
            "offline": True,
            "binary": final_ref("owner_aux"),
            "dep_info": final_ref("owner_aux.d"),
            "source_closure": {
                **final_ref("SOURCE-CLOSURE.json"),
                "members_identity_sha256": source[
                    "members_identity_sha256"],
                "member_count": source["member_count"],
            },
            "build_command": final_ref("BUILD-COMMAND.json"),
            "build_stdout": final_ref("BUILD.stdout"),
            "build_stderr": final_ref("BUILD.stderr"),
            "build_time": final_ref("BUILD-TIME.txt"),
            "toolchain": {
                "cargo_version": cargo_version,
                "rustc_vv": rustc_vv.decode(),
                "rustc_vv_sha256": sha(rustc_vv),
            },
            "source_snapshot_equal_before_after_build": True,
            "all_source_mtimes_not_newer_than_binary": True,
            "proving_key_read": False,
            "matrix_synthesized": False,
            "fixture_or_trial_read": False,
            "network_enabled": False,
            "authorization": False,
            "privacy_or_financial_acceptance": False,
        }
        write(staging / "BUILD-RECEIPT.json", receipt)
        fixture.fsync_directory(staging)
        fixture.rename_no_replace(staging, final)
    print(json.dumps({
        "status": "OWNER_AUX_BUILD_FROZEN",
        "output": str(output),
        "binary_sha256": receipt["binary"]["sha256"],
        "source_members_identity_sha256": source[
            "members_identity_sha256"],
        "source_member_count": source["member_count"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
