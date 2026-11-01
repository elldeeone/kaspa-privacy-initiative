#!/usr/bin/env python3
"""Build and freeze the feature-gated evidence-only W1 verifier.

The script snapshots the exact dep-info-derived Rust source set before and
after one locked/offline release build.  It never reads a proving key or a W1
fixture and publishes no authority or validity boolean.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

import offline_w1_fixture as fixture
import freeze_offline_w1_rust_build as freeze


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RELATION = ROOT / "poc/local-private-payment/private-batch-relation"
AUTH_EXIT = HERE / "auth_exit"


def source_set(dep_info):
    paths = set(fixture._cargo_dep_info_sources(dep_info))
    for package in (
        RELATION,
        ROOT / "poc/local-private-payment/native-authority/native-core",
        ROOT / "poc/local-private-payment/native-authority/vendor/native-relation",
        AUTH_EXIT,
    ):
        for name in ("Cargo.toml", "Cargo.lock", "build.rs"):
            candidate = package / name
            if candidate.is_file():
                paths.add(candidate.resolve(strict=True))
    freeze.need(paths and all(path.is_relative_to(ROOT) for path in paths),
                "verifier-repository-source-set")
    return sorted(paths)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bootstrap-dep-info", required=True)
    args = parser.parse_args()
    target = Path(args.target_dir).absolute()
    output = Path(args.output).absolute()
    bootstrap = freeze.regular(args.bootstrap_dep_info)
    freeze.need(not target.exists() and not output.exists(),
                "fresh-verifier-target-and-bundle")
    target.mkdir(mode=0o700)
    fixture.fsync_directory(target.parent)

    paths_before = source_set(bootstrap)
    snapshot_before = freeze.snapshot(paths_before)
    source_identity = freeze.sha(freeze.canonical(snapshot_before))
    rustc_vv = subprocess.run(
        [freeze.RUSTC, "-Vv"], check=True, capture_output=True,
        env={
            "PATH": f"{freeze.TOOLCHAIN}:/usr/bin:/bin",
            "LANG": "C.UTF-8", "TZ": "UTC",
        },
    ).stdout
    cargo_version = subprocess.run(
        [freeze.CARGO, "-V"], check=True, capture_output=True, text=True,
        env={
            "PATH": f"{freeze.TOOLCHAIN}:/usr/bin:/bin",
            "LANG": "C.UTF-8", "TZ": "UTC",
        },
    ).stdout.strip()
    command = {
        "schema": "kpb-offline-w1-verifier-build-command/v1",
        "cwd": str(RELATION),
        "argv": [
            "cargo", "build", "--locked", "--offline", "--release",
            "--features", "offline-w1-verifier", "--example",
            "verify_offline_w1_aggregate",
        ],
        "environment": {
            "CARGO_TARGET_DIR": str(target),
            "KPB_CARGO_VERSION": cargo_version,
            "KPB_RUSTC_VV_SHA256": freeze.sha(rustc_vv),
            "KPB_SOURCE_CLOSURE_SHA256": source_identity,
        },
        "self_hash_environment_name": "KPB_BUILD_COMMAND_SHA256",
    }
    command_raw = freeze.canonical(command)
    command_sha = freeze.sha(command_raw)
    environment = {
        "PATH": f"{freeze.TOOLCHAIN}:/usr/bin:/bin",
        "CARGO_HOME": "/home/luke/.cargo",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target),
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "KPB_CARGO_VERSION": cargo_version,
        "KPB_RUSTC_VV_SHA256": freeze.sha(rustc_vv),
        "KPB_SOURCE_CLOSURE_SHA256": source_identity,
        "KPB_BUILD_COMMAND_SHA256": command_sha,
    }
    with tempfile.TemporaryDirectory(
            prefix=".w1-verifier-freeze-", dir=output.parent) as temporary:
        staging = Path(temporary)
        time_path = staging / "BUILD-TIME.txt"
        argv = [
            "/usr/bin/time", "-v", "-o", str(time_path),
            str(freeze.CARGO), "build", "--locked", "--offline", "--release",
            "--features", "offline-w1-verifier", "--example",
            "verify_offline_w1_aggregate",
        ]
        result = subprocess.run(
            argv, cwd=RELATION, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        freeze.write(staging / "BUILD.stdout", result.stdout)
        freeze.write(staging / "BUILD.stderr", result.stderr)
        freeze.need(result.returncode == 0,
                    "locked-offline-verifier-build")
        binary = freeze.regular(
            target / "release/examples/verify_offline_w1_aggregate")
        dep_info = freeze.regular(
            target / "release/examples/verify_offline_w1_aggregate.d")
        paths_after = source_set(dep_info)
        snapshot_after = freeze.snapshot(paths_after)
        freeze.need(paths_after == paths_before
                    and snapshot_after == snapshot_before,
                    "verifier-source-changed-during-build")
        freeze.need(all(path.stat().st_mtime_ns <= binary.stat().st_mtime_ns
                        for path in paths_after),
                    "verifier-source-newer-than-binary")
        final = output
        freeze.copy(binary, staging / "verify_offline_w1_aggregate", 0o500)
        freeze.copy(dep_info, staging / "verify_offline_w1_aggregate.d", 0o400)
        source = {
            "schema": "kpb-offline-w1-verifier-source-closure/v1",
            "classification": fixture.RUST_RECEIPT_CLASSIFICATION,
            "derivation": (
                "cargo-link-dep-info-plus-local-package-manifests-lockfiles-and-build-scripts"
            ),
            "dep_info_sha256": freeze.sha(dep_info.read_bytes()),
            "member_count": len(snapshot_after),
            "members_identity_sha256": source_identity,
            "members": snapshot_after,
        }
        freeze.write(staging / "SOURCE-CLOSURE.json", source)
        freeze.write(staging / "BUILD-COMMAND.json", command_raw)

        def final_ref(name):
            current = freeze.reference(staging / name)
            current["path"] = str(final / name)
            return current

        receipt = {
            "schema": "kpb-offline-w1-verifier-build-receipt/v1",
            "classification": fixture.RUST_RECEIPT_CLASSIFICATION,
            "feature": "offline-w1-verifier",
            "build_profile": "release",
            "locked": True,
            "offline": True,
            "binary": final_ref("verify_offline_w1_aggregate"),
            "dep_info": final_ref("verify_offline_w1_aggregate.d"),
            "build_command": final_ref("BUILD-COMMAND.json"),
            "source_closure": {
                **final_ref("SOURCE-CLOSURE.json"),
                "members_identity_sha256": source_identity,
                "member_count": len(snapshot_after),
            },
            "toolchain": {
                "cargo_version": cargo_version,
                "rustc_vv": rustc_vv.decode(),
                "rustc_vv_sha256": freeze.sha(rustc_vv),
            },
            "compiled_bindings": {
                "rustc_vv_sha256": freeze.sha(rustc_vv),
                "cargo_version": cargo_version,
                "source_closure_sha256": source_identity,
                "build_command_sha256": command_sha,
            },
            "running_inode_hash_source": "/proc/self/exe",
            "offline_synthetic_provenance_enforced": False,
            "build_bundle_reverified_by_binary": False,
            "network_enabled": False,
            "proving_key_read": False,
            "proof_generated": False,
            "private_fixture_read": False,
            "authorization": False,
            "privacy_or_financial_acceptance": False,
        }
        freeze.write(staging / "BUILD-RECEIPT.json", receipt)
        freeze.write(staging / "BUILD-METADATA.json", {
            "schema": "kpb-offline-w1-verifier-build-metadata/v1",
            "build_stdout": final_ref("BUILD.stdout"),
            "build_stderr": final_ref("BUILD.stderr"),
            "build_time": final_ref("BUILD-TIME.txt"),
            "source_snapshot_equal_before_after_build": True,
            "all_source_mtimes_not_newer_than_binary": True,
            "proving_key_read": False,
            "fixture_or_trial_read": False,
        })
        fixture.fsync_directory(staging)
        fixture.rename_no_replace(staging, final)
    os.chmod(output / "BUILD-TIME.txt", 0o400)
    print(json.dumps({
        "status": "OFFLINE_W1_VERIFIER_BUILD_FROZEN",
        "output": str(output),
        "binary_sha256": receipt["binary"]["sha256"],
        "source_members_identity_sha256": source_identity,
        "source_member_count": len(snapshot_after),
        "build_command_sha256": command_sha,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
