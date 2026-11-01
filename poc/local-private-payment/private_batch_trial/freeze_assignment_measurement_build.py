#!/usr/bin/env python3
"""Freeze one test-only current-source assignment-measurement build.

This is a fixed, no-argument entrypoint.  It snapshots the four recursive
local Cargo packages used by the assignment preparer, performs one locked and
offline release build from that read-only snapshot, derives the exact local
dep-info members produced by that build, and delegates atomic source/binary/
receipt sealing to ``freeze_current_w1_source_build``'s test-only core.

The result is build evidence only.  It is not a production build authority,
privacy acceptance, proof authority, or permission to execute the binary.
No setup, proving-key read, synthesis, proof, network communication, or funds
operation is performed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import uuid

import freeze_current_w1_source_build as core


SCHEMA = "kpb-w1-assignment-measurement-build-freezer/v1"
RECEIPT_SCHEMA = "kpb-w1-assignment-measurement-build-receipt/v1"
CLASSIFICATION = "TEST_ONLY_ASSIGNMENT_MEASUREMENT_BUILD_NOT_AUTHORITY"

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
PRIVATE_OUTPUT_BASE = Path("/home/luke/projects/kpi-intensive-2026-10-22")
OUTPUT_PARENT = (
    PRIVATE_OUTPUT_BASE
    / "private-batch-w1-assignment-measurement-build-private-20261029-06"
)
OUTPUT_NAME = "assignment-measurement-build"
EVIDENCE_NAME = "assignment-measurement-build-contract"
RELATION_RELATIVE = "poc/local-private-payment/private-batch-relation"
PACKAGE_ROOTS = (RELATION_RELATIVE,)
EXPECTED_PACKAGE_ROOTS = (
    "poc/local-private-payment/native-authority/native-core",
    "poc/local-private-payment/native-authority/vendor/native-relation",
    "poc/local-private-payment/private-batch-relation",
    "poc/local-private-payment/private_batch_trial/auth_exit",
)
EXAMPLE_NAME = "prepare_frozen_w1_round1_assignment"
FEATURE_NAME = "offline-w1-preparer"

CARGO = Path("/home/luke/.cargo/bin/cargo")
PYTHON = Path("/usr/bin/python3")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
JOURNALCTL = Path("/usr/bin/journalctl")
PROBE_UNIT = "kpb-w1-assignment-freeze-netprobe-20261029-06"
BUILD_UNIT = "kpb-w1-assignment-freeze-build-20261029-06"

DENIED_BUILD_NETWORK_SYSCALLS = (
    "accept",
    "accept4",
    "bind",
    "connect",
    "getpeername",
    "getsockname",
    "getsockopt",
    "listen",
    "recvmmsg",
    "recvmmsg_time64",
    "recvmsg",
    "sendmmsg",
    "sendmsg",
    "setsockopt",
    "shutdown",
    "socketcall",
)

SYSTEMD_PROPERTIES = (
    "SystemCallFilter=~" + " ".join(DENIED_BUILD_NETWORK_SYSCALLS),
    "SystemCallErrorNumber=EPERM",
    "RestrictAddressFamilies=AF_UNIX",
    "NoNewPrivileges=yes",
    "LimitCORE=0",
    "MemoryMax=12G",
    "MemorySwapMax=0",
    "UMask=0077",
)
SHOW_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainStatus",
    "RestrictAddressFamilies",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "NoNewPrivileges",
    "LimitCORE",
    "MemoryMax",
    "MemorySwapMax",
    "UMask",
)
REQUIRED_DEPENDENCY_RELATIVES = {
    "poc/local-private-payment/private-batch-relation/examples/"
    "prepare_frozen_w1_round1_assignment.rs",
    "poc/local-private-payment/private-batch-relation/src/lib.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1.rs",
    "poc/local-private-payment/private-batch-relation/src/"
    "counterfactual_w1/offline_verifier.rs",
    "poc/local-private-payment/private-batch-relation/src/"
    "counterfactual_w1/offline_verifier/frozen_assignment.rs",
    "poc/local-private-payment/native-authority/native-core/src/lib.rs",
    "poc/local-private-payment/native-authority/vendor/native-relation/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/auth_exit/src/lib.rs",
}
FORBIDDEN_ASSIGNMENT_DEPENDENCY_RELATIVE = (
    "poc/local-private-payment/private-batch-relation/src/"
    "counterfactual_w1/offline_verifier/frozen_prover.rs"
)
FORBIDDEN_LOW_MEMORY_PREFIX = (
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/"
)

NETWORK_PROBE_SOURCE = """\
import errno
import socket
import subprocess

for family in (socket.AF_INET, socket.AF_INET6):
    try:
        socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EAFNOSUPPORT:
            raise SystemExit(2)
    else:
        raise SystemExit(3)

standalone = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
if left.send(b"x") != 1 or right.recv(1) != b"x":
    raise SystemExit(6)
subprocess.run(["/bin/true"], check=True)
try:
    standalone.connect("\\0kpb-assignment-build-network-probe")
except OSError as error:
    if error.errno != errno.EPERM:
        raise SystemExit(4)
else:
    raise SystemExit(5)
standalone.close()
left.close()
right.close()
"""


def _need(value: bool, category: str) -> None:
    core.need(value, category)


def _require_no_arguments(arguments: list[str]) -> None:
    _need(type(arguments) is list and not arguments, "arguments-not-accepted")


def _fixed_actions() -> dict:
    return {
        "source_snapshot": True,
        "build": True,
        "binary_execution": False,
        "setup": False,
        "pk_decode": False,
        "proving_key_read": False,
        "synthesis": False,
        "proof": False,
        "verification": False,
        "network_communication": False,
        "funds": False,
        "authorization": False,
    }


def _validate_fixed_host_paths() -> None:
    _need(os.geteuid() != 0, "root-execution-refused")
    _need(REPO_ROOT == REPO_ROOT.resolve(strict=True), "repo-root-canonical")
    _need(Path.cwd().resolve(strict=True) == REPO_ROOT, "cwd-must-be-repo-root")
    _need(
        PRIVATE_OUTPUT_BASE == PRIVATE_OUTPUT_BASE.resolve(strict=True)
        and not PRIVATE_OUTPUT_BASE.is_relative_to(REPO_ROOT),
        "private-output-base-canonical-disjoint",
    )
    core._directory(PRIVATE_OUTPUT_BASE)
    for tool in (CARGO, PYTHON, SYSTEMD_RUN, SYSTEMCTL, JOURNALCTL):
        _need(tool.is_absolute() and tool.exists(), "fixed-tool-missing")
        resolved = tool.resolve(strict=True)
        value = os.stat(resolved, follow_symlinks=False)
        _need(
            stat.S_ISREG(value.st_mode) and os.access(resolved, os.X_OK),
            "fixed-tool-not-executable",
        )


def _systemd_prefix(unit_name: str) -> list[str]:
    _need(
        unit_name in (PROBE_UNIT, BUILD_UNIT),
        "unexpected-transient-unit-name",
    )
    arguments = [
        str(SYSTEMD_RUN),
        "--user",
        "--quiet",
        "--no-block",
        "--remain-after-exit",
        f"--unit={unit_name}",
        "--service-type=exec",
        "--expand-environment=no",
    ]
    for value in SYSTEMD_PROPERTIES:
        arguments.extend(("--property", value))
    return arguments


def _network_probe_command() -> list[str]:
    return _systemd_prefix(PROBE_UNIT) + [
        str(PYTHON),
        "-I",
        "-c",
        NETWORK_PROBE_SOURCE,
    ]


def _cargo_environment(target_root: Path) -> tuple[str, ...]:
    target_root = Path(target_root).absolute()
    return (
        "HOME=/home/luke",
        "PATH=/home/luke/.cargo/bin:/usr/bin:/bin",
        "CARGO_HOME=/home/luke/.cargo",
        "RUSTUP_HOME=/home/luke/.rustup",
        "CARGO_NET_OFFLINE=true",
        f"CARGO_TARGET_DIR={target_root}",
        "CARGO_INCREMENTAL=0",
        "CARGO_TERM_COLOR=never",
        "RUSTC_WRAPPER=",
        "RUSTC_WORKSPACE_WRAPPER=",
        "RUSTFLAGS=",
        "CARGO_ENCODED_RUSTFLAGS=",
        "HTTP_PROXY=",
        "HTTPS_PROXY=",
        "ALL_PROXY=",
        "NO_PROXY=",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "TZ=UTC",
    )


def _cargo_build_command(snapshot_root: Path, target_root: Path) -> list[str]:
    snapshot_root = Path(snapshot_root).absolute()
    target_root = Path(target_root).absolute()
    workdir = snapshot_root / RELATION_RELATIVE
    arguments = _systemd_prefix(BUILD_UNIT)
    arguments.append(f"--working-directory={workdir}")
    for value in _cargo_environment(target_root):
        arguments.extend(("--setenv", value))
    arguments.extend(
        (
            str(CARGO),
            "build",
            "--release",
            "--locked",
            "--offline",
            "--no-default-features",
            "--features",
            FEATURE_NAME,
            "--example",
            EXAMPLE_NAME,
        )
    )
    return arguments


def _parse_show(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise core.Refused("systemd-show-utf8") from None
    values: dict[str, str] = {}
    for line in text.splitlines():
        _need("=" in line, "systemd-show-line")
        key, value = line.split("=", 1)
        _need(key in SHOW_PROPERTIES and key not in values, "systemd-show-key")
        values[key] = value
    _need(set(values) == set(SHOW_PROPERTIES), "systemd-show-exact-properties")
    return values


def _validate_active_unit_properties(values: dict[str, str]) -> dict:
    _need(values["LoadState"] == "loaded", "systemd-unit-not-loaded")
    _need(values["RestrictAddressFamilies"] == "AF_UNIX", "systemd-af-filter")
    _need(values["SystemCallErrorNumber"] == "1", "systemd-syscall-errno")
    _need(values["NoNewPrivileges"] == "yes", "systemd-no-new-privileges")
    _need(values["LimitCORE"] == "0", "systemd-core-limit")
    _need(values["MemoryMax"] == str(12 * 1024**3), "systemd-memory-max")
    _need(values["MemorySwapMax"] == "0", "systemd-swap-max")
    _need(values["UMask"] == "0077", "systemd-umask")
    syscall_filter = values["SystemCallFilter"]
    _need(syscall_filter.startswith("~"), "systemd-syscall-filter-form")
    denied = set(syscall_filter[1:].split())
    _need(
        denied == set(DENIED_BUILD_NETWORK_SYSCALLS),
        "systemd-network-syscall-filter",
    )
    _need(
        not {
            "socket",
            "socketpair",
            "send",
            "recv",
            "sendto",
            "recvfrom",
        }.intersection(denied),
          "systemd-local-spawn-ipc-must-remain")
    return {
        "restrict_address_families": values["RestrictAddressFamilies"],
        "denied_network_syscalls": sorted(denied),
        "system_call_error_number": int(values["SystemCallErrorNumber"]),
        "no_new_privileges": True,
        "limit_core_bytes": 0,
        "memory_max_bytes": int(values["MemoryMax"]),
        "memory_swap_max_bytes": int(values["MemorySwapMax"]),
        "umask_octal": values["UMask"],
    }


def _show_unit(unit_name: str) -> tuple[dict[str, str], bytes]:
    command = [str(SYSTEMCTL), "--user", "show", f"{unit_name}.service"]
    for name in SHOW_PROPERTIES:
        command.extend(("--property", name))
    command.append("--no-pager")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _need(result.returncode == 0 and not result.stderr, "systemd-show-failed")
    return _parse_show(result.stdout), result.stdout


def _unit_journal(unit_name: str) -> bytes:
    result = subprocess.run(
        [
            str(JOURNALCTL),
            "--user",
            "--unit",
            f"{unit_name}.service",
            "--no-pager",
            "--output=cat",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _need(result.returncode == 0, "systemd-journal-read")
    raw = result.stdout + result.stderr
    lowered = raw.lower()
    for forbidden in (
        b"proceeding without",
        b"does not support",
        b"failed to apply",
        b"unknown lvalue",
        b"invalid argument",
    ):
        _need(forbidden not in lowered, "systemd-restriction-warning")
    return raw


def _stop_unit(unit_name: str) -> None:
    result = subprocess.run(
        [str(SYSTEMCTL), "--user", "stop", f"{unit_name}.service"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _need(result.returncode == 0, "systemd-unit-stop")


def _run_transient_unit(unit_name: str, command: list[str]) -> dict:
    _need(command[: len(_systemd_prefix(unit_name))] == _systemd_prefix(unit_name),
          "systemd-command-prefix")
    start = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _need(start.returncode == 0, "systemd-unit-start")
    final_values = None
    active_evidence = None
    show_raw = b""
    journal_raw = b""
    try:
        while True:
            values, observed_raw = _show_unit(unit_name)
            if values["LoadState"] == "loaded":
                active_evidence = _validate_active_unit_properties(values)
                show_raw = observed_raw
                if values["SubState"] in ("exited", "failed", "dead"):
                    final_values = values
                    break
            time.sleep(0.05)
        journal_raw = _unit_journal(unit_name)
        _need(final_values is not None, "systemd-final-state-missing")
        _need(
            final_values["ActiveState"] == "active"
            and final_values["SubState"] == "exited"
            and final_values["Result"] == "success"
            and final_values["ExecMainStatus"] == "0",
            "systemd-command-failed",
        )
    finally:
        _stop_unit(unit_name)
    _need(active_evidence is not None, "systemd-active-properties-missing")
    return {
        "unit": f"{unit_name}.service",
        "command_sha256": core.sha256_bytes(core.canonical(command)),
        "properties": active_evidence,
        "show_sha256": core.sha256_bytes(show_raw),
        "show_bytes": len(show_raw),
        "journal_sha256": core.sha256_bytes(journal_raw),
        "journal_bytes": len(journal_raw),
        "result": "success",
        "exec_main_status": 0,
        "unit_stopped_after_capture": True,
    }


def _validate_manifest_packages(manifest: dict) -> None:
    _need(
        tuple(manifest.get("package_roots", ())) == EXPECTED_PACKAGE_ROOTS,
        "exact-four-local-packages",
    )


def _derive_dep_info_members(
    raw: bytes,
    *,
    snapshot_root: Path,
    target_root: Path,
    original_source_root: Path,
    snapshot_refs: list[dict],
    expected_target: Path,
) -> tuple[tuple[str, ...], dict]:
    snapshot_root = Path(snapshot_root).absolute()
    target_root = Path(target_root).absolute()
    original_source_root = Path(original_source_root).absolute()
    expected_target = Path(expected_target).absolute()
    target, dependencies = core._parse_dep_info(raw)
    _need(Path(target).is_absolute(), "dep-info-target-absolute")
    _need(Path(target) == expected_target, "dep-info-target-binding")
    _need(expected_target.is_relative_to(target_root), "dep-info-target-root")
    manifested = {item["relative_path"]: item for item in snapshot_refs}
    relatives = []
    canonical_absolutes = []
    mappings = []
    first_indexes: dict[str, int] = {}
    for index, raw_path in enumerate(dependencies):
        lexical = Path(raw_path)
        _need(lexical.is_absolute(), "dep-info-path-absolute")
        if lexical.is_relative_to(snapshot_root):
            lexical_relative = lexical.relative_to(snapshot_root).as_posix()
            _need(
                lexical_relative != FORBIDDEN_ASSIGNMENT_DEPENDENCY_RELATIVE,
                "dep-info-offline-w1-prover-source",
            )
            _need(
                not lexical_relative.startswith(FORBIDDEN_LOW_MEMORY_PREFIX),
                "dep-info-low-memory-prover-source",
            )
        try:
            path = lexical.resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            raise core.Refused("dep-info-path-resolution") from None
        _need(path.is_relative_to(snapshot_root), "dep-info-not-snapshot")
        _need(not path.is_relative_to(original_source_root), "dep-info-live-source")
        relative = path.relative_to(snapshot_root).as_posix()
        _need(
            relative != FORBIDDEN_ASSIGNMENT_DEPENDENCY_RELATIVE,
            "dep-info-offline-w1-prover-source",
        )
        _need(
            not relative.startswith(FORBIDDEN_LOW_MEMORY_PREFIX),
            "dep-info-low-memory-prover-source",
        )
        _need(relative in manifested, "dep-info-unmanifested-source")
        identity = core._stable_file_identity(path, 0o400)
        expected = manifested[relative]
        _need(
            identity["device"] == expected["device"]
            and identity["inode"] == expected["inode"]
            and identity["bytes"] == expected["bytes"]
            and identity["sha256"] == expected["sha256"],
            "dep-info-resolved-member-identity",
        )
        first_index = first_indexes.get(relative)
        duplicate = first_index is not None
        if not duplicate:
            first_indexes[relative] = index
            relatives.append(relative)
            canonical_absolutes.append(str(path))
        mappings.append(
            {
                "raw_index": index,
                "raw_absolute": raw_path,
                "canonical_absolute": str(path),
                "canonical_relative": relative,
                "lexical_alias": raw_path != str(path),
                "duplicate_canonical_member": duplicate,
                "duplicate_of_raw_index": first_index,
                "device": identity["device"],
                "inode": identity["inode"],
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
            }
        )
    _need(len(relatives) == len(set(relatives)), "dep-info-canonical-dedup")
    _need(
        REQUIRED_DEPENDENCY_RELATIVES.issubset(relatives),
        "dep-info-required-assignment-source",
    )
    for package_root in EXPECTED_PACKAGE_ROOTS:
        prefix = package_root + "/"
        _need(
            any(relative.startswith(prefix) for relative in relatives),
            "dep-info-all-four-packages",
        )
    _need(
        FORBIDDEN_ASSIGNMENT_DEPENDENCY_RELATIVE not in relatives
        and not any(
            relative.startswith(FORBIDDEN_LOW_MEMORY_PREFIX)
            for relative in relatives
        ),
        "dep-info-assignment-only-closure",
    )
    return tuple(relatives), {
        "raw_target": target,
        "raw_dependency_count": len(dependencies),
        "raw_dependencies": dependencies,
        "raw_dep_info_sha256": core.sha256_bytes(raw),
        "canonical_unique_dependency_count": len(relatives),
        "canonical_dependency_absolutes": canonical_absolutes,
        "lexical_alias_count": sum(item["lexical_alias"] for item in mappings),
        "duplicate_canonical_member_count": sum(
            item["duplicate_canonical_member"] for item in mappings
        ),
        "first_occurrence_order_preserved": True,
        "mappings": mappings,
    }


def _stable_cargo_hardlinked_binary(path: Path) -> tuple[bytes, dict]:
    path = Path(path).absolute()
    before_path = os.lstat(path)
    _need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == os.getuid()
        and before_path.st_nlink == 2
        and stat.S_IMODE(before_path.st_mode) == 0o700
        and before_path.st_size > 0,
        "cargo-binary-hardlink-shape",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        _need(
            core._stat_identity(opened) == core._stat_identity(before_path),
            "cargo-binary-open-race",
        )
        chunks = []
        while True:
            block = os.read(descriptor, core.CHUNK)
            if not block:
                break
            chunks.append(block)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        _need(
            core._stat_identity(opened)
            == core._stat_identity(after)
            == core._stat_identity(after_path)
            and len(raw) == after.st_size,
            "cargo-binary-read-race",
        )
    finally:
        os.close(descriptor)
    return raw, {
        "path": str(path),
        "device": after.st_dev,
        "inode": after.st_ino,
        "bytes": after.st_size,
        "sha256": core.sha256_bytes(raw),
        "mode_octal": f"{stat.S_IMODE(after.st_mode):04o}",
        "link_count": after.st_nlink,
        "owner_uid": after.st_uid,
    }


def _normalize_dep_info(
    raw: bytes,
    *,
    original_target: Path,
    detached_target: Path,
    target_root: Path,
    canonical_dependency_absolutes: list[str],
) -> tuple[bytes, dict]:
    original_target = Path(original_target).absolute()
    detached_target = Path(detached_target).absolute()
    target_root = Path(target_root).absolute()
    raw_target, raw_dependencies = core._parse_dep_info(raw)
    _need(Path(raw_target) == original_target, "cargo-dep-info-original-target")
    _need(
        detached_target != original_target
        and detached_target.is_relative_to(target_root)
        and original_target.is_relative_to(target_root)
        and canonical_dependency_absolutes
        and all(Path(value).is_absolute() for value in canonical_dependency_absolutes),
        "normalized-dep-info-target-shape",
    )
    normalized = (
        f"{detached_target}: {' '.join(canonical_dependency_absolutes)}\n"
    ).encode("utf-8")
    observed_target, observed_dependencies = core._parse_dep_info(normalized)
    _need(
        observed_target == str(detached_target)
        and observed_dependencies == canonical_dependency_absolutes
        and len(observed_dependencies) == len(set(observed_dependencies)),
        "normalized-dep-info-shape",
    )
    return normalized, {
        "derivation": (
            "target-rewrite-plus-strict-canonicalization-and-first-occurrence-"
            "dedup-after-sealed-inode-binding"
        ),
        "original_target": raw_target,
        "detached_target": str(detached_target),
        "raw_dependency_count": len(raw_dependencies),
        "normalized_dependency_count": len(observed_dependencies),
        "canonical_duplicate_count": len(raw_dependencies) - len(observed_dependencies),
        "canonical_first_occurrence_order_preserved": True,
        "raw_dep_info_sha256": core.sha256_bytes(raw),
        "normalized_dep_info_sha256": core.sha256_bytes(normalized),
    }


def _file_reference(path: Path, mode: int) -> dict:
    raw, identity = core._stable_file_bytes(path, mode)
    return {
        "path": str(path),
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
        "mode_octal": identity["mode_octal"],
        "link_count": 1,
        "raw": raw,
    }


def _capture_python_source(path: Path) -> tuple[bytes, dict]:
    path = Path(path).resolve(strict=True)
    raw, identity = core._stable_file_bytes(path)
    value = os.lstat(path)
    _need(
        stat.S_ISREG(value.st_mode)
        and not stat.S_ISLNK(value.st_mode)
        and value.st_nlink == 1
        and value.st_uid == os.getuid()
        and value.st_dev == identity["device"]
        and value.st_ino == identity["inode"]
        and value.st_size == identity["bytes"]
        and f"{stat.S_IMODE(value.st_mode):04o}" == identity["mode_octal"],
        "python-source-stat-race",
    )
    return raw, {
        "path": str(path),
        "device": value.st_dev,
        "inode": value.st_ino,
        "bytes": value.st_size,
        "sha256": identity["sha256"],
        "mode_octal": identity["mode_octal"],
        "link_count": value.st_nlink,
        "owner_uid": value.st_uid,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _require_python_source_unchanged(
    path: Path, initial_raw: bytes, initial_reference: dict
) -> dict:
    observed_raw, observed_reference = _capture_python_source(path)
    _need(
        observed_raw == initial_raw and observed_reference == initial_reference,
        "python-source-changed-during-build",
    )
    return observed_reference


def _without_raw(reference: dict) -> dict:
    return {key: value for key, value in reference.items() if key != "raw"}


def _receipt_identity(value: dict) -> dict:
    result = dict(value)
    _need("receipt_identity_sha256" not in result, "outer-receipt-preidentified")
    result["receipt_identity_sha256"] = core.sha256_bytes(core.canonical(result))
    return result


def _validate_outer_receipt(value: dict) -> None:
    _need(value["schema"] == RECEIPT_SCHEMA, "outer-receipt-schema")
    _need(value["classification"] == CLASSIFICATION, "outer-classification")
    _need(value["authorization"] is False, "outer-authorization")
    _need(value["privacy_acceptance"] is False, "outer-privacy-acceptance")
    _need(value["financial_acceptance"] is False, "outer-financial-acceptance")
    _need(value["actions"] == _fixed_actions(), "outer-actions")
    unsigned = dict(value)
    claimed = unsigned.pop("receipt_identity_sha256")
    _need(claimed == core.sha256_bytes(core.canonical(unsigned)),
          "outer-receipt-identity")


def _publish_outer_evidence(
    parent: Path, source_raw: bytes, cargo_dep_info_raw: bytes, receipt: dict
) -> dict:
    parent = Path(parent).absolute()
    core._directory(parent, 0o700)
    final = parent / EVIDENCE_NAME
    _need(not os.path.lexists(final), "outer-evidence-create-new")
    staging = parent / f".{EVIDENCE_NAME}.staging-{uuid.uuid4()}"
    os.mkdir(staging, 0o700)
    try:
        source_ref = core._write_new(
            staging / "FREEZER-SOURCE.py", source_raw, 0o400
        )
        cargo_dep_info_ref = core._write_new(
            staging / "CARGO-ORIGINAL-DEP-INFO.d", cargo_dep_info_raw, 0o400
        )
        expected_cargo_dep_info = receipt["dep_info"]["cargo_original"][
            "frozen_original"
        ]
        _need(
            expected_cargo_dep_info
            == {
                "name": "CARGO-ORIGINAL-DEP-INFO.d",
                "bytes": cargo_dep_info_ref["bytes"],
                "sha256": cargo_dep_info_ref["sha256"],
                "mode_octal": "0400",
                "link_count": 1,
            },
            "outer-original-dep-info-binding",
        )
        _validate_outer_receipt(receipt)
        receipt_ref = core._write_new(
            staging / "MEASUREMENT-BUILD-RECEIPT.json",
            core.canonical(receipt),
            0o400,
        )
        _need(
            set(os.listdir(staging))
            == {
                "FREEZER-SOURCE.py",
                "CARGO-ORIGINAL-DEP-INFO.d",
                "MEASUREMENT-BUILD-RECEIPT.json",
            },
            "outer-evidence-exact-files",
        )
        core._fsync_directory(staging)
        os.chmod(staging, 0o500, follow_symlinks=False)
        core._directory(staging, 0o500)
        descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            core._rename_no_replace_at(descriptor, staging.name, final.name)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        # Retain any failed create-new staging evidence for diagnosis.
        raise
    core._directory(final, 0o500)
    final_source = core._stable_file_identity(final / "FREEZER-SOURCE.py", 0o400)
    final_receipt = core._stable_file_identity(
        final / "MEASUREMENT-BUILD-RECEIPT.json", 0o400
    )
    final_cargo_dep_info = core._stable_file_identity(
        final / "CARGO-ORIGINAL-DEP-INFO.d", 0o400
    )
    _need(
        final_source["sha256"] == source_ref["sha256"]
        and final_receipt["sha256"] == receipt_ref["sha256"]
        and final_cargo_dep_info["sha256"] == cargo_dep_info_ref["sha256"],
        "outer-evidence-final-content",
    )
    return {
        "root": str(final),
        "freezer_source_sha256": source_ref["sha256"],
        "cargo_original_dep_info_sha256": cargo_dep_info_ref["sha256"],
        "receipt_sha256": receipt_ref["sha256"],
    }


def _create_private_parent() -> None:
    _need(not os.path.lexists(OUTPUT_PARENT), "fixed-output-parent-create-new")
    os.mkdir(OUTPUT_PARENT, 0o700)
    core._directory(OUTPUT_PARENT, 0o700)
    core._fsync_directory(PRIVATE_OUTPUT_BASE)


def run_freeze() -> dict:
    _validate_fixed_host_paths()
    script_path = Path(__file__).resolve(strict=True)
    core_path = Path(core.__file__).resolve(strict=True)
    freezer_raw, freezer_initial = _capture_python_source(script_path)
    core_raw, core_initial = _capture_python_source(core_path)
    _create_private_parent()

    probe = _run_transient_unit(PROBE_UNIT, _network_probe_command())
    probe["af_inet_and_af_inet6_socket_calls_denied_with_eafnosupport"] = True
    probe["af_unix_socket_and_socketpair_available_for_process_spawn"] = True
    probe["local_af_unix_ipc_observed"] = True
    probe["af_unix_seqpacket_send_and_recv_observed"] = True
    probe["linux_sendto_and_recvfrom_aliases_required_for_send_and_recv"] = True
    probe["fixed_subprocess_spawn_succeeded"] = True
    probe["af_unix_connect_attempt_denied_with_eperm"] = True
    probe["network_communication_performed"] = False

    session = core._test_only_begin_candidate(
        REPO_ROOT, PACKAGE_ROOTS, OUTPUT_PARENT, OUTPUT_NAME
    )
    _validate_manifest_packages(session.manifest)
    build_command = _cargo_build_command(session.snapshot_root, session.target_root)
    build = _run_transient_unit(BUILD_UNIT, build_command)

    cargo_binary = (
        session.target_root / "release" / "examples" / EXAMPLE_NAME
    )
    cargo_dep_info = cargo_binary.with_suffix(".d")
    cargo_binary_raw, cargo_binary_reference = _stable_cargo_hardlinked_binary(
        cargo_binary
    )
    dep_raw, cargo_dep_info_identity = core._stable_file_bytes(
        cargo_dep_info, 0o600
    )
    dependency_relatives, dep_derivation = _derive_dep_info_members(
        dep_raw,
        snapshot_root=session.snapshot_root,
        target_root=session.target_root,
        original_source_root=session.source_root,
        snapshot_refs=session.snapshot_refs,
        expected_target=cargo_binary,
    )
    admission = session.target_root / "assignment-freeze-admission"
    os.mkdir(admission, 0o700)
    detached_binary = admission / "assignment-measurement-binary"
    detached_binary_reference = core._write_new(
        detached_binary, cargo_binary_raw, 0o500
    )
    detached_binary_reference["link_count"] = 1
    normalized_dep_raw, dep_normalization = _normalize_dep_info(
        dep_raw,
        original_target=cargo_binary,
        detached_target=detached_binary,
        target_root=session.target_root,
        canonical_dependency_absolutes=dep_derivation[
            "canonical_dependency_absolutes"
        ],
    )
    normalized_dep_info = admission / "assignment-measurement-binary.d"
    normalized_dep_info_reference = core._write_new(
        normalized_dep_info, normalized_dep_raw, 0o400
    )
    normalized_dep_info_reference["link_count"] = 1
    _need(
        detached_binary_reference["sha256"] == cargo_binary_reference["sha256"]
        and detached_binary_reference["bytes"] == cargo_binary_reference["bytes"]
        and detached_binary_reference["mode_octal"] == "0500",
        "detached-binary-byte-identity",
    )
    live_after_build = core.derive_recursive_direct_path_package_manifest(
        REPO_ROOT, PACKAGE_ROOTS
    )
    _need(live_after_build == session.manifest, "live-source-changed-during-build")
    frozen = core._test_only_finalize_candidate(
        session,
        binary=detached_binary,
        dep_info=normalized_dep_info,
        expected_target=detached_binary,
        expected_dependency_relatives=dependency_relatives,
    )
    _need(frozen["production_build"] is False, "core-production-build-claim")
    _need(frozen["authorization"] is False, "core-authorization-claim")
    cargo_binary_after_raw, cargo_binary_after_reference = (
        _stable_cargo_hardlinked_binary(cargo_binary)
    )
    dep_after_raw, dep_after_identity = core._stable_file_bytes(
        cargo_dep_info, 0o600
    )
    _need(
        cargo_binary_after_raw == cargo_binary_raw
        and cargo_binary_after_reference == cargo_binary_reference,
        "cargo-binary-changed-across-freeze",
    )
    _need(
        dep_after_raw == dep_raw
        and dep_after_identity == cargo_dep_info_identity,
        "cargo-dep-info-changed-across-freeze",
    )
    live_after_freeze = core.derive_recursive_direct_path_package_manifest(
        REPO_ROOT, PACKAGE_ROOTS
    )
    _need(live_after_freeze == session.manifest, "live-source-changed-during-freeze")

    bundle = Path(frozen["root"])
    inner_receipt = _file_reference(bundle / "BUILD-RECEIPT.json", 0o400)
    source_manifest = _file_reference(bundle / "SOURCE-MANIFEST.json", 0o400)
    frozen_core_source = _file_reference(bundle / "FREEZER-SOURCE.py", 0o400)
    frozen_binary = _file_reference(
        bundle / "artifacts" / "candidate-binary", 0o500
    )
    frozen_dep_info = _file_reference(
        bundle / "artifacts" / "candidate-binary.d", 0o400
    )
    _need(
        frozen_binary["sha256"] == cargo_binary_reference["sha256"]
        and frozen_binary["bytes"] == cargo_binary_reference["bytes"]
        and frozen_binary["link_count"] == 1,
        "frozen-binary-not-detached-cargo-binary",
    )
    try:
        inner_value = json.loads(inner_receipt["raw"])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise core.Refused("inner-receipt-json") from None
    _need(
        inner_value.get("classification")
        == "TEST_ONLY_FILESYSTEM_CONTRACT_NOT_A_BUILD_AUTHORITY"
        and inner_value.get("authorization") is False
        and inner_value.get("proof") is False
        and inner_value.get("network") is False,
        "inner-receipt-nonauthority",
    )

    freezer_after = _require_python_source_unchanged(
        script_path, freezer_raw, freezer_initial
    )
    core_after = _require_python_source_unchanged(
        core_path, core_raw, core_initial
    )
    _need(
        frozen_core_source["bytes"] == len(core_raw)
        and frozen_core_source["sha256"] == core.sha256_bytes(core_raw),
        "frozen-core-source-not-executed-core-source",
    )
    receipt = _receipt_identity(
        {
            "schema": RECEIPT_SCHEMA,
            "classification": CLASSIFICATION,
            "fixed_no_argument_entrypoint": True,
            "repository_root": str(REPO_ROOT),
            "private_output_parent": str(OUTPUT_PARENT),
            "source_snapshot": {
                "root": str(bundle / "sources"),
                "package_roots": list(EXPECTED_PACKAGE_ROOTS),
                "package_count": 4,
                "member_count": frozen["source_member_count"],
                "members_identity_sha256": frozen[
                    "source_members_identity_sha256"
                ],
                "manifest": _without_raw(source_manifest),
                "files_mode_0400": True,
                "directories_mode_0500": True,
                "live_manifest_equal_after_build": True,
                "live_manifest_equal_after_atomic_freeze": True,
                "source_identity_predeclared": False,
            },
            "build": {
                "actual_subprocess_executed": True,
                "command": build_command,
                "command_sha256": core.sha256_bytes(core.canonical(build_command)),
                "cwd": str(session.snapshot_root / RELATION_RELATIVE),
                "profile": "release",
                "locked": True,
                "offline": True,
                "default_features": False,
                "features": [FEATURE_NAME],
                "example": EXAMPLE_NAME,
                "target_outside_snapshot": True,
                "unit": build,
                "binary_was_not_executed": True,
                "cargo_original_binary": cargo_binary_reference,
                "cargo_original_binary_was_hardlink": True,
                "cargo_original_binary_unchanged_across_freeze": True,
                "detached_create_new_binary": detached_binary_reference,
                "detached_binary_byte_identical": True,
            },
            "network_boundary": {
                "denied_network_syscalls": list(DENIED_BUILD_NETWORK_SYSCALLS),
                "system_call_error": "EPERM",
                "restrict_address_families": "AF_UNIX",
                "socket_and_socketpair_allowed_for_local_process_spawn": True,
                "send_recv_sendto_recvfrom_allowed_for_local_spawn_status_ipc": True,
                "af_unix_connect_bind_listen_accept_denied": True,
                "ip_address_families_available": False,
                "local_af_unix_ipc_permitted": True,
                "local_af_unix_ipc_observed": True,
                "preexisting_af_unix_datagram_sendto_not_excluded": True,
                "strict_no_socket_runtime_boundary_is_not_this_build_boundary": True,
                "probe": probe,
                "network_communication_performed": False,
            },
            "dep_info": {
                "derivation": (
                    "raw-cargo-dep-info-bound-then-sealed-inode-canonicalized-"
                    "first-occurrence-dedup-for-test-only-core"
                ),
                "dependency_relatives": list(dependency_relatives),
                "dependency_count": len(dependency_relatives),
                "raw_cargo_derivation": dep_derivation,
                "normalization": dep_normalization,
                "absolute_snapshot_paths_are_prepublication_staging_paths": True,
                "canonical_relative_members_remain_bundle_locatable": True,
                "cargo_original": {
                    "path": str(cargo_dep_info),
                    "bytes": cargo_dep_info_identity["bytes"],
                    "sha256": cargo_dep_info_identity["sha256"],
                    "mode_octal": cargo_dep_info_identity["mode_octal"],
                    "link_count": 1,
                    "unchanged_across_freeze": True,
                    "frozen_original": {
                        "name": "CARGO-ORIGINAL-DEP-INFO.d",
                        "bytes": len(dep_raw),
                        "sha256": core.sha256_bytes(dep_raw),
                        "mode_octal": "0400",
                        "link_count": 1,
                    },
                },
                "normalized_core_input": {
                    "path": str(normalized_dep_info),
                    "bytes": normalized_dep_info_reference["bytes"],
                    "sha256": normalized_dep_info_reference["sha256"],
                    "mode_octal": normalized_dep_info_reference["mode_octal"],
                    "link_count": 1,
                },
                "all_members_under_sealed_snapshot": True,
                "all_four_local_packages_represented": True,
                "required_assignment_members_present": True,
                "offline_w1_prover_source_absent_from_assignment_dep_info": True,
                "low_memory_w1_prover_source_absent_from_assignment_dep_info": True,
                "predeclared_production_authority": False,
                "frozen": _without_raw(frozen_dep_info),
            },
            "closure_scope": {
                "assignment_only_closure_frozen": True,
                "combined_assignment_plus_prover_closure_frozen": False,
                "combined_closure_status": "STOP_NOT_FROZEN_BY_THIS_ENTRYPOINT",
            },
            "atomic_core_bundle": {
                "root": str(bundle),
                "result": frozen,
                "receipt": _without_raw(inner_receipt),
                "binary": _without_raw(frozen_binary),
                "source_binary_receipt_atomically_published": True,
            },
            "freezer_source": {
                "name": "FREEZER-SOURCE.py",
                "bytes": len(freezer_raw),
                "sha256": core.sha256_bytes(freezer_raw),
                "startup_reference": freezer_initial,
                "end_reference": freezer_after,
                "unchanged_across_build": True,
            },
            "executed_core_source": {
                "module": "freeze_current_w1_source_build",
                "startup_reference": core_initial,
                "end_reference": core_after,
                "unchanged_across_build": True,
                "frozen_inner_copy": _without_raw(frozen_core_source),
                "frozen_inner_copy_matches_executed_source": True,
            },
            "limitations": {
                "production_cargo_graph_authority": False,
                "registry_dependency_source_closure_bound": False,
                "rust_toolchain_binary_closure_bound": False,
                "build_filesystem_sandbox_present": False,
                "external_build_script_ambient_reads_sandboxed": False,
                "unsealed_original_target_is_authority": False,
                "cryptographic_correctness_proved": False,
                "privacy_proved": False,
            },
            "actions": _fixed_actions(),
            "setup": False,
            "pk_decode": False,
            "proving_key_read": False,
            "synthesis": False,
            "proof": False,
            "network_communication": False,
            "funds": False,
            "production_build_authority": False,
            "privacy_acceptance": False,
            "financial_acceptance": False,
            "authorization": False,
        }
    )
    evidence = _publish_outer_evidence(
        OUTPUT_PARENT, freezer_raw, dep_raw, receipt
    )
    return {
        "status": "TEST_ONLY_ASSIGNMENT_MEASUREMENT_BUILD_FROZEN",
        "classification": CLASSIFICATION,
        "output_parent": str(OUTPUT_PARENT),
        "bundle": str(bundle),
        "evidence": evidence,
        "binary_sha256": frozen_binary["sha256"],
        "source_members_identity_sha256": frozen[
            "source_members_identity_sha256"
        ],
        "source_member_count": frozen["source_member_count"],
        "dependency_count": len(dependency_relatives),
        "raw_cargo_dependency_count": dep_derivation["raw_dependency_count"],
        "canonical_duplicate_count": dep_derivation[
            "duplicate_canonical_member_count"
        ],
        "executed_core_source_sha256": core_initial["sha256"],
        "proof": False,
        "network_communication": False,
        "authorization": False,
    }


def main(arguments: list[str] | None = None) -> int:
    if arguments is None:
        arguments = sys.argv[1:]
    try:
        _require_no_arguments(arguments)
        result = run_freeze()
    except (core.Refused, FileExistsError, OSError) as error:
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "classification": CLASSIFICATION,
                    "reason": str(error),
                    "authorization": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
