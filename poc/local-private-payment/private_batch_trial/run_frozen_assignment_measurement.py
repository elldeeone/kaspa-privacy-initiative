#!/usr/bin/env python3
"""Run one fixed assignment-only W1 measurement under a strict host boundary.

This entrypoint is deliberately no-argument and one-shot.  It validates one
sealed assignment-only build, launches that exact binary with every network
syscall denied, validates the private assignment receipt, and seals a second
receipt binding the build and launch evidence.  It never opens a proving key,
generates a proof, performs setup, accesses funds, or grants authority.

The fixed artifact hashes remain fail-closed until the reviewed selected build
has completed and this source is patched to those exact immutable values.
Running this module's unit tests does not run the assignment binary.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import time
import uuid


SCHEMA = "kpb-frozen-w1-assignment-launch-supervisor/v2"
RECEIPT_SCHEMA = "kpb-frozen-w1-assignment-launch-receipt/v2"
CLASSIFICATION = (
    "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_ASSIGNMENT_"
    "PREPARATION_ONLY_NOT_AUTHORITY"
)

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
LOCAL_ROOT = REPO_ROOT / ".local"
BUILD_PARENT = (
    Path("/home/luke/projects/kpi-intensive-2026-10-22")
    / "private-batch-w1-assignment-measurement-build-private-20261029-06"
)
BUILD_BUNDLE = BUILD_PARENT / "assignment-measurement-build"
BUILD_EVIDENCE = BUILD_PARENT / "assignment-measurement-build-contract"
BUILD_BINARY = BUILD_BUNDLE / "artifacts" / "candidate-binary"
BUILD_DEP_INFO = BUILD_BUNDLE / "artifacts" / "candidate-binary.d"
BUILD_MANIFEST = BUILD_BUNDLE / "SOURCE-MANIFEST.json"
BUILD_RECEIPT = BUILD_BUNDLE / "BUILD-RECEIPT.json"
BUILD_CORE_SOURCE = BUILD_BUNDLE / "FREEZER-SOURCE.py"
BUILD_OUTER_RECEIPT = BUILD_EVIDENCE / "MEASUREMENT-BUILD-RECEIPT.json"
BUILD_FREEZER_SOURCE = BUILD_EVIDENCE / "FREEZER-SOURCE.py"
BUILD_ORIGINAL_DEP_INFO = BUILD_EVIDENCE / "CARGO-ORIGINAL-DEP-INFO.d"

RUN_ROOT = LOCAL_ROOT / "private-batch-w1-assignment-run-private-20261029-02"
ASSIGNMENT_RECEIPT = RUN_ROOT / "ASSIGNMENT-RECEIPT.json"
SUPERVISOR_SOURCE = RUN_ROOT / "SUPERVISOR-SOURCE.py"
LAUNCH_RECEIPT = RUN_ROOT / "LAUNCH-RECEIPT.json"

PYTHON = Path("/usr/bin/python3")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
JOURNALCTL = Path("/usr/bin/journalctl")
PROBE_UNIT = "kpb-w1-assignment-runtime-netprobe-20261029-02"
RUN_UNIT = "kpb-w1-assignment-runtime-20261029-02"

# Exact identities from the independently reviewed, create-new -06 bundle.
EXPECTED_BUILD_FREEZER_SOURCE_SHA256 = (
    "479260214f525a354608e47d009221025d918306f600ea830ddc7811f0a89a76"
)
EXPECTED_BUILD_CORE_SOURCE_SHA256 = (
    "cbf850cb6052c12d727a9dcaa320b7b22628c008549c448151363c41a7392f1e"
)
EXPECTED_MANIFEST_SHA256 = (
    "5429c10390c29283a8bde790e903386ff8294e04fdda965a2abf4e08de206cc9"
)
EXPECTED_INNER_RECEIPT_SHA256 = (
    "0305e2ccd1ff731c51b5645f2aa42311ff7ce587f103277a92a0acd3995f3f16"
)
EXPECTED_DEP_INFO_SHA256 = (
    "369b4abb54dca11745074b8c1beef285a20f453d14ad89622eea3ee53bc36e1e"
)
EXPECTED_ORIGINAL_DEP_INFO_SHA256 = (
    "23fb3f789e68819a40d74cbfb24c5cba9dcf2f3050103c2d3b6b795ade65c7e9"
)
EXPECTED_BINARY_SHA256 = (
    "1f826be966e7d9274c7c5401e67c7c3f720959b2bca846d0a345a398a6949cdb"
)
EXPECTED_BINARY_BYTES = 3_756_792
EXPECTED_BINARY_DEVICE = 64_512
EXPECTED_BINARY_INODE = 118_112_418
EXPECTED_BINARY_OWNER_UID = 1_000
EXPECTED_OUTER_RECEIPT_SHA256 = (
    "5a09479f165aca2f867406cb0514cb412444f4099a6e133cfcc18b58d9916940"
)
EXPECTED_SOURCE_MEMBER_COUNT = 93
EXPECTED_RAW_DEPENDENCY_COUNT = 47
EXPECTED_CANONICAL_DEPENDENCY_COUNT = 43
EXPECTED_CANONICAL_DUPLICATE_COUNT = 4
EXPECTED_FROZEN_ASSIGNMENT_SOURCE_SHA256 = (
    "2dbbadfefd6eee4c0ce549a9ba23c962dfccfb1612951bea13d2659ec3f4323f"
)
EXPECTED_FROZEN_PROVER_SOURCE_SHA256 = (
    "4b54f8de4f9f02bffae60773a0d7c4e68cbc2446055e714020a826ccd059639c"
)
EXPECTED_IDENTITY_BOUND_HELPER_SHA256 = (
    "f2f5c94e59efc4fd60a7b34372f2215b508c9d4ac7649f04b7d738a0d9affbda"
)
EXPECTED_RUN_COMMAND_SHA256 = (
    "989d16dd15f20996607c91933f282d30a2e32d6b56b521e11be6e6e2e2aeeb0e"
)

EXPECTED_PACKAGE_ROOTS = (
    "poc/local-private-payment/native-authority/native-core",
    "poc/local-private-payment/native-authority/vendor/native-relation",
    "poc/local-private-payment/private-batch-relation",
    "poc/local-private-payment/private_batch_trial/auth_exit",
)
FORBIDDEN_PROVER_SOURCE = (
    "poc/local-private-payment/private-batch-relation/src/"
    "counterfactual_w1/offline_verifier/frozen_prover.rs"
)
FORBIDDEN_LOW_MEMORY_PREFIX = (
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/"
)
EXPECTED_BUILD_DENIED_NETWORK_SYSCALLS = {
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
}

STRICT_DENIED_NETWORK_SYSCALLS = {
    "accept",
    "accept4",
    "bind",
    "connect",
    "getpeername",
    "getsockname",
    "getsockopt",
    "listen",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmmsg_time64",
    "recvmsg",
    "send",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setsockopt",
    "shutdown",
    "socket",
    "socketcall",
    "socketpair",
}
UNSET_ENVIRONMENT = (
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_PROFILE",
    "LD_SHOW_AUXV",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCPATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "RUST_LOG",
    "RUST_LIB_BACKTRACE",
)
EXPECTED_MANAGER_ENVIRONMENT = (
    "CLAUDE_CODE_CERT_STORE=system",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    "GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1",
    "HOME=/home/luke",
    "LANG=en_US.UTF-8",
    "LOGNAME=luke",
    "NODE_OPTIONS=--use-openssl-ca",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
    "/usr/games:/usr/local/games:/snap/bin:/snap/bin",
    "QT_ACCESSIBILITY=1",
    "SHELL=/usr/bin/zsh",
    "SSH_AUTH_SOCK=/run/user/1000/openssh_agent",
    "USER=luke",
    "XDG_DATA_DIRS=/usr/local/share/:/usr/share/:/var/lib/snapd/desktop",
    "XDG_RUNTIME_DIR=/run/user/1000",
)
MANAGER_ENVIRONMENT_UNSETS = (
    "CLAUDE_CODE_CERT_STORE",
    "DBUS_SESSION_BUS_ADDRESS",
    "GPG_AGENT_INFO",
    "HOME=/home/luke",
    "LANG=en_US.UTF-8",
    "LOGNAME",
    "NODE_OPTIONS",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
    "/usr/games:/usr/local/games:/snap/bin:/snap/bin",
    "QT_ACCESSIBILITY",
    "SHELL",
    "SSH_AUTH_SOCK",
    "USER",
    "XDG_DATA_DIRS",
    "XDG_RUNTIME_DIR",
)
SYSTEMD_INJECTED_ENVIRONMENT_UNSETS = (
    "INVOCATION_ID",
    "JOURNAL_STREAM",
    "MANAGERPID",
    "MANAGERPIDFDID",
    "MEMORY_PRESSURE_WATCH",
    "MEMORY_PRESSURE_WRITE",
    "SYSTEMD_EXEC_PID",
)
ALL_UNSET_ENVIRONMENT = (
    UNSET_ENVIRONMENT
    + MANAGER_ENVIRONMENT_UNSETS
    + SYSTEMD_INJECTED_ENVIRONMENT_UNSETS
)
COMMON_SYSTEMD_PROPERTIES = (
    "SystemCallFilter=~@network-io",
    "SystemCallErrorNumber=EPERM",
    "RestrictAddressFamilies=AF_UNIX",
    "NoNewPrivileges=yes",
    "LimitCORE=0",
    "MemoryMax=12G",
    "MemorySwapMax=0",
    "OOMPolicy=stop",
    "UMask=0077",
    "UnsetEnvironment=" + " ".join(ALL_UNSET_ENVIRONMENT),
    "StandardInput=null",
)
PROBE_SYSTEMD_PROPERTIES = COMMON_SYSTEMD_PROPERTIES + (
    "StandardOutput=journal",
    "StandardError=journal",
)
RUN_SYSTEMD_PROPERTIES = COMMON_SYSTEMD_PROPERTIES + (
    "StandardOutput=null",
    "StandardError=null",
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
    "MemoryPeak",
    "MemorySwapCurrent",
    "MemorySwapPeak",
    "OOMPolicy",
    "NRestarts",
    "UMask",
    "UnsetEnvironment",
    "Environment",
    "StandardInput",
    "StandardOutput",
    "StandardError",
)
FIXED_ENVIRONMENT = (
    "HOME=/nonexistent",
    "PATH=/usr/bin:/bin",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "TZ=UTC",
    "RUST_BACKTRACE=0",
    "RAYON_NUM_THREADS=1",
    "MALLOC_ARENA_MAX=2",
)

NETWORK_PROBE_SOURCE = """\
import errno
import os
import socket

expected_environment = {
    "HOME": "/nonexistent",
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "RUST_BACKTRACE": "0",
    "RAYON_NUM_THREADS": "1",
    "MALLOC_ARENA_MAX": "2",
}
if dict(os.environ) != expected_environment:
    raise SystemExit(4)

for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
    try:
        socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise SystemExit(2)
    else:
        raise SystemExit(3)
"""

ASSIGNMENT_KEYS = {
    "abort_oom_zeroization",
    "aggregate_proof_generated",
    "allocator_abort_can_return_receipt",
    "assignment_callback_exposed",
    "assignment_receipt_binds_current_preparer_identity",
    "assignment_serialized",
    "classification",
    "core_dump_disabled_by_external_launcher_required",
    "current_preparer_assignment_shape_matches_historical_contract",
    "current_preparer_binary_identity_bound",
    "current_preparer_constraint_rows_recorded",
    "current_preparer_constraint_satisfaction_checked",
    "current_preparer_lc_assignments_generated",
    "current_preparer_matrix_constructed",
    "current_preparer_observed_constraints",
    "current_preparer_source_closure_bound",
    "current_swap_kib",
    "derived_public_inputs_decimal",
    "elapsed_seconds",
    "error_path_source_zeroization_complete",
    "external_launch_receipt_required_for_current_preparer_identity",
    "full_secret_zeroization",
    "historical_component_expected_matrix_identity_recomputed",
    "historical_component_expected_matrix_rows_materialized",
    "historical_component_expected_matrix_sha256",
    "historical_component_expected_constraints",
    "historical_component_plan_sha256",
    "historical_component_run_id",
    "historical_component_selected_build_identity_sha256",
    "historical_component_seven_checkpoints_and_artifacts_rehashed",
    "historical_component_source_closure_sha256",
    "historical_component_source_instance_epoch_id",
    "historical_component_source_members_rehashed",
    "historical_source_bundle_manifest_sha256",
    "one_shot_process_operation",
    "output_proofs_verified",
    "peak_rss_kib",
    "prepared_instances",
    "prepared_variables",
    "prepared_witnesses",
    "private_local_evidence_only",
    "proving_key_opened",
    "public_input_selector",
    "public_or_production_authority",
    "receipt_is_authority",
    "rounds_validated",
    "schema",
    "selected_round",
    "setup_network_or_funds",
    "signature_relations_satisfied",
}
ASSIGNMENT_FALSE_FIELDS = {
    "abort_oom_zeroization",
    "aggregate_proof_generated",
    "allocator_abort_can_return_receipt",
    "assignment_callback_exposed",
    "assignment_receipt_binds_current_preparer_identity",
    "assignment_serialized",
    "current_preparer_binary_identity_bound",
    "current_preparer_constraint_rows_recorded",
    "current_preparer_constraint_satisfaction_checked",
    "current_preparer_lc_assignments_generated",
    "current_preparer_matrix_constructed",
    "current_preparer_source_closure_bound",
    "error_path_source_zeroization_complete",
    "full_secret_zeroization",
    "historical_component_expected_matrix_identity_recomputed",
    "historical_component_expected_matrix_rows_materialized",
    "proving_key_opened",
    "public_input_selector",
    "public_or_production_authority",
    "receipt_is_authority",
    "setup_network_or_funds",
}
ASSIGNMENT_TRUE_FIELDS = {
    "core_dump_disabled_by_external_launcher_required",
    "current_preparer_assignment_shape_matches_historical_contract",
    "external_launch_receipt_required_for_current_preparer_identity",
    "historical_component_seven_checkpoints_and_artifacts_rehashed",
    "historical_component_source_members_rehashed",
    "one_shot_process_operation",
    "private_local_evidence_only",
}
EXPECTED_PUBLIC_INPUTS = (
    "13917591994071772114488105153423377273",
    "33826997814916552742078018202966096202",
)
EXPECTED_ROUND1_EFFECTS_CORE_SHA256 = (
    "7983de2691ae57b60167c780436e780a4af9a6a2104134804f9afcdfc1d77219"
)


class Refused(RuntimeError):
    """One fail-closed supervisor refusal."""


def need(value: bool, category: str) -> None:
    if not value:
        raise Refused(category)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _render_identity_bound_exec_source(
    *,
    binary_path: Path,
    receipt_path: Path,
    expected_device: int,
    expected_inode: int,
    expected_bytes: int,
    expected_sha256: str,
    expected_owner_uid: int,
) -> str:
    environment = dict(value.split("=", 1) for value in FIXED_ENVIRONMENT)
    return f'''import errno
import fcntl
import hashlib
import os
import stat

BINARY = {str(binary_path)!r}
RECEIPT = {str(receipt_path)!r}
EXPECTED_DEVICE = {expected_device!r}
EXPECTED_INODE = {expected_inode!r}
EXPECTED_BYTES = {expected_bytes!r}
EXPECTED_SHA256 = {expected_sha256!r}
EXPECTED_OWNER_UID = {expected_owner_uid!r}
ENVIRONMENT = {environment!r}

def refuse():
    raise SystemExit(70)

def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )

before_path = os.lstat(BINARY)
if not (
    stat.S_ISREG(before_path.st_mode)
    and not stat.S_ISLNK(before_path.st_mode)
    and before_path.st_dev == EXPECTED_DEVICE
    and before_path.st_ino == EXPECTED_INODE
    and before_path.st_nlink == 1
    and before_path.st_uid == EXPECTED_OWNER_UID
    and before_path.st_size == EXPECTED_BYTES
    and stat.S_IMODE(before_path.st_mode) == 0o500
):
    refuse()
source_descriptor = os.open(
    BINARY,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
sealed_descriptor = -1
try:
    opened = os.fstat(source_descriptor)
    if identity(opened) != identity(before_path):
        refuse()
    try:
        sealed_descriptor = os.memfd_create(
            "kpb-frozen-assignment-exec",
            os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
        )
    except (AttributeError, OSError):
        refuse()
    digest = hashlib.sha256()
    total = 0
    while True:
        block = os.pread(source_descriptor, 1024 * 1024, total)
        if not block:
            break
        digest.update(block)
        view = memoryview(block)
        while view:
            written = os.write(sealed_descriptor, view)
            if written <= 0:
                refuse()
            view = view[written:]
        total += len(block)
    after_fd = os.fstat(source_descriptor)
    after_path = os.lstat(BINARY)
    if not (
        identity(opened) == identity(after_fd) == identity(after_path)
        and total == EXPECTED_BYTES
        and digest.hexdigest() == EXPECTED_SHA256
    ):
        refuse()
    os.fchmod(sealed_descriptor, 0o500)
    required_seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    if required_seals != 0x0F:
        refuse()
    try:
        fcntl.fcntl(sealed_descriptor, fcntl.F_ADD_SEALS, required_seals)
        actual_seals = fcntl.fcntl(sealed_descriptor, fcntl.F_GET_SEALS)
    except (AttributeError, OSError):
        refuse()
    if actual_seals != required_seals:
        refuse()
    sealed_stat = os.fstat(sealed_descriptor)
    if not (
        stat.S_ISREG(sealed_stat.st_mode)
        and sealed_stat.st_nlink == 0
        and sealed_stat.st_uid == EXPECTED_OWNER_UID
        and sealed_stat.st_size == EXPECTED_BYTES
        and stat.S_IMODE(sealed_stat.st_mode) == 0o500
    ):
        refuse()
    for operation in (
        lambda: os.pwrite(sealed_descriptor, b"\\x00", 0),
        lambda: os.ftruncate(sealed_descriptor, EXPECTED_BYTES + 1),
        lambda: os.ftruncate(sealed_descriptor, EXPECTED_BYTES - 1),
    ):
        try:
            operation()
        except OSError as error:
            if error.errno != errno.EPERM:
                refuse()
        else:
            refuse()
    if fcntl.fcntl(sealed_descriptor, fcntl.F_GET_SEALS) != required_seals:
        refuse()
    sealed_before = os.fstat(sealed_descriptor)
    sealed_digest = hashlib.sha256()
    sealed_total = 0
    while True:
        block = os.pread(sealed_descriptor, 1024 * 1024, sealed_total)
        if not block:
            break
        sealed_digest.update(block)
        sealed_total += len(block)
    sealed_after = os.fstat(sealed_descriptor)
    if not (
        identity(sealed_before) == identity(sealed_after)
        and sealed_total == EXPECTED_BYTES
        and sealed_digest.hexdigest() == EXPECTED_SHA256
    ):
        refuse()
    os.execve(sealed_descriptor, [BINARY, RECEIPT], ENVIRONMENT)
finally:
    os.close(source_descriptor)
    if sealed_descriptor >= 0:
        os.close(sealed_descriptor)
'''


def _identity_bound_exec_source() -> str:
    return _render_identity_bound_exec_source(
        binary_path=BUILD_BINARY,
        receipt_path=ASSIGNMENT_RECEIPT,
        expected_device=EXPECTED_BINARY_DEVICE,
        expected_inode=EXPECTED_BINARY_INODE,
        expected_bytes=EXPECTED_BINARY_BYTES,
        expected_sha256=EXPECTED_BINARY_SHA256,
        expected_owner_uid=EXPECTED_BINARY_OWNER_UID,
    )


def _identity_bound_helper_reference() -> dict:
    raw = _identity_bound_exec_source().encode()
    return {
        "interpreter": str(PYTHON),
        "source_bytes": len(raw),
        "source_sha256": sha256_bytes(raw),
        "exec_primitive": "sealed-memfd-os.execve-by-file-descriptor",
        "memfd_seals": [
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        ],
        "sealed_memfd_rehashed_before_exec": True,
        "binary_path": str(BUILD_BINARY),
        "binary_device": EXPECTED_BINARY_DEVICE,
        "binary_inode": EXPECTED_BINARY_INODE,
        "binary_bytes": EXPECTED_BINARY_BYTES,
        "binary_sha256": EXPECTED_BINARY_SHA256,
        "binary_mode_octal": "0500",
        "binary_link_count": 1,
        "binary_owner_uid": EXPECTED_BINARY_OWNER_UID,
        "binary_argv": [str(BUILD_BINARY), str(ASSIGNMENT_RECEIPT)],
        "exact_environment": list(FIXED_ENVIRONMENT),
        "stdout_and_stderr_inherited_null": True,
    }


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
        left.st_uid,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
        right.st_uid,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _directory(path: Path, mode: int) -> dict:
    path = Path(path)
    value = os.lstat(path)
    need(
        stat.S_ISDIR(value.st_mode)
        and not stat.S_ISLNK(value.st_mode)
        and value.st_uid == os.getuid()
        and stat.S_IMODE(value.st_mode) == mode,
        "directory-stat",
    )
    return {
        "path": str(path),
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode_octal": f"{mode:04o}",
        "owner_uid": value.st_uid,
    }


def _stable_file(
    path: Path,
    mode: int,
    *,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
    expected_link_count: int = 1,
) -> tuple[bytes, dict]:
    path = Path(path)
    before = os.lstat(path)
    need(
        stat.S_ISREG(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and before.st_uid == os.getuid()
        and before.st_nlink == expected_link_count
        and stat.S_IMODE(before.st_mode) == mode,
        "file-stat",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        need(_same_stat(before, opened), "file-open-race")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    need(
        _same_stat(before, after_fd) and _same_stat(after_fd, after_path),
        "file-read-race",
    )
    actual_sha256 = digest.hexdigest()
    need(total == before.st_size, "file-size-race")
    if expected_sha256 is not None:
        need(actual_sha256 == expected_sha256, "file-sha256")
    if expected_bytes is not None:
        need(total == expected_bytes, "file-bytes")
    return b"".join(chunks), {
        "path": str(path),
        "device": before.st_dev,
        "inode": before.st_ino,
        "bytes": total,
        "sha256": actual_sha256,
        "mode_octal": f"{mode:04o}",
        "link_count": before.st_nlink,
        "owner_uid": before.st_uid,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }


def _unique_json(raw: bytes) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict:
        result: dict[str, object] = {}
        for key, value in values:
            need(key not in result, "json-duplicate-key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, Refused):
        raise Refused("json-shape") from None
    return value


def _safe_relative(value: object) -> PurePosixPath:
    need(type(value) is str and value != "", "relative-type")
    need(
        "\\" not in value
        and "\x00" not in value
        and not any(character.isspace() or ord(character) < 32 for character in value),
        "relative-encoding",
    )
    path = PurePosixPath(value)
    need(
        not path.is_absolute()
        and str(path) == value
        and all(part not in ("", ".", "..") for part in path.parts),
        "relative-canonical",
    )
    return path


def _require_bound_artifact_constants() -> None:
    for value in (
        EXPECTED_MANIFEST_SHA256,
        EXPECTED_INNER_RECEIPT_SHA256,
        EXPECTED_DEP_INFO_SHA256,
        EXPECTED_ORIGINAL_DEP_INFO_SHA256,
        EXPECTED_BINARY_SHA256,
        EXPECTED_OUTER_RECEIPT_SHA256,
        EXPECTED_IDENTITY_BOUND_HELPER_SHA256,
        EXPECTED_RUN_COMMAND_SHA256,
    ):
        need(
            type(value) is str
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value),
            "artifact-hash-unbound",
        )
    need(
        type(EXPECTED_BINARY_BYTES) is int and EXPECTED_BINARY_BYTES > 0,
        "artifact-bytes-unbound",
    )
    helper = _identity_bound_helper_reference()
    need(
        helper["source_sha256"] == EXPECTED_IDENTITY_BOUND_HELPER_SHA256,
        "identity-bound-helper-source",
    )
    need(
        sha256_bytes(canonical(_run_command())) == EXPECTED_RUN_COMMAND_SHA256,
        "identity-bound-run-command",
    )


def _derived_expected_public_inputs() -> tuple[str, str]:
    digest = bytes.fromhex(EXPECTED_ROUND1_EFFECTS_CORE_SHA256)
    need(len(digest) == 32, "effects-core-sha256")
    return (
        str(int.from_bytes(digest[:16], "little")),
        str(int.from_bytes(digest[16:], "little")),
    )


def _validate_manifest(raw: bytes) -> tuple[dict, tuple[str, ...]]:
    value = _unique_json(raw)
    need(type(value) is dict, "manifest-object")
    need(
        set(value)
        == {
            "schema",
            "classification",
            "source_root",
            "package_roots",
            "derivation",
            "members",
            "member_count",
            "members_identity_sha256",
            "authorization",
            "manifest_identity_sha256",
        }
        and value["schema"] == "kpb-current-w1-source-snapshot-manifest/v1"
        and value["classification"] == "CURRENT_SOURCE_FINAL_CANDIDATE_NOT_AUTHORITY"
        and value["authorization"] is False
        and value["source_root"] == str(REPO_ROOT)
        and tuple(value["package_roots"]) == EXPECTED_PACKAGE_ROOTS
        and type(value["members"]) is list
        and value["member_count"] == len(value["members"])
        == EXPECTED_SOURCE_MEMBER_COUNT,
        "manifest-shape",
    )
    need(
        value["members_identity_sha256"] == sha256_bytes(canonical(value["members"])),
        "manifest-members-identity",
    )
    unsigned = dict(value)
    claimed = unsigned.pop("manifest_identity_sha256")
    need(claimed == sha256_bytes(canonical(unsigned)), "manifest-identity")
    paths: list[str] = []
    for item in value["members"]:
        need(
            type(item) is dict
            and set(item) == {"relative_path", "bytes", "sha256"}
            and type(item["bytes"]) is int
            and item["bytes"] >= 0
            and type(item["sha256"]) is str
            and len(item["sha256"]) == 64,
            "manifest-member",
        )
        paths.append(str(_safe_relative(item["relative_path"])))
    need(paths == sorted(paths) and len(paths) == len(set(paths)), "manifest-order")
    members = {item["relative_path"]: item for item in value["members"]}
    need(
        members[FORBIDDEN_PROVER_SOURCE]["sha256"]
        == EXPECTED_FROZEN_PROVER_SOURCE_SHA256
        and members[
            "poc/local-private-payment/private-batch-relation/src/"
            "counterfactual_w1/offline_verifier/frozen_assignment.rs"
        ]["sha256"]
        == EXPECTED_FROZEN_ASSIGNMENT_SOURCE_SHA256,
        "manifest-frozen-source-identities",
    )
    return value, tuple(paths)


def _validate_snapshot(manifest: dict, paths: tuple[str, ...]) -> dict:
    root = BUILD_BUNDLE / "sources"
    _directory(root, 0o500)
    expected_files = set(paths)
    expected_directories = {""}
    for path in paths:
        parent = PurePosixPath(path).parent
        while str(parent) not in ("", "."):
            expected_directories.add(str(parent))
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories = {""}
    references = []
    for current_raw, directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_raw)
        relative_current = current.relative_to(root).as_posix()
        if relative_current == ".":
            relative_current = ""
        _directory(current, 0o500)
        for name in directories:
            child = current / name
            _directory(child, 0o500)
            relative = child.relative_to(root).as_posix()
            actual_directories.add(relative)
        for name in files:
            path = current / name
            relative = path.relative_to(root).as_posix()
            actual_files.add(relative)
    need(actual_files == expected_files, "snapshot-file-set")
    need(actual_directories == expected_directories, "snapshot-directory-set")
    members = {item["relative_path"]: item for item in manifest["members"]}
    for relative in paths:
        item = members[relative]
        _, reference = _stable_file(
            root / relative,
            0o400,
            expected_sha256=item["sha256"],
            expected_bytes=item["bytes"],
        )
        references.append(reference)
    return {
        "member_count": len(references),
        "members_identity_sha256": manifest["members_identity_sha256"],
        "all_files_mode_0400": True,
        "all_directories_mode_0500": True,
    }


def _validate_receipt_identity(value: dict, category: str) -> None:
    need("receipt_identity_sha256" in value, category)
    unsigned = dict(value)
    claimed = unsigned.pop("receipt_identity_sha256")
    need(claimed == sha256_bytes(canonical(unsigned)), category)


def _parse_dep_info(raw: bytes) -> tuple[str, list[str]]:
    need(b"\x00" not in raw and raw.endswith(b"\n"), "dep-info-encoding")
    normalized = raw.replace(b"\\\n", b" ")
    try:
        text = normalized.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("dep-info-utf8") from None
    lines = [line for line in text.splitlines() if line]
    need(len(lines) == 1 and ": " in lines[0], "dep-info-one-rule")
    target, dependencies = lines[0].split(": ", 1)
    tokens = dependencies.split(" ")
    need(
        target != ""
        and tokens
        and all(tokens)
        and len(tokens) == len(set(tokens)),
        "dep-info-shape",
    )
    return target, tokens


def _validate_inner_receipt(raw: bytes, references: dict[str, dict]) -> dict:
    value = _unique_json(raw)
    need(type(value) is dict, "inner-receipt-object")
    _validate_receipt_identity(value, "inner-receipt-identity")
    need(
        set(value)
        == {
            "actual_subprocess_build_executed_by_contract",
            "authorization",
            "binary",
            "build_target_outside_snapshot",
            "classification",
            "dep_info",
            "freezer_source",
            "frozen_dep_info",
            "funds",
            "network",
            "pk_decode",
            "production_binary_accepted",
            "production_source_manifest_bound",
            "proof",
            "receipt_identity_sha256",
            "schema",
            "setup",
            "snapshot_directories_mode_0500",
            "snapshot_files_mode_0400",
            "snapshot_same_inodes_before_after",
            "source_manifest",
            "source_member_count",
            "source_members_identity_sha256",
            "synthesis",
        }
        and value.get("schema") == "kpb-current-w1-test-build-freeze-receipt/v1"
        and value.get("classification")
        == "TEST_ONLY_FILESYSTEM_CONTRACT_NOT_A_BUILD_AUTHORITY"
        and value.get("source_member_count") == EXPECTED_SOURCE_MEMBER_COUNT
        and value.get("snapshot_same_inodes_before_after") is True
        and value.get("snapshot_files_mode_0400") is True
        and value.get("snapshot_directories_mode_0500") is True
        and value.get("build_target_outside_snapshot") is True
        and value.get("actual_subprocess_build_executed_by_contract") is False
        and value.get("production_source_manifest_bound") is False
        and value.get("production_binary_accepted") is False
        and value.get("setup") is False
        and value.get("pk_decode") is False
        and value.get("synthesis") is False
        and value.get("proof") is False
        and value.get("network") is False
        and value.get("funds") is False
        and value.get("authorization") is False,
        "inner-receipt-truth",
    )
    need(
        value["source_manifest"]["bytes"] == references["manifest"]["bytes"]
        and value["source_manifest"]["sha256"] == references["manifest"]["sha256"]
        and value["source_members_identity_sha256"]
        == references["manifest_members_identity_sha256"]
        and value["freezer_source"]["sha256"] == references["core_source"]["sha256"]
        and value["binary"]["bytes"] == references["binary"]["bytes"]
        and value["binary"]["sha256"] == references["binary"]["sha256"]
        and value["binary"]["mode_octal"] == "0500"
        and value["frozen_dep_info"]["bytes"] == references["dep_info"]["bytes"]
        and value["frozen_dep_info"]["sha256"] == references["dep_info"]["sha256"]
        and value["frozen_dep_info"]["mode_octal"] == "0400",
        "inner-receipt-artifacts",
    )
    return value


def _canonical_existing_build_path(value: object, category: str) -> Path:
    need(type(value) is str, category)
    path = Path(value)
    try:
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, RuntimeError):
        raise Refused(category) from None
    need(
        path.is_absolute()
        and ".." not in path.parts
        and resolved == path
        and path.is_relative_to(BUILD_PARENT),
        category,
    )
    return path


def _validate_retained_build_outputs(
    outer: dict, references: dict[str, dict]
) -> dict:
    build = outer["build"]
    dep_info = outer["dep_info"]
    original_binary = build["cargo_original_binary"]
    normalization = dep_info["normalization"]
    original_dep_info = dep_info["cargo_original"]
    normalized_input = dep_info["normalized_core_input"]

    original_binary_path = _canonical_existing_build_path(
        original_binary.get("path"), "cargo-original-binary-path"
    )
    target_root = original_binary_path.parents[2]
    need(
        target_root.parent == BUILD_PARENT
        and target_root.name.startswith(".assignment-measurement-build.target-")
        and original_binary_path.parent == target_root / "release" / "examples",
        "cargo-target-root",
    )
    _directory(target_root, 0o700)
    original_raw, original_reference = _stable_file(
        original_binary_path,
        0o700,
        expected_sha256=EXPECTED_BINARY_SHA256,
        expected_bytes=EXPECTED_BINARY_BYTES,
        expected_link_count=2,
    )
    need(
        all(
            original_binary.get(key) == original_reference[key]
            for key in (
                "device",
                "inode",
                "bytes",
                "sha256",
                "mode_octal",
                "link_count",
                "owner_uid",
            )
        ),
        "cargo-original-binary-reference",
    )
    aliases = []
    for candidate in original_binary_path.parent.iterdir():
        value = os.lstat(candidate)
        if (value.st_dev, value.st_ino) == (
            original_reference["device"],
            original_reference["inode"],
        ):
            aliases.append(candidate.name)
    need(
        len(aliases) == 2
        and original_binary_path.name in aliases
        and all(
            name == original_binary_path.name
            or name.startswith(original_binary_path.name + "-")
            for name in aliases
        ),
        "cargo-original-hardlink-aliases",
    )

    detached_path = _canonical_existing_build_path(
        normalization.get("detached_target"), "detached-binary-path"
    )
    need(
        detached_path.parent == target_root / "assignment-freeze-admission",
        "detached-binary-parent",
    )
    _directory(detached_path.parent, 0o700)
    detached_raw, detached_reference = _stable_file(
        detached_path,
        0o500,
        expected_sha256=EXPECTED_BINARY_SHA256,
        expected_bytes=EXPECTED_BINARY_BYTES,
    )
    detached_claim = build["detached_create_new_binary"]
    need(
        detached_raw == original_raw
        and all(
            detached_claim.get(key) == detached_reference[key]
            for key in (
                "device",
                "inode",
                "bytes",
                "sha256",
                "mode_octal",
                "link_count",
            )
        ),
        "detached-binary-reference",
    )

    cargo_dep_path = _canonical_existing_build_path(
        original_dep_info.get("path"), "cargo-original-dep-info-path"
    )
    need(
        cargo_dep_path == original_binary_path.with_suffix(".d"),
        "cargo-original-dep-info-location",
    )
    cargo_dep_raw, cargo_dep_reference = _stable_file(
        cargo_dep_path,
        0o600,
        expected_sha256=EXPECTED_ORIGINAL_DEP_INFO_SHA256,
    )
    need(
        original_dep_info.get("bytes") == cargo_dep_reference["bytes"]
        and original_dep_info.get("sha256") == cargo_dep_reference["sha256"]
        and original_dep_info.get("mode_octal") == "0600"
        and original_dep_info.get("link_count") == 1
        and original_dep_info.get("unchanged_across_freeze") is True
        and cargo_dep_raw == references["original_dep_info_raw"],
        "cargo-original-dep-info-reference",
    )

    normalized_path = _canonical_existing_build_path(
        normalized_input.get("path"), "normalized-dep-info-path"
    )
    need(
        normalized_path == detached_path.with_suffix(".d"),
        "normalized-dep-info-location",
    )
    normalized_raw, normalized_reference = _stable_file(
        normalized_path,
        0o400,
        expected_sha256=EXPECTED_DEP_INFO_SHA256,
    )
    need(
        all(
            normalized_input.get(key) == normalized_reference[key]
            for key in ("bytes", "sha256", "mode_octal", "link_count")
        )
        and normalized_raw == references["dep_info_raw"],
        "normalized-dep-info-reference",
    )
    need(
        set(os.listdir(BUILD_PARENT))
        == {BUILD_BUNDLE.name, BUILD_EVIDENCE.name, target_root.name},
        "build-parent-exact-tree",
    )
    return {
        "target_root": str(target_root),
        "cargo_original_binary": original_reference,
        "detached_binary": detached_reference,
        "cargo_original_dep_info": cargo_dep_reference,
        "normalized_dep_info": normalized_reference,
        "cargo_hardlink_aliases": sorted(aliases),
    }


def _validate_dep_info_derivation(
    outer: dict,
    inner: dict,
    manifest: dict,
    normalized_raw: bytes,
    original_raw: bytes,
) -> tuple[str, ...]:
    dep_info = outer["dep_info"]
    derivation = dep_info["raw_cargo_derivation"]
    normalization = dep_info["normalization"]
    normalized_target, normalized_paths = _parse_dep_info(normalized_raw)
    original_target, original_paths = _parse_dep_info(original_raw)
    relatives = dep_info.get("dependency_relatives")
    mappings = derivation.get("mappings")
    need(
        type(relatives) is list
        and all(type(value) is str for value in relatives)
        and type(mappings) is list
        and len(original_paths) == EXPECTED_RAW_DEPENDENCY_COUNT
        and len(mappings) == EXPECTED_RAW_DEPENDENCY_COUNT
        and len(normalized_paths) == EXPECTED_CANONICAL_DEPENDENCY_COUNT
        and len(relatives) == EXPECTED_CANONICAL_DEPENDENCY_COUNT
        and len(set(relatives)) == len(relatives)
        and derivation.get("raw_target") == original_target
        and derivation.get("raw_dependencies") == original_paths
        and derivation.get("raw_dependency_count") == len(original_paths)
        and derivation.get("canonical_dependency_absolutes") == normalized_paths
        and derivation.get("canonical_unique_dependency_count") == len(normalized_paths)
        and derivation.get("raw_dep_info_sha256")
        == EXPECTED_ORIGINAL_DEP_INFO_SHA256
        and derivation.get("first_occurrence_order_preserved") is True
        and normalization.get("original_target") == original_target
        and normalization.get("detached_target") == normalized_target
        and normalization.get("raw_dependency_count") == len(original_paths)
        and normalization.get("normalized_dependency_count") == len(normalized_paths)
        and normalization.get("canonical_duplicate_count")
        == EXPECTED_CANONICAL_DUPLICATE_COUNT
        and normalization.get("canonical_first_occurrence_order_preserved") is True
        and normalization.get("raw_dep_info_sha256")
        == EXPECTED_ORIGINAL_DEP_INFO_SHA256
        and normalization.get("normalized_dep_info_sha256")
        == EXPECTED_DEP_INFO_SHA256
        and inner["dep_info"]["target"] == normalized_target
        and inner["dep_info"]["dependencies"] == normalized_paths
        and inner["dep_info"]["dependency_count"] == len(normalized_paths)
        and inner["dep_info"]["dep_info_sha256"] == EXPECTED_DEP_INFO_SHA256,
        "dep-info-counts-and-bindings",
    )
    manifest_members = {item["relative_path"]: item for item in manifest["members"]}
    first_indexes: dict[str, int] = {}
    observed_relatives: list[str] = []
    snapshot_prefix: str | None = None
    aliases = 0
    duplicates = 0
    for index, (raw_path, mapping) in enumerate(
        zip(original_paths, mappings, strict=True)
    ):
        need(type(mapping) is dict and type(raw_path) is str, "dep-info-mapping-shape")
        canonical = os.path.normpath(raw_path)
        relative = mapping.get("canonical_relative")
        need(
            type(relative) is str
            and relative in manifest_members
            and Path(raw_path).is_absolute()
            and Path(canonical).is_absolute()
            and ".." not in Path(canonical).parts
            and mapping.get("raw_index") == index
            and mapping.get("raw_absolute") == raw_path
            and mapping.get("canonical_absolute") == canonical
            and canonical.endswith("/sources/" + relative),
            "dep-info-mapping-path",
        )
        prefix = canonical[: -len("/" + relative)]
        if snapshot_prefix is None:
            snapshot_prefix = prefix
            prefix_path = Path(prefix)
            need(
                prefix_path.name == "sources"
                and prefix_path.parent.parent == BUILD_PARENT
                and prefix_path.parent.name.startswith(
                    ".assignment-measurement-build.staging-"
                ),
                "dep-info-staging-prefix",
            )
        need(prefix == snapshot_prefix, "dep-info-multiple-snapshots")
        member = manifest_members[relative]
        frozen_member = os.lstat(BUILD_BUNDLE / "sources" / relative)
        need(
            mapping.get("device") == frozen_member.st_dev
            and mapping.get("inode") == frozen_member.st_ino
            and mapping.get("bytes") == member["bytes"] == frozen_member.st_size
            and mapping.get("sha256") == member["sha256"],
            "dep-info-mapping-inode",
        )
        alias = raw_path != canonical
        duplicate = relative in first_indexes
        need(
            mapping.get("lexical_alias") is alias
            and mapping.get("duplicate_canonical_member") is duplicate
            and mapping.get("duplicate_of_raw_index")
            == first_indexes.get(relative),
            "dep-info-mapping-duplicate",
        )
        aliases += int(alias)
        duplicates += int(duplicate)
        if not duplicate:
            first_indexes[relative] = index
            observed_relatives.append(relative)
    need(
        aliases == EXPECTED_CANONICAL_DUPLICATE_COUNT
        == derivation.get("lexical_alias_count")
        and duplicates == EXPECTED_CANONICAL_DUPLICATE_COUNT
        == derivation.get("duplicate_canonical_member_count")
        and observed_relatives == relatives
        and normalized_paths == derivation["canonical_dependency_absolutes"]
        and FORBIDDEN_PROVER_SOURCE not in relatives
        and not any(
            relative.startswith(FORBIDDEN_LOW_MEMORY_PREFIX)
            for relative in relatives
        ),
        "dep-info-assignment-only",
    )
    return tuple(relatives)


def _validate_outer_receipt(
    raw: bytes,
    references: dict[str, dict],
    manifest: dict,
    inner: dict,
    normalized_dep_raw: bytes,
    original_dep_raw: bytes,
) -> tuple[dict, dict]:
    value = _unique_json(raw)
    need(type(value) is dict, "outer-receipt-object")
    _validate_receipt_identity(value, "outer-receipt-identity")
    build = value.get("build", {})
    network = value.get("network_boundary", {})
    dep_info = value.get("dep_info", {})
    closure = value.get("closure_scope", {})
    bundle = value.get("atomic_core_bundle", {})
    limitations = value.get("limitations", {})
    need(
        set(value)
        == {
            "actions",
            "atomic_core_bundle",
            "authorization",
            "build",
            "classification",
            "closure_scope",
            "dep_info",
            "executed_core_source",
            "financial_acceptance",
            "fixed_no_argument_entrypoint",
            "freezer_source",
            "funds",
            "limitations",
            "network_boundary",
            "network_communication",
            "pk_decode",
            "privacy_acceptance",
            "private_output_parent",
            "production_build_authority",
            "proof",
            "proving_key_read",
            "receipt_identity_sha256",
            "repository_root",
            "schema",
            "setup",
            "source_snapshot",
            "synthesis",
        }
        and value.get("schema") == "kpb-w1-assignment-measurement-build-receipt/v1"
        and value.get("classification")
        == "TEST_ONLY_ASSIGNMENT_MEASUREMENT_BUILD_NOT_AUTHORITY"
        and value.get("fixed_no_argument_entrypoint") is True
        and value.get("repository_root") == str(REPO_ROOT)
        and value.get("private_output_parent") == str(BUILD_PARENT)
        and value.get("authorization") is False
        and value.get("privacy_acceptance") is False
        and value.get("financial_acceptance") is False
        and value.get("production_build_authority") is False
        and value.get("setup") is False
        and value.get("pk_decode") is False
        and value.get("proving_key_read") is False
        and value.get("synthesis") is False
        and value.get("proof") is False
        and value.get("network_communication") is False
        and value.get("funds") is False
        and build.get("actual_subprocess_executed") is True
        and build.get("binary_was_not_executed") is True
        and build.get("locked") is True
        and build.get("offline") is True
        and build.get("default_features") is False
        and build.get("features") == ["offline-w1-preparer"]
        and build.get("example") == "prepare_frozen_w1_round1_assignment"
        and build.get("profile") == "release"
        and build.get("target_outside_snapshot") is True
        and build.get("cargo_original_binary_was_hardlink") is True
        and build.get("cargo_original_binary_unchanged_across_freeze") is True
        and build.get("detached_binary_byte_identical") is True
        and network.get("restrict_address_families") == "AF_UNIX"
        and network.get("local_af_unix_ipc_observed") is True
        and network.get("preexisting_af_unix_datagram_sendto_not_excluded") is True
        and network.get("strict_no_socket_runtime_boundary_is_not_this_build_boundary")
        is True
        and network.get("network_communication_performed") is False
        and dep_info.get("all_members_under_sealed_snapshot") is True
        and dep_info.get("offline_w1_prover_source_absent_from_assignment_dep_info") is True
        and dep_info.get("low_memory_w1_prover_source_absent_from_assignment_dep_info") is True
        and closure.get("assignment_only_closure_frozen") is True
        and closure.get("combined_assignment_plus_prover_closure_frozen") is False
        and closure.get("combined_closure_status") == "STOP_NOT_FROZEN_BY_THIS_ENTRYPOINT"
        and bundle.get("source_binary_receipt_atomically_published") is True,
        "outer-receipt-truth",
    )
    need(
        bundle["binary"]["sha256"] == references["binary"]["sha256"]
        and bundle["receipt"]["sha256"] == references["inner_receipt"]["sha256"]
        and value["source_snapshot"]["manifest"]["sha256"]
        == references["manifest"]["sha256"]
        and value["executed_core_source"]["frozen_inner_copy"]["sha256"]
        == references["core_source"]["sha256"]
        and value["freezer_source"]["sha256"]
        == references["build_freezer_source"]["sha256"],
        "outer-receipt-artifacts",
    )
    need(
        set(network.get("denied_network_syscalls", ()))
        == EXPECTED_BUILD_DENIED_NETWORK_SYSCALLS
        and network.get("socket_and_socketpair_allowed_for_local_process_spawn")
        is True
        and network.get("send_recv_sendto_recvfrom_allowed_for_local_spawn_status_ipc")
        is True
        and network.get("af_unix_connect_bind_listen_accept_denied") is True
        and network.get("ip_address_families_available") is False
        and network.get("local_af_unix_ipc_permitted") is True,
        "outer-build-network-boundary",
    )
    need(
        limitations
        == {
            "build_filesystem_sandbox_present": False,
            "cryptographic_correctness_proved": False,
            "external_build_script_ambient_reads_sandboxed": False,
            "privacy_proved": False,
            "production_cargo_graph_authority": False,
            "registry_dependency_source_closure_bound": False,
            "rust_toolchain_binary_closure_bound": False,
            "unsealed_original_target_is_authority": False,
        },
        "outer-limitations",
    )
    need(
        value.get("actions")
        == {
            "authorization": False,
            "binary_execution": False,
            "build": True,
            "funds": False,
            "network_communication": False,
            "pk_decode": False,
            "proof": False,
            "proving_key_read": False,
            "setup": False,
            "source_snapshot": True,
            "synthesis": False,
            "verification": False,
        },
        "outer-actions",
    )
    unit = build.get("unit", {})
    probe = network.get("probe", {})
    for observed, expected_unit in (
        (unit, "kpb-w1-assignment-freeze-build-20261029-06.service"),
        (probe, "kpb-w1-assignment-freeze-netprobe-20261029-06.service"),
    ):
        properties = observed.get("properties", {})
        need(
            observed.get("unit") == expected_unit
            and observed.get("result") == "success"
            and observed.get("exec_main_status") == 0
            and observed.get("unit_stopped_after_capture") is True
            and properties.get("restrict_address_families") == "AF_UNIX"
            and set(properties.get("denied_network_syscalls", ()))
            == EXPECTED_BUILD_DENIED_NETWORK_SYSCALLS
            and properties.get("system_call_error_number") == 1
            and properties.get("no_new_privileges") is True
            and properties.get("limit_core_bytes") == 0
            and properties.get("memory_max_bytes") == 12 * 1024**3
            and properties.get("memory_swap_max_bytes") == 0
            and properties.get("umask_octal") == "0077",
            "outer-build-systemd-evidence",
        )
    command = build.get("command")
    need(type(command) is list and all(type(part) is str for part in command), "build-command")
    try:
        cargo_index = command.index("/home/luke/.cargo/bin/cargo")
    except ValueError:
        raise Refused("build-command") from None
    need(
        command[cargo_index:]
        == [
            "/home/luke/.cargo/bin/cargo",
            "build",
            "--release",
            "--locked",
            "--offline",
            "--no-default-features",
            "--features",
            "offline-w1-preparer",
            "--example",
            "prepare_frozen_w1_round1_assignment",
        ]
        and "/bin/sh" not in command
        and "run" not in command[cargo_index + 1 :],
        "build-command-tail",
    )
    dependencies = _validate_dep_info_derivation(
        value, inner, manifest, normalized_dep_raw, original_dep_raw
    )
    retained = _validate_retained_build_outputs(value, references)
    return value, {"dependency_relatives": dependencies, "retained": retained}


def validate_build_bundle() -> dict:
    _require_bound_artifact_constants()
    need(
        BUILD_PARENT.is_absolute()
        and not BUILD_PARENT.is_relative_to(REPO_ROOT)
        and BUILD_PARENT == BUILD_PARENT.resolve(strict=True),
        "build-parent-canonical-disjoint",
    )
    _directory(BUILD_PARENT, 0o700)
    _directory(BUILD_BUNDLE, 0o500)
    _directory(BUILD_BUNDLE / "artifacts", 0o500)
    _directory(BUILD_EVIDENCE, 0o500)
    need(
        set(os.listdir(BUILD_BUNDLE))
        == {
            "sources",
            "artifacts",
            "SOURCE-MANIFEST.json",
            "FREEZER-SOURCE.py",
            "BUILD-RECEIPT.json",
        }
        and set(os.listdir(BUILD_BUNDLE / "artifacts"))
        == {"candidate-binary", "candidate-binary.d"}
        and set(os.listdir(BUILD_EVIDENCE))
        == {
            "FREEZER-SOURCE.py",
            "CARGO-ORIGINAL-DEP-INFO.d",
            "MEASUREMENT-BUILD-RECEIPT.json",
        },
        "build-tree-files",
    )
    manifest_raw, manifest_ref = _stable_file(
        BUILD_MANIFEST, 0o400, expected_sha256=EXPECTED_MANIFEST_SHA256
    )
    inner_raw, inner_ref = _stable_file(
        BUILD_RECEIPT, 0o400, expected_sha256=EXPECTED_INNER_RECEIPT_SHA256
    )
    dep_raw, dep_ref = _stable_file(
        BUILD_DEP_INFO, 0o400, expected_sha256=EXPECTED_DEP_INFO_SHA256
    )
    original_dep_raw, original_dep_ref = _stable_file(
        BUILD_ORIGINAL_DEP_INFO,
        0o400,
        expected_sha256=EXPECTED_ORIGINAL_DEP_INFO_SHA256,
    )
    _, binary_ref = _stable_file(
        BUILD_BINARY,
        0o500,
        expected_sha256=EXPECTED_BINARY_SHA256,
        expected_bytes=EXPECTED_BINARY_BYTES,
    )
    need(
        binary_ref["device"] == EXPECTED_BINARY_DEVICE
        and binary_ref["inode"] == EXPECTED_BINARY_INODE
        and binary_ref["owner_uid"] == EXPECTED_BINARY_OWNER_UID,
        "sealed-binary-inode-identity",
    )
    _, core_ref = _stable_file(
        BUILD_CORE_SOURCE,
        0o400,
        expected_sha256=EXPECTED_BUILD_CORE_SOURCE_SHA256,
    )
    _, build_freezer_ref = _stable_file(
        BUILD_FREEZER_SOURCE,
        0o400,
        expected_sha256=EXPECTED_BUILD_FREEZER_SOURCE_SHA256,
    )
    outer_raw, outer_ref = _stable_file(
        BUILD_OUTER_RECEIPT,
        0o400,
        expected_sha256=EXPECTED_OUTER_RECEIPT_SHA256,
    )
    references = {
        "manifest": manifest_ref,
        "inner_receipt": inner_ref,
        "dep_info": dep_ref,
        "original_dep_info": original_dep_ref,
        "binary": binary_ref,
        "core_source": core_ref,
        "build_freezer_source": build_freezer_ref,
        "outer_receipt": outer_ref,
    }
    manifest, paths = _validate_manifest(manifest_raw)
    references["manifest_members_identity_sha256"] = manifest[
        "members_identity_sha256"
    ]
    references["dep_info_raw"] = dep_raw
    references["original_dep_info_raw"] = original_dep_raw
    snapshot = _validate_snapshot(manifest, paths)
    inner = _validate_inner_receipt(inner_raw, references)
    outer, outer_validation = _validate_outer_receipt(
        outer_raw,
        references,
        manifest,
        inner,
        dep_raw,
        original_dep_raw,
    )
    dependency_relatives = outer_validation["dependency_relatives"]
    # Raw bytes are validated above but never embedded into the launch receipt.
    references.pop("dep_info_raw")
    references.pop("original_dep_info_raw")
    return {
        "references": references,
        "source_snapshot": snapshot,
        "source_members_identity_sha256": inner["source_members_identity_sha256"],
        "dependency_count": len(dependency_relatives),
        "raw_dependency_count": EXPECTED_RAW_DEPENDENCY_COUNT,
        "canonical_duplicate_count": EXPECTED_CANONICAL_DUPLICATE_COUNT,
        "retained_build_outputs": outer_validation["retained"],
        "assignment_only": True,
        "prover_sources_absent": True,
    }


def _parse_show(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("systemd-show-utf8") from None
    result: dict[str, str] = {}
    for line in text.splitlines():
        need("=" in line, "systemd-show-line")
        key, value = line.split("=", 1)
        need(key in SHOW_PROPERTIES and key not in result, "systemd-show-key")
        result[key] = value
    need(set(result) == set(SHOW_PROPERTIES), "systemd-show-properties")
    return result


def _validate_manager_environment() -> dict:
    result = subprocess.run(
        [str(SYSTEMCTL), "--user", "show-environment"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    need(result.returncode == 0 and not result.stderr, "manager-environment-read")
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise Refused("manager-environment-utf8") from None
    names = []
    for line in lines:
        need("=" in line and "\x00" not in line, "manager-environment-line")
        names.append(line.split("=", 1)[0])
    need(
        len(names) == len(set(names))
        and tuple(sorted(lines)) == EXPECTED_MANAGER_ENVIRONMENT,
        "manager-environment-drift",
    )
    return {
        "entry_count": len(lines),
        "environment_sha256": sha256_bytes(canonical(sorted(lines))),
        "all_manager_entries_removed_or_replaced": True,
        "all_observed_systemd_injected_entries_removed": True,
        "fixed_runtime_environment": list(FIXED_ENVIRONMENT),
    }


def _metric(value: str, *, allow_unset: bool) -> int | None:
    if value == "[not set]" and allow_unset:
        return None
    need(value.isdigit(), "systemd-metric")
    return int(value)


def _validate_systemd_properties(
    values: dict[str, str], *, final: bool, assignment_run: bool
) -> dict:
    need(values["LoadState"] == "loaded", "systemd-load")
    need(values["RestrictAddressFamilies"] == "AF_UNIX", "systemd-families")
    need(values["SystemCallErrorNumber"] == "1", "systemd-errno")
    need(values["NoNewPrivileges"] == "yes", "systemd-privileges")
    need(values["LimitCORE"] == "0", "systemd-core")
    need(values["MemoryMax"] == str(12 * 1024**3), "systemd-memory")
    need(values["MemorySwapMax"] == "0", "systemd-swap-limit")
    need(values["OOMPolicy"] == "stop", "systemd-oom-policy")
    need(values["NRestarts"] == "0", "systemd-restarts")
    need(values["UMask"] == "0077", "systemd-umask")
    need(values["ExecMainStatus"].isdigit(), "systemd-exec-status")
    need(
        values["UnsetEnvironment"].split() == list(ALL_UNSET_ENVIRONMENT),
        "systemd-unset-environment",
    )
    need(
        values["Environment"].split() == list(FIXED_ENVIRONMENT),
        "systemd-environment",
    )
    expected_output = "null" if assignment_run else "journal"
    need(
        values["StandardInput"] == "null"
        and values["StandardOutput"] == expected_output
        and values["StandardError"] == expected_output,
        "systemd-stdio",
    )
    syscall_filter = values["SystemCallFilter"]
    need(syscall_filter.startswith("~"), "systemd-filter-form")
    denied = set(syscall_filter[1:].split())
    need(denied == STRICT_DENIED_NETWORK_SYSCALLS, "systemd-filter")
    memory_peak = _metric(values["MemoryPeak"], allow_unset=not final)
    swap_current = _metric(values["MemorySwapCurrent"], allow_unset=True)
    swap_peak = _metric(values["MemorySwapPeak"], allow_unset=True)
    if final:
        need(
            values["ActiveState"] == "active"
            and values["SubState"] == "exited"
            and values["Result"] == "success"
            and values["ExecMainStatus"] == "0"
            and memory_peak is not None
            and memory_peak > 0
            and swap_current in (None, 0)
            and swap_peak in (None, 0),
            "systemd-final",
        )
    return {
        "active_state": values["ActiveState"],
        "sub_state": values["SubState"],
        "result": values["Result"],
        "exec_main_status": int(values["ExecMainStatus"]),
        "restrict_address_families": "AF_UNIX",
        "denied_network_syscalls": sorted(denied),
        "system_call_error_number": 1,
        "no_new_privileges": True,
        "limit_core_bytes": 0,
        "memory_max_bytes": int(values["MemoryMax"]),
        "memory_swap_max_bytes": 0,
        "memory_peak_bytes": memory_peak,
        "memory_swap_current_bytes": swap_current,
        "memory_swap_peak_bytes": swap_peak,
        "oom_policy": "stop",
        "restart_count": 0,
        "umask_octal": "0077",
        "standard_input": "null",
        "standard_output": expected_output,
        "standard_error": expected_output,
    }


def _systemd_prefix(unit: str) -> list[str]:
    need(unit in (PROBE_UNIT, RUN_UNIT), "unit-name")
    command = [
        str(SYSTEMD_RUN),
        "--user",
        "--quiet",
        "--no-block",
        "--remain-after-exit",
        f"--unit={unit}",
        "--service-type=exec",
        "--expand-environment=no",
    ]
    properties = RUN_SYSTEMD_PROPERTIES if unit == RUN_UNIT else PROBE_SYSTEMD_PROPERTIES
    for value in properties:
        command.extend(("--property", value))
    for value in FIXED_ENVIRONMENT:
        command.extend(("--setenv", value))
    return command


def _probe_command() -> list[str]:
    return _systemd_prefix(PROBE_UNIT) + [
        str(PYTHON),
        "-I",
        "-c",
        NETWORK_PROBE_SOURCE,
    ]


def _run_command() -> list[str]:
    command = _systemd_prefix(RUN_UNIT)
    command.extend((str(PYTHON), "-I", "-c", _identity_bound_exec_source()))
    return command


def _show_unit(unit: str) -> tuple[dict[str, str], bytes]:
    command = [str(SYSTEMCTL), "--user", "show", f"{unit}.service"]
    for name in SHOW_PROPERTIES:
        command.extend(("--property", name))
    command.append("--no-pager")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    need(result.returncode == 0 and not result.stderr, "systemd-show")
    return _parse_show(result.stdout), result.stdout


def _journal(unit: str) -> bytes:
    result = subprocess.run(
        [
            str(JOURNALCTL),
            "--user",
            "--unit",
            f"{unit}.service",
            "--no-pager",
            "--output=cat",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    need(result.returncode == 0 and not result.stderr, "journal-read")
    raw = result.stdout
    lowered = raw.lower()
    for forbidden in (
        b"proceeding without",
        b"does not support",
        b"failed to apply",
        b"unknown lvalue",
        b"invalid argument",
        b"out of memory",
        b"oom-kill",
        b"memory cgroup out of memory",
        b"killed process",
        b"core-dump",
        b"code=dumped",
    ):
        need(forbidden not in lowered, "journal-failure")
    return raw


def _stop_unit(unit: str) -> None:
    result = subprocess.run(
        [str(SYSTEMCTL), "--user", "stop", f"{unit}.service"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    need(result.returncode == 0, "unit-stop")


def _run_transient(
    unit: str,
    command: list[str],
    *,
    require_running_observation: bool,
) -> dict:
    prefix = _systemd_prefix(unit)
    need(command[: len(prefix)] == prefix, "unit-command-prefix")
    assignment_run = unit == RUN_UNIT
    start = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    need(
        start.returncode == 0 and not start.stdout and not start.stderr,
        "unit-start",
    )
    first_evidence = None
    first_show_raw = b""
    live_evidence = None
    live_show_raw = b""
    final_evidence = None
    final_show_raw = b""
    journal_raw = b""
    try:
        while True:
            values, observed_raw = _show_unit(unit)
            if values["LoadState"] == "loaded":
                observed = _validate_systemd_properties(
                    values, final=False, assignment_run=assignment_run
                )
                if first_evidence is None:
                    first_evidence = observed
                    first_show_raw = observed_raw
                if (
                    live_evidence is None
                    and values["ActiveState"] == "active"
                    and values["SubState"] in ("start", "start-pre", "running")
                ):
                    live_evidence = observed
                    live_show_raw = observed_raw
                if values["SubState"] in ("exited", "failed", "dead"):
                    final_evidence = _validate_systemd_properties(
                        values, final=True, assignment_run=assignment_run
                    )
                    final_show_raw = observed_raw
                    break
            time.sleep(0.1)
        need(first_evidence is not None, "unit-first-evidence")
        if require_running_observation:
            need(live_evidence is not None, "unit-live-running-evidence")
        elif live_evidence is None:
            live_evidence = first_evidence
            live_show_raw = first_show_raw
        journal_raw = _journal(unit)
    finally:
        _stop_unit(unit)
    need(
        live_evidence is not None and final_evidence is not None,
        "unit-evidence",
    )
    return {
        "unit": f"{unit}.service",
        "command_sha256": sha256_bytes(canonical(command)),
        "start_stdout_bytes": len(start.stdout),
        "start_stdout_sha256": sha256_bytes(start.stdout),
        "start_stderr_bytes": len(start.stderr),
        "start_stderr_sha256": sha256_bytes(start.stderr),
        "live": {
            "running_observed": live_evidence["sub_state"]
            in ("start", "start-pre", "running"),
            "properties": live_evidence,
            "show_bytes": len(live_show_raw),
            "show_sha256": sha256_bytes(live_show_raw),
        },
        "final": {
            "properties": final_evidence,
            "show_bytes": len(final_show_raw),
            "show_sha256": sha256_bytes(final_show_raw),
        },
        "properties": final_evidence,
        "show_bytes": len(final_show_raw),
        "show_sha256": sha256_bytes(final_show_raw),
        "journal_bytes": len(journal_raw),
        "journal_sha256": sha256_bytes(journal_raw),
        "stdout": {
            "transport": "null" if assignment_run else "systemd-journal",
            "child_output_persisted": False,
            "success_marker_reliance": False,
        },
        "stderr": {
            "transport": "null" if assignment_run else "systemd-journal",
            "child_output_persisted": False,
        },
        "identity_bound_exec_helper": (
            _identity_bound_helper_reference() if assignment_run else None
        ),
        "result": "success",
        "exec_main_status": 0,
        "unit_stopped_after_capture": True,
    }


def validate_assignment_receipt(value: object) -> None:
    need(type(value) is dict and set(value) == ASSIGNMENT_KEYS, "assignment-keys")
    need(
        EXPECTED_PUBLIC_INPUTS == _derived_expected_public_inputs(),
        "assignment-public-input-derivation",
    )
    for key in (
        "selected_round",
        "prepared_instances",
        "prepared_witnesses",
        "prepared_variables",
        "historical_component_expected_constraints",
        "current_preparer_observed_constraints",
        "rounds_validated",
        "output_proofs_verified",
        "signature_relations_satisfied",
        "peak_rss_kib",
        "current_swap_kib",
    ):
        need(type(value[key]) is int, "assignment-integer-type")
    need(
        value["schema"] == "kpb-frozen-w1-round1-assignment-preparation/v3"
        and value["classification"]
        == "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_PREPARATION_ONLY"
        and value["historical_component_run_id"]
        == "2904ab69-cc9e-40ce-834f-07a56cd15bbc"
        and value["historical_component_source_instance_epoch_id"]
        == "d3d47403-5350-414d-a133-2447bb28da5a"
        and value["historical_component_source_closure_sha256"]
        == "8fcca654b4eb03b38a62c22648cd14323919279dc49d841751d3802683c66aae"
        and value["historical_component_selected_build_identity_sha256"]
        == "eee5536d5bcab041c7f98476ba6a5b8c4e8632373cc51b7087a568866072a55a"
        and value["historical_component_plan_sha256"]
        == "8b24a987f87d2bd9dca0b04f4622022eac0e04724af06ff761141169f0853482"
        and value["historical_source_bundle_manifest_sha256"]
        == "8db2a202c0c2547af841bade48f49168d093fa74ff18620573f041f6fcfbcfbd"
        and value["historical_component_expected_matrix_sha256"]
        == "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab"
        and value["selected_round"] == 1
        and value["prepared_instances"] == 3
        and value["prepared_witnesses"] == 12_949_818
        and value["prepared_variables"] == 12_949_821
        and value["historical_component_expected_constraints"] == 13_093_029
        and value["current_preparer_observed_constraints"] == 0
        and value["rounds_validated"] == 2
        and value["output_proofs_verified"] == 12
        and value["signature_relations_satisfied"] == 6
        and type(value["derived_public_inputs_decimal"]) is list
        and tuple(value["derived_public_inputs_decimal"]) == EXPECTED_PUBLIC_INPUTS,
        "assignment-values",
    )
    elapsed = value["elapsed_seconds"]
    need(
        type(elapsed) in (int, float)
        and math.isfinite(elapsed)
        and elapsed >= 0.0
        and type(value["peak_rss_kib"]) is int
        and value["peak_rss_kib"] > 0
        and value["current_swap_kib"] == 0,
        "assignment-resources",
    )
    for key in ASSIGNMENT_FALSE_FIELDS:
        need(value[key] is False, "assignment-false-field")
    for key in ASSIGNMENT_TRUE_FIELDS:
        need(value[key] is True, "assignment-true-field")


def _assignment_receipt_reference() -> tuple[dict, dict]:
    raw, reference = _stable_file(ASSIGNMENT_RECEIPT, 0o400)
    need(raw.endswith(b"\n"), "assignment-newline")
    value = _unique_json(raw)
    validate_assignment_receipt(value)
    return value, reference


def _write_new(path: Path, raw: bytes, mode: int) -> dict:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            need(count > 0, "write-progress")
            view = view[count:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _, reference = _stable_file(path, mode, expected_sha256=sha256_bytes(raw))
    return reference


def _rename_no_replace(directory_fd: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    need(renameat2 is not None, "renameat2-unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(target),
        1,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise Refused("launch-receipt-exists")
        raise OSError(error, os.strerror(error))


def _fixed_actions() -> dict:
    return {
        "build_validation": True,
        "strict_network_preflight": True,
        "assignment_binary_execution": True,
        "assignment_synthesis": True,
        "assignment_shape_validation": True,
        "current_r1cs_constraint_rows_recorded": False,
        "current_r1cs_constraint_satisfaction": False,
        "current_r1cs_lc_assignments_generated": False,
        "assignment_receipt_validation": True,
        "historical_component_validation": True,
        "historical_output_proof_verification": True,
        "signature_relation_satisfaction": True,
        "assignment_serialization": False,
        "setup": False,
        "pk_decode": False,
        "proving_key_read": False,
        "aggregate_proof_generation": False,
        "aggregate_proof_verification": False,
        "network_communication": False,
        "funds": False,
        "authorization": False,
    }


def _receipt_identity(value: dict) -> dict:
    result = dict(value)
    need("receipt_identity_sha256" not in result, "receipt-preidentified")
    result["receipt_identity_sha256"] = sha256_bytes(canonical(result))
    return result


def _publish_launch_evidence(supervisor_raw: bytes, receipt: dict) -> dict:
    source_ref = _write_new(SUPERVISOR_SOURCE, supervisor_raw, 0o400)
    receipt_raw = canonical(receipt)
    staging_name = f".LAUNCH-RECEIPT.json.staging-{uuid.uuid4()}"
    staging = RUN_ROOT / staging_name
    staging_ref = _write_new(staging, receipt_raw, 0o400)
    directory_fd = os.open(
        RUN_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        _rename_no_replace(directory_fd, staging_name, LAUNCH_RECEIPT.name)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    _, final_ref = _stable_file(
        LAUNCH_RECEIPT, 0o400, expected_sha256=staging_ref["sha256"]
    )
    need(
        set(os.listdir(RUN_ROOT))
        == {ASSIGNMENT_RECEIPT.name, SUPERVISOR_SOURCE.name, LAUNCH_RECEIPT.name},
        "run-root-files",
    )
    os.chmod(RUN_ROOT, 0o500, follow_symlinks=False)
    directory_fd = os.open(
        LOCAL_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    _directory(RUN_ROOT, 0o500)
    return {
        "supervisor_source_sha256": source_ref["sha256"],
        "launch_receipt_sha256": final_ref["sha256"],
    }


def _create_run_root() -> None:
    need(not os.path.lexists(RUN_ROOT), "run-root-create-new")
    os.mkdir(RUN_ROOT, 0o700)
    _directory(RUN_ROOT, 0o700)
    directory_fd = os.open(
        LOCAL_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def run_measurement() -> dict:
    need(os.geteuid() != 0, "root-refused")
    need(Path.cwd().resolve(strict=True) == REPO_ROOT, "cwd-repo-root")
    _directory(LOCAL_ROOT, stat.S_IMODE(os.lstat(LOCAL_ROOT).st_mode))
    for tool in (PYTHON, SYSTEMD_RUN, SYSTEMCTL, JOURNALCTL):
        value = os.lstat(tool.resolve(strict=True))
        need(stat.S_ISREG(value.st_mode) and os.access(tool, os.X_OK), "tool")
    source_path = Path(__file__).resolve(strict=True)
    supervisor_raw, supervisor_initial = _stable_file(
        source_path, stat.S_IMODE(os.lstat(source_path).st_mode)
    )
    build_before = validate_build_bundle()
    manager_environment = _validate_manager_environment()
    _create_run_root()
    probe = _run_transient(
        PROBE_UNIT,
        _probe_command(),
        require_running_observation=False,
    )
    probe["af_inet_af_inet6_af_unix_socket_denied_with_eperm"] = True
    probe["exact_fixed_environment_observed"] = True
    probe["network_communication_performed"] = False
    runtime = _run_transient(
        RUN_UNIT,
        _run_command(),
        require_running_observation=True,
    )
    assignment_value, assignment_ref = _assignment_receipt_reference()
    build_after = validate_build_bundle()
    need(build_after == build_before, "build-changed-during-run")
    supervisor_after_raw, supervisor_after = _stable_file(
        source_path, stat.S_IMODE(os.lstat(source_path).st_mode)
    )
    need(
        supervisor_after_raw == supervisor_raw
        and supervisor_after == supervisor_initial,
        "supervisor-source-changed",
    )
    receipt = _receipt_identity(
        {
            "schema": RECEIPT_SCHEMA,
            "classification": CLASSIFICATION,
            "fixed_no_argument_entrypoint": True,
            "build_bundle": build_before,
            "binary": build_before["references"]["binary"],
            "identity_bound_exec_helper": _identity_bound_helper_reference(),
            "manager_environment": manager_environment,
            "strict_network_preflight": probe,
            "assignment_runtime": runtime,
            "assignment_receipt": assignment_ref,
            "assignment_receipt_validation": {
                "exact_schema": assignment_value["schema"],
                "exact_key_set_sha256": sha256_bytes(
                    canonical(sorted(ASSIGNMENT_KEYS))
                ),
                "selected_round": assignment_value["selected_round"],
                "prepared_instances": assignment_value["prepared_instances"],
                "prepared_witnesses": assignment_value["prepared_witnesses"],
                "prepared_variables": assignment_value["prepared_variables"],
                "historical_component_expected_constraints": assignment_value[
                    "historical_component_expected_constraints"
                ],
                "current_preparer_observed_constraints": assignment_value[
                    "current_preparer_observed_constraints"
                ],
                "current_preparer_constraint_rows_recorded": assignment_value[
                    "current_preparer_constraint_rows_recorded"
                ],
                "current_preparer_constraint_satisfaction_checked": assignment_value[
                    "current_preparer_constraint_satisfaction_checked"
                ],
                "rounds_validated": assignment_value["rounds_validated"],
                "output_proofs_verified": assignment_value[
                    "output_proofs_verified"
                ],
                "signature_relations_satisfied": assignment_value[
                    "signature_relations_satisfied"
                ],
                "all_required_true_flags_validated": True,
                "all_required_false_flags_validated": True,
                "unexpected_or_fingerprint_fields_absent": True,
            },
            "assignment_public_inputs_decimal": assignment_value[
                "derived_public_inputs_decimal"
            ],
            "assignment_public_inputs_derivation": {
                "round1_effects_core_sha256": EXPECTED_ROUND1_EFFECTS_CORE_SHA256,
                "split": "two-16-byte-little-endian-unsigned-integers",
                "independently_derived": list(_derived_expected_public_inputs()),
            },
            "assignment_peak_rss_kib": assignment_value["peak_rss_kib"],
            "assignment_current_swap_kib": assignment_value["current_swap_kib"],
            "supervisor_source": supervisor_initial,
            "full_secret_zeroization": False,
            "error_path_source_zeroization_complete": False,
            "abort_oom_zeroization": False,
            "assignment_serialized": False,
            "proving_key_opened": False,
            "aggregate_proof_generated": False,
            "network_communication": False,
            "setup": False,
            "funds": False,
            "privacy_acceptance": False,
            "financial_acceptance": False,
            "production_authority": False,
            "authorization": False,
            "actions": _fixed_actions(),
        }
    )
    evidence = _publish_launch_evidence(supervisor_raw, receipt)
    return {
        "status": "FROZEN_W1_ROUND1_ASSIGNMENT_PREPARED_NO_PROOF",
        "classification": CLASSIFICATION,
        "run_root": str(RUN_ROOT),
        "assignment_receipt_sha256": assignment_ref["sha256"],
        "binary_sha256": build_before["references"]["binary"]["sha256"],
        "memory_peak_bytes": runtime["properties"]["memory_peak_bytes"],
        "swap_peak_bytes": runtime["properties"]["memory_swap_peak_bytes"],
        "evidence": evidence,
        "proof": False,
        "network_communication": False,
        "authorization": False,
    }


def main(arguments: list[str] | None = None) -> int:
    if arguments is None:
        arguments = sys.argv[1:]
    try:
        need(type(arguments) is list and not arguments, "arguments-not-accepted")
        result = run_measurement()
    except (Refused, FileExistsError, OSError) as error:
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
