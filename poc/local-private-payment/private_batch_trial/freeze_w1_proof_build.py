#!/usr/bin/env python3
"""Freeze the fixed, reviewed W1 proof and verifier examples as build evidence.

This no-argument entrypoint is deliberately inert while
``REVIEWED_PROOF_SEAM_SHA256`` is ``None``. Once an independent review clears
the proof seam and that gate is explicitly bound, it snapshots the four local
Cargo packages plus the path-compiled low-memory prover, runs one locked and
offline release build for both examples under a systemd unit that denies IP
sockets and addressed AF_UNIX relay while retaining connected process-tree
local IPC, and atomically publishes detached source/binaries/dep-info/receipt
evidence.

Neither binary is dispatched. This performs no setup, proving-key read,
synthesis, proof, verification, network communication, or funds action. It
does not claim a filesystem-hermetic build, toolchain closure, production
authority, cryptographic correctness, or privacy.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import tomllib
import uuid

import freeze_current_w1_source_build as core


SCHEMA = "kpb-w1-proof-build-freezer/v1"
RECEIPT_SCHEMA = "kpb-w1-proof-build-receipt/v1"
CLASSIFICATION = "TEST_ONLY_COMBINED_W1_PROOF_BUILD_NOT_AUTHORITY"

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
PRIVATE_OUTPUT_BASE = Path("/home/luke/projects/kpi-intensive-2026-10-22")
OUTPUT_PARENT = (
    PRIVATE_OUTPUT_BASE / "private-batch-w1-proof-build-private-20261029-01"
)
OUTPUT_NAME = "w1-proof-build"
EVIDENCE_NAME = "w1-proof-build-contract"
RELATION_RELATIVE = "poc/local-private-payment/private-batch-relation"
PACKAGE_ROOTS = (RELATION_RELATIVE,)
EXPECTED_PACKAGE_ROOTS = (
    "poc/local-private-payment/native-authority/native-core",
    "poc/local-private-payment/native-authority/vendor/native-relation",
    "poc/local-private-payment/private-batch-relation",
    "poc/local-private-payment/private_batch_trial/auth_exit",
)
PROOF_EXAMPLE_NAME = "prove_frozen_w1_round1"
VERIFIER_EXAMPLE_NAME = "verify_frozen_w1_round1_receipt"
EXAMPLE_NAME = PROOF_EXAMPLE_NAME
EXAMPLE_NAMES = (PROOF_EXAMPLE_NAME, VERIFIER_EXAMPLE_NAME)
FEATURE_NAME = "offline-w1-prover"

CARGO = Path(
    "/home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo"
)
RUSTC = Path(
    "/home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc"
)
RUSTDOC = Path(
    "/home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustdoc"
)
CC = Path("/usr/bin/x86_64-linux-gnu-gcc-15")
CXX = Path("/usr/bin/x86_64-linux-gnu-g++-15")
AR = Path("/usr/bin/x86_64-linux-gnu-ar")
RANLIB = Path("/usr/bin/x86_64-linux-gnu-ranlib")
LINKER = Path("/usr/bin/x86_64-linux-gnu-ld.bfd")
ENV = Path("/usr/bin/env")
PYTHON = Path("/usr/bin/python3")
TRUE = Path("/bin/true")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
JOURNALCTL = Path("/usr/bin/journalctl")
PROBE_UNIT_PREFIX = "kpb-w1-proof-freeze-netprobe-"
BUILD_UNIT_PREFIX = "kpb-w1-proof-freeze-build-"
UNIT_LEDGER_NAME = "UNIT-IDENTITY-LEDGER"
UNIT_RUN_IDENTITY_SCHEMA = "kpb-w1-proof-build-unit-run-identity/v1"
UNIT_RESERVATION_SCHEMA = "kpb-w1-proof-build-unit-reservation/v1"
UNIT_CONSUMPTION_SCHEMA = "kpb-w1-proof-build-unit-consumption/v1"
REVIEW_SNAPSHOT_BINDING_SCHEMA = "kpb-w1-review-snapshot-binding/v1"
BUILD_BOOTSTRAP_SCHEMA = "kpb-w1-proof-build-bootstrap/v1"

# Deliberately unbound. Only the parent may populate this exact map after an
# independent proof-seam review says GO. run_freeze() checks it before creating
# the output parent, starting a unit, or invoking Cargo.
REVIEWED_PROOF_SEAM_SHA256: dict[str, str] | None = None
# Separately unbound executable-leaf identities. The independent build review
# must bind exact hashes and version-output hashes before a build is possible.
REVIEWED_BUILD_TOOL_IDENTITIES: dict[str, dict] | None = None
REVIEWED_PROOF_SEAM_RELATIVES = (
    "poc/local-private-payment/private-batch-relation/Cargo.toml",
    "poc/local-private-payment/private-batch-relation/Cargo.lock",
    "poc/local-private-payment/private-batch-relation/examples/prove_frozen_w1_round1.rs",
    "poc/local-private-payment/private-batch-relation/examples/verify_frozen_w1_round1_receipt.rs",
    "poc/local-private-payment/private-batch-relation/src/lib.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_assignment.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_prover.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/source_only_runner.rs",
    "poc/local-private-payment/native-authority/native-core/src/lib.rs",
    "poc/local-private-payment/native-authority/vendor/native-relation/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/auth_exit/src/lib.rs",
)
PATH_COMPILED_SOURCE_RELATIVES = (
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/source_only_runner.rs",
)
REQUIRED_PROOF_DEPENDENCY_RELATIVES = {
    "poc/local-private-payment/private-batch-relation/examples/prove_frozen_w1_round1.rs",
    "poc/local-private-payment/private-batch-relation/src/lib.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_assignment.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_prover.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/source_only_runner.rs",
    "poc/local-private-payment/native-authority/native-core/src/lib.rs",
    "poc/local-private-payment/native-authority/vendor/native-relation/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/auth_exit/src/lib.rs",
}
REQUIRED_VERIFIER_DEPENDENCY_RELATIVES = {
    "poc/local-private-payment/private-batch-relation/examples/verify_frozen_w1_round1_receipt.rs",
    "poc/local-private-payment/private-batch-relation/src/lib.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_assignment.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_prover.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/source_only_runner.rs",
    "poc/local-private-payment/native-authority/native-core/src/lib.rs",
    "poc/local-private-payment/native-authority/vendor/native-relation/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/auth_exit/src/lib.rs",
}
REQUIRED_DEPENDENCY_RELATIVES = (
    REQUIRED_PROOF_DEPENDENCY_RELATIVES
    | REQUIRED_VERIFIER_DEPENDENCY_RELATIVES
)
PROOF_EXECUTION_MARKER_NAMES = frozenset(
    {
        "PROOF-EXECUTION-MARKER",
        "VERIFIER-EXECUTION-MARKER",
        "PROOF-RECEIPT.json",
        "LAUNCH-RECEIPT.json",
    }
)

DENIED_BUILD_NETWORK_SYSCALLS = (
    "accept", "accept4", "bind", "connect", "getpeername", "getsockname",
    "getsockopt", "listen", "recvmmsg", "recvmmsg_time64", "recvmsg",
    "sendmmsg", "sendmsg", "setsockopt", "shutdown", "socketcall",
    "sendto", "recvfrom",
    "io_uring_enter", "io_uring_register", "io_uring_setup",
    "pidfd_getfd", "ptrace", "process_vm_readv", "process_vm_writev",
)
BOOTSTRAP_UNSET_ENVIRONMENT = (
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
    "LD_DEBUG_OUTPUT", "LD_PROFILE", "LD_SHOW_AUXV", "GLIBC_TUNABLES",
    "GCONV_PATH", "LOCPATH", "PYTHONPATH", "PYTHONHOME", "PYTHONINSPECT",
    "PYTHONSTARTUP", "PYTHONBREAKPOINT", "PYTHONWARNINGS", "PYTHONMALLOC",
    "RUSTC", "RUSTDOC", "RUSTUP_TOOLCHAIN", "CARGO_BUILD_TARGET",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
    "CC", "CXX", "AR", "RANLIB", "CFLAGS", "CXXFLAGS", "LDFLAGS",
    "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
    "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES", "NOTIFY_SOCKET",
    "WATCHDOG_PID", "WATCHDOG_USEC",
)
SYSTEMD_PROPERTIES = (
    "SystemCallFilter=~" + " ".join(DENIED_BUILD_NETWORK_SYSCALLS),
    "SystemCallErrorNumber=EPERM",
    "SystemCallArchitectures=native",
    "RestrictAddressFamilies=AF_UNIX",
    "NoNewPrivileges=yes",
    "LimitCORE=0",
    "MemoryMax=20G",
    "MemorySwapMax=0",
    "UMask=0077",
    "UnsetEnvironment=" + " ".join(BOOTSTRAP_UNSET_ENVIRONMENT),
    "StandardInput=null",
    "StandardOutput=null",
    "StandardError=null",
)
SHOW_PROPERTIES = (
    "LoadState", "ActiveState", "SubState", "Result", "ExecMainStatus",
    "RestrictAddressFamilies", "SystemCallFilter", "SystemCallErrorNumber",
    "SystemCallArchitectures",
    "NoNewPrivileges", "LimitCORE", "MemoryMax", "MemorySwapMax", "UMask",
    "UnsetEnvironment", "StandardInput", "StandardOutput", "StandardError",
    "InvocationID", "ExecMainPID", "Sockets", "TriggeredBy", "Triggers",
)

BUILD_TOOL_PATHS = {
    "cargo": CARGO,
    "rustc": RUSTC,
    "rustdoc": RUSTDOC,
    "cc": CC,
    "cxx": CXX,
    "ar": AR,
    "ranlib": RANLIB,
    "linker": LINKER,
    "env": ENV,
    "python": PYTHON,
    "true": TRUE,
    "systemd_run": SYSTEMD_RUN,
    "systemctl": SYSTEMCTL,
    "journalctl": JOURNALCTL,
}
ROOT_OWNED_BUILD_TOOLS = {
    "cc", "cxx", "ar", "ranlib", "linker", "env", "python", "true",
    "systemd_run", "systemctl", "journalctl",
}
TOOLCHAIN_ROOT = CARGO.parents[1]
LOCKED_REGISTRY_SOURCE_ROOT = Path(
    "/home/luke/projects/kpi-intensive-2026-10-22/binding-cargo-home/"
    "registry/src/index.crates.io-1949cf8c6b5b557f"
)
TOOL_IDENTITY_DIRECTORIES = (
    TOOLCHAIN_ROOT,
    TOOLCHAIN_ROOT / "bin",
    TOOLCHAIN_ROOT / "lib",
    TOOLCHAIN_ROOT / "lib" / "rustlib",
    Path("/usr/bin"),
    Path("/usr/lib/cargo/bin/coreutils"),
)
CARGO_BUILD_ARGUMENTS = (
    "build", "--release", "--locked", "--offline", "--no-default-features",
    "--features", FEATURE_NAME,
    "--example", PROOF_EXAMPLE_NAME,
    "--example", VERIFIER_EXAMPLE_NAME,
)

NETWORK_PROBE_SOURCE = """\
import ctypes
import errno
import os
import socket
import stat
import subprocess

for descriptor in (0, 1, 2):
    value = os.fstat(descriptor)
    if not stat.S_ISCHR(value.st_mode) or os.readlink(f"/proc/self/fd/{descriptor}") != "/dev/null":
        raise SystemExit(10)
live_descriptors = []
for raw_descriptor in os.listdir("/proc/self/fd"):
    descriptor = int(raw_descriptor)
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise SystemExit(11)
    else:
        live_descriptors.append(descriptor)
if sorted(live_descriptors) != [0, 1, 2]:
    raise SystemExit(12)

for family in (socket.AF_INET, socket.AF_INET6):
    try:
        socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EAFNOSUPPORT:
            raise SystemExit(2)
    else:
        raise SystemExit(3)

standalone = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
datagram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
if os.write(left.fileno(), b"x") != 1 or os.read(right.fileno(), 1) != b"x":
    raise SystemExit(6)
subprocess.run(["/bin/true"], check=True)
try:
    standalone.connect("\\0kpb-proof-build-network-probe")
except OSError as error:
    if error.errno != errno.EPERM:
        raise SystemExit(4)
else:
    raise SystemExit(5)
try:
    datagram.sendto(b"x", "\\0kpb-proof-build-datagram-probe")
except OSError as error:
    if error.errno != errno.EPERM:
        raise SystemExit(7)
else:
    raise SystemExit(8)
try:
    datagram.recvfrom(1)
except OSError as error:
    if error.errno != errno.EPERM:
        raise SystemExit(9)
else:
    raise SystemExit(13)

libc = ctypes.CDLL(None, use_errno=True)
for number, arguments in (
    (425, (0, 0)),
    (426, (-1, 0, 0, 0, 0, 0)),
    (427, (-1, 0, 0, 0)),
    (438, (-1, -1, 0)),
    (101, (16, -1, 0, 0)),
    (310, (-1, 0, 0, 0, 0, 0)),
    (311, (-1, 0, 0, 0, 0, 0)),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *arguments)
    observed_errno = ctypes.get_errno()
    if result != -1 or observed_errno not in (errno.EPERM, errno.ENOSYS):
        raise SystemExit(14)
standalone.close()
datagram.close()
left.close()
right.close()
"""

BUILD_BOOTSTRAP_SOURCE = f"""\
import errno
import hashlib
import os
import stat
import sys

if len(sys.argv) != 6:
    raise SystemExit(20)
target_root, cargo_sha256, cargo_bytes_raw, cargo_mtime_raw, cargo_ctime_raw = sys.argv[1:]
if not os.path.isabs(target_root) or os.path.normpath(target_root) != target_root:
    raise SystemExit(21)
expected_environment = dict(
    item.split("=", 1)
    for item in (
        "HOME=/home/luke",
        "PATH=/usr/bin:/bin",
        f"CARGO_HOME={{target_root}}/isolated-cargo-home",
        "CARGO_NET_OFFLINE=true",
        f"CARGO_TARGET_DIR={{target_root}}",
        "CARGO_INCREMENTAL=0",
        "CARGO_TERM_COLOR=never",
        "RUSTC_WRAPPER=",
        "RUSTC_WORKSPACE_WRAPPER=",
        "RUSTFLAGS=",
        "CARGO_ENCODED_RUSTFLAGS=",
        "RUSTC={RUSTC}",
        "RUSTDOC={RUSTDOC}",
        "CC={CC}",
        "CXX={CXX}",
        "AR={AR}",
        "RANLIB={RANLIB}",
        "LD={LINKER}",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER={CC}",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=",
        "HTTP_PROXY=",
        "HTTPS_PROXY=",
        "ALL_PROXY=",
        "NO_PROXY=",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "TZ=UTC",
    )
)
if dict(os.environ) != expected_environment:
    raise SystemExit(22)
for descriptor in (0, 1, 2):
    value = os.fstat(descriptor)
    if not stat.S_ISCHR(value.st_mode) or os.readlink(f"/proc/self/fd/{{descriptor}}") != "/dev/null":
        raise SystemExit(23)
live_descriptors = []
for raw_descriptor in os.listdir("/proc/self/fd"):
    descriptor = int(raw_descriptor)
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise SystemExit(24)
    else:
        live_descriptors.append(descriptor)
if sorted(live_descriptors) != [0, 1, 2]:
    raise SystemExit(25)
cargo_path = {str(CARGO)!r}
expected_bytes = int(cargo_bytes_raw)
expected_mtime = int(cargo_mtime_raw)
expected_ctime = int(cargo_ctime_raw)
before_path = os.lstat(cargo_path)
cargo_fd = os.open(cargo_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
before = os.fstat(cargo_fd)
if (
    not stat.S_ISREG(before.st_mode)
    or before.st_uid != os.getuid()
    or before.st_nlink != 1
    or stat.S_IMODE(before.st_mode) != 0o755
    or before.st_size != expected_bytes
    or before.st_mtime_ns != expected_mtime
    or before.st_ctime_ns != expected_ctime
    or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)
):
    raise SystemExit(26)
digest = hashlib.sha256()
offset = 0
while True:
    block = os.pread(cargo_fd, 1024 * 1024, offset)
    if not block:
        break
    digest.update(block)
    offset += len(block)
after = os.fstat(cargo_fd)
after_path = os.lstat(cargo_path)
if (
    digest.hexdigest() != cargo_sha256
    or offset != expected_bytes
    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    != (after_path.st_dev, after_path.st_ino, after_path.st_size, after_path.st_mtime_ns, after_path.st_ctime_ns)
    or os.execve not in os.supports_fd
):
    raise SystemExit(27)
os.execve(cargo_fd, [cargo_path, *{CARGO_BUILD_ARGUMENTS!r}], expected_environment)
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


def _review_gate_status() -> dict:
    return {
        "bound": REVIEWED_PROOF_SEAM_SHA256 is not None,
        "expected_relatives": list(REVIEWED_PROOF_SEAM_RELATIVES),
        "authorization": False,
    }


def _require_reviewed_source_bindings() -> dict[str, dict]:
    bindings = REVIEWED_PROOF_SEAM_SHA256
    _need(type(bindings) is dict, "proof-seam-review-go-not-bound")
    _need(set(bindings) == set(REVIEWED_PROOF_SEAM_RELATIVES),
          "proof-seam-review-binding-set")
    references: dict[str, dict] = {}
    for relative in REVIEWED_PROOF_SEAM_RELATIVES:
        expected = bindings[relative]
        _need(
            type(expected) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
            "proof-seam-review-binding-shape",
        )
        identity = _stable_file_metadata_identity(REPO_ROOT / relative)
        _need(identity["sha256"] == expected, "proof-seam-reviewed-source-hash")
        references[relative] = {
            "bytes": identity["bytes"],
            "sha256": identity["sha256"],
            "device": identity["device"],
            "inode": identity["inode"],
            "mtime_ns": identity["mtime_ns"],
            "ctime_ns": identity["ctime_ns"],
        }
    return references


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
    _need(
        LOCKED_REGISTRY_SOURCE_ROOT
        == LOCKED_REGISTRY_SOURCE_ROOT.resolve(strict=True),
        "locked-registry-source-root-canonical",
    )
    core._directory(LOCKED_REGISTRY_SOURCE_ROOT)
    for tool in BUILD_TOOL_PATHS.values():
        _need(tool.is_absolute() and tool.exists(), "fixed-tool-missing")
        resolved = tool.resolve(strict=True)
        value = os.stat(resolved, follow_symlinks=False)
        _need(stat.S_ISREG(value.st_mode) and os.access(resolved, os.X_OK),
              "fixed-tool-not-executable")


def _require_reviewed_tool_bindings() -> dict[str, dict]:
    expected = REVIEWED_BUILD_TOOL_IDENTITIES
    _need(type(expected) is dict, "build-tool-review-go-not-bound")
    _need(set(expected) == set(BUILD_TOOL_PATHS),
          "build-tool-review-binding-set")
    for name, value in expected.items():
        _need(
            type(value) is dict
            and set(value)
            == {
                "bytes", "sha256", "version_stdout_sha256",
                "version_stderr_sha256",
            }
            and type(value["bytes"]) is int
            and value["bytes"] > 0
            and all(
                type(value[key]) is str
                and re.fullmatch(r"[0-9a-f]{64}", value[key]) is not None
                for key in (
                    "sha256", "version_stdout_sha256",
                    "version_stderr_sha256",
                )
            ),
            "build-tool-review-binding-shape",
        )
    return expected


def _tool_version_argv(name: str, path: Path) -> list[str]:
    _need(name in BUILD_TOOL_PATHS and BUILD_TOOL_PATHS[name] == path,
          "build-tool-version-name")
    if name in {"cargo", "rustc", "rustdoc"}:
        return [str(path), "--version", "--verbose"]
    return [str(path), "--version"]


def _tool_path_identity(name: str, path: Path) -> dict:
    path = Path(path)
    invocation = os.lstat(path)
    _need(
        (stat.S_ISREG(invocation.st_mode) or stat.S_ISLNK(invocation.st_mode))
        and invocation.st_nlink == 1,
        "build-tool-invocation-path",
    )
    resolved = path.resolve(strict=True)
    identity = _stable_file_metadata_identity(resolved)
    expected_uid = 0 if name in ROOT_OWNED_BUILD_TOOLS else os.getuid()
    _need(
        identity["owner_uid"] == expected_uid
        and stat.S_IMODE(os.lstat(resolved).st_mode) & 0o022 == 0
        and os.access(resolved, os.X_OK),
        "build-tool-owner-or-mode",
    )
    if name in ROOT_OWNED_BUILD_TOOLS:
        _need(invocation.st_uid == 0, "build-tool-invocation-owner")
    return {
        "name": name,
        "invocation_path": str(path),
        "invocation_path_is_symlink": stat.S_ISLNK(invocation.st_mode),
        "invocation_path_device": invocation.st_dev,
        "invocation_path_inode": invocation.st_ino,
        "invocation_path_mtime_ns": invocation.st_mtime_ns,
        "invocation_path_ctime_ns": invocation.st_ctime_ns,
        "invocation_symlink_target": (
            os.readlink(path) if stat.S_ISLNK(invocation.st_mode) else None
        ),
        "resolved_path": str(resolved),
        **identity,
    }


def _capture_build_tool_identities(expected: dict[str, dict]) -> dict:
    _need(expected is REVIEWED_BUILD_TOOL_IDENTITIES or type(expected) is dict,
          "build-tool-expected-map")
    directory_before = {
        str(path): core._directory_ref(path)
        for path in TOOL_IDENTITY_DIRECTORIES
    }
    tools = {}
    version_environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }
    for name, path in BUILD_TOOL_PATHS.items():
        before = _tool_path_identity(name, path)
        argv = _tool_version_argv(name, path)
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=version_environment,
        )
        _need(result.returncode == 0, "build-tool-version-command")
        after = _tool_path_identity(name, path)
        _need(after == before, "build-tool-changed-during-version")
        evidence = {
            **before,
            "version_argv": argv,
            "version_stdout_bytes": len(result.stdout),
            "version_stdout_sha256": core.sha256_bytes(result.stdout),
            "version_stderr_bytes": len(result.stderr),
            "version_stderr_sha256": core.sha256_bytes(result.stderr),
        }
        reviewed = expected[name]
        _need(
            evidence["bytes"] == reviewed["bytes"]
            and evidence["sha256"] == reviewed["sha256"]
            and evidence["version_stdout_sha256"]
            == reviewed["version_stdout_sha256"]
            and evidence["version_stderr_sha256"]
            == reviewed["version_stderr_sha256"],
            "build-tool-reviewed-identity",
        )
        tools[name] = evidence
    directory_after = {
        str(path): core._directory_ref(path)
        for path in TOOL_IDENTITY_DIRECTORIES
    }
    _need(directory_after == directory_before,
          "build-tool-directory-changed-during-capture")
    value = {
        "tools": tools,
        "tool_count": len(tools),
        "directories": directory_before,
        "directory_count": len(directory_before),
        "versions_executed_with_cleared_environment": True,
        "user_writable_path_excluded": True,
        "full_dynamic_library_closure_bound": False,
    }
    value["identity_sha256"] = core.sha256_bytes(core.canonical(value))
    return value


def _unit_role(unit_name: str) -> str:
    _need(type(unit_name) is str, "transient-unit-name-type")
    if re.fullmatch(re.escape(PROBE_UNIT_PREFIX) + r"[0-9a-f]{32}", unit_name):
        return "network_probe"
    if re.fullmatch(re.escape(BUILD_UNIT_PREFIX) + r"[0-9a-f]{32}", unit_name):
        return "cargo_build"
    raise core.Refused("unexpected-transient-unit-name")


def _systemd_prefix(unit_name: str) -> list[str]:
    _unit_role(unit_name)
    arguments = [
        str(SYSTEMD_RUN), "--user", "--quiet", "--no-block",
        "--remain-after-exit", f"--unit={unit_name}", "--service-type=exec",
        "--expand-environment=no",
    ]
    for value in SYSTEMD_PROPERTIES:
        arguments.extend(("--property", value))
    return arguments


def _network_probe_command(unit_name: str) -> list[str]:
    _need(_unit_role(unit_name) == "network_probe", "network-probe-unit-role")
    return _systemd_prefix(unit_name) + [
        str(PYTHON), "-I", "-c", NETWORK_PROBE_SOURCE
    ]


def _cargo_environment(target_root: Path) -> tuple[str, ...]:
    target_root = Path(target_root).absolute()
    return (
        "HOME=/home/luke", "PATH=/usr/bin:/bin",
        f"CARGO_HOME={target_root / 'isolated-cargo-home'}",
        "CARGO_NET_OFFLINE=true", f"CARGO_TARGET_DIR={target_root}",
        "CARGO_INCREMENTAL=0", "CARGO_TERM_COLOR=never", "RUSTC_WRAPPER=",
        "RUSTC_WORKSPACE_WRAPPER=", "RUSTFLAGS=", "CARGO_ENCODED_RUSTFLAGS=",
        f"RUSTC={RUSTC}", f"RUSTDOC={RUSTDOC}",
        f"CC={CC}", f"CXX={CXX}", f"AR={AR}", f"RANLIB={RANLIB}",
        f"LD={LINKER}",
        f"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER={CC}",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=",
        "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=",
        "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC",
    )


def _cargo_build_command(
    snapshot_root: Path,
    target_root: Path,
    unit_name: str,
    cargo_identity: dict,
) -> list[str]:
    snapshot_root = Path(snapshot_root).absolute()
    target_root = Path(target_root).absolute()
    _need(_unit_role(unit_name) == "cargo_build", "cargo-build-unit-role")
    arguments = _systemd_prefix(unit_name)
    arguments.append(f"--working-directory={snapshot_root / RELATION_RELATIVE}")
    arguments.extend(
        (
            str(ENV), "-i", *_cargo_environment(target_root),
            str(PYTHON), "-I", "-c", BUILD_BOOTSTRAP_SOURCE,
            str(target_root), cargo_identity["sha256"],
            str(cargo_identity["bytes"]), str(cargo_identity["mtime_ns"]),
            str(cargo_identity["ctime_ns"]),
        )
    )
    _assert_build_only_command(
        arguments, snapshot_root, target_root, unit_name, cargo_identity
    )
    return arguments


def _assert_build_only_command(
    command: list[str],
    snapshot_root: Path,
    target_root: Path,
    unit_name: str,
    cargo_identity: dict,
) -> None:
    _need(type(command) is list and all(type(item) is str for item in command),
          "build-command-shape")
    snapshot_root = Path(snapshot_root).absolute()
    target_root = Path(target_root).absolute()
    expected_workdir = f"--working-directory={snapshot_root / RELATION_RELATIVE}"
    expected = [
        *_systemd_prefix(unit_name),
        expected_workdir,
        str(ENV),
        "-i",
        *_cargo_environment(target_root),
        str(PYTHON),
        "-I",
        "-c",
        BUILD_BOOTSTRAP_SOURCE,
        str(target_root),
        cargo_identity["sha256"],
        str(cargo_identity["bytes"]),
        str(cargo_identity["mtime_ns"]),
        str(cargo_identity["ctime_ns"]),
    ]
    _need(command == expected, "build-command-exact")
    env_index = command.index(str(ENV))
    python_index = command.index(str(PYTHON), env_index + 1)
    _need(
        command.count(str(ENV)) == 1
        and command.count(str(PYTHON)) == 1
        and str(CARGO) not in command
        and env_index < python_index
        and command[env_index:python_index]
        == [str(ENV), "-i", *_cargo_environment(target_root)]
        and "--setenv" not in command,
        "build-command-cleared-exact-environment",
    )
    _need(
        command[python_index:]
        == [
            str(PYTHON), "-I", "-c", BUILD_BOOTSTRAP_SOURCE,
            str(target_root), cargo_identity["sha256"],
            str(cargo_identity["bytes"]), str(cargo_identity["mtime_ns"]),
            str(cargo_identity["ctime_ns"]),
        ],
        "build-command-exact-bootstrap-tail",
    )
    _need(command.count(expected_workdir) == 1, "build-command-working-directory")
    _need(command.count(f"CARGO_TARGET_DIR={target_root}") == 1,
          "build-command-target")
    _need(
        "os.execve(cargo_fd" in BUILD_BOOTSTRAP_SOURCE
        and repr(CARGO_BUILD_ARGUMENTS) in BUILD_BOOTSTRAP_SOURCE
        and not any(value in CARGO_BUILD_ARGUMENTS for value in ("run", "test", "rustc")),
          "proof-binary-execution-command")


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
    _need(
        values["SystemCallArchitectures"] == "native",
        "systemd-syscall-architectures",
    )
    _need(values["NoNewPrivileges"] == "yes", "systemd-no-new-privileges")
    _need(values["LimitCORE"] == "0", "systemd-core-limit")
    _need(values["MemoryMax"] == str(20 * 1024**3), "systemd-memory-max")
    _need(values["MemorySwapMax"] == "0", "systemd-swap-max")
    _need(values["UMask"] == "0077", "systemd-umask")
    _need(
        set(values["UnsetEnvironment"].split())
        == set(BOOTSTRAP_UNSET_ENVIRONMENT),
        "systemd-unset-environment",
    )
    _need(
        values["StandardInput"] == "null"
        and values["StandardOutput"] == "null"
        and values["StandardError"] == "null",
        "systemd-inherited-communication-fds",
    )
    _need(
        values["Sockets"] == ""
        and values["TriggeredBy"] == ""
        and values["Triggers"] == "",
        "systemd-socket-unit-association",
    )
    _need(
        re.fullmatch(r"[0-9a-f]{32}", values["InvocationID"]) is not None
        and values["ExecMainPID"].isdigit()
        and int(values["ExecMainPID"]) > 0,
        "systemd-invocation-identity",
    )
    syscall_filter = values["SystemCallFilter"]
    _need(syscall_filter.startswith("~"), "systemd-syscall-filter-form")
    denied = set(syscall_filter[1:].split())
    _need(denied == set(DENIED_BUILD_NETWORK_SYSCALLS),
          "systemd-network-syscall-filter")
    _need(
        not {"socket", "socketpair"}.intersection(denied),
        "systemd-local-spawn-ipc-must-remain",
    )
    return {
        "restrict_address_families": values["RestrictAddressFamilies"],
        "denied_network_syscalls": sorted(denied),
        "system_call_error_number": int(values["SystemCallErrorNumber"]),
        "system_call_architectures": "native",
        "no_new_privileges": True,
        "limit_core_bytes": 0,
        "memory_max_bytes": int(values["MemoryMax"]),
        "memory_swap_max_bytes": int(values["MemorySwapMax"]),
        "umask_octal": values["UMask"],
        "unset_environment": sorted(BOOTSTRAP_UNSET_ENVIRONMENT),
        "standard_input": "null",
        "standard_output": "null",
        "standard_error": "null",
        "inherited_communication_fds": False,
        "socket_unit_associations": [],
    }


def _validate_active_unit_evidence(value: dict) -> None:
    _need(
        type(value) is dict
        and set(value)
        == {
            "restrict_address_families",
            "denied_network_syscalls",
            "system_call_error_number",
            "system_call_architectures",
            "no_new_privileges",
            "limit_core_bytes",
            "memory_max_bytes",
            "memory_swap_max_bytes",
            "umask_octal",
            "unset_environment",
            "standard_input",
            "standard_output",
            "standard_error",
            "inherited_communication_fds",
            "socket_unit_associations",
        }
        and value["restrict_address_families"] == "AF_UNIX"
        and value["denied_network_syscalls"]
        == sorted(DENIED_BUILD_NETWORK_SYSCALLS)
        and value["system_call_error_number"] == 1
        and value["system_call_architectures"] == "native"
        and value["no_new_privileges"] is True
        and value["limit_core_bytes"] == 0
        and value["memory_max_bytes"] == 20 * 1024**3
        and value["memory_swap_max_bytes"] == 0
        and value["umask_octal"] == "0077"
        and value["unset_environment"] == sorted(BOOTSTRAP_UNSET_ENVIRONMENT)
        and value["standard_input"] == "null"
        and value["standard_output"] == "null"
        and value["standard_error"] == "null"
        and value["inherited_communication_fds"] is False
        and value["socket_unit_associations"] == [],
        "systemd-active-evidence-contract",
    )


def _validate_transient_unit_evidence(
    value: dict, unit_name: str, command_sha256: str
) -> None:
    _need(
        type(value) is dict
        and value.get("unit") == f"{unit_name}.service"
        and value.get("unit_identity_was_fresh_and_consumed_before_start") is True
        and value.get("command_sha256") == command_sha256
        and type(value.get("show_sha256")) is str
        and re.fullmatch(r"[0-9a-f]{64}", value["show_sha256"]) is not None
        and type(value.get("show_bytes")) is int
        and value["show_bytes"] > 0
        and type(value.get("journal_sha256")) is str
        and re.fullmatch(r"[0-9a-f]{64}", value["journal_sha256"]) is not None
        and type(value.get("journal_bytes")) is int
        and value["journal_bytes"] >= 0
        and re.fullmatch(r"[0-9a-f]{32}", value.get("invocation_id", ""))
        is not None
        and type(value.get("exec_main_pid")) is int
        and value["exec_main_pid"] > 0
        and value.get("result") == "success"
        and value.get("exec_main_status") == 0
        and value.get("unit_stopped_after_capture") is True,
        "transient-unit-evidence-contract",
    )
    _validate_unit_identity_contract(value["unit_identity"], unit_name)
    _validate_active_unit_evidence(value["properties"])
    journal = value["journal"]
    _need(
        type(journal) is dict
        and set(journal)
        == {
            "show_invocation_id",
            "show_exec_main_pid",
            "unfiltered_command_sha256",
            "invocation_filtered_command_sha256",
            "unfiltered_equals_invocation_filtered",
            "record_count",
            "exec_main_pid_record_count",
            "all_records_current_invocation",
            "all_records_current_unit",
            "export_bytes",
            "export_sha256",
        }
        and journal["show_invocation_id"] == value["invocation_id"]
        and journal["show_exec_main_pid"] == value["exec_main_pid"]
        and journal["unfiltered_equals_invocation_filtered"] is True
        and type(journal["record_count"]) is int
        and journal["record_count"] >= 0
        and type(journal["exec_main_pid_record_count"]) is int
        and 0 <= journal["exec_main_pid_record_count"] <= journal["record_count"]
        and journal["all_records_current_invocation"] is True
        and journal["all_records_current_unit"] is True
        and journal["export_bytes"] == value["journal_bytes"]
        and journal["export_sha256"] == value["journal_sha256"]
        and all(
            type(journal[key]) is str
            and re.fullmatch(r"[0-9a-f]{64}", journal[key]) is not None
            for key in (
                "unfiltered_command_sha256",
                "invocation_filtered_command_sha256",
                "export_sha256",
            )
        ),
        "systemd-journal-evidence-contract",
    )


def _show_unit(unit_name: str) -> tuple[dict[str, str], bytes]:
    command = [str(SYSTEMCTL), "--user", "show", f"{unit_name}.service"]
    for name in SHOW_PROPERTIES:
        command.extend(("--property", name))
    command.append("--no-pager")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _need(result.returncode == 0 and not result.stderr, "systemd-show-failed")
    return _parse_show(result.stdout), result.stdout


def _inspect_pristine_unit(unit_name: str) -> dict:
    _unit_role(unit_name)
    show_command = [
        str(SYSTEMCTL), "--user", "show", f"{unit_name}.service",
        "--property=LoadState", "--value", "--no-pager",
    ]
    show = subprocess.run(
        show_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _need(
        show.returncode == 0
        and show.stderr == b""
        and show.stdout == b"not-found\n",
        "transient-unit-loaded-used-or-uninspectable",
    )
    journal_command = [
        str(JOURNALCTL), "--user", "--unit", f"{unit_name}.service",
        "--no-pager", "--quiet", "--output=export",
    ]
    journal = subprocess.run(
        journal_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _need(
        journal.returncode == 0
        and journal.stderr == b""
        and journal.stdout == b"",
        "transient-unit-historical-journal-not-empty",
    )
    return {
        "load_state": "not-found",
        "systemctl_command_sha256": core.sha256_bytes(core.canonical(show_command)),
        "systemctl_stdout_bytes": len(show.stdout),
        "systemctl_stdout_sha256": core.sha256_bytes(show.stdout),
        "historical_journal_command_sha256": core.sha256_bytes(
            core.canonical(journal_command)
        ),
        "historical_journal_bytes": 0,
        "historical_journal_sha256": core.sha256_bytes(b""),
        "historical_journal_empty": True,
    }


def _unit_record_identity(value: dict) -> dict:
    result = dict(value)
    _need("record_identity_sha256" not in result, "unit-record-preidentified")
    result["record_identity_sha256"] = core.sha256_bytes(core.canonical(result))
    return result


def _unit_record_reference(path: Path, expected_name: str) -> dict:
    identity = _stable_file_metadata_identity(path, 0o400)
    return {
        "name": expected_name,
        "path": str(Path(path).absolute()),
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
        "mode_octal": "0400",
        "link_count": 1,
        "device": identity["device"],
        "inode": identity["inode"],
        "owner_uid": identity["owner_uid"],
        "mtime_ns": identity["mtime_ns"],
        "ctime_ns": identity["ctime_ns"],
    }


def _load_unit_record(path: Path, schema: str) -> tuple[dict, dict]:
    raw, identity = core._stable_file_bytes(path, 0o400)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise core.Refused("unit-record-json") from None
    _need(
        type(value) is dict
        and raw == core.canonical(value)
        and value.get("schema") == schema,
        "unit-record-canonical-schema",
    )
    unsigned = dict(value)
    claimed = unsigned.pop("record_identity_sha256", None)
    _need(
        claimed == core.sha256_bytes(core.canonical(unsigned)),
        "unit-record-identity",
    )
    return value, identity


def _validate_unit_record_pair(unit_root: Path, unit_name: str) -> None:
    role = _unit_role(unit_name)
    reservation, reservation_identity = _load_unit_record(
        unit_root / "RESERVATION.json", UNIT_RESERVATION_SCHEMA
    )
    consumption, _ = _load_unit_record(
        unit_root / "CONSUMPTION.json", UNIT_CONSUMPTION_SCHEMA
    )
    _need(
        set(reservation)
        == {
            "schema",
            "unit_name",
            "service_unit",
            "role",
            "reservation_id",
            "command_sha256",
            "private_output_parent",
            "identity_reserved_create_new",
            "systemd_start_dispatched",
            "authorization",
            "record_identity_sha256",
        }
        and reservation["unit_name"] == unit_name
        and reservation["service_unit"] == f"{unit_name}.service"
        and reservation["role"] == role
        and _is_canonical_uuid(reservation["reservation_id"])
        and reservation["private_output_parent"] == str(OUTPUT_PARENT)
        and reservation["identity_reserved_create_new"] is True
        and reservation["systemd_start_dispatched"] is False
        and reservation["authorization"] is False,
        "unit-reservation-record-contract",
    )
    _need(
        set(consumption)
        == {
            "schema",
            "unit_name",
            "service_unit",
            "role",
            "reservation_id",
            "reservation_sha256",
            "command_sha256",
            "identity_consumed_before_start",
            "pristine_observation_required_after_consumption",
            "systemd_start_dispatched",
            "authorization",
            "record_identity_sha256",
        }
        and consumption["unit_name"] == unit_name
        and consumption["service_unit"] == f"{unit_name}.service"
        and consumption["role"] == role
        and consumption["reservation_id"] == reservation["reservation_id"]
        and consumption["reservation_sha256"] == reservation_identity["sha256"]
        and consumption["command_sha256"] == reservation["command_sha256"]
        and consumption["identity_consumed_before_start"] is True
        and consumption["pristine_observation_required_after_consumption"] is True
        and consumption["systemd_start_dispatched"] is False
        and consumption["authorization"] is False,
        "unit-consumption-record-contract",
    )


def _seal_unit_identity_directory(path: Path) -> None:
    core._fsync_directory(path)
    os.chmod(path, 0o500, follow_symlinks=False)
    core._directory(path, 0o500)


def _reserve_unit_identity(
    unit_name: str, command: list[str], ledger_root: Path
) -> dict:
    """Consume a never-used unit identity durably before any start attempt."""
    role = _unit_role(unit_name)
    ledger_root = Path(ledger_root).absolute()
    core._directory(ledger_root, 0o700)
    run_identity = _load_unit_run_identity(ledger_root)
    expected_name = (
        run_identity["probe_unit_name"]
        if role == "network_probe"
        else run_identity["build_unit_name"]
    )
    _need(unit_name == expected_name, "unit-name-not-durable-run-reservation")
    ledger_initial_ref = core._directory_ref(ledger_root, 0o700)
    prefix = _systemd_prefix(unit_name)
    _need(command[: len(prefix)] == prefix, "unit-reservation-command-prefix")
    unit_root = ledger_root / f"{unit_name}.identity"
    _need(not os.path.lexists(unit_root), "unit-identity-prior-reservation")
    os.mkdir(unit_root, 0o700)
    core._require_same_directory_object(ledger_root, ledger_initial_ref, 0o700)
    ledger_after_mkdir_ref = core._directory_ref(ledger_root, 0o700)
    unit_root_ref = core._directory_ref(unit_root, 0o700)
    core._fsync_directory(ledger_root)
    reservation_id = str(uuid.uuid4())
    command_sha256 = core.sha256_bytes(core.canonical(command))
    reservation = _unit_record_identity(
        {
            "schema": UNIT_RESERVATION_SCHEMA,
            "unit_name": unit_name,
            "service_unit": f"{unit_name}.service",
            "role": role,
            "reservation_id": reservation_id,
            "command_sha256": command_sha256,
            "private_output_parent": str(OUTPUT_PARENT),
            "identity_reserved_create_new": True,
            "systemd_start_dispatched": False,
            "authorization": False,
        }
    )
    reservation_path = unit_root / "RESERVATION.json"
    consumption_path = unit_root / "CONSUMPTION.json"
    try:
        reservation_written = core._write_new(
            reservation_path, core.canonical(reservation), 0o400
        )
        core._fsync_directory(unit_root)
        consumption = _unit_record_identity(
            {
                "schema": UNIT_CONSUMPTION_SCHEMA,
                "unit_name": unit_name,
                "service_unit": f"{unit_name}.service",
                "role": role,
                "reservation_id": reservation_id,
                "reservation_sha256": reservation_written["sha256"],
                "command_sha256": command_sha256,
                "identity_consumed_before_start": True,
                "pristine_observation_required_after_consumption": True,
                "systemd_start_dispatched": False,
                "authorization": False,
            }
        )
        core._write_new(consumption_path, core.canonical(consumption), 0o400)
        core._fsync_directory(unit_root)
        core._require_same_directory_object(unit_root, unit_root_ref, 0o700)
        _need(
            set(os.listdir(unit_root)) == {"RESERVATION.json", "CONSUMPTION.json"},
            "unit-identity-exact-records",
        )
        core._require_same_directory(ledger_root, ledger_after_mkdir_ref, 0o700)
        _seal_unit_identity_directory(unit_root)
        first_pristine = _inspect_pristine_unit(unit_name)
        second_pristine = _inspect_pristine_unit(unit_name)
    except BaseException:
        if os.path.lexists(unit_root):
            try:
                observed = os.lstat(unit_root)
                if (
                    stat.S_ISDIR(observed.st_mode)
                    and observed.st_dev == unit_root_ref["device"]
                    and observed.st_ino == unit_root_ref["inode"]
                    and stat.S_IMODE(observed.st_mode) == 0o700
                ):
                    _seal_unit_identity_directory(unit_root)
            except OSError:
                pass
        raise
    _need(first_pristine == second_pristine, "unit-pristine-state-changed")
    sealed_unit_ref = core._directory_ref(unit_root, 0o500)
    _need(
        sealed_unit_ref["device"] == unit_root_ref["device"]
        and sealed_unit_ref["inode"] == unit_root_ref["inode"]
        and sealed_unit_ref["owner_uid"] == unit_root_ref["owner_uid"],
        "unit-identity-directory-substitution",
    )
    core._require_same_directory(ledger_root, ledger_after_mkdir_ref, 0o700)
    _validate_unit_record_pair(unit_root, unit_name)
    return {
        "unit_root": str(unit_root),
        "unit_name": unit_name,
        "service_unit": f"{unit_name}.service",
        "role": role,
        "reservation_id": reservation_id,
        "reservation": _unit_record_reference(
            reservation_path, "RESERVATION.json"
        ),
        "consumption": _unit_record_reference(
            consumption_path, "CONSUMPTION.json"
        ),
        "first_pristine_observation": first_pristine,
        "second_pristine_observation": second_pristine,
        "reservation_and_consumption_durable_before_start": True,
        "prestart_load_state_not_found": True,
        "prestart_historical_journal_empty": True,
        "start_dispatched_after_consumption": False,
    }


def _parse_journal_export(raw: bytes) -> list[dict[bytes, bytes]]:
    _need(type(raw) is bytes and len(raw) <= 2 * 1024 * 1024,
          "systemd-journal-export-size")
    records: list[dict[bytes, bytes]] = []
    offset = 0
    while offset < len(raw):
        fields: dict[bytes, bytes] = {}
        while True:
            newline = raw.find(b"\n", offset)
            _need(newline >= 0, "systemd-journal-export-line")
            header = raw[offset:newline]
            offset = newline + 1
            if header == b"":
                _need(fields, "systemd-journal-export-empty-record")
                records.append(fields)
                break
            if b"=" in header:
                key, value = header.split(b"=", 1)
            else:
                key = header
                _need(offset + 8 <= len(raw),
                      "systemd-journal-export-binary-length")
                length = int.from_bytes(raw[offset:offset + 8], "little")
                offset += 8
                _need(
                    length <= 2 * 1024 * 1024 and offset + length < len(raw),
                    "systemd-journal-export-binary-size",
                )
                value = raw[offset:offset + length]
                offset += length
                _need(raw[offset:offset + 1] == b"\n",
                      "systemd-journal-export-binary-terminator")
                offset += 1
            _need(
                key
                and all(
                    byte == 95 or 48 <= byte <= 57 or 65 <= byte <= 90
                    for byte in key
                )
                and key not in fields,
                "systemd-journal-export-field",
            )
            fields[key] = value
    return records


def _unit_journal(
    unit_name: str, invocation_id: str, exec_main_pid: int
) -> tuple[bytes, dict]:
    _unit_role(unit_name)
    _need(
        re.fullmatch(r"[0-9a-f]{32}", invocation_id) is not None
        and type(exec_main_pid) is int
        and exec_main_pid > 0,
        "systemd-journal-invocation-selector",
    )
    synchronized = subprocess.run(
        [str(JOURNALCTL), "--user", "--sync"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _need(
        synchronized.returncode == 0
        and synchronized.stdout == b""
        and synchronized.stderr == b"",
        "systemd-journal-sync",
    )
    base_command = [
        str(JOURNALCTL), "--user", "--unit", f"{unit_name}.service",
        "--no-pager", "--all", "--output=export",
        (
            "--output-fields=_SYSTEMD_INVOCATION_ID,USER_INVOCATION_ID,"
            "_SYSTEMD_USER_UNIT,USER_UNIT,_PID,_UID,_TRANSPORT,MESSAGE"
        ),
    ]
    all_result = subprocess.run(
        base_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    current_command = [*base_command, f"--invocation={invocation_id}"]
    current_result = subprocess.run(
        current_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _need(
        all_result.returncode == 0
        and all_result.stderr == b""
        and current_result.returncode == 0
        and current_result.stderr == b""
        and all_result.stdout == current_result.stdout,
        "systemd-journal-current-invocation-exclusive",
    )
    lowered = all_result.stdout.lower()
    for forbidden in (
        b"proceeding without", b"does not support", b"failed to apply",
        b"unknown lvalue", b"invalid argument",
    ):
        _need(forbidden not in lowered, "systemd-restriction-warning")
    records = _parse_journal_export(all_result.stdout)
    expected_invocation = invocation_id.encode()
    expected_unit = f"{unit_name}.service".encode()
    pid_matches = 0
    for fields in records:
        ids = {
            fields[key]
            for key in (b"_SYSTEMD_INVOCATION_ID", b"USER_INVOCATION_ID")
            if key in fields
        }
        _need(ids == {expected_invocation},
              "systemd-journal-foreign-invocation")
        units = {
            fields[key]
            for key in (b"_SYSTEMD_USER_UNIT", b"USER_UNIT")
            if key in fields
        }
        _need(not units or units == {expected_unit},
              "systemd-journal-foreign-unit")
        if fields.get(b"_PID") == str(exec_main_pid).encode():
            pid_matches += 1
    evidence = {
        "show_invocation_id": invocation_id,
        "show_exec_main_pid": exec_main_pid,
        "unfiltered_command_sha256": core.sha256_bytes(
            core.canonical(base_command)
        ),
        "invocation_filtered_command_sha256": core.sha256_bytes(
            core.canonical(current_command)
        ),
        "unfiltered_equals_invocation_filtered": True,
        "record_count": len(records),
        "exec_main_pid_record_count": pid_matches,
        "all_records_current_invocation": True,
        "all_records_current_unit": True,
        "export_bytes": len(all_result.stdout),
        "export_sha256": core.sha256_bytes(all_result.stdout),
    }
    return all_result.stdout, evidence


def _stop_unit(unit_name: str) -> None:
    result = subprocess.run(
        [str(SYSTEMCTL), "--user", "stop", f"{unit_name}.service"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _need(result.returncode == 0, "systemd-unit-stop")


def _run_transient_unit(
    unit_name: str, command: list[str], ledger_root: Path
) -> dict:
    prefix = _systemd_prefix(unit_name)
    _need(command[: len(prefix)] == prefix, "systemd-command-prefix")
    unit_identity = _reserve_unit_identity(unit_name, command, ledger_root)
    start = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    unit_identity["start_dispatched_after_consumption"] = True
    _need(start.returncode == 0, "systemd-unit-start")
    final_values = None
    active_evidence = None
    show_raw = b""
    journal_raw = b""
    journal_evidence = None
    try:
        while True:
            values, observed_raw = _show_unit(unit_name)
            if values["LoadState"] == "loaded":
                if values["SubState"] in ("exited", "failed", "dead"):
                    active_evidence = _validate_active_unit_properties(values)
                    show_raw = observed_raw
                    final_values = values
                    break
            time.sleep(0.05)
        _need(final_values is not None, "systemd-final-state-missing")
        _need(
            final_values["ActiveState"] == "active"
            and final_values["SubState"] == "exited"
            and final_values["Result"] == "success"
            and final_values["ExecMainStatus"] == "0",
            "systemd-command-failed",
        )
        invocation_id = final_values["InvocationID"]
        exec_main_pid_raw = final_values["ExecMainPID"]
        _need(
            re.fullmatch(r"[0-9a-f]{32}", invocation_id) is not None
            and exec_main_pid_raw.isdigit()
            and int(exec_main_pid_raw) > 0,
            "systemd-final-invocation-binding",
        )
        exec_main_pid = int(exec_main_pid_raw)
        journal_raw, journal_evidence = _unit_journal(
            unit_name, invocation_id, exec_main_pid
        )
    finally:
        _stop_unit(unit_name)
    _need(active_evidence is not None, "systemd-active-properties-missing")
    _need(journal_evidence is not None, "systemd-journal-evidence-missing")
    return {
        "unit": f"{unit_name}.service",
        "unit_identity": unit_identity,
        "unit_identity_was_fresh_and_consumed_before_start": True,
        "command_sha256": core.sha256_bytes(core.canonical(command)),
        "properties": active_evidence,
        "show_sha256": core.sha256_bytes(show_raw),
        "show_bytes": len(show_raw),
        "journal_sha256": core.sha256_bytes(journal_raw),
        "journal_bytes": len(journal_raw),
        "journal": journal_evidence,
        "invocation_id": invocation_id,
        "exec_main_pid": exec_main_pid,
        "result": "success",
        "exec_main_status": 0,
        "unit_stopped_after_capture": True,
    }


def _extra_manifest_member(source_root: Path, relative_raw: str) -> dict:
    relative = core._safe_relative(relative_raw)
    core._path_components_are_real(source_root, relative)
    identity = core._stable_file_identity(source_root.joinpath(*relative.parts))
    return {
        "relative_path": str(relative),
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
    }


def _derive_proof_manifest(source_root: Path) -> dict:
    source_root = Path(source_root).absolute()
    base = core.derive_recursive_direct_path_package_manifest(
        source_root, PACKAGE_ROOTS
    )
    _validate_manifest_packages(base)
    by_relative = {member["relative_path"]: member for member in base["members"]}
    _need(len(by_relative) == len(base["members"]), "base-manifest-duplicate")
    for relative in PATH_COMPILED_SOURCE_RELATIVES:
        extra = _extra_manifest_member(source_root, relative)
        existing = by_relative.get(relative)
        _need(existing is None or existing == extra, "path-source-manifest-conflict")
        by_relative[relative] = extra
    members = [by_relative[key] for key in sorted(by_relative)]
    value = dict(base)
    value["derivation"] = (
        base["derivation"]
        + ";plus-fixed-path-compiled-low-memory-lib-and-source-only-runner"
    )
    value["members"] = members
    value["member_count"] = len(members)
    value["members_identity_sha256"] = core.sha256_bytes(core.canonical(members))
    value.pop("manifest_identity_sha256")
    value["manifest_identity_sha256"] = core.sha256_bytes(core.canonical(value))
    core._validate_manifest(value)
    _validate_manifest_packages(value)
    paths = {member["relative_path"] for member in members}
    _need(set(PATH_COMPILED_SOURCE_RELATIVES).issubset(paths),
          "path-compiled-source-not-manifested")
    return value


def _require_live_manifest_unchanged(expected: dict, category: str) -> dict:
    observed = _derive_proof_manifest(REPO_ROOT)
    _need(observed == expected, category)
    return observed


def _stable_file_metadata_identity(path: Path, mode: int | None = None) -> dict:
    before = os.lstat(path)
    identity = core._stable_file_identity(path, mode)
    after = os.lstat(path)
    _need(
        core._stat_identity(before) == core._stat_identity(after)
        and identity["device"] == after.st_dev
        and identity["inode"] == after.st_ino
        and identity["bytes"] == after.st_size,
        "metadata-file-identity-race",
    )
    return {
        **identity,
        "owner_uid": after.st_uid,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
    }


def _snapshot_metadata_contract(
    snapshot_root: Path, snapshot_refs: list[dict]
) -> dict:
    root = Path(snapshot_root).absolute()
    core._directory(root, 0o500)
    members = []
    directory_relatives = {""}
    for reference in snapshot_refs:
        relative = core._safe_relative(reference["relative_path"])
        for depth in range(1, len(relative.parts)):
            directory_relatives.add(
                Path(*relative.parts[:depth]).as_posix()
            )
        identity = _stable_file_metadata_identity(
            root.joinpath(*relative.parts), 0o400
        )
        _need(
            all(identity[key] == reference[key] for key in (
                "device", "inode", "bytes", "sha256", "mode_octal",
                "owner_uid", "mtime_ns", "ctime_ns",
            )),
            "snapshot-member-metadata-changed",
        )
        members.append({"relative_path": str(relative), **identity})
    directories = []
    for relative in sorted(directory_relatives):
        path = root if relative == "" else root / relative
        directories.append(
            {"relative_path": relative, **core._directory_ref(path, 0o500)}
        )
    value = {
        "member_count": len(members),
        "members": members,
        "directory_count": len(directories),
        "directories": directories,
        "all_members_bind_mtime_and_ctime": True,
        "all_relevant_directories_bind_mtime_and_ctime": True,
    }
    value["metadata_identity_sha256"] = core.sha256_bytes(
        core.canonical(value)
    )
    return value


def _reviewed_directory_contract(root: Path) -> dict:
    root = Path(root).absolute()
    relatives = {""}
    for relative_raw in REVIEWED_PROOF_SEAM_RELATIVES:
        relative = core._safe_relative(relative_raw)
        for depth in range(1, len(relative.parts)):
            relatives.add(Path(*relative.parts[:depth]).as_posix())
    directories = []
    for relative in sorted(relatives):
        path = root if relative == "" else root / relative
        directories.append(
            {"relative_path": relative, **core._directory_ref(path)}
        )
    value = {
        "directory_count": len(directories),
        "directories": directories,
        "all_relevant_directories_bind_mtime_and_ctime": True,
    }
    value["metadata_identity_sha256"] = core.sha256_bytes(
        core.canonical(value)
    )
    return value


def _tree_metadata_contract(
    root: Path,
    *,
    top_level_directories: tuple[str, ...] | None = None,
    expected_file_mode: int | None = None,
    expected_directory_mode: int | None = None,
) -> dict:
    root = Path(root).absolute()
    core._directory(root, expected_directory_mode)
    selected = None if top_level_directories is None else set(top_level_directories)
    if selected is not None:
        _need(len(selected) == len(top_level_directories),
              "tree-top-level-duplicate")
    files = []
    directories_contract = []
    for current_raw, directories, names in os.walk(root, followlinks=False):
        current = Path(current_raw)
        if current == root and selected is not None:
            _need(selected.issubset(directories), "tree-top-level-missing")
            directories[:] = sorted(selected)
        else:
            directories[:] = sorted(directories)
        relative_directory = current.relative_to(root)
        relative_directory_raw = (
            "" if relative_directory == Path(".")
            else relative_directory.as_posix()
        )
        directories_contract.append(
            {
                "relative_path": relative_directory_raw,
                **core._directory_ref(current, expected_directory_mode),
            }
        )
        for name in names:
            path = current / name
            value = os.lstat(path)
            _need(
                stat.S_ISREG(value.st_mode)
                and not stat.S_ISLNK(value.st_mode)
                and value.st_uid == os.getuid()
                and value.st_nlink == 1,
                "tree-source-file-shape",
            )
            identity = _stable_file_metadata_identity(path, expected_file_mode)
            files.append(
                {
                    "relative_path": path.relative_to(root).as_posix(),
                    **identity,
                }
            )
    files.sort(key=lambda item: item["relative_path"])
    directories_contract.sort(key=lambda item: item["relative_path"])
    if selected is not None:
        actual_top = {
            item["relative_path"] for item in directories_contract
            if item["relative_path"] and "/" not in item["relative_path"]
        }
        _need(actual_top == selected, "tree-top-level-extra")
    value = {
        "file_count": len(files),
        "files": files,
        "directory_count": len(directories_contract),
        "directories": directories_contract,
    }
    value["metadata_identity_sha256"] = core.sha256_bytes(
        core.canonical(value)
    )
    return value


def _locked_registry_packages(lock_path: Path) -> tuple[list[dict], dict]:
    raw, identity = core._stable_file_bytes(lock_path, 0o400)
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise core.Refused("locked-registry-lock-parse") from None
    _need(type(value) is dict and type(value.get("package")) is list,
          "locked-registry-lock-shape")
    packages = []
    names = set()
    for package in value["package"]:
        _need(type(package) is dict, "locked-registry-package-shape")
        source = package.get("source")
        if source is None:
            continue
        _need(
            source == "registry+https://github.com/rust-lang/crates.io-index",
            "locked-registry-non-crates-io-source",
        )
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        _need(
            type(name) is str
            and re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None
            and type(version) is str
            and re.fullmatch(r"[0-9A-Za-z.+-]+", version) is not None
            and type(checksum) is str
            and re.fullmatch(r"[0-9a-f]{64}", checksum) is not None,
            "locked-registry-package-identity",
        )
        directory_name = f"{name}-{version}"
        _need(directory_name not in names, "locked-registry-package-duplicate")
        names.add(directory_name)
        packages.append(
            {
                "name": name,
                "version": version,
                "checksum": checksum,
                "directory_name": directory_name,
            }
        )
    packages.sort(key=lambda item: item["directory_name"])
    _need(packages, "locked-registry-packages-empty")
    return packages, {
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
        "mode_octal": identity["mode_octal"],
    }


def _copy_selected_tree(
    source_root: Path,
    destination_root: Path,
    source_contract: dict,
) -> None:
    source_root = Path(source_root).absolute()
    destination_root = Path(destination_root).absolute()
    os.mkdir(destination_root, 0o700)
    for directory in source_contract["directories"]:
        relative = directory["relative_path"]
        if relative:
            os.mkdir(destination_root / relative, 0o700)
    for expected in source_contract["files"]:
        relative = expected["relative_path"]
        source = source_root / relative
        raw, identity = core._stable_file_bytes(source)
        _need(
            all(identity[key] == expected[key] for key in (
                "device", "inode", "bytes", "sha256", "mode_octal"
            )),
            "locked-registry-source-changed-during-copy",
        )
        core._write_new(destination_root / relative, raw, 0o400)
    core._seal_directories(destination_root)


def _create_isolated_cargo_home(session: core._TestOnlySession) -> dict:
    packages, lock_reference = _locked_registry_packages(
        session.snapshot_root / RELATION_RELATIVE / "Cargo.lock"
    )
    package_directories = tuple(
        package["directory_name"] for package in packages
    )
    core._directory(LOCKED_REGISTRY_SOURCE_ROOT)
    source_before = _tree_metadata_contract(
        LOCKED_REGISTRY_SOURCE_ROOT,
        top_level_directories=package_directories,
    )
    cargo_home = session.target_root / "isolated-cargo-home"
    vendor = cargo_home / "vendor"
    _need(not os.path.lexists(cargo_home), "isolated-cargo-home-create-new")
    os.mkdir(cargo_home, 0o700)
    _copy_selected_tree(LOCKED_REGISTRY_SOURCE_ROOT, vendor, source_before)
    source_after = _tree_metadata_contract(
        LOCKED_REGISTRY_SOURCE_ROOT,
        top_level_directories=package_directories,
    )
    _need(source_after == source_before,
          "locked-registry-source-changed-across-copy")
    config_raw = (
        "[net]\n"
        "offline = true\n"
        "\n[source.crates-io]\n"
        'replace-with = "frozen-vendor"\n'
        "\n[source.frozen-vendor]\n"
        f"directory = {json.dumps(str(vendor))}\n"
    ).encode()
    config_reference = core._write_new(
        cargo_home / "config.toml", config_raw, 0o400
    )
    config_identity = _stable_file_metadata_identity(
        cargo_home / "config.toml", 0o400
    )
    core._fsync_directory(cargo_home)
    vendor_contract = _tree_metadata_contract(
        vendor, expected_file_mode=0o400, expected_directory_mode=0o500
    )
    value = {
        "root": str(cargo_home),
        "root_mode_octal": "0700",
        "config": {
            "path": str(cargo_home / "config.toml"),
            **config_identity,
        },
        "vendor_root": str(vendor),
        "vendor": vendor_contract,
        "locked_packages": packages,
        "locked_package_count": len(packages),
        "cargo_lock": lock_reference,
        "source_cache_copied_with_before_after_metadata_identity": True,
        "ambient_user_cargo_home_used": False,
        "registry_dependency_source_closure_bound": True,
    }
    value["identity_sha256"] = core.sha256_bytes(core.canonical(value))
    return value


def _require_isolated_cargo_home_unchanged(value: dict) -> None:
    root = Path(value["root"])
    core._directory(root, 0o700)
    config = _stable_file_metadata_identity(
        Path(value["config"]["path"]), 0o400
    )
    _need(
        {"path": value["config"]["path"], **config}
        == value["config"],
        "isolated-cargo-config-changed",
    )
    observed_vendor = _tree_metadata_contract(
        Path(value["vendor_root"]),
        expected_file_mode=0o400,
        expected_directory_mode=0o500,
    )
    _need(observed_vendor == value["vendor"],
          "isolated-cargo-vendor-changed")


def _review_snapshot_binding(
    reviewed: dict[str, dict],
    session: core._TestOnlySession,
    *,
    snapshot_root: Path | None = None,
) -> dict:
    """Bind reviewed live and full snapshot bytes plus non-resettable metadata."""
    _need(
        type(reviewed) is dict
        and set(reviewed) == set(REVIEWED_PROOF_SEAM_RELATIVES),
        "review-snapshot-reviewed-set",
    )
    manifest_members = {
        member["relative_path"]: member for member in session.manifest["members"]
    }
    snapshot_refs = {
        member["relative_path"]: member for member in session.snapshot_refs
    }
    _need(
        len(manifest_members) == len(session.manifest["members"])
        and len(snapshot_refs) == len(session.snapshot_refs),
        "review-snapshot-source-duplicates",
    )
    root = session.snapshot_root if snapshot_root is None else Path(snapshot_root)
    root = root.absolute()
    core._directory(root, 0o500)
    entries = []
    for relative_raw in REVIEWED_PROOF_SEAM_RELATIVES:
        relative = core._safe_relative(relative_raw)
        reviewed_member = reviewed[relative_raw]
        manifest_member = manifest_members.get(relative_raw)
        snapshot_ref = snapshot_refs.get(relative_raw)
        _need(
            type(reviewed_member) is dict
            and set(reviewed_member)
            == {
                "bytes", "sha256", "device", "inode", "mtime_ns", "ctime_ns"
            }
            and manifest_member is not None
            and snapshot_ref is not None,
            "review-snapshot-member-presence",
        )
        live_identity = _stable_file_metadata_identity(
            session.source_root.joinpath(*relative.parts)
        )
        identity = _stable_file_metadata_identity(
            root.joinpath(*relative.parts), 0o400
        )
        expected_content = {
            "bytes": reviewed_member["bytes"],
            "sha256": reviewed_member["sha256"],
        }
        _need(
            expected_content
            == {
                "bytes": manifest_member["bytes"],
                "sha256": manifest_member["sha256"],
            }
            == {
                "bytes": snapshot_ref["bytes"],
                "sha256": snapshot_ref["sha256"],
            }
            == {"bytes": identity["bytes"], "sha256": identity["sha256"]}
            and all(
                live_identity[key] == reviewed_member[key]
                for key in (
                    "bytes", "sha256", "device", "inode", "mtime_ns", "ctime_ns"
                )
            )
            and identity["device"] == snapshot_ref["device"]
            and identity["inode"] == snapshot_ref["inode"]
            and identity["mtime_ns"] == snapshot_ref["mtime_ns"]
            and identity["ctime_ns"] == snapshot_ref["ctime_ns"],
            "review-snapshot-content-or-inode",
        )
        entries.append(
            {
                "relative_path": relative_raw,
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
                "live_device": live_identity["device"],
                "live_inode": live_identity["inode"],
                "live_mtime_ns": live_identity["mtime_ns"],
                "live_ctime_ns": live_identity["ctime_ns"],
                "snapshot_device": identity["device"],
                "snapshot_inode": identity["inode"],
                "snapshot_mtime_ns": identity["mtime_ns"],
                "snapshot_ctime_ns": identity["ctime_ns"],
            }
        )
    _need(
        len(entries) == len(REVIEWED_PROOF_SEAM_RELATIVES),
        "review-snapshot-exact-reviewed-closure",
    )
    reviewed_live_directories = _reviewed_directory_contract(
        session.source_root
    )
    snapshot_tree_metadata = _snapshot_metadata_contract(
        root, session.snapshot_refs
    )
    value = {
        "schema": REVIEW_SNAPSHOT_BINDING_SCHEMA,
        "reviewed_member_count": len(REVIEWED_PROOF_SEAM_RELATIVES),
        "reviewed_manifest_snapshot_exact_match": True,
        "entries": entries,
        "reviewed_live_directories": reviewed_live_directories,
        "snapshot_tree_metadata": snapshot_tree_metadata,
        "authorization": False,
    }
    value["binding_identity_sha256"] = core.sha256_bytes(core.canonical(value))
    return value


def _require_review_snapshot_binding_unchanged(
    expected: dict,
    reviewed: dict[str, dict],
    session: core._TestOnlySession,
    *,
    snapshot_root: Path | None = None,
) -> dict:
    observed = _review_snapshot_binding(
        reviewed, session, snapshot_root=snapshot_root
    )
    _need(observed == expected, "review-snapshot-binding-changed")
    return observed


def _validate_manifest_packages(manifest: dict) -> None:
    _need(tuple(manifest.get("package_roots", ())) == EXPECTED_PACKAGE_ROOTS,
          "exact-four-local-packages")


def _begin_proof_candidate(
    source_root: Path, output_parent: Path, output_name: str
) -> core._TestOnlySession:
    _need(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,95}", output_name) is not None,
          "test-output-name")
    source_root = Path(source_root).absolute()
    output_parent = Path(output_parent).absolute()
    _need(
        source_root == source_root.resolve(strict=True)
        and output_parent == output_parent.resolve(strict=True),
        "test-root-canonical",
    )
    source_root_ref = core._directory_ref(source_root)
    output_parent_initial_ref = core._directory_ref(output_parent, 0o700)
    final = output_parent / output_name
    _need(not os.path.lexists(final), "test-final-create-new")
    staging = output_parent / f".{output_name}.staging-{uuid.uuid4()}"
    target = output_parent / f".{output_name}.target-{uuid.uuid4()}"
    os.mkdir(staging, 0o700)
    os.mkdir(target, 0o700)
    staging_initial_ref = core._directory_ref(staging, 0o700)
    target_ref = core._directory_ref(target, 0o700)
    manifest = _derive_proof_manifest(source_root)
    snapshot = staging / "sources"
    refs = core._snapshot_members(source_root, snapshot, manifest)
    for reference in refs:
        relative = core._safe_relative(reference["relative_path"])
        identity = _stable_file_metadata_identity(
            snapshot.joinpath(*relative.parts), 0o400
        )
        _need(
            all(identity[key] == reference[key] for key in (
                "device", "inode", "bytes", "sha256"
            )),
            "snapshot-reference-metadata-initial",
        )
        reference.update(
            {
                key: identity[key]
                for key in (
                    "mode_octal", "owner_uid", "mtime_ns", "ctime_ns"
                )
            }
        )
    after = _derive_proof_manifest(source_root)
    _need(after == manifest, "source-set-changed-during-snapshot")
    core._require_same_directory(
        source_root, source_root_ref, int(source_root_ref["mode_octal"], 8)
    )
    core._require_same_directory_object(
        output_parent, output_parent_initial_ref, 0o700
    )
    core._require_same_directory_object(staging, staging_initial_ref, 0o700)
    core._require_same_directory(target, target_ref, 0o700)
    core._verify_snapshot(snapshot, refs)
    session = core._TestOnlySession(
        source_root=source_root,
        output_parent=output_parent,
        output_name=output_name,
        staging_root=staging,
        snapshot_root=snapshot,
        target_root=target,
        manifest=manifest,
        snapshot_refs=refs,
        source_root_ref=source_root_ref,
        output_parent_ref=core._directory_ref(output_parent, 0o700),
        staging_root_ref=core._directory_ref(staging, 0o700),
        target_root_ref=target_ref,
    )
    session.snapshot_metadata_contract = _snapshot_metadata_contract(
        snapshot, refs
    )
    return session


def _derive_dep_info_members(
    raw: bytes,
    *,
    snapshot_root: Path,
    target_root: Path,
    original_source_root: Path,
    snapshot_refs: list[dict],
    expected_target: Path,
    required_dependency_relatives: set[str] = REQUIRED_PROOF_DEPENDENCY_RELATIVES,
    closure_label: str = "proof",
) -> tuple[tuple[str, ...], dict]:
    snapshot_root = Path(snapshot_root).absolute()
    target_root = Path(target_root).absolute()
    original_source_root = Path(original_source_root).absolute()
    expected_target = Path(expected_target).absolute()
    _need(
        type(required_dependency_relatives) is set
        and required_dependency_relatives
        and closure_label in ("proof", "verifier"),
        "dep-info-required-set-shape",
    )
    target, dependencies = core._parse_dep_info(raw)
    _need(Path(target).is_absolute(), "dep-info-target-absolute")
    _need(Path(target) == expected_target, "dep-info-target-binding")
    _need(expected_target.is_relative_to(target_root), "dep-info-target-root")
    manifested = {item["relative_path"]: item for item in snapshot_refs}
    canonical_members: dict[str, dict] = {}
    mappings = []
    first_indexes: dict[str, int] = {}
    for index, raw_path in enumerate(dependencies):
        lexical = Path(raw_path)
        _need(lexical.is_absolute(), "dep-info-path-absolute")
        try:
            path = lexical.resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            raise core.Refused("dep-info-path-resolution") from None
        _need(path.is_relative_to(snapshot_root), "dep-info-not-snapshot")
        _need(not path.is_relative_to(original_source_root), "dep-info-live-source")
        relative = path.relative_to(snapshot_root).as_posix()
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
            canonical_members[relative] = {
                "absolute": str(path),
                "device": identity["device"],
                "inode": identity["inode"],
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
            }
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
    manifest_order = [item["relative_path"] for item in snapshot_refs]
    relatives = tuple(
        relative for relative in manifest_order if relative in canonical_members
    )
    _need(len(relatives) == len(canonical_members), "dep-info-canonical-dedup")
    _need(set(relatives) == required_dependency_relatives,
          "dep-info-exact-reviewed-local-closure")
    for package_root in EXPECTED_PACKAGE_ROOTS:
        prefix = package_root + "/"
        _need(any(relative.startswith(prefix) for relative in relatives),
              "dep-info-all-four-packages")
    _need(set(PATH_COMPILED_SOURCE_RELATIVES).issubset(relatives),
          "dep-info-path-compiled-low-memory-closure")
    return relatives, {
        "raw_target": target,
        "closure_label": closure_label,
        "required_dependency_relatives": sorted(required_dependency_relatives),
        "raw_dependency_count": len(dependencies),
        "raw_dependencies": dependencies,
        "raw_dep_info_sha256": core.sha256_bytes(raw),
        "canonical_unique_dependency_count": len(relatives),
        "canonical_dependency_absolutes_manifest_order": [
            canonical_members[relative]["absolute"] for relative in relatives
        ],
        "canonical_dependency_relatives_manifest_order": list(relatives),
        "lexical_alias_count": sum(item["lexical_alias"] for item in mappings),
        "duplicate_canonical_member_count": sum(
            item["duplicate_canonical_member"] for item in mappings
        ),
        "raw_first_occurrence_indexes": {
            relative: first_indexes[relative] for relative in relatives
        },
        "publication_order": "SOURCE_MANIFEST_RELATIVE_PATH_ORDER",
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
        _need(core._stat_identity(opened) == core._stat_identity(before_path),
              "cargo-binary-open-race")
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


def _admission_dep_info(
    *, detached_target: Path, snapshot_root: Path, relatives: tuple[str, ...]
) -> bytes:
    detached_target = Path(detached_target).absolute()
    snapshot_root = Path(snapshot_root).absolute()
    _need(relatives and len(relatives) == len(set(relatives)),
          "admission-dep-info-relatives")
    dependencies = [str(snapshot_root / relative) for relative in relatives]
    raw = f"{detached_target}: {' '.join(dependencies)}\n".encode()
    target, observed = core._parse_dep_info(raw)
    _need(target == str(detached_target) and observed == dependencies,
          "admission-dep-info-shape")
    return raw


def _publication_dep_info(
    relatives: tuple[str, ...],
    target_relative: str = "artifacts/candidate-binary",
) -> bytes:
    _need(relatives and len(relatives) == len(set(relatives)),
          "publication-dep-info-relatives")
    _need(
        target_relative
        in (
            "artifacts/candidate-binary",
            "artifacts/verify_frozen_w1_round1_receipt",
        ),
        "publication-dep-info-target",
    )
    target = target_relative
    dependencies = [f"sources/{relative}" for relative in relatives]
    raw = f"{target}: {' '.join(dependencies)}\n".encode()
    observed_target, observed_dependencies = core._parse_dep_info(raw)
    _need(observed_target == target and observed_dependencies == dependencies,
          "publication-dep-info-shape")
    return raw


def _validate_proof_bundle_tree(root: Path, root_mode: int) -> None:
    core._directory(root, root_mode)
    _need(
        set(os.listdir(root))
        == {
            "sources",
            "artifacts",
            "SOURCE-MANIFEST.json",
            "FREEZER-SOURCE.py",
            "BUILD-RECEIPT.json",
        },
        "proof-bundle-root-file-set",
    )
    core._directory(root / "sources", 0o500)
    core._directory(root / "artifacts", 0o500)
    _need(
        set(os.listdir(root / "artifacts"))
        == {
            "candidate-binary",
            "candidate-binary.d",
            "verify_frozen_w1_round1_receipt",
            "verify_frozen_w1_round1_receipt.d",
        },
        "proof-bundle-artifact-file-set",
    )
    for name in (
        "SOURCE-MANIFEST.json",
        "FREEZER-SOURCE.py",
        "BUILD-RECEIPT.json",
        "artifacts/candidate-binary.d",
        "artifacts/verify_frozen_w1_round1_receipt.d",
    ):
        core._stable_file_identity(root / name, 0o400)
    for name in (
        "artifacts/candidate-binary",
        "artifacts/verify_frozen_w1_round1_receipt",
    ):
        core._stable_file_identity(root / name, 0o500)


def _refuse_proof_execution_markers(target_root: Path) -> None:
    target_root = Path(target_root).absolute()
    core._directory(target_root, 0o700)
    for current_raw, directories, files in os.walk(target_root, followlinks=False):
        current = Path(current_raw)
        for name in directories:
            _need(not (current / name).is_symlink(), "target-symlink-directory")
        for name in files:
            _need(name not in PROOF_EXECUTION_MARKER_NAMES,
                  "proof-execution-marker-observed")


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
    _need(observed_raw == initial_raw and observed_reference == initial_reference,
          "python-source-changed-during-build")
    return observed_reference


def _without_raw(reference: dict) -> dict:
    return {key: value for key, value in reference.items() if key != "raw"}


def _receipt_identity(value: dict) -> dict:
    result = dict(value)
    _need("receipt_identity_sha256" not in result, "outer-receipt-preidentified")
    result["receipt_identity_sha256"] = core.sha256_bytes(core.canonical(result))
    return result


def _finalize_proof_candidate(
    session: core._TestOnlySession,
    *,
    proof_binary: Path,
    proof_admission_dep_info: Path,
    proof_dependency_relatives: tuple[str, ...],
    verifier_binary: Path,
    verifier_admission_dep_info: Path,
    verifier_dependency_relatives: tuple[str, ...],
) -> dict:
    """Publish both detached examples with relocatable final dep-info."""
    _need(not session.finalized, "test-session-finalized")
    session.finalized = True
    core._require_same_directory(
        session.source_root,
        session.source_root_ref,
        int(session.source_root_ref["mode_octal"], 8),
    )
    core._require_same_directory(session.output_parent, session.output_parent_ref, 0o700)
    core._require_same_directory(session.staging_root, session.staging_root_ref, 0o700)
    core._require_same_directory_object(session.target_root, session.target_root_ref, 0o700)
    target_ready_ref = core._directory_ref(session.target_root, 0o700)
    proof_binary = Path(proof_binary).absolute()
    proof_admission_dep_info = Path(proof_admission_dep_info).absolute()
    verifier_binary = Path(verifier_binary).absolute()
    verifier_admission_dep_info = Path(verifier_admission_dep_info).absolute()
    _need(
        all(
            path.is_relative_to(session.target_root)
            for path in (
                proof_binary,
                proof_admission_dep_info,
                verifier_binary,
                verifier_admission_dep_info,
            )
        )
        and len(
            {
                proof_binary,
                proof_admission_dep_info,
                verifier_binary,
                verifier_admission_dep_info,
            }
        )
        == 4,
        "test-build-output-outside-target",
    )
    _refuse_proof_execution_markers(session.target_root)
    before = core._verify_snapshot(session.snapshot_root, session.snapshot_refs)
    proof_admission_raw, _ = core._stable_file_bytes(
        proof_admission_dep_info, 0o400
    )
    proof_admission = core._validate_test_only_snapshot_dep_info(
        proof_admission_raw,
        snapshot_root=session.snapshot_root,
        target_root=session.target_root,
        expected_target=proof_binary,
        snapshot_refs=session.snapshot_refs,
        caller_expected_dependency_relatives=proof_dependency_relatives,
        original_source_root=session.source_root,
    )
    verifier_admission_raw, _ = core._stable_file_bytes(
        verifier_admission_dep_info, 0o400
    )
    verifier_admission = core._validate_test_only_snapshot_dep_info(
        verifier_admission_raw,
        snapshot_root=session.snapshot_root,
        target_root=session.target_root,
        expected_target=verifier_binary,
        snapshot_refs=session.snapshot_refs,
        caller_expected_dependency_relatives=verifier_dependency_relatives,
        original_source_root=session.source_root,
    )
    proof_publication_raw = _publication_dep_info(
        proof_dependency_relatives, "artifacts/candidate-binary"
    )
    verifier_publication_raw = _publication_dep_info(
        verifier_dependency_relatives,
        "artifacts/verify_frozen_w1_round1_receipt",
    )

    artifacts = session.staging_root / "artifacts"
    os.mkdir(artifacts, 0o700)
    proof_binary_ref = core._copy_generated(
        proof_binary, artifacts / "candidate-binary", 0o500
    )
    proof_dep_ref = core._write_new(
        artifacts / "candidate-binary.d", proof_publication_raw, 0o400
    )
    verifier_binary_ref = core._copy_generated(
        verifier_binary,
        artifacts / "verify_frozen_w1_round1_receipt",
        0o500,
    )
    verifier_dep_ref = core._write_new(
        artifacts / "verify_frozen_w1_round1_receipt.d",
        verifier_publication_raw,
        0o400,
    )
    after = core._verify_snapshot(session.snapshot_root, session.snapshot_refs)
    _need(before == after, "snapshot-changed-across-build")

    manifest_ref = core._write_new(
        session.staging_root / "SOURCE-MANIFEST.json",
        core.canonical(session.manifest),
        0o400,
    )
    core_raw, _ = core._stable_file_bytes(Path(core.__file__).resolve(strict=True))
    freezer_ref = core._write_new(
        session.staging_root / "FREEZER-SOURCE.py", core_raw, 0o400
    )
    receipt = _receipt_identity(
        {
            "schema": core.BUILD_RECEIPT_SCHEMA,
            "classification": "TEST_ONLY_FILESYSTEM_CONTRACT_NOT_A_BUILD_AUTHORITY",
            "source_manifest": {
                "bytes": manifest_ref["bytes"],
                "sha256": manifest_ref["sha256"],
            },
            "source_members_identity_sha256": session.manifest[
                "members_identity_sha256"
            ],
            "freezer_source": {
                "name": "FREEZER-SOURCE.py",
                "bytes": freezer_ref["bytes"],
                "sha256": freezer_ref["sha256"],
            },
            "source_member_count": session.manifest["member_count"],
            "snapshot_same_inodes_before_after": True,
            "snapshot_files_mode_0400": True,
            "snapshot_directories_mode_0500": True,
            "build_target_outside_snapshot": True,
            "built_examples": list(EXAMPLE_NAMES),
            "dep_info": {
                "target": "artifacts/candidate-binary",
                "dependencies": [
                    f"sources/{relative}" for relative in proof_dependency_relatives
                ],
                "dependency_count": len(proof_dependency_relatives),
                "dep_info_sha256": proof_dep_ref["sha256"],
                "snapshot_only": True,
                "live_path_provenance": False,
                "admission_sha256": core.sha256_bytes(proof_admission_raw),
                "admission": proof_admission,
            },
            "verifier_dep_info": {
                "target": "artifacts/verify_frozen_w1_round1_receipt",
                "dependencies": [
                    f"sources/{relative}"
                    for relative in verifier_dependency_relatives
                ],
                "dependency_count": len(verifier_dependency_relatives),
                "dep_info_sha256": verifier_dep_ref["sha256"],
                "snapshot_only": True,
                "live_path_provenance": False,
                "admission_sha256": core.sha256_bytes(verifier_admission_raw),
                "admission": verifier_admission,
            },
            "binary": {
                "name": "candidate-binary",
                "bytes": proof_binary_ref["bytes"],
                "sha256": proof_binary_ref["sha256"],
                "mode_octal": "0500",
                "link_count": 1,
            },
            "verifier_binary": {
                "name": "verify_frozen_w1_round1_receipt",
                "bytes": verifier_binary_ref["bytes"],
                "sha256": verifier_binary_ref["sha256"],
                "mode_octal": "0500",
                "link_count": 1,
            },
            "frozen_dep_info": {
                "name": "candidate-binary.d",
                "bytes": proof_dep_ref["bytes"],
                "sha256": proof_dep_ref["sha256"],
                "mode_octal": "0400",
                "link_count": 1,
            },
            "frozen_verifier_dep_info": {
                "name": "verify_frozen_w1_round1_receipt.d",
                "bytes": verifier_dep_ref["bytes"],
                "sha256": verifier_dep_ref["sha256"],
                "mode_octal": "0400",
                "link_count": 1,
            },
            "actual_subprocess_build_executed_by_contract": True,
            "production_source_manifest_bound": False,
            "production_binary_accepted": False,
            "setup": False,
            "pk_decode": False,
            "synthesis": False,
            "proof": False,
            "network": False,
            "funds": False,
            "authorization": False,
        }
    )
    receipt_ref = core._write_new(
        session.staging_root / "BUILD-RECEIPT.json",
        core.canonical(receipt),
        0o400,
    )
    core._seal_directories(artifacts)
    _validate_proof_bundle_tree(session.staging_root, 0o700)
    core._fsync_directory(session.staging_root)
    os.chmod(session.staging_root, 0o500, follow_symlinks=False)
    core._directory(session.staging_root, 0o500)
    core._require_same_directory(session.target_root, target_ready_ref, 0o700)
    final = session.output_parent / session.output_name
    _need(
        session.staging_root.parent == session.output_parent
        and final.parent == session.output_parent,
        "test-publication-parent-binding",
    )
    parent_descriptor = os.open(
        session.output_parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        _need(
            core._directory_ref_from_fd(parent_descriptor, 0o700)
            == session.output_parent_ref,
            "test-publication-parent-fd-substitution",
        )
        core._rename_no_replace_at(
            parent_descriptor, session.staging_root.name, session.output_name
        )
        os.fsync(parent_descriptor)
        after_parent = core._directory_ref_from_fd(parent_descriptor, 0o700)
        _need(core._directory_ref(session.output_parent, 0o700) == after_parent,
              "test-publication-parent-path-substitution")
        for key in ("device", "inode", "link_count", "owner_uid", "mode_octal"):
            _need(after_parent[key] == session.output_parent_ref[key],
                  "test-publication-parent-object-changed")
    finally:
        os.close(parent_descriptor)

    _validate_proof_bundle_tree(final, 0o500)
    core._verify_snapshot(final / "sources", session.snapshot_refs)
    final_receipt = core._stable_file_identity(final / "BUILD-RECEIPT.json", 0o400)
    final_proof_binary = core._stable_file_identity(
        final / "artifacts" / "candidate-binary", 0o500
    )
    final_proof_dep = core._stable_file_identity(
        final / "artifacts" / "candidate-binary.d", 0o400
    )
    final_verifier_binary = core._stable_file_identity(
        final / "artifacts" / "verify_frozen_w1_round1_receipt", 0o500
    )
    final_verifier_dep = core._stable_file_identity(
        final / "artifacts" / "verify_frozen_w1_round1_receipt.d", 0o400
    )
    _need(
        final_receipt["sha256"] == receipt_ref["sha256"]
        and final_proof_binary["sha256"] == proof_binary_ref["sha256"]
        and final_proof_dep["sha256"] == proof_dep_ref["sha256"]
        and final_verifier_binary["sha256"] == verifier_binary_ref["sha256"]
        and final_verifier_dep["sha256"] == verifier_dep_ref["sha256"],
        "test-final-artifacts",
    )
    return {
        "status": "TEST_ONLY_CURRENT_SOURCE_FREEZE_CONTRACT_COMPLETE",
        "root": str(final),
        "receipt_sha256": receipt_ref["sha256"],
        "source_members_identity_sha256": session.manifest[
            "members_identity_sha256"
        ],
        "source_member_count": session.manifest["member_count"],
        "binary_sha256": proof_binary_ref["sha256"],
        "dep_info_sha256": proof_dep_ref["sha256"],
        "verifier_binary_sha256": verifier_binary_ref["sha256"],
        "verifier_dep_info_sha256": verifier_dep_ref["sha256"],
        "production_build": False,
        "authorization": False,
    }


def _validate_pristine_unit_observation(value: dict) -> None:
    _need(
        type(value) is dict
        and set(value)
        == {
            "load_state",
            "systemctl_command_sha256",
            "systemctl_stdout_bytes",
            "systemctl_stdout_sha256",
            "historical_journal_command_sha256",
            "historical_journal_bytes",
            "historical_journal_sha256",
            "historical_journal_empty",
        }
        and value["load_state"] == "not-found"
        and value["systemctl_stdout_bytes"] == len(b"not-found\n")
        and value["systemctl_stdout_sha256"]
        == core.sha256_bytes(b"not-found\n")
        and value["historical_journal_bytes"] == 0
        and value["historical_journal_sha256"] == core.sha256_bytes(b"")
        and value["historical_journal_empty"] is True
        and all(
            type(value[key]) is str
            and re.fullmatch(r"[0-9a-f]{64}", value[key]) is not None
            for key in (
                "systemctl_command_sha256",
                "historical_journal_command_sha256",
            )
        ),
        "pristine-unit-observation-contract",
    )


def _validate_unit_record_reference(value: dict, name: str) -> None:
    _need(
        type(value) is dict
        and set(value)
        == {
            "name", "path", "bytes", "sha256", "mode_octal", "link_count",
            "device", "inode", "owner_uid", "mtime_ns", "ctime_ns",
        }
        and value["name"] == name
        and type(value["path"]) is str
        and os.path.isabs(value["path"])
        and type(value["bytes"]) is int
        and value["bytes"] > 0
        and type(value["sha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
        and value["mode_octal"] == "0400"
        and value["link_count"] == 1
        and all(
            type(value[key]) is int and value[key] >= 0
            for key in (
                "device", "inode", "owner_uid", "mtime_ns", "ctime_ns"
            )
        ),
        "unit-record-reference-contract",
    )


def _reopen_unit_record_reference(value: dict, expected_path: Path) -> None:
    _validate_unit_record_reference(value, expected_path.name)
    _need(value["path"] == str(expected_path.absolute()),
          "unit-record-reference-path")
    observed = _stable_file_metadata_identity(expected_path, 0o400)
    _need(
        all(
            observed[key] == value[key]
            for key in (
                "bytes", "sha256", "mode_octal", "device", "inode",
                "owner_uid", "mtime_ns", "ctime_ns",
            )
        )
        and value["link_count"] == 1,
        "unit-record-reference-reopen",
    )


def _is_canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _validate_unit_identity_contract(value: dict, unit_name: str) -> None:
    role = _unit_role(unit_name)
    _need(
        type(value) is dict
        and set(value)
        == {
            "unit_root",
            "unit_name",
            "service_unit",
            "role",
            "reservation_id",
            "reservation",
            "consumption",
            "first_pristine_observation",
            "second_pristine_observation",
            "reservation_and_consumption_durable_before_start",
            "prestart_load_state_not_found",
            "prestart_historical_journal_empty",
            "start_dispatched_after_consumption",
        }
        and value["unit_name"] == unit_name
        and value["service_unit"] == f"{unit_name}.service"
        and value["role"] == role
        and value["unit_root"]
        == str(OUTPUT_PARENT / UNIT_LEDGER_NAME / f"{unit_name}.identity")
        and _is_canonical_uuid(value["reservation_id"])
        and value["reservation_and_consumption_durable_before_start"] is True
        and value["prestart_load_state_not_found"] is True
        and value["prestart_historical_journal_empty"] is True
        and value["start_dispatched_after_consumption"] is True,
        "unit-identity-contract",
    )
    _validate_unit_record_reference(value["reservation"], "RESERVATION.json")
    _validate_unit_record_reference(value["consumption"], "CONSUMPTION.json")
    _validate_pristine_unit_observation(value["first_pristine_observation"])
    _validate_pristine_unit_observation(value["second_pristine_observation"])
    _need(
        value["first_pristine_observation"]
        == value["second_pristine_observation"],
        "unit-pristine-observations-differ",
    )


def _validate_unit_ledger_contract(value: dict) -> None:
    _need(
        type(value) is dict
        and set(value)
        == {
            "root",
            "mode_octal",
            "root_reference",
            "unit_count",
            "run_id",
            "probe_unit_name",
            "build_unit_name",
            "run_identity",
            "units",
            "atomic_evidence",
            "reservations_and_consumptions_retained",
            "authorization",
            "ledger_identity_sha256",
        }
        and value["root"] == str(OUTPUT_PARENT / UNIT_LEDGER_NAME)
        and value["mode_octal"] == "0500"
        and value["root_reference"]
        == core._directory_ref(Path(value["root"]), 0o500)
        and value["unit_count"] == 2
        and _is_canonical_uuid(value["run_id"])
        and _unit_role(value["probe_unit_name"]) == "network_probe"
        and _unit_role(value["build_unit_name"]) == "cargo_build"
        and value["probe_unit_name"] != value["build_unit_name"]
        and type(value["units"]) is dict
        and set(value["units"])
        == {value["probe_unit_name"], value["build_unit_name"]}
        and value["reservations_and_consumptions_retained"] is True
        and value["authorization"] is False,
        "unit-ledger-contract",
    )
    ledger_root = Path(value["root"])
    _reopen_unit_record_reference(
        value["run_identity"], ledger_root / "RUN-IDENTITY.json"
    )
    for unit_name in (value["probe_unit_name"], value["build_unit_name"]):
        unit = value["units"][unit_name]
        _need(
            type(unit) is dict
            and set(unit)
            == {
                "unit_root", "unit_root_reference", "reservation",
                "consumption",
            }
            and unit["unit_root"]
            == str(OUTPUT_PARENT / UNIT_LEDGER_NAME / f"{unit_name}.identity"),
            "unit-ledger-member-contract",
        )
        unit_root = ledger_root / f"{unit_name}.identity"
        _need(
            unit["unit_root_reference"]
            == core._directory_ref(unit_root, 0o500),
            "unit-ledger-member-directory-reference",
        )
        _reopen_unit_record_reference(
            unit["reservation"], unit_root / "RESERVATION.json"
        )
        _reopen_unit_record_reference(
            unit["consumption"], unit_root / "CONSUMPTION.json"
        )
    atomic = value["atomic_evidence"]
    expected_relatives = {
        "RUN-IDENTITY.json",
        *(
            f"{unit_name}.identity/{record_name}"
            for unit_name in (
                value["probe_unit_name"], value["build_unit_name"]
            )
            for record_name in ("RESERVATION.json", "CONSUMPTION.json")
        ),
    }
    _need(
        type(atomic) is dict
        and set(atomic)
        == {
            "root_name", "record_count",
            "reservation_and_consumption_record_count", "records",
            "copied_into_atomic_outer_evidence",
        }
        and atomic["root_name"] == "UNIT-IDENTITY-EVIDENCE"
        and atomic["record_count"] == 5
        and atomic["reservation_and_consumption_record_count"] == 4
        and type(atomic["records"]) is list
        and len(atomic["records"]) == 5
        and {record.get("relative_path") for record in atomic["records"]}
        == expected_relatives
        and all(
            type(record) is dict
            and set(record)
            == {
                "relative_path", "bytes", "sha256", "mode_octal",
                "link_count",
            }
            and type(record["bytes"]) is int
            and record["bytes"] > 0
            and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None
            and record["mode_octal"] == "0400"
            and record["link_count"] == 1
            for record in atomic["records"]
        )
        and atomic["copied_into_atomic_outer_evidence"] is True,
        "unit-ledger-atomic-evidence-contract",
    )
    unsigned = dict(value)
    claimed = unsigned.pop("ledger_identity_sha256")
    _need(claimed == core.sha256_bytes(core.canonical(unsigned)),
          "unit-ledger-identity")


def _validate_review_snapshot_contract(value: dict) -> None:
    _need(
        type(value) is dict
        and set(value)
        == {
            "independent_review_explicitly_bound_before_execution",
            "reviewed_sources",
            "review_manifest_snapshot_binding",
            "review_manifest_snapshot_rechecked_after_build",
            "review_manifest_snapshot_rechecked_after_publication",
            "reviewed_sources_equal_after_atomic_freeze",
        }
        and value["independent_review_explicitly_bound_before_execution"] is True
        and value["review_manifest_snapshot_rechecked_after_build"] is True
        and value["review_manifest_snapshot_rechecked_after_publication"] is True
        and value["reviewed_sources_equal_after_atomic_freeze"] is True
        and type(value["reviewed_sources"]) is dict
        and set(value["reviewed_sources"]) == set(REVIEWED_PROOF_SEAM_RELATIVES),
        "review-snapshot-receipt-contract",
    )
    binding = value["review_manifest_snapshot_binding"]
    for relative in REVIEWED_PROOF_SEAM_RELATIVES:
        reviewed_source = value["reviewed_sources"][relative]
        _need(
            type(reviewed_source) is dict
            and set(reviewed_source)
            == {
                "bytes", "sha256", "device", "inode", "mtime_ns", "ctime_ns"
            }
            and type(reviewed_source["bytes"]) is int
            and reviewed_source["bytes"] > 0
            and re.fullmatch(r"[0-9a-f]{64}", reviewed_source["sha256"])
            is not None
            and all(
                type(reviewed_source[key]) is int
                and reviewed_source[key] >= 0
                for key in ("device", "inode", "mtime_ns", "ctime_ns")
            ),
            "reviewed-source-metadata-contract",
        )
    _need(
        type(binding) is dict
        and set(binding)
        == {
            "schema",
            "reviewed_member_count",
            "reviewed_manifest_snapshot_exact_match",
            "entries",
            "reviewed_live_directories",
            "snapshot_tree_metadata",
            "authorization",
            "binding_identity_sha256",
        }
        and binding["schema"] == REVIEW_SNAPSHOT_BINDING_SCHEMA
        and binding["reviewed_member_count"]
        == len(REVIEWED_PROOF_SEAM_RELATIVES)
        and binding["reviewed_manifest_snapshot_exact_match"] is True
        and binding["authorization"] is False
        and type(binding["entries"]) is list
        and len(binding["entries"]) == len(REVIEWED_PROOF_SEAM_RELATIVES),
        "review-snapshot-binding-receipt-shape",
    )
    for relative, entry in zip(
        REVIEWED_PROOF_SEAM_RELATIVES, binding["entries"], strict=True
    ):
        reviewed = value["reviewed_sources"][relative]
        _need(
            type(entry) is dict
            and set(entry)
            == {
                "relative_path",
                "bytes",
                "sha256",
                "live_device",
                "live_inode",
                "live_mtime_ns",
                "live_ctime_ns",
                "snapshot_device",
                "snapshot_inode",
                "snapshot_mtime_ns",
                "snapshot_ctime_ns",
            }
            and entry["relative_path"] == relative
            and {"bytes": entry["bytes"], "sha256": entry["sha256"]}
            == {"bytes": reviewed["bytes"], "sha256": reviewed["sha256"]}
            and all(
                type(entry[key]) is int and entry[key] >= 0
                for key in (
                    "live_device", "live_inode", "live_mtime_ns",
                    "live_ctime_ns", "snapshot_device", "snapshot_inode",
                    "snapshot_mtime_ns", "snapshot_ctime_ns",
                )
            )
            and all(
                type(reviewed[key]) is int and reviewed[key] >= 0
                for key in ("device", "inode", "mtime_ns", "ctime_ns")
            )
            and entry["live_device"] == reviewed["device"]
            and entry["live_inode"] == reviewed["inode"]
            and entry["live_mtime_ns"] == reviewed["mtime_ns"]
            and entry["live_ctime_ns"] == reviewed["ctime_ns"],
            "review-snapshot-binding-receipt-entry",
        )
    for metadata, required_keys in (
        (
            binding["reviewed_live_directories"],
            {
                "directory_count", "directories",
                "all_relevant_directories_bind_mtime_and_ctime",
                "metadata_identity_sha256",
            },
        ),
        (
            binding["snapshot_tree_metadata"],
            {
                "member_count", "members", "directory_count", "directories",
                "all_members_bind_mtime_and_ctime",
                "all_relevant_directories_bind_mtime_and_ctime",
                "metadata_identity_sha256",
            },
        ),
    ):
        _need(type(metadata) is dict and set(metadata) == required_keys,
              "review-snapshot-metadata-shape")
        unsigned_metadata = dict(metadata)
        metadata_identity = unsigned_metadata.pop("metadata_identity_sha256")
        _need(
            metadata_identity
            == core.sha256_bytes(core.canonical(unsigned_metadata)),
            "review-snapshot-metadata-identity",
        )
    unsigned = dict(binding)
    claimed = unsigned.pop("binding_identity_sha256")
    _need(claimed == core.sha256_bytes(core.canonical(unsigned)),
          "review-snapshot-binding-receipt-identity")


def _validate_build_environment_contract(build: dict) -> None:
    command = build.get("command")
    environment = build.get("exact_cargo_environment")
    _need(
        type(command) is list
        and all(type(item) is str for item in command)
        and build.get("command_sha256")
        == core.sha256_bytes(core.canonical(command))
        and build.get("environment_launcher") == str(ENV)
        and build.get("environment_cleared_with_i") is True
        and type(environment) is list
        and all(type(item) is str for item in environment)
        and build.get("ambient_manager_environment_inherited_by_cargo") is False
        and build.get("bootstrap_unset_environment")
        == list(BOOTSTRAP_UNSET_ENVIRONMENT),
        "outer-build-environment-contract",
    )
    target_entries = [
        item for item in environment if item.startswith("CARGO_TARGET_DIR=")
    ]
    _need(len(target_entries) == 1, "outer-build-target-environment")
    target_raw = target_entries[0].removeprefix("CARGO_TARGET_DIR=")
    _need(
        target_raw
        and os.path.isabs(target_raw)
        and os.path.normpath(target_raw) == target_raw,
        "outer-build-target-path",
    )
    target_root = Path(target_raw)
    _need(
        environment == list(_cargo_environment(target_root)),
        "outer-build-exact-cargo-environment",
    )
    cwd_raw = build.get("cwd")
    _need(
        type(cwd_raw) is str
        and os.path.isabs(cwd_raw)
        and os.path.normpath(cwd_raw) == cwd_raw,
        "outer-build-cwd",
    )
    cwd = Path(cwd_raw)
    relation_parts = Path(RELATION_RELATIVE).parts
    _need(
        len(cwd.parts) > len(relation_parts)
        and cwd.parts[-len(relation_parts):] == relation_parts,
        "outer-build-cwd-relation",
    )
    snapshot_root = cwd
    for _ in relation_parts:
        snapshot_root = snapshot_root.parent
    unit_name = build["unit"]["unit_identity"]["unit_name"]
    _need(_unit_role(unit_name) == "cargo_build", "outer-build-unit-role")
    bootstrap = build["bootstrap"]
    _need(
        type(bootstrap) is dict
        and set(bootstrap)
        == {
            "schema", "interpreter", "source_bytes", "source_sha256",
            "exact_environment_verified_in_build_unit",
            "inherited_fds_exactly_0_1_2_dev_null_verified_in_build_unit",
            "cargo_opened_and_rehashed_after_inherited_fd_check",
            "cargo_exec_primitive", "cargo_argv", "cargo_identity",
            "proof_or_verifier_binary_executed",
        }
        and bootstrap["schema"] == BUILD_BOOTSTRAP_SCHEMA
        and bootstrap["interpreter"] == str(PYTHON)
        and bootstrap["source_bytes"] == len(BUILD_BOOTSTRAP_SOURCE.encode())
        and bootstrap["source_sha256"]
        == core.sha256_bytes(BUILD_BOOTSTRAP_SOURCE.encode())
        and bootstrap["exact_environment_verified_in_build_unit"] is True
        and bootstrap[
            "inherited_fds_exactly_0_1_2_dev_null_verified_in_build_unit"
        ] is True
        and bootstrap["cargo_opened_and_rehashed_after_inherited_fd_check"]
        is True
        and bootstrap["cargo_exec_primitive"] == "os.execve-authenticated-fd"
        and bootstrap["cargo_argv"] == [str(CARGO), *CARGO_BUILD_ARGUMENTS]
        and bootstrap["proof_or_verifier_binary_executed"] is False,
        "outer-build-bootstrap-contract",
    )
    build_tools = build["build_tools"]
    _need(
        type(build_tools) is dict
        and set(build_tools)
        == {
            "before", "after", "exactly_equal_across_build",
            "reviewed_identity_map", "toolchain_dynamic_library_closure_bound",
        }
        and build_tools["before"] == build_tools["after"]
        and build_tools["exactly_equal_across_build"] is True
        and build_tools["reviewed_identity_map"]
        == REVIEWED_BUILD_TOOL_IDENTITIES
        and build_tools["toolchain_dynamic_library_closure_bound"] is False
        and bootstrap["cargo_identity"]
        == build_tools["before"]["tools"]["cargo"],
        "outer-build-tool-contract",
    )
    _assert_build_only_command(
        command, snapshot_root, target_root, unit_name,
        bootstrap["cargo_identity"],
    )
    _require_isolated_cargo_home_unchanged(build["isolated_cargo_home"])
    _validate_transient_unit_evidence(
        build["unit"], unit_name, build["command_sha256"]
    )


def _validate_network_boundary_contract(value: dict) -> None:
    _need(
        type(value) is dict
        and set(value)
        == {
            "denied_network_syscalls",
            "system_call_error",
            "system_call_architectures",
            "restrict_address_families",
            "socket_and_socketpair_allowed_for_local_process_spawn",
            "socketpair_connected_write_read_classified_as_local_ipc_only",
            "sendto_recvfrom_denied",
            "sendmsg_recvmsg_mmsg_denied",
            "af_unix_connect_bind_listen_accept_denied",
            "io_uring_setup_enter_register_denied",
            "same_uid_descriptor_and_memory_relay_syscalls_denied",
            "inherited_communication_fds",
            "ip_address_families_available",
            "local_af_unix_ipc_permitted",
            "local_af_unix_ipc_observed",
            "af_unix_external_relay_surface_observed",
            "strict_no_socket_runtime_boundary_is_not_this_build_boundary",
            "probe",
            "network_communication_performed",
        }
        and value["denied_network_syscalls"]
        == list(DENIED_BUILD_NETWORK_SYSCALLS)
        and value["system_call_error"] == "EPERM"
        and value["system_call_architectures"] == "native"
        and value["restrict_address_families"] == "AF_UNIX"
        and value["socket_and_socketpair_allowed_for_local_process_spawn"] is True
        and value[
            "socketpair_connected_write_read_classified_as_local_ipc_only"
        ] is True
        and value["sendto_recvfrom_denied"] is True
        and value["sendmsg_recvmsg_mmsg_denied"] is True
        and value["af_unix_connect_bind_listen_accept_denied"] is True
        and value["io_uring_setup_enter_register_denied"] is True
        and value[
            "same_uid_descriptor_and_memory_relay_syscalls_denied"
        ] is True
        and value["inherited_communication_fds"] is False
        and value["ip_address_families_available"] is False
        and value["local_af_unix_ipc_permitted"] is True
        and value["local_af_unix_ipc_observed"] is True
        and value["af_unix_external_relay_surface_observed"] is False
        and value[
            "strict_no_socket_runtime_boundary_is_not_this_build_boundary"
        ] is True
        and value["network_communication_performed"] is False,
        "outer-network-boundary-contract",
    )
    probe = value["probe"]
    _need(
        type(probe) is dict
        and set(probe)
        == {
            "unit",
            "unit_identity",
            "unit_identity_was_fresh_and_consumed_before_start",
            "command_sha256",
            "properties",
            "show_sha256",
            "show_bytes",
            "journal_sha256",
            "journal_bytes",
            "journal",
            "invocation_id",
            "exec_main_pid",
            "result",
            "exec_main_status",
            "unit_stopped_after_capture",
            "af_inet_and_af_inet6_socket_calls_denied_with_eafnosupport",
            "af_unix_socket_and_socketpair_available_for_process_spawn",
            "local_af_unix_ipc_observed",
            "af_unix_seqpacket_connected_write_and_read_observed",
            "fixed_subprocess_spawn_succeeded",
            "af_unix_connect_attempt_denied_with_eperm",
            "af_unix_datagram_sendto_denied_with_eperm",
            "af_unix_recvfrom_denied_with_eperm",
            "io_uring_setup_enter_register_denied_with_eperm_or_enosys",
            "same_uid_descriptor_and_memory_relay_syscalls_denied",
            "initial_standard_fds_are_dev_null",
            "no_other_inherited_fds_observed",
            "network_communication_performed",
        }
        and probe[
            "af_inet_and_af_inet6_socket_calls_denied_with_eafnosupport"
        ] is True
        and probe[
            "af_unix_socket_and_socketpair_available_for_process_spawn"
        ] is True
        and probe["local_af_unix_ipc_observed"] is True
        and probe[
            "af_unix_seqpacket_connected_write_and_read_observed"
        ] is True
        and probe["fixed_subprocess_spawn_succeeded"] is True
        and probe["af_unix_connect_attempt_denied_with_eperm"] is True
        and probe["af_unix_datagram_sendto_denied_with_eperm"] is True
        and probe["af_unix_recvfrom_denied_with_eperm"] is True
        and probe[
            "io_uring_setup_enter_register_denied_with_eperm_or_enosys"
        ] is True
        and probe[
            "same_uid_descriptor_and_memory_relay_syscalls_denied"
        ] is True
        and probe["initial_standard_fds_are_dev_null"] is True
        and probe["no_other_inherited_fds_observed"] is True
        and probe["network_communication_performed"] is False,
        "outer-network-probe-contract",
    )
    probe_unit_name = probe["unit_identity"]["unit_name"]
    _need(_unit_role(probe_unit_name) == "network_probe",
          "outer-probe-unit-role")
    probe_command_sha256 = core.sha256_bytes(
        core.canonical(_network_probe_command(probe_unit_name))
    )
    _validate_transient_unit_evidence(
        probe, probe_unit_name, probe_command_sha256
    )


def _validate_outer_receipt(value: dict) -> None:
    _need(value["schema"] == RECEIPT_SCHEMA, "outer-receipt-schema")
    _need(value["classification"] == CLASSIFICATION, "outer-classification")
    _need(value["authorization"] is False, "outer-authorization")
    _need(value["privacy_acceptance"] is False, "outer-privacy-acceptance")
    _need(value["financial_acceptance"] is False, "outer-financial-acceptance")
    _need(value["verification"] is False, "outer-verification")
    _need(value["actions"] == _fixed_actions(), "outer-actions")
    _validate_review_snapshot_contract(value["review_gate"])
    build = value["build"]
    _need(
        build["actual_subprocess_executed"] is True
        and build["binary_was_not_executed"] is True
        and build["locked"] is True
        and build["offline"] is True
        and build["default_features"] is False
        and build["features"] == [FEATURE_NAME]
        and build["example"] == PROOF_EXAMPLE_NAME
        and build["examples"] == list(EXAMPLE_NAMES)
        and build["single_cargo_invocation_for_both_examples"] is True
        and build["both_binaries_were_not_executed"] is True,
        "outer-build-contract",
    )
    _validate_build_environment_contract(build)
    _validate_network_boundary_contract(value["network_boundary"])
    ledger = build["unit_identity_ledger"]
    _validate_unit_ledger_contract(ledger)
    build_unit_name = ledger["build_unit_name"]
    probe_unit_name = ledger["probe_unit_name"]
    _need(
        build["unit"]["unit_identity"]["reservation"]
        == ledger["units"][build_unit_name]["reservation"]
        and build["unit"]["unit_identity"]["consumption"]
        == ledger["units"][build_unit_name]["consumption"]
        and value["network_boundary"]["probe"]["unit_identity"]["reservation"]
        == ledger["units"][probe_unit_name]["reservation"]
        and value["network_boundary"]["probe"]["unit_identity"]["consumption"]
        == ledger["units"][probe_unit_name]["consumption"]
        and build["unit"]["unit_identity"]["unit_name"] == build_unit_name
        and value["network_boundary"]["probe"]["unit_identity"]["unit_name"]
        == probe_unit_name,
        "unit-ledger-execution-binding",
    )
    closure = value["closure_scope"]
    _need(
        closure["combined_assignment_plus_prover_closure_frozen"] is True
        and closure["proof_entry_source_present"] is True
        and closure["verifier_entry_source_present"] is True
        and closure["private_prover_source_present"] is True
        and closure["reviewed_low_memory_source_present"] is True
        and closure["parent_verifier_closure_frozen"] is True,
        "outer-closure-contract",
    )
    unsigned = dict(value)
    claimed = unsigned.pop("receipt_identity_sha256")
    _need(claimed == core.sha256_bytes(core.canonical(unsigned)),
          "outer-receipt-identity")


def _validate_atomic_unit_identity_evidence(root: Path, ledger: dict) -> None:
    atomic = ledger["atomic_evidence"]
    root = Path(root)
    core._directory(root, 0o500)
    expected_files = {
        record["relative_path"]: record for record in atomic["records"]
    }
    observed_files = []
    observed_directories = []
    for current_raw, directories, files in os.walk(root, followlinks=False):
        current = Path(current_raw)
        core._directory(current, 0o500)
        relative_dir = current.relative_to(root)
        observed_directories.append(
            "" if relative_dir == Path(".") else relative_dir.as_posix()
        )
        for name in directories:
            core._directory(current / name, 0o500)
        for name in files:
            path = current / name
            relative = path.relative_to(root).as_posix()
            expected = expected_files.get(relative)
            _need(expected is not None, "unit-atomic-evidence-extra-file")
            identity = core._stable_file_identity(path, 0o400)
            _need(
                identity["bytes"] == expected["bytes"]
                and identity["sha256"] == expected["sha256"]
                and identity["mode_octal"] == "0400"
                and os.lstat(path).st_nlink == 1,
                "unit-atomic-evidence-file",
            )
            observed_files.append(relative)
    expected_directories = {
        "",
        f"{ledger['probe_unit_name']}.identity",
        f"{ledger['build_unit_name']}.identity",
    }
    _need(
        set(observed_files) == set(expected_files)
        and set(observed_directories) == expected_directories,
        "unit-atomic-evidence-tree",
    )


def _copy_atomic_unit_identity_evidence(staging: Path, ledger: dict) -> None:
    _validate_unit_ledger_contract(ledger)
    destination = staging / ledger["atomic_evidence"]["root_name"]
    os.mkdir(destination, 0o700)
    for unit_name in (ledger["probe_unit_name"], ledger["build_unit_name"]):
        os.mkdir(destination / f"{unit_name}.identity", 0o700)
    source_references = {
        "RUN-IDENTITY.json": ledger["run_identity"],
    }
    for unit_name in (ledger["probe_unit_name"], ledger["build_unit_name"]):
        for record_name, key in (
            ("RESERVATION.json", "reservation"),
            ("CONSUMPTION.json", "consumption"),
        ):
            source_references[
                f"{unit_name}.identity/{record_name}"
            ] = ledger["units"][unit_name][key]
    for expected in ledger["atomic_evidence"]["records"]:
        relative = expected["relative_path"]
        source_reference = source_references[relative]
        raw, identity = core._stable_file_bytes(
            Path(source_reference["path"]), 0o400
        )
        _need(
            identity["bytes"] == source_reference["bytes"]
            and identity["sha256"] == source_reference["sha256"],
            "unit-atomic-source-record-changed",
        )
        copied = core._write_new(destination / relative, raw, 0o400)
        _need(
            copied["bytes"] == expected["bytes"]
            and copied["sha256"] == expected["sha256"],
            "unit-atomic-copy-content",
        )
    core._seal_directories(destination)
    _validate_atomic_unit_identity_evidence(destination, ledger)
    _validate_unit_ledger_contract(ledger)


def _publish_outer_evidence(parent: Path, source_raw: bytes, receipt: dict) -> dict:
    parent = Path(parent).absolute()
    core._directory(parent, 0o700)
    final = parent / EVIDENCE_NAME
    _need(not os.path.lexists(final), "outer-evidence-create-new")
    staging = parent / f".{EVIDENCE_NAME}.staging-{uuid.uuid4()}"
    os.mkdir(staging, 0o700)
    try:
        source_ref = core._write_new(staging / "FREEZER-SOURCE.py", source_raw, 0o400)
        _validate_outer_receipt(receipt)
        _copy_atomic_unit_identity_evidence(
            staging, receipt["build"]["unit_identity_ledger"]
        )
        receipt_ref = core._write_new(
            staging / "PROOF-BUILD-RECEIPT.json", core.canonical(receipt), 0o400
        )
        _need(
            set(os.listdir(staging))
            == {
                "FREEZER-SOURCE.py", "PROOF-BUILD-RECEIPT.json",
                "UNIT-IDENTITY-EVIDENCE",
            },
            "outer-evidence-exact-files",
        )
        core._fsync_directory(staging)
        os.chmod(staging, 0o500, follow_symlinks=False)
        core._directory(staging, 0o500)
        _validate_unit_ledger_contract(
            receipt["build"]["unit_identity_ledger"]
        )
        descriptor = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            core._rename_no_replace_at(descriptor, staging.name, final.name)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        # Retain failed create-new staging evidence for diagnosis.
        raise
    core._directory(final, 0o500)
    final_source = core._stable_file_identity(final / "FREEZER-SOURCE.py", 0o400)
    final_receipt = core._stable_file_identity(
        final / "PROOF-BUILD-RECEIPT.json", 0o400
    )
    _validate_atomic_unit_identity_evidence(
        final / "UNIT-IDENTITY-EVIDENCE",
        receipt["build"]["unit_identity_ledger"],
    )
    _validate_unit_ledger_contract(receipt["build"]["unit_identity_ledger"])
    _need(
        final_source["sha256"] == source_ref["sha256"]
        and final_receipt["sha256"] == receipt_ref["sha256"],
        "outer-evidence-final-content",
    )
    return {
        "root": str(final),
        "freezer_source_sha256": source_ref["sha256"],
        "receipt_sha256": receipt_ref["sha256"],
    }


def _create_private_parent() -> None:
    _need(not os.path.lexists(OUTPUT_PARENT), "fixed-output-parent-create-new")
    os.mkdir(OUTPUT_PARENT, 0o700)
    core._directory(OUTPUT_PARENT, 0o700)
    core._fsync_directory(PRIVATE_OUTPUT_BASE)


def _fresh_unit_name(prefix: str) -> str:
    _need(prefix in (PROBE_UNIT_PREFIX, BUILD_UNIT_PREFIX),
          "unit-name-prefix")
    value = prefix + secrets.token_hex(16)
    _unit_role(value)
    return value


def _create_unit_identity_ledger() -> tuple[Path, dict]:
    core._directory(OUTPUT_PARENT, 0o700)
    ledger = OUTPUT_PARENT / UNIT_LEDGER_NAME
    _need(not os.path.lexists(ledger), "unit-ledger-create-new")
    os.mkdir(ledger, 0o700)
    core._directory(ledger, 0o700)
    probe_unit_name = _fresh_unit_name(PROBE_UNIT_PREFIX)
    build_unit_name = _fresh_unit_name(BUILD_UNIT_PREFIX)
    _need(probe_unit_name != build_unit_name, "unit-names-distinct")
    run_identity = _unit_record_identity(
        {
            "schema": UNIT_RUN_IDENTITY_SCHEMA,
            "run_id": str(uuid.uuid4()),
            "probe_unit_name": probe_unit_name,
            "build_unit_name": build_unit_name,
            "unit_names_cryptographically_unpredictable": True,
            "unit_names_reserved_before_inspection_or_start": True,
            "authorization": False,
        }
    )
    core._write_new(
        ledger / "RUN-IDENTITY.json", core.canonical(run_identity), 0o400
    )
    core._fsync_directory(ledger)
    core._fsync_directory(OUTPUT_PARENT)
    return ledger, run_identity


def _load_unit_run_identity(ledger_root: Path) -> dict:
    value, _ = _load_unit_record(
        Path(ledger_root) / "RUN-IDENTITY.json", UNIT_RUN_IDENTITY_SCHEMA
    )
    _need(
        set(value)
        == {
            "schema",
            "run_id",
            "probe_unit_name",
            "build_unit_name",
            "unit_names_cryptographically_unpredictable",
            "unit_names_reserved_before_inspection_or_start",
            "authorization",
            "record_identity_sha256",
        }
        and _is_canonical_uuid(value["run_id"])
        and _unit_role(value["probe_unit_name"]) == "network_probe"
        and _unit_role(value["build_unit_name"]) == "cargo_build"
        and value["probe_unit_name"] != value["build_unit_name"]
        and value["unit_names_cryptographically_unpredictable"] is True
        and value["unit_names_reserved_before_inspection_or_start"] is True
        and value["authorization"] is False,
        "unit-run-identity-contract",
    )
    return value


def _seal_unit_identity_ledger(ledger_root: Path) -> dict:
    ledger_root = Path(ledger_root).absolute()
    core._directory(ledger_root, 0o700)
    run_identity = _load_unit_run_identity(ledger_root)
    probe_unit_name = run_identity["probe_unit_name"]
    build_unit_name = run_identity["build_unit_name"]
    expected_children = {
        "RUN-IDENTITY.json",
        f"{probe_unit_name}.identity",
        f"{build_unit_name}.identity",
    }
    _need(set(os.listdir(ledger_root)) == expected_children,
          "unit-ledger-exact-units")
    units = {}
    for unit_name in (probe_unit_name, build_unit_name):
        unit_root = ledger_root / f"{unit_name}.identity"
        core._directory(unit_root, 0o500)
        _need(
            set(os.listdir(unit_root)) == {"RESERVATION.json", "CONSUMPTION.json"},
            "unit-ledger-exact-records",
        )
        _validate_unit_record_pair(unit_root, unit_name)
        units[unit_name] = {
            "unit_root": str(unit_root),
            "unit_root_reference": core._directory_ref(unit_root, 0o500),
            "reservation": _unit_record_reference(
                unit_root / "RESERVATION.json", "RESERVATION.json"
            ),
            "consumption": _unit_record_reference(
                unit_root / "CONSUMPTION.json", "CONSUMPTION.json"
            ),
        }
    core._fsync_directory(ledger_root)
    os.chmod(ledger_root, 0o500, follow_symlinks=False)
    core._directory(ledger_root, 0o500)
    root_reference = core._directory_ref(ledger_root, 0o500)
    value = {
        "root": str(ledger_root),
        "mode_octal": "0500",
        "root_reference": root_reference,
        "unit_count": 2,
        "run_id": run_identity["run_id"],
        "probe_unit_name": probe_unit_name,
        "build_unit_name": build_unit_name,
        "run_identity": _unit_record_reference(
            ledger_root / "RUN-IDENTITY.json", "RUN-IDENTITY.json"
        ),
        "units": units,
        "atomic_evidence": {
            "root_name": "UNIT-IDENTITY-EVIDENCE",
            "record_count": 5,
            "reservation_and_consumption_record_count": 4,
            "records": [
                {
                    "relative_path": "RUN-IDENTITY.json",
                    **{
                        key: _unit_record_reference(
                            ledger_root / "RUN-IDENTITY.json",
                            "RUN-IDENTITY.json",
                        )[key]
                        for key in (
                            "bytes", "sha256", "mode_octal", "link_count"
                        )
                    },
                },
                *[
                    {
                        "relative_path": f"{unit_name}.identity/{record_name}",
                        **{
                            key: units[unit_name][record_key][key]
                            for key in (
                                "bytes", "sha256", "mode_octal", "link_count"
                            )
                        },
                    }
                    for unit_name in (probe_unit_name, build_unit_name)
                    for record_name, record_key in (
                        ("RESERVATION.json", "reservation"),
                        ("CONSUMPTION.json", "consumption"),
                    )
                ],
            ],
            "copied_into_atomic_outer_evidence": True,
        },
        "reservations_and_consumptions_retained": True,
        "authorization": False,
    }
    value["ledger_identity_sha256"] = core.sha256_bytes(core.canonical(value))
    return value


def run_freeze() -> dict:
    reviewed_initial = _require_reviewed_source_bindings()
    reviewed_tool_bindings = _require_reviewed_tool_bindings()
    _validate_fixed_host_paths()
    build_tools_initial = _capture_build_tool_identities(
        reviewed_tool_bindings
    )
    script_path = Path(__file__).resolve(strict=True)
    core_path = Path(core.__file__).resolve(strict=True)
    freezer_raw, freezer_initial = _capture_python_source(script_path)
    core_raw, core_initial = _capture_python_source(core_path)
    _create_private_parent()
    unit_ledger, unit_run_identity = _create_unit_identity_ledger()
    probe_unit_name = unit_run_identity["probe_unit_name"]
    build_unit_name = unit_run_identity["build_unit_name"]

    probe = _run_transient_unit(
        probe_unit_name, _network_probe_command(probe_unit_name), unit_ledger
    )
    probe.update(
        {
            "af_inet_and_af_inet6_socket_calls_denied_with_eafnosupport": True,
            "af_unix_socket_and_socketpair_available_for_process_spawn": True,
            "local_af_unix_ipc_observed": True,
            "af_unix_seqpacket_connected_write_and_read_observed": True,
            "fixed_subprocess_spawn_succeeded": True,
            "af_unix_connect_attempt_denied_with_eperm": True,
            "af_unix_datagram_sendto_denied_with_eperm": True,
            "af_unix_recvfrom_denied_with_eperm": True,
            "io_uring_setup_enter_register_denied_with_eperm_or_enosys": True,
            "same_uid_descriptor_and_memory_relay_syscalls_denied": True,
            "initial_standard_fds_are_dev_null": True,
            "no_other_inherited_fds_observed": True,
            "network_communication_performed": False,
        }
    )

    session = _begin_proof_candidate(REPO_ROOT, OUTPUT_PARENT, OUTPUT_NAME)
    review_snapshot_binding = _review_snapshot_binding(reviewed_initial, session)
    _validate_manifest_packages(session.manifest)
    isolated_cargo_home = _create_isolated_cargo_home(session)
    _refuse_proof_execution_markers(session.target_root)
    build_command = _cargo_build_command(
        session.snapshot_root,
        session.target_root,
        build_unit_name,
        build_tools_initial["tools"]["cargo"],
    )
    build = _run_transient_unit(
        build_unit_name, build_command, unit_ledger
    )
    unit_ledger_evidence = _seal_unit_identity_ledger(unit_ledger)
    build_tools_after = _capture_build_tool_identities(
        reviewed_tool_bindings
    )
    _need(build_tools_after == build_tools_initial,
          "build-tools-changed-across-build")
    _require_isolated_cargo_home_unchanged(isolated_cargo_home)
    _refuse_proof_execution_markers(session.target_root)
    _require_review_snapshot_binding_unchanged(
        review_snapshot_binding, reviewed_initial, session
    )

    cargo_proof_binary = (
        session.target_root / "release" / "examples" / PROOF_EXAMPLE_NAME
    )
    cargo_verifier_binary = (
        session.target_root / "release" / "examples" / VERIFIER_EXAMPLE_NAME
    )
    cargo_proof_dep_info = cargo_proof_binary.with_suffix(".d")
    cargo_verifier_dep_info = cargo_verifier_binary.with_suffix(".d")
    cargo_proof_raw, cargo_proof_reference = _stable_cargo_hardlinked_binary(
        cargo_proof_binary
    )
    cargo_verifier_raw, cargo_verifier_reference = (
        _stable_cargo_hardlinked_binary(cargo_verifier_binary)
    )
    proof_dep_raw, cargo_proof_dep_identity = core._stable_file_bytes(
        cargo_proof_dep_info, 0o600
    )
    verifier_dep_raw, cargo_verifier_dep_identity = core._stable_file_bytes(
        cargo_verifier_dep_info, 0o600
    )
    proof_dependency_relatives, proof_dep_derivation = _derive_dep_info_members(
        proof_dep_raw,
        snapshot_root=session.snapshot_root,
        target_root=session.target_root,
        original_source_root=session.source_root,
        snapshot_refs=session.snapshot_refs,
        expected_target=cargo_proof_binary,
        required_dependency_relatives=REQUIRED_PROOF_DEPENDENCY_RELATIVES,
        closure_label="proof",
    )
    verifier_dependency_relatives, verifier_dep_derivation = (
        _derive_dep_info_members(
            verifier_dep_raw,
            snapshot_root=session.snapshot_root,
            target_root=session.target_root,
            original_source_root=session.source_root,
            snapshot_refs=session.snapshot_refs,
            expected_target=cargo_verifier_binary,
            required_dependency_relatives=REQUIRED_VERIFIER_DEPENDENCY_RELATIVES,
            closure_label="verifier",
        )
    )
    _need(
        set(proof_dependency_relatives).issubset(reviewed_initial)
        and set(verifier_dependency_relatives).issubset(reviewed_initial),
        "dependency-closure-not-independently-reviewed",
    )
    admission = session.target_root / "proof-freeze-admission"
    os.mkdir(admission, 0o700)
    detached_proof_binary = admission / "w1-proof-build-binary"
    detached_verifier_binary = admission / "w1-parent-verifier-build-binary"
    detached_proof_reference = core._write_new(
        detached_proof_binary, cargo_proof_raw, 0o500
    )
    detached_proof_reference["link_count"] = 1
    detached_verifier_reference = core._write_new(
        detached_verifier_binary, cargo_verifier_raw, 0o500
    )
    detached_verifier_reference["link_count"] = 1
    proof_admission_dep_raw = _admission_dep_info(
        detached_target=detached_proof_binary,
        snapshot_root=session.snapshot_root,
        relatives=proof_dependency_relatives,
    )
    verifier_admission_dep_raw = _admission_dep_info(
        detached_target=detached_verifier_binary,
        snapshot_root=session.snapshot_root,
        relatives=verifier_dependency_relatives,
    )
    proof_admission_dep_info = admission / "w1-proof-build-binary.d"
    verifier_admission_dep_info = admission / "w1-parent-verifier-build-binary.d"
    proof_admission_dep_reference = core._write_new(
        proof_admission_dep_info, proof_admission_dep_raw, 0o400
    )
    proof_admission_dep_reference["link_count"] = 1
    verifier_admission_dep_reference = core._write_new(
        verifier_admission_dep_info, verifier_admission_dep_raw, 0o400
    )
    verifier_admission_dep_reference["link_count"] = 1
    _need(
        detached_proof_reference["sha256"] == cargo_proof_reference["sha256"]
        and detached_proof_reference["bytes"] == cargo_proof_reference["bytes"]
        and detached_proof_reference["mode_octal"] == "0500"
        and detached_verifier_reference["sha256"]
        == cargo_verifier_reference["sha256"]
        and detached_verifier_reference["bytes"]
        == cargo_verifier_reference["bytes"]
        and detached_verifier_reference["mode_octal"] == "0500",
        "detached-binaries-byte-identity",
    )
    _require_live_manifest_unchanged(
        session.manifest, "live-source-changed-during-build"
    )
    frozen = _finalize_proof_candidate(
        session,
        proof_binary=detached_proof_binary,
        proof_admission_dep_info=proof_admission_dep_info,
        proof_dependency_relatives=proof_dependency_relatives,
        verifier_binary=detached_verifier_binary,
        verifier_admission_dep_info=verifier_admission_dep_info,
        verifier_dependency_relatives=verifier_dependency_relatives,
    )
    _need(frozen["production_build"] is False, "core-production-build-claim")
    _need(frozen["authorization"] is False, "core-authorization-claim")

    cargo_proof_after_raw, cargo_proof_after_reference = (
        _stable_cargo_hardlinked_binary(cargo_proof_binary)
    )
    cargo_verifier_after_raw, cargo_verifier_after_reference = (
        _stable_cargo_hardlinked_binary(cargo_verifier_binary)
    )
    proof_dep_after_raw, proof_dep_after_identity = core._stable_file_bytes(
        cargo_proof_dep_info, 0o600
    )
    verifier_dep_after_raw, verifier_dep_after_identity = core._stable_file_bytes(
        cargo_verifier_dep_info, 0o600
    )
    _need(
        cargo_proof_after_raw == cargo_proof_raw
        and cargo_proof_after_reference == cargo_proof_reference
        and cargo_verifier_after_raw == cargo_verifier_raw
        and cargo_verifier_after_reference == cargo_verifier_reference,
        "cargo-binaries-changed-across-freeze",
    )
    _need(
        proof_dep_after_raw == proof_dep_raw
        and proof_dep_after_identity == cargo_proof_dep_identity
        and verifier_dep_after_raw == verifier_dep_raw
        and verifier_dep_after_identity == cargo_verifier_dep_identity,
        "cargo-dep-infos-changed-across-freeze",
    )
    _refuse_proof_execution_markers(session.target_root)
    _require_live_manifest_unchanged(
        session.manifest, "live-source-changed-during-freeze"
    )
    reviewed_after = _require_reviewed_source_bindings()
    _need(reviewed_after == reviewed_initial, "reviewed-source-changed-during-build")

    bundle = Path(frozen["root"])
    _require_review_snapshot_binding_unchanged(
        review_snapshot_binding,
        reviewed_initial,
        session,
        snapshot_root=bundle / "sources",
    )
    inner_receipt = _file_reference(bundle / "BUILD-RECEIPT.json", 0o400)
    source_manifest = _file_reference(bundle / "SOURCE-MANIFEST.json", 0o400)
    frozen_core_source = _file_reference(bundle / "FREEZER-SOURCE.py", 0o400)
    frozen_binary = _file_reference(
        bundle / "artifacts" / "candidate-binary", 0o500
    )
    frozen_dep_info = _file_reference(
        bundle / "artifacts" / "candidate-binary.d", 0o400
    )
    frozen_verifier_binary = _file_reference(
        bundle / "artifacts" / "verify_frozen_w1_round1_receipt", 0o500
    )
    frozen_verifier_dep_info = _file_reference(
        bundle / "artifacts" / "verify_frozen_w1_round1_receipt.d", 0o400
    )
    _need(
        frozen_binary["sha256"] == cargo_proof_reference["sha256"]
        and frozen_binary["bytes"] == cargo_proof_reference["bytes"]
        and frozen_binary["link_count"] == 1
        and frozen_verifier_binary["sha256"] == cargo_verifier_reference["sha256"]
        and frozen_verifier_binary["bytes"] == cargo_verifier_reference["bytes"]
        and frozen_verifier_binary["link_count"] == 1,
        "frozen-binaries-not-detached-cargo-binaries",
    )
    expected_publication_dep = _publication_dep_info(
        proof_dependency_relatives, "artifacts/candidate-binary"
    )
    expected_verifier_publication_dep = _publication_dep_info(
        verifier_dependency_relatives,
        "artifacts/verify_frozen_w1_round1_receipt",
    )
    _need(
        frozen_dep_info["raw"] == expected_publication_dep
        and frozen_verifier_dep_info["raw"]
        == expected_verifier_publication_dep,
        "frozen-dep-infos-not-relocatable-contract",
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
    core_after = _require_python_source_unchanged(core_path, core_raw, core_initial)
    _need(
        frozen_core_source["bytes"] == len(core_raw)
        and frozen_core_source["sha256"] == core.sha256_bytes(core_raw),
        "frozen-core-source-not-executed-core-source",
    )
    manifest_paths = [member["relative_path"] for member in session.manifest["members"]]
    _need(
        list(proof_dependency_relatives)
        == [
            relative
            for relative in manifest_paths
            if relative in set(proof_dependency_relatives)
        ]
        and list(verifier_dependency_relatives)
        == [
            relative
            for relative in manifest_paths
            if relative in set(verifier_dependency_relatives)
        ],
        "dependency-orders-not-manifest-order",
    )

    receipt = _receipt_identity(
        {
            "schema": RECEIPT_SCHEMA,
            "classification": CLASSIFICATION,
            "fixed_no_argument_entrypoint": True,
            "repository_root": str(REPO_ROOT),
            "private_output_parent": str(OUTPUT_PARENT),
            "review_gate": {
                "independent_review_explicitly_bound_before_execution": True,
                "reviewed_sources": reviewed_initial,
                "review_manifest_snapshot_binding": review_snapshot_binding,
                "review_manifest_snapshot_rechecked_after_build": True,
                "review_manifest_snapshot_rechecked_after_publication": True,
                "reviewed_sources_equal_after_atomic_freeze": True,
            },
            "source_snapshot": {
                "root": str(bundle / "sources"),
                "package_roots": list(EXPECTED_PACKAGE_ROOTS),
                "package_count": 4,
                "path_compiled_sources": list(PATH_COMPILED_SOURCE_RELATIVES),
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
                "environment_launcher": str(ENV),
                "environment_cleared_with_i": True,
                "exact_cargo_environment": list(
                    _cargo_environment(session.target_root)
                ),
                "ambient_manager_environment_inherited_by_cargo": False,
                "bootstrap_unset_environment": list(
                    BOOTSTRAP_UNSET_ENVIRONMENT
                ),
                "bootstrap": {
                    "schema": BUILD_BOOTSTRAP_SCHEMA,
                    "interpreter": str(PYTHON),
                    "source_bytes": len(BUILD_BOOTSTRAP_SOURCE.encode()),
                    "source_sha256": core.sha256_bytes(
                        BUILD_BOOTSTRAP_SOURCE.encode()
                    ),
                    "exact_environment_verified_in_build_unit": True,
                    "inherited_fds_exactly_0_1_2_dev_null_verified_in_build_unit": True,
                    "cargo_opened_and_rehashed_after_inherited_fd_check": True,
                    "cargo_exec_primitive": "os.execve-authenticated-fd",
                    "cargo_argv": [str(CARGO), *CARGO_BUILD_ARGUMENTS],
                    "cargo_identity": build_tools_initial["tools"]["cargo"],
                    "proof_or_verifier_binary_executed": False,
                },
                "build_tools": {
                    "before": build_tools_initial,
                    "after": build_tools_after,
                    "exactly_equal_across_build": True,
                    "reviewed_identity_map": reviewed_tool_bindings,
                    "toolchain_dynamic_library_closure_bound": False,
                },
                "isolated_cargo_home": isolated_cargo_home,
                "cwd": str(session.snapshot_root / RELATION_RELATIVE),
                "profile": "release",
                "locked": True,
                "offline": True,
                "default_features": False,
                "features": [FEATURE_NAME],
                "example": PROOF_EXAMPLE_NAME,
                "examples": list(EXAMPLE_NAMES),
                "single_cargo_invocation_for_both_examples": True,
                "target_outside_snapshot": True,
                "unit": build,
                "unit_identity_ledger": unit_ledger_evidence,
                "binary_was_not_executed": True,
                "both_binaries_were_not_executed": True,
                "no_binary_execution_command_dispatched": True,
                "proof_execution_markers_absent_before_and_after": True,
                "historical_execution_outside_this_freezer_not_claimed": True,
                "cargo_original_binary": cargo_proof_reference,
                "cargo_original_verifier_binary": cargo_verifier_reference,
                "cargo_original_binaries_were_hardlinks": True,
                "cargo_original_binaries_unchanged_across_freeze": True,
                "detached_create_new_binary": detached_proof_reference,
                "detached_create_new_verifier_binary": detached_verifier_reference,
                "detached_binaries_byte_identical": True,
            },
            "network_boundary": {
                "denied_network_syscalls": list(DENIED_BUILD_NETWORK_SYSCALLS),
                "system_call_error": "EPERM",
                "system_call_architectures": "native",
                "restrict_address_families": "AF_UNIX",
                "socket_and_socketpair_allowed_for_local_process_spawn": True,
                "socketpair_connected_write_read_classified_as_local_ipc_only": True,
                "sendto_recvfrom_denied": True,
                "sendmsg_recvmsg_mmsg_denied": True,
                "af_unix_connect_bind_listen_accept_denied": True,
                "io_uring_setup_enter_register_denied": True,
                "same_uid_descriptor_and_memory_relay_syscalls_denied": True,
                "inherited_communication_fds": False,
                "ip_address_families_available": False,
                "local_af_unix_ipc_permitted": True,
                "local_af_unix_ipc_observed": True,
                "af_unix_external_relay_surface_observed": False,
                "strict_no_socket_runtime_boundary_is_not_this_build_boundary": True,
                "probe": probe,
                "network_communication_performed": False,
            },
            "dep_info": {
                "derivation": (
                    "raw-cargo-dep-info-resolved-to-sealed-inodes-deduplicated-"
                    "then-ordered-by-source-manifest-for-relocatable-publication"
                ),
                "target_relative": "artifacts/candidate-binary",
                "dependency_relatives": list(proof_dependency_relatives),
                "dependency_count": len(proof_dependency_relatives),
                "raw_cargo_derivation": proof_dep_derivation,
                "cargo_original": {
                    "path": str(cargo_proof_dep_info),
                    "bytes": cargo_proof_dep_identity["bytes"],
                    "sha256": cargo_proof_dep_identity["sha256"],
                    "mode_octal": cargo_proof_dep_identity["mode_octal"],
                    "link_count": 1,
                    "unchanged_across_freeze": True,
                },
                "admission_normalized": {
                    "path": str(proof_admission_dep_info),
                    "bytes": proof_admission_dep_reference["bytes"],
                    "sha256": proof_admission_dep_reference["sha256"],
                    "mode_octal": proof_admission_dep_reference["mode_octal"],
                    "link_count": 1,
                },
                "all_members_under_sealed_snapshot": True,
                "all_four_local_packages_represented": True,
                "required_assignment_and_prover_members_present": True,
                "path_compiled_low_memory_sources_present": True,
                "publication_paths_are_bundle_relative": True,
                "predeclared_production_authority": False,
                "frozen": _without_raw(frozen_dep_info),
            },
            "verifier_dep_info": {
                "derivation": (
                    "raw-cargo-dep-info-resolved-to-sealed-inodes-deduplicated-"
                    "then-ordered-by-source-manifest-for-relocatable-publication"
                ),
                "target_relative": "artifacts/verify_frozen_w1_round1_receipt",
                "dependency_relatives": list(verifier_dependency_relatives),
                "dependency_count": len(verifier_dependency_relatives),
                "raw_cargo_derivation": verifier_dep_derivation,
                "cargo_original": {
                    "path": str(cargo_verifier_dep_info),
                    "bytes": cargo_verifier_dep_identity["bytes"],
                    "sha256": cargo_verifier_dep_identity["sha256"],
                    "mode_octal": cargo_verifier_dep_identity["mode_octal"],
                    "link_count": 1,
                    "unchanged_across_freeze": True,
                },
                "admission_normalized": {
                    "path": str(verifier_admission_dep_info),
                    "bytes": verifier_admission_dep_reference["bytes"],
                    "sha256": verifier_admission_dep_reference["sha256"],
                    "mode_octal": verifier_admission_dep_reference["mode_octal"],
                    "link_count": 1,
                },
                "all_members_under_sealed_snapshot": True,
                "all_four_local_packages_represented": True,
                "required_verifier_and_prover_members_present": True,
                "path_compiled_low_memory_sources_present": True,
                "publication_paths_are_bundle_relative": True,
                "predeclared_production_authority": False,
                "frozen": _without_raw(frozen_verifier_dep_info),
            },
            "closure_scope": {
                "combined_assignment_plus_prover_closure_frozen": True,
                "proof_entry_source_present": True,
                "verifier_entry_source_present": True,
                "private_prover_source_present": True,
                "reviewed_low_memory_source_present": True,
                "parent_verifier_closure_frozen": True,
                "local_compiler_source_closure_only": True,
                "registry_dependency_source_closure_frozen": True,
                "isolated_cargo_home_effective_config_frozen": True,
                "toolchain_binary_closure_frozen": False,
            },
            "atomic_core_bundle": {
                "root": str(bundle),
                "result": frozen,
                "receipt": _without_raw(inner_receipt),
                "binary": _without_raw(frozen_binary),
                "parent_verifier_binary": _without_raw(frozen_verifier_binary),
                "parent_verifier_dep_info": _without_raw(
                    frozen_verifier_dep_info
                ),
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
                "registry_dependency_source_closure_bound": True,
                "rust_toolchain_binary_closure_bound": False,
                "build_filesystem_sandbox_present": False,
                "external_build_script_ambient_reads_sandboxed": False,
                "unsealed_original_target_is_authority": False,
                "cryptographic_correctness_proved": False,
                "privacy_proved": False,
                "proof_executed": False,
                "verifier_binary_executed": False,
            },
            "actions": _fixed_actions(),
            "setup": False,
            "pk_decode": False,
            "proving_key_read": False,
            "synthesis": False,
            "proof": False,
            "verification": False,
            "network_communication": False,
            "funds": False,
            "production_build_authority": False,
            "privacy_acceptance": False,
            "financial_acceptance": False,
            "authorization": False,
        }
    )
    evidence = _publish_outer_evidence(OUTPUT_PARENT, freezer_raw, receipt)
    _require_review_snapshot_binding_unchanged(
        review_snapshot_binding,
        reviewed_initial,
        session,
        snapshot_root=bundle / "sources",
    )
    return {
        "status": "TEST_ONLY_COMBINED_W1_PROOF_BUILD_FROZEN",
        "classification": CLASSIFICATION,
        "output_parent": str(OUTPUT_PARENT),
        "bundle": str(bundle),
        "evidence": evidence,
        "binary_sha256": frozen_binary["sha256"],
        "verifier_binary_sha256": frozen_verifier_binary["sha256"],
        "source_members_identity_sha256": frozen[
            "source_members_identity_sha256"
        ],
        "source_member_count": frozen["source_member_count"],
        "dependency_count": len(proof_dependency_relatives),
        "verifier_dependency_count": len(verifier_dependency_relatives),
        "raw_cargo_dependency_count": proof_dep_derivation[
            "raw_dependency_count"
        ],
        "raw_verifier_cargo_dependency_count": verifier_dep_derivation[
            "raw_dependency_count"
        ],
        "canonical_duplicate_count": proof_dep_derivation[
            "duplicate_canonical_member_count"
        ],
        "verifier_canonical_duplicate_count": verifier_dep_derivation[
            "duplicate_canonical_member_count"
        ],
        "executed_core_source_sha256": core_initial["sha256"],
        "proof": False,
        "verification": False,
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
                    "review_gate": _review_gate_status(),
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
