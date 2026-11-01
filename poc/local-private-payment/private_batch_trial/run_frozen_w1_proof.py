#!/usr/bin/env python3
"""One-shot supervisor for the fixed offline W1 proof candidate.

This source is intentionally inert until every artifact-specific constant is
bound after an independently reviewed combined assignment+prover build.  The
no-argument entrypoint then validates the successful assignment-only launch,
the sealed dual-binary build, and the fixed R1CS/PK/VK artifacts before running
the exact proof binary once under a no-network, no-swap, no-core systemd user
unit. Its journal commitment authenticates the exact owned receipt bytes before
the separately sealed verification-only binary repeats genuine verification
and hostile controls. Only the proof, its two public inputs, and public
execution evidence are sealed. No assignment value or assignment fingerprint
is admitted.

Unit tests never execute the proof binary or open a proving key.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
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


SCHEMA = "kpb-frozen-w1-proof-launch-supervisor/v2"
RECEIPT_SCHEMA = "kpb-frozen-w1-proof-launch-receipt/v2"
PROOF_SCHEMA = "kpb-frozen-w1-round1-proof/v1"
CLASSIFICATION = "OFFLINE_SYNTHETIC_UNBACKED_FIXED_W1_GROTH16_PROOF_EVIDENCE_ONLY"

REPO_ROOT = Path(
    "/home/luke/projects/kpi-intensive-2026-10-22/continuation"
)
HERE = REPO_ROOT / "poc/local-private-payment/private_batch_trial"
SUPERVISOR_WORKSPACE_SOURCE = HERE / "run_frozen_w1_proof.py"
LOCAL_ROOT = REPO_ROOT / ".local"
PRIVATE_BUILD_PARENT = Path(
    "/home/luke/projects/kpi-intensive-2026-10-22/"
    "private-batch-w1-proof-build-private-20261029-01"
)
BUILD_BUNDLE = PRIVATE_BUILD_PARENT / "w1-proof-build"
BUILD_EVIDENCE = PRIVATE_BUILD_PARENT / "w1-proof-build-contract"
BUILD_BINARY = BUILD_BUNDLE / "artifacts" / "candidate-binary"
BUILD_DEP_INFO = BUILD_BUNDLE / "artifacts" / "candidate-binary.d"
BUILD_VERIFIER_BINARY = (
    BUILD_BUNDLE / "artifacts" / "verify_frozen_w1_round1_receipt"
)
BUILD_VERIFIER_DEP_INFO = (
    BUILD_BUNDLE / "artifacts" / "verify_frozen_w1_round1_receipt.d"
)
BUILD_MANIFEST = BUILD_BUNDLE / "SOURCE-MANIFEST.json"
BUILD_INNER_RECEIPT = BUILD_BUNDLE / "BUILD-RECEIPT.json"
BUILD_CORE_SOURCE = BUILD_BUNDLE / "FREEZER-SOURCE.py"
BUILD_OUTER_RECEIPT = BUILD_EVIDENCE / "PROOF-BUILD-RECEIPT.json"
BUILD_FREEZER_SOURCE = BUILD_EVIDENCE / "FREEZER-SOURCE.py"

ASSIGNMENT_RUN_ROOT = LOCAL_ROOT / "private-batch-w1-assignment-run-private-20261029-02"
ASSIGNMENT_LAUNCH_RECEIPT = ASSIGNMENT_RUN_ROOT / "LAUNCH-RECEIPT.json"

RUN_ROOT = LOCAL_ROOT / "private-batch-w1-proof-run-private-20261029-01"
PROOF_RECEIPT = RUN_ROOT / "PROOF-RECEIPT.json"
SUPERVISOR_SOURCE = RUN_ROOT / "SUPERVISOR-SOURCE.py"
LAUNCH_RECEIPT = RUN_ROOT / "LAUNCH-RECEIPT.json"

R1CS_PATH = LOCAL_ROOT / "r1cs-aggregate-export-c023-20261029-02" / "aggregate.r1cs"
DECODED_PK_PATH = (
    LOCAL_ROOT / "private-batch-w1-decoded-pk-20261029-01" / "AGGREGATE-PK.bin"
)
DECODE_RECEIPT_PATH = (
    LOCAL_ROOT / "private-batch-w1-decoded-pk-20261029-01" / "DECODE-RECEIPT.json"
)
COMPRESSED_PK_PATH = (
    LOCAL_ROOT
    / "private-batch-stock-setup-20261028-02"
    / "artifact"
    / "AGGREGATE-PK.bin.gz"
)
VK_PATH = (
    LOCAL_ROOT
    / "private-batch-stock-setup-20261028-02"
    / "artifact"
    / "AGGREGATE-VK.bin"
)

ENV = Path("/usr/lib/cargo/bin/coreutils/env")
PYTHON = Path("/usr/bin/python3.14")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
JOURNALCTL = Path("/usr/bin/journalctl")
YAMA_PTRACE_SCOPE = Path("/proc/sys/kernel/yama/ptrace_scope")
# -01/-02 were consumed by host-boundary rehearsals; execution remains bound
# to the fresh, never-started -03 identity.
PROBE_UNIT = "kpb-w1-proof-runtime-netprobe-20261029-03"
RUN_UNIT = "kpb-w1-proof-runtime-20261029-01"
VERIFY_UNIT = "kpb-w1-parent-verifier-runtime-20261029-01"
STAGE0_UNIT = "kpb-w1-proof-supervisor-stage0-20261029-01"
STAGE0_SUPERVISOR_FD = 3
STAGE0_CONTRACT_FD = 4
STAGE0_CONTRACT_SCHEMA = "kpb-w1-proof-supervisor-stage0-contract/v1"
STAGE0_BOOTSTRAP_CONTRACT_SCHEMA = (
    "kpb-w1-proof-supervisor-external-bootstrap-contract/v1"
)

PROOF_RECEIPT_MARKER = "FROZEN_W1_PROOF_RECEIPT_SHA256="
PARENT_VERIFIER_MARKER = "FROZEN_W1_VERIFIED_PROOF_RECEIPT_SHA256="
JOURNAL_PID_REHEARSAL_UNIT = (
    "kpb-w1-proof-journal-rehearsal-72e8e13a9a4348b6ba1e3af43e126e59"
)
JOURNAL_PID_REHEARSAL_INVOCATION_ID = "cd9312eae3724847919a7ba3db2e3898"
JOURNAL_PID_REHEARSAL_EXEC_MAIN_PID = 1_612_556
JOURNAL_PID_REHEARSAL_EXPORT_BYTES = 3_216
JOURNAL_PID_REHEARSAL_EXPORT_SHA256 = (
    "b29d99d0998109a89e99febe4962a3f3c081d6a4e6de6a0494a51cb19ed6d0e2"
)

# These remain None until the create-new dual-binary build (prover plus minimal
# verification-only parent), its dependency closures, and the assignment
# launch have all completed and been independently reviewed.  This is the
# principal fail-closed execution gate.
EXPECTED_BUILD_FREEZER_SOURCE_SHA256: str | None = None
EXPECTED_BUILD_CORE_SOURCE_SHA256: str | None = None
EXPECTED_MANIFEST_SHA256: str | None = None
EXPECTED_INNER_RECEIPT_SHA256: str | None = None
EXPECTED_DEP_INFO_SHA256: str | None = None
EXPECTED_BINARY_SHA256: str | None = None
EXPECTED_BINARY_BYTES: int | None = None
EXPECTED_OUTER_RECEIPT_SHA256: str | None = None
EXPECTED_ASSIGNMENT_LAUNCH_RECEIPT_SHA256: str | None = None
EXPECTED_VERIFIER_BINARY_SHA256: str | None = None
EXPECTED_VERIFIER_BINARY_BYTES: int | None = None
EXPECTED_VERIFIER_DEP_INFO_SHA256: str | None = None
EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256: str | None = None
EXPECTED_VERIFIER_DEPENDENCY_RELATIVES: tuple[str, ...] | None = None

EXPECTED_PUBLIC_INPUTS = (
    "13917591994071772114488105153423377273",
    "33826997814916552742078018202966096202",
)
EXPECTED_ASSIGNMENT_RECEIPT_KEYS_SHA256 = (
    "0ef33def223ee857432f55d0da4f25db070787f7371821445c4875bb1fea2075"
)
EXPECTED_ROUND1_EFFECTS_CORE_SHA256 = (
    "7983de2691ae57b60167c780436e780a4af9a6a2104134804f9afcdfc1d77219"
)
EXPECTED_PACKAGE_ROOTS = (
    "poc/local-private-payment/native-authority/native-core",
    "poc/local-private-payment/native-authority/vendor/native-relation",
    "poc/local-private-payment/private-batch-relation",
    "poc/local-private-payment/private_batch_trial/auth_exit",
)
REQUIRED_PROOF_DEPENDENCIES = (
    "poc/local-private-payment/private-batch-relation/examples/prove_frozen_w1_round1.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_assignment.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_prover.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/lib.rs",
)
REQUIRED_VERIFIER_DEPENDENCIES = (
    "poc/local-private-payment/native-authority/native-core/src/lib.rs",
    "poc/local-private-payment/native-authority/vendor/native-relation/src/lib.rs",
    "poc/local-private-payment/private-batch-relation/examples/verify_frozen_w1_round1_receipt.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_assignment.rs",
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier/frozen_prover.rs",
    "poc/local-private-payment/private-batch-relation/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/auth_exit/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/lib.rs",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover/src/source_only_runner.rs",
)
BUILD_EXAMPLES = (
    "prove_frozen_w1_round1",
    "verify_frozen_w1_round1_receipt",
)
BUILD_ACTIONS = {
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
BUILD_FREEZE_PROBE_UNIT = "kpb-w1-proof-freeze-netprobe-20261029-02"
BUILD_FREEZE_BUILD_UNIT = "kpb-w1-proof-freeze-build-20261029-02"
BUILD_UNIT_LEDGER = PRIVATE_BUILD_PARENT / "UNIT-IDENTITY-LEDGER"
BUILD_UNIT_RESERVATION_SCHEMA = "kpb-w1-proof-build-unit-reservation/v1"
BUILD_UNIT_CONSUMPTION_SCHEMA = "kpb-w1-proof-build-unit-consumption/v1"
BUILD_REVIEW_SNAPSHOT_BINDING_SCHEMA = "kpb-w1-review-snapshot-binding/v1"
BUILD_DENIED_NETWORK_SYSCALLS = (
    "accept", "accept4", "bind", "connect", "getpeername", "getsockname",
    "getsockopt", "listen", "recvmmsg", "recvmmsg_time64", "recvmsg",
    "sendmmsg", "sendmsg", "setsockopt", "shutdown", "socketcall",
    "sendto", "recvfrom", "io_uring_enter", "io_uring_register",
    "io_uring_setup",
)
BUILD_BOOTSTRAP_UNSET_ENVIRONMENT = (
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
    "LD_DEBUG_OUTPUT", "LD_PROFILE", "LD_SHOW_AUXV", "GLIBC_TUNABLES",
    "GCONV_PATH", "LOCPATH", "PYTHONPATH", "PYTHONHOME", "PYTHONINSPECT",
    "PYTHONSTARTUP", "PYTHONBREAKPOINT", "PYTHONWARNINGS", "PYTHONMALLOC",
    "RUSTC", "RUSTDOC", "RUSTUP_TOOLCHAIN", "CARGO_BUILD_TARGET",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
    "CC", "CXX", "AR", "RANLIB", "CFLAGS", "CXXFLAGS", "LDFLAGS",
    "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
)
REVIEWED_BUILD_SOURCES = (
    "poc/local-private-payment/native-authority/native-core/src/lib.rs",
    "poc/local-private-payment/native-authority/vendor/native-relation/src/lib.rs",
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
    "poc/local-private-payment/private_batch_trial/auth_exit/src/lib.rs",
)
VERIFIER_CONTRACT_SOURCE = (
    "poc/local-private-payment/private-batch-relation/src/"
    "counterfactual_w1/offline_verifier/frozen_prover.rs"
)

FIXED_ARTIFACTS = {
    "r1cs": (R1CS_PATH, 2_840_345_392, "cc76d603d0cb184f4e43b99d3af9f215274c0a67bdbec28ed435046c2b9c42bc", 0o400),
    "decoded_pk": (DECODED_PK_PATH, 2_608_842_576, "170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945", 0o400),
    "decode_receipt": (DECODE_RECEIPT_PATH, 1_810, "023171d9ff4328e9fd0653f0a9c7455f11c9da4600e0835231b439b79ba6c40c", 0o400),
    "compressed_pk": (COMPRESSED_PK_PATH, 1_749_414_110, "4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff", 0o444),
    "independent_vk": (VK_PATH, 328, "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102", 0o444),
}

STRICT_DENIED_NETWORK_SYSCALLS = {
    "accept", "accept4", "bind", "connect", "getpeername", "getsockname",
    "getsockopt", "listen", "recv", "recvfrom", "recvmmsg",
    "recvmmsg_time64", "recvmsg", "send", "sendmmsg", "sendmsg", "sendto",
    "setsockopt", "shutdown", "socket", "socketcall", "socketpair",
    "io_uring_enter", "io_uring_register", "io_uring_setup", "pidfd_getfd",
    "process_vm_readv", "process_vm_writev", "ptrace",
}
STAGE0_DENIED_SYSCALLS = {
    "io_uring_enter", "io_uring_register", "io_uring_setup",
    "pidfd_getfd", "process_vm_readv", "process_vm_writev", "ptrace",
}
BOOTSTRAP_UNSET_ENVIRONMENT = (
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
    "LD_DEBUG_OUTPUT", "LD_PROFILE", "LD_SHOW_AUXV", "GLIBC_TUNABLES",
    "GCONV_PATH", "LOCPATH", "PYTHONPATH", "PYTHONHOME", "PYTHONINSPECT",
    "PYTHONSTARTUP", "PYTHONBREAKPOINT", "PYTHONWARNINGS", "PYTHONMALLOC",
)
MEMORY_MAX_BYTES = 20 * 1024**3
RESOURCE_SYSTEMD_PROPERTIES = (
    "SystemCallArchitectures=native",
    "NoNewPrivileges=yes",
    "LimitCORE=0",
    "MemoryMax=20G",
    "MemorySwapMax=0",
    "OOMPolicy=stop",
    "TimeoutStopSec=30s",
    "KillMode=control-group",
    "UMask=0077",
    "UnsetEnvironment=" + " ".join(BOOTSTRAP_UNSET_ENVIRONMENT),
)
COMMON_SYSTEMD_PROPERTIES = (
    "SystemCallFilter=~@network-io io_uring_enter io_uring_register io_uring_setup "
    "pidfd_getfd process_vm_readv process_vm_writev ptrace",
    "SystemCallErrorNumber=EPERM",
    "RestrictAddressFamilies=AF_UNIX",
    *RESOURCE_SYSTEMD_PROPERTIES,
)
PROBE_SYSTEMD_PROPERTIES = COMMON_SYSTEMD_PROPERTIES + (
    "StandardInput=null", "StandardOutput=null", "StandardError=null",
)
PROOF_SYSTEMD_PROPERTIES = COMMON_SYSTEMD_PROPERTIES + (
    "StandardInput=null", "StandardOutput=journal", "StandardError=null",
)
VERIFIER_SYSTEMD_PROPERTIES = COMMON_SYSTEMD_PROPERTIES + (
    "StandardInput=data", "StandardOutput=journal", "StandardError=null",
)
SHOW_PROPERTIES = (
    "LoadState", "ActiveState", "SubState", "Result", "ExecMainStatus",
    "RestrictAddressFamilies", "SystemCallFilter", "SystemCallErrorNumber",
    "SystemCallArchitectures",
    "NoNewPrivileges", "LimitCORE", "MemoryMax", "MemorySwapMax",
    "MemoryPeak", "MemorySwapCurrent", "MemorySwapPeak", "OOMPolicy",
    "RuntimeMaxUSec", "TimeoutStopUSec", "KillMode", "NRestarts", "UMask",
    "InvocationID", "ExecMainPID",
    "TriggeredBy", "Triggers",
    "UnsetEnvironment", "StandardInput", "StandardOutput", "StandardError",
)
STAGE0_SHOW_PROPERTIES = (
    "LoadState", "ActiveState", "SubState", "RestrictAddressFamilies",
    "SystemCallFilter", "SystemCallErrorNumber", "NoNewPrivileges",
    "SystemCallArchitectures",
    "LimitCORE", "MemoryMax", "MemorySwapMax", "OOMPolicy",
    "RuntimeMaxUSec", "TimeoutStopUSec", "KillMode", "NRestarts", "UMask",
    "InvocationID", "ExecMainPID", "UnsetEnvironment", "StandardInput",
    "TriggeredBy", "Triggers",
    "StandardOutput", "StandardError",
)
STAGE0_JOURNAL_FIELDS = (
    "USER_INVOCATION_ID", "_SYSTEMD_INVOCATION_ID", "_SYSTEMD_USER_UNIT",
    "USER_UNIT", "_UID", "_PID", "_TRANSPORT",
)
FIXED_ENVIRONMENT = (
    "HOME=/nonexistent",
    "PATH=/usr/bin:/bin",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "TZ=UTC",
    "RUST_BACKTRACE=0",
    "RAYON_NUM_THREADS=4",
    "MALLOC_ARENA_MAX=2",
)
STAGE0_SYSTEMD_PROPERTIES = (
    "SystemCallFilter=~io_uring_enter io_uring_register io_uring_setup "
    "pidfd_getfd process_vm_readv process_vm_writev ptrace",
    "SystemCallErrorNumber=EPERM",
    "RestrictAddressFamilies=AF_UNIX",
    *RESOURCE_SYSTEMD_PROPERTIES,
    "StandardInput=null",
    "StandardOutput=null",
    "StandardError=null",
)

NETWORK_PROBE_SOURCE = f"""\
import ctypes
import errno
import os
import socket
expected_environment = {dict(value.split("=", 1) for value in FIXED_ENVIRONMENT)!r}
if dict(os.environ) != expected_environment:
    raise SystemExit(4)
live_descriptors = []
for raw_descriptor in os.listdir("/proc/self/fd"):
    descriptor = int(raw_descriptor)
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise SystemExit(10)
    else:
        live_descriptors.append(descriptor)
if sorted(live_descriptors) != [0, 1, 2]:
    raise SystemExit(11)
if any(os.readlink(f"/proc/self/fd/{{descriptor}}") != "/dev/null" for descriptor in (0, 1, 2)):
    raise SystemExit(12)
for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
    try:
        socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise SystemExit(2)
    else:
        raise SystemExit(3)
if os.uname().machine != "x86_64":
    raise SystemExit(7)
library = ctypes.CDLL(None, use_errno=True)
for syscall_number, arguments in (
    (425, (1, 0)),
    (426, (-1, 0, 0, 0, 0, 0)),
    (427, (-1, 0, 0, 0)),
):
    ctypes.set_errno(0)
    if library.syscall(syscall_number, *arguments) != -1:
        raise SystemExit(8)
    if ctypes.get_errno() != errno.EPERM:
        raise SystemExit(9)
"""

# Copy the exact authenticated candidate into a sealed anonymous executable,
# reauthenticate the sealed bytes, and execute only that immutable descriptor.
# This closes the same-UID in-place mutation window between source rehash and
# exec. The final Rust process receives exactly FIXED_ENVIRONMENT.
def _render_identity_bound_exec_source(
    *,
    binary_path: Path,
    receipt_path: Path | None,
    expected_device: int,
    expected_inode: int,
    expected_bytes: int,
    expected_sha256: str,
    expected_owner_uid: int,
) -> str:
    environment = dict(value.split("=", 1) for value in FIXED_ENVIRONMENT)
    arguments = () if receipt_path is None else (str(receipt_path),)
    return f'''import errno
import fcntl
import hashlib
import json
import os
import stat

BINARY = {str(binary_path)!r}
ARGUMENTS = {arguments!r}
EXPECTED_DEVICE = {expected_device!r}
EXPECTED_INODE = {expected_inode!r}
EXPECTED_BYTES = {expected_bytes!r}
EXPECTED_SHA256 = {expected_sha256!r}
EXPECTED_OWNER_UID = {expected_owner_uid!r}
ENVIRONMENT = {environment!r}

def refuse():
    raise SystemExit(70)

def open_descriptors():
    observed = []
    for raw_descriptor in os.listdir("/proc/self/fd"):
        descriptor = int(raw_descriptor)
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                refuse()
        else:
            observed.append(descriptor)
    return sorted(observed)

identity = lambda value: (
    value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
    value.st_size, value.st_mtime_ns, value.st_ctime_ns,
)

if open_descriptors() != [0, 1, 2]:
    refuse()

before_path = os.lstat(BINARY)
if (
    not stat.S_ISREG(before_path.st_mode)
    or stat.S_ISLNK(before_path.st_mode)
    or before_path.st_dev != EXPECTED_DEVICE
    or before_path.st_ino != EXPECTED_INODE
    or before_path.st_size != EXPECTED_BYTES
    or before_path.st_nlink != 1
    or before_path.st_uid != EXPECTED_OWNER_UID
    or stat.S_IMODE(before_path.st_mode) != 0o500
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
            "kpb-frozen-w1-proof-exec",
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
    os.close(source_descriptor)
    source_descriptor = -1
    if open_descriptors() != [0, 1, 2, sealed_descriptor]:
        refuse()
    os.execve(sealed_descriptor, [BINARY, *ARGUMENTS], ENVIRONMENT)
finally:
    if source_descriptor >= 0:
        os.close(source_descriptor)
    if sealed_descriptor >= 0:
        os.close(sealed_descriptor)
'''

TOOL_IDENTITIES = {
    "env": (
        ENV,
        11_807_104,
        "f84e76ea4da1e0c4e92254bd0d7dccdabe2c8b3098e734f27997dae3ee5d8e02",
        116,
    ),
    "python": (
        PYTHON,
        7_477_160,
        "52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41",
        1,
    ),
    "journalctl": (
        JOURNALCTL,
        93_376,
        "a06e30235761e2e6aec20e68ff6f31b82c559944b0c012e24a3db5e0cbcfe479",
        1,
    ),
    "systemd-run": (
        SYSTEMD_RUN,
        97_272,
        "03a68bafb0ebc0f5eff41cbdf3cbbdf126a3bb87e21140f9147bf78edce36d88",
        1,
    ),
    "systemctl": (
        SYSTEMCTL,
        302_112,
        "6394f5e8df92878184de9d4dfb7ac242471cb09daf89d23be4e81ae17e9c03b2",
        1,
    ),
}


def _stage0_systemd_prefix() -> list[str]:
    command = [
        str(SYSTEMD_RUN),
        "--user",
        "--quiet",
        "--no-block",
        f"--unit={STAGE0_UNIT}",
        "--service-type=exec",
        "--expand-environment=no",
    ]
    for value in STAGE0_SYSTEMD_PROPERTIES:
        command.extend(("--property", value))
    return command


def _stage0_show_command() -> list[str]:
    command = [str(SYSTEMCTL), "--user", "show", f"{STAGE0_UNIT}.service"]
    for name in STAGE0_SHOW_PROPERTIES:
        command.extend(("--property", name))
    command.append("--no-pager")
    return command


def _stage0_journal_command() -> list[str]:
    return [
        str(JOURNALCTL), "--user", "--no-pager", "--all",
        "--output=export",
        "--output-fields=" + ",".join(STAGE0_JOURNAL_FIELDS),
        f"--unit={STAGE0_UNIT}.service",
    ]


def _stage0_socket_show_command() -> list[str]:
    return [
        str(SYSTEMCTL), "--user", "show", f"{STAGE0_UNIT}.socket",
        "--property=LoadState", "--property=TriggeredBy",
        "--property=Triggers", "--no-pager",
    ]


def _stage0_socket_journal_command() -> list[str]:
    return [
        str(JOURNALCTL), "--user", "--quiet", "--no-pager", "--all",
        "--output=export", f"--unit={STAGE0_UNIT}.socket",
    ]


def _validate_stage0_source_reference(value: object) -> None:
    need(
        type(value) is dict
        and value.get("path") == str(SUPERVISOR_WORKSPACE_SOURCE)
        and type(value.get("device")) is int
        and type(value.get("inode")) is int
        and type(value.get("bytes")) is int
        and value["bytes"] > 0
        and _is_sha256(value.get("sha256"))
        and value.get("mode_octal") == "0400"
        and value.get("link_count") == 1
        and value.get("owner_uid") == os.getuid()
        and type(value.get("mtime_ns")) is int
        and type(value.get("ctime_ns")) is int,
        "stage0-source-reference",
    )


def _render_stage0_bootstrap_source(supervisor_reference: dict) -> str:
    """Render the finite external root; it imports no workspace module."""
    _validate_stage0_source_reference(supervisor_reference)
    supervisor_reference = _unique_json(canonical(supervisor_reference))
    environment = dict(value.split("=", 1) for value in FIXED_ENVIRONMENT)
    python_contract = TOOL_IDENTITIES["python"]
    return f'''import errno
import fcntl
import hashlib
import json
import os
import stat
import sys

SOURCE = {str(SUPERVISOR_WORKSPACE_SOURCE)!r}
EXPECTED_SOURCE = {supervisor_reference!r}
SOURCE_FD = {STAGE0_SUPERVISOR_FD}
BOOTSTRAP_CONTRACT_FD = {STAGE0_CONTRACT_FD}
BOOTSTRAP_CONTRACT_SCHEMA = {STAGE0_BOOTSTRAP_CONTRACT_SCHEMA!r}
ENV = {str(ENV)!r}
PYTHON = {str(PYTHON)!r}
PYTHON_CONTRACT = {(str(python_contract[0]), *python_contract[1:])!r}
ENVIRONMENT_ITEMS = {FIXED_ENVIRONMENT!r}
ENVIRONMENT = {environment!r}
REQUIRED_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)

def refuse():
    raise SystemExit(70)

def identity(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )

def canonical(value):
    return (json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ) + "\\n").encode()

def read_all(descriptor):
    digest = hashlib.sha256()
    blocks = []
    offset = 0
    while True:
        block = os.pread(descriptor, 1024 * 1024, offset)
        if not block:
            break
        digest.update(block)
        blocks.append(block)
        offset += len(block)
    return b"".join(blocks), digest.hexdigest()

if sys.argv[:1] != ["-c"] or len(sys.argv) != 2:
    refuse()
if dict(os.environ) != ENVIRONMENT:
    refuse()
live = []
for raw_descriptor in os.listdir("/proc/self/fd"):
    descriptor = int(raw_descriptor)
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            refuse()
    else:
        live.append(descriptor)
if sorted(live) != [0, 1, 2]:
    refuse()
try:
    cmdline_raw = open("/proc/self/cmdline", "rb", buffering=0).read()
except OSError:
    refuse()
cmdline = cmdline_raw.split(b"\\x00")
if not cmdline or cmdline[-1] != b"":
    refuse()
cmdline.pop()
try:
    decoded = [value.decode("utf-8") for value in cmdline]
except UnicodeDecodeError:
    refuse()
if len(decoded) != 5 or decoded[:3] != [PYTHON, "-I", "-c"]:
    refuse()
source = decoded[3]
source_sha256 = decoded[4]
if source_sha256 != sys.argv[1] or hashlib.sha256(source.encode()).hexdigest() != source_sha256:
    refuse()

python_path, python_bytes, python_sha256, python_links = PYTHON_CONTRACT
python_before_path = os.lstat(python_path)
if not (
    stat.S_ISREG(python_before_path.st_mode)
    and not stat.S_ISLNK(python_before_path.st_mode)
    and python_before_path.st_uid == 0
    and python_before_path.st_nlink == python_links
    and stat.S_IMODE(python_before_path.st_mode) == 0o755
    and python_before_path.st_size == python_bytes
):
    refuse()
python_descriptor = os.open(python_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    python_before = os.fstat(python_descriptor)
    python_raw, observed_python_sha256 = read_all(python_descriptor)
    python_after = os.fstat(python_descriptor)
    python_after_path = os.lstat(python_path)
    running_python = os.stat("/proc/self/exe")
    if not (
        identity(python_before) == identity(python_after) == identity(python_after_path)
        and (running_python.st_dev, running_python.st_ino)
        == (python_after.st_dev, python_after.st_ino)
        and len(python_raw) == python_bytes
        and observed_python_sha256 == python_sha256
    ):
        refuse()
finally:
    os.close(python_descriptor)

expected_identity = (
    EXPECTED_SOURCE["device"], EXPECTED_SOURCE["inode"], 0o100400,
    EXPECTED_SOURCE["link_count"], EXPECTED_SOURCE["owner_uid"],
    EXPECTED_SOURCE["bytes"], EXPECTED_SOURCE["mtime_ns"],
    EXPECTED_SOURCE["ctime_ns"],
)
before_path = os.lstat(SOURCE)
if identity(before_path) != expected_identity:
    refuse()
source_descriptor = os.open(SOURCE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
sealed_descriptor = -1
bootstrap_contract_descriptor = -1
try:
    opened = os.fstat(source_descriptor)
    source_raw, observed_source_sha256 = read_all(source_descriptor)
    after = os.fstat(source_descriptor)
    after_path = os.lstat(SOURCE)
    if not (
        identity(opened) == identity(after) == identity(after_path)
        and len(source_raw) == EXPECTED_SOURCE["bytes"]
        and observed_source_sha256 == EXPECTED_SOURCE["sha256"]
    ):
        refuse()
    sealed_descriptor = os.memfd_create(
        "kpb-w1-reviewed-supervisor-bootstrap",
        os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
    )
    view = memoryview(source_raw)
    while view:
        count = os.write(sealed_descriptor, view)
        if count <= 0:
            refuse()
        view = view[count:]
    os.fchmod(sealed_descriptor, 0o400)
    fcntl.fcntl(sealed_descriptor, fcntl.F_ADD_SEALS, REQUIRED_SEALS)
    if fcntl.fcntl(sealed_descriptor, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
        refuse()
    for operation in (
        lambda: os.pwrite(sealed_descriptor, b"\\x00", 0),
        lambda: os.ftruncate(sealed_descriptor, len(source_raw) + 1),
        lambda: os.ftruncate(sealed_descriptor, len(source_raw) - 1),
    ):
        try:
            operation()
        except OSError as error:
            if error.errno != errno.EPERM:
                refuse()
        else:
            refuse()
    sealed_raw, sealed_sha256 = read_all(sealed_descriptor)
    sealed = os.fstat(sealed_descriptor)
    if not (
        sealed_raw == source_raw
        and sealed_sha256 == EXPECTED_SOURCE["sha256"]
        and stat.S_ISREG(sealed.st_mode)
        and sealed.st_nlink == 0
        and sealed.st_uid == os.getuid()
        and stat.S_IMODE(sealed.st_mode) == 0o400
    ):
        refuse()
    bootstrap_command = [
        ENV, "-i", *ENVIRONMENT_ITEMS, PYTHON, "-I", "-c", source,
        source_sha256,
    ]
    bootstrap_argv_sha256 = hashlib.sha256(canonical(bootstrap_command)).hexdigest()
    bootstrap_contract = {{
        "schema": BOOTSTRAP_CONTRACT_SCHEMA,
        "bootstrap_source_sha256": source_sha256,
        "bootstrap_argv_sha256": bootstrap_argv_sha256,
        "supervisor_source_reference": EXPECTED_SOURCE,
        "supervisor_source_sha256": EXPECTED_SOURCE["sha256"],
        "exact_environment": list(ENVIRONMENT_ITEMS),
        "sealed_supervisor_fd": SOURCE_FD,
        "sealed_contract_fd": BOOTSTRAP_CONTRACT_FD,
        "authorization": False,
    }}
    bootstrap_contract_raw = canonical(bootstrap_contract)
    bootstrap_contract_descriptor = os.memfd_create(
        "kpb-w1-external-bootstrap-contract",
        os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
    )
    view = memoryview(bootstrap_contract_raw)
    while view:
        count = os.write(bootstrap_contract_descriptor, view)
        if count <= 0:
            refuse()
        view = view[count:]
    os.fchmod(bootstrap_contract_descriptor, 0o400)
    fcntl.fcntl(
        bootstrap_contract_descriptor, fcntl.F_ADD_SEALS, REQUIRED_SEALS,
    )
    if fcntl.fcntl(bootstrap_contract_descriptor, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
        refuse()
    for operation in (
        lambda: os.pwrite(bootstrap_contract_descriptor, b"\\x00", 0),
        lambda: os.ftruncate(
            bootstrap_contract_descriptor, len(bootstrap_contract_raw) + 1,
        ),
        lambda: os.ftruncate(
            bootstrap_contract_descriptor, len(bootstrap_contract_raw) - 1,
        ),
    ):
        try:
            operation()
        except OSError as error:
            if error.errno != errno.EPERM:
                refuse()
        else:
            refuse()
    observed_contract_raw, observed_contract_sha256 = read_all(
        bootstrap_contract_descriptor
    )
    if not (
        observed_contract_raw == bootstrap_contract_raw
        and observed_contract_sha256
        == hashlib.sha256(bootstrap_contract_raw).hexdigest()
    ):
        refuse()
    null_descriptor = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    try:
        for descriptor in (0, 1, 2):
            os.dup2(null_descriptor, descriptor, inheritable=True)
    finally:
        if null_descriptor > 2:
            os.close(null_descriptor)
    os.dup2(sealed_descriptor, SOURCE_FD, inheritable=True)
    os.dup2(
        bootstrap_contract_descriptor, BOOTSTRAP_CONTRACT_FD, inheritable=True,
    )
    os.set_inheritable(SOURCE_FD, True)
    os.set_inheritable(BOOTSTRAP_CONTRACT_FD, True)
    os.execve(
        PYTHON,
        [PYTHON, "-I", f"/proc/self/fd/{{SOURCE_FD}}", "--stage0-render"],
        ENVIRONMENT,
    )
finally:
    os.close(source_descriptor)
    for descriptor in (sealed_descriptor, bootstrap_contract_descriptor):
        if descriptor >= 0 and descriptor not in (SOURCE_FD, BOOTSTRAP_CONTRACT_FD):
            os.close(descriptor)
'''


def _stage0_bootstrap_command(supervisor_reference: dict) -> list[str]:
    source = _render_stage0_bootstrap_source(supervisor_reference)
    return [
        str(ENV), "-i", *FIXED_ENVIRONMENT, str(PYTHON), "-I", "-c",
        source, sha256_bytes(source.encode()),
    ]


def _render_stage0_source(
    supervisor_reference: dict,
    external_bootstrap_source_sha256: str,
    external_bootstrap_argv_sha256: str,
) -> str:
    _validate_stage0_source_reference(supervisor_reference)
    supervisor_reference = _unique_json(canonical(supervisor_reference))
    need(
        _is_sha256(external_bootstrap_source_sha256)
        and _is_sha256(external_bootstrap_argv_sha256),
        "stage0-external-bootstrap-digests",
    )
    tool_contract = {
        name: (str(path), size, digest, links)
        for name, (path, size, digest, links) in TOOL_IDENTITIES.items()
    }
    environment = dict(value.split("=", 1) for value in FIXED_ENVIRONMENT)
    manager_environment = _manager_tool_environment()
    return f'''import errno
import fcntl
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys

SOURCE = {str(SUPERVISOR_WORKSPACE_SOURCE)!r}
EXPECTED_SOURCE = {supervisor_reference!r}
SOURCE_FD = {STAGE0_SUPERVISOR_FD}
CONTRACT_FD = {STAGE0_CONTRACT_FD}
UNIT = {STAGE0_UNIT!r}
SCHEMA = {STAGE0_CONTRACT_SCHEMA!r}
ENV = {str(ENV)!r}
PYTHON = {str(PYTHON)!r}
SYSTEMD_PREFIX = {_stage0_systemd_prefix()!r}
ENVIRONMENT_ITEMS = {FIXED_ENVIRONMENT!r}
ENVIRONMENT = {environment!r}
MANAGER_ENVIRONMENT = {manager_environment!r}
TOOLS = {tool_contract!r}
DENIED = {sorted(STAGE0_DENIED_SYSCALLS)!r}
UNSET = {BOOTSTRAP_UNSET_ENVIRONMENT!r}
SHOW_PROPERTIES = {STAGE0_SHOW_PROPERTIES!r}
SHOW_COMMAND = {_stage0_show_command()!r}
JOURNAL_COMMAND = {_stage0_journal_command()!r}
SOCKET_SHOW_COMMAND = {_stage0_socket_show_command()!r}
SOCKET_JOURNAL_COMMAND = {_stage0_socket_journal_command()!r}
YAMA_PTRACE_SCOPE = {str(YAMA_PTRACE_SCOPE)!r}
EXPECTED_EXTERNAL_BOOTSTRAP_SOURCE_SHA256 = {external_bootstrap_source_sha256!r}
EXPECTED_EXTERNAL_BOOTSTRAP_ARGV_SHA256 = {external_bootstrap_argv_sha256!r}
REQUIRED_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)

def refuse():
    raise SystemExit(70)

def canonical(value):
    return (json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ) + "\\n").encode()

def identity(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )

def read_all(descriptor):
    digest = hashlib.sha256()
    blocks = []
    offset = 0
    while True:
        block = os.pread(descriptor, 1024 * 1024, offset)
        if not block:
            break
        digest.update(block)
        blocks.append(block)
        offset += len(block)
    return b"".join(blocks), digest.hexdigest()

def pinned_tool(path, expected_bytes, expected_sha256, expected_links):
    before_path = os.lstat(path)
    if not (
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == 0
        and before_path.st_nlink == expected_links
        and stat.S_IMODE(before_path.st_mode) == 0o755
        and before_path.st_size == expected_bytes
    ):
        refuse()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        raw, digest = read_all(descriptor)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        if not (
            identity(before) == identity(after) == identity(after_path)
            and len(raw) == expected_bytes
            and digest == expected_sha256
        ):
            refuse()
    finally:
        os.close(descriptor)
    return {{
        "path": path, "device": after.st_dev, "inode": after.st_ino,
        "bytes": expected_bytes, "sha256": expected_sha256,
        "mode_octal": "0755", "link_count": expected_links,
        "owner_uid": 0,
    }}

def seal(descriptor, raw, mode):
    view = memoryview(raw)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            refuse()
        view = view[count:]
    os.fchmod(descriptor, mode)
    fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, REQUIRED_SEALS)
    if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
        refuse()
    for operation in (
        lambda: os.pwrite(descriptor, b"\\x00", 0),
        lambda: os.ftruncate(descriptor, len(raw) + 1),
        lambda: os.ftruncate(descriptor, max(0, len(raw) - 1)),
    ):
        try:
            operation()
        except OSError as error:
            if error.errno != errno.EPERM:
                refuse()
        else:
            refuse()
    observed, digest = read_all(descriptor)
    value = os.fstat(descriptor)
    if not (
        observed == raw
        and digest == hashlib.sha256(raw).hexdigest()
        and stat.S_ISREG(value.st_mode)
        and value.st_nlink == 0
        and value.st_uid == os.getuid()
        and value.st_size == len(raw)
        and stat.S_IMODE(value.st_mode) == mode
    ):
        refuse()

if sys.argv[:1] != ["-c"] or len(sys.argv) != 4:
    refuse()
if dict(os.environ) != ENVIRONMENT:
    refuse()
live_descriptors = []
for raw_descriptor in os.listdir("/proc/self/fd"):
    descriptor = int(raw_descriptor)
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            refuse()
    else:
        live_descriptors.append(descriptor)
if sorted(live_descriptors) != [0, 1, 2]:
    refuse()
for descriptor in (0, 1, 2):
    try:
        target = os.readlink(f"/proc/self/fd/{{descriptor}}")
    except OSError:
        refuse()
    if target != "/dev/null":
        refuse()
for family in (socket.AF_INET, socket.AF_INET6):
    try:
        candidate = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EAFNOSUPPORT):
            refuse()
    else:
        candidate.close()
        refuse()
yama_before_path = os.lstat(YAMA_PTRACE_SCOPE)
if not (
    stat.S_ISREG(yama_before_path.st_mode)
    and not stat.S_ISLNK(yama_before_path.st_mode)
    and yama_before_path.st_uid == 0
    and yama_before_path.st_nlink == 1
    and stat.S_IMODE(yama_before_path.st_mode) == 0o644
):
    refuse()
yama_descriptor = os.open(
    YAMA_PTRACE_SCOPE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
try:
    yama_before = os.fstat(yama_descriptor)
    yama_raw = os.read(yama_descriptor, 16)
    yama_extra = os.read(yama_descriptor, 1)
    yama_after = os.fstat(yama_descriptor)
    yama_after_path = os.lstat(YAMA_PTRACE_SCOPE)
finally:
    os.close(yama_descriptor)
if not (
    identity(yama_before_path) == identity(yama_before)
    == identity(yama_after) == identity(yama_after_path)
    and yama_raw == b"1\\n"
    and yama_extra == b""
):
    refuse()
helper_sha256 = sys.argv[1]
external_bootstrap_source_sha256 = sys.argv[2]
external_bootstrap_argv_sha256 = sys.argv[3]
if not (
    external_bootstrap_source_sha256 == EXPECTED_EXTERNAL_BOOTSTRAP_SOURCE_SHA256
    and external_bootstrap_argv_sha256 == EXPECTED_EXTERNAL_BOOTSTRAP_ARGV_SHA256
):
    refuse()
try:
    cmdline_raw = open("/proc/self/cmdline", "rb", buffering=0).read()
except OSError:
    refuse()
cmdline = cmdline_raw.split(b"\\x00")
if not cmdline or cmdline[-1] != b"":
    refuse()
cmdline.pop()
try:
    decoded_cmdline = [value.decode("utf-8") for value in cmdline]
except UnicodeDecodeError:
    refuse()
if len(decoded_cmdline) != 7 or decoded_cmdline[:3] != [PYTHON, "-I", "-c"]:
    refuse()
helper_source = decoded_cmdline[3]
if (
    decoded_cmdline[4] != helper_sha256
    or decoded_cmdline[5] != external_bootstrap_source_sha256
    or decoded_cmdline[6] != external_bootstrap_argv_sha256
    or hashlib.sha256(helper_source.encode()).hexdigest() != helper_sha256
):
    refuse()
full_command = SYSTEMD_PREFIX + [
    ENV, "-i", *ENVIRONMENT_ITEMS, PYTHON, "-I", "-c",
    helper_source, helper_sha256,
    external_bootstrap_source_sha256, external_bootstrap_argv_sha256,
]

tool_references = {{
    name: pinned_tool(*contract)
    for name, contract in TOOLS.items()
}}

show = subprocess.run(
    SHOW_COMMAND, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, env=MANAGER_ENVIRONMENT, check=False,
)
if show.returncode != 0 or show.stderr != b"":
    refuse()
values = {{}}
try:
    show_text = show.stdout.decode("utf-8")
except UnicodeDecodeError:
    refuse()
for line in show_text.splitlines():
    if "=" not in line:
        refuse()
    key, value = line.split("=", 1)
    if key not in SHOW_PROPERTIES or key in values:
        refuse()
    values[key] = value
if set(values) != set(SHOW_PROPERTIES):
    refuse()
denied = set(values["SystemCallFilter"].removeprefix("~").split())
if not (
    values["LoadState"] == "loaded"
    and values["ActiveState"] == "active"
    and values["SubState"] == "running"
    and values["RestrictAddressFamilies"] == "AF_UNIX"
    and values["SystemCallFilter"].startswith("~")
    and denied == set(DENIED)
    and values["SystemCallErrorNumber"] == str(errno.EPERM)
    and values["SystemCallArchitectures"] == "native"
    and values["NoNewPrivileges"] == "yes"
    and values["LimitCORE"] == "0"
    and values["MemoryMax"] == str(20 * 1024**3)
    and values["MemorySwapMax"] == "0"
    and values["OOMPolicy"] == "stop"
    and values["RuntimeMaxUSec"] == "infinity"
    and values["TimeoutStopUSec"] in ("30s", "30s 0us")
    and values["KillMode"] == "control-group"
    and values["NRestarts"] == "0"
    and values["UMask"] == "0077"
    and len(values["InvocationID"]) == 32
    and all(character in "0123456789abcdef" for character in values["InvocationID"])
    and values["ExecMainPID"] == str(os.getpid())
    and values["TriggeredBy"] == ""
    and values["Triggers"] == ""
    and set(values["UnsetEnvironment"].split()) == set(UNSET)
    and values["StandardInput"] == "null"
    and values["StandardOutput"] == "null"
    and values["StandardError"] == "null"
):
    refuse()
try:
    cgroup_raw = open("/proc/self/cgroup", "rb", buffering=0).read()
except OSError:
    refuse()
if f"/{{UNIT}}.service".encode() not in cgroup_raw:
    refuse()

sync = subprocess.run(
    [TOOLS["journalctl"][0], "--user", "--sync"],
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    env=MANAGER_ENVIRONMENT, check=False,
)
if sync.returncode != 0 or sync.stdout != b"" or sync.stderr != b"":
    refuse()
journal = subprocess.run(
    JOURNAL_COMMAND, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, env=MANAGER_ENVIRONMENT, check=False,
)
if journal.returncode != 0 or journal.stderr != b"" or not journal.stdout:
    refuse()
record_count = 0
for record in journal.stdout.split(b"\\n\\n"):
    if not record:
        continue
    record_count += 1
    invocation_ids = []
    for line in record.splitlines():
        if line.startswith(b"USER_INVOCATION_ID=") or line.startswith(b"_SYSTEMD_INVOCATION_ID="):
            invocation_ids.append(line.split(b"=", 1)[1].decode("ascii"))
    if not invocation_ids or set(invocation_ids) != {{values["InvocationID"]}}:
        refuse()

socket_show = subprocess.run(
    SOCKET_SHOW_COMMAND, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, env=MANAGER_ENVIRONMENT, check=False,
)
if socket_show.returncode != 0 or socket_show.stderr != b"":
    refuse()
try:
    socket_show_values = dict(
        line.split("=", 1)
        for line in socket_show.stdout.decode("utf-8").splitlines()
    )
except (UnicodeDecodeError, ValueError):
    refuse()
if socket_show_values != {{
    "LoadState": "not-found", "TriggeredBy": "", "Triggers": "",
}}:
    refuse()
socket_journal = subprocess.run(
    SOCKET_JOURNAL_COMMAND, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, env=MANAGER_ENVIRONMENT, check=False,
)
if not (
    socket_journal.returncode == 0
    and socket_journal.stdout == b""
    and socket_journal.stderr == b""
):
    refuse()

before_path = os.lstat(SOURCE)
expected_identity = (
    EXPECTED_SOURCE["device"], EXPECTED_SOURCE["inode"], 0o100400,
    EXPECTED_SOURCE["link_count"], EXPECTED_SOURCE["owner_uid"],
    EXPECTED_SOURCE["bytes"], EXPECTED_SOURCE["mtime_ns"],
    EXPECTED_SOURCE["ctime_ns"],
)
if identity(before_path) != expected_identity:
    refuse()
source_descriptor = os.open(SOURCE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
source_memfd = -1
contract_memfd = -1
try:
    opened = os.fstat(source_descriptor)
    source_raw, source_sha256 = read_all(source_descriptor)
    after = os.fstat(source_descriptor)
    after_path = os.lstat(SOURCE)
    if not (
        identity(opened) == identity(after) == identity(after_path)
        and source_sha256 == EXPECTED_SOURCE["sha256"]
        and len(source_raw) == EXPECTED_SOURCE["bytes"]
    ):
        refuse()
    source_memfd = os.memfd_create(
        "kpb-w1-supervisor-source",
        os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
    )
    seal(source_memfd, source_raw, 0o400)
    contract = {{
        "schema": SCHEMA,
        "stage0_unit": UNIT,
        "uid": os.getuid(),
        "supervisor_fd": SOURCE_FD,
        "contract_fd": CONTRACT_FD,
        "supervisor_source_reference": EXPECTED_SOURCE,
        "supervisor_bytes": len(source_raw),
        "supervisor_sha256": source_sha256,
        "supervisor_mode_octal": "0400",
        "stage0_source_bytes": len(helper_source.encode()),
        "stage0_source_sha256": helper_sha256,
        "full_systemd_argv_sha256": hashlib.sha256(canonical(full_command)).hexdigest(),
        "external_bootstrap_source_sha256": external_bootstrap_source_sha256,
        "external_bootstrap_argv_sha256": external_bootstrap_argv_sha256,
        "preexec_proc_cmdline_bytes": len(cmdline_raw),
        "preexec_proc_cmdline_sha256": hashlib.sha256(cmdline_raw).hexdigest(),
        "exact_environment": list(ENVIRONMENT_ITEMS),
        "no_other_inherited_fds_observed": True,
        "standard_fds_all_dev_null": True,
        "ip_address_family_socket_creation_denied": True,
        "local_af_unix_system_manager_and_journal_ipc_performed": True,
        "ip_network_communication_performed": False,
        "host_inbound_same_uid_process_memory_boundary": {{
            "path": YAMA_PTRACE_SCOPE,
            "value": 1,
            "raw_sha256": hashlib.sha256(yama_raw).hexdigest(),
            "root_owned_mode_octal": "0644",
            "same_uid_non_ancestor_ptrace_denied": True,
            "same_uid_non_ancestor_process_vm_read_write_denied": True,
            "proof_children_parented_by_user_systemd_manager": True,
            "trusted_direct_ancestor_and_root_boundary_remains": True,
            "hostile_unit_rehearsal_performed": False,
        }},
        "pinned_tool_references": tool_references,
        "unit_evidence": {{
            "service_unit": f"{{UNIT}}.service",
            "invocation_id": values["InvocationID"],
            "exec_main_pid": os.getpid(),
            "show_command_sha256": hashlib.sha256(canonical(SHOW_COMMAND)).hexdigest(),
            "show_bytes": len(show.stdout),
            "show_sha256": hashlib.sha256(show.stdout).hexdigest(),
            "journal_command_sha256": hashlib.sha256(canonical(JOURNAL_COMMAND)).hexdigest(),
            "journal_bytes": len(journal.stdout),
            "journal_sha256": hashlib.sha256(journal.stdout).hexdigest(),
            "journal_record_count": record_count,
            "no_historical_foreign_invocation_observed": True,
            "socket_unit_load_state_not_found": True,
            "socket_unit_historical_journal_empty": True,
            "socket_show_command_sha256": hashlib.sha256(
                canonical(SOCKET_SHOW_COMMAND)
            ).hexdigest(),
            "socket_show_sha256": hashlib.sha256(socket_show.stdout).hexdigest(),
            "socket_journal_command_sha256": hashlib.sha256(
                canonical(SOCKET_JOURNAL_COMMAND)
            ).hexdigest(),
            "cgroup_sha256": hashlib.sha256(cgroup_raw).hexdigest(),
        }},
        "memfd_seals": ["F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"],
        "no_fork_exec_preserved_exec_main_pid": True,
        "authorization": False,
    }}
    contract_raw = canonical(contract)
    contract_memfd = os.memfd_create(
        "kpb-w1-supervisor-contract",
        os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
    )
    seal(contract_memfd, contract_raw, 0o400)
    os.dup2(source_memfd, SOURCE_FD, inheritable=True)
    os.dup2(contract_memfd, CONTRACT_FD, inheritable=True)
    os.set_inheritable(SOURCE_FD, True)
    os.set_inheritable(CONTRACT_FD, True)
    for descriptor, raw in ((SOURCE_FD, source_raw), (CONTRACT_FD, contract_raw)):
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != REQUIRED_SEALS:
            refuse()
        observed, digest = read_all(descriptor)
        if observed != raw or digest != hashlib.sha256(raw).hexdigest():
            refuse()
    os.execve(
        PYTHON,
        [PYTHON, "-I", f"/proc/self/fd/{{SOURCE_FD}}"],
        ENVIRONMENT,
    )
finally:
    for descriptor in (source_descriptor, source_memfd, contract_memfd):
        if descriptor >= 0 and descriptor not in (SOURCE_FD, CONTRACT_FD):
            try:
                os.close(descriptor)
            except OSError:
                pass
'''


def _stage0_command(
    supervisor_reference: dict,
    external_bootstrap_source_sha256: str,
    external_bootstrap_argv_sha256: str,
) -> list[str]:
    helper = _render_stage0_source(
        supervisor_reference,
        external_bootstrap_source_sha256,
        external_bootstrap_argv_sha256,
    )
    helper_sha256 = sha256_bytes(helper.encode())
    return _stage0_systemd_prefix() + [
        str(ENV),
        "-i",
        *FIXED_ENVIRONMENT,
        str(PYTHON),
        "-I",
        "-c",
        helper,
        helper_sha256,
        external_bootstrap_source_sha256,
        external_bootstrap_argv_sha256,
    ]

ASSIGNMENT_LAUNCH_KEYS = {
    "schema", "classification", "fixed_no_argument_entrypoint", "build_bundle",
    "binary", "strict_network_preflight", "assignment_runtime",
    "assignment_receipt", "assignment_receipt_validation",
    "assignment_public_inputs_decimal", "assignment_public_inputs_derivation",
    "assignment_peak_rss_kib", "assignment_current_swap_kib", "supervisor_source",
    "identity_bound_exec_helper", "manager_environment",
    "full_secret_zeroization", "error_path_source_zeroization_complete",
    "abort_oom_zeroization", "assignment_serialized", "proving_key_opened",
    "aggregate_proof_generated", "network_communication", "setup", "funds",
    "privacy_acceptance", "financial_acceptance", "production_authority",
    "authorization", "actions", "receipt_identity_sha256",
}
ASSIGNMENT_ACTIONS = {
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


class Refused(RuntimeError):
    """One fail-closed public error category."""


def need(value: bool, category: str) -> None:
    if not value:
        raise Refused(category)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_json(raw: bytes) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict:
        result: dict[str, object] = {}
        for key, value in items:
            need(key not in result, "json-duplicate-key")
            result[key] = value
        return result
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise Refused("json-parse") from None
    return value


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev, left.st_ino, left.st_mode, left.st_nlink, left.st_uid,
        left.st_size, left.st_mtime_ns, left.st_ctime_ns,
    ) == (
        right.st_dev, right.st_ino, right.st_mode, right.st_nlink, right.st_uid,
        right.st_size, right.st_mtime_ns, right.st_ctime_ns,
    )


def _yama_ptrace_scope_reference() -> dict:
    before_path = os.lstat(YAMA_PTRACE_SCOPE)
    need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == 0
        and before_path.st_nlink == 1
        and stat.S_IMODE(before_path.st_mode) == 0o644,
        "yama-ptrace-scope-stat",
    )
    descriptor = os.open(
        YAMA_PTRACE_SCOPE,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        raw = os.read(descriptor, 16)
        extra = os.read(descriptor, 1)
        after = os.fstat(descriptor)
        after_path = os.lstat(YAMA_PTRACE_SCOPE)
    finally:
        os.close(descriptor)
    need(
        _same_stat(before_path, before)
        and _same_stat(before, after)
        and _same_stat(after, after_path)
        and raw == b"1\n"
        and extra == b"",
        "yama-ptrace-scope-value",
    )
    return {
        "path": str(YAMA_PTRACE_SCOPE),
        "value": 1,
        "raw_sha256": sha256_bytes(raw),
        "root_owned_mode_octal": "0644",
        "same_uid_non_ancestor_ptrace_denied": True,
        "same_uid_non_ancestor_process_vm_read_write_denied": True,
        "proof_children_parented_by_user_systemd_manager": True,
        "trusted_direct_ancestor_and_root_boundary_remains": True,
        "hostile_unit_rehearsal_performed": False,
    }


def _stable_file(
    path: Path,
    mode: int,
    *,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
    retain: bool = True,
) -> tuple[bytes, dict]:
    before_path = os.lstat(path)
    need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == os.getuid()
        and before_path.st_nlink == 1
        and stat.S_IMODE(before_path.st_mode) == mode,
        "file-stat",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(_same_stat(before, before_path), "file-open-race")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
            if retain:
                chunks.append(block)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        need(_same_stat(before, after) and _same_stat(after, after_path) and total == after.st_size, "file-read-race")
    finally:
        os.close(descriptor)
    actual = digest.hexdigest()
    need(expected_sha256 is None or actual == expected_sha256, "file-hash")
    need(expected_bytes is None or total == expected_bytes, "file-bytes")
    return b"".join(chunks), {
        "path": str(path), "bytes": total, "sha256": actual,
        "mode_octal": f"{mode:04o}", "device": after.st_dev, "inode": after.st_ino,
        "link_count": after.st_nlink, "owner_uid": after.st_uid,
        "mtime_ns": after.st_mtime_ns, "ctime_ns": after.st_ctime_ns,
    }


def _stable_root_tool(
    path: Path,
    expected_bytes: int,
    expected_sha256: str,
    expected_links: int,
) -> dict:
    need(path == path.resolve(strict=True), "tool-path-canonical")
    before_path = os.lstat(path)
    need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == 0
        and before_path.st_nlink == expected_links
        and stat.S_IMODE(before_path.st_mode) == 0o755
        and before_path.st_size == expected_bytes,
        "tool-stat",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(_same_stat(before, before_path), "tool-open-race")
        digest = hashlib.sha256()
        offset = 0
        while True:
            block = os.pread(descriptor, 1024 * 1024, offset)
            if not block:
                break
            digest.update(block)
            offset += len(block)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        need(
            _same_stat(before, after)
            and _same_stat(after, after_path)
            and offset == expected_bytes
            and digest.hexdigest() == expected_sha256,
            "tool-read-race-or-hash",
        )
    finally:
        os.close(descriptor)
    return {
        "path": str(path),
        "device": after.st_dev,
        "inode": after.st_ino,
        "bytes": expected_bytes,
        "sha256": expected_sha256,
        "mode_octal": "0755",
        "link_count": expected_links,
        "owner_uid": 0,
    }


def _fixed_tool_references() -> dict:
    return {
        name: _stable_root_tool(path, size, digest, links)
        for name, (path, size, digest, links) in TOOL_IDENTITIES.items()
    }


def _sealed_stage0_fd(fd: int, logical_name: str, maximum_bytes: int) -> tuple[bytes, dict]:
    need(fd in (STAGE0_SUPERVISOR_FD, STAGE0_CONTRACT_FD), "stage0-fd-number")
    before = os.fstat(fd)
    required_seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 0
        and before.st_uid == os.getuid()
        and stat.S_IMODE(before.st_mode) == 0o400
        and 0 < before.st_size <= maximum_bytes
        and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == required_seals,
        "stage0-sealed-fd-stat",
    )
    digest = hashlib.sha256()
    blocks: list[bytes] = []
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            break
        blocks.append(block)
        digest.update(block)
        offset += len(block)
    after = os.fstat(fd)
    need(
        _same_stat(before, after)
        and offset == before.st_size
        and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == required_seals,
        "stage0-sealed-fd-read-race",
    )
    for operation in (
        lambda: os.pwrite(fd, b"\x00", 0),
        lambda: os.ftruncate(fd, before.st_size + 1),
        lambda: os.ftruncate(fd, before.st_size - 1),
    ):
        try:
            operation()
        except OSError as error:
            need(error.errno == errno.EPERM, "stage0-sealed-fd-mutation-errno")
        else:
            raise Refused("stage0-sealed-fd-mutation-succeeded")
    fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    raw = b"".join(blocks)
    return raw, {
        "path": f"/proc/self/fd/{fd}",
        "logical_name": logical_name,
        "device": after.st_dev,
        "inode": after.st_ino,
        "bytes": len(raw),
        "sha256": digest.hexdigest(),
        "mode_octal": "0400",
        "link_count": 0,
        "owner_uid": after.st_uid,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
        "seals": ["F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"],
        "close_on_exec_set_by_supervisor": True,
    }


def _run_stage0_renderer(arguments: list[str]) -> None:
    """Run only from the externally sealed FD3; never import a workspace path."""
    need(
        __file__ == f"/proc/self/fd/{STAGE0_SUPERVISOR_FD}"
        and type(arguments) is list
        and arguments == ["--stage0-render"]
        and dict(os.environ)
        == dict(value.split("=", 1) for value in FIXED_ENVIRONMENT),
        "stage0-render-entry-contract",
    )
    source_raw, source_reference = _sealed_stage0_fd(
        STAGE0_SUPERVISOR_FD,
        "externally-reviewed-supervisor-render-source",
        1024 * 1024,
    )
    bootstrap_contract_raw, bootstrap_contract_reference = _sealed_stage0_fd(
        STAGE0_CONTRACT_FD,
        "external-bootstrap-contract",
        128 * 1024,
    )
    bootstrap_contract = _unique_json(bootstrap_contract_raw)
    need(
        bootstrap_contract_raw == canonical(bootstrap_contract)
        and type(bootstrap_contract) is dict
        and set(bootstrap_contract)
        == {
            "schema", "bootstrap_source_sha256", "bootstrap_argv_sha256",
            "supervisor_source_reference", "supervisor_source_sha256",
            "exact_environment", "sealed_supervisor_fd", "sealed_contract_fd",
            "authorization",
        }
        and bootstrap_contract["schema"] == STAGE0_BOOTSTRAP_CONTRACT_SCHEMA
        and _is_sha256(bootstrap_contract["bootstrap_source_sha256"])
        and _is_sha256(bootstrap_contract["bootstrap_argv_sha256"])
        and bootstrap_contract["exact_environment"] == list(FIXED_ENVIRONMENT)
        and bootstrap_contract["sealed_supervisor_fd"] == STAGE0_SUPERVISOR_FD
        and bootstrap_contract["sealed_contract_fd"] == STAGE0_CONTRACT_FD
        and bootstrap_contract["authorization"] is False,
        "stage0-render-bootstrap-contract",
    )
    workspace_reference = bootstrap_contract["supervisor_source_reference"]
    _validate_stage0_source_reference(workspace_reference)
    bootstrap_source = _render_stage0_bootstrap_source(workspace_reference)
    bootstrap_command = _stage0_bootstrap_command(workspace_reference)
    need(
        source_reference["bytes"] == workspace_reference["bytes"]
        and source_reference["sha256"] == workspace_reference["sha256"]
        and bootstrap_contract["supervisor_source_sha256"]
        == workspace_reference["sha256"]
        and bootstrap_contract["bootstrap_source_sha256"]
        == sha256_bytes(bootstrap_source.encode())
        and bootstrap_contract["bootstrap_argv_sha256"]
        == sha256_bytes(canonical(bootstrap_command)),
        "stage0-render-bootstrap-binding",
    )
    # Pin all render/manager tools before the first systemd-manager action.
    _fixed_tool_references()
    _yama_ptrace_scope_reference()
    command = _stage0_command(
        workspace_reference,
        bootstrap_contract["bootstrap_source_sha256"],
        bootstrap_contract["bootstrap_argv_sha256"],
    )
    after_raw, after_reference = _sealed_stage0_fd(
        STAGE0_SUPERVISOR_FD,
        "externally-reviewed-supervisor-render-source",
        1024 * 1024,
    )
    after_contract_raw, after_contract_reference = _sealed_stage0_fd(
        STAGE0_CONTRACT_FD,
        "external-bootstrap-contract",
        128 * 1024,
    )
    need(
        after_raw == source_raw
        and after_reference == source_reference
        and after_contract_raw == bootstrap_contract_raw
        and after_contract_reference == bootstrap_contract_reference,
        "stage0-render-source-changed-before-systemd-exec",
    )
    live = []
    for raw_descriptor in os.listdir("/proc/self/fd"):
        descriptor = int(raw_descriptor)
        try:
            os.fstat(descriptor)
        except OSError as error:
            need(error.errno == errno.EBADF, "stage0-render-fd-scan")
        else:
            live.append(descriptor)
    need(
        sorted(live)
        == [0, 1, 2, STAGE0_SUPERVISOR_FD, STAGE0_CONTRACT_FD]
        and bootstrap_contract_reference["sha256"]
        == sha256_bytes(bootstrap_contract_raw),
        "stage0-render-inherited-fds",
    )
    os.execve(SYSTEMD_RUN, command, _manager_tool_environment())


def _validate_stage0_contract(value: object, source_reference: dict) -> None:
    need(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "stage0_unit",
            "uid",
            "supervisor_fd",
            "contract_fd",
            "supervisor_source_reference",
            "supervisor_bytes",
            "supervisor_sha256",
            "supervisor_mode_octal",
            "stage0_source_bytes",
            "stage0_source_sha256",
            "full_systemd_argv_sha256",
            "external_bootstrap_source_sha256",
            "external_bootstrap_argv_sha256",
            "preexec_proc_cmdline_bytes",
            "preexec_proc_cmdline_sha256",
            "exact_environment",
            "no_other_inherited_fds_observed",
            "standard_fds_all_dev_null",
            "ip_address_family_socket_creation_denied",
            "local_af_unix_system_manager_and_journal_ipc_performed",
            "ip_network_communication_performed",
            "host_inbound_same_uid_process_memory_boundary",
            "pinned_tool_references",
            "unit_evidence",
            "memfd_seals",
            "no_fork_exec_preserved_exec_main_pid",
            "authorization",
        }
        and value["schema"] == STAGE0_CONTRACT_SCHEMA
        and value["stage0_unit"] == STAGE0_UNIT
        and value["uid"] == os.getuid()
        and value["supervisor_fd"] == STAGE0_SUPERVISOR_FD
        and value["contract_fd"] == STAGE0_CONTRACT_FD
        and value["supervisor_bytes"] == source_reference["bytes"]
        and value["supervisor_sha256"] == source_reference["sha256"]
        and value["supervisor_mode_octal"] == "0400"
        and value["exact_environment"] == list(FIXED_ENVIRONMENT)
        and value["no_other_inherited_fds_observed"] is True
        and value["standard_fds_all_dev_null"] is True
        and value["ip_address_family_socket_creation_denied"] is True
        and value["local_af_unix_system_manager_and_journal_ipc_performed"] is True
        and value["ip_network_communication_performed"] is False
        and value["host_inbound_same_uid_process_memory_boundary"]
        == _yama_ptrace_scope_reference()
        and value["memfd_seals"]
        == ["F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"]
        and value["no_fork_exec_preserved_exec_main_pid"] is True
        and value["authorization"] is False,
        "stage0-contract-shape",
    )
    workspace_reference = value["supervisor_source_reference"]
    _validate_stage0_source_reference(workspace_reference)
    need(
        workspace_reference["bytes"] == source_reference["bytes"]
        and workspace_reference["sha256"] == source_reference["sha256"],
        "stage0-contract-source-binding",
    )
    bootstrap_source = _render_stage0_bootstrap_source(workspace_reference)
    bootstrap_command = _stage0_bootstrap_command(workspace_reference)
    need(
        value["external_bootstrap_source_sha256"]
        == sha256_bytes(bootstrap_source.encode())
        and value["external_bootstrap_argv_sha256"]
        == sha256_bytes(canonical(bootstrap_command)),
        "stage0-contract-external-bootstrap",
    )
    helper = _render_stage0_source(
        workspace_reference,
        value["external_bootstrap_source_sha256"],
        value["external_bootstrap_argv_sha256"],
    )
    helper_sha256 = sha256_bytes(helper.encode())
    command = _stage0_command(
        workspace_reference,
        value["external_bootstrap_source_sha256"],
        value["external_bootstrap_argv_sha256"],
    )
    proc_cmdline = b"\x00".join(
        value.encode()
        for value in (
            str(PYTHON), "-I", "-c", helper, helper_sha256,
            value["external_bootstrap_source_sha256"],
            value["external_bootstrap_argv_sha256"],
        )
    ) + b"\x00"
    need(
        value["stage0_source_bytes"] == len(helper.encode())
        and value["stage0_source_sha256"] == helper_sha256
        and value["full_systemd_argv_sha256"] == sha256_bytes(canonical(command))
        and value["preexec_proc_cmdline_bytes"] == len(proc_cmdline)
        and value["preexec_proc_cmdline_sha256"] == sha256_bytes(proc_cmdline)
        and value["pinned_tool_references"] == _fixed_tool_references(),
        "stage0-contract-helper-command-tools",
    )
    unit = value["unit_evidence"]
    need(
        type(unit) is dict
        and set(unit)
        == {
            "service_unit",
            "invocation_id",
            "exec_main_pid",
            "show_command_sha256",
            "show_bytes",
            "show_sha256",
            "journal_command_sha256",
            "journal_bytes",
            "journal_sha256",
            "journal_record_count",
            "no_historical_foreign_invocation_observed",
            "socket_unit_load_state_not_found",
            "socket_unit_historical_journal_empty",
            "socket_show_command_sha256",
            "socket_show_sha256",
            "socket_journal_command_sha256",
            "cgroup_sha256",
        }
        and unit["service_unit"] == f"{STAGE0_UNIT}.service"
        and unit["show_command_sha256"]
        == sha256_bytes(canonical(_stage0_show_command()))
        and type(unit["show_bytes"]) is int
        and unit["show_bytes"] > 0
        and _is_sha256(unit["show_sha256"])
        and unit["journal_command_sha256"]
        == sha256_bytes(canonical(_stage0_journal_command()))
        and type(unit["journal_bytes"]) is int
        and unit["journal_bytes"] > 0
        and _is_sha256(unit["journal_sha256"])
        and type(unit["journal_record_count"]) is int
        and unit["journal_record_count"] > 0
        and unit["no_historical_foreign_invocation_observed"] is True
        and unit["socket_unit_load_state_not_found"] is True
        and unit["socket_unit_historical_journal_empty"] is True
        and unit["socket_show_command_sha256"]
        == sha256_bytes(canonical(_stage0_socket_show_command()))
        and _is_sha256(unit["socket_show_sha256"])
        and unit["socket_journal_command_sha256"]
        == sha256_bytes(canonical(_stage0_socket_journal_command()))
        and _is_sha256(unit["cgroup_sha256"]),
        "stage0-contract-unit-evidence",
    )


def _stage0_contract_reference() -> tuple[bytes, dict, dict]:
    need(
        __file__ == f"/proc/self/fd/{STAGE0_SUPERVISOR_FD}"
        and sys.argv == [f"/proc/self/fd/{STAGE0_SUPERVISOR_FD}"]
        and dict(os.environ)
        == dict(value.split("=", 1) for value in FIXED_ENVIRONMENT),
        "stage0-entry-contract",
    )
    source_raw, source_reference = _sealed_stage0_fd(
        STAGE0_SUPERVISOR_FD,
        "reviewed-supervisor-source",
        1024 * 1024,
    )
    contract_raw, contract_reference = _sealed_stage0_fd(
        STAGE0_CONTRACT_FD,
        "stage0-launch-contract",
        128 * 1024,
    )
    contract = _unique_json(contract_raw)
    need(contract_raw == canonical(contract), "stage0-contract-noncanonical")
    _validate_stage0_contract(contract, source_reference)
    values, show_raw = _show_unit(STAGE0_UNIT)
    properties = _validate_systemd_properties(
        values,
        final=False,
        standard_input="null",
        standard_output="null",
        standard_error="null",
        expected_denied_syscalls=STAGE0_DENIED_SYSCALLS,
        denied_evidence_key="denied_stage0_syscalls",
    )
    unit = contract["unit_evidence"]
    need(
        values["ActiveState"] == "active"
        and values["SubState"] == "running"
        and properties["exec_main_pid"] == os.getpid()
        and properties["exec_main_pid"] == unit["exec_main_pid"]
        and properties["invocation_id"] == unit["invocation_id"],
        "stage0-current-unit-binding",
    )
    cgroup_raw = Path("/proc/self/cgroup").read_bytes()
    need(
        f"/{STAGE0_UNIT}.service".encode() in cgroup_raw
        and sha256_bytes(cgroup_raw) == unit["cgroup_sha256"],
        "stage0-current-cgroup-binding",
    )
    return source_raw, source_reference, {
        "contract": contract,
        "contract_reference": contract_reference,
        "expected_inline_helper": {
            "source_bytes": contract["stage0_source_bytes"],
            "source_sha256": contract["stage0_source_sha256"],
            "full_systemd_argv_sha256": contract["full_systemd_argv_sha256"],
        },
        "external_inline_bootstrap": {
            "source_sha256": contract["external_bootstrap_source_sha256"],
            "argv_sha256": contract["external_bootstrap_argv_sha256"],
            "imports_workspace_module_by_path": False,
            "workspace_source_copied_to_fully_sealed_memfd": True,
            "sealed_supervisor_render_mode_only": True,
        },
        "current_unit_properties": properties,
        "stage0_ip_address_families_unavailable": ["AF_INET", "AF_INET6"],
        "stage0_local_af_unix_ipc_scope": [
            "user-systemd-manager", "user-journal",
        ],
        "proof_probe_and_verifier_child_units_use_strict_no_socket_filter": True,
        "current_show_bytes": len(show_raw),
        "current_show_sha256": sha256_bytes(show_raw),
        "external_review_of_inline_stage0_and_argv_required": True,
    }


def _recheck_stage0_fds(
    expected_source_raw: bytes,
    expected_source_reference: dict,
    expected_contract: dict,
) -> None:
    source_raw, source_reference = _sealed_stage0_fd(
        STAGE0_SUPERVISOR_FD,
        "reviewed-supervisor-source",
        1024 * 1024,
    )
    contract_raw, contract_reference = _sealed_stage0_fd(
        STAGE0_CONTRACT_FD,
        "stage0-launch-contract",
        128 * 1024,
    )
    need(
        source_raw == expected_source_raw
        and source_reference == expected_source_reference
        and contract_raw == canonical(expected_contract["contract"])
        and contract_reference == expected_contract["contract_reference"],
        "stage0-fd-changed-before-publication",
    )


def _directory(path: Path, mode: int) -> None:
    value = os.lstat(path)
    need(
        stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode)
        and value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == mode,
        "directory-stat",
    )


def _safe_relative(value: str) -> PurePosixPath:
    need(type(value) is str and value != "" and "\\" not in value and "\x00" not in value, "relative-path")
    path = PurePosixPath(value)
    need(not path.is_absolute() and str(path) == value and all(part not in ("", ".", "..") for part in path.parts), "relative-path")
    return path


def _receipt_identity(value: dict, category: str) -> None:
    need(type(value.get("receipt_identity_sha256")) is str, category)
    unsigned = dict(value)
    claimed = unsigned.pop("receipt_identity_sha256")
    need(claimed == sha256_bytes(canonical(unsigned)), category)


FILE_REFERENCE_KEYS = {
    "bytes",
    "ctime_ns",
    "device",
    "inode",
    "link_count",
    "mode_octal",
    "mtime_ns",
    "owner_uid",
    "path",
    "sha256",
}
ASSIGNMENT_HELPER_KEYS = {
    "binary_argv",
    "binary_bytes",
    "binary_device",
    "binary_inode",
    "binary_link_count",
    "binary_mode_octal",
    "binary_owner_uid",
    "binary_path",
    "binary_sha256",
    "exact_environment",
    "exec_primitive",
    "interpreter",
    "memfd_seals",
    "sealed_memfd_rehashed_before_exec",
    "source_bytes",
    "source_sha256",
    "stdout_and_stderr_inherited_null",
}
ASSIGNMENT_VALIDATION_KEYS = {
    "all_required_false_flags_validated",
    "all_required_true_flags_validated",
    "current_preparer_constraint_rows_recorded",
    "current_preparer_constraint_satisfaction_checked",
    "current_preparer_observed_constraints",
    "exact_key_set_sha256",
    "exact_schema",
    "historical_component_expected_constraints",
    "output_proofs_verified",
    "prepared_instances",
    "prepared_variables",
    "prepared_witnesses",
    "rounds_validated",
    "selected_round",
    "signature_relations_satisfied",
    "unexpected_or_fingerprint_fields_absent",
}


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_assignment_file_reference(
    value: object,
    *,
    mode: str,
    expected_path: Path | None = None,
) -> None:
    need(type(value) is dict and set(value) == FILE_REFERENCE_KEYS, "assignment-file-reference")
    need(
        type(value["bytes"]) is int
        and value["bytes"] > 0
        and type(value["device"]) is int
        and value["device"] >= 0
        and type(value["inode"]) is int
        and value["inode"] > 0
        and type(value["link_count"]) is int
        and value["link_count"] == 1
        and value["mode_octal"] == mode
        and type(value["owner_uid"]) is int
        and value["owner_uid"] >= 0
        and type(value["mtime_ns"]) is int
        and type(value["ctime_ns"]) is int
        and type(value["path"]) is str
        and (expected_path is None or value["path"] == str(expected_path))
        and _is_sha256(value["sha256"]),
        "assignment-file-reference",
    )


def _validate_assignment_helper(value: object, binary: dict) -> None:
    need(type(value) is dict and set(value) == ASSIGNMENT_HELPER_KEYS, "assignment-helper-keys")
    expected_receipt = ASSIGNMENT_RUN_ROOT / "ASSIGNMENT-RECEIPT.json"
    need(
        value["interpreter"] == "/usr/bin/python3"
        and type(value["source_bytes"]) is int
        and value["source_bytes"] > 0
        and _is_sha256(value["source_sha256"])
        and value["exec_primitive"] == "sealed-memfd-os.execve-by-file-descriptor"
        and value["memfd_seals"]
        == ["F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"]
        and value["sealed_memfd_rehashed_before_exec"] is True
        and value["binary_path"] == binary["path"]
        and value["binary_device"] == binary["device"]
        and value["binary_inode"] == binary["inode"]
        and value["binary_bytes"] == binary["bytes"]
        and value["binary_sha256"] == binary["sha256"]
        and value["binary_mode_octal"] == "0500"
        and value["binary_link_count"] == 1
        and value["binary_owner_uid"] == binary["owner_uid"]
        and value["binary_argv"] == [binary["path"], str(expected_receipt)]
        and value["exact_environment"] == list(FIXED_ENVIRONMENT)
        and value["stdout_and_stderr_inherited_null"] is True,
        "assignment-helper-values",
    )


def _validate_assignment_execution(value: dict, helper: dict) -> None:
    runtime = value["assignment_runtime"]
    probe = value["strict_network_preflight"]
    need(type(runtime) is dict and type(probe) is dict, "assignment-runtime-shape")
    properties = runtime.get("properties")
    need(
        runtime.get("identity_bound_exec_helper") == helper
        and runtime.get("result") == "success"
        and runtime.get("exec_main_status") == 0
        and runtime.get("unit_stopped_after_capture") is True
        and type(properties) is dict
        and properties.get("denied_network_syscalls")
        == sorted(STRICT_DENIED_NETWORK_SYSCALLS)
        and properties.get("limit_core_bytes") == 0
        and properties.get("memory_swap_max_bytes") == 0
        and properties.get("memory_swap_peak_bytes") == 0
        and properties.get("no_new_privileges") is True
        and properties.get("restart_count") == 0
        and properties.get("standard_input") == "null"
        and properties.get("standard_output") == "null"
        and properties.get("standard_error") == "null"
        and probe.get("identity_bound_exec_helper") is None
        and probe.get("result") == "success"
        and probe.get("exec_main_status") == 0
        and probe.get("unit_stopped_after_capture") is True
        and probe.get("af_inet_af_inet6_af_unix_socket_denied_with_eperm") is True
        and probe.get("exact_fixed_environment_observed") is True
        and probe.get("network_communication_performed") is False,
        "assignment-runtime-values",
    )


def _require_bound_constants() -> None:
    strings = (
        EXPECTED_BUILD_FREEZER_SOURCE_SHA256,
        EXPECTED_BUILD_CORE_SOURCE_SHA256,
        EXPECTED_MANIFEST_SHA256,
        EXPECTED_INNER_RECEIPT_SHA256,
        EXPECTED_DEP_INFO_SHA256,
        EXPECTED_BINARY_SHA256,
        EXPECTED_OUTER_RECEIPT_SHA256,
        EXPECTED_ASSIGNMENT_LAUNCH_RECEIPT_SHA256,
        EXPECTED_VERIFIER_BINARY_SHA256,
        EXPECTED_VERIFIER_DEP_INFO_SHA256,
        EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256,
    )
    need(all(type(value) is str and len(value) == 64 and value == value.lower() for value in strings), "artifact-constants-unbound")
    need(type(EXPECTED_BINARY_BYTES) is int and EXPECTED_BINARY_BYTES > 0, "artifact-constants-unbound")
    need(
        type(EXPECTED_VERIFIER_BINARY_BYTES) is int
        and EXPECTED_VERIFIER_BINARY_BYTES > 0,
        "artifact-constants-unbound",
    )
    need(
        type(EXPECTED_VERIFIER_DEPENDENCY_RELATIVES) is tuple
        and EXPECTED_VERIFIER_DEPENDENCY_RELATIVES
        and all(
            type(relative) is str
            and str(_safe_relative(relative)) == relative
            for relative in EXPECTED_VERIFIER_DEPENDENCY_RELATIVES
        )
        and len(EXPECTED_VERIFIER_DEPENDENCY_RELATIVES)
        == len(set(EXPECTED_VERIFIER_DEPENDENCY_RELATIVES)),
        "artifact-constants-unbound",
    )
    need(
        set(EXPECTED_VERIFIER_DEPENDENCY_RELATIVES)
        <= set(REVIEWED_BUILD_SOURCES),
        "verifier-closure-not-independently-reviewed",
    )


def validate_assignment_launch(value: object) -> None:
    need(
        type(value) is dict and set(value) == ASSIGNMENT_LAUNCH_KEYS,
        "assignment-launch-keys",
    )
    _receipt_identity(value, "assignment-launch-identity")
    actions = value.get("actions")
    binary = value.get("binary")
    assignment_receipt = value.get("assignment_receipt")
    helper = value.get("identity_bound_exec_helper")
    _validate_assignment_file_reference(binary, mode="0500")
    _validate_assignment_file_reference(
        assignment_receipt,
        mode="0400",
        expected_path=ASSIGNMENT_RUN_ROOT / "ASSIGNMENT-RECEIPT.json",
    )
    _validate_assignment_helper(helper, binary)
    _validate_assignment_execution(value, helper)
    validation = value.get("assignment_receipt_validation")
    derivation = value.get("assignment_public_inputs_derivation")
    manager = value.get("manager_environment")
    validation_integer_keys = (
        "current_preparer_observed_constraints",
        "historical_component_expected_constraints",
        "output_proofs_verified",
        "prepared_instances",
        "prepared_variables",
        "prepared_witnesses",
        "rounds_validated",
        "selected_round",
        "signature_relations_satisfied",
    )
    need(
        value.get("schema") == "kpb-frozen-w1-assignment-launch-receipt/v2"
        and value.get("classification") == "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_ASSIGNMENT_PREPARATION_ONLY_NOT_AUTHORITY"
        and value.get("fixed_no_argument_entrypoint") is True
        and type(value.get("assignment_public_inputs_decimal")) is list
        and value["assignment_public_inputs_decimal"] == list(EXPECTED_PUBLIC_INPUTS)
        and type(value.get("assignment_peak_rss_kib")) is int
        and value["assignment_peak_rss_kib"] > 0
        and type(value.get("assignment_current_swap_kib")) is int
        and value["assignment_current_swap_kib"] == 0
        and value.get("assignment_serialized") is False
        and value.get("full_secret_zeroization") is False
        and value.get("error_path_source_zeroization_complete") is False
        and value.get("abort_oom_zeroization") is False
        and value.get("proving_key_opened") is False
        and value.get("aggregate_proof_generated") is False
        and value.get("network_communication") is False
        and value.get("setup") is False
        and value.get("funds") is False
        and value.get("privacy_acceptance") is False
        and value.get("financial_acceptance") is False
        and value.get("production_authority") is False
        and value.get("authorization") is False
        and actions == ASSIGNMENT_ACTIONS
        and type(validation) is dict
        and set(validation) == ASSIGNMENT_VALIDATION_KEYS
        and all(type(validation[key]) is int for key in validation_integer_keys)
        and validation["exact_schema"] == "kpb-frozen-w1-round1-assignment-preparation/v3"
        and validation["exact_key_set_sha256"] == EXPECTED_ASSIGNMENT_RECEIPT_KEYS_SHA256
        and validation["selected_round"] == 1
        and validation["prepared_instances"] == 3
        and validation["prepared_witnesses"] == 12_949_818
        and validation["prepared_variables"] == 12_949_821
        and validation["historical_component_expected_constraints"] == 13_093_029
        and validation["current_preparer_observed_constraints"] == 0
        and validation["current_preparer_constraint_rows_recorded"] is False
        and validation["current_preparer_constraint_satisfaction_checked"] is False
        and validation["rounds_validated"] == 2
        and validation["output_proofs_verified"] == 12
        and validation["signature_relations_satisfied"] == 6
        and validation["all_required_true_flags_validated"] is True
        and validation["all_required_false_flags_validated"] is True
        and validation["unexpected_or_fingerprint_fields_absent"] is True
        and type(derivation) is dict
        and set(derivation) == {"round1_effects_core_sha256", "split", "independently_derived"}
        and derivation["round1_effects_core_sha256"] == EXPECTED_ROUND1_EFFECTS_CORE_SHA256
        and derivation["split"] == "two-16-byte-little-endian-unsigned-integers"
        and type(derivation["independently_derived"]) is list
        and derivation["independently_derived"] == list(EXPECTED_PUBLIC_INPUTS)
        and type(manager) is dict
        and set(manager)
        == {
            "all_manager_entries_removed_or_replaced",
            "all_observed_systemd_injected_entries_removed",
            "entry_count",
            "environment_sha256",
            "fixed_runtime_environment",
        }
        and manager["all_manager_entries_removed_or_replaced"] is True
        and manager["all_observed_systemd_injected_entries_removed"] is True
        and type(manager["entry_count"]) is int
        and manager["entry_count"] > 0
        and _is_sha256(manager["environment_sha256"])
        and manager["fixed_runtime_environment"] == list(FIXED_ENVIRONMENT),
        "assignment-launch-truth",
    )


def _assignment_launch_reference() -> dict:
    raw, reference = _stable_file(
        ASSIGNMENT_LAUNCH_RECEIPT,
        0o400,
        expected_sha256=EXPECTED_ASSIGNMENT_LAUNCH_RECEIPT_SHA256,
    )
    value = _unique_json(raw)
    validate_assignment_launch(value)
    need(raw == canonical(value), "assignment-launch-noncanonical")
    return reference


def _validate_manifest(raw: bytes) -> tuple[dict, list[str]]:
    value = _unique_json(raw)
    need(type(value) is dict, "manifest-object")
    unsigned = dict(value)
    claimed = unsigned.pop("manifest_identity_sha256", None)
    members = value.get("members")
    need(
        value.get("schema") == "kpb-current-w1-source-snapshot-manifest/v1"
        and value.get("classification") == "CURRENT_SOURCE_FINAL_CANDIDATE_NOT_AUTHORITY"
        and value.get("authorization") is False
        and tuple(value.get("package_roots", ())) == EXPECTED_PACKAGE_ROOTS
        and type(members) is list and value.get("member_count") == len(members)
        and value.get("members_identity_sha256") == sha256_bytes(canonical(members))
        and claimed == sha256_bytes(canonical(unsigned)),
        "manifest-truth",
    )
    paths: list[str] = []
    for member in members:
        need(type(member) is dict and set(member) == {"relative_path", "bytes", "sha256"}, "manifest-member")
        relative = str(_safe_relative(member["relative_path"]))
        need(type(member["bytes"]) is int and member["bytes"] >= 0 and type(member["sha256"]) is str and len(member["sha256"]) == 64, "manifest-member")
        paths.append(relative)
    need(paths == sorted(paths) and len(paths) == len(set(paths)), "manifest-order")
    for required in (*REQUIRED_PROOF_DEPENDENCIES, *REQUIRED_VERIFIER_DEPENDENCIES):
        need(required in paths, "manifest-required-proof-source")
    verifier_contract = next(
        (member for member in members if member["relative_path"] == VERIFIER_CONTRACT_SOURCE),
        None,
    )
    need(
        type(verifier_contract) is dict
        and verifier_contract["sha256"] == EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256,
        "manifest-verifier-contract-source",
    )
    return value, paths


def _validate_snapshot(manifest: dict, paths: list[str]) -> dict:
    source_root = BUILD_BUNDLE / "sources"
    _directory(source_root, 0o500)
    refs = []
    for member, relative in zip(manifest["members"], paths, strict=True):
        path = source_root.joinpath(*PurePosixPath(relative).parts)
        raw, reference = _stable_file(
            path, 0o400, expected_sha256=member["sha256"], expected_bytes=member["bytes"], retain=False
        )
        if relative == VERIFIER_CONTRACT_SOURCE:
            # The source hash is an independent binding constant.  These exact
            # contract literals additionally make the fixed VK and real hostile
            # cryptographic controls visible to this launch validator.
            raw, _ = _stable_file(
                path,
                0o400,
                expected_sha256=EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256,
            )
            source = raw.decode("utf-8")
            for required in (
                "const VK_BYTES: usize = 328;",
                f'const VK_SHA256_HEX: &str = "{FIXED_ARTIFACTS["independent_vk"][2]}";',
                f'const VK_PATH: &str = "{VK_PATH}";',
                "let owned_vk = read_authenticated_exact::<VK_BYTES>(",
                "verify_proof_with_hostile_controls(&vk, &proof, &public_inputs)?;",
            ):
                need(required in source, "verifier-fixed-vk-source-contract")
        refs.append({"relative_path": relative, "bytes": reference["bytes"], "sha256": reference["sha256"]})
    actual = []
    for current_raw, directories, files in os.walk(source_root, followlinks=False):
        current = Path(current_raw)
        for name in directories:
            child = current / name
            need(not child.is_symlink(), "snapshot-symlink")
        for name in files:
            actual.append((current / name).relative_to(source_root).as_posix())
    need(sorted(actual) == paths and refs == manifest["members"], "snapshot-member-set")
    return {"member_count": len(refs), "members_identity_sha256": sha256_bytes(canonical(refs))}


def _parse_dep_info(raw: bytes) -> tuple[str, list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("dep-info-utf8") from None
    lines = [line for line in text.splitlines() if line]
    need(len(lines) == 1 and ": " in lines[0], "dep-info-shape")
    target, raw_dependencies = lines[0].split(": ", 1)
    dependencies = raw_dependencies.split(" ")
    need(target != "" and dependencies and all(dependencies) and len(dependencies) == len(set(dependencies)), "dep-info-shape")
    return target, dependencies


def _validate_dependency_contract(
    dep_info: object,
    dependencies: object,
    manifest_paths: list[str],
    dep_raw: bytes,
) -> int:
    need(
        type(dep_info) is dict
        and type(dependencies) is list
        and dep_info.get("dependency_count") == len(dependencies)
        and all(type(relative) is str for relative in dependencies),
        "outer-dependency-set",
    )
    canonical_dependencies = [str(_safe_relative(relative)) for relative in dependencies]
    dependency_set = set(canonical_dependencies)
    need(
        canonical_dependencies == dependencies
        and len(dependencies) == len(dependency_set)
        and dependencies
        == [relative for relative in manifest_paths if relative in dependency_set]
        and all(required in dependency_set for required in REQUIRED_PROOF_DEPENDENCIES)
        and dep_info.get("target_relative") == "artifacts/candidate-binary",
        "outer-dependency-membership-order",
    )
    raw_target, raw_paths = _parse_dep_info(dep_raw)
    need(
        raw_target == "artifacts/candidate-binary"
        and raw_paths == [f"sources/{relative}" for relative in dependencies],
        "dep-info-binding",
    )
    return len(dependencies)


def _validate_verifier_dependency_contract(
    dep_info: object,
    dependencies: object,
    manifest_paths: list[str],
    dep_raw: bytes,
    expected_sha256: str,
    expected_dependencies: object,
) -> int:
    need(
        _is_sha256(expected_sha256)
        and sha256_bytes(dep_raw) == expected_sha256
        and type(expected_dependencies) is tuple
        and expected_dependencies
        and all(type(relative) is str for relative in expected_dependencies)
        and
        type(dep_info) is dict
        and type(dependencies) is list
        and dep_info.get("dependency_count") == len(dependencies)
        and all(type(relative) is str for relative in dependencies),
        "outer-verifier-dependency-set",
    )
    target, raw_paths = _parse_dep_info(dep_raw)
    prefix = "sources/"
    need(
        target == "artifacts/verify_frozen_w1_round1_receipt"
        and raw_paths
        and len(raw_paths) == len(set(raw_paths))
        and all(path.startswith(prefix) for path in raw_paths),
        "verifier-dep-info-shape",
    )
    raw_dependencies = [path[len(prefix):] for path in raw_paths]
    dependency_set = set(dependencies)
    need(
        dependencies == raw_dependencies
        and dependencies == list(expected_dependencies)
        and dep_info.get("dependency_relatives") == dependencies
        and all(str(_safe_relative(relative)) == relative for relative in dependencies)
        and
        dependencies
        == [relative for relative in manifest_paths if relative in dependency_set]
        and all(required in dependency_set for required in REQUIRED_VERIFIER_DEPENDENCIES)
        and dep_info.get("target_relative")
        == "artifacts/verify_frozen_w1_round1_receipt",
        "verifier-dependency-membership-order",
    )
    return len(dependencies)


def _validate_build_command(build: dict, outer: dict) -> None:
    command = build.get("command")
    need(
        type(command) is list
        and all(type(item) is str for item in command)
        and build.get("command_sha256") == sha256_bytes(canonical(command)),
        "outer-build-command",
    )
    cargo = "/home/luke/.cargo/bin/cargo"
    need(command.count(cargo) == 1, "outer-build-command-cargo")
    cargo_index = command.index(cargo)
    target_entries = [
        item for item in command if item.startswith("CARGO_TARGET_DIR=")
    ]
    need(
        len(target_entries) == 1
        and target_entries[0] != "CARGO_TARGET_DIR=",
        "outer-build-target-directory",
    )
    relation = PurePosixPath(
        "poc/local-private-payment/private-batch-relation"
    )
    cwd = Path(build.get("cwd", ""))
    snapshot_root = cwd
    for _ in relation.parts:
        snapshot_root = snapshot_root.parent
    staging_root = snapshot_root.parent
    target_root = Path(target_entries[0].split("=", 1)[1])
    staging_prefix = f".{BUILD_BUNDLE.name}.staging-"
    target_prefix = f".{BUILD_BUNDLE.name}.target-"
    need(
        cwd.is_absolute()
        and cwd == snapshot_root.joinpath(*relation.parts)
        and snapshot_root.name == "sources"
        and staging_root.parent == PRIVATE_BUILD_PARENT
        and staging_root.name.startswith(staging_prefix)
        and _canonical_uuid(staging_root.name.removeprefix(staging_prefix))
        and target_root.is_absolute()
        and target_root.parent == PRIVATE_BUILD_PARENT
        and target_root.name.startswith(target_prefix)
        and _canonical_uuid(target_root.name.removeprefix(target_prefix))
        and target_root != staging_root
        and outer.get("private_output_parent") == str(PRIVATE_BUILD_PARENT)
        and build.get("cargo_original_binary", {}).get("path")
        == str(target_root / "release" / "examples" / BUILD_EXAMPLES[0])
        and build.get("cargo_original_verifier_binary", {}).get("path")
        == str(target_root / "release" / "examples" / BUILD_EXAMPLES[1]),
        "outer-build-private-source-target-binding",
    )
    expected = [
        str(SYSTEMD_RUN),
        "--user",
        "--quiet",
        "--no-block",
        "--remain-after-exit",
        "--unit=kpb-w1-proof-freeze-build-20261029-02",
        "--service-type=exec",
        "--expand-environment=no",
        "--property",
        "SystemCallFilter=~" + " ".join(BUILD_DENIED_NETWORK_SYSCALLS),
        "--property",
        "SystemCallErrorNumber=EPERM",
        "--property",
        "RestrictAddressFamilies=AF_UNIX",
        "--property",
        "NoNewPrivileges=yes",
        "--property",
        "LimitCORE=0",
        "--property",
        "MemoryMax=20G",
        "--property",
        "MemorySwapMax=0",
        "--property",
        "UMask=0077",
        "--property",
        "UnsetEnvironment=" + " ".join(BUILD_BOOTSTRAP_UNSET_ENVIRONMENT),
        "--property",
        "StandardInput=null",
        "--property",
        "StandardOutput=null",
        "--property",
        "StandardError=null",
        f"--working-directory={build.get('cwd')}",
        "/usr/bin/env",
        "-i",
    ]
    build_environment = (
        "HOME=/home/luke",
        "PATH=/home/luke/.cargo/bin:/usr/bin:/bin",
        "CARGO_HOME=/home/luke/.cargo",
        "RUSTUP_HOME=/home/luke/.rustup",
        "CARGO_NET_OFFLINE=true",
        target_entries[0],
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
    expected.extend(build_environment)
    expected.extend([
        cargo,
        "build",
        "--release",
        "--locked",
        "--offline",
        "--no-default-features",
        "--features",
        "offline-w1-prover",
        "--example",
        BUILD_EXAMPLES[0],
        "--example",
        BUILD_EXAMPLES[1],
    ])
    need(
        command == expected
        and cargo_index == len(command) - 12
        and command.count("/usr/bin/env") == 1
        and command[command.index("/usr/bin/env") + 1] == "-i"
        and "--setenv" not in command
        and command.count("--example") == 2
        and all(item not in command[cargo_index:] for item in ("run", "test", "rustc"))
        and type(build.get("cwd")) is str,
        "outer-build-command-exact",
    )
    need(
        build.get("environment_launcher") == "/usr/bin/env"
        and build.get("environment_cleared_with_i") is True
        and build.get("exact_cargo_environment") == list(build_environment)
        and build.get("ambient_manager_environment_inherited_by_cargo") is False
        and build.get("bootstrap_unset_environment")
        == list(BUILD_BOOTSTRAP_UNSET_ENVIRONMENT),
        "outer-build-exact-environment",
    )


def _validate_reviewed_build_sources(
    outer: dict,
    manifest: dict,
    manifest_ref: dict,
) -> None:
    gate = outer.get("review_gate")
    snapshot = outer.get("source_snapshot")
    need(
        type(gate) is dict
        and set(gate)
        == {
            "independent_review_explicitly_bound_before_execution",
            "reviewed_sources",
            "review_manifest_snapshot_binding",
            "review_manifest_snapshot_rechecked_after_build",
            "review_manifest_snapshot_rechecked_after_publication",
            "reviewed_sources_equal_after_atomic_freeze",
        }
        and gate.get("independent_review_explicitly_bound_before_execution") is True
        and gate.get("review_manifest_snapshot_rechecked_after_build") is True
        and gate.get("review_manifest_snapshot_rechecked_after_publication") is True
        and gate.get("reviewed_sources_equal_after_atomic_freeze") is True
        and type(snapshot) is dict
        and snapshot.get("package_roots") == list(EXPECTED_PACKAGE_ROOTS)
        and snapshot.get("manifest", {}).get("sha256") == manifest_ref["sha256"]
        and snapshot.get("member_count") == manifest["member_count"]
        and snapshot.get("members_identity_sha256")
        == manifest["members_identity_sha256"],
        "outer-reviewed-source-gate",
    )
    reviewed = gate.get("reviewed_sources")
    members = {
        member["relative_path"]: {
            "bytes": member["bytes"],
            "sha256": member["sha256"],
        }
        for member in manifest["members"]
    }
    need(
        type(reviewed) is dict
        and set(reviewed) == set(REVIEWED_BUILD_SOURCES)
        and all(reviewed[relative] == members.get(relative) for relative in reviewed),
        "outer-reviewed-source-binding",
    )
    binding = gate.get("review_manifest_snapshot_binding")
    need(
        type(binding) is dict
        and set(binding)
        == {
            "schema",
            "reviewed_member_count",
            "reviewed_manifest_snapshot_exact_match",
            "entries",
            "authorization",
            "binding_identity_sha256",
        }
        and binding["schema"] == BUILD_REVIEW_SNAPSHOT_BINDING_SCHEMA
        and binding["reviewed_member_count"] == len(REVIEWED_BUILD_SOURCES)
        and binding["reviewed_manifest_snapshot_exact_match"] is True
        and binding["authorization"] is False
        and type(binding["entries"]) is list
        and len(binding["entries"]) == len(REVIEWED_BUILD_SOURCES),
        "outer-review-snapshot-binding",
    )
    for relative, entry in zip(
        REVIEWED_BUILD_SOURCES,
        binding["entries"],
        strict=True,
    ):
        need(
            type(entry) is dict
            and set(entry)
            == {
                "relative_path",
                "bytes",
                "sha256",
                "snapshot_device",
                "snapshot_inode",
            }
            and entry["relative_path"] == relative
            and {"bytes": entry["bytes"], "sha256": entry["sha256"]}
            == reviewed[relative]
            and type(entry["snapshot_device"]) is int
            and entry["snapshot_device"] > 0
            and type(entry["snapshot_inode"]) is int
            and entry["snapshot_inode"] > 0,
            "outer-review-snapshot-entry",
        )
    unsigned_binding = dict(binding)
    claimed_binding = unsigned_binding.pop("binding_identity_sha256")
    need(
        claimed_binding == sha256_bytes(canonical(unsigned_binding)),
        "outer-review-snapshot-binding-identity",
    )


def _matches_file_claim(
    claim: object,
    reference: dict,
    *,
    name: str | None = None,
    path: Path | None = None,
) -> bool:
    return (
        type(claim) is dict
        and claim.get("bytes") == reference["bytes"]
        and claim.get("sha256") == reference["sha256"]
        and claim.get("mode_octal") == reference["mode_octal"]
        and claim.get("link_count") == 1
        and (name is None or claim.get("name") == name)
        and (path is None or claim.get("path") == str(path))
    )


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _validate_build_pristine_observation(value: object, unit: str) -> None:
    show_command = [
        str(SYSTEMCTL),
        "--user",
        "show",
        f"{unit}.service",
        "--property=LoadState",
        "--value",
        "--no-pager",
    ]
    journal_command = [
        str(JOURNALCTL),
        "--user",
        "--unit",
        f"{unit}.service",
        "--no-pager",
        "--quiet",
        "--output=export",
    ]
    need(
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
        and value["systemctl_command_sha256"] == sha256_bytes(canonical(show_command))
        and value["systemctl_stdout_bytes"] == len(b"not-found\n")
        and value["systemctl_stdout_sha256"] == sha256_bytes(b"not-found\n")
        and value["historical_journal_command_sha256"]
        == sha256_bytes(canonical(journal_command))
        and value["historical_journal_bytes"] == 0
        and value["historical_journal_sha256"] == sha256_bytes(b"")
        and value["historical_journal_empty"] is True,
        "build-unit-pristine-observation",
    )


def _validate_build_unit_record_reference(value: object, name: str) -> None:
    need(
        type(value) is dict
        and set(value) == {"name", "bytes", "sha256", "mode_octal", "link_count"}
        and value["name"] == name
        and type(value["bytes"]) is int
        and value["bytes"] > 0
        and _is_sha256(value["sha256"])
        and value["mode_octal"] == "0400"
        and value["link_count"] == 1,
        "build-unit-record-reference",
    )


def _load_build_unit_record(
    unit_root: Path,
    claim: dict,
    schema: str,
) -> tuple[dict, dict]:
    path = unit_root / claim["name"]
    raw, reference = _stable_file(
        path,
        0o400,
        expected_sha256=claim["sha256"],
        expected_bytes=claim["bytes"],
    )
    value = _unique_json(raw)
    need(
        type(value) is dict
        and raw == canonical(value)
        and value.get("schema") == schema,
        "build-unit-record-canonical-schema",
    )
    unsigned = dict(value)
    claimed = unsigned.pop("record_identity_sha256", None)
    need(
        claimed == sha256_bytes(canonical(unsigned)),
        "build-unit-record-identity",
    )
    return value, reference


def _validate_build_unit_identity(
    value: object,
    ledger_member: object,
    runtime: object,
    unit: str,
    role: str,
) -> None:
    unit_root = BUILD_UNIT_LEDGER / f"{unit}.identity"
    need(
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
        and value["unit_root"] == str(unit_root)
        and value["unit_name"] == unit
        and value["service_unit"] == f"{unit}.service"
        and value["role"] == role
        and _canonical_uuid(value["reservation_id"])
        and value["reservation_and_consumption_durable_before_start"] is True
        and value["prestart_load_state_not_found"] is True
        and value["prestart_historical_journal_empty"] is True
        and value["start_dispatched_after_consumption"] is True
        and type(ledger_member) is dict
        and set(ledger_member) == {"unit_root", "reservation", "consumption"}
        and ledger_member["unit_root"] == str(unit_root)
        and value["reservation"] == ledger_member["reservation"]
        and value["consumption"] == ledger_member["consumption"]
        and type(runtime) is dict
        and runtime.get("unit") == f"{unit}.service"
        and runtime.get("unit_identity") == value
        and runtime.get("unit_identity_was_fresh_and_consumed_before_start") is True
        and _is_sha256(runtime.get("command_sha256")),
        "build-unit-identity-contract",
    )
    for name in ("reservation", "consumption"):
        _validate_build_unit_record_reference(value[name], f"{name.upper()}.json")
    first = value["first_pristine_observation"]
    second = value["second_pristine_observation"]
    _validate_build_pristine_observation(first, unit)
    _validate_build_pristine_observation(second, unit)
    need(first == second, "build-unit-pristine-observations-differ")
    _directory(unit_root, 0o500)
    need(
        set(os.listdir(unit_root)) == {"RESERVATION.json", "CONSUMPTION.json"},
        "build-unit-record-files",
    )
    reservation, reservation_ref = _load_build_unit_record(
        unit_root,
        value["reservation"],
        BUILD_UNIT_RESERVATION_SCHEMA,
    )
    consumption, consumption_ref = _load_build_unit_record(
        unit_root,
        value["consumption"],
        BUILD_UNIT_CONSUMPTION_SCHEMA,
    )
    need(
        _matches_file_claim(value["reservation"], reservation_ref)
        and _matches_file_claim(value["consumption"], consumption_ref),
        "build-unit-record-file-binding",
    )
    need(
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
        and reservation["unit_name"] == unit
        and reservation["service_unit"] == f"{unit}.service"
        and reservation["role"] == role
        and reservation["reservation_id"] == value["reservation_id"]
        and reservation["command_sha256"] == runtime["command_sha256"]
        and reservation["private_output_parent"] == str(PRIVATE_BUILD_PARENT)
        and reservation["identity_reserved_create_new"] is True
        and reservation["systemd_start_dispatched"] is False
        and reservation["authorization"] is False,
        "build-unit-reservation-record",
    )
    need(
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
        and consumption["unit_name"] == unit
        and consumption["service_unit"] == f"{unit}.service"
        and consumption["role"] == role
        and consumption["reservation_id"] == value["reservation_id"]
        and consumption["reservation_sha256"] == reservation_ref["sha256"]
        and consumption["command_sha256"] == runtime["command_sha256"]
        and consumption["identity_consumed_before_start"] is True
        and consumption["pristine_observation_required_after_consumption"] is True
        and consumption["systemd_start_dispatched"] is False
        and consumption["authorization"] is False,
        "build-unit-consumption-record",
    )


def _validate_build_unit_ledger(outer: dict, build: dict) -> None:
    ledger = build.get("unit_identity_ledger")
    need(
        type(ledger) is dict
        and set(ledger)
        == {
            "root",
            "mode_octal",
            "unit_count",
            "units",
            "reservations_and_consumptions_retained",
            "authorization",
            "ledger_identity_sha256",
        }
        and ledger["root"] == str(BUILD_UNIT_LEDGER)
        and ledger["mode_octal"] == "0500"
        and ledger["unit_count"] == 2
        and type(ledger["units"]) is dict
        and set(ledger["units"])
        == {BUILD_FREEZE_PROBE_UNIT, BUILD_FREEZE_BUILD_UNIT}
        and ledger["reservations_and_consumptions_retained"] is True
        and ledger["authorization"] is False,
        "build-unit-ledger-contract",
    )
    unsigned = dict(ledger)
    claimed = unsigned.pop("ledger_identity_sha256")
    need(claimed == sha256_bytes(canonical(unsigned)), "build-unit-ledger-identity")
    _directory(BUILD_UNIT_LEDGER, 0o500)
    need(
        set(os.listdir(BUILD_UNIT_LEDGER))
        == {
            f"{BUILD_FREEZE_PROBE_UNIT}.identity",
            f"{BUILD_FREEZE_BUILD_UNIT}.identity",
        },
        "build-unit-ledger-members",
    )
    network = outer.get("network_boundary")
    need(type(network) is dict and type(network.get("probe")) is dict,
         "build-network-probe-evidence")
    _validate_build_unit_identity(
        network["probe"].get("unit_identity"),
        ledger["units"][BUILD_FREEZE_PROBE_UNIT],
        network["probe"],
        BUILD_FREEZE_PROBE_UNIT,
        "network_probe",
    )
    _validate_build_unit_identity(
        build.get("unit", {}).get("unit_identity"),
        ledger["units"][BUILD_FREEZE_BUILD_UNIT],
        build.get("unit"),
        BUILD_FREEZE_BUILD_UNIT,
        "cargo_build",
    )
    need(
        build["unit"]["command_sha256"] == build["command_sha256"],
        "build-unit-command-binding",
    )


def _validate_build_runtime_common(runtime: object) -> None:
    need(type(runtime) is dict, "build-runtime-shape")
    properties = runtime.get("properties")
    need(
        type(properties) is dict
        and set(properties)
        == {
            "restrict_address_families",
            "denied_network_syscalls",
            "system_call_error_number",
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
        }
        and properties["restrict_address_families"] == "AF_UNIX"
        and properties["denied_network_syscalls"]
        == sorted(BUILD_DENIED_NETWORK_SYSCALLS)
        and properties["system_call_error_number"] == errno.EPERM
        and properties["no_new_privileges"] is True
        and properties["limit_core_bytes"] == 0
        and properties["memory_max_bytes"] == MEMORY_MAX_BYTES
        and properties["memory_swap_max_bytes"] == 0
        and properties["umask_octal"] == "0077"
        and properties["unset_environment"]
        == sorted(BUILD_BOOTSTRAP_UNSET_ENVIRONMENT)
        and properties["standard_input"] == "null"
        and properties["standard_output"] == "null"
        and properties["standard_error"] == "null"
        and properties["inherited_communication_fds"] is False
        and _is_sha256(runtime.get("show_sha256"))
        and type(runtime.get("show_bytes")) is int
        and runtime["show_bytes"] > 0
        and _is_sha256(runtime.get("journal_sha256"))
        and type(runtime.get("journal_bytes")) is int
        and runtime["journal_bytes"] >= 0
        and runtime.get("result") == "success"
        and runtime.get("exec_main_status") == 0
        and runtime.get("unit_stopped_after_capture") is True,
        "build-runtime-contract",
    )


def _validate_build_network_boundary(outer: dict) -> None:
    network = outer.get("network_boundary")
    expected_keys = {
        "denied_network_syscalls",
        "system_call_error",
        "restrict_address_families",
        "socket_and_socketpair_allowed_for_local_process_spawn",
        "socketpair_connected_write_read_classified_as_local_ipc_only",
        "sendto_recvfrom_denied",
        "sendmsg_recvmsg_mmsg_denied",
        "af_unix_connect_bind_listen_accept_denied",
        "io_uring_setup_enter_register_denied",
        "inherited_communication_fds",
        "ip_address_families_available",
        "local_af_unix_ipc_permitted",
        "local_af_unix_ipc_observed",
        "af_unix_external_relay_surface_observed",
        "strict_no_socket_runtime_boundary_is_not_this_build_boundary",
        "probe",
        "network_communication_performed",
    }
    need(
        type(network) is dict
        and set(network) == expected_keys
        and network["denied_network_syscalls"] == list(BUILD_DENIED_NETWORK_SYSCALLS)
        and network["system_call_error"] == "EPERM"
        and network["restrict_address_families"] == "AF_UNIX"
        and network["socket_and_socketpair_allowed_for_local_process_spawn"] is True
        and network["socketpair_connected_write_read_classified_as_local_ipc_only"] is True
        and network["sendto_recvfrom_denied"] is True
        and network["sendmsg_recvmsg_mmsg_denied"] is True
        and network["af_unix_connect_bind_listen_accept_denied"] is True
        and network["io_uring_setup_enter_register_denied"] is True
        and network["inherited_communication_fds"] is False
        and network["ip_address_families_available"] is False
        and network["local_af_unix_ipc_permitted"] is True
        and network["local_af_unix_ipc_observed"] is True
        and network["af_unix_external_relay_surface_observed"] is False
        and network["strict_no_socket_runtime_boundary_is_not_this_build_boundary"] is True
        and network["network_communication_performed"] is False,
        "build-network-boundary",
    )
    probe = network["probe"]
    _validate_build_runtime_common(probe)
    for key in (
        "af_inet_and_af_inet6_socket_calls_denied_with_eafnosupport",
        "af_unix_socket_and_socketpair_available_for_process_spawn",
        "local_af_unix_ipc_observed",
        "af_unix_seqpacket_connected_write_and_read_observed",
        "fixed_subprocess_spawn_succeeded",
        "af_unix_connect_attempt_denied_with_eperm",
        "af_unix_datagram_sendto_denied_with_eperm",
        "af_unix_recvfrom_denied_with_eperm",
        "io_uring_setup_enter_register_denied_with_eperm_or_enosys",
        "initial_standard_fds_are_dev_null",
        "no_other_inherited_fds_observed",
    ):
        need(probe.get(key) is True, "build-network-probe-outcome")
    need(
        probe.get("network_communication_performed") is False,
        "build-network-probe-outcome",
    )


def validate_build_bundle() -> dict:
    _require_bound_constants()
    _directory(PRIVATE_BUILD_PARENT, 0o700)
    _directory(BUILD_BUNDLE, 0o500)
    _directory(BUILD_BUNDLE / "artifacts", 0o500)
    _directory(BUILD_EVIDENCE, 0o500)
    need(
        set(os.listdir(BUILD_BUNDLE)) == {"sources", "artifacts", "SOURCE-MANIFEST.json", "FREEZER-SOURCE.py", "BUILD-RECEIPT.json"}
        and set(os.listdir(BUILD_BUNDLE / "artifacts"))
        == {
            "candidate-binary",
            "candidate-binary.d",
            "verify_frozen_w1_round1_receipt",
            "verify_frozen_w1_round1_receipt.d",
        }
        and set(os.listdir(BUILD_EVIDENCE)) == {"FREEZER-SOURCE.py", "PROOF-BUILD-RECEIPT.json"},
        "build-tree-files",
    )
    manifest_raw, manifest_ref = _stable_file(BUILD_MANIFEST, 0o400, expected_sha256=EXPECTED_MANIFEST_SHA256)
    inner_raw, inner_ref = _stable_file(BUILD_INNER_RECEIPT, 0o400, expected_sha256=EXPECTED_INNER_RECEIPT_SHA256)
    dep_raw, dep_ref = _stable_file(BUILD_DEP_INFO, 0o400, expected_sha256=EXPECTED_DEP_INFO_SHA256)
    _, binary_ref = _stable_file(BUILD_BINARY, 0o500, expected_sha256=EXPECTED_BINARY_SHA256, expected_bytes=EXPECTED_BINARY_BYTES, retain=False)
    verifier_dep_raw, verifier_dep_ref = _stable_file(
        BUILD_VERIFIER_DEP_INFO,
        0o400,
        expected_sha256=EXPECTED_VERIFIER_DEP_INFO_SHA256,
    )
    _, verifier_ref = _stable_file(
        BUILD_VERIFIER_BINARY,
        0o500,
        expected_sha256=EXPECTED_VERIFIER_BINARY_SHA256,
        expected_bytes=EXPECTED_VERIFIER_BINARY_BYTES,
        retain=False,
    )
    _, core_ref = _stable_file(BUILD_CORE_SOURCE, 0o400, expected_sha256=EXPECTED_BUILD_CORE_SOURCE_SHA256)
    _, freezer_ref = _stable_file(BUILD_FREEZER_SOURCE, 0o400, expected_sha256=EXPECTED_BUILD_FREEZER_SOURCE_SHA256)
    outer_raw, outer_ref = _stable_file(BUILD_OUTER_RECEIPT, 0o400, expected_sha256=EXPECTED_OUTER_RECEIPT_SHA256)
    manifest, paths = _validate_manifest(manifest_raw)
    need(manifest_raw == canonical(manifest), "manifest-noncanonical")
    snapshot = _validate_snapshot(manifest, paths)
    inner = _unique_json(inner_raw)
    outer = _unique_json(outer_raw)
    need(type(inner) is dict and type(outer) is dict, "build-receipt-object")
    _receipt_identity(inner, "inner-build-identity")
    _receipt_identity(outer, "outer-build-identity")
    need(
        inner_raw == canonical(inner) and outer_raw == canonical(outer),
        "build-receipt-noncanonical",
    )
    need(
        inner.get("schema") == "kpb-current-w1-test-build-freeze-receipt/v1"
        and inner.get("authorization") is False
        and inner.get("setup") is False
        and inner.get("pk_decode") is False
        and inner.get("synthesis") is False
        and inner.get("proof") is False
        and inner.get("network") is False
        and inner.get("funds") is False,
        "inner-build-truth",
    )
    build = outer.get("build", {})
    closure = outer.get("closure_scope", {})
    dep_info = outer.get("dep_info", {})
    verifier_dep_info = outer.get("verifier_dep_info", {})
    bundle = outer.get("atomic_core_bundle", {})
    limitations = outer.get("limitations", {})
    need(
        outer.get("schema") == "kpb-w1-proof-build-receipt/v1"
        and outer.get("classification") == "TEST_ONLY_COMBINED_W1_PROOF_BUILD_NOT_AUTHORITY"
        and outer.get("authorization") is False
        and outer.get("privacy_acceptance") is False
        and outer.get("financial_acceptance") is False
        and outer.get("setup") is False
        and outer.get("pk_decode") is False
        and outer.get("proving_key_read") is False
        and outer.get("synthesis") is False
        and outer.get("proof") is False
        and outer.get("verification") is False
        and outer.get("network_communication") is False
        and outer.get("funds") is False
        and outer.get("actions") == BUILD_ACTIONS
        and build.get("actual_subprocess_executed") is True
        and build.get("binary_was_not_executed") is True
        and build.get("both_binaries_were_not_executed") is True
        and build.get("no_binary_execution_command_dispatched") is True
        and build.get("locked") is True and build.get("offline") is True
        and build.get("profile") == "release"
        and build.get("default_features") is False
        and build.get("features") == ["offline-w1-prover"]
        and build.get("example") == BUILD_EXAMPLES[0]
        and build.get("examples") == list(BUILD_EXAMPLES)
        and build.get("single_cargo_invocation_for_both_examples") is True
        and closure.get("combined_assignment_plus_prover_closure_frozen") is True
        and closure.get("proof_entry_source_present") is True
        and closure.get("verifier_entry_source_present") is True
        and closure.get("private_prover_source_present") is True
        and closure.get("reviewed_low_memory_source_present") is True
        and closure.get("parent_verifier_closure_frozen") is True
        and bundle.get("source_binary_receipt_atomically_published") is True,
        "outer-build-truth",
    )
    need(
        limitations.get("proof_executed") is False
        and limitations.get("verifier_binary_executed") is False
        and limitations.get("cryptographic_correctness_proved") is False
        and limitations.get("privacy_proved") is False,
        "outer-build-limitations",
    )
    _validate_build_command(build, outer)
    _validate_reviewed_build_sources(outer, manifest, manifest_ref)
    _validate_build_unit_ledger(outer, build)
    _validate_build_runtime_common(build.get("unit"))
    _validate_build_network_boundary(outer)
    dependencies = dep_info.get("dependency_relatives")
    dependency_count = _validate_dependency_contract(
        dep_info,
        dependencies,
        paths,
        dep_raw,
    )
    verifier_dependencies = verifier_dep_info.get("dependency_relatives")
    verifier_dependency_count = _validate_verifier_dependency_contract(
        verifier_dep_info,
        verifier_dependencies,
        paths,
        verifier_dep_raw,
        EXPECTED_VERIFIER_DEP_INFO_SHA256,
        EXPECTED_VERIFIER_DEPENDENCY_RELATIVES,
    )
    inner_dep = inner.get("dep_info", {})
    inner_verifier_dep = inner.get("verifier_dep_info", {})
    need(
        inner.get("source_manifest", {}).get("sha256") == manifest_ref["sha256"]
        and inner.get("built_examples") == list(BUILD_EXAMPLES)
        and inner.get("actual_subprocess_build_executed_by_contract") is True
        and inner.get("production_source_manifest_bound") is False
        and inner.get("production_binary_accepted") is False
        and inner.get("binary", {}).get("sha256") == binary_ref["sha256"]
        and inner.get("frozen_dep_info", {}).get("sha256") == dep_ref["sha256"]
        and _matches_file_claim(
            inner.get("verifier_binary"),
            verifier_ref,
            name="verify_frozen_w1_round1_receipt",
        )
        and _matches_file_claim(
            inner.get("frozen_verifier_dep_info"),
            verifier_dep_ref,
            name="verify_frozen_w1_round1_receipt.d",
        ),
        "inner-build-artifact-binding",
    )
    need(
        inner_dep.get("target") == "artifacts/candidate-binary"
        and inner_dep.get("dependencies")
        == [f"sources/{relative}" for relative in dependencies]
        and inner_dep.get("dependency_count") == dependency_count
        and inner_dep.get("dep_info_sha256") == dep_ref["sha256"]
        and inner_dep.get("snapshot_only") is True
        and inner_dep.get("live_path_provenance") is False
        and inner_verifier_dep.get("target")
        == "artifacts/verify_frozen_w1_round1_receipt"
        and inner_verifier_dep.get("dependencies")
        == [f"sources/{relative}" for relative in verifier_dependencies]
        and inner_verifier_dep.get("dependency_count") == verifier_dependency_count
        and inner_verifier_dep.get("dep_info_sha256")
        == verifier_dep_ref["sha256"]
        and inner_verifier_dep.get("snapshot_only") is True
        and inner_verifier_dep.get("live_path_provenance") is False,
        "inner-build-dependency-binding",
    )
    need(
        outer.get("freezer_source", {}).get("sha256") == freezer_ref["sha256"]
        and outer.get("executed_core_source", {}).get("frozen_inner_copy", {}).get("sha256") == core_ref["sha256"]
        and bundle.get("binary", {}).get("sha256") == binary_ref["sha256"]
        and bundle.get("receipt", {}).get("sha256") == inner_ref["sha256"],
        "outer-core-artifact-binding",
    )
    need(
        _matches_file_claim(
            bundle.get("parent_verifier_binary"),
            verifier_ref,
            path=BUILD_VERIFIER_BINARY,
        )
        and _matches_file_claim(
            bundle.get("parent_verifier_dep_info"),
            verifier_dep_ref,
            path=BUILD_VERIFIER_DEP_INFO,
        )
        and _matches_file_claim(
            verifier_dep_info.get("frozen"),
            verifier_dep_ref,
            path=BUILD_VERIFIER_DEP_INFO,
        )
        and bundle.get("result", {}).get("verifier_binary_sha256")
        == verifier_ref["sha256"]
        and bundle.get("result", {}).get("verifier_dep_info_sha256")
        == verifier_dep_ref["sha256"]
        and build.get("cargo_original_verifier_binary", {}).get("sha256")
        == verifier_ref["sha256"]
        and build.get("detached_create_new_verifier_binary", {}).get("sha256")
        == verifier_ref["sha256"]
        and build.get("detached_binaries_byte_identical") is True,
        "outer-verifier-artifact-binding",
    )
    return {
        "references": {
            "manifest": manifest_ref, "inner_receipt": inner_ref, "dep_info": dep_ref,
            "binary": binary_ref, "core_source": core_ref,
            "parent_verifier_binary": verifier_ref,
            "parent_verifier_dep_info": verifier_dep_ref,
            "build_freezer_source": freezer_ref, "outer_receipt": outer_ref,
        },
        "source_snapshot": snapshot,
        "dependency_count": dependency_count,
        "parent_verifier_dependency_count": verifier_dependency_count,
        "combined_assignment_plus_prover_and_parent_verifier": True,
    }


def _fixed_artifact_references() -> dict:
    result = {}
    for name, (path, size, digest, mode) in FIXED_ARTIFACTS.items():
        _, result[name] = _stable_file(path, mode, expected_sha256=digest, expected_bytes=size, retain=False)
    return result


def validate_proof_receipt(value: object) -> None:
    keys = {
        "schema", "classification", "selected_round", "prepared_instances",
        "prepared_witnesses", "prepared_variables", "prepared_constraints",
        "public_inputs_decimal", "proof_ark_compressed_hex", "proof_bytes",
        "proof_sha256", "r1cs_bytes", "r1cs_sha256", "decoded_pk_bytes",
        "decoded_pk_sha256", "compressed_pk_bytes", "compressed_pk_sha256",
        "decode_receipt_bytes", "decode_receipt_sha256", "vk_bytes", "vk_sha256",
        "historical_sources_rehashed", "r1cs_satisfaction_checked",
        "proof_parameter_descriptors_opened_after_satisfaction",
        "historical_source_vk_opened_during_assignment_preparation",
        "decoded_pk_rehashed_before_deserialization",
        "internal_osrng_nonzero_blinding", "proof_generated", "independent_vk_rehashed",
        "independent_verification", "wrong_public_inputs_rejected", "mutated_proof_rejected",
        "assignment_serialized", "secret_fingerprint_emitted", "setup_executed",
        "network_communication", "funds", "testnet", "full_secret_zeroization",
        "error_path_source_zeroization_complete", "abort_oom_zeroization",
        "receipt_is_authority", "public_or_production_authority",
    }
    need(type(value) is dict and set(value) == keys, "proof-receipt-keys")
    proof_hex = value["proof_ark_compressed_hex"]
    public_inputs = value["public_inputs_decimal"]
    need(type(proof_hex) is str and len(proof_hex) == 256 and proof_hex == proof_hex.lower(), "proof-encoding")
    try:
        proof = bytes.fromhex(proof_hex)
    except ValueError:
        raise Refused("proof-encoding") from None
    need(
        value["schema"] == PROOF_SCHEMA and value["classification"] == CLASSIFICATION
        and type(value["selected_round"]) is int and value["selected_round"] == 1
        and type(value["prepared_instances"]) is int and value["prepared_instances"] == 3
        and type(value["prepared_witnesses"]) is int and value["prepared_witnesses"] == 12_949_818
        and type(value["prepared_variables"]) is int and value["prepared_variables"] == 12_949_821
        and type(value["prepared_constraints"]) is int and value["prepared_constraints"] == 13_093_029
        and type(public_inputs) is list
        and len(public_inputs) == 2
        and all(type(item) is str for item in public_inputs)
        and public_inputs == list(EXPECTED_PUBLIC_INPUTS)
        and type(value["proof_bytes"]) is int and value["proof_bytes"] == 128
        and len(proof) == 128 and value["proof_sha256"] == sha256_bytes(proof)
        and value["r1cs_bytes"] == FIXED_ARTIFACTS["r1cs"][1]
        and value["r1cs_sha256"] == FIXED_ARTIFACTS["r1cs"][2]
        and value["decoded_pk_bytes"] == FIXED_ARTIFACTS["decoded_pk"][1]
        and value["decoded_pk_sha256"] == FIXED_ARTIFACTS["decoded_pk"][2]
        and value["compressed_pk_bytes"] == FIXED_ARTIFACTS["compressed_pk"][1]
        and value["compressed_pk_sha256"] == FIXED_ARTIFACTS["compressed_pk"][2]
        and value["decode_receipt_bytes"] == FIXED_ARTIFACTS["decode_receipt"][1]
        and value["decode_receipt_sha256"] == FIXED_ARTIFACTS["decode_receipt"][2]
        and value["vk_bytes"] == FIXED_ARTIFACTS["independent_vk"][1]
        and value["vk_sha256"] == FIXED_ARTIFACTS["independent_vk"][2],
        "proof-receipt-values",
    )
    for key in (
        "historical_sources_rehashed", "r1cs_satisfaction_checked",
        "proof_parameter_descriptors_opened_after_satisfaction",
        "historical_source_vk_opened_during_assignment_preparation",
        "decoded_pk_rehashed_before_deserialization",
        "internal_osrng_nonzero_blinding", "proof_generated", "independent_vk_rehashed",
        "independent_verification", "wrong_public_inputs_rejected", "mutated_proof_rejected",
    ):
        need(value[key] is True, "proof-required-true")
    for key in (
        "assignment_serialized", "secret_fingerprint_emitted", "setup_executed",
        "network_communication", "funds", "testnet", "full_secret_zeroization",
        "error_path_source_zeroization_complete", "abort_oom_zeroization",
        "receipt_is_authority", "public_or_production_authority",
    ):
        need(value[key] is False, "proof-required-false")


def _proof_receipt_reference(expected_sha256: str) -> tuple[bytes, dict, dict]:
    need(_is_sha256(expected_sha256), "proof-receipt-expected-sha256")
    raw, reference = _stable_file(
        PROOF_RECEIPT,
        0o400,
        expected_sha256=expected_sha256,
    )
    value = _unique_json(raw)
    validate_proof_receipt(value)
    need(raw == canonical(value), "proof-receipt-noncanonical")
    return raw, value, reference


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
    need(set(result) == set(SHOW_PROPERTIES), "systemd-show-fields")
    return result


def _timespan_usec(value: str) -> int:
    units = {"us": 1, "ms": 1_000, "s": 1_000_000, "min": 60_000_000, "h": 3_600_000_000}
    for suffix in ("min", "ms", "us", "h", "s"):
        if value.endswith(suffix):
            try:
                number = float(value[:-len(suffix)])
            except ValueError:
                break
            need(math.isfinite(number) and number >= 0 and number * units[suffix] == int(number * units[suffix]), "systemd-timespan")
            return int(number * units[suffix])
    raise Refused("systemd-timespan")


def _validate_systemd_properties(
    values: dict[str, str],
    *,
    final: bool,
    standard_input: str = "null",
    standard_output: str = "null",
    standard_error: str = "null",
    expected_denied_syscalls: set[str] = STRICT_DENIED_NETWORK_SYSCALLS,
    denied_evidence_key: str = "denied_network_syscalls",
) -> dict:
    syscall_filter = values["SystemCallFilter"]
    need(syscall_filter.startswith("~"), "systemd-filter-form")
    denied = set(syscall_filter[1:].split())
    need(
        values["LoadState"] == "loaded"
        and values["RestrictAddressFamilies"] == "AF_UNIX"
        and type(expected_denied_syscalls) is set
        and denied == expected_denied_syscalls
        and denied_evidence_key in (
            "denied_network_syscalls", "denied_stage0_syscalls",
        )
        and values["SystemCallErrorNumber"] == str(errno.EPERM)
        and values["SystemCallArchitectures"] == "native"
        and values["NoNewPrivileges"] == "yes"
        and values["LimitCORE"] == "0"
        and values["MemoryMax"] == str(MEMORY_MAX_BYTES)
        and values["MemorySwapMax"] == "0"
        and values["OOMPolicy"] == "stop"
        and values["RuntimeMaxUSec"] == "infinity"
        and _timespan_usec(values["TimeoutStopUSec"]) == 30_000_000
        and values["KillMode"] == "control-group"
        and values["NRestarts"] == "0"
        and values["UMask"] == "0077"
        and tuple(values["UnsetEnvironment"].split())
        == BOOTSTRAP_UNSET_ENVIRONMENT
        and values["StandardInput"] == standard_input
        and values["StandardOutput"] == standard_output
        and values["StandardError"] == standard_error
        and len(values["InvocationID"]) == 32
        and all(character in "0123456789abcdef" for character in values["InvocationID"])
        and values["ExecMainPID"].isdigit()
        and values["TriggeredBy"] == ""
        and values["Triggers"] == "",
        "systemd-boundary",
    )
    def metric(name: str, *, allow_unset: bool) -> int | None:
        raw = values[name]
        if raw == "[not set]" and allow_unset:
            return None
        need(raw.isdigit(), "systemd-metric")
        return int(raw)

    peak = metric("MemoryPeak", allow_unset=not final)
    swap_current = metric("MemorySwapCurrent", allow_unset=True)
    swap_peak = metric("MemorySwapPeak", allow_unset=True)
    exec_main_pid = int(values["ExecMainPID"])
    if final:
        need(
            values["ActiveState"] == "active"
            and values["SubState"] == "exited"
            and values["Result"] == "success"
            and values["ExecMainStatus"] == "0"
            and exec_main_pid > 0
            and peak is not None and peak > 0
            and swap_current in (None, 0)
            and swap_peak in (None, 0),
            "systemd-result",
        )
    need(peak is None or peak <= MEMORY_MAX_BYTES, "systemd-memory-peak")
    return {
        denied_evidence_key: sorted(denied),
        "memory_max_bytes": int(values["MemoryMax"]),
        "memory_peak_bytes": peak,
        "memory_swap_max_bytes": 0,
        "memory_swap_current_bytes": swap_current,
        "memory_swap_peak_bytes": swap_peak,
        "automatic_runtime_timeout": False,
        "standard_input": standard_input,
        "standard_output": standard_output,
        "standard_error": standard_error,
        "invocation_id": values["InvocationID"],
        "exec_main_pid": exec_main_pid,
        "bootstrap_loader_environment_unset": True,
        "core_limit_bytes": 0,
        "no_new_privileges": True,
        "restart_count": 0,
    }


def _unit_systemd_properties(unit: str) -> tuple[str, ...]:
    need(unit in (PROBE_UNIT, RUN_UNIT, VERIFY_UNIT), "unit-name")
    if unit == PROBE_UNIT:
        return PROBE_SYSTEMD_PROPERTIES
    if unit == RUN_UNIT:
        return PROOF_SYSTEMD_PROPERTIES
    return VERIFIER_SYSTEMD_PROPERTIES


def _unit_standard_io(unit: str) -> tuple[str, str, str]:
    properties = _unit_systemd_properties(unit)
    values = dict(value.split("=", 1) for value in properties if value.startswith("Standard"))
    return (
        values["StandardInput"],
        values["StandardOutput"],
        values["StandardError"],
    )


def _base_systemd_command(
    unit: str,
    *,
    standard_input_data: bytes | None = None,
) -> list[str]:
    properties = _unit_systemd_properties(unit)
    need(
        (unit == VERIFY_UNIT) == (standard_input_data is not None),
        "unit-standard-input-data",
    )
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
    for property_value in properties:
        command.extend(("--property", property_value))
    if standard_input_data is not None:
        need(0 < len(standard_input_data) <= 4_096, "verifier-stdin-bounds")
        encoded = base64.b64encode(standard_input_data).decode("ascii")
        command.extend(("--property", f"StandardInputData={encoded}"))
    return command


def _cleared_python_command(source: str, arguments: tuple[str, ...]) -> list[str]:
    return [
        str(ENV),
        "-i",
        *FIXED_ENVIRONMENT,
        str(PYTHON),
        "-I",
        "-c",
        source,
        *arguments,
    ]


def _manager_tool_environment() -> dict[str, str]:
    uid = os.getuid()
    runtime = f"/run/user/{uid}"
    return {
        "HOME": "/nonexistent",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }


def _probe_command() -> list[str]:
    return _base_systemd_command(PROBE_UNIT) + _cleared_python_command(
        NETWORK_PROBE_SOURCE,
        (),
    )


def _run_command(binary: dict) -> list[str]:
    need(
        binary.get("path") == str(BUILD_BINARY)
        and type(binary.get("device")) is int
        and type(binary.get("inode")) is int
        and type(binary.get("bytes")) is int
        and type(binary.get("sha256")) is str
        and type(binary.get("owner_uid")) is int
        and binary.get("mode_octal") == "0500"
        and binary.get("link_count") == 1,
        "binary-launch-reference",
    )
    helper = _render_identity_bound_exec_source(
        binary_path=BUILD_BINARY,
        receipt_path=PROOF_RECEIPT,
        expected_device=binary["device"],
        expected_inode=binary["inode"],
        expected_bytes=binary["bytes"],
        expected_sha256=binary["sha256"],
        expected_owner_uid=binary["owner_uid"],
    )
    return _base_systemd_command(RUN_UNIT) + _cleared_python_command(
        helper,
        (),
    )


def _verifier_command(binary: dict, proof_receipt_raw: bytes) -> list[str]:
    need(
        binary.get("path") == str(BUILD_VERIFIER_BINARY)
        and type(binary.get("device")) is int
        and type(binary.get("inode")) is int
        and type(binary.get("bytes")) is int
        and _is_sha256(binary.get("sha256"))
        and type(binary.get("owner_uid")) is int
        and binary.get("mode_octal") == "0500"
        and binary.get("link_count") == 1,
        "verifier-launch-reference",
    )
    helper = _render_identity_bound_exec_source(
        binary_path=BUILD_VERIFIER_BINARY,
        receipt_path=None,
        expected_device=binary["device"],
        expected_inode=binary["inode"],
        expected_bytes=binary["bytes"],
        expected_sha256=binary["sha256"],
        expected_owner_uid=binary["owner_uid"],
    )
    return _base_systemd_command(
        VERIFY_UNIT,
        standard_input_data=proof_receipt_raw,
    ) + _cleared_python_command(helper, ())


def _identity_bound_helper_reference(binary: dict) -> dict:
    helper = _run_command(binary)[-1]
    return {
        "interpreter": str(PYTHON),
        "source_bytes": len(helper.encode()),
        "source_sha256": sha256_bytes(helper.encode()),
        "exec_primitive": "sealed-memfd-os.execve-by-file-descriptor",
        "memfd_seals": [
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        ],
        "sealed_memfd_rehashed_before_exec": True,
        "binary_path": str(BUILD_BINARY),
        "binary_device": binary["device"],
        "binary_inode": binary["inode"],
        "binary_bytes": binary["bytes"],
        "binary_sha256": binary["sha256"],
        "binary_mode_octal": "0500",
        "binary_link_count": 1,
        "binary_owner_uid": binary["owner_uid"],
        "binary_argv": [str(BUILD_BINARY), str(PROOF_RECEIPT)],
        "exact_environment": list(FIXED_ENVIRONMENT),
        "initial_only_standard_fds_observed": True,
        "immediate_pre_exec_only_standard_fds_and_sealed_executable_observed": True,
        "stdout_local_journal_ipc_from_validated_unit_properties": True,
        "stdout_journal_stderr_null": True,
    }


def _verifier_identity_bound_helper_reference(binary: dict, proof_receipt_raw: bytes) -> dict:
    helper = _verifier_command(binary, proof_receipt_raw)[-1]
    return {
        "interpreter": str(PYTHON),
        "source_bytes": len(helper.encode()),
        "source_sha256": sha256_bytes(helper.encode()),
        "exec_primitive": "sealed-memfd-os.execve-by-file-descriptor",
        "memfd_seals": [
            "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL",
        ],
        "sealed_memfd_rehashed_before_exec": True,
        "binary_path": str(BUILD_VERIFIER_BINARY),
        "binary_device": binary["device"],
        "binary_inode": binary["inode"],
        "binary_bytes": binary["bytes"],
        "binary_sha256": binary["sha256"],
        "binary_mode_octal": "0500",
        "binary_link_count": 1,
        "binary_owner_uid": binary["owner_uid"],
        "binary_argv": [str(BUILD_VERIFIER_BINARY)],
        "exact_environment": list(FIXED_ENVIRONMENT),
        "initial_only_standard_fds_observed": True,
        "immediate_pre_exec_only_standard_fds_and_sealed_executable_observed": True,
        "stdout_local_journal_ipc_from_validated_unit_properties": True,
        "stdin_exact_canonical_receipt_bytes": len(proof_receipt_raw),
        "stdout_journal_stderr_null": True,
    }


def _show_unit(unit: str) -> tuple[dict[str, str], bytes]:
    command = [str(SYSTEMCTL), "--user", "show", f"{unit}.service"]
    for name in SHOW_PROPERTIES:
        command.append(f"--property={name}")
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_manager_tool_environment(),
        check=False,
    )
    need(completed.returncode == 0 and completed.stderr == b"", "systemd-show")
    return _parse_show(completed.stdout), completed.stdout


def _pristine_unit_observation(unit: str) -> dict:
    need(
        unit in (PROBE_UNIT, RUN_UNIT, VERIFY_UNIT),
        "pristine-unit-name",
    )
    synchronized = subprocess.run(
        [str(JOURNALCTL), "--user", "--sync"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_manager_tool_environment(),
        check=False,
    )
    need(
        synchronized.returncode == 0
        and synchronized.stdout == b""
        and synchronized.stderr == b"",
        "pristine-unit-journal-sync",
    )
    observations = {}
    for suffix in ("service", "socket"):
        unit_name = f"{unit}.{suffix}"
        show_command = [
            str(SYSTEMCTL), "--user", "show", unit_name,
            "--property=LoadState", "--property=TriggeredBy",
            "--property=Triggers", "--no-pager",
        ]
        show = subprocess.run(
            show_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_manager_tool_environment(),
            check=False,
        )
        need(show.returncode == 0 and show.stderr == b"", "pristine-unit-show")
        values = {}
        try:
            lines = show.stdout.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            raise Refused("pristine-unit-show-utf8") from None
        for line in lines:
            need("=" in line, "pristine-unit-show-line")
            key, value = line.split("=", 1)
            need(
                key in ("LoadState", "TriggeredBy", "Triggers")
                and key not in values,
                "pristine-unit-show-key",
            )
            values[key] = value
        need(
            values
            == {"LoadState": "not-found", "TriggeredBy": "", "Triggers": ""},
            "pristine-unit-not-found",
        )
        journal_command = [
            str(JOURNALCTL), "--user", "--quiet", "--no-pager", "--all",
            "--output=export", f"--unit={unit_name}",
        ]
        journal = subprocess.run(
            journal_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_manager_tool_environment(),
            check=False,
        )
        need(
            journal.returncode == 0
            and journal.stdout == b""
            and journal.stderr == b"",
            "pristine-unit-historical-journal",
        )
        observations[suffix] = {
            "unit": unit_name,
            "load_state": "not-found",
            "no_socket_association": True,
            "show_command_sha256": sha256_bytes(canonical(show_command)),
            "show_bytes": len(show.stdout),
            "show_sha256": sha256_bytes(show.stdout),
            "historical_journal_command_sha256": sha256_bytes(
                canonical(journal_command)
            ),
            "historical_journal_empty": True,
        }
    return {
        "unit_root": unit,
        "service_and_socket_unit_names_pristine": True,
        "observations": observations,
    }


def _stop_unit(unit: str) -> None:
    completed = subprocess.run(
        [str(SYSTEMCTL), "--user", "stop", f"{unit}.service"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=_manager_tool_environment(),
        check=False,
    )
    need(completed.returncode == 0, "unit-stop")


def _parse_journal_export(raw: bytes) -> list[dict[bytes, bytes]]:
    need(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024, "journal-export-size")
    records: list[dict[bytes, bytes]] = []
    offset = 0
    while offset < len(raw):
        fields: dict[bytes, bytes] = {}
        while True:
            newline = raw.find(b"\n", offset)
            need(newline >= 0, "journal-export-line")
            header = raw[offset:newline]
            offset = newline + 1
            if header == b"":
                need(fields, "journal-export-empty-record")
                records.append(fields)
                break
            if b"=" in header:
                key, value = header.split(b"=", 1)
            else:
                key = header
                need(offset + 8 <= len(raw), "journal-export-binary-length")
                length = int.from_bytes(raw[offset:offset + 8], "little")
                offset += 8
                need(length <= 2 * 1024 * 1024 and offset + length < len(raw), "journal-export-binary-size")
                value = raw[offset:offset + length]
                offset += length
                need(raw[offset:offset + 1] == b"\n", "journal-export-binary-terminator")
                offset += 1
            need(
                key
                and all(
                    byte == 95 or 48 <= byte <= 57 or 65 <= byte <= 90
                    for byte in key
                )
                and key not in fields,
                "journal-export-field",
            )
            fields[key] = value
    need(records, "journal-export-records")
    return records


def _journal_export(unit: str, invocation_id: str) -> bytes:
    need(
        unit in (RUN_UNIT, VERIFY_UNIT, JOURNAL_PID_REHEARSAL_UNIT)
        and len(invocation_id) == 32
        and all(character in "0123456789abcdef" for character in invocation_id),
        "journal-selector",
    )
    synchronized = subprocess.run(
        [str(JOURNALCTL), "--user", "--sync"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_manager_tool_environment(),
        check=False,
    )
    need(
        synchronized.returncode == 0
        and synchronized.stdout == b""
        and synchronized.stderr == b"",
        "journal-sync",
    )
    completed = subprocess.run(
        [
            str(JOURNALCTL),
            "--user",
            "--no-pager",
            "--all",
            "--output=export",
            "--output-fields=MESSAGE,_PID,_UID,_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT,_SYSTEMD_INVOCATION_ID,_TRANSPORT,_STREAM_ID,_LINE_BREAK,PRIORITY",
            f"--unit={unit}.service",
            f"--invocation={invocation_id}",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_manager_tool_environment(),
        check=False,
    )
    need(completed.returncode == 0 and completed.stderr == b"", "journal-export")
    _parse_journal_export(completed.stdout)
    return completed.stdout


def _journal_pid_rehearsal_reference() -> dict:
    raw = _journal_export(
        JOURNAL_PID_REHEARSAL_UNIT,
        JOURNAL_PID_REHEARSAL_INVOCATION_ID,
    )
    need(
        len(raw) == JOURNAL_PID_REHEARSAL_EXPORT_BYTES
        and sha256_bytes(raw) == JOURNAL_PID_REHEARSAL_EXPORT_SHA256,
        "journal-pid-rehearsal-export",
    )
    digest, trusted_record = _journal_commitment(
        raw,
        unit=JOURNAL_PID_REHEARSAL_UNIT,
        invocation_id=JOURNAL_PID_REHEARSAL_INVOCATION_ID,
        exec_main_pid=JOURNAL_PID_REHEARSAL_EXEC_MAIN_PID,
        marker=PROOF_RECEIPT_MARKER,
        expected_digest="a" * 64,
    )
    need(digest == "a" * 64, "journal-pid-rehearsal-digest")
    return {
        "unit": f"{JOURNAL_PID_REHEARSAL_UNIT}.service",
        "invocation_id": JOURNAL_PID_REHEARSAL_INVOCATION_ID,
        "exec_main_pid": JOURNAL_PID_REHEARSAL_EXEC_MAIN_PID,
        "journal_pid": int(trusted_record["_PID"]),
        "pid_relation": "journal-_PID-equals-ExecMainPID",
        "trusted_record": trusted_record,
        "export_bytes": len(raw),
        "export_sha256": sha256_bytes(raw),
        "benign_fixed_helper_only": True,
        "proof_executed": False,
    }


def _journal_commitment(
    raw: bytes,
    *,
    unit: str,
    invocation_id: str,
    exec_main_pid: int,
    marker: str,
    expected_digest: str | None,
) -> tuple[str, dict[str, str]]:
    need(
        marker in (PROOF_RECEIPT_MARKER, PARENT_VERIFIER_MARKER)
        and type(exec_main_pid) is int
        and exec_main_pid > 0
        and (expected_digest is None or _is_sha256(expected_digest)),
        "journal-commitment-contract",
    )
    expected = {
        b"_PID": str(exec_main_pid).encode(),
        b"_UID": str(os.getuid()).encode(),
        b"_SYSTEMD_UNIT": f"user@{os.getuid()}.service".encode(),
        b"_SYSTEMD_USER_UNIT": f"{unit}.service".encode(),
        b"_SYSTEMD_INVOCATION_ID": invocation_id.encode(),
        b"_TRANSPORT": b"stdout",
        b"PRIORITY": b"6",
    }
    selected: list[dict[bytes, bytes]] = []
    marker_raw = marker.encode()
    for fields in _parse_journal_export(raw):
        message = fields.get(b"MESSAGE", b"")
        candidate = message.startswith(marker_raw) or any(
            fields.get(key) == value
            for key, value in expected.items()
            if key in (b"_PID", b"_SYSTEMD_USER_UNIT", b"_SYSTEMD_INVOCATION_ID")
        )
        if not candidate:
            continue
        need(
            all(fields.get(key) == value for key, value in expected.items())
            and b"_LINE_BREAK" not in fields
            and len(fields.get(b"_STREAM_ID", b"")) == 32
            and all(byte in b"0123456789abcdef" for byte in fields[b"_STREAM_ID"])
            and message.startswith(marker_raw)
            and len(message) == len(marker_raw) + 64,
            "journal-foreign-or-malformed-record",
        )
        digest = message[len(marker_raw):]
        need(
            all(byte in b"0123456789abcdef" for byte in digest),
            "journal-commitment-digest",
        )
        selected.append(fields)
    need(len(selected) == 1, "journal-commitment-cardinality")
    digest_text = selected[0][b"MESSAGE"][len(marker_raw):].decode("ascii")
    need(expected_digest is None or digest_text == expected_digest, "journal-commitment-mismatch")
    normalized = {
        key.decode("ascii"): selected[0][key].decode("ascii")
        for key in (*expected, b"_STREAM_ID", b"MESSAGE")
    }
    return digest_text, normalized


def _journal_commitment_pair(
    before_stop: bytes,
    after_stop: bytes,
    **contract: object,
) -> dict:
    before_digest, before_record = _journal_commitment(before_stop, **contract)
    after_digest, after_record = _journal_commitment(after_stop, **contract)
    need(
        before_digest == after_digest and before_record == after_record,
        "journal-delayed-or-changed-record",
    )
    return {
        "receipt_sha256": before_digest,
        "trusted_record": before_record,
        "pid_relation": "journal-_PID-equals-ExecMainPID",
        "pid_relation_checked_in_current_runtime_record": True,
        "before_stop_export_bytes": len(before_stop),
        "before_stop_export_sha256": sha256_bytes(before_stop),
        "after_stop_export_bytes": len(after_stop),
        "after_stop_export_sha256": sha256_bytes(after_stop),
        "missing_extra_duplicate_delayed_foreign_records_refused": True,
    }


def _run_transient(
    unit: str,
    command: list[str],
    *,
    standard_input_data: bytes | None = None,
    journal_marker: str | None = None,
    expected_journal_digest: str | None = None,
) -> dict:
    prefix = _base_systemd_command(unit, standard_input_data=standard_input_data)
    need(command[:len(prefix)] == prefix, "unit-command-prefix")
    standard_input, standard_output, standard_error = _unit_standard_io(unit)
    need(
        (journal_marker is not None) == (standard_output == "journal"),
        "unit-journal-contract",
    )
    first_pristine = _pristine_unit_observation(unit)
    second_pristine = _pristine_unit_observation(unit)
    need(first_pristine == second_pristine, "unit-not-pristine-twice")
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_manager_tool_environment(),
        check=False,
    )
    need(
        completed.returncode == 0
        and completed.stdout == b""
        and completed.stderr == b"",
        "systemd-run-start",
    )
    final_values: dict[str, str] | None = None
    show_raw = b""
    before_stop_journal: bytes | None = None
    try:
        while True:
            values, observed_raw = _show_unit(unit)
            if values["LoadState"] == "loaded":
                _validate_systemd_properties(
                    values,
                    final=False,
                    standard_input=standard_input,
                    standard_output=standard_output,
                    standard_error=standard_error,
                )
                show_raw = observed_raw
                if values["SubState"] in ("exited", "failed", "dead"):
                    final_values = values
                    break
            time.sleep(0.2)
        evidence = _validate_systemd_properties(
            final_values,
            final=True,
            standard_input=standard_input,
            standard_output=standard_output,
            standard_error=standard_error,
        )
        if journal_marker is not None:
            before_stop_journal = _journal_export(unit, evidence["invocation_id"])
    finally:
        _stop_unit(unit)
    journal = None
    if journal_marker is not None:
        need(before_stop_journal is not None, "journal-before-stop")
        after_stop_journal = _journal_export(unit, evidence["invocation_id"])
        journal = _journal_commitment_pair(
            before_stop_journal,
            after_stop_journal,
            unit=unit,
            invocation_id=evidence["invocation_id"],
            exec_main_pid=evidence["exec_main_pid"],
            marker=journal_marker,
            expected_digest=expected_journal_digest,
        )
    return {
        "unit": f"{unit}.service", "command_sha256": sha256_bytes(canonical(command)),
        "unit_identity": {
            "first_pristine_observation": first_pristine,
            "second_pristine_observation": second_pristine,
            "service_and_socket_history_empty_before_start": True,
            "start_dispatched_after_two_pristine_observations": True,
            "current_triggered_by_and_triggers_empty": True,
        },
        "properties": evidence, "show_bytes": len(show_raw), "show_sha256": sha256_bytes(show_raw),
        "child_stdout_transport": standard_output,
        "child_stdout_single_authenticated_commitment": journal is not None,
        "child_stderr_persisted": False,
        "result": "success", "exec_main_status": 0,
        "unit_stopped_after_capture": True,
        "journal_commitment": journal,
    }


def _write_new(path: Path, raw: bytes, mode: int) -> dict:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
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


def _stable_file_at(
    directory_fd: int,
    name: str,
    logical_path: Path,
    mode: int,
    *,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
) -> tuple[bytes, dict]:
    need(name == Path(name).name and name not in ("", ".", ".."), "file-at-name")
    before_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    need(
        stat.S_ISREG(before_path.st_mode)
        and before_path.st_uid == os.getuid()
        and before_path.st_nlink == 1
        and stat.S_IMODE(before_path.st_mode) == mode,
        "file-at-stat",
    )
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        need(_same_stat(before, before_path), "file-at-open-race")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            chunks.append(block)
            total += len(block)
        after = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        need(
            _same_stat(before, after)
            and _same_stat(after, after_path)
            and total == after.st_size,
            "file-at-read-race",
        )
    finally:
        os.close(descriptor)
    actual = digest.hexdigest()
    need(expected_sha256 is None or actual == expected_sha256, "file-at-hash")
    need(expected_bytes is None or total == expected_bytes, "file-at-bytes")
    return b"".join(chunks), {
        "path": str(logical_path),
        "bytes": total,
        "sha256": actual,
        "mode_octal": f"{mode:04o}",
        "device": after.st_dev,
        "inode": after.st_ino,
        "link_count": after.st_nlink,
        "owner_uid": after.st_uid,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
    }


def _write_new_at(
    directory_fd: int,
    name: str,
    logical_path: Path,
    raw: bytes,
    mode: int,
) -> dict:
    need(name == Path(name).name and name not in ("", ".", ".."), "write-at-name")
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            need(count > 0, "write-at-progress")
            view = view[count:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _, reference = _stable_file_at(
        directory_fd,
        name,
        logical_path,
        mode,
        expected_sha256=sha256_bytes(raw),
    )
    return reference


def _proof_receipt_reference_at(
    directory_fd: int,
    expected_sha256: str,
) -> tuple[bytes, dict, dict]:
    need(_is_sha256(expected_sha256), "proof-receipt-at-expected-sha256")
    raw, reference = _stable_file_at(
        directory_fd,
        PROOF_RECEIPT.name,
        PROOF_RECEIPT,
        0o400,
        expected_sha256=expected_sha256,
    )
    value = _unique_json(raw)
    validate_proof_receipt(value)
    need(raw == canonical(value), "proof-receipt-at-noncanonical")
    return raw, value, reference


def _rename_no_replace(directory_fd: int, source: str, target: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    need(renameat2 is not None, "renameat2-unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(directory_fd, os.fsencode(source), directory_fd, os.fsencode(target), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(target)
        raise OSError(code, os.strerror(code), target)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_run_root() -> None:
    need(not os.path.lexists(RUN_ROOT), "run-root-create-new")
    os.mkdir(RUN_ROOT, 0o700)
    _directory(RUN_ROOT, 0o700)
    _fsync_directory(LOCAL_ROOT)


def _publish(
    supervisor_raw: bytes,
    receipt: dict,
    expected_proof_raw: bytes,
    expected_proof_reference: dict,
) -> dict:
    need(
        RUN_ROOT.parent == LOCAL_ROOT
        and PROOF_RECEIPT.parent == RUN_ROOT
        and SUPERVISOR_SOURCE.parent == RUN_ROOT
        and LAUNCH_RECEIPT.parent == RUN_ROOT,
        "publication-path-contract",
    )
    parent_before_path = os.lstat(LOCAL_ROOT)
    need(
        stat.S_ISDIR(parent_before_path.st_mode)
        and not stat.S_ISLNK(parent_before_path.st_mode)
        and parent_before_path.st_uid == os.getuid(),
        "publication-parent-stat",
    )
    parent = os.open(
        LOCAL_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        parent_before = os.fstat(parent)
        need(_same_stat(parent_before, parent_before_path), "publication-parent-open-race")
        run_before_path = os.stat(
            RUN_ROOT.name,
            dir_fd=parent,
            follow_symlinks=False,
        )
        need(
            stat.S_ISDIR(run_before_path.st_mode)
            and run_before_path.st_uid == os.getuid()
            and stat.S_IMODE(run_before_path.st_mode) == 0o700,
            "publication-run-root-stat",
        )
        directory = os.open(
            RUN_ROOT.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        try:
            run_before = os.fstat(directory)
            need(_same_stat(run_before, run_before_path), "publication-run-root-open-race")
            initial_raw, _, initial_ref = _proof_receipt_reference_at(
                directory,
                expected_proof_reference["sha256"],
            )
            need(
                initial_raw == expected_proof_raw
                and initial_ref == expected_proof_reference,
                "proof-receipt-changed-at-publication-entry",
            )
            source_ref = _write_new_at(
                directory,
                SUPERVISOR_SOURCE.name,
                SUPERVISOR_SOURCE,
                supervisor_raw,
                0o400,
            )
            staging_name = f".LAUNCH-RECEIPT.json.staging-{uuid.uuid4()}"
            staging_ref = _write_new_at(
                directory,
                staging_name,
                RUN_ROOT / staging_name,
                canonical(receipt),
                0o400,
            )
            _rename_no_replace(directory, staging_name, LAUNCH_RECEIPT.name)
            os.fsync(directory)
            _, launch_ref = _stable_file_at(
                directory,
                LAUNCH_RECEIPT.name,
                LAUNCH_RECEIPT,
                0o400,
                expected_sha256=staging_ref["sha256"],
            )
            need(
                set(os.listdir(directory))
                == {
                    PROOF_RECEIPT.name,
                    SUPERVISOR_SOURCE.name,
                    LAUNCH_RECEIPT.name,
                },
                "run-root-files",
            )
            final_raw, _, final_ref = _proof_receipt_reference_at(
                directory,
                expected_proof_reference["sha256"],
            )
            need(
                final_raw == expected_proof_raw
                and final_ref == expected_proof_reference,
                "proof-receipt-changed-during-publication",
            )
            os.fchmod(directory, 0o500)
            os.fsync(directory)
            sealed_raw, _, sealed_ref = _proof_receipt_reference_at(
                directory,
                expected_proof_reference["sha256"],
            )
            need(
                sealed_raw == expected_proof_raw
                and sealed_ref == expected_proof_reference,
                "proof-receipt-changed-before-publication-return",
            )
            run_after = os.fstat(directory)
            run_after_path = os.stat(
                RUN_ROOT.name,
                dir_fd=parent,
                follow_symlinks=False,
            )
            need(
                _same_stat(run_after, run_after_path)
                and run_after.st_dev == run_before.st_dev
                and run_after.st_ino == run_before.st_ino
                and stat.S_IMODE(run_after.st_mode) == 0o500,
                "publication-run-root-replaced",
            )
            os.fsync(parent)
        finally:
            os.close(directory)
        parent_after = os.fstat(parent)
        parent_after_path = os.lstat(LOCAL_ROOT)
        need(
            _same_stat(parent_before, parent_after)
            and _same_stat(parent_after, parent_after_path),
            "publication-parent-replaced",
        )
    finally:
        os.close(parent)
    return {
        "supervisor_source_sha256": source_ref["sha256"],
        "launch_receipt_sha256": launch_ref["sha256"],
        "proof_receipt_reauthenticated_inside_publication": True,
        "proof_receipt_sha256": sealed_ref["sha256"],
    }


def _identity(value: dict) -> dict:
    need("receipt_identity_sha256" not in value, "receipt-preidentified")
    result = dict(value)
    result["receipt_identity_sha256"] = sha256_bytes(canonical(value))
    return result


def _parent_cryptographic_verification(
    proof_receipt_raw: bytes,
    proof_reference: dict,
    proof_value: dict,
    verifier_reference: dict,
    vk_reference: dict,
) -> dict:
    need(
        0 < len(proof_receipt_raw) <= 4_096
        and proof_reference["sha256"] == sha256_bytes(proof_receipt_raw)
        and proof_receipt_raw == canonical(proof_value)
        and proof_value["public_inputs_decimal"] == list(EXPECTED_PUBLIC_INPUTS)
        and proof_value["proof_bytes"] == 128
        and len(bytes.fromhex(proof_value["proof_ark_compressed_hex"])) == 128
        and vk_reference["path"] == str(VK_PATH)
        and vk_reference["bytes"] == 328
        and vk_reference["sha256"] == FIXED_ARTIFACTS["independent_vk"][2]
        and verifier_reference["path"] == str(BUILD_VERIFIER_BINARY),
        "parent-verifier-input-contract",
    )
    helper = _verifier_identity_bound_helper_reference(
        verifier_reference,
        proof_receipt_raw,
    )
    runtime = _run_transient(
        VERIFY_UNIT,
        _verifier_command(verifier_reference, proof_receipt_raw),
        standard_input_data=proof_receipt_raw,
        journal_marker=PARENT_VERIFIER_MARKER,
        expected_journal_digest=proof_reference["sha256"],
    )
    need(
        runtime["journal_commitment"]["receipt_sha256"]
        == proof_reference["sha256"],
        "parent-verifier-receipt-commitment",
    )
    return {
        "contract": "kpb-frozen-w1-parent-verifier/v1",
        "verifier_binary": verifier_reference,
        "identity_bound_exec_helper": helper,
        "runtime": runtime,
        "exact_canonical_receipt_stdin_bytes": len(proof_receipt_raw),
        "exact_canonical_receipt_stdin_sha256": proof_reference["sha256"],
        "supervisor_preflight_vk_reference": vk_reference,
        "pinned_verifier_internal_vk_contract": {
            "fixed_path": str(VK_PATH),
            "exact_owned_buffer_bytes": 328,
            "expected_sha256": FIXED_ARTIFACTS["independent_vk"][2],
            "source_bound_by_reviewed_dual_binary_build": True,
        },
        "cryptographic_results_attested_by_exact_verifier_success_marker": {
            "valid_proof_accepted": True,
            "wrong_public_inputs_rejected": True,
            "mutated_proof_rejected": True,
            "receipt_sha256": proof_reference["sha256"],
        },
        "assignment_opened": False,
        "r1cs_opened": False,
        "proving_key_opened": False,
        "setup": False,
        "network_communication": False,
        "funds": False,
        "authorization": False,
    }


def run_proof() -> dict:
    need(os.geteuid() != 0, "root-refused")
    need(Path.cwd().resolve(strict=True) == REPO_ROOT, "cwd-repo-root")
    # This must be the first identity-bearing operation: stage 0 has already
    # executed this module from the reviewed sealed descriptor, not a path.
    supervisor_raw, supervisor_before, stage0 = _stage0_contract_reference()
    inbound_process_memory_boundary = _yama_ptrace_scope_reference()
    _require_bound_constants()
    tools_before = _fixed_tool_references()
    manager_environment = _manager_tool_environment()
    journal_pid_rehearsal = _journal_pid_rehearsal_reference()
    assignment = _assignment_launch_reference()
    build_before = validate_build_bundle()
    binary_reference = build_before["references"]["binary"]
    verifier_reference = build_before["references"]["parent_verifier_binary"]
    helper_reference = _identity_bound_helper_reference(binary_reference)
    artifacts_before = _fixed_artifact_references()
    _create_run_root()
    probe = _run_transient(PROBE_UNIT, _probe_command())
    probe["af_inet_af_inet6_af_unix_socket_denied_with_eperm"] = True
    probe["io_uring_setup_enter_register_denied_with_eperm"] = True
    probe["network_communication_performed"] = False
    runtime = _run_transient(
        RUN_UNIT,
        _run_command(binary_reference),
        journal_marker=PROOF_RECEIPT_MARKER,
    )
    proof_commitment = runtime["journal_commitment"]["receipt_sha256"]
    proof_raw, proof_value, proof_ref = _proof_receipt_reference(proof_commitment)
    parent_verification = _parent_cryptographic_verification(
        proof_raw,
        proof_ref,
        proof_value,
        verifier_reference,
        artifacts_before["independent_vk"],
    )
    proof_after_raw, proof_after_value, proof_after_ref = _proof_receipt_reference(
        proof_commitment
    )
    need(
        proof_after_raw == proof_raw
        and proof_after_value == proof_value
        and proof_after_ref == proof_ref,
        "proof-receipt-changed-after-parent-verification",
    )
    need(assignment == _assignment_launch_reference(), "assignment-changed-during-run")
    need(build_before == validate_build_bundle(), "build-changed-during-run")
    need(artifacts_before == _fixed_artifact_references(), "fixed-artifact-changed-during-run")
    need(tools_before == _fixed_tool_references(), "launcher-tool-changed-during-run")
    need(
        inbound_process_memory_boundary == _yama_ptrace_scope_reference(),
        "inbound-process-memory-boundary-changed-during-run",
    )
    _recheck_stage0_fds(
        supervisor_raw,
        supervisor_before,
        stage0,
    )
    final_proof_raw, final_proof_value, final_proof_ref = _proof_receipt_reference(
        proof_commitment
    )
    need(
        final_proof_raw == proof_raw
        and final_proof_value == proof_value
        and final_proof_ref == proof_ref,
        "proof-receipt-changed-before-publication",
    )
    receipt = _identity({
        "schema": RECEIPT_SCHEMA,
        "classification": CLASSIFICATION,
        "fixed_no_argument_entrypoint": True,
        "assignment_launch_receipt": assignment,
        "build_bundle": build_before,
        "binary": binary_reference,
        "launcher_tools": tools_before,
        "manager_tool_environment": manager_environment,
        "journal_pid_rehearsal": journal_pid_rehearsal,
        "identity_bound_exec_helper": helper_reference,
        "binary_exec_descriptor_bound": True,
        "sealed_memfd_exec": True,
        "proof_environment_exact_cleared": True,
        "proof_environment": list(FIXED_ENVIRONMENT),
        "proof_stdout_single_journal_commitment_stderr_null": True,
        "fixed_artifacts": artifacts_before,
        "strict_network_preflight": probe,
        "proof_runtime": runtime,
        "proof_receipt_origin_commitment": runtime["journal_commitment"],
        "proof_receipt": proof_ref,
        "parent_cryptographic_verification": parent_verification,
        "proof_sha256": proof_value["proof_sha256"],
        "proof_bytes": proof_value["proof_bytes"],
        "public_inputs_decimal": proof_value["public_inputs_decimal"],
        "supervisor_source": supervisor_before,
        "stage0": stage0,
        "host_inbound_same_uid_process_memory_boundary": (
            inbound_process_memory_boundary
        ),
        "supervisor_loaded_from_exact_sealed_reviewed_fd": True,
        "r1cs_satisfaction_checked": True,
        "proof_parameter_descriptors_opened_after_satisfaction": True,
        "historical_source_vk_opened_during_assignment_preparation": True,
        "supervisor_preflight_artifact_hashing_before_proof_process": True,
        "parent_valid_proof_accepted": parent_verification[
            "cryptographic_results_attested_by_exact_verifier_success_marker"
        ]["valid_proof_accepted"],
        "parent_wrong_public_inputs_rejected": parent_verification[
            "cryptographic_results_attested_by_exact_verifier_success_marker"
        ]["wrong_public_inputs_rejected"],
        "parent_mutated_proof_rejected": parent_verification[
            "cryptographic_results_attested_by_exact_verifier_success_marker"
        ]["mutated_proof_rejected"],
        "assignment_serialized": False,
        "secret_fingerprint_emitted": False,
        "setup": False,
        "external_ip_network_communication": False,
        "stage0_local_af_unix_system_manager_and_journal_ipc_performed": True,
        "proof_and_verifier_local_journal_stdout_ipc_performed": True,
        "funds": False,
        "testnet": False,
        "privacy_acceptance": False,
        "financial_acceptance": False,
        "production_authority": False,
        "authorization": False,
    })
    evidence = _publish(
        supervisor_raw,
        receipt,
        proof_raw,
        proof_ref,
    )
    return {
        "status": "FROZEN_W1_ROUND1_PROOF_VERIFIED",
        "classification": CLASSIFICATION,
        "run_root": str(RUN_ROOT),
        "proof_sha256": proof_value["proof_sha256"],
        "public_inputs_decimal": proof_value["public_inputs_decimal"],
        "memory_peak_bytes": runtime["properties"]["memory_peak_bytes"],
        "swap_peak_bytes": runtime["properties"]["memory_swap_peak_bytes"],
        "evidence": evidence,
        "external_ip_network_communication": False,
        "stage0_local_af_unix_system_manager_and_journal_ipc_performed": True,
        "proof_and_verifier_local_journal_stdout_ipc_performed": True,
        "funds": False,
        "testnet": False,
        "authorization": False,
    }


def main(arguments: list[str] | None = None) -> int:
    if arguments is None:
        arguments = sys.argv[1:]
    try:
        need(type(arguments) is list and not arguments, "arguments-not-accepted")
        result = run_proof()
    except (Refused, FileExistsError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "REFUSED", "classification": CLASSIFICATION, "reason": str(error), "authorization": False}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


def _entrypoint() -> int:
    if sys.argv[1:2] == ["--stage0-render"]:
        try:
            _run_stage0_renderer(sys.argv[1:])
        except (Refused, OSError, subprocess.SubprocessError):
            return 70
        return 70
    return main()


if __name__ == "__main__":
    raise SystemExit(_entrypoint())
