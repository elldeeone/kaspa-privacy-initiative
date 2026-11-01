#!/usr/bin/env python3
"""Inert direct-bwrap supervisor for the fixed W1 prover and verifier.

This is a create-new replacement surface.  It does not import the historical
supervisor or any repository module.  It cannot execute in the checked-in
state: every independently reviewed source, executable, artifact, seccomp and
cgroup binding is deliberately ``None``.

The eventual execution contract is deliberately narrower than the historical
systemd-unit design:

* an external ``python -I -S -B -c`` bootstrap authenticates this source before
  it can be imported, seals source and contract memfds, and execs fd 3;
* that first sealed Python enters and authenticates the swap-disabled parent
  cgroup, seals an exact transition receipt, and execs fd 3 a second time;
  only the second sealed Python may read or hash private experiment content;
* the exact reviewed Debian 0.13.1-1 ``/usr/bin/bwrap`` ELF, loader closure,
  loaded mappings and AppArmor enforce/source closure are authenticated (the
  installed Ubuntu 0.11.1-1ubuntu0.3 build is refused);
* the payload root is synthetic.  Executables, their exact runtime closure,
  and private artifacts are immutable descriptor mounts;
* explicit user, IPC, PID, network, UTS and cgroup namespaces are mandatory;
* an architecture-checking sealed seccomp filter denies networking, descriptor
  relays, kernel attack surfaces and namespace/mount escape syscalls;
* the parent owns bounded pipes, sealed memfds, pidfds, the start barrier, and
  all publication.  Success requires exact wait4, EOF and zero descendants;
* the supervisor enters a trusted pre-existing parent cgroup enforcing
  ``memory.swap.max=0`` before private reads; workers use its distinct nested
  pre-existing kill leaf.  This file never creates or configures a cgroup;
* the assignment launch receipt and the actual assignment receipt are reopened
  before proof and after verification; and
* the verifier sandbox receives no proving key, R1CS, decode receipt or
  assignment.  Its only private inputs are the fixed VK mount and the exact
  canonical proof receipt on stdin.

The frozen experiment's threat boundary is one trusted host.  The manager,
same-UID processes, privileged host processes, host swap configuration and
physical host remain in its TCB.  These controls isolate the pinned payload;
they do not claim protection from a hostile same-UID or root host observer.

Even after binding and a successful run, the result is test-only evidence.  It
is not proof of cryptographic correctness, privacy, side-channel resistance,
financial safety, production readiness, or authorization to use funds.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import signal
import stat
import struct
import sys
import time
import uuid


SCHEMA = "kpb-frozen-w1-bwrap-supervisor/v1"
STAGE0_SCHEMA = "kpb-frozen-w1-bwrap-stage0/v1"
STAGE1_TRANSITION_SCHEMA = "kpb-frozen-w1-bwrap-stage1-transition/v1"
PUBLICATION_SCHEMA = "kpb-frozen-w1-bwrap-publication/v1"
PROOF_SCHEMA = "kpb-frozen-w1-round1-proof/v1"
CLASSIFICATION = "OFFLINE_SYNTHETIC_UNBACKED_FIXED_W1_GROTH16_PROOF_EVIDENCE_ONLY"

REPO_ROOT = Path("/home/luke/projects/kpi-intensive-2026-10-22/continuation")
HERE = REPO_ROOT / "poc/local-private-payment/private_batch_trial"
SOURCE_PATH = HERE / "run_frozen_w1_proof_bwrap.py"
PYTHON = Path("/usr/bin/python3.14")
EXTERNAL_STAGE0_AUTHORITY = Path(
    "/etc/kaspa-privacy/w1-bwrap-stage0-authority.json"
)
APPROVED_BWRAP_PATH = Path("/usr/bin/bwrap")
REJECTED_HOST_BWRAP = APPROVED_BWRAP_PATH
REJECTED_HOST_BWRAP_PACKAGE = "0.11.1-1ubuntu0.3"
# The frozen authority is deliberately one exact Debian amd64 artifact at the
# one path covered by the separately reviewed host AppArmor policy.  A custom
# executable path is not an alternate authority.
FIXED_DEBIAN_BWRAP_PACKAGE = "0.13.1-1"
FIXED_DEBIAN_BWRAP_VERSION = (0, 13, 1)
FIXED_DEBIAN_BWRAP_PACKAGE_SHA256 = (
    "e02257507a93bbf4efc682873378967de1692e8794c09a04be801f4001d9cb58"
)
FIXED_DEBIAN_BWRAP_ELF_SHA256 = (
    "263a40b4dca7b24d47c05bf2f64d05093dbefa8577c556c9a185040a173bf7b8"
)
FIXED_DEBIAN_BWRAP_ELF_BYTES = 84_352
FIXED_DEBIAN_BWRAP_BUILD_ID = "510ce1d9d24214068dbf282a1a4eeda4a304eced"
FIXED_DEBIAN_BWRAP_PT_INTERP = "/lib64/ld-linux-x86-64.so.2"
FIXED_DEBIAN_BWRAP_DT_NEEDED = (
    "libselinux.so.1",
    "libcap.so.2",
    "libc.so.6",
)
FIXED_DEBIAN_BWRAP_DEPENDENCY_GRAPH = {
    "/usr/bin/bwrap": list(FIXED_DEBIAN_BWRAP_DT_NEEDED),
    "libselinux.so.1": ["libpcre2-8.so.0", "libc.so.6", "ld-linux-x86-64.so.2"],
    "libcap.so.2": ["libc.so.6"],
    "libc.so.6": ["ld-linux-x86-64.so.2"],
    "libpcre2-8.so.0": ["libc.so.6"],
    "ld-linux-x86-64.so.2": [],
}
FIXED_DEBIAN_BWRAP_CLOSURE_NAMES = (
    "PT_INTERP",
    *FIXED_DEBIAN_BWRAP_DT_NEEDED,
    "libpcre2-8.so.0",
)
FIXED_BWRAP_APPARMOR_PROFILE = "bwrap"
FIXED_BWRAP_APPARMOR_LABEL = "bwrap (enforce)"
FIXED_BWRAP_APPARMOR_ROOT = "/etc/apparmor.d/usr.bin.bwrap"
PRIVATE_OUTPUT_ROOT = Path(
    "/home/luke/projects/kpi-intensive-2026-10-22/"
    "private-batch-w1-bwrap-proof-private-20261101-01"
)
FINAL_OUTPUT = PRIVATE_OUTPUT_ROOT / "verified-w1-proof"

LOCAL_ROOT = REPO_ROOT / ".local"
R1CS_PATH = LOCAL_ROOT / "r1cs-aggregate-export-c023-20261029-02/aggregate.r1cs"
DECODED_PK_PATH = (
    LOCAL_ROOT
    / "private-batch-w1-decoded-pk-20261029-01/AGGREGATE-PK.bin"
)
DECODE_RECEIPT_PATH = (
    LOCAL_ROOT
    / "private-batch-w1-decoded-pk-20261029-01/DECODE-RECEIPT.json"
)
COMPRESSED_PK_PATH = (
    LOCAL_ROOT
    / "private-batch-stock-setup-20261028-02/artifact/AGGREGATE-PK.bin.gz"
)
VK_PATH = (
    LOCAL_ROOT
    / "private-batch-stock-setup-20261028-02/artifact/AGGREGATE-VK.bin"
)

EXPECTED_PUBLIC_INPUTS = (
    "13917591994071772114488105153423377273",
    "33826997814916552742078018202966096202",
)
EXPECTED_ARTIFACTS = {
    "r1cs": {
        "path": str(R1CS_PATH),
        "bytes": 2_840_345_392,
        "sha256": "cc76d603d0cb184f4e43b99d3af9f215274c0a67bdbec28ed435046c2b9c42bc",
        "mode_octal": "0400",
    },
    "decoded_pk": {
        "path": str(DECODED_PK_PATH),
        "bytes": 2_608_842_576,
        "sha256": "170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945",
        "mode_octal": "0400",
    },
    "decode_receipt": {
        "path": str(DECODE_RECEIPT_PATH),
        "bytes": 1_810,
        "sha256": "023171d9ff4328e9fd0653f0a9c7455f11c9da4600e0835231b439b79ba6c40c",
        "mode_octal": "0400",
    },
    "compressed_pk": {
        "path": str(COMPRESSED_PK_PATH),
        "bytes": 1_749_414_110,
        "sha256": "4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff",
        "mode_octal": "0444",
    },
    "vk": {
        "path": str(VK_PATH),
        "bytes": 328,
        "sha256": "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102",
        "mode_octal": "0444",
    },
}

# No checked-in value below is an execution authority.  A future binding must
# be an explicit source edit followed by a fresh independent review.  Keeping
# these as separate gates prevents one approved hash from silently authorizing
# a different trust boundary.
REVIEWED_SUPERVISOR_SOURCE_BINDING: dict | None = None
REVIEWED_EXTERNAL_STAGE0_SOURCE_SHA256: str | None = None
REVIEWED_WORKER_SOURCE_SHA256: str | None = None
REVIEWED_BWRAP_BINDING: dict | None = None
REVIEWED_BUILD_BINDING: dict | None = None
REVIEWED_RUNTIME_CLOSURE: tuple[dict, ...] | None = None
REVIEWED_ARTIFACT_BINDINGS: dict | None = None
REVIEWED_ASSIGNMENT_BINDING: dict | None = None
REVIEWED_SECCOMP_BINDINGS: dict | None = None
REVIEWED_CGROUP_BINDING: dict | None = None
REVIEWED_PUBLICATION_BINDING: dict | None = None

REVIEW_GATE_NAMES = (
    "supervisor_source",
    "external_stage0",
    "worker_source",
    "bwrap",
    "build",
    "runtime_closure",
    "artifacts",
    "assignment",
    "seccomp",
    "cgroup",
    "publication",
)

MANDATORY_NAMESPACE_FLAGS = (
    "--unshare-all",
    "--unshare-user",
    "--disable-userns",
    "--assert-userns-disabled",
    "--unshare-ipc",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-uts",
    "--unshare-cgroup",
    "--as-pid-1",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
)
FORBIDDEN_BWRAP_OPTIONS = frozenset(
    {
        "--share-net",
        "--bind",
        "--bind-try",
        "--dev-bind",
        "--dev-bind-try",
        "--ro-bind",
        "--ro-bind-try",
        "--overlay",
        "--tmp-overlay",
        "--userns",
        "--userns2",
        "--pidns",
    }
)
NAMESPACE_NAMES = ("mnt", "user", "ipc", "pid", "net", "uts", "cgroup")

SANDBOX_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
}
STAGE0_ENVIRONMENT = dict(SANDBOX_ENVIRONMENT, KPB_W1_STAGE0="1")
STAGE2_ENVIRONMENT = dict(SANDBOX_ENVIRONMENT, KPB_W1_STAGE2="1")

PROOF_PRIVATE_LABELS = frozenset(
    {"r1cs", "decoded_pk", "decode_receipt", "compressed_pk", "vk"}
)
VERIFIER_PRIVATE_LABELS = frozenset({"vk"})
PROOF_RECEIPT_MARKER = b"FROZEN_W1_PROOF_RECEIPT_SHA256="
VERIFIED_MARKER = b"FROZEN_W1_VERIFIED_PROOF_RECEIPT_SHA256="
WORKER_READY_PREFIX = b"KPB-W1-WORKER-READY:"
FRAME_MAGIC = b"KPB-W1-PROOF-RECEIPT\x00\x01"
MAX_PROOF_RECEIPT_BYTES = 4_096
MAX_PROOF_STDOUT_BYTES = len(FRAME_MAGIC) + 4 + MAX_PROOF_RECEIPT_BYTES
MAX_VERIFIER_STDOUT_BYTES = len(VERIFIED_MARKER) + 64 + 1
MAX_STATUS_BYTES = 64 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_ASSIGNMENT_RECEIPT_BYTES = 256 * 1024
MAX_ASSIGNMENT_LAUNCH_BYTES = 256 * 1024
MIN_MEMORY_MAX_BYTES = 20 * 1024**3
MIN_PIDS_MAX = 256
MAX_PIDS_MAX = 4_096
PRESTART_DEADLINE_SECONDS = 30.0
POST_EXIT_DRAIN_SECONDS = 5.0
# A live proving computation has no elapsed-time abort.  Only an explicit
# owner cancellation signal may terminate it; operational timing is evidence,
# never a reason to invalidate an otherwise live trial.
LIVE_PROOF_DEADLINE_SECONDS = None
PR_SET_DUMPABLE = 4
PR_SET_PDEATHSIG = 1

F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
FS_IOC_MEASURE_VERITY = 0xC0046686
FS_VERITY_HASH_ALG_SHA256 = 1

AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000

# Linux x86_64 syscall numbers.  clone/clone3 are intentionally not denied:
# the reviewed prover may create worker threads.  Descendants are contained and
# must be absent at success by the cgroup and PID-namespace evidence.
DENIED_SYSCALLS_X86_64 = frozenset(
    {
        # Network and local socket relays.
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        288, 299, 307,
        # ptrace, process_vm, kcmp, open-by-handle and pidfd relay/control.
        101, 303, 304, 310, 311, 312, 424, 434, 438,
        # add_key, request_key, keyctl, perf, bpf, userfaultfd and io_uring.
        248, 249, 250, 298, 321, 323, 425, 426, 427,
        # Namespace and mount mutation after bwrap has installed the filter.
        155, 165, 166, 272, 308, 428, 429, 430, 431, 432, 442,
    }
)


class Refused(RuntimeError):
    """One opaque, fail-closed boundary refusal category."""


class OwnerCancelled(Refused):
    """An explicit SIGINT/SIGTERM owner cancellation, never an elapsed timer."""


def need(value: bool, category: str) -> None:
    if not value:
        raise Refused(category)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(byte in "0123456789abcdef" for byte in value)
    )


def is_git_object_id(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(byte in "0123456789abcdef" for byte in value)
    )


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Refused("json-duplicate-key")
        result[key] = value
    return result


def decode_canonical_json(raw: bytes, *, category: str) -> object:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                Refused("json-nonfinite")
            ),
        )
    except Refused:
        raise
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise Refused(f"{category}-json") from error
    need(canonical(value) == raw, f"{category}-noncanonical")
    return value


def decode_unique_json(raw: bytes, *, category: str) -> object:
    """Decode external JSON while rejecting duplicate keys and nonfinite values."""
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                Refused("json-nonfinite")
            ),
        )
    except Refused:
        raise
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise Refused(f"{category}-json") from error


def _identity_tuple(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _ref_from_stat(path: str, value: os.stat_result, digest: str) -> dict:
    return {
        "path": path,
        "device": value.st_dev,
        "inode": value.st_ino,
        "bytes": value.st_size,
        "sha256": digest,
        "mode_octal": f"{stat.S_IMODE(value.st_mode):04o}",
        "owner_uid": value.st_uid,
        "owner_gid": value.st_gid,
        "link_count": value.st_nlink,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _validate_file_ref_shape(reference: object, *, category: str) -> dict:
    keys = {
        "path", "device", "inode", "bytes", "sha256", "mode_octal",
        "owner_uid", "owner_gid", "link_count", "mtime_ns", "ctime_ns",
    }
    need(type(reference) is dict and set(reference) == keys, f"{category}-ref-shape")
    assert isinstance(reference, dict)
    need(
        type(reference["path"]) is str
        and PurePosixPath(reference["path"]).is_absolute()
        and all(
            type(reference[key]) is int and reference[key] >= 0
            for key in (
                "device", "inode", "bytes", "owner_uid", "owner_gid",
                "link_count", "mtime_ns", "ctime_ns",
            )
        )
        and reference["link_count"] == 1
        and is_sha256(reference["sha256"])
        and type(reference["mode_octal"]) is str
        and len(reference["mode_octal"]) == 4,
        f"{category}-ref-values",
    )
    return reference


def stable_open(reference: dict, *, max_bytes: int | None = None) -> tuple[int, dict]:
    """Open one exact regular file without following or later reopening a path."""
    reference = _validate_file_ref_shape(reference, category="stable-file")
    path = reference["path"]
    before_path = os.lstat(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode), "stable-file-not-regular")
        need(before.st_nlink == 1, "stable-file-link-count")
        if max_bytes is not None:
            need(before.st_size <= max_bytes, "stable-file-size-bound")
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            need(bool(block), "stable-file-short-read")
            digest.update(block)
            offset += len(block)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        observed = _ref_from_stat(path, after, digest.hexdigest())
        need(
            _identity_tuple(before_path)
            == _identity_tuple(before)
            == _identity_tuple(after)
            == _identity_tuple(after_path),
            "stable-file-raced",
        )
        need(observed == reference, "stable-file-substitution")
        return descriptor, observed
    except BaseException:
        os.close(descriptor)
        raise


def stable_read(reference: dict, *, max_bytes: int) -> tuple[bytes, dict]:
    descriptor, observed = stable_open(reference, max_bytes=max_bytes)
    try:
        raw = os.pread(descriptor, observed["bytes"], 0)
        need(len(raw) == observed["bytes"], "stable-read-short")
        return raw, observed
    finally:
        os.close(descriptor)


def _pread_exact(descriptor: int, offset: int, length: int, size: int) -> bytes:
    need(
        type(offset) is int
        and type(length) is int
        and 0 <= offset <= size
        and 0 <= length <= size - offset,
        "elf-read-bounds",
    )
    raw = os.pread(descriptor, length, offset)
    need(len(raw) == length, "elf-short-read")
    return raw


def parse_elf_descriptor(descriptor: int) -> dict:
    """Derive x86-64 build ID, PT_INTERP and DT_NEEDED from opened bytes."""
    value = os.fstat(descriptor)
    size = value.st_size
    need(stat.S_ISREG(value.st_mode) and 64 <= size <= 256 * 1024**2, "elf-file")
    header = struct.unpack(
        "<16sHHIQQQIHHHHHH", _pread_exact(descriptor, 0, 64, size)
    )
    ident = header[0]
    need(
        ident[:4] == b"\x7fELF"
        and ident[4] == 2
        and ident[5] == 1
        and ident[6] == 1
        and header[2] == 62
        and header[3] == 1,
        "elf-x86-64-little-endian",
    )
    phoff = header[5]
    phentsize = header[9]
    phnum = header[10]
    need(phentsize == 56 and 0 < phnum <= 1024, "elf-program-header-shape")
    program_headers: list[tuple[int, ...]] = []
    for index in range(phnum):
        raw = _pread_exact(
            descriptor, phoff + index * phentsize, phentsize, size
        )
        program_headers.append(struct.unpack("<IIQQQQQQ", raw))

    interpreter: str | None = None
    build_ids: list[str] = []
    dynamic: tuple[int, ...] | None = None
    loads: list[tuple[int, ...]] = []
    for item in program_headers:
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = item
        if p_type == 1:
            loads.append(item)
        elif p_type == 3:
            raw = _pread_exact(descriptor, p_offset, p_filesz, size)
            need(raw.endswith(b"\x00") and raw.count(b"\x00") == 1, "elf-interpreter")
            try:
                interpreter = raw[:-1].decode("ascii")
            except UnicodeDecodeError as error:
                raise Refused("elf-interpreter") from error
        elif p_type == 2:
            need(dynamic is None, "elf-dynamic-duplicate")
            dynamic = item
        elif p_type == 4:
            raw = _pread_exact(descriptor, p_offset, p_filesz, size)
            cursor = 0
            while cursor < len(raw):
                if not any(raw[cursor:]):
                    break
                need(len(raw) - cursor >= 12, "elf-note-header")
                namesz, descsz, note_type = struct.unpack_from("<III", raw, cursor)
                cursor += 12
                name_end = cursor + namesz
                need(name_end <= len(raw), "elf-note-name")
                name = raw[cursor:name_end]
                cursor = (name_end + 3) & ~3
                desc_end = cursor + descsz
                need(desc_end <= len(raw), "elf-note-description")
                description = raw[cursor:desc_end]
                cursor = (desc_end + 3) & ~3
                if note_type == 3 and name.rstrip(b"\x00") == b"GNU":
                    build_ids.append(description.hex())

    needed_offsets: list[int] = []
    strtab_address: int | None = None
    strtab_size: int | None = None
    if dynamic is not None:
        _type, _flags, p_offset, _vaddr, _paddr, p_filesz, _memsz, _align = dynamic
        need(p_filesz % 16 == 0, "elf-dynamic-size")
        for offset in range(0, p_filesz, 16):
            tag, entry = struct.unpack(
                "<qQ", _pread_exact(descriptor, p_offset + offset, 16, size)
            )
            if tag == 0:
                break
            if tag == 1:
                needed_offsets.append(entry)
            elif tag == 5:
                strtab_address = entry
            elif tag == 10:
                strtab_size = entry
    needed: list[str] = []
    if needed_offsets:
        need(
            strtab_address is not None
            and strtab_size is not None
            and 0 < strtab_size <= 16 * 1024**2,
            "elf-dynamic-string-table",
        )
        string_offset: int | None = None
        for load in loads:
            _type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = load
            if p_vaddr <= strtab_address < p_vaddr + p_filesz:
                string_offset = p_offset + (strtab_address - p_vaddr)
                break
        need(string_offset is not None, "elf-dynamic-string-mapping")
        string_table = _pread_exact(
            descriptor, string_offset, strtab_size, size
        )
        for offset in needed_offsets:
            need(offset < len(string_table), "elf-needed-offset")
            end = string_table.find(b"\x00", offset)
            need(end > offset, "elf-needed-string")
            try:
                needed.append(string_table[offset:end].decode("ascii"))
            except UnicodeDecodeError as error:
                raise Refused("elf-needed-string") from error
    need(len(build_ids) == 1 and is_git_object_id(build_ids[0]), "elf-build-id")
    return {
        "build_id": build_ids[0],
        "pt_interp": interpreter,
        "dt_needed": needed,
    }


def sealed_memfd(name: str, raw: bytes) -> int:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
        need(fcntl.fcntl(descriptor, F_GET_SEALS) == REQUIRED_SEALS, "memfd-seals")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def sealed_copy(reference: dict, *, name: str, max_bytes: int) -> tuple[int, dict]:
    """Copy one reviewed executable into an immutable sealed descriptor."""
    source, observed = stable_open(reference, max_bytes=max_bytes)
    destination = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        digest = hashlib.sha256()
        offset = 0
        while offset < observed["bytes"]:
            block = os.pread(
                source,
                min(1024 * 1024, observed["bytes"] - offset),
                offset,
            )
            need(bool(block), "sealed-copy-short-read")
            digest.update(block)
            written = 0
            while written < len(block):
                written += os.write(destination, block[written:])
            offset += len(block)
        need(
            offset == observed["bytes"]
            and digest.hexdigest() == observed["sha256"],
            "sealed-copy-source-drift",
        )
        os.fchmod(destination, 0o500)
        fcntl.fcntl(destination, F_ADD_SEALS, REQUIRED_SEALS)
        need(
            fcntl.fcntl(destination, F_GET_SEALS) == REQUIRED_SEALS
            and stat.S_IMODE(os.fstat(destination).st_mode) == 0o500,
            "sealed-copy-seals",
        )
        os.lseek(destination, 0, os.SEEK_SET)
        return destination, observed
    except BaseException:
        os.close(destination)
        raise
    finally:
        os.close(source)


def measure_fsverity(descriptor: int) -> str:
    """Return the kernel-measured SHA-256 fs-verity descriptor digest."""
    buffer = bytearray(struct.pack("HH", FS_VERITY_HASH_ALG_SHA256, 32) + b"\x00" * 32)
    try:
        fcntl.ioctl(descriptor, FS_IOC_MEASURE_VERITY, buffer, True)
    except OSError as error:
        raise Refused("fsverity-measurement-required") from error
    algorithm, size = struct.unpack("HH", buffer[:4])
    need(
        algorithm == FS_VERITY_HASH_ALG_SHA256 and size == 32,
        "fsverity-algorithm",
    )
    return bytes(buffer[4:36]).hex()


def open_immutable_artifact(binding: object, *, category: str) -> tuple[int, dict]:
    need(
        type(binding) is dict
        and set(binding) == {"file", "fsverity"}
        and type(binding["fsverity"]) is dict
        and set(binding["fsverity"])
        == {"enabled", "algorithm", "descriptor_digest"},
        f"{category}-immutable-binding",
    )
    reference = _validate_file_ref_shape(binding["file"], category=category)
    verity = binding["fsverity"]
    need(
        verity["enabled"] is True
        and verity["algorithm"] == "sha256"
        and is_sha256(verity["descriptor_digest"]),
        f"{category}-fsverity-binding",
    )
    descriptor, observed = stable_open(reference)
    try:
        need(
            measure_fsverity(descriptor) == verity["descriptor_digest"],
            f"{category}-fsverity-drift",
        )
        return descriptor, observed
    except BaseException:
        os.close(descriptor)
        raise


def read_sealed_fd(descriptor: int, *, max_bytes: int, expected_sha256: str) -> bytes:
    need(fcntl.fcntl(descriptor, F_GET_SEALS) == REQUIRED_SEALS, "sealed-fd-seals")
    value = os.fstat(descriptor)
    need(stat.S_ISREG(value.st_mode) and value.st_size <= max_bytes, "sealed-fd-shape")
    raw = os.pread(descriptor, value.st_size, 0)
    need(len(raw) == value.st_size, "sealed-fd-short")
    need(sha256_bytes(raw) == expected_sha256, "sealed-fd-hash")
    return raw


def _live_fds() -> set[int]:
    result: set[int] = set()
    for raw in os.listdir("/proc/self/fd"):
        descriptor = int(raw)
        try:
            os.fstat(descriptor)
        except OSError as error:
            need(error.errno == errno.EBADF, "fd-enumeration")
        else:
            result.add(descriptor)
    return result


EXTERNAL_STAGE0_SOURCE = r'''import fcntl,hashlib,json,os,stat,sys
F_ADD_SEALS=getattr(fcntl,"F_ADD_SEALS",1033); F_GET_SEALS=getattr(fcntl,"F_GET_SEALS",1034)
SEALS=(getattr(fcntl,"F_SEAL_SEAL",1)|getattr(fcntl,"F_SEAL_SHRINK",2)|getattr(fcntl,"F_SEAL_GROW",4)|getattr(fcntl,"F_SEAL_WRITE",8))
ENV={"HOME":"/nonexistent","PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","TZ":"UTC","PYTHONDONTWRITEBYTECODE":"1","KPB_W1_STAGE0":"1"}
AUTH="/etc/kaspa-privacy/w1-bwrap-stage0-authority.json"
def no(ok,code):
    if not ok: raise SystemExit(code)
def pairs(rows):
    out={}
    for key,value in rows:
        no(key not in out,11); out[key]=value
    return out
def canon(value): return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def memfd(name,raw):
    fd=os.memfd_create(name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING); offset=0
    while offset<len(raw): offset+=os.write(fd,raw[offset:])
    fcntl.fcntl(fd,F_ADD_SEALS,SEALS); no(fcntl.fcntl(fd,F_GET_SEALS)==SEALS,12); os.lseek(fd,0,0); return fd
def ident(value): return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
no(len(sys.argv)==1 and dict(os.environ)==ENV,13)
authority_before_path=os.lstat(AUTH); authority_fd=os.open(AUTH,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); authority_before=os.fstat(authority_fd)
no(stat.S_ISREG(authority_before.st_mode) and authority_before.st_uid==0 and authority_before.st_gid==0 and authority_before.st_nlink==1 and stat.S_IMODE(authority_before.st_mode)&0o022==0 and 0<authority_before.st_size<=1048576,14)
raw=os.pread(authority_fd,authority_before.st_size,0); authority_after=os.fstat(authority_fd); authority_after_path=os.lstat(AUTH); os.close(authority_fd)
no(len(raw)==authority_before.st_size and ident(authority_before_path)==ident(authority_before)==ident(authority_after)==ident(authority_after_path),15)
try: contract=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:no(False,16))
except BaseException: raise SystemExit(15)
no(canon(contract)==raw,17); contract_sha=hashlib.sha256(raw).hexdigest()
no(contract.get("schema")=="kpb-frozen-w1-bwrap-stage0/v1" and contract.get("external_authority_path")==AUTH and contract.get("externally_authenticated") is True and contract.get("mainnet") is False and contract.get("funds") is False,18)
ref=contract.get("supervisor_source"); no(type(ref) is dict and ref.get("path") and ref.get("sha256"),18)
before_path=os.lstat(ref["path"]); fd=os.open(ref["path"],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd)
no(stat.S_ISREG(before.st_mode) and before.st_nlink==1,19); digest=hashlib.sha256(); blocks=[]; offset=0
while offset<before.st_size:
    block=os.pread(fd,min(1048576,before.st_size-offset),offset); no(bool(block),20); blocks.append(block); digest.update(block); offset+=len(block)
after=os.fstat(fd); after_path=os.lstat(ref["path"])
no(ident(before_path)==ident(before)==ident(after)==ident(after_path),21)
no(offset==ref["bytes"] and digest.hexdigest()==ref["sha256"] and before.st_dev==ref["device"] and before.st_ino==ref["inode"] and before.st_mtime_ns==ref["mtime_ns"] and before.st_ctime_ns==ref["ctime_ns"],22)
source_fd=memfd("kpb-w1-bwrap-supervisor",b"".join(blocks)); contract_fd=memfd("kpb-w1-bwrap-contract",raw); os.close(fd)
os.dup2(source_fd,3); os.dup2(contract_fd,4)
for keep in (3,4): fcntl.fcntl(keep,fcntl.F_SETFD,fcntl.fcntl(keep,fcntl.F_GETFD)&~fcntl.FD_CLOEXEC)
for raw_fd in os.listdir("/proc/self/fd"):
    candidate=int(raw_fd)
    if candidate>4:
        try: os.close(candidate)
        except OSError: pass
os.execve("/usr/bin/python3.14",["/usr/bin/python3.14","-I","-S","-B","/proc/self/fd/3","--sealed-stage1",contract_sha],ENV)
'''


def external_stage0_template() -> dict:
    """Return a non-executing template for an independently authenticated launcher."""
    return {
        "schema": STAGE0_SCHEMA,
        "python": str(PYTHON),
        "argv": [str(PYTHON), "-I", "-S", "-B", "-c", EXTERNAL_STAGE0_SOURCE],
        "environment": STAGE0_ENVIRONMENT,
        "root_owned_authority": str(EXTERNAL_STAGE0_AUTHORITY),
        "external_stage0_source_sha256": sha256_bytes(EXTERNAL_STAGE0_SOURCE.encode()),
        "root_owned_canonical_contract_required": True,
        "executed": False,
        "authorization": False,
    }


def _read_external_stage0_authority() -> tuple[bytes, dict]:
    path = str(EXTERNAL_STAGE0_AUTHORITY)
    before_path = os.lstat(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_gid == 0
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) & 0o022 == 0
            and 0 < before.st_size <= 1024 * 1024,
            "stage0-authority-permissions",
        )
        raw = os.pread(descriptor, before.st_size, 0)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        need(
            len(raw) == before.st_size
            and _identity_tuple(before_path)
            == _identity_tuple(before)
            == _identity_tuple(after)
            == _identity_tuple(after_path),
            "stage0-authority-raced",
        )
    finally:
        os.close(descriptor)
    value = decode_canonical_json(raw, category="stage0-authority")
    need(type(value) is dict, "stage0-authority-shape")
    return raw, value


def _validate_sealed_source_contract(
    contract_sha256: str,
    *,
    environment: dict[str, str],
    live_fds: set[int],
    category: str,
) -> dict:
    """Authenticate the sealed source and contract at either exec boundary."""
    need(dict(os.environ) == environment, f"{category}-environment")
    need(_live_fds() == live_fds, f"{category}-fd-allowlist")
    contract_raw = read_sealed_fd(
        4, max_bytes=1024 * 1024, expected_sha256=contract_sha256
    )
    contract = decode_canonical_json(contract_raw, category="stage0-contract")
    authority_raw, authority = _read_external_stage0_authority()
    need(type(contract) is dict, "stage0-contract-shape")
    assert isinstance(contract, dict)
    need(
        authority == contract and authority_raw == contract_raw,
        "stage0-external-authority-binding",
    )
    source_ref = _validate_file_ref_shape(
        contract.get("supervisor_source"), category="stage0-source"
    )
    source_raw = read_sealed_fd(
        3, max_bytes=4 * 1024 * 1024, expected_sha256=source_ref["sha256"]
    )
    source_stat = os.fstat(3)
    need(
        contract.get("schema") == STAGE0_SCHEMA
        and contract.get("external_authority_path")
        == str(EXTERNAL_STAGE0_AUTHORITY)
        and contract.get("externally_authenticated") is True
        and contract.get("mainnet") is False
        and contract.get("funds") is False
        and contract.get("external_stage0_source_sha256")
        == sha256_bytes(EXTERNAL_STAGE0_SOURCE.encode())
        and len(source_raw) == source_ref["bytes"]
        and (source_stat.st_dev, source_stat.st_ino)
        != (source_ref["device"], source_ref["inode"]),
        "stage0-contract-binding",
    )
    return contract


def validate_stage0_entry(contract_sha256: str) -> dict:
    """Authenticate the external bootstrap's two sealed descriptors."""
    return _validate_sealed_source_contract(
        contract_sha256,
        environment=STAGE0_ENVIRONMENT,
        live_fds={0, 1, 2, 3, 4},
        category="stage0",
    )


WORKER_SOURCE = r'''import errno,hashlib,json,os,resource,selectors,signal,socket,stat,struct,subprocess,sys
MAGIC=b"KPB-W1-PROOF-RECEIPT\x00\x01"; PM=b"FROZEN_W1_PROOF_RECEIPT_SHA256="; VM=b"FROZEN_W1_VERIFIED_PROOF_RECEIPT_SHA256="
MAX=4096; ENV={"HOME":"/nonexistent","PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","TZ":"UTC","PYTHONDONTWRITEBYTECODE":"1"}
def die(code): os._exit(code)
def need(ok,code):
    if not ok: die(code)
def pairs(rows):
    out={}
    for key,value in rows: need(key not in out,30); out[key]=value
    return out
def canon(value): return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def fds():
    out=set()
    for raw in os.listdir("/proc/self/fd"):
        try: os.fstat(int(raw)); out.add(int(raw))
        except OSError: pass
    return out
def status():
    rows={}
    for line in open("/proc/self/status",encoding="ascii"):
        if ":" in line:
            key,value=line.split(":",1); rows[key]=value.strip()
    need(all(rows.get(key)=="0000000000000000" for key in ("CapInh","CapPrm","CapEff","CapBnd","CapAmb")),31)
    need(rows.get("NoNewPrivs")=="1" and rows.get("Seccomp")=="2" and rows.get("Seccomp_filters")=="1",32)
    return rows
def denied(call):
    try:
        value=call()
    except OSError as error:
        return error.errno==errno.EPERM
    try:
        if hasattr(value,"close"): value.close()
        elif type(value) is int: os.close(value)
    except OSError: pass
    return False
def exact(stream,count):
    out=b""
    while len(out)<count:
        block=stream.read(count-len(out)); need(bool(block),42); out+=block
    return out
def bounded(argv,input_raw,stdout_limit):
    child=subprocess.Popen(argv,stdin=subprocess.PIPE if input_raw is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,env=ENV)
    if input_raw is not None:
        try: child.stdin.write(input_raw); child.stdin.close()
        except BrokenPipeError: pass
    streams={child.stdout:(bytearray(),stdout_limit),child.stderr:(bytearray(),65536)}; selector=selectors.DefaultSelector()
    for stream in streams: os.set_blocking(stream.fileno(),False); selector.register(stream,selectors.EVENT_READ)
    while selector.get_map():
        for key,_ in selector.select():
            block=os.read(key.fileobj.fileno(),65536)
            if not block: selector.unregister(key.fileobj); key.fileobj.close(); continue
            target,limit=streams[key.fileobj]; target.extend(block)
            if len(target)>limit:
                child.kill(); child.wait(); die(33)
    code=child.wait(); return code,bytes(streams[child.stdout][0]),bytes(streams[child.stderr][0])
def receipt(raw):
    need(0<len(raw)<=MAX,34)
    try: value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:die(35))
    except BaseException: die(36)
    need(canon(value)==raw and type(value) is dict,37)
    need(value.get("schema")=="kpb-frozen-w1-round1-proof/v1" and value.get("public_inputs_decimal")==["13917591994071772114488105153423377273","33826997814916552742078018202966096202"],38)
    proof=value.get("proof_ark_compressed_hex"); need(type(proof) is str and len(proof)==256 and proof==proof.lower(),39)
    try: proof_raw=bytes.fromhex(proof)
    except ValueError: die(40)
    need(len(proof_raw)==128 and value.get("proof_bytes")==128 and value.get("proof_sha256")==hashlib.sha256(proof_raw).hexdigest(),41)
    return hashlib.sha256(raw).hexdigest()
need(len(sys.argv)>=3 and dict(os.environ)==ENV and fds()=={0,1,2},20); observed=status(); resource.setrlimit(resource.RLIMIT_CORE,(0,0)); resource.setrlimit(resource.RLIMIT_NOFILE,(1024,1024))
role=sys.argv[1]; binary=sys.argv[2]; need(role in ("proof","verify"),27)
probes={"getpid":os.getpid()==1,"pidfd_open":denied(lambda:os.pidfd_open(os.getpid(),0)),"socket":denied(lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM))}; need(all(probes.values()),46)
ready={"schema":"kpb-w1-worker-ready/v1","role":role,"namespace_pid":os.getpid(),"fds":[0,1,2],"caps_zero":all(observed[key]=="0000000000000000" for key in ("CapInh","CapPrm","CapEff","CapBnd","CapAmb")),"no_new_privs":int(observed["NoNewPrivs"]),"seccomp":int(observed["Seccomp"]),"seccomp_filters":int(observed["Seccomp_filters"]),"seccomp_probes":probes}
os.write(1,b"KPB-W1-WORKER-READY:"+canon(ready)); start=sys.stdin.buffer.readline(64); need(start==b"KPB-W1-START:"+role.encode()+b"\n",43)
if role=="proof":
    need(len(sys.argv)==4 and sys.stdin.buffer.read(1)==b"",21); output=sys.argv[3]; need(not os.path.lexists(output),22)
    code,out,err=bounded([binary,output],None,256); need(code==0 and err==b"",23)
    with open(output,"rb",buffering=0) as stream: raw=stream.read(MAX+1)
    digest=receipt(raw); need(out==PM+digest.encode()+b"\n",24)
    os.write(1,MAGIC+struct.pack(">I",len(raw))+raw)
elif role=="verify":
    need(len(sys.argv)==3,25); length=struct.unpack(">I",exact(sys.stdin.buffer,4))[0]; need(0<length<=MAX,44); raw=exact(sys.stdin.buffer,length); need(sys.stdin.buffer.read(1)==b"",45); digest=receipt(raw)
    code,out,err=bounded([binary],raw,256); need(code==0 and err==b"" and out==VM+digest.encode()+b"\n",26)
    os.write(1,out)
'''


def seccomp_filter_bytes() -> bytes:
    """Create an x86_64-only classic-BPF deny filter for the payload."""
    load_word_abs = 0x20
    jump_equal = 0x15
    jump_bits_set = 0x45
    return_k = 0x06
    instructions: list[tuple[int, int, int, int]] = [
        (load_word_abs, 0, 0, 4),
        (jump_equal, 1, 0, AUDIT_ARCH_X86_64),
        (return_k, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (load_word_abs, 0, 0, 0),
        # x32 shares AUDIT_ARCH_X86_64 but ORs this bit into syscall numbers.
        # Kill it before comparing native x86_64 deny numbers.
        (jump_bits_set, 0, 1, X32_SYSCALL_BIT),
        (return_k, 0, 0, SECCOMP_RET_KILL_PROCESS),
    ]
    for number in sorted(DENIED_SYSCALLS_X86_64):
        instructions.append((jump_equal, 0, 1, number))
        instructions.append((return_k, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM))
    instructions.append((return_k, 0, 0, SECCOMP_RET_ALLOW))
    need(len(instructions) < 4096, "seccomp-size")
    return b"".join(struct.pack("HBBI", *instruction) for instruction in instructions)


def current_review_bindings() -> dict:
    return {
        "supervisor_source": REVIEWED_SUPERVISOR_SOURCE_BINDING,
        "external_stage0": REVIEWED_EXTERNAL_STAGE0_SOURCE_SHA256,
        "worker_source": REVIEWED_WORKER_SOURCE_SHA256,
        "bwrap": REVIEWED_BWRAP_BINDING,
        "build": REVIEWED_BUILD_BINDING,
        "runtime_closure": REVIEWED_RUNTIME_CLOSURE,
        "artifacts": REVIEWED_ARTIFACT_BINDINGS,
        "assignment": REVIEWED_ASSIGNMENT_BINDING,
        "seccomp": REVIEWED_SECCOMP_BINDINGS,
        "cgroup": REVIEWED_CGROUP_BINDING,
        "publication": REVIEWED_PUBLICATION_BINDING,
    }


def _version_tuple(value: object) -> tuple[int, int, int]:
    need(
        type(value) in (list, tuple)
        and len(value) == 3
        and all(type(item) is int and item >= 0 for item in value),
        "bwrap-version-shape",
    )
    return tuple(value)  # type: ignore[arg-type,return-value]


def validate_review_bindings(bindings: object) -> dict:
    need(type(bindings) is dict and set(bindings) == set(REVIEW_GATE_NAMES), "review-bindings-shape")
    assert isinstance(bindings, dict)
    need(all(bindings[name] is not None for name in REVIEW_GATE_NAMES), "review-binding-unbound")

    source = bindings["supervisor_source"]
    need(
        type(source) is dict
        and is_sha256(source.get("sha256"))
        and source.get("externally_authenticated") is True,
        "source-review-binding",
    )
    need(
        bindings["external_stage0"] == sha256_bytes(EXTERNAL_STAGE0_SOURCE.encode()),
        "external-stage0-review-binding",
    )
    need(
        bindings["worker_source"] == sha256_bytes(WORKER_SOURCE.encode()),
        "worker-source-review-binding",
    )

    bwrap = bindings["bwrap"]
    need(type(bwrap) is dict, "bwrap-review-binding")
    assert isinstance(bwrap, dict)
    bwrap_keys = {
        "executable", "version", "package_release", "package_sha256",
        "elf_build_id", "elf_pt_interp", "elf_dt_needed",
        "elf_dependency_graph",
        "cve_2026_87766_safe_openat_fix_present",
        "symlink_destination_rehearsal_refused",
        "json_status_block_fd_observation_rehearsal_passed",
        "fd_exec_apparmor_attachment_rehearsal_passed",
        "expected_apparmor_label", "apparmor_profile_name",
        "apparmor_mode", "apparmor_exact_exec_path",
        "apparmor_exact_path_authorized", "apparmor_profile_loaded",
        "apparmor_root_path", "apparmor_source_closure",
        "apparmor_source_closure_sha256", "apparmor_include_graph",
        "apparmor_optional_missing",
        "upstream_tag_object", "upstream_commit",
        "upstream_tag_api_verified", "upstream_tag_signature_verified",
        "loader_closure", "loader_closure_sha256", "independently_reviewed",
        "admin_installed", "user_writable", "rehearsed_live_mount_allowlists",
    }
    need(set(bwrap) == bwrap_keys, "bwrap-review-binding-keys")
    executable = _validate_file_ref_shape(bwrap.get("executable"), category="bwrap")
    version = _version_tuple(bwrap.get("version"))
    loader_closure = bwrap.get("loader_closure")
    need(
        executable["path"] == str(APPROVED_BWRAP_PATH)
        and executable["sha256"] == FIXED_DEBIAN_BWRAP_ELF_SHA256
        and executable["bytes"] == FIXED_DEBIAN_BWRAP_ELF_BYTES
        and executable["mode_octal"] == "0755"
        and executable["owner_uid"] == 0
        and executable["owner_gid"] == 0
        and version == FIXED_DEBIAN_BWRAP_VERSION
        and bwrap.get("package_release") == FIXED_DEBIAN_BWRAP_PACKAGE
        and bwrap.get("package_sha256") == FIXED_DEBIAN_BWRAP_PACKAGE_SHA256
        and bwrap.get("elf_build_id") == FIXED_DEBIAN_BWRAP_BUILD_ID
        and bwrap.get("elf_pt_interp") == FIXED_DEBIAN_BWRAP_PT_INTERP
        and tuple(bwrap.get("elf_dt_needed", ())) == FIXED_DEBIAN_BWRAP_DT_NEEDED
        and bwrap.get("elf_dependency_graph")
        == FIXED_DEBIAN_BWRAP_DEPENDENCY_GRAPH,
        "bwrap-exact-debian-artifact",
    )
    need(
        bwrap.get("apparmor_profile_name") == FIXED_BWRAP_APPARMOR_PROFILE
        and bwrap.get("apparmor_mode") == "enforce"
        and bwrap.get("expected_apparmor_label") == FIXED_BWRAP_APPARMOR_LABEL
        and bwrap.get("apparmor_exact_exec_path") == str(APPROVED_BWRAP_PATH)
        and bwrap.get("apparmor_exact_path_authorized") is True
        and bwrap.get("apparmor_profile_loaded") is True
        and type(bwrap.get("apparmor_source_closure")) is tuple
        and bool(bwrap["apparmor_source_closure"])
        and bwrap.get("apparmor_root_path") == FIXED_BWRAP_APPARMOR_ROOT
        and type(bwrap.get("apparmor_include_graph")) is dict
        and type(bwrap.get("apparmor_optional_missing")) is list,
        "bwrap-apparmor-enforce-authority",
    )
    for reference_value in bwrap["apparmor_source_closure"]:
        reference = _validate_file_ref_shape(
            reference_value, category="bwrap-apparmor-source"
        )
        need(
            reference["owner_uid"] == 0
            and reference["owner_gid"] == 0
            and int(reference["mode_octal"], 8) & 0o022 == 0,
            "bwrap-apparmor-source-root-owned",
        )
    closure_paths = [
        item["path"] for item in bwrap["apparmor_source_closure"]
    ]
    include_graph = bwrap["apparmor_include_graph"]
    optional_missing = bwrap["apparmor_optional_missing"]
    need(
        closure_paths[0] == FIXED_BWRAP_APPARMOR_ROOT
        and len(closure_paths) == len(set(closure_paths))
        and set(include_graph) == set(closure_paths)
        and all(
            type(path) is str
            and path.startswith("/etc/apparmor.d/")
            and ".." not in PurePosixPath(path).parts
            and type(children) is list
            and children == list(dict.fromkeys(children))
            for path, children in include_graph.items()
        )
        and optional_missing == sorted(set(optional_missing))
        and all(
            type(path) is str
            and path.startswith("/etc/apparmor.d/")
            and ".." not in PurePosixPath(path).parts
            and path not in closure_paths
            for path in optional_missing
        )
        and set(
            child for children in include_graph.values() for child in children
        )
        == (set(closure_paths) - {FIXED_BWRAP_APPARMOR_ROOT})
        | set(optional_missing),
        "bwrap-apparmor-include-graph",
    )
    reachable: set[str] = set()
    pending = [FIXED_BWRAP_APPARMOR_ROOT]
    while pending:
        path = pending.pop()
        if path in reachable:
            continue
        reachable.add(path)
        pending.extend(
            child
            for child in include_graph[path]
            if child in include_graph
        )
    need(reachable == set(closure_paths), "bwrap-apparmor-include-reachability")
    need(
        bwrap.get("apparmor_source_closure_sha256")
        == sha256_bytes(canonical(bwrap["apparmor_source_closure"])),
        "bwrap-apparmor-source-closure-hash",
    )
    need(
        bwrap.get("cve_2026_87766_safe_openat_fix_present") is True
        and bwrap.get("symlink_destination_rehearsal_refused") is True
        and bwrap.get("json_status_block_fd_observation_rehearsal_passed") is True
        and bwrap.get("fd_exec_apparmor_attachment_rehearsal_passed") is True
        and bwrap.get("independently_reviewed") is True,
        "bwrap-fixed-review-required",
    )
    need(
        bwrap.get("admin_installed") is True
        and bwrap.get("user_writable") is False
        and is_git_object_id(bwrap.get("upstream_tag_object"))
        and is_git_object_id(bwrap.get("upstream_commit"))
        and bwrap.get("upstream_tag_api_verified") is True
        and bwrap.get("upstream_tag_signature_verified") is True
        and type(loader_closure) is tuple
        and len(loader_closure) == len(FIXED_DEBIAN_BWRAP_CLOSURE_NAMES),
        "bwrap-admin-apparmor-provenance",
    )
    expected_elf_names = FIXED_DEBIAN_BWRAP_CLOSURE_NAMES
    need(
        tuple(item.get("elf_name") for item in loader_closure)
        == expected_elf_names,
        "bwrap-loader-derived-names",
    )
    for item in loader_closure:
        need(
            type(item) is dict
            and set(item)
            == {
                "elf_name", "elf_build_id", "elf_pt_interp", "elf_needed",
                "destination", "file",
            }
            and type(item["destination"]) is str
            and PurePosixPath(item["destination"]).is_absolute()
            and is_git_object_id(item["elf_build_id"])
            and item["elf_pt_interp"] in {None, FIXED_DEBIAN_BWRAP_PT_INTERP},
            "bwrap-loader-closure-item",
        )
        graph_name = (
            "ld-linux-x86-64.so.2"
            if item["elf_name"] == "PT_INTERP"
            else item["elf_name"]
        )
        need(
            item["elf_needed"]
            == FIXED_DEBIAN_BWRAP_DEPENDENCY_GRAPH[graph_name],
            "bwrap-loader-derived-dependencies",
        )
        if item["elf_name"] == "PT_INTERP":
            need(
                item["destination"] == FIXED_DEBIAN_BWRAP_PT_INTERP,
                "bwrap-loader-interpreter-destination",
            )
        else:
            need(
                PurePosixPath(item["destination"]).name == item["elf_name"],
                "bwrap-loader-soname-destination",
            )
        reference = _validate_file_ref_shape(
            item["file"], category="bwrap-loader-closure"
        )
        need(
            reference["owner_uid"] == 0
            and reference["owner_gid"] == 0
            and int(reference["mode_octal"], 8) & 0o022 == 0,
            "bwrap-loader-closure-root-owned",
        )
    need(
        bwrap.get("loader_closure_sha256") == sha256_bytes(canonical(loader_closure)),
        "bwrap-loader-closure-hash",
    )
    mount_allowlists = bwrap.get("rehearsed_live_mount_allowlists")
    need(
        type(mount_allowlists) is dict
        and set(mount_allowlists) == {"proof", "verifier"}
        and all(
            type(mount_allowlists[role]) is tuple
            and bool(mount_allowlists[role])
            and list(mount_allowlists[role])
            == sorted(set(mount_allowlists[role]))
            and all(
                type(path) is str
                and PurePosixPath(path).is_absolute()
                and ".." not in PurePosixPath(path).parts
                for path in mount_allowlists[role]
            )
            and {"/", "/proc", "/dev", "/tmp", "/out"}
            .issubset(mount_allowlists[role])
            for role in ("proof", "verifier")
        ),
        "bwrap-rehearsed-live-mount-allowlists",
    )

    build = bindings["build"]
    need(type(build) is dict and set(build) == {"proof", "verifier"}, "build-binding")
    assert isinstance(build, dict)
    role_binary_identities: set[tuple[str, int, str]] = set()
    role_source_closures: set[str] = set()
    role_receipts: set[tuple[str, int, str]] = set()
    for role in ("proof", "verifier"):
        role_build = build[role]
        need(
            type(role_build) is dict
            and set(role_build)
            == {"binary", "source_closure_sha256", "build_receipt"},
            f"{role}-build-binding",
        )
        ref = _validate_file_ref_shape(
            role_build["binary"], category=f"{role}-binary"
        )
        need(ref["mode_octal"] in {"0500", "0555"}, f"{role}-binary-mode")
        need(
            is_sha256(role_build["source_closure_sha256"]),
            f"{role}-build-source-closure",
        )
        receipt_ref = _validate_file_ref_shape(
            role_build["build_receipt"], category=f"{role}-build-receipt"
        )
        role_binary_identities.add((ref["path"], ref["bytes"], ref["sha256"]))
        role_source_closures.add(role_build["source_closure_sha256"])
        role_receipts.add(
            (receipt_ref["path"], receipt_ref["bytes"], receipt_ref["sha256"])
        )
    need(
        len(role_binary_identities) == 2
        and len(role_source_closures) == 2
        and len(role_receipts) == 2,
        "role-distinct-build-authority",
    )
    proof_build = build["proof"]
    verifier_build = build["verifier"]
    need(
        proof_build["binary"]["sha256"]
        != verifier_build["binary"]["sha256"]
        and (proof_build["binary"]["device"], proof_build["binary"]["inode"])
        != (
            verifier_build["binary"]["device"],
            verifier_build["binary"]["inode"],
        )
        and proof_build["build_receipt"]["sha256"]
        != verifier_build["build_receipt"]["sha256"]
        and (
            proof_build["build_receipt"]["device"],
            proof_build["build_receipt"]["inode"],
        )
        != (
            verifier_build["build_receipt"]["device"],
            verifier_build["build_receipt"]["inode"],
        ),
        "role-distinct-build-content",
    )

    closure = bindings["runtime_closure"]
    need(
        type(closure) is dict and set(closure) == {"proof", "verifier"},
        "runtime-closure-binding",
    )
    for role in ("proof", "verifier"):
        role_closure = closure[role]
        need(type(role_closure) is tuple and role_closure, "runtime-closure-role")
        destinations: set[str] = set()
        for item in role_closure:
            need(type(item) is dict and set(item) == {"label", "destination", "file"}, "runtime-closure-item")
            destination = item["destination"]
            need(
                type(item["label"]) is str
                and type(destination) is str
                and PurePosixPath(destination).is_absolute()
                and destination.startswith(("/usr/", "/lib/", "/lib64/"))
                and destination not in destinations,
                "runtime-closure-destination",
            )
            destinations.add(destination)
            runtime_reference = _validate_file_ref_shape(
                item["file"], category="runtime-closure-file"
            )
            need(
                runtime_reference["owner_uid"] == 0
                and runtime_reference["owner_gid"] == 0
                and int(runtime_reference["mode_octal"], 8) & 0o022 == 0,
                "runtime-closure-root-owned",
            )
        need(str(PYTHON) in destinations, "runtime-python-closure")

    artifacts = bindings["artifacts"]
    need(type(artifacts) is dict and set(artifacts) == set(EXPECTED_ARTIFACTS), "artifact-bindings")
    assert isinstance(artifacts, dict)
    private_content_identities: set[tuple[int, str]] = set()
    for name, expected in EXPECTED_ARTIFACTS.items():
        immutable = artifacts[name]
        need(
            type(immutable) is dict
            and set(immutable) == {"file", "fsverity"}
            and type(immutable["fsverity"]) is dict
            and immutable["fsverity"].get("enabled") is True
            and immutable["fsverity"].get("algorithm") == "sha256"
            and is_sha256(immutable["fsverity"].get("descriptor_digest")),
            f"artifact-{name}-immutable-binding",
        )
        reference = _validate_file_ref_shape(
            immutable["file"], category=f"artifact-{name}"
        )
        need(
            all(reference[key] == expected[key] for key in expected),
            f"artifact-{name}-fixed",
        )
        private_content_identities.add((reference["bytes"], reference["sha256"]))

    assignment = bindings["assignment"]
    need(
        type(assignment) is dict
        and set(assignment) == {"launch_receipt", "assignment_receipt"},
        "assignment-binding",
    )
    _validate_file_ref_shape(assignment["launch_receipt"], category="assignment-launch")
    _validate_file_ref_shape(assignment["assignment_receipt"], category="assignment-receipt")
    assignment_paths = {
        assignment["launch_receipt"]["path"],
        assignment["assignment_receipt"]["path"],
    }
    private_content_identities.update(
        {
            (assignment["launch_receipt"]["bytes"], assignment["launch_receipt"]["sha256"]),
            (assignment["assignment_receipt"]["bytes"], assignment["assignment_receipt"]["sha256"]),
        }
    )
    for role_closure in closure.values():
        for item in role_closure:
            reference = item["file"]
            need(
                (reference["bytes"], reference["sha256"])
                not in private_content_identities
                and reference["path"] not in assignment_paths,
                "runtime-closure-private-input-leak",
            )

    filters = bindings["seccomp"]
    filter_sha = sha256_bytes(seccomp_filter_bytes())
    need(
        type(filters) is dict
        and set(filters) == {"proof", "verifier"}
        and all(
            type(filters[role]) is dict
            and set(filters[role])
            == {
                "architecture", "sha256", "sealed",
                "independently_reviewed", "expected_filter_count",
                "required_probes",
            }
            and filters[role].get("architecture") == "x86_64"
            and filters[role].get("sha256") == filter_sha
            and filters[role].get("sealed") is True
            and filters[role].get("independently_reviewed") is True
            and filters[role].get("expected_filter_count") == 1
            and filters[role].get("required_probes")
            == ["getpid", "pidfd_open", "socket"]
            for role in ("proof", "verifier")
        ),
        "seccomp-review-binding",
    )

    validate_cgroup_binding(bindings["cgroup"])
    publication = bindings["publication"]
    need(
        type(publication) is dict
        and set(publication)
        == {
            "output", "create_new", "rename_noreplace",
            "commit_marker", "final_reopen", "exact_entries",
        }
        and publication.get("output") == str(FINAL_OUTPUT)
        and publication.get("create_new") is True
        and publication.get("rename_noreplace") is True
        and publication.get("commit_marker") is True
        and publication.get("final_reopen") is True
        and publication.get("exact_entries") is True,
        "publication-binding",
    )
    return bindings


def require_review_bindings() -> dict:
    """The first stage-1 operation.  It must precede every path open or write."""
    return validate_review_bindings(current_review_bindings())


def harden_parent_process() -> None:
    """Reduce accidental same-UID inspection; the trusted-host TCB still applies."""
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    need(result == 0, "parent-dumpable-zero")


def validate_cgroup_binding(binding: object) -> dict:
    need(type(binding) is dict, "cgroup-binding-shape")
    assert isinstance(binding, dict)
    need(
        set(binding)
        == {
            "parent", "worker_leaf", "trusted_host_tcb",
            "manager_and_same_uid_in_tcb", "limits_authenticated_pre_post",
            "assignment_protocol",
        },
        "cgroup-binding-keys",
    )
    parent = binding["parent"]
    leaf = binding["worker_leaf"]
    identity_keys = {
        "path", "device", "inode", "owner_uid", "owner_gid", "mode_octal",
    }
    parent_keys = identity_keys | {
        "memory_max", "memory_swap_max", "pids_max", "cgroup_type",
        "controllers", "trusted_preexisting",
    }
    leaf_keys = identity_keys | {
        "cgroup_type", "cgroup_kill", "trusted_preexisting", "parent_path",
    }
    need(
        type(parent) is dict
        and set(parent) == parent_keys
        and type(leaf) is dict
        and set(leaf) == leaf_keys,
        "cgroup-nested-binding-shape",
    )
    need(
        all(
            type(value["path"]) is str
            and value["path"].startswith("/sys/fs/cgroup/")
            and ".." not in PurePosixPath(value["path"]).parts
            and type(value["device"]) is int
            and type(value["inode"]) is int
            and type(value["owner_uid"]) is int
            and value["owner_uid"] >= 0
            and type(value["owner_gid"]) is int
            and value["mode_octal"] in {"0755", "0711", "0555", "0511"}
            and value["trusted_preexisting"] is True
            for value in (parent, leaf)
        )
        and type(parent["memory_max"]) is int
        and parent["memory_max"] >= MIN_MEMORY_MAX_BYTES
        and parent["memory_swap_max"] == 0
        and type(parent["pids_max"]) is int
        and MIN_PIDS_MAX <= parent["pids_max"] <= MAX_PIDS_MAX
        and parent["cgroup_type"] == "domain"
        and type(parent["controllers"]) is list
        and parent["controllers"] == sorted(set(parent["controllers"]))
        and {"memory", "pids"}.issubset(set(parent["controllers"]))
        and leaf["cgroup_type"] == "domain"
        and leaf["cgroup_kill"] is True
        and leaf["parent_path"] == parent["path"]
        and PurePosixPath(leaf["path"]).parent == PurePosixPath(parent["path"])
        and binding["trusted_host_tcb"] is True
        and binding["manager_and_same_uid_in_tcb"] is True
        and binding["limits_authenticated_pre_post"] is True
        and binding["assignment_protocol"]
        == "parent-enter-authenticate-pdeathsig-sigstop-leaf-assign-pidfd-sigcont",
        "cgroup-binding-values",
    )
    return binding


PARENT_CGROUP_SNAPSHOT_KEYS = {
    "path", "device", "inode", "owner_uid", "owner_gid", "mode_octal",
    "memory_max", "memory_swap_max", "memory_swap_current",
    "memory_swap_peak", "pids_max", "cgroup_type",
    "controllers", "populated", "procs", "oom", "oom_kill",
}
LEAF_CGROUP_SNAPSHOT_KEYS = {
    "path", "device", "inode", "owner_uid", "owner_gid", "mode_octal",
    "cgroup_type", "cgroup_kill", "populated", "procs",
}


def validate_parent_cgroup_snapshot(snapshot: object, binding: dict) -> dict:
    need(
        type(snapshot) is dict
        and set(snapshot) == PARENT_CGROUP_SNAPSHOT_KEYS,
        "parent-cgroup-snapshot-shape",
    )
    assert isinstance(snapshot, dict)
    validate_cgroup_binding(binding)
    parent = binding["parent"]
    for key in (
        "path", "device", "inode", "owner_uid", "owner_gid", "mode_octal",
        "memory_max", "memory_swap_max", "pids_max", "cgroup_type",
        "controllers",
    ):
        need(snapshot[key] == parent[key], "parent-cgroup-contract-drift")
    need(
        snapshot["memory_swap_max"] == 0
        and snapshot["memory_swap_current"] == 0
        and type(snapshot["memory_swap_peak"]) is int
        and snapshot["memory_swap_peak"] >= 0
        and type(snapshot["oom"]) is int
        and snapshot["oom"] >= 0
        and type(snapshot["oom_kill"]) is int
        and snapshot["oom_kill"] >= 0,
        "parent-cgroup-swap-contract",
    )
    need(
        type(snapshot["procs"]) is list
        and all(type(pid) is int and pid > 0 for pid in snapshot["procs"]),
        "parent-cgroup-procs-shape",
    )
    return snapshot


def validate_cgroup_snapshot(snapshot: object, binding: dict, *, empty: bool) -> dict:
    """Validate only the nested kill leaf; OOM accounting lives at parent."""
    need(
        type(snapshot) is dict and set(snapshot) == LEAF_CGROUP_SNAPSHOT_KEYS,
        "leaf-cgroup-snapshot-shape",
    )
    assert isinstance(snapshot, dict)
    validate_cgroup_binding(binding)
    leaf = binding["worker_leaf"]
    for key in (
        "path", "device", "inode", "owner_uid", "owner_gid", "mode_octal",
        "cgroup_type", "cgroup_kill",
    ):
        need(snapshot[key] == leaf[key], "leaf-cgroup-contract-drift")
    need(
        type(snapshot["procs"]) is list
        and all(type(pid) is int and pid > 0 for pid in snapshot["procs"]),
        "leaf-cgroup-procs-shape",
    )
    if empty:
        need(
            snapshot["populated"] == 0 and snapshot["procs"] == [],
            "leaf-cgroup-not-empty",
        )
    return snapshot


def validate_cgroup_pair(before: dict, after: dict, binding: dict) -> None:
    need(
        type(before) is dict
        and type(after) is dict
        and set(before) == {"parent", "leaf"}
        and set(after) == {"parent", "leaf"},
        "cgroup-evidence-pair-shape",
    )
    validate_parent_cgroup_snapshot(before["parent"], binding)
    validate_parent_cgroup_snapshot(after["parent"], binding)
    validate_cgroup_snapshot(before["leaf"], binding, empty=True)
    validate_cgroup_snapshot(after["leaf"], binding, empty=True)
    need(before == after, "cgroup-pre-post-drift")


def validate_assignment_values(launch: object, assignment: object, binding: dict) -> None:
    need(type(launch) is dict and type(assignment) is dict, "assignment-json-shape")
    assert isinstance(launch, dict) and isinstance(assignment, dict)
    receipt_ref = launch.get("assignment_receipt")
    need(type(receipt_ref) is dict, "assignment-launch-reference")
    expected = binding["assignment_receipt"]
    for key in ("path", "bytes", "sha256", "device", "inode", "mode_octal", "link_count"):
        need(receipt_ref.get(key) == expected[key], "assignment-launch-reference-drift")
    need(
        launch.get("schema") == "kpb-frozen-w1-assignment-launch-receipt/v2"
        and launch.get("assignment_public_inputs_decimal") == list(EXPECTED_PUBLIC_INPUTS)
        and launch.get("assignment_serialized") is False
        and launch.get("network_communication") is False
        and launch.get("funds") is False
        and launch.get("setup") is False
        and launch.get("proving_key_opened") is False
        and launch.get("aggregate_proof_generated") is False,
        "assignment-launch-values",
    )
    need(
        assignment.get("schema") == "kpb-frozen-w1-round1-assignment-preparation/v3"
        and assignment.get("derived_public_inputs_decimal")
        == list(EXPECTED_PUBLIC_INPUTS)
        and assignment.get("assignment_serialized") is False
        and assignment.get("setup_network_or_funds") is False
        and assignment.get("proving_key_opened") is False
        and assignment.get("aggregate_proof_generated") is False
        and assignment.get("receipt_is_authority") is False
        and assignment.get("public_or_production_authority") is False,
        "assignment-receipt-values",
    )


def authenticate_assignment_pair(binding: dict) -> dict:
    """Open both receipts themselves; a nested launch reference is insufficient."""
    launch_raw, launch_ref = stable_read(
        binding["launch_receipt"], max_bytes=MAX_ASSIGNMENT_LAUNCH_BYTES
    )
    assignment_raw, assignment_ref = stable_read(
        binding["assignment_receipt"], max_bytes=MAX_ASSIGNMENT_RECEIPT_BYTES
    )
    launch = decode_canonical_json(launch_raw, category="assignment-launch")
    assignment = decode_canonical_json(assignment_raw, category="assignment-receipt")
    validate_assignment_values(launch, assignment, binding)
    return {
        "launch": launch_ref,
        "assignment": assignment_ref,
        "launch_canonical_sha256": sha256_bytes(launch_raw),
        "assignment_canonical_sha256": sha256_bytes(assignment_raw),
    }


def validate_assignment_reopen(before: dict, after: dict) -> None:
    need(before == after, "assignment-pre-post-drift")


def _synthetic_dirs(destinations: list[str]) -> list[str]:
    directories = {"/payload", "/supervisor", "/out"}
    for destination in destinations:
        current = PurePosixPath(destination).parent
        while str(current) != "/":
            directories.add(str(current))
            current = current.parent
    return sorted(directories, key=lambda value: (value.count("/"), value))


def _construct_sandbox_plan(
    role: str,
    *,
    bwrap_fd: int,
    binary_fd: int,
    runtime_fds: tuple[tuple[str, int], ...],
    artifact_fds: dict[str, int],
    worker_fd: int,
    seccomp_fd: int,
    status_fd: int,
    barrier_fd: int,
) -> dict:
    need(role in {"proof", "verifier"}, "sandbox-role")
    private_labels = PROOF_PRIVATE_LABELS if role == "proof" else VERIFIER_PRIVATE_LABELS
    need(set(artifact_fds) == set(private_labels), "sandbox-private-input-set")
    runtime_items = list(runtime_fds)
    need(runtime_items and len({item[0] for item in runtime_items}) == len(runtime_items), "sandbox-runtime-fds")
    descriptor_roles = [
        bwrap_fd, binary_fd, worker_fd, seccomp_fd, status_fd, barrier_fd,
        *(descriptor for _, descriptor in runtime_items),
        *artifact_fds.values(),
    ]
    need(
        all(type(descriptor) is int and descriptor >= 3 for descriptor in descriptor_roles)
        and len(descriptor_roles) == len(set(descriptor_roles)),
        "sandbox-distinct-descriptor-roles",
    )

    mounts: list[dict] = []
    binary_destination = f"/payload/{role}"
    mounts.append({"kind": "ro-bind-fd", "label": f"{role}-binary", "fd": binary_fd, "destination": binary_destination})
    for destination, descriptor in runtime_items:
        mounts.append({"kind": "ro-bind-fd", "label": "runtime", "fd": descriptor, "destination": destination})
    for label in sorted(private_labels):
        mounts.append(
            {
                "kind": "ro-bind-fd",
                "label": label,
                "fd": artifact_fds[label],
                "destination": EXPECTED_ARTIFACTS[label]["path"],
            }
        )
    mounts.append({"kind": "ro-bind-fd", "label": "worker", "fd": worker_fd, "destination": "/supervisor/worker.py"})
    destinations = [item["destination"] for item in mounts]

    command = [
        f"/proc/self/fd/{bwrap_fd}",
        *MANDATORY_NAMESPACE_FLAGS,
        "--cap-drop", "ALL",
        "--uid", "0",
        "--gid", "0",
        "--hostname", "kpb-w1",
        "--tmpfs", "/",
    ]
    for directory in _synthetic_dirs(destinations):
        if directory == "/out":
            continue
        command.extend(("--dir", directory))
    command.extend(("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"))
    command.extend(("--size", str(64 * 1024), "--tmpfs", "/out"))
    for item in mounts:
        option = "--ro-bind-fd" if item["kind"] == "ro-bind-fd" else "--ro-bind-data"
        command.extend((option, str(item["fd"]), item["destination"]))
    command.extend(("--seccomp", str(seccomp_fd)))
    command.extend(("--json-status-fd", str(status_fd)))
    command.extend(("--block-fd", str(barrier_fd)))
    for key, value in SANDBOX_ENVIRONMENT.items():
        command.extend(("--setenv", key, value))
    worker_role = "proof" if role == "proof" else "verify"
    payload_argv = [str(PYTHON), "-I", "-S", "-B", "/supervisor/worker.py", worker_role, binary_destination]
    if role == "proof":
        payload_argv.append("/out/PROOF-RECEIPT.json")
    command.extend(("--chdir", "/", "--", *payload_argv))
    passed_fds = tuple(sorted(descriptor_roles))
    mount_requirements = [
        {"destination": destination, "mode": "rw"}
        for destination in ("/", "/proc", "/dev", "/tmp", "/out")
    ] + [
        {"destination": item["destination"], "mode": "ro"}
        for item in mounts
    ]
    plan_base = {
        "role": role,
        "worker_role": worker_role,
        "command": command,
        "passed_fds": passed_fds,
        "mounts": mounts,
        "mount_requirements": mount_requirements,
        "private_input_labels": sorted(private_labels),
        "payload_argv": payload_argv,
        "payload_fd_allowlist": [0, 1, 2],
        "bwrap_fd": bwrap_fd,
        "binary_fd": binary_fd,
        "runtime_fds": tuple(runtime_items),
        "artifact_fds": dict(sorted(artifact_fds.items())),
        "worker_fd": worker_fd,
        "status_fd": status_fd,
        "barrier_fd": barrier_fd,
        "seccomp_fd": seccomp_fd,
        "environment": dict(SANDBOX_ENVIRONMENT),
    }
    return plan_base | {"plan_sha256": sha256_bytes(canonical(plan_base))}


def build_sandbox_plan(
    role: str,
    *,
    bwrap_fd: int,
    binary_fd: int,
    runtime_fds: tuple[tuple[str, int], ...],
    artifact_fds: dict[str, int],
    worker_fd: int,
    seccomp_fd: int,
    status_fd: int,
    barrier_fd: int,
) -> dict:
    plan = _construct_sandbox_plan(
        role,
        bwrap_fd=bwrap_fd,
        binary_fd=binary_fd,
        runtime_fds=runtime_fds,
        artifact_fds=artifact_fds,
        worker_fd=worker_fd,
        seccomp_fd=seccomp_fd,
        status_fd=status_fd,
        barrier_fd=barrier_fd,
    )
    validate_sandbox_plan(plan)
    return plan


def validate_sandbox_plan(plan: object) -> dict:
    need(type(plan) is dict, "sandbox-plan-shape")
    assert isinstance(plan, dict)
    role = plan.get("role")
    need(role in {"proof", "verifier"}, "sandbox-plan-role")
    reconstruct_keys = {
        "bwrap_fd", "binary_fd", "runtime_fds", "artifact_fds", "worker_fd",
        "seccomp_fd", "status_fd", "barrier_fd",
    }
    need(
        reconstruct_keys.issubset(plan)
        and type(plan["runtime_fds"]) is tuple
        and type(plan["artifact_fds"]) is dict,
        "sandbox-reconstruction-inputs",
    )
    expected = _construct_sandbox_plan(
        role,
        bwrap_fd=plan["bwrap_fd"],
        binary_fd=plan["binary_fd"],
        runtime_fds=plan["runtime_fds"],
        artifact_fds=plan["artifact_fds"],
        worker_fd=plan["worker_fd"],
        seccomp_fd=plan["seccomp_fd"],
        status_fd=plan["status_fd"],
        barrier_fd=plan["barrier_fd"],
    )
    need(plan == expected, "sandbox-canonical-reconstruction")
    need(
        "LD_PRELOAD" not in plan["environment"]
        and "LD_LIBRARY_PATH" not in plan["environment"],
        "sandbox-loader-environment",
    )
    return plan


def sandbox_start_frame(plan: dict, stdin_raw: bytes) -> bytes:
    validate_sandbox_plan(plan)
    need(len(stdin_raw) <= MAX_PROOF_RECEIPT_BYTES, "sandbox-stdin-bounds")
    frame = b"KPB-W1-START:" + plan["worker_role"].encode("ascii") + b"\n"
    if plan["role"] == "proof":
        need(stdin_raw == b"", "proof-unexpected-stdin")
    else:
        frame += struct.pack(">I", len(stdin_raw)) + stdin_raw
    return frame


def canonical_launch_contract(plan: dict, stdin_raw: bytes) -> dict:
    frame = sandbox_start_frame(plan, stdin_raw)
    return {
        "schema": "kpb-w1-bwrap-launch-contract/v1",
        "plan_sha256": plan["plan_sha256"],
        "command_sha256": sha256_bytes(canonical(plan["command"])),
        "mounts_sha256": sha256_bytes(canonical(plan["mounts"])),
        "passed_fds": list(plan["passed_fds"]),
        "environment": dict(plan["environment"]),
        "payload_argv": list(plan["payload_argv"]),
        "payload_fd_allowlist": list(plan["payload_fd_allowlist"]),
        "stdin_bytes": len(stdin_raw),
        "stdin_sha256": sha256_bytes(stdin_raw),
        "start_frame_bytes": len(frame),
        "start_frame_sha256": sha256_bytes(frame),
        "live_runtime_deadline_seconds": LIVE_PROOF_DEADLINE_SECONDS,
        "runtime_cancellation": "SIGINT-or-SIGTERM-owner-cancel-pipe",
    }


def parse_status_stream(raw: bytes) -> list[dict]:
    need(0 < len(raw) <= MAX_STATUS_BYTES and raw.endswith(b"\n"), "bwrap-status-bounds")
    rows: list[dict] = []
    for line in raw.splitlines(keepends=True):
        value = decode_unique_json(line, category="bwrap-status")
        need(type(value) is dict, "bwrap-status-row")
        rows.append(value)
    child_rows = [row for row in rows if type(row.get("child-pid")) is int]
    exit_rows = [row for row in rows if type(row.get("exit-code")) is int]
    need(len(child_rows) == 1 and len(exit_rows) == 1, "bwrap-status-lifecycle")
    return rows


def validate_launch_contract(contract: object, plan: dict) -> dict:
    validate_sandbox_plan(plan)
    required = {
        "schema", "plan_sha256", "command_sha256", "mounts_sha256",
        "passed_fds", "environment", "payload_argv", "payload_fd_allowlist",
        "stdin_bytes", "stdin_sha256", "start_frame_bytes",
        "start_frame_sha256", "live_runtime_deadline_seconds",
        "runtime_cancellation",
    }
    need(type(contract) is dict and set(contract) == required, "launch-contract-shape")
    assert isinstance(contract, dict)
    need(
        contract["schema"] == "kpb-w1-bwrap-launch-contract/v1"
        and contract["plan_sha256"] == plan["plan_sha256"]
        and contract["command_sha256"]
        == sha256_bytes(canonical(plan["command"]))
        and contract["mounts_sha256"]
        == sha256_bytes(canonical(plan["mounts"]))
        and contract["passed_fds"] == list(plan["passed_fds"])
        and contract["environment"] == plan["environment"]
        and contract["payload_argv"] == plan["payload_argv"]
        and contract["payload_fd_allowlist"] == plan["payload_fd_allowlist"]
        and type(contract["stdin_bytes"]) is int
        and 0 <= contract["stdin_bytes"] <= MAX_PROOF_RECEIPT_BYTES
        and is_sha256(contract["stdin_sha256"])
        and type(contract["start_frame_bytes"]) is int
        and contract["start_frame_bytes"] > 0
        and is_sha256(contract["start_frame_sha256"])
        and contract["live_runtime_deadline_seconds"] is None
        and contract["runtime_cancellation"]
        == "SIGINT-or-SIGTERM-owner-cancel-pipe",
        "launch-contract-values",
    )
    if plan["role"] == "proof":
        need(
            contract["stdin_bytes"] == 0
            and contract["stdin_sha256"] == sha256_bytes(b""),
            "proof-launch-stdin",
        )
    return contract


MOUNT_EVIDENCE_ENTRY_KEYS = {
    "mount_id", "parent_id", "device", "root", "mount_point",
    "mount_options", "optional_fields", "fs_type", "mount_source",
    "super_options",
}


def validate_mount_evidence(
    evidence: object, plan: dict, bwrap_binding: dict
) -> dict:
    need(
        type(evidence) is dict
        and set(evidence) == {"schema", "raw_sha256", "entries", "entries_sha256"}
        and evidence.get("schema") == "kpb-w1-proc-mountinfo/v1"
        and is_sha256(evidence.get("raw_sha256"))
        and type(evidence.get("entries")) is list
        and is_sha256(evidence.get("entries_sha256")),
        "mount-evidence-shape",
    )
    assert isinstance(evidence, dict)
    entries = evidence["entries"]
    need(
        bool(entries)
        and all(type(item) is dict and set(item) == MOUNT_EVIDENCE_ENTRY_KEYS for item in entries)
        and evidence["entries_sha256"] == sha256_bytes(canonical(entries)),
        "mount-evidence-entries",
    )
    for requirement in plan["mount_requirements"]:
        candidates = [
            item for item in entries
            if item["mount_point"] == requirement["destination"]
        ]
        need(bool(candidates), "mount-evidence-destination-missing")
        need(
            any(
                requirement["mode"]
                in set(item["mount_options"]) | set(item["super_options"])
                for item in candidates
            ),
            "mount-evidence-mode",
        )
    observed_mount_points = [item["mount_point"] for item in entries]
    expected_mount_points = bwrap_binding[
        "rehearsed_live_mount_allowlists"
    ][plan["role"]]
    need(
        len(observed_mount_points) == len(set(observed_mount_points))
        and tuple(sorted(observed_mount_points)) == expected_mount_points,
        "mount-evidence-exact-rehearsed-allowlist",
    )
    return evidence


def validate_mount_target_identities(evidence: object, plan: dict) -> list[dict]:
    need(type(evidence) is list, "mount-target-identities-shape")
    expected = [
        {
            "label": item["label"],
            "fd": item["fd"],
            "destination": item["destination"],
        }
        for item in plan["mounts"]
    ]
    need(len(evidence) == len(expected), "mount-target-identities-count")
    for observed, contract in zip(evidence, expected, strict=True):
        need(
            type(observed) is dict
            and set(observed)
            == {
                "label", "fd", "destination", "source_device",
                "source_inode", "target_device", "target_inode",
            }
            and all(observed[key] == contract[key] for key in contract)
            and observed["source_device"] == observed["target_device"]
            and observed["source_inode"] == observed["target_inode"],
            "mount-target-identity",
        )
    return evidence


def validate_cgroup_assignment_receipt(receipt: object, binding: dict) -> dict:
    need(
        type(receipt) is dict
        and set(receipt)
        == {
            "schema", "pid", "starttime_before", "starttime_after",
            "pidfd_opened", "leaf_path", "observed_proc_cgroup",
            "leaf_snapshot", "pdeathsig", "assignment_verified",
        },
        "cgroup-assignment-shape",
    )
    assert isinstance(receipt, dict)
    leaf = binding["worker_leaf"]
    validate_cgroup_snapshot(receipt["leaf_snapshot"], binding, empty=False)
    need(
        receipt["schema"] == "kpb-w1-cgroup-assignment/v1"
        and type(receipt["pid"]) is int
        and receipt["pid"] > 1
        and receipt["starttime_before"] == receipt["starttime_after"]
        and receipt["pidfd_opened"] is True
        and receipt["leaf_path"] == leaf["path"]
        and receipt["observed_proc_cgroup"]
        == _expected_proc_cgroup_path(binding)
        and receipt["pid"] in receipt["leaf_snapshot"]["procs"]
        and receipt["leaf_snapshot"]["populated"] == 1
        and receipt["pdeathsig"] == "SIGKILL-before-SIGSTOP"
        and receipt["assignment_verified"] is True,
        "cgroup-assignment-values",
    )
    return receipt


def validate_launch_evidence(
    evidence: object,
    plan: dict,
    host_namespaces: dict,
    cgroup_binding: dict,
    bwrap_binding: dict,
) -> dict:
    need(type(evidence) is dict, "launch-evidence-shape")
    assert isinstance(evidence, dict)
    required = {
        "bwrap_pid", "bwrap_starttime_before", "bwrap_starttime_after",
        "bwrap_pidfd_opened", "payload_pid", "payload_starttime_before",
        "payload_starttime_after", "payload_pidfd_opened", "status_child_pid",
        "host_namespaces", "payload_namespaces", "capabilities", "no_new_privs",
        "seccomp_mode", "seccomp_filter_count", "cgroup_path",
        "expected_cgroup_path", "cgroup_assignment", "payload_cmdline",
        "payload_fds", "bwrap_executable_sha256", "expected_bwrap_sha256",
        "bwrap_executable_device", "expected_bwrap_device",
        "bwrap_executable_inode", "expected_bwrap_inode",
        "bwrap_apparmor_label", "expected_bwrap_apparmor_label",
        "barrier_release_sequence", "status_json_unique_keys",
        "launch_contract", "mount_evidence", "mount_target_identities",
        "loaded_elf_mappings",
    }
    need(set(evidence) == required, "launch-evidence-keys")
    need(
        type(evidence["bwrap_pid"]) is int
        and type(evidence["payload_pid"]) is int
        and evidence["bwrap_pid"] > 1
        and evidence["payload_pid"] > 1
        and evidence["bwrap_pid"] != evidence["payload_pid"]
        and evidence["bwrap_starttime_before"] == evidence["bwrap_starttime_after"]
        and evidence["payload_starttime_before"] == evidence["payload_starttime_after"]
        and evidence["bwrap_pidfd_opened"] is True
        and evidence["payload_pidfd_opened"] is True
        and evidence["status_child_pid"] == evidence["payload_pid"],
        "launch-pid-substitution",
    )
    need(evidence["host_namespaces"] == host_namespaces, "launch-host-namespace-binding")
    child_namespaces = evidence["payload_namespaces"]
    need(
        type(child_namespaces) is dict
        and set(child_namespaces) == set(NAMESPACE_NAMES)
        and set(host_namespaces) == set(NAMESPACE_NAMES)
        and all(
            type(child_namespaces[name]) is list
            and len(child_namespaces[name]) == 2
            and child_namespaces[name] != host_namespaces[name]
            for name in NAMESPACE_NAMES
        ),
        "launch-namespace-separation",
    )
    need(
        evidence["capabilities"]
        == {"CapInh": 0, "CapPrm": 0, "CapEff": 0, "CapBnd": 0, "CapAmb": 0}
        and evidence["no_new_privs"] == 1
        and evidence["seccomp_mode"] == 2
        and evidence["seccomp_filter_count"] == 1,
        "launch-capability-or-seccomp",
    )
    validate_launch_contract(evidence["launch_contract"], plan)
    validate_mount_evidence(evidence["mount_evidence"], plan, bwrap_binding)
    validate_mount_target_identities(evidence["mount_target_identities"], plan)
    validate_loaded_elf_mappings(
        evidence["loaded_elf_mappings"], bwrap_binding
    )
    validate_cgroup_assignment_receipt(evidence["cgroup_assignment"], cgroup_binding)
    need(
        evidence["cgroup_path"] == evidence["expected_cgroup_path"]
        and evidence["payload_cmdline"] == plan["payload_argv"]
        and evidence["payload_fds"] == plan["payload_fd_allowlist"]
        and evidence["bwrap_executable_sha256"] == evidence["expected_bwrap_sha256"]
        and evidence["bwrap_executable_device"] == evidence["expected_bwrap_device"]
        and evidence["bwrap_executable_inode"] == evidence["expected_bwrap_inode"]
        and evidence["bwrap_apparmor_label"]
        == evidence["expected_bwrap_apparmor_label"]
        == FIXED_BWRAP_APPARMOR_LABEL
        and evidence["barrier_release_sequence"]
        == "bwrap-block-then-worker-ready-then-pidfd-namespace-capability-cgroup-fd-checks"
        and evidence["status_json_unique_keys"] is True,
        "launch-boundary-substitution",
    )
    return evidence


def validate_wait_evidence(evidence: object, *, expected_pid: int) -> dict:
    need(type(evidence) is dict, "wait-evidence-shape")
    assert isinstance(evidence, dict)
    required = {
        "wait4_pid", "exited", "exit_code", "term_signal", "status_exit_code",
        "stdout_eof", "stderr_eof", "status_eof", "zero_descendants",
        "cgroup_populated", "cgroup_procs", "parent_memory_swap_current",
        "parent_memory_swap_peak", "group_kill_armed", "max_rss_kib",
        "pidfd_death_observed", "wait4_exactly_once",
        "payload_pidfd_death_observed", "leaf_empty_supplemental",
        "cgroup_assignment_verified",
    }
    need(set(evidence) == required, "wait-evidence-keys")
    need(
        evidence["wait4_pid"] == expected_pid
        and evidence["exited"] is True
        and evidence["exit_code"] == 0
        and evidence["term_signal"] == 0
        and evidence["status_exit_code"] == 0,
        "wait4-exit-status",
    )
    need(
        evidence["stdout_eof"] is True
        and evidence["stderr_eof"] is True
        and evidence["status_eof"] is True,
        "wait4-stream-eof",
    )
    need(
        evidence["zero_descendants"] is True
        and evidence["cgroup_populated"] == 0
        and evidence["cgroup_procs"] == []
        and evidence["parent_memory_swap_current"] == 0
        and type(evidence["parent_memory_swap_peak"]) is int
        and evidence["parent_memory_swap_peak"] >= 0
        and evidence["group_kill_armed"] is True
        and evidence["pidfd_death_observed"] is True
        and evidence["payload_pidfd_death_observed"] is True
        and evidence["wait4_exactly_once"] is True
        and evidence["leaf_empty_supplemental"] is True
        and evidence["cgroup_assignment_verified"] is True
        and type(evidence["max_rss_kib"]) is int
        and evidence["max_rss_kib"] >= 0,
        "wait4-descendants-or-swap",
    )
    return evidence


def _read_small_fd(descriptor: int, *, limit: int, category: str) -> bytes:
    result = bytearray()
    while True:
        block = os.read(descriptor, min(4096, limit + 1 - len(result)))
        if not block:
            break
        result.extend(block)
        need(len(result) <= limit, category)
    return bytes(result)


def _read_cgroup_file(directory_fd: int, name: str, *, limit: int = 4096) -> str:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        return _read_small_fd(
            descriptor, limit=limit, category="cgroup-file-overflow"
        ).decode("ascii")
    except UnicodeDecodeError as error:
        raise Refused("cgroup-file-encoding") from error
    finally:
        os.close(descriptor)


def _decimal_control(value: str, *, category: str) -> int:
    value = value.strip()
    need(value.isascii() and value.isdecimal(), category)
    result = int(value)
    need(result >= 0, category)
    return result


def _keyed_decimal_control(value: str, *, category: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in value.splitlines():
        fields = line.split()
        need(len(fields) == 2 and fields[0] not in result, category)
        result[fields[0]] = _decimal_control(fields[1], category=category)
    return result


def _open_authenticated_cgroup(contract: dict, *, category: str) -> int:
    path = contract["path"]
    directory_fd = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    value = os.fstat(directory_fd)
    try:
        need(
            value.st_dev == contract["device"]
            and value.st_ino == contract["inode"]
            and value.st_uid == contract["owner_uid"]
            and value.st_gid == contract["owner_gid"]
            and f"{stat.S_IMODE(value.st_mode):04o}" == contract["mode_octal"],
            category,
        )
    except BaseException:
        os.close(directory_fd)
        raise
    return directory_fd


def _read_cgroup_procs(directory_fd: int, *, category: str) -> list[int]:
    raw = _read_cgroup_file(directory_fd, "cgroup.procs", limit=64 * 1024)
    return [] if not raw.strip() else sorted(
        _decimal_control(item, category=category) for item in raw.splitlines()
    )


def read_parent_cgroup_snapshot(binding: dict) -> dict:
    validate_cgroup_binding(binding)
    parent = binding["parent"]
    directory_fd = _open_authenticated_cgroup(
        parent, category="parent-cgroup-directory-drift"
    )
    try:
        value = os.fstat(directory_fd)
        memory_max = _decimal_control(
            _read_cgroup_file(directory_fd, "memory.max"),
            category="parent-cgroup-memory-max",
        )
        swap_max = _decimal_control(
            _read_cgroup_file(directory_fd, "memory.swap.max"),
            category="parent-cgroup-swap-max",
        )
        pids_max = _decimal_control(
            _read_cgroup_file(directory_fd, "pids.max"),
            category="parent-cgroup-pids-max",
        )
        swap_current = _decimal_control(
            _read_cgroup_file(directory_fd, "memory.swap.current"),
            category="parent-cgroup-swap-current",
        )
        swap_peak = _decimal_control(
            _read_cgroup_file(directory_fd, "memory.swap.peak"),
            category="parent-cgroup-swap-peak",
        )
        events = _keyed_decimal_control(
            _read_cgroup_file(directory_fd, "cgroup.events"),
            category="parent-cgroup-events",
        )
        memory_events = _keyed_decimal_control(
            _read_cgroup_file(directory_fd, "memory.events"),
            category="parent-cgroup-memory-events",
        )
        controllers = sorted(
            _read_cgroup_file(directory_fd, "cgroup.controllers").split()
        )
        snapshot = {
            "path": parent["path"],
            "device": value.st_dev,
            "inode": value.st_ino,
            "owner_uid": value.st_uid,
            "owner_gid": value.st_gid,
            "mode_octal": f"{stat.S_IMODE(value.st_mode):04o}",
            "memory_max": memory_max,
            "memory_swap_max": swap_max,
            "memory_swap_current": swap_current,
            "memory_swap_peak": swap_peak,
            "pids_max": pids_max,
            "cgroup_type": _read_cgroup_file(directory_fd, "cgroup.type").strip(),
            "controllers": controllers,
            "populated": events.get("populated"),
            "procs": _read_cgroup_procs(
                directory_fd, category="parent-cgroup-procs"
            ),
            "oom": memory_events.get("oom"),
            "oom_kill": memory_events.get("oom_kill"),
        }
        return validate_parent_cgroup_snapshot(snapshot, binding)
    finally:
        os.close(directory_fd)


def read_cgroup_snapshot(binding: dict) -> dict:
    """Read only the nested worker kill leaf; no OOM counters are required."""
    validate_cgroup_binding(binding)
    leaf = binding["worker_leaf"]
    directory_fd = _open_authenticated_cgroup(
        leaf, category="leaf-cgroup-directory-drift"
    )
    try:
        value = os.fstat(directory_fd)
        events = _keyed_decimal_control(
            _read_cgroup_file(directory_fd, "cgroup.events"),
            category="leaf-cgroup-events",
        )
        os.stat("cgroup.kill", dir_fd=directory_fd, follow_symlinks=False)
        snapshot = {
            "path": leaf["path"],
            "device": value.st_dev,
            "inode": value.st_ino,
            "owner_uid": value.st_uid,
            "owner_gid": value.st_gid,
            "mode_octal": f"{stat.S_IMODE(value.st_mode):04o}",
            "cgroup_type": _read_cgroup_file(directory_fd, "cgroup.type").strip(),
            "cgroup_kill": True,
            "populated": events.get("populated"),
            "procs": _read_cgroup_procs(
                directory_fd, category="leaf-cgroup-procs"
            ),
        }
        return validate_cgroup_snapshot(snapshot, binding, empty=False)
    finally:
        os.close(directory_fd)


def capture_cgroup_snapshot(binding: dict) -> dict:
    return {
        "parent": read_parent_cgroup_snapshot(binding),
        "leaf": read_cgroup_snapshot(binding),
    }


def _write_cgroup_control_at(contract: dict, name: str, raw: bytes) -> None:
    need(name in {"cgroup.procs", "cgroup.kill"}, "cgroup-write-surface")
    directory_fd = _open_authenticated_cgroup(
        contract, category="cgroup-write-directory-drift"
    )
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            need(os.write(descriptor, raw) == len(raw), "cgroup-write-short")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def _write_cgroup_control(binding: dict, name: str, raw: bytes) -> None:
    validate_cgroup_binding(binding)
    _write_cgroup_control_at(binding["worker_leaf"], name, raw)


def open_cgroup_kill(binding: dict) -> int:
    """Pre-open the authenticated group-kill capability before any spawn."""
    validate_cgroup_binding(binding)
    directory_fd = _open_authenticated_cgroup(
        binding["worker_leaf"], category="cgroup-kill-directory-drift"
    )
    try:
        descriptor = os.open(
            "cgroup.kill",
            os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        need(stat.S_ISREG(os.fstat(descriptor).st_mode), "cgroup-kill-file")
        return descriptor
    finally:
        os.close(directory_fd)


def trigger_cgroup_kill(descriptor: int) -> None:
    need(os.write(descriptor, b"1\n") == 2, "cgroup-kill-write")


def kill_cgroup(binding: dict) -> None:
    descriptor = open_cgroup_kill(binding)
    try:
        trigger_cgroup_kill(descriptor)
    finally:
        os.close(descriptor)


def verify_cgroup_empty_bounded(binding: dict, *, seconds: float = 5.0) -> dict:
    deadline = time.monotonic() + seconds
    while True:
        snapshot = read_cgroup_snapshot(binding)
        if snapshot["populated"] == 0 and snapshot["procs"] == []:
            return snapshot
        need(time.monotonic() < deadline, "failure-cgroup-not-empty")
        time.sleep(0.05)


def enter_and_authenticate_parent_cgroup(binding: dict) -> dict:
    """Enter the swap-disabled parent before any assignment or PK content read."""
    validate_cgroup_binding(binding)
    before = read_parent_cgroup_snapshot(binding)
    validate_cgroup_snapshot(read_cgroup_snapshot(binding), binding, empty=True)
    pid = os.getpid()
    starttime = _proc_starttime(pid)
    _write_cgroup_control_at(
        binding["parent"], "cgroup.procs", f"{pid}\n".encode("ascii")
    )
    after = read_parent_cgroup_snapshot(binding)
    observed_path = _proc_cgroup_path(pid)
    need(
        _proc_starttime(pid) == starttime
        and observed_path == _expected_parent_proc_cgroup_path(binding)
        and pid in after["procs"]
        and after["memory_swap_max"] == 0
        and after["memory_swap_current"] == 0,
        "parent-cgroup-entry-unverified",
    )
    return {
        "schema": "kpb-w1-parent-cgroup-entry/v1",
        "pid": pid,
        "starttime": starttime,
        "observed_proc_cgroup": observed_path,
        "before": before,
        "after": after,
        "swap_zero_before_private_reads": True,
    }


PARENT_CGROUP_ENTRY_BASE_KEYS = {
    "schema", "pid", "starttime", "observed_proc_cgroup",
    "before", "after", "swap_zero_before_private_reads",
}


def _validate_parent_cgroup_entry_base(receipt: object, binding: dict) -> dict:
    need(
        type(receipt) is dict
        and set(receipt) == PARENT_CGROUP_ENTRY_BASE_KEYS,
        "parent-cgroup-entry-shape",
    )
    assert isinstance(receipt, dict)
    validate_parent_cgroup_snapshot(receipt["before"], binding)
    validate_parent_cgroup_snapshot(receipt["after"], binding)
    need(
        receipt["schema"] == "kpb-w1-parent-cgroup-entry/v1"
        and receipt["pid"] == os.getpid()
        and receipt["observed_proc_cgroup"]
        == _expected_parent_proc_cgroup_path(binding)
        and receipt["pid"] in receipt["after"]["procs"]
        and receipt["after"]["memory_swap_max"] == 0
        and receipt["after"]["memory_swap_current"] == 0
        and receipt["swap_zero_before_private_reads"] is True,
        "parent-cgroup-entry-values",
    )
    return receipt


def validate_parent_cgroup_entry(receipt: object, binding: dict) -> dict:
    """Validate the evidence only the post-exec stage is allowed to mint."""
    final_keys = PARENT_CGROUP_ENTRY_BASE_KEYS | {
        "sealed_reexec_completed", "sealed_transition_sha256",
        "post_reexec_starttime", "post_reexec_proc_cgroup",
        "post_reexec_parent_snapshot",
    }
    need(
        type(receipt) is dict and set(receipt) == final_keys,
        "parent-cgroup-post-reexec-shape",
    )
    assert isinstance(receipt, dict)
    base = {key: receipt[key] for key in PARENT_CGROUP_ENTRY_BASE_KEYS}
    _validate_parent_cgroup_entry_base(base, binding)
    post = receipt["post_reexec_parent_snapshot"]
    validate_parent_cgroup_snapshot(post, binding)
    need(
        receipt["sealed_reexec_completed"] is True
        and is_sha256(receipt["sealed_transition_sha256"])
        and receipt["post_reexec_starttime"] == receipt["starttime"]
        and receipt["post_reexec_proc_cgroup"]
        == _expected_parent_proc_cgroup_path(binding)
        and receipt["pid"] in post["procs"]
        and post["memory_swap_max"] == 0
        and post["memory_swap_current"] == 0,
        "parent-cgroup-post-reexec-values",
    )
    return receipt


def _revalidate_live_parent_cgroup_entry(receipt: object, binding: dict) -> dict:
    """Repeat live membership and swap checks immediately before private IO."""
    value = validate_parent_cgroup_entry(receipt, binding)
    pid = os.getpid()
    live_parent = read_parent_cgroup_snapshot(binding)
    validate_cgroup_snapshot(read_cgroup_snapshot(binding), binding, empty=True)
    need(
        value["pid"] == pid
        and _proc_starttime(pid) == value["post_reexec_starttime"]
        and _proc_cgroup_path(pid) == value["post_reexec_proc_cgroup"]
        == _expected_parent_proc_cgroup_path(binding)
        and pid in live_parent["procs"]
        and live_parent["memory_swap_max"] == 0
        and live_parent["memory_swap_current"] == 0,
        "parent-cgroup-live-post-reexec-drift",
    )
    return value


def _proc_starttime(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    close = raw.rfind(b")")
    need(close > 0, "proc-stat-shape")
    fields = raw[close + 2 :].split()
    need(len(fields) >= 20 and fields[19].isdecimal(), "proc-starttime")
    return int(fields[19])


def _proc_namespaces(pid: int) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for name in NAMESPACE_NAMES:
        value = os.stat(f"/proc/{pid}/ns/{name}", follow_symlinks=True)
        result[name] = [value.st_dev, value.st_ino]
    return result


def _proc_status(pid: int) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def _proc_cmdline(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    need(raw.endswith(b"\x00") and raw != b"\x00", "proc-cmdline-shape")
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in raw[:-1].split(b"\x00")
    ]


def _proc_fds(pid: int) -> list[int]:
    return sorted(int(item) for item in os.listdir(f"/proc/{pid}/fd"))


def _mount_unescape(value: str) -> str:
    for escaped, plain in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(escaped, plain)
    return value


def _proc_mount_evidence(pid: int) -> dict:
    descriptor = os.open(
        f"/proc/{pid}/mountinfo", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        raw = _read_small_fd(
            descriptor, limit=1024 * 1024, category="proc-mountinfo-overflow"
        )
    finally:
        os.close(descriptor)
    need(raw.endswith(b"\n"), "proc-mountinfo-bounds")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise Refused("proc-mountinfo-encoding") from error
    entries: list[dict] = []
    for line in lines:
        need(line.count(" - ") == 1, "proc-mountinfo-separator")
        left_raw, right_raw = line.split(" - ", 1)
        left = left_raw.split()
        right = right_raw.split()
        need(len(left) >= 6 and len(right) == 3, "proc-mountinfo-shape")
        need(left[0].isdecimal() and left[1].isdecimal(), "proc-mountinfo-ids")
        entries.append(
            {
                "mount_id": int(left[0]),
                "parent_id": int(left[1]),
                "device": left[2],
                "root": _mount_unescape(left[3]),
                "mount_point": _mount_unescape(left[4]),
                "mount_options": left[5].split(","),
                "optional_fields": left[6:],
                "fs_type": right[0],
                "mount_source": _mount_unescape(right[1]),
                "super_options": right[2].split(","),
            }
        )
    return {
        "schema": "kpb-w1-proc-mountinfo/v1",
        "raw_sha256": sha256_bytes(raw),
        "entries": entries,
        "entries_sha256": sha256_bytes(canonical(entries)),
    }


def _proc_mount_target_identities(pid: int, plan: dict) -> list[dict]:
    result: list[dict] = []
    for item in plan["mounts"]:
        source = os.fstat(item["fd"])
        target = os.stat(
            f"/proc/{pid}/root{item['destination']}", follow_symlinks=True
        )
        result.append(
            {
                "label": item["label"],
                "fd": item["fd"],
                "destination": item["destination"],
                "source_device": source.st_dev,
                "source_inode": source.st_ino,
                "target_device": target.st_dev,
                "target_inode": target.st_ino,
            }
        )
    return validate_mount_target_identities(result, plan)


def _proc_loaded_elf_mappings(pid: int, bwrap_binding: dict) -> dict:
    descriptor = os.open(
        f"/proc/{pid}/maps", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        raw = _read_small_fd(
            descriptor, limit=4 * 1024**2, category="proc-maps-overflow"
        )
    finally:
        os.close(descriptor)
    need(raw.endswith(b"\n"), "proc-maps-bounds")
    expected = [
        ("bwrap", bwrap_binding["executable"]),
        *(
            (item["elf_name"], item["file"])
            for item in bwrap_binding["loader_closure"]
        ),
    ]
    by_identity: dict[tuple[int, int], list[dict]] = {
        (reference["device"], reference["inode"]): []
        for _, reference in expected
    }
    expected_identities = set(by_identity)
    executable_identities: set[tuple[int, int]] = set()
    try:
        lines = raw.decode("utf-8", errors="surrogateescape").splitlines()
    except UnicodeDecodeError as error:
        raise Refused("proc-maps-encoding") from error
    for line in lines:
        fields = line.split(maxsplit=5)
        need(len(fields) >= 5, "proc-maps-shape")
        device_fields = fields[3].split(":")
        need(
            len(device_fields) == 2
            and all(device_fields)
            and fields[4].isdecimal(),
            "proc-maps-identity",
        )
        device = os.makedev(
            int(device_fields[0], 16), int(device_fields[1], 16)
        )
        identity = (device, int(fields[4]))
        if "x" in fields[1] and identity[1] != 0:
            need(
                identity in expected_identities,
                "proc-maps-unexpected-executable-object",
            )
            executable_identities.add(identity)
        if identity in by_identity:
            by_identity[identity].append(
                {
                    "address": fields[0],
                    "permissions": fields[1],
                    "offset": fields[2],
                    "path": fields[5] if len(fields) == 6 else "",
                }
            )
    objects: list[dict] = []
    for name, reference in expected:
        segments = by_identity[(reference["device"], reference["inode"])]
        need(
            bool(segments)
            and any("x" in item["permissions"] for item in segments),
            "proc-maps-loader-object-missing",
        )
        objects.append(
            {
                "elf_name": name,
                "device": reference["device"],
                "inode": reference["inode"],
                "segments": segments,
            }
        )
    exact_executable_identities = [
        {
            "elf_name": name,
            "device": reference["device"],
            "inode": reference["inode"],
        }
        for name, reference in expected
    ]
    need(
        executable_identities == expected_identities,
        "proc-maps-executable-closure",
    )
    return {
        "schema": "kpb-w1-bwrap-loaded-elf-mappings/v1",
        "raw_sha256": sha256_bytes(raw),
        "objects": objects,
        "objects_sha256": sha256_bytes(canonical(objects)),
        "executable_identities": exact_executable_identities,
    }


def validate_loaded_elf_mappings(evidence: object, bwrap_binding: dict) -> dict:
    need(
        type(evidence) is dict
        and set(evidence)
        == {
            "schema", "raw_sha256", "objects", "objects_sha256",
            "executable_identities",
        }
        and evidence.get("schema")
        == "kpb-w1-bwrap-loaded-elf-mappings/v1"
        and is_sha256(evidence.get("raw_sha256"))
        and type(evidence.get("objects")) is list
        and evidence.get("objects_sha256")
        == sha256_bytes(canonical(evidence.get("objects"))),
        "loaded-elf-mappings-shape",
    )
    assert isinstance(evidence, dict)
    expected = [
        ("bwrap", bwrap_binding["executable"]),
        *(
            (item["elf_name"], item["file"])
            for item in bwrap_binding["loader_closure"]
        ),
    ]
    expected_executable_identities = [
        {
            "elf_name": name,
            "device": reference["device"],
            "inode": reference["inode"],
        }
        for name, reference in expected
    ]
    need(
        evidence["executable_identities"]
        == expected_executable_identities,
        "loaded-elf-executable-closure",
    )
    need(len(evidence["objects"]) == len(expected), "loaded-elf-mappings-count")
    for observed, (name, reference) in zip(
        evidence["objects"], expected, strict=True
    ):
        need(
            type(observed) is dict
            and set(observed) == {"elf_name", "device", "inode", "segments"}
            and observed["elf_name"] == name
            and observed["device"] == reference["device"]
            and observed["inode"] == reference["inode"]
            and type(observed["segments"]) is list
            and bool(observed["segments"]),
            "loaded-elf-mapping-identity",
        )
    return evidence


def _proc_cgroup_path(pid: int) -> str:
    rows = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()
    unified = [line[3:] for line in rows if line.startswith("0::")]
    need(len(unified) == 1 and unified[0].startswith("/"), "proc-cgroup-shape")
    return unified[0]


def _expected_proc_cgroup_path(binding: dict) -> str:
    prefix = "/sys/fs/cgroup"
    path = binding["worker_leaf"]["path"]
    need(path.startswith(prefix + "/"), "cgroup-host-path")
    return path[len(prefix) :]


def _expected_parent_proc_cgroup_path(binding: dict) -> str:
    prefix = "/sys/fs/cgroup"
    path = binding["parent"]["path"]
    need(path.startswith(prefix + "/"), "parent-cgroup-host-path")
    return path[len(prefix) :]


def _assign_stopped_process(
    pid: int,
    pidfd: int,
    starttime: int,
    binding: dict,
) -> dict:
    need(_proc_starttime(pid) == starttime, "cgroup-assignment-pid-substitution")
    _write_cgroup_control(binding, "cgroup.procs", f"{pid}\n".encode("ascii"))
    need(
        _proc_starttime(pid) == starttime
        and _proc_cgroup_path(pid) == _expected_proc_cgroup_path(binding),
        "cgroup-assignment-receipt",
    )
    snapshot = read_cgroup_snapshot(binding)
    need(pid in snapshot["procs"] and snapshot["populated"] == 1, "cgroup-assignment-membership")
    need(hasattr(signal, "pidfd_send_signal"), "pidfd-send-signal-unavailable")
    receipt = {
        "schema": "kpb-w1-cgroup-assignment/v1",
        "pid": pid,
        "starttime_before": starttime,
        "starttime_after": _proc_starttime(pid),
        "pidfd_opened": pidfd >= 0,
        "leaf_path": binding["worker_leaf"]["path"],
        "observed_proc_cgroup": _proc_cgroup_path(pid),
        "leaf_snapshot": snapshot,
        "pdeathsig": "SIGKILL-before-SIGSTOP",
        "assignment_verified": True,
    }
    validate_cgroup_assignment_receipt(receipt, binding)
    signal.pidfd_send_signal(pidfd, signal.SIGCONT)
    return receipt


def _close_except(allowed: set[int]) -> None:
    for raw in os.listdir("/proc/self/fd"):
        descriptor = int(raw)
        if descriptor not in allowed:
            try:
                os.close(descriptor)
            except OSError as error:
                need(error.errno == errno.EBADF, "child-close-fds")


def _set_parent_death_signal(expected_parent_pid: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    need(
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) == 0,
        "child-pdeathsig",
    )
    need(
        expected_parent_pid > 1 and os.getppid() == expected_parent_pid,
        "child-parent-died-before-pdeathsig",
    )


def _contain_unreturned_fork_child(pid: int) -> None:
    """Kill and reap a known direct child before its PID can be forgotten."""
    need(pid > 1, "fork-parent-cleanup-pid")
    pidfd = -1
    cleanup_errors: list[BaseException] = []
    try:
        try:
            pidfd = os.pidfd_open(pid, 0)
        except OSError:
            # The unreaped direct-child PID cannot be reused.  A PID kill plus
            # exact wait4 is therefore still safe if pidfd_open itself failed.
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError as error:
                if error.errno != errno.ESRCH:
                    cleanup_errors.append(error)
        else:
            if not hasattr(signal, "pidfd_send_signal"):
                cleanup_errors.append(
                    Refused("fork-parent-cleanup-pidfd-signal")
                )
            else:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        cleanup_errors.append(error)
            try:
                _wait_pidfd_death(pidfd, seconds=POST_EXIT_DRAIN_SECONDS)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            waited = _reap_child_bounded(
                pid, seconds=POST_EXIT_DRAIN_SECONDS
            )
            need(waited[0] == pid, "fork-parent-cleanup-wait4")
        except BaseException as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            raise Refused("fork-parent-cleanup-unproven") from cleanup_errors[0]
    finally:
        if pidfd >= 0:
            os.close(pidfd)


def _fork_stopped_bwrap(
    plan: dict,
    *,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
) -> tuple[int, int]:
    """Fork, arm PDEATHSIG first, attest it, then stop before FD setup/exec."""
    receipt_read, receipt_write = os.pipe2(os.O_CLOEXEC)
    expected_parent_pid = os.getpid()
    try:
        pid = os.fork()
    except BaseException:
        os.close(receipt_read)
        os.close(receipt_write)
        raise
    if pid != 0:
        try:
            os.close(receipt_write)
        except BaseException as original_error:
            try:
                _contain_unreturned_fork_child(pid)
            finally:
                for descriptor in (receipt_read, receipt_write):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            raise original_error
        return pid, receipt_read
    try:
        os.close(receipt_read)
        _set_parent_death_signal(expected_parent_pid)
        need(os.write(receipt_write, b"P") == 1, "child-pdeathsig-receipt")
        os.close(receipt_write)
        os.kill(os.getpid(), signal.SIGSTOP)
        os.dup2(stdin_fd, 0)
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        allowed = {0, 1, 2, *plan["passed_fds"]}
        for descriptor in allowed:
            os.set_inheritable(descriptor, True)
        _close_except(allowed)
        os.execve(plan["command"][0], plan["command"], {})
    except BaseException:
        os._exit(127)
    os._exit(127)


def _read_deadline(
    descriptor: int,
    *,
    deadline: float,
    maximum: int,
    complete,
    category: str,
) -> bytes:
    raw = bytearray()
    selector = selectors.DefaultSelector()
    os.set_blocking(descriptor, False)
    selector.register(descriptor, selectors.EVENT_READ)
    try:
        while not complete(raw):
            remaining = deadline - time.monotonic()
            need(remaining > 0, category)
            ready = selector.select(remaining)
            need(bool(ready), category)
            block = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            need(bool(block), f"{category}-eof")
            raw.extend(block)
            need(len(raw) <= maximum, f"{category}-overflow")
        return bytes(raw)
    finally:
        selector.close()


def _read_pdeathsig_receipt(descriptor: int, *, deadline: float) -> None:
    raw = _read_deadline(
        descriptor,
        deadline=deadline,
        maximum=1,
        complete=lambda value: len(value) == 1,
        category="child-pdeathsig-timeout",
    )
    need(raw == b"P", "child-pdeathsig-receipt")


def _wait_stopped_bounded(pid: int, *, deadline: float) -> None:
    while True:
        stopped_pid, stopped_status = os.waitpid(
            pid, os.WUNTRACED | os.WNOHANG
        )
        if stopped_pid != 0:
            need(
                stopped_pid == pid
                and os.WIFSTOPPED(stopped_status)
                and os.WSTOPSIG(stopped_status) == signal.SIGSTOP,
                "bwrap-pre-exec-stop",
            )
            return
        need(time.monotonic() < deadline, "bwrap-pre-exec-stop-timeout")
        time.sleep(0.01)


def _read_start_status(status_fd: int, *, deadline: float) -> tuple[bytes, int]:
    raw = _read_deadline(
        status_fd,
        deadline=deadline,
        maximum=MAX_STATUS_BYTES,
        complete=lambda value: b"\n" in value,
        category="bwrap-status-readiness-timeout",
    )
    first = bytes(raw[: raw.index(b"\n") + 1])
    row = decode_unique_json(first, category="bwrap-start-status")
    need(type(row) is dict and type(row.get("child-pid")) is int, "bwrap-start-child-pid")
    return bytes(raw), row["child-pid"]


def _read_worker_ready(stdout_fd: int, *, role: str, deadline: float) -> dict:
    raw = _read_deadline(
        stdout_fd,
        deadline=deadline,
        maximum=1024,
        complete=lambda value: value.endswith(b"\n"),
        category="worker-readiness-timeout",
    )
    need(raw.startswith(WORKER_READY_PREFIX), "worker-ready-prefix")
    value = decode_canonical_json(
        bytes(raw[len(WORKER_READY_PREFIX) :]), category="worker-ready"
    )
    need(
        type(value) is dict
        and set(value)
        == {
            "schema", "role", "namespace_pid", "fds", "caps_zero",
            "no_new_privs", "seccomp", "seccomp_filters", "seccomp_probes",
        }
        and value["schema"] == "kpb-w1-worker-ready/v1"
        and value["role"] == role
        and value["namespace_pid"] == 1
        and value["fds"] == [0, 1, 2]
        and value["caps_zero"] is True
        and value["no_new_privs"] == 1
        and value["seccomp"] == 2
        and value["seccomp_filters"] == 1
        and value["seccomp_probes"]
        == {"getpid": True, "pidfd_open": True, "socket": True},
        "worker-ready-values",
    )
    return value


def _drain_and_wait4(
    pid: int,
    pidfd: int,
    owner_cancel_fd: int,
    streams: dict[int, tuple[str, int]],
    *,
    initial: dict[str, bytes] | None = None,
) -> tuple[dict[str, bytes], tuple[int, int, resource.struct_rusage], bool]:
    selector = selectors.DefaultSelector()
    buffers = {
        name: bytearray((initial or {}).get(name, b""))
        for name, _ in streams.values()
    }
    for descriptor, (name, limit) in streams.items():
        need(len(buffers[name]) <= limit, f"{name}-overflow")
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ, ("stream", name, limit))
    selector.register(pidfd, selectors.EVENT_READ, ("pidfd", "", 0))
    selector.register(
        owner_cancel_fd, selectors.EVENT_READ, ("owner-cancel", "", 0)
    )
    death_observed = False
    post_exit_deadline: float | None = None
    try:
        while selector.get_map():
            timeout = None
            if death_observed:
                assert post_exit_deadline is not None
                timeout = max(0.0, post_exit_deadline - time.monotonic())
            ready = selector.select(timeout)
            need(
                bool(ready) or not death_observed,
                "post-exit-stream-drain-timeout",
            )
            for key, _ in ready:
                kind, name, limit = key.data
                if kind == "pidfd":
                    selector.unregister(key.fd)
                    death_observed = True
                    post_exit_deadline = time.monotonic() + POST_EXIT_DRAIN_SECONDS
                    continue
                if kind == "owner-cancel":
                    os.read(key.fd, 4096)
                    raise OwnerCancelled("explicit-owner-cancellation")
                block = os.read(key.fd, 64 * 1024)
                if not block:
                    selector.unregister(key.fd)
                    os.close(key.fd)
                    continue
                bounded_append(
                    buffers[name],
                    block,
                    limit=limit,
                    category=f"{name}-overflow",
                )
            if death_observed and not any(
                key.data[0] == "stream"
                for key in selector.get_map().values()
            ):
                try:
                    selector.unregister(owner_cancel_fd)
                except KeyError:
                    pass
        need(death_observed, "pidfd-death-not-observed")
        waited = os.wait4(pid, 0)
        need(waited[0] == pid, "wait4-pid")
        return (
            {name: bytes(value) for name, value in buffers.items()},
            waited,
            True,
        )
    finally:
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fd)
                if key.data[0] == "stream":
                    os.close(key.fd)
            except OSError:
                pass
        selector.close()


def _collect_launch_evidence(
    *,
    plan: dict,
    bwrap_pid: int,
    bwrap_pidfd: int,
    bwrap_starttime: int,
    payload_pid: int,
    payload_pidfd: int,
    payload_starttime: int,
    host_namespaces: dict,
    cgroup_binding: dict,
    bwrap_reference: dict,
    bwrap_binding: dict,
    cgroup_assignment: dict,
    launch_contract: dict,
) -> dict:
    status = _proc_status(payload_pid)
    capabilities = {
        key: int(status.get(key, "-1"), 16)
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    }
    executable = os.stat(f"/proc/{bwrap_pid}/exe", follow_symlinks=True)
    apparmor_label = Path(f"/proc/{bwrap_pid}/attr/current").read_text(
        encoding="ascii"
    ).strip()
    evidence = {
        "bwrap_pid": bwrap_pid,
        "bwrap_starttime_before": bwrap_starttime,
        "bwrap_starttime_after": _proc_starttime(bwrap_pid),
        "bwrap_pidfd_opened": bwrap_pidfd >= 0,
        "payload_pid": payload_pid,
        "payload_starttime_before": payload_starttime,
        "payload_starttime_after": _proc_starttime(payload_pid),
        "payload_pidfd_opened": payload_pidfd >= 0,
        "status_child_pid": payload_pid,
        "host_namespaces": host_namespaces,
        "payload_namespaces": _proc_namespaces(payload_pid),
        "capabilities": capabilities,
        "no_new_privs": int(status.get("NoNewPrivs", "-1")),
        "seccomp_mode": int(status.get("Seccomp", "-1")),
        "seccomp_filter_count": int(status.get("Seccomp_filters", "-1")),
        "cgroup_path": _proc_cgroup_path(payload_pid),
        "expected_cgroup_path": _expected_proc_cgroup_path(cgroup_binding),
        "cgroup_assignment": cgroup_assignment,
        "payload_cmdline": _proc_cmdline(payload_pid),
        "payload_fds": _proc_fds(payload_pid),
        "bwrap_executable_sha256": bwrap_reference["sha256"],
        "expected_bwrap_sha256": bwrap_reference["sha256"],
        "bwrap_executable_device": executable.st_dev,
        "expected_bwrap_device": bwrap_reference["device"],
        "bwrap_executable_inode": executable.st_ino,
        "expected_bwrap_inode": bwrap_reference["inode"],
        "bwrap_apparmor_label": apparmor_label,
        "expected_bwrap_apparmor_label": bwrap_binding["expected_apparmor_label"],
        "barrier_release_sequence": "bwrap-block-then-worker-ready-then-pidfd-namespace-capability-cgroup-fd-checks",
        "status_json_unique_keys": True,
        "launch_contract": launch_contract,
        "mount_evidence": _proc_mount_evidence(payload_pid),
        "mount_target_identities": _proc_mount_target_identities(
            payload_pid, plan
        ),
        "loaded_elf_mappings": _proc_loaded_elf_mappings(
            bwrap_pid, bwrap_binding
        ),
    }
    return validate_launch_evidence(
        evidence, plan, host_namespaces, cgroup_binding, bwrap_binding
    )


def _wait_pidfd_death(pidfd: int, *, seconds: float) -> None:
    need(pidfd >= 0 and seconds > 0, "pidfd-death-wait-arguments")
    selector = selectors.DefaultSelector()
    selector.register(pidfd, selectors.EVENT_READ)
    try:
        need(bool(selector.select(seconds)), "pidfd-death-timeout")
    finally:
        selector.close()


def _reap_child_bounded(
    pid: int, *, seconds: float
) -> tuple[int, int, resource.struct_rusage]:
    deadline = time.monotonic() + seconds
    while True:
        waited = os.wait4(pid, os.WNOHANG)
        if waited[0] != 0:
            need(waited[0] == pid, "failure-wait4-pid")
            return waited
        need(time.monotonic() < deadline, "failure-wait4-timeout")
        time.sleep(0.01)


def contain_failed_sandbox(
    *,
    payload_pidfd: int,
    bwrap_pidfd: int,
    payload_pid: int,
    bwrap_pid: int,
    cgroup_kill_fd: int,
    cgroup_binding: dict,
    bwrap_waited: tuple[int, int, resource.struct_rusage] | None = None,
) -> dict:
    """Kill, prove PIDFD death, reap exactly once, then prove the leaf empty."""
    direct_kill_errors: list[OSError] = []
    cleanup_errors: list[BaseException] = []
    for descriptor, fallback_pid in (
        (payload_pidfd, payload_pid if payload_pid > 0 else None),
        (bwrap_pidfd, bwrap_pid if bwrap_waited is None else None),
    ):
        try:
            if descriptor >= 0 and hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            elif fallback_pid is not None:
                os.kill(fallback_pid, signal.SIGKILL)
        except OSError as error:
            if error.errno != errno.ESRCH:
                direct_kill_errors.append(error)
    # Every cleanup fact is attempted even if an earlier fact fails.  None of
    # kill, PIDFD death, wait4, or leaf emptiness substitutes for another.
    try:
        trigger_cgroup_kill(cgroup_kill_fd)
    except BaseException as error:
        cleanup_errors.append(error)
    bwrap_death_observed = False
    if bwrap_pidfd >= 0:
        try:
            _wait_pidfd_death(bwrap_pidfd, seconds=POST_EXIT_DRAIN_SECONDS)
            bwrap_death_observed = True
        except BaseException as error:
            cleanup_errors.append(error)
    else:
        cleanup_errors.append(Refused("failure-bwrap-pidfd-unavailable"))
    payload_death_observed = payload_pid <= 0
    if payload_pid > 0 and payload_pidfd < 0:
        cleanup_errors.append(Refused("failure-payload-pidfd-unavailable"))
    if payload_pidfd >= 0:
        try:
            _wait_pidfd_death(payload_pidfd, seconds=POST_EXIT_DRAIN_SECONDS)
            payload_death_observed = True
        except BaseException as error:
            cleanup_errors.append(error)
    try:
        if bwrap_waited is None:
            waited = (
                os.wait4(bwrap_pid, 0)
                if bwrap_death_observed
                else _reap_child_bounded(
                    bwrap_pid, seconds=POST_EXIT_DRAIN_SECONDS
                )
            )
        else:
            waited = bwrap_waited
        need(waited[0] == bwrap_pid, "failure-wait4-pid")
    except BaseException as error:
        cleanup_errors.append(error)
        waited = None
    try:
        leaf_after = verify_cgroup_empty_bounded(cgroup_binding)
    except BaseException as error:
        cleanup_errors.append(error)
        leaf_after = None
    if cleanup_errors:
        raise Refused("failure-containment-unproven") from cleanup_errors[0]
    if direct_kill_errors:
        raise Refused("failure-direct-kill-error") from direct_kill_errors[0]
    assert waited is not None and leaf_after is not None
    return {
        "schema": "kpb-w1-failure-containment/v1",
        "bwrap_pid": bwrap_pid,
        "bwrap_pidfd_death_observed": bwrap_death_observed,
        "payload_pidfd_death_observed": payload_death_observed,
        "wait4_pid": waited[0],
        "wait4_exactly_once": True,
        "leaf_empty": leaf_after,
    }


def _install_owner_cancellation() -> tuple[int, int, dict[int, object]]:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    previous: dict[int, object] = {}

    def notify(signum, _frame) -> None:
        try:
            os.write(write_fd, bytes((signum & 0xFF,)))
        except BlockingIOError:
            pass

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, notify)
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    return read_fd, write_fd, previous


def _restore_owner_cancellation(
    read_fd: int, write_fd: int, previous: dict[int, object]
) -> None:
    restore_error: BaseException | None = None
    for signum, handler in previous.items():
        try:
            signal.signal(signum, handler)
        except BaseException as error:
            restore_error = error
    os.close(read_fd)
    os.close(write_fd)
    if restore_error is not None:
        raise Refused("owner-cancellation-handler-restore") from restore_error


def _assert_prestart_release_allowed(
    owner_cancel_fd: int, *, deadline: float
) -> None:
    """Refuse an expired setup or queued owner cancel at the last barrier."""
    need(
        time.monotonic() < deadline,
        "bwrap-prestart-deadline-expired-before-worker-release",
    )
    try:
        queued = os.read(owner_cancel_fd, 4096)
    except BlockingIOError:
        queued = None
    if queued is not None:
        if queued:
            raise OwnerCancelled("explicit-owner-cancellation-before-worker-release")
        raise Refused("owner-cancellation-channel-eof-before-worker-release")
    need(
        time.monotonic() < deadline,
        "bwrap-prestart-deadline-expired-before-worker-release",
    )


def supervise_sandbox(
    plan: dict,
    *,
    stdin_raw: bytes,
    cgroup_binding: dict,
    bwrap_reference: dict,
    bwrap_binding: dict,
    control_pipes: tuple[int, int, int, int],
) -> dict:
    """Directly supervise one already authenticated descriptor-only plan."""
    validate_sandbox_plan(plan)
    before = capture_cgroup_snapshot(cgroup_binding)
    validate_cgroup_snapshot(before["leaf"], cgroup_binding, empty=True)
    launch_contract = canonical_launch_contract(plan, stdin_raw)
    host_namespaces = _proc_namespaces(os.getpid())
    cgroup_kill_fd = open_cgroup_kill(cgroup_binding)
    owner_cancel_read = owner_cancel_write = -1
    previous_handlers: dict[int, object] = {}
    setup_fds: list[int] = []
    try:
        owner_cancel_read, owner_cancel_write, previous_handlers = (
            _install_owner_cancellation()
        )
        stdin_read, stdin_write = os.pipe2(os.O_CLOEXEC)
        setup_fds.extend((stdin_read, stdin_write))
        stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
        setup_fds.extend((stdout_read, stdout_write))
        stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
        setup_fds.extend((stderr_read, stderr_write))
        need(
            type(control_pipes) is tuple
            and len(control_pipes) == 4
            and all(type(item) is int and item >= 0 for item in control_pipes),
            "sandbox-control-pipes",
        )
        status_read, status_write, barrier_read, barrier_write = control_pipes
        need(
            plan["status_fd"] == status_write
            and plan["barrier_fd"] == barrier_read,
            "sandbox-plan-pipe-binding",
        )
    except BaseException:
        control_cleanup = control_pipes if type(control_pipes) is tuple else ()
        for descriptor in (*setup_fds, *control_cleanup):
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.close(cgroup_kill_fd)
        if owner_cancel_read >= 0:
            _restore_owner_cancellation(
                owner_cancel_read, owner_cancel_write, previous_handlers
            )
        raise
    try:
        bwrap_pid, pdeath_receipt_fd = _fork_stopped_bwrap(
            plan,
            stdin_fd=stdin_read,
            stdout_fd=stdout_write,
            stderr_fd=stderr_write,
        )
    except BaseException:
        for descriptor in (
            stdin_read, stdin_write, stdout_read, stdout_write, stderr_read,
            stderr_write, status_read, status_write, barrier_read, barrier_write,
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.close(cgroup_kill_fd)
        _restore_owner_cancellation(
            owner_cancel_read, owner_cancel_write, previous_handlers
        )
        raise
    bwrap_pidfd = -1
    payload_pidfd = -1
    payload_pid = -1
    waited: tuple[int, int, resource.struct_rusage] | None = None
    try:
        bwrap_pidfd = os.pidfd_open(bwrap_pid, 0)
        for descriptor in (
            stdin_read, stdout_write, stderr_write, status_write, barrier_read
        ):
            os.close(descriptor)
        setup_deadline = time.monotonic() + PRESTART_DEADLINE_SECONDS
        _read_pdeathsig_receipt(pdeath_receipt_fd, deadline=setup_deadline)
        os.close(pdeath_receipt_fd)
        pdeath_receipt_fd = -1
        _wait_stopped_bounded(bwrap_pid, deadline=setup_deadline)
        bwrap_starttime = _proc_starttime(bwrap_pid)
        cgroup_assignment = _assign_stopped_process(
            bwrap_pid, bwrap_pidfd, bwrap_starttime, cgroup_binding
        )
        status_prefix, payload_pid = _read_start_status(
            status_read, deadline=setup_deadline
        )
        payload_pidfd = os.pidfd_open(payload_pid, 0)
        payload_starttime = _proc_starttime(payload_pid)
        # bwrap's own barrier is before seccomp and payload exec.  It is only
        # the first barrier: release it, then wait for the fixed worker to
        # attest its exact FD/capability/seccomp state and block on stdin.
        need(os.write(barrier_write, b"\x01") == 1, "bwrap-barrier-release")
        os.close(barrier_write)
        barrier_write = -1
        worker_ready = _read_worker_ready(
            stdout_read, role=plan["worker_role"], deadline=setup_deadline
        )
        launch = _collect_launch_evidence(
            plan=plan,
            bwrap_pid=bwrap_pid,
            bwrap_pidfd=bwrap_pidfd,
            bwrap_starttime=bwrap_starttime,
            payload_pid=payload_pid,
            payload_pidfd=payload_pidfd,
            payload_starttime=payload_starttime,
            host_namespaces=host_namespaces,
            cgroup_binding=cgroup_binding,
            bwrap_reference=bwrap_reference,
            bwrap_binding=bwrap_binding,
            cgroup_assignment=cgroup_assignment,
            launch_contract=launch_contract,
        )
        start_frame = sandbox_start_frame(plan, stdin_raw)
        need(
            sha256_bytes(start_frame) == launch_contract["start_frame_sha256"],
            "sandbox-start-frame-contract",
        )
        # This is the proof/verifier worker's actual start barrier.  Launch
        # evidence collection may itself take time or receive a queued owner
        # signal, so repeat both checks immediately before releasing it.
        _assert_prestart_release_allowed(
            owner_cancel_read, deadline=setup_deadline
        )
        need(
            os.write(stdin_write, start_frame) == len(start_frame),
            "sandbox-stdin-write",
        )
        os.close(stdin_write)
        stdin_write = -1
        stdout_limit = (
            MAX_PROOF_STDOUT_BYTES
            if plan["role"] == "proof"
            else MAX_VERIFIER_STDOUT_BYTES
        )
        buffers, waited, pidfd_death_observed = _drain_and_wait4(
            bwrap_pid,
            bwrap_pidfd,
            owner_cancel_read,
            {
                stdout_read: ("stdout", stdout_limit),
                stderr_read: ("stderr", MAX_STDERR_BYTES),
                status_read: ("status", MAX_STATUS_BYTES),
            },
            initial={"status": status_prefix},
        )
        _wait_pidfd_death(payload_pidfd, seconds=POST_EXIT_DRAIN_SECONDS)
        rows = parse_status_stream(buffers["status"])
        exit_code = next(row["exit-code"] for row in rows if type(row.get("exit-code")) is int)
        status_value = waited[1]
        after = capture_cgroup_snapshot(cgroup_binding)
        validate_cgroup_snapshot(after["leaf"], cgroup_binding, empty=True)
        wait = {
            "wait4_pid": waited[0],
            "exited": os.WIFEXITED(status_value),
            "exit_code": os.WEXITSTATUS(status_value) if os.WIFEXITED(status_value) else None,
            "term_signal": os.WTERMSIG(status_value) if os.WIFSIGNALED(status_value) else 0,
            "status_exit_code": exit_code,
            "stdout_eof": True,
            "stderr_eof": True,
            "status_eof": True,
            "zero_descendants": after["leaf"]["populated"] == 0 and after["leaf"]["procs"] == [],
            "cgroup_populated": after["leaf"]["populated"],
            "cgroup_procs": after["leaf"]["procs"],
            "parent_memory_swap_current": after["parent"]["memory_swap_current"],
            "parent_memory_swap_peak": after["parent"]["memory_swap_peak"],
            "group_kill_armed": cgroup_binding["worker_leaf"]["cgroup_kill"],
            "max_rss_kib": waited[2].ru_maxrss,
            "pidfd_death_observed": pidfd_death_observed,
            "payload_pidfd_death_observed": True,
            "wait4_exactly_once": True,
            "leaf_empty_supplemental": True,
            "cgroup_assignment_verified": cgroup_assignment["assignment_verified"],
        }
        validate_wait_evidence(wait, expected_pid=bwrap_pid)
        need(buffers["stderr"] == b"", "sandbox-stderr")
        return {
            "stdout": buffers["stdout"],
            "worker_ready": worker_ready,
            "launch_evidence": launch,
            "wait_evidence": wait,
            "verified_wait_evidence": True,
            "cgroup_after": after,
            "cgroup_before": before,
            "cgroup_binding": cgroup_binding,
            "launch_contract": launch_contract,
            "plan": plan,
            "host_namespaces": host_namespaces,
        }
    except BaseException as original_error:
        contain_failed_sandbox(
            payload_pidfd=payload_pidfd,
            bwrap_pidfd=bwrap_pidfd,
            payload_pid=payload_pid,
            bwrap_pid=bwrap_pid,
            cgroup_kill_fd=cgroup_kill_fd,
            cgroup_binding=cgroup_binding,
            bwrap_waited=waited,
        )
        raise original_error
    finally:
        if pdeath_receipt_fd >= 0:
            try:
                os.close(pdeath_receipt_fd)
            except OSError:
                pass
        if stdin_write >= 0:
            try:
                os.close(stdin_write)
            except OSError:
                pass
        if barrier_write >= 0:
            try:
                os.close(barrier_write)
            except OSError:
                pass
        for descriptor in (
            stdin_read, stdin_write, stdout_read, stdout_write, stderr_read,
            stderr_write, status_read, status_write, barrier_read,
            barrier_write,
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
        for descriptor in (payload_pidfd, bwrap_pidfd):
            if descriptor >= 0:
                os.close(descriptor)
        os.close(cgroup_kill_fd)
        _restore_owner_cancellation(
            owner_cancel_read, owner_cancel_write, previous_handlers
        )


def _authenticate_loader_closure(bwrap_binding: dict) -> list[dict]:
    result: list[dict] = []
    for item in bwrap_binding["loader_closure"]:
        descriptor, observed = stable_open(
            item["file"], max_bytes=256 * 1024**2
        )
        try:
            elf = parse_elf_descriptor(descriptor)
        finally:
            os.close(descriptor)
        graph_name = (
            "ld-linux-x86-64.so.2"
            if item["elf_name"] == "PT_INTERP"
            else item["elf_name"]
        )
        need(
            elf["build_id"] == item["elf_build_id"]
            and elf["pt_interp"] == item["elf_pt_interp"]
            and elf["dt_needed"]
            == FIXED_DEBIAN_BWRAP_DEPENDENCY_GRAPH[graph_name],
            "bwrap-loader-live-elf-metadata",
        )
        result.append(
            {
                "elf_name": item["elf_name"],
                "elf_build_id": item["elf_build_id"],
                "elf_pt_interp": item["elf_pt_interp"],
                "elf_needed": item["elf_needed"],
                "destination": item["destination"],
                "file": observed,
            }
        )
    need(
        tuple(result) == bwrap_binding["loader_closure"]
        and sha256_bytes(canonical(tuple(result)))
        == bwrap_binding["loader_closure_sha256"],
        "bwrap-loader-closure-live-hash",
    )
    return result


def _authenticate_bwrap_elf_descriptor(
    descriptor: int, bwrap_binding: dict
) -> dict:
    elf = parse_elf_descriptor(descriptor)
    need(
        elf
        == {
            "build_id": FIXED_DEBIAN_BWRAP_BUILD_ID,
            "pt_interp": FIXED_DEBIAN_BWRAP_PT_INTERP,
            "dt_needed": list(FIXED_DEBIAN_BWRAP_DT_NEEDED),
        }
        and bwrap_binding["elf_build_id"] == elf["build_id"]
        and bwrap_binding["elf_pt_interp"] == elf["pt_interp"]
        and bwrap_binding["elf_dt_needed"] == elf["dt_needed"],
        "bwrap-live-elf-metadata",
    )
    return elf


def _parse_apparmor_includes(raw: bytes, source_path: str) -> list[dict]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refused("apparmor-source-encoding") from error
    result: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#include"):
            tail = stripped[len("#include") :].strip()
        elif stripped.startswith("include"):
            tail = stripped[len("include") :].strip()
        else:
            continue
        optional = False
        if tail.startswith("if exists"):
            optional = True
            tail = tail[len("if exists") :].strip()
        if tail.startswith("<") and tail.endswith(">"):
            target = "/etc/apparmor.d/" + tail[1:-1]
        elif tail.startswith('"') and tail.endswith('"'):
            quoted = tail[1:-1]
            target = (
                quoted
                if quoted.startswith("/")
                else str(PurePosixPath(source_path).parent / quoted)
            )
        else:
            raise Refused("apparmor-include-syntax")
        normalized = str(PurePosixPath(target))
        need(
            normalized.startswith("/etc/apparmor.d/")
            and ".." not in PurePosixPath(normalized).parts
            and normalized != source_path,
            "apparmor-include-path",
        )
        result.append({"path": normalized, "optional": optional})
    need(
        len(result) == len({item["path"] for item in result}),
        "apparmor-include-duplicate",
    )
    return result


def _authenticate_apparmor_closure(bwrap_binding: dict) -> dict:
    result: list[dict] = []
    observed_graph: dict[str, list[str]] = {}
    observed_optional_missing: list[str] = []
    closure_paths = {
        item["path"] for item in bwrap_binding["apparmor_source_closure"]
    }
    root_raw: bytes | None = None
    for reference in bwrap_binding["apparmor_source_closure"]:
        raw, observed = stable_read(reference, max_bytes=4 * 1024**2)
        result.append(observed)
        if reference["path"] == FIXED_BWRAP_APPARMOR_ROOT:
            root_raw = raw
        includes = _parse_apparmor_includes(raw, reference["path"])
        observed_graph[reference["path"]] = [
            item["path"] for item in includes
        ]
        for include in includes:
            if include["path"] in closure_paths:
                continue
            need(include["optional"] is True, "apparmor-required-include-missing")
            need(
                not os.path.lexists(include["path"]),
                "apparmor-optional-include-unbound",
            )
            observed_optional_missing.append(include["path"])
    need(
        tuple(result) == bwrap_binding["apparmor_source_closure"]
        and sha256_bytes(canonical(tuple(result)))
        == bwrap_binding["apparmor_source_closure_sha256"]
        and observed_graph == bwrap_binding["apparmor_include_graph"]
        and sorted(observed_optional_missing)
        == bwrap_binding["apparmor_optional_missing"],
        "bwrap-apparmor-source-live-hash",
    )
    need(root_raw is not None, "apparmor-root-source-missing")
    root_text = root_raw.decode("utf-8")
    attachment = re.search(
        r"(?m)^\s*profile\s+bwrap\s+/usr/bin/bwrap(?:\s+flags=\(([^\n]*)\))?\s*\{",
        root_text,
    )
    need(
        attachment is not None
        and not {"unconfined", "complain"}.intersection(
            {
                item.strip()
                for item in (attachment.group(1) or "").split(",")
                if item.strip()
            }
        ),
        "apparmor-root-attachment",
    )
    return {
        "files": result,
        "include_graph": observed_graph,
        "optional_missing": sorted(observed_optional_missing),
        "root_attachment": {
            "profile": FIXED_BWRAP_APPARMOR_PROFILE,
            "path": str(APPROVED_BWRAP_PATH),
            "mode": "enforce",
            "expected_label": FIXED_BWRAP_APPARMOR_LABEL,
        },
    }


def authenticate_role_build_receipt(role: str, bindings: dict) -> dict:
    need(role in {"proof", "verifier"}, "build-receipt-role")
    role_build = bindings["build"][role]
    raw, observed = stable_read(
        role_build["build_receipt"], max_bytes=256 * 1024
    )
    value = decode_canonical_json(raw, category=f"{role}-build-receipt")
    expected = {
        "schema": "kpb-frozen-w1-role-build-receipt/v1",
        "role": role,
        "binary": role_build["binary"],
        "source_closure_sha256": role_build["source_closure_sha256"],
        "runtime_closure_sha256": sha256_bytes(
            canonical(bindings["runtime_closure"][role])
        ),
        "independently_reviewed": True,
        "test_only": True,
    }
    need(value == expected, f"{role}-build-receipt-values")
    return {
        "file": observed,
        "canonical_sha256": sha256_bytes(raw),
        "value": value,
    }


def execute_role(
    role: str,
    *,
    stdin_raw: bytes,
    bindings: dict,
    parent_cgroup_entry: dict,
) -> dict:
    """Open exact inputs, construct sealed control FDs, and supervise one role."""
    need(role in {"proof", "verifier"}, "execute-role")
    _revalidate_live_parent_cgroup_entry(
        parent_cgroup_entry, bindings["cgroup"]
    )
    need(
        _proc_starttime(os.getpid()) == parent_cgroup_entry["starttime"]
        and _proc_cgroup_path(os.getpid())
        == _expected_parent_proc_cgroup_path(bindings["cgroup"]),
        "execute-parent-cgroup-live-binding",
    )
    before = capture_cgroup_snapshot(bindings["cgroup"])
    validate_cgroup_snapshot(before["leaf"], bindings["cgroup"], empty=True)
    loader_before = _authenticate_loader_closure(bindings["bwrap"])
    apparmor_before = _authenticate_apparmor_closure(bindings["bwrap"])
    build_receipt = authenticate_role_build_receipt(role, bindings)
    opened: list[int] = []
    pipe_fds: tuple[int, int, int, int] | None = None
    try:
        bwrap_fd, bwrap_reference = stable_open(bindings["bwrap"]["executable"])
        opened.append(bwrap_fd)
        bwrap_elf = _authenticate_bwrap_elf_descriptor(
            bwrap_fd, bindings["bwrap"]
        )
        binary_fd, _ = sealed_copy(
            bindings["build"][role]["binary"],
            name=f"kpb-w1-{role}-binary",
            max_bytes=256 * 1024**2,
        )
        opened.append(binary_fd)
        runtime_fds_list: list[tuple[str, int]] = []
        for item in bindings["runtime_closure"][role]:
            descriptor, _ = stable_open(item["file"])
            opened.append(descriptor)
            runtime_fds_list.append((item["destination"], descriptor))
        private_labels = PROOF_PRIVATE_LABELS if role == "proof" else VERIFIER_PRIVATE_LABELS
        artifact_fds: dict[str, int] = {}
        for label in private_labels:
            descriptor, _ = open_immutable_artifact(
                bindings["artifacts"][label], category=f"artifact-{label}"
            )
            opened.append(descriptor)
            artifact_fds[label] = descriptor
        worker_fd = sealed_memfd("kpb-w1-worker", WORKER_SOURCE.encode())
        seccomp_fd = sealed_memfd("kpb-w1-seccomp", seccomp_filter_bytes())
        opened.extend((worker_fd, seccomp_fd))
        need(
            sha256_bytes(WORKER_SOURCE.encode()) == bindings["worker_source"]
            and sha256_bytes(seccomp_filter_bytes())
            == bindings["seccomp"][role]["sha256"],
            "sealed-control-source-binding",
        )
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
        pipe_fds = (status_read, status_write, barrier_read, barrier_write)
        plan = build_sandbox_plan(
            role,
            bwrap_fd=bwrap_fd,
            binary_fd=binary_fd,
            runtime_fds=tuple(runtime_fds_list),
            artifact_fds=artifact_fds,
            worker_fd=worker_fd,
            seccomp_fd=seccomp_fd,
            status_fd=status_write,
            barrier_fd=barrier_read,
        )
        pipe_bundle = pipe_fds
        result = supervise_sandbox(
            plan,
            stdin_raw=stdin_raw,
            cgroup_binding=bindings["cgroup"],
            bwrap_reference=bwrap_reference,
            bwrap_binding=bindings["bwrap"],
            control_pipes=pipe_bundle,
        )
        pipe_fds = None  # supervise_sandbox consumed and closed the bundle
        need(before == result["cgroup_before"], "cgroup-pre-launch-drift")
        validate_cgroup_pair(
            result["cgroup_before"], result["cgroup_after"], bindings["cgroup"]
        )
        return result | {
            "parent_cgroup_entry": parent_cgroup_entry,
            "build_receipt": build_receipt,
            "bwrap_loader_closure": loader_before,
            "bwrap_elf": bwrap_elf,
            "apparmor_source_closure": apparmor_before,
        }
    finally:
        if pipe_fds is not None:
            for descriptor in pipe_fds:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for descriptor in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass
        loader_after = _authenticate_loader_closure(bindings["bwrap"])
        apparmor_after = _authenticate_apparmor_closure(bindings["bwrap"])
        need(loader_after == loader_before, "bwrap-loader-closure-pre-post-drift")
        need(
            apparmor_after == apparmor_before,
            "bwrap-apparmor-source-pre-post-drift",
        )


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
        "internal_osrng_nonzero_blinding", "proof_generated",
        "independent_vk_rehashed", "independent_verification",
        "wrong_public_inputs_rejected", "mutated_proof_rejected",
        "assignment_serialized", "secret_fingerprint_emitted", "setup_executed",
        "network_communication", "funds", "testnet", "full_secret_zeroization",
        "error_path_source_zeroization_complete", "abort_oom_zeroization",
        "receipt_is_authority", "public_or_production_authority",
    }
    need(type(value) is dict and set(value) == keys, "proof-receipt-keys")
    assert isinstance(value, dict)
    proof_hex = value["proof_ark_compressed_hex"]
    need(type(proof_hex) is str and len(proof_hex) == 256 and proof_hex == proof_hex.lower(), "proof-encoding")
    try:
        proof = bytes.fromhex(proof_hex)
    except ValueError as error:
        raise Refused("proof-encoding") from error
    need(
        value["schema"] == PROOF_SCHEMA
        and value["classification"] == CLASSIFICATION
        and value["selected_round"] == 1
        and value["prepared_instances"] == 3
        and value["prepared_witnesses"] == 12_949_818
        and value["prepared_variables"] == 12_949_821
        and value["prepared_constraints"] == 13_093_029
        and value["public_inputs_decimal"] == list(EXPECTED_PUBLIC_INPUTS)
        and value["proof_bytes"] == 128
        and len(proof) == 128
        and value["proof_sha256"] == sha256_bytes(proof)
        and value["r1cs_bytes"] == EXPECTED_ARTIFACTS["r1cs"]["bytes"]
        and value["r1cs_sha256"] == EXPECTED_ARTIFACTS["r1cs"]["sha256"]
        and value["decoded_pk_bytes"] == EXPECTED_ARTIFACTS["decoded_pk"]["bytes"]
        and value["decoded_pk_sha256"] == EXPECTED_ARTIFACTS["decoded_pk"]["sha256"]
        and value["compressed_pk_bytes"] == EXPECTED_ARTIFACTS["compressed_pk"]["bytes"]
        and value["compressed_pk_sha256"] == EXPECTED_ARTIFACTS["compressed_pk"]["sha256"]
        and value["decode_receipt_bytes"] == EXPECTED_ARTIFACTS["decode_receipt"]["bytes"]
        and value["decode_receipt_sha256"] == EXPECTED_ARTIFACTS["decode_receipt"]["sha256"]
        and value["vk_bytes"] == EXPECTED_ARTIFACTS["vk"]["bytes"]
        and value["vk_sha256"] == EXPECTED_ARTIFACTS["vk"]["sha256"],
        "proof-receipt-values",
    )
    true_fields = (
        "historical_sources_rehashed", "r1cs_satisfaction_checked",
        "proof_parameter_descriptors_opened_after_satisfaction",
        "historical_source_vk_opened_during_assignment_preparation",
        "decoded_pk_rehashed_before_deserialization",
        "internal_osrng_nonzero_blinding", "proof_generated",
        "independent_vk_rehashed", "independent_verification",
        "wrong_public_inputs_rejected", "mutated_proof_rejected",
    )
    false_fields = (
        "assignment_serialized", "secret_fingerprint_emitted", "setup_executed",
        "network_communication", "funds", "testnet", "full_secret_zeroization",
        "error_path_source_zeroization_complete", "abort_oom_zeroization",
        "receipt_is_authority", "public_or_production_authority",
    )
    need(all(value[key] is True for key in true_fields), "proof-required-true")
    need(all(value[key] is False for key in false_fields), "proof-required-false")


def parse_proof_frame(raw: bytes) -> tuple[bytes, dict]:
    need(len(raw) <= MAX_PROOF_STDOUT_BYTES, "proof-output-overflow")
    need(raw.startswith(FRAME_MAGIC), "proof-frame-magic")
    offset = len(FRAME_MAGIC)
    need(len(raw) >= offset + 4, "proof-frame-length")
    length = struct.unpack(">I", raw[offset : offset + 4])[0]
    offset += 4
    need(0 < length <= MAX_PROOF_RECEIPT_BYTES, "proof-frame-bounds")
    need(len(raw) == offset + length, "proof-frame-trailing-or-truncated")
    receipt_raw = raw[offset:]
    value = decode_canonical_json(receipt_raw, category="proof-receipt")
    validate_proof_receipt(value)
    assert isinstance(value, dict)
    return receipt_raw, value


def parse_verified_marker(raw: bytes, receipt_raw: bytes) -> str:
    need(len(raw) <= MAX_VERIFIER_STDOUT_BYTES, "verifier-output-overflow")
    digest = sha256_bytes(receipt_raw)
    expected = VERIFIED_MARKER + digest.encode("ascii") + b"\n"
    need(raw == expected, "verifier-marker")
    return digest


def bounded_append(buffer: bytearray, block: bytes, *, limit: int, category: str) -> None:
    need(len(buffer) + len(block) <= limit, category)
    buffer.extend(block)


def _write_new(path: Path, raw: bytes, mode: int = 0o400) -> dict:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        value = os.fstat(descriptor)
        need(stat.S_IMODE(value.st_mode) == mode and value.st_nlink == 1, "publish-file-mode")
    finally:
        os.close(descriptor)
    return _ref_from_stat(str(path), value, sha256_bytes(raw))


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reopen_exact_publication(
    directory: Path, expected: dict[str, bytes]
) -> dict[str, dict]:
    need(
        sorted(os.listdir(directory)) == sorted(expected),
        "publish-final-entry-set",
    )
    observed: dict[str, dict] = {}
    for name in sorted(expected):
        path = directory / name
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            value = os.fstat(descriptor)
            need(
                stat.S_ISREG(value.st_mode)
                and stat.S_IMODE(value.st_mode) == 0o400
                and value.st_nlink == 1,
                "publish-final-file-identity",
            )
            raw = _read_small_fd(
                descriptor,
                limit=max(len(expected[name]), 1),
                category="publish-final-file-overflow",
            )
            need(raw == expected[name], "publish-final-byte-substitution")
            observed[name] = _ref_from_stat(
                str(path), value, sha256_bytes(raw)
            )
        finally:
            os.close(descriptor)
    return observed


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    need(renameat2 is not None, "renameat2-unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = renameat2(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(destination),
        rename_noreplace,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise Refused(f"publish-rename-noreplace-{error}")


def validate_publication_runtime(
    runtime: object,
    *,
    expected_role: str,
    bindings: dict,
    parent_cgroup_entry: dict,
) -> dict:
    need(type(runtime) is dict, "publication-runtime-shape")
    assert isinstance(runtime, dict)
    need(
        runtime.get("verified_wait_evidence") is True
        and runtime.get("plan", {}).get("role") == expected_role
        and runtime.get("worker_ready", {}).get("role")
        == ("proof" if expected_role == "proof" else "verify"),
        "publication-runtime-role",
    )
    validate_sandbox_plan(runtime["plan"])
    need(
        runtime["cgroup_binding"] == bindings["cgroup"]
        and runtime["parent_cgroup_entry"] == parent_cgroup_entry
        and runtime["launch_contract"] == runtime["launch_evidence"]["launch_contract"],
        "publication-runtime-authority",
    )
    validate_parent_cgroup_entry(parent_cgroup_entry, bindings["cgroup"])
    launch = validate_launch_evidence(
        runtime["launch_evidence"],
        runtime["plan"],
        runtime["host_namespaces"],
        bindings["cgroup"],
        bindings["bwrap"],
    )
    validate_wait_evidence(
        runtime["wait_evidence"], expected_pid=launch["bwrap_pid"]
    )
    validate_cgroup_pair(
        runtime["cgroup_before"],
        runtime["cgroup_after"],
        runtime["cgroup_binding"],
    )
    role_build = bindings["build"][expected_role]
    expected_build_value = {
        "schema": "kpb-frozen-w1-role-build-receipt/v1",
        "role": expected_role,
        "binary": role_build["binary"],
        "source_closure_sha256": role_build["source_closure_sha256"],
        "runtime_closure_sha256": sha256_bytes(
            canonical(bindings["runtime_closure"][expected_role])
        ),
        "independently_reviewed": True,
        "test_only": True,
    }
    need(
        runtime["build_receipt"]["value"] == expected_build_value
        and runtime["bwrap_elf"]
        == {
            "build_id": FIXED_DEBIAN_BWRAP_BUILD_ID,
            "pt_interp": FIXED_DEBIAN_BWRAP_PT_INTERP,
            "dt_needed": list(FIXED_DEBIAN_BWRAP_DT_NEEDED),
        }
        and tuple(runtime["bwrap_loader_closure"])
        == bindings["bwrap"]["loader_closure"]
        and tuple(runtime["apparmor_source_closure"]["files"])
        == bindings["bwrap"]["apparmor_source_closure"]
        and runtime["apparmor_source_closure"]["include_graph"]
        == bindings["bwrap"]["apparmor_include_graph"]
        and runtime["apparmor_source_closure"]["optional_missing"]
        == bindings["bwrap"]["apparmor_optional_missing"],
        "publication-role-build-or-host-closure",
    )
    return runtime


def _runtime_manifest(runtime: dict) -> dict:
    return {
        "role": runtime["plan"]["role"],
        "plan": runtime["plan"],
        "worker_ready": runtime["worker_ready"],
        "launch_contract": runtime["launch_contract"],
        "launch_evidence": runtime["launch_evidence"],
        "wait_evidence": runtime["wait_evidence"],
        "cgroup_before": runtime["cgroup_before"],
        "cgroup_after": runtime["cgroup_after"],
        "cgroup_binding": runtime["cgroup_binding"],
        "parent_cgroup_entry": runtime["parent_cgroup_entry"],
        "build_receipt": runtime["build_receipt"],
        "bwrap_elf": runtime["bwrap_elf"],
        "bwrap_loader_closure": runtime["bwrap_loader_closure"],
        "apparmor_source_closure": runtime["apparmor_source_closure"],
    }


def build_evidence_manifest(
    *,
    stage0_contract: dict,
    bindings: dict,
    parent_cgroup_entry: dict,
    assignment_before: dict,
    assignment_after_proof: dict,
    assignment_after: dict,
    receipt_raw: bytes,
    verifier_stdout: bytes,
    proof_runtime: dict,
    verifier_runtime: dict,
) -> dict:
    return {
        "schema": "kpb-frozen-w1-bwrap-evidence-manifest/v1",
        "classification": CLASSIFICATION,
        "stage0_contract_sha256": sha256_bytes(canonical(stage0_contract)),
        "review_bindings": bindings,
        "review_bindings_sha256": sha256_bytes(canonical(bindings)),
        "parent_cgroup_entry": parent_cgroup_entry,
        "assignment_receipts": {
            "before_proof": assignment_before,
            "after_proof": assignment_after_proof,
            "after_verifier": assignment_after,
        },
        "proof_receipt": {
            "bytes": len(receipt_raw),
            "sha256": sha256_bytes(receipt_raw),
        },
        "verifier_marker": verifier_stdout.decode("ascii").rstrip("\n"),
        "proof_runtime": _runtime_manifest(proof_runtime),
        "verifier_runtime": _runtime_manifest(verifier_runtime),
        "publication_protocol": {
            "create_new_staging": True,
            "rename_noreplace": True,
            "commit_marker_written_last": True,
            "exact_final_entries": True,
            "final_bytes_reopened": True,
            "directory_and_parent_fsync": True,
            "without_valid_commit_marker": "uncertain-not-committed",
            "remaining_uncertainty": (
                "filesystem, storage hardware, kernel, privileged host, and "
                "post-run tampering remain inside the trusted-host TCB"
            ),
        },
        "claims": {
            "test_only": True,
            "mainnet": False,
            "funds": False,
            "privacy_proven": False,
            "cryptographic_correctness_proven": False,
            "side_channels_eliminated": False,
            "production_authority": False,
        },
    }


def validate_evidence_manifest(
    manifest: object,
    *,
    bindings: dict,
    receipt_raw: bytes,
    verifier_stdout: bytes,
) -> dict:
    required = {
        "schema", "classification", "stage0_contract_sha256",
        "review_bindings", "review_bindings_sha256", "parent_cgroup_entry",
        "assignment_receipts", "proof_receipt", "verifier_marker",
        "proof_runtime", "verifier_runtime", "publication_protocol", "claims",
    }
    need(type(manifest) is dict and set(manifest) == required, "evidence-manifest-shape")
    assert isinstance(manifest, dict)
    assignments = manifest["assignment_receipts"]
    protocol = manifest["publication_protocol"]
    claims = manifest["claims"]
    need(
        manifest["schema"] == "kpb-frozen-w1-bwrap-evidence-manifest/v1"
        and manifest["classification"] == CLASSIFICATION
        and is_sha256(manifest["stage0_contract_sha256"])
        and manifest["review_bindings"] == bindings
        and manifest["review_bindings_sha256"]
        == sha256_bytes(canonical(bindings))
        and type(assignments) is dict
        and set(assignments)
        == {"before_proof", "after_proof", "after_verifier"}
        and assignments["before_proof"] == assignments["after_proof"]
        == assignments["after_verifier"]
        and manifest["proof_receipt"]
        == {"bytes": len(receipt_raw), "sha256": sha256_bytes(receipt_raw)}
        and manifest["verifier_marker"]
        == verifier_stdout.decode("ascii").rstrip("\n")
        and manifest["proof_runtime"]["role"] == "proof"
        and manifest["verifier_runtime"]["role"] == "verifier"
        and type(manifest["proof_runtime"]["launch_evidence"]["mount_evidence"])
        is dict
        and type(manifest["verifier_runtime"]["launch_evidence"]["mount_evidence"])
        is dict,
        "evidence-manifest-bindings",
    )
    need(
        type(protocol) is dict
        and set(protocol)
        == {
            "create_new_staging", "rename_noreplace",
            "commit_marker_written_last", "exact_final_entries",
            "final_bytes_reopened", "directory_and_parent_fsync",
            "without_valid_commit_marker", "remaining_uncertainty",
        }
        and all(
            protocol[key] is True
            for key in (
                "create_new_staging", "rename_noreplace",
                "commit_marker_written_last", "exact_final_entries",
                "final_bytes_reopened", "directory_and_parent_fsync",
            )
        )
        and protocol["without_valid_commit_marker"]
        == "uncertain-not-committed"
        and type(protocol["remaining_uncertainty"]) is str
        and bool(protocol["remaining_uncertainty"]),
        "evidence-publication-protocol",
    )
    need(
        claims
        == {
            "test_only": True,
            "mainnet": False,
            "funds": False,
            "privacy_proven": False,
            "cryptographic_correctness_proven": False,
            "side_channels_eliminated": False,
            "production_authority": False,
        },
        "evidence-claim-boundary",
    )
    return manifest


def validate_publication_commit(
    commit: object, staged_raw: dict[str, bytes]
) -> dict:
    required = {
        "schema", "committed", "manifest_sha256", "files",
        "expected_entries", "commit_protocol", "marker_alone_is_not_authority",
        "remaining_uncertainty",
    }
    need(type(commit) is dict and set(commit) == required, "commit-marker-shape")
    assert isinstance(commit, dict)
    expected_files = {
        name: {"bytes": len(raw), "sha256": sha256_bytes(raw)}
        for name, raw in sorted(staged_raw.items())
    }
    need(
        commit["schema"] == "kpb-frozen-w1-publication-commit/v1"
        and commit["committed"] is True
        and commit["manifest_sha256"]
        == sha256_bytes(staged_raw["EVIDENCE-MANIFEST.json"])
        and commit["files"] == expected_files
        and commit["expected_entries"]
        == sorted((*staged_raw, "PUBLICATION-COMMIT.json"))
        and commit["commit_protocol"]
        == "create-new-marker-last-fsync-reopen-exact"
        and commit["marker_alone_is_not_authority"] is True
        and type(commit["remaining_uncertainty"]) is str
        and bool(commit["remaining_uncertainty"]),
        "commit-marker-bindings",
    )
    return commit


def atomic_publish(
    *,
    receipt_raw: bytes,
    receipt_value: dict,
    verifier_stdout: bytes,
    assignment_before: dict,
    assignment_after_proof: dict,
    assignment_after: dict,
    proof_runtime: dict,
    verifier_runtime: dict,
    bindings: dict,
    parent_cgroup_entry: dict,
    stage0_contract: dict,
    output_root: Path = PRIVATE_OUTPUT_ROOT,
    final_output: Path = FINAL_OUTPUT,
) -> dict:
    """Publish only after exact independent-verifier success is in hand."""
    validate_proof_receipt(receipt_value)
    need(receipt_raw == canonical(receipt_value), "publish-receipt-canonical-binding")
    digest = parse_verified_marker(verifier_stdout, receipt_raw)
    validate_assignment_reopen(assignment_before, assignment_after)
    validate_review_bindings(bindings)
    validate_publication_runtime(
        proof_runtime,
        expected_role="proof",
        bindings=bindings,
        parent_cgroup_entry=parent_cgroup_entry,
    )
    validate_publication_runtime(
        verifier_runtime,
        expected_role="verifier",
        bindings=bindings,
        parent_cgroup_entry=parent_cgroup_entry,
    )
    need(
        proof_runtime["launch_contract"]
        == canonical_launch_contract(proof_runtime["plan"], b"")
        and verifier_runtime["launch_contract"]
        == canonical_launch_contract(verifier_runtime["plan"], receipt_raw),
        "publish-launch-payload-binding",
    )
    manifest = build_evidence_manifest(
        stage0_contract=stage0_contract,
        bindings=bindings,
        parent_cgroup_entry=parent_cgroup_entry,
        assignment_before=assignment_before,
        assignment_after_proof=assignment_after_proof,
        assignment_after=assignment_after,
        receipt_raw=receipt_raw,
        verifier_stdout=verifier_stdout,
        proof_runtime=proof_runtime,
        verifier_runtime=verifier_runtime,
    )
    validate_evidence_manifest(
        manifest,
        bindings=bindings,
        receipt_raw=receipt_raw,
        verifier_stdout=verifier_stdout,
    )
    manifest_raw = canonical(manifest)
    need(not os.path.lexists(final_output), "publish-final-exists")
    output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    _fsync_directory(output_root.parent)
    staging = output_root / f".staging-{uuid.uuid4().hex}"
    staging.mkdir(mode=0o700)
    publication = {
        "schema": PUBLICATION_SCHEMA,
        "classification": CLASSIFICATION,
        "proof_receipt_sha256": digest,
        "proof_receipt_bytes": len(receipt_raw),
        "verifier_marker": verifier_stdout.decode("ascii").rstrip("\n"),
        "evidence_manifest_sha256": sha256_bytes(manifest_raw),
        "assignment_reopened_pre_and_post": True,
        "bwrap_namespaces_seccomp_and_cgroup_evidence_validated": True,
        "test_only": True,
        "mainnet": False,
        "funds": False,
        "privacy_proven": False,
        "cryptographic_correctness_proven": False,
        "side_channels_eliminated": False,
        "production_authority": False,
        "authorization": False,
        "commit_state": "requires-valid-PUBLICATION-COMMIT.json",
        "publication_without_commit_marker": "uncertain-not-committed",
    }
    verification_raw = canonical(publication)
    staged_raw = {
        "PROOF-RECEIPT.json": receipt_raw,
        "EVIDENCE-MANIFEST.json": manifest_raw,
        "VERIFICATION.json": verification_raw,
    }
    for name, raw in staged_raw.items():
        _write_new(staging / name, raw)
    _fsync_directory(staging)
    _rename_noreplace(staging, final_output)
    _fsync_directory(output_root)
    _fsync_directory(output_root.parent)
    precommit_reopen = _reopen_exact_publication(final_output, staged_raw)
    commit = {
        "schema": "kpb-frozen-w1-publication-commit/v1",
        "committed": True,
        "manifest_sha256": sha256_bytes(manifest_raw),
        "files": {
            name: {"bytes": len(raw), "sha256": sha256_bytes(raw)}
            for name, raw in sorted(staged_raw.items())
        },
        "expected_entries": sorted(
            (*staged_raw, "PUBLICATION-COMMIT.json")
        ),
        "commit_protocol": "create-new-marker-last-fsync-reopen-exact",
        "marker_alone_is_not_authority": True,
        "remaining_uncertainty": manifest["publication_protocol"]["remaining_uncertainty"],
    }
    validate_publication_commit(commit, staged_raw)
    commit_raw = canonical(commit)
    _write_new(final_output / "PUBLICATION-COMMIT.json", commit_raw)
    _fsync_directory(final_output)
    _fsync_directory(output_root)
    _fsync_directory(output_root.parent)
    final_raw = staged_raw | {"PUBLICATION-COMMIT.json": commit_raw}
    references = _reopen_exact_publication(final_output, final_raw)
    return {
        "publication": publication,
        "commit": commit,
        "precommit_reopen": precommit_reopen,
        "files": references,
        "final_reopen_completed": True,
        "output": str(final_output),
    }


def _execute_bound_pipeline(
    _contract: dict, _bindings: dict, _parent_cgroup_entry: dict
) -> dict:
    """Run proof then verifier; unreachable while any review gate is ``None``."""
    contract = _contract
    bindings = _bindings
    parent_cgroup_entry = _parent_cgroup_entry
    need(os.geteuid() != 0, "root-supervisor-refused")
    need(Path.cwd().resolve(strict=True) == REPO_ROOT, "cwd-repo-root")
    need(
        contract.get("mainnet") is False
        and contract.get("funds") is False
        and contract.get("test_only") is True,
        "stage0-test-only-scope",
    )
    # The first sealed Python entered the swap-disabled parent and then execed
    # this second sealed Python.  Requiring the post-exec receipt here prevents
    # any heap page charged before cgroup entry from being reused for private
    # assignment, key, R1CS, VK, build-receipt, or artifact bytes.
    _revalidate_live_parent_cgroup_entry(
        parent_cgroup_entry, bindings["cgroup"]
    )
    assignment_before = authenticate_assignment_pair(bindings["assignment"])
    proof_runtime = execute_role(
        "proof",
        stdin_raw=b"",
        bindings=bindings,
        parent_cgroup_entry=parent_cgroup_entry,
    )
    receipt_raw, receipt_value = parse_proof_frame(proof_runtime["stdout"])
    assignment_after_proof = authenticate_assignment_pair(bindings["assignment"])
    validate_assignment_reopen(assignment_before, assignment_after_proof)
    verifier_runtime = execute_role(
        "verifier",
        stdin_raw=receipt_raw,
        bindings=bindings,
        parent_cgroup_entry=parent_cgroup_entry,
    )
    proof_digest = parse_verified_marker(verifier_runtime["stdout"], receipt_raw)
    need(proof_digest == sha256_bytes(receipt_raw), "verifier-receipt-binding")
    assignment_after = authenticate_assignment_pair(bindings["assignment"])
    validate_assignment_reopen(assignment_before, assignment_after)
    return atomic_publish(
        receipt_raw=receipt_raw,
        receipt_value=receipt_value,
        verifier_stdout=verifier_runtime["stdout"],
        assignment_before=assignment_before,
        assignment_after_proof=assignment_after_proof,
        assignment_after=assignment_after,
        proof_runtime=proof_runtime,
        verifier_runtime=verifier_runtime,
        bindings=bindings,
        parent_cgroup_entry=parent_cgroup_entry,
        stage0_contract=contract,
    )


def _validate_contract_review_bindings(contract: dict, bindings: dict) -> None:
    need(
        contract.get("review_bindings_sha256")
        == sha256_bytes(canonical(bindings))
        and bindings["supervisor_source"]["sha256"]
        == contract["supervisor_source"]["sha256"]
        and bindings["external_stage0"]
        == contract["external_stage0_source_sha256"],
        "stage0-review-bindings",
    )


def _stage1_transition_value(
    contract_sha256: str,
    contract: dict,
    bindings: dict,
    parent_cgroup_entry: dict,
) -> dict:
    _validate_parent_cgroup_entry_base(
        parent_cgroup_entry, bindings["cgroup"]
    )
    return {
        "schema": STAGE1_TRANSITION_SCHEMA,
        "contract_sha256": contract_sha256,
        "review_bindings_sha256": sha256_bytes(canonical(bindings)),
        "supervisor_source_sha256": contract["supervisor_source"]["sha256"],
        "stage1_pid": os.getpid(),
        "stage1_starttime": parent_cgroup_entry["starttime"],
        "parent_cgroup_entry": parent_cgroup_entry,
        "private_content_opened_or_hashed": False,
        "next_stage": "sealed-stage2-post-cgroup-reexec",
    }


def _reexec_sealed_stage2(
    contract_sha256: str,
    contract: dict,
    bindings: dict,
    parent_cgroup_entry: dict,
) -> None:
    """Seal the cgroup-entry receipt and replace the entire Python process."""
    transition_raw = canonical(
        _stage1_transition_value(
            contract_sha256, contract, bindings, parent_cgroup_entry
        )
    )
    transition_sha256 = sha256_bytes(transition_raw)
    transition_fd = sealed_memfd("kpb-w1-stage1-transition", transition_raw)
    try:
        if transition_fd != 5:
            os.dup2(transition_fd, 5, inheritable=True)
            os.close(transition_fd)
            transition_fd = 5
        else:
            os.set_inheritable(transition_fd, True)
        for descriptor in (3, 4, 5):
            os.set_inheritable(descriptor, True)
        for descriptor in sorted(_live_fds() - {0, 1, 2, 3, 4, 5}):
            os.close(descriptor)
        need(
            _live_fds() == {0, 1, 2, 3, 4, 5},
            "stage1-transition-fd-allowlist",
        )
        os.execve(
            str(PYTHON),
            [
                str(PYTHON), "-I", "-S", "-B", "/proc/self/fd/3",
                "--sealed-stage2", contract_sha256, transition_sha256,
            ],
            STAGE2_ENVIRONMENT,
        )
        raise Refused("sealed-stage2-exec-returned")
    finally:
        try:
            os.close(transition_fd)
        except OSError:
            pass


def _validate_stage1_transition(
    transition_sha256: str,
    contract_sha256: str,
    contract: dict,
    bindings: dict,
) -> dict:
    raw = read_sealed_fd(
        5, max_bytes=1024 * 1024, expected_sha256=transition_sha256
    )
    transition = decode_canonical_json(raw, category="stage1-transition")
    required = {
        "schema", "contract_sha256", "review_bindings_sha256",
        "supervisor_source_sha256", "stage1_pid", "stage1_starttime",
        "parent_cgroup_entry", "private_content_opened_or_hashed",
        "next_stage",
    }
    need(
        type(transition) is dict and set(transition) == required,
        "stage1-transition-shape",
    )
    assert isinstance(transition, dict)
    entry = transition["parent_cgroup_entry"]
    _validate_parent_cgroup_entry_base(entry, bindings["cgroup"])
    pid = os.getpid()
    starttime = _proc_starttime(pid)
    proc_cgroup = _proc_cgroup_path(pid)
    post = read_parent_cgroup_snapshot(bindings["cgroup"])
    validate_cgroup_snapshot(
        read_cgroup_snapshot(bindings["cgroup"]),
        bindings["cgroup"],
        empty=True,
    )
    need(
        transition["schema"] == STAGE1_TRANSITION_SCHEMA
        and transition["contract_sha256"] == contract_sha256
        and transition["review_bindings_sha256"]
        == sha256_bytes(canonical(bindings))
        and transition["supervisor_source_sha256"]
        == contract["supervisor_source"]["sha256"]
        and transition["stage1_pid"] == pid == entry["pid"]
        and transition["stage1_starttime"] == starttime == entry["starttime"]
        and transition["private_content_opened_or_hashed"] is False
        and transition["next_stage"] == "sealed-stage2-post-cgroup-reexec"
        and proc_cgroup == _expected_parent_proc_cgroup_path(bindings["cgroup"])
        and pid in post["procs"]
        and post["memory_swap_max"] == 0
        and post["memory_swap_current"] == 0,
        "stage1-transition-values",
    )
    final_entry = dict(entry)
    final_entry.update(
        sealed_reexec_completed=True,
        sealed_transition_sha256=transition_sha256,
        post_reexec_starttime=starttime,
        post_reexec_proc_cgroup=proc_cgroup,
        post_reexec_parent_snapshot=post,
    )
    return validate_parent_cgroup_entry(final_entry, bindings["cgroup"])


def run_sealed_stage1(contract_sha256: str) -> None:
    contract = validate_stage0_entry(contract_sha256)
    # This validates only checked-in authority metadata.  It does not open or
    # hash assignment, proving-key, R1CS, VK, build, or artifact content.
    bindings = require_review_bindings()
    _validate_contract_review_bindings(contract, bindings)
    harden_parent_process()
    parent_cgroup_entry = enter_and_authenticate_parent_cgroup(
        bindings["cgroup"]
    )
    _reexec_sealed_stage2(
        contract_sha256, contract, bindings, parent_cgroup_entry
    )
    raise Refused("sealed-stage2-reexec-returned")


def run_sealed_stage2(
    contract_sha256: str, transition_sha256: str
) -> dict:
    contract = _validate_sealed_source_contract(
        contract_sha256,
        environment=STAGE2_ENVIRONMENT,
        live_fds={0, 1, 2, 3, 4, 5},
        category="stage2",
    )
    bindings = require_review_bindings()
    _validate_contract_review_bindings(contract, bindings)
    parent_cgroup_entry = _validate_stage1_transition(
        transition_sha256, contract_sha256, contract, bindings
    )
    # PR_SET_DUMPABLE may be reset by exec; harden again before private reads.
    harden_parent_process()
    return _execute_bound_pipeline(
        contract, bindings, parent_cgroup_entry
    )


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 2 and argv[0] == "--sealed-stage1" and is_sha256(argv[1]):
            run_sealed_stage1(argv[1])
            return 0
        if (
            len(argv) == 3
            and argv[0] == "--sealed-stage2"
            and is_sha256(argv[1])
            and is_sha256(argv[2])
        ):
            run_sealed_stage2(argv[1], argv[2])
            return 0
        raise Refused("external-sealed-stage0-required")
    except Refused as error:
        print(f"STOP:{error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError):
        print("STOP:sealed-stage1-boundary", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
