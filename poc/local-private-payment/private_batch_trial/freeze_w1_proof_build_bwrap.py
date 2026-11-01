#!/usr/bin/env python3
"""Fail-closed bwrap freezer for the fixed W1 prover and verifier.

This file is intentionally self-contained.  It imports no repository module,
and the default no-argument entry point is inert while the independent review
bindings below are ``None``.  A reviewed external inline bootstrap must first
authenticate this exact source, copy it into a sealed memfd, and execute that
memfd with a sealed contract on fd 4.

When eventually bound, the freezer performs a *source-only build*.  It does
not read a proving key, assignment, witness, or R1CS; it does not execute the
resulting binaries; and it makes no cryptographic, privacy, financial, or
production claim.  Build scripts and proc macros run only in a final bubblewrap
sandbox with a private network, private writable filesystems, a read-only
authenticated source/vendor/toolchain copy, an architecture-pinned seccomp
filter, and no host home, run directory, or temporary directory.

The root-owned operating-system runtime is an explicit trust boundary rather
than a reproducible-build claim.  An independently rebuilt identical binary is
required before either output may be used with private proving material.
This follows the accepted one-trusted-host model: same-UID and privileged host
processes are in the measurement TCB, not adversaries this runner claims to
isolate from.
"""

from __future__ import annotations

import base64
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid


SCHEMA = "kpb-w1-bwrap-build-freezer/v1"
RECEIPT_SCHEMA = "kpb-w1-bwrap-build-receipt/v1"
STAGE0_CONTRACT_SCHEMA = "kpb-w1-bwrap-build-stage0-contract/v1"
FRAME_SCHEMA = "kpb-w1-bwrap-build-frame/v1"
CLASSIFICATION = "TEST_ONLY_SOURCE_BUILD_NOT_AUTHORITY"

SOURCE_PATH = Path(
    "/home/luke/projects/kpi-intensive-2026-10-22/continuation/"
    "poc/local-private-payment/private_batch_trial/"
    "freeze_w1_proof_build_bwrap.py"
)
HERE = SOURCE_PATH.parent
REPO_ROOT = HERE.parents[2]
PRIVATE_OUTPUT_BASE = Path("/home/luke/projects/kpi-intensive-2026-10-22")
OUTPUT_PARENT = PRIVATE_OUTPUT_BASE / "private-batch-w1-bwrap-build-private-20261101-01"
OUTPUT_NAME = "w1-bwrap-build"

PYTHON = Path("/usr/bin/python3.14")
# The installed Ubuntu 0.11.1-1ubuntu0.3 package is explicitly inadmissible:
# its local changelog records a security regression that dropped the
# The bytes currently installed at this AppArmor-authorized path are
# inadmissible Ubuntu 0.11.1-1ubuntu0.3 bytes whose changelog drops the
# CVE-2026-87766 safe_openat fix.  No invocation is possible while the gates
# remain None.  A future admin replacement at this exact path must be >=0.12,
# root-owned/non-writable, provenance-bound, and closure-bound before review.
BWRAP = Path("/usr/bin/bwrap")
MINIMUM_BWRAP_VERSION = (0, 12, 0)
APPARMOR_PROFILE_SOURCE = Path("/etc/apparmor.d/bwrap-userns-restrict")
BWRAP_PROVENANCE_ROOT = Path("/var/lib/kpb-reviewed-bwrap")
ENV = Path("/usr/lib/cargo/bin/coreutils/env")
TOOLCHAIN_ROOT = Path(
    "/home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu"
)
CARGO = TOOLCHAIN_ROOT / "bin/cargo"
RUSTC = TOOLCHAIN_ROOT / "bin/rustc"
RUSTDOC = TOOLCHAIN_ROOT / "bin/rustdoc"
REGISTRY_ROOT = Path(
    "/home/luke/projects/kpi-intensive-2026-10-22/binding-cargo-home/"
    "registry/src/index.crates.io-1949cf8c6b5b557f"
)
RELATION_RELATIVE = "poc/local-private-payment/private-batch-relation"
MANIFEST_RELATIVE = f"{RELATION_RELATIVE}/Cargo.toml"
LOCK_RELATIVE = f"{RELATION_RELATIVE}/Cargo.lock"
PROVER_NAME = "prove_frozen_w1_round1"
VERIFIER_NAME = "verify_frozen_w1_round1_receipt"
FEATURE_NAME = "offline-w1-prover"

LOCAL_SOURCE_ROOTS = (
    "poc/local-private-payment/native-authority/native-core",
    "poc/local-private-payment/native-authority/vendor/native-relation",
    "poc/local-private-payment/private-batch-relation",
    "poc/local-private-payment/private_batch_trial/auth_exit",
    "poc/local-private-payment/private_batch_trial/low_memory_w1_prover",
)
EXCLUDED_TREE_PARTS = frozenset({"target", "__pycache__", ".git"})

# These are deliberately unbound.  Populating them is a source edit that must
# happen only after an independent review of the exact source/tree identities.
REVIEWED_LOCAL_SOURCE_TREE_SHA256: str | None = None
REVIEWED_LOCAL_SOURCE_FILES_SHA256: dict[str, str] | None = None
REVIEWED_VENDOR_TREE_SHA256: str | None = None
REVIEWED_TOOLCHAIN_TREE_SHA256: str | None = None
REVIEWED_ROOT_RUNTIME_SHA256: dict[str, str] | None = None
REVIEWED_LEAF_TOOL_SHA256: dict[str, str] | None = None
REVIEWED_BWRAP_VERSION: str | None = None
REVIEWED_BWRAP_APPARMOR_EXEC_PATH: str | None = None
REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256: str | None = None
REVIEWED_BWRAP_APPARMOR_POLICY: dict[str, object] | None = None
REVIEWED_BWRAP_PROVENANCE: dict[str, object] | None = None
REVIEWED_BWRAP_ELF_CLOSURE: dict[str, object] | None = None

LEAF_TOOLS = {
    "python": PYTHON,
    "bwrap": BWRAP,
    "env": ENV,
    "cargo": CARGO,
    "rustc": RUSTC,
    "rustdoc": RUSTDOC,
}

# Exact dynamic closure expected for the separately reviewed x86_64 bwrap
# ELF.  The fixed ELF does not exist in the checked-in state, so these hashes
# remain review gates rather than values learned from the inadmissible host
# bwrap.  The wider host /usr and /lib trees used by Python and the compiler
# remain an explicit, non-reproducible trust limit.
BWRAP_RUNTIME_FILES = (
    "/etc/ld.so.cache",
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libcap.so.2.75",
    "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.14.0",
    "/usr/lib/x86_64-linux-gnu/libselinux.so.1",
)
BWRAP_INTERPRETER_LITERAL = "/lib64/ld-linux-x86-64.so.2"
BWRAP_INTERPRETER_RESOLVED = (
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
)
BWRAP_RUNTIME_MOUNT_DESTINATIONS = frozenset(
    {*BWRAP_RUNTIME_FILES, BWRAP_INTERPRETER_LITERAL}
)
BWRAP_RUNTIME_REQUIRED_ABSENT = ("/etc/ld.so.preload",)
LD_SO_CACHE_X86_64_FLAGS = 0x0303
LD_SO_CACHE_ENDIAN_LITTLE = 2
LD_SO_CACHE_EXTENSION_MAGIC = 0xEAA42174
LD_SO_CACHE_EXTENSION_GENERATOR = 0
ELF_LOADER_EXTENSION_TAGS = {
    0x6FFFFEFB,  # DT_DEPAUDIT
    0x6FFFFEFC,  # DT_AUDIT
    0x7FFFFFFD,  # DT_AUXILIARY
    0x7FFFFFFF,  # DT_FILTER
}

STAGE0_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
    "KPB_W1_BWRAP_STAGE0": "1",
}
SANDBOX_ENVIRONMENT = {
    "HOME": "/home/build",
    "PATH": "/toolchain/bin:/usr/bin:/bin",
    "CARGO_HOME": "/cargo-home",
    "CARGO_NET_OFFLINE": "true",
    "CARGO_TARGET_DIR": "/target",
    "CARGO_INCREMENTAL": "0",
    "CARGO_TERM_COLOR": "never",
    "RUSTC": "/toolchain/bin/rustc",
    "RUSTDOC": "/toolchain/bin/rustdoc",
    "RUSTC_WRAPPER": "",
    "RUSTC_WORKSPACE_WRAPPER": "",
    "RUSTFLAGS": "",
    "CARGO_ENCODED_RUSTFLAGS": "",
    "CC": "/usr/bin/x86_64-linux-gnu-gcc-15",
    "CXX": "/usr/bin/x86_64-linux-gnu-g++-15",
    "AR": "/usr/bin/x86_64-linux-gnu-ar",
    "RANLIB": "/usr/bin/x86_64-linux-gnu-ranlib",
    "LD": "/usr/bin/x86_64-linux-gnu-ld.bfd",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": (
        "/usr/bin/x86_64-linux-gnu-gcc-15"
    ),
    "HTTP_PROXY": "",
    "HTTPS_PROXY": "",
    "ALL_PROXY": "",
    "NO_PROXY": "",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}

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
    "--die-with-parent",
    "--new-session",
    "--clearenv",
)
OUTER_NAMESPACE_FLAGS = (
    "--unshare-all",
    "--unshare-user",
    "--unshare-ipc",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-uts",
    "--unshare-cgroup",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
)
OUTER_FD_ROLES = (
    "bwrap",
    "repo",
    "registry",
    "toolchain",
    "outer_source",
    "local_manifest",
    "vendor_manifest",
    "toolchain_manifest",
    "seccomp",
    "status_write",
    "launch_block_read",
)

FRAME_MAGIC = b"KPB-W1-BWRAP-BUILD\x00\x01"
MAX_FRAME_HEADER_BYTES = 64 * 1024
MAX_EXPORTED_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_EXPORT_BYTES = 512 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
MEMORY_LIMIT_BYTES = 20 * 1024**3
FILE_LIMIT_BYTES = 4 * 1024**3
MAX_BWRAP_DEB_BYTES = 64 * 1024 * 1024
MAX_PROVENANCE_EVIDENCE_BYTES = 1024 * 1024

F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE

# Linux x86_64 syscall numbers.  AUDIT_ARCH_X86_64 is shared by the native and
# x32 ABIs, so the BPF program separately kills every syscall number carrying
# the x32 ABI bit before it reaches this native-number deny table.
DENIED_SYSCALL_NAMES_X86_64 = {
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
    "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48,
    "bind": 49, "listen": 50, "getsockname": 51, "getpeername": 52,
    "socketpair": 53, "setsockopt": 54, "getsockopt": 55,
    "ptrace": 101, "pivot_root": 155, "mount": 165, "umount2": 166,
    "kexec_load": 246, "add_key": 248, "request_key": 249, "keyctl": 250,
    "unshare": 272, "accept4": 288, "perf_event_open": 298,
    "recvmmsg": 299, "name_to_handle_at": 303, "open_by_handle_at": 304,
    "sendmmsg": 307, "setns": 308, "process_vm_readv": 310,
    "process_vm_writev": 311, "kcmp": 312, "bpf": 321,
    "userfaultfd": 323, "io_uring_setup": 425, "io_uring_enter": 426,
    "io_uring_register": 427, "open_tree": 428, "move_mount": 429,
    "fsopen": 430, "fsconfig": 431, "fsmount": 432,
    "pidfd_getfd": 438, "mount_setattr": 442,
}
DENIED_SYSCALLS_X86_64 = set(DENIED_SYSCALL_NAMES_X86_64.values())
AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000


class Refused(RuntimeError):
    """A fail-closed boundary refusal."""


def need(value: bool, category: str) -> None:
    if not value:
        raise Refused(category)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def is_sha256(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def bwrap_version_tuple(value: object) -> tuple[int, int, int] | None:
    if type(value) is not str:
        return None
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", value)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def valid_bwrap_provenance(value: object, elf_sha256: object) -> bool:
    if type(value) is not dict:
        return False
    if set(value) != {
        "schema",
        "distribution",
        "suite",
        "architecture",
        "package",
        "package_version",
        "package_filename",
        "deb_path",
        "runtime_version",
        "deb_sha256",
        "deb_control_sha256",
        "elf_sha256",
        "elf_build_id",
        "upstream_tag",
        "upstream_tag_object",
        "upstream_commit",
        "upstream_signature_verified",
        "upstream_verification_path",
        "upstream_verification_sha256",
    }:
        return False
    runtime_version = value["runtime_version"]
    package_version = value["package_version"]
    if bwrap_version_tuple(runtime_version) is None:
        return False
    upstream_path = value["upstream_verification_path"]
    if type(upstream_path) is not str:
        return False
    upstream_pure = PurePosixPath(upstream_path)
    if (
        not upstream_pure.is_absolute()
        or ".." in upstream_pure.parts
        or not upstream_pure.is_relative_to(PurePosixPath(BWRAP_PROVENANCE_ROOT))
        or upstream_pure == PurePosixPath(BWRAP_PROVENANCE_ROOT)
        or str(upstream_pure) != upstream_path
    ):
        return False
    return (
        value["schema"] == "kpb-reviewed-bwrap-provenance/v3"
        and value["distribution"] == "Debian"
        and value["suite"] == "sid"
        and value["architecture"] == "amd64"
        and value["package"] == "bubblewrap"
        and type(package_version) is str
        and re.fullmatch(
            re.escape(runtime_version) + r"-[0-9A-Za-z.+~]+", package_version
        )
        is not None
        and value["package_filename"]
        == f"bubblewrap_{package_version}_amd64.deb"
        and value["deb_path"]
        == str(BWRAP_PROVENANCE_ROOT / value["package_filename"])
        and runtime_version == REVIEWED_BWRAP_VERSION
        and is_sha256(value["deb_sha256"])
        and is_sha256(value["deb_control_sha256"])
        and value["elf_sha256"] == elf_sha256
        and type(value["elf_build_id"]) is str
        and re.fullmatch(r"[0-9a-f]{16,128}", value["elf_build_id"]) is not None
        and value["upstream_tag"] == f"v{runtime_version}"
        and type(value["upstream_tag_object"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["upstream_tag_object"])
        is not None
        and type(value["upstream_commit"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["upstream_commit"]) is not None
        and value["upstream_tag_object"] != value["upstream_commit"]
        and value["upstream_signature_verified"] is True
        and upstream_path.startswith(str(BWRAP_PROVENANCE_ROOT) + "/")
        and is_sha256(value["upstream_verification_sha256"])
    )


def parse_elf_dynamic_identity(raw: bytes) -> dict[str, object]:
    """Parse the loader-relevant identity of one little-endian ELF64 object."""
    need(len(raw) >= 64 and raw[:4] == b"\x7fELF", "elf-header")
    need(raw[4:7] == b"\x02\x01\x01", "elf-format")
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw, 0)
    except struct.error as error:
        raise Refused("elf-header") from error
    elf_type, machine = header[1], header[2]
    program_offset, program_entry_bytes, program_count = header[5], header[9], header[10]
    need(
        elf_type in {2, 3}
        and machine == 62
        and program_entry_bytes == 56
        and 0 < program_count < 4096,
        "elf-architecture",
    )
    need(
        program_offset <= len(raw)
        and program_count * program_entry_bytes <= len(raw) - program_offset,
        "elf-program-table",
    )
    programs: list[tuple[int, int, int, int, int, int, int, int]] = []
    for index in range(program_count):
        programs.append(
            struct.unpack_from(
                "<IIQQQQQQ", raw, program_offset + index * program_entry_bytes
            )
        )

    def segment_bytes(program: tuple[int, int, int, int, int, int, int, int]) -> bytes:
        offset, file_bytes = program[2], program[5]
        need(offset <= len(raw) and file_bytes <= len(raw) - offset, "elf-segment")
        return raw[offset : offset + file_bytes]

    def virtual_to_offset(address: int, size: int) -> int:
        for program in programs:
            if program[0] != 1:  # PT_LOAD
                continue
            offset, virtual, file_bytes = program[2], program[3], program[5]
            if virtual <= address and size <= file_bytes and address - virtual <= file_bytes - size:
                result = offset + address - virtual
                need(result <= len(raw) and size <= len(raw) - result, "elf-vaddr")
                return result
        raise Refused("elf-vaddr")

    interpreter_rows = [segment_bytes(program) for program in programs if program[0] == 3]
    need(len(interpreter_rows) <= 1, "elf-interpreter-count")
    interpreter: str | None = None
    if interpreter_rows:
        value = interpreter_rows[0]
        need(value.endswith(b"\x00") and b"\x00" not in value[:-1], "elf-interpreter")
        try:
            interpreter = value[:-1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise Refused("elf-interpreter") from error
        need(interpreter.startswith("/") and ".." not in PurePosixPath(interpreter).parts,
             "elf-interpreter")

    build_ids: list[str] = []
    for program in programs:
        if program[0] != 4:  # PT_NOTE
            continue
        notes = segment_bytes(program)
        cursor = 0
        while cursor < len(notes):
            need(len(notes) - cursor >= 12, "elf-note")
            name_bytes, description_bytes, note_type = struct.unpack_from(
                "<III", notes, cursor
            )
            cursor += 12
            name_end = cursor + name_bytes
            name_padded_end = (name_end + 3) & ~3
            description_end = name_padded_end + description_bytes
            description_padded_end = (description_end + 3) & ~3
            need(description_padded_end <= len(notes), "elf-note")
            name = notes[cursor:name_end]
            description = notes[name_padded_end:description_end]
            cursor = description_padded_end
            if note_type == 3 and name.rstrip(b"\x00") == b"GNU":
                need(description, "elf-build-id")
                build_ids.append(description.hex())
    need(len(build_ids) == 1, "elf-build-id")

    dynamic_rows = [program for program in programs if program[0] == 2]
    need(len(dynamic_rows) == 1, "elf-dynamic-count")
    dynamic_raw = segment_bytes(dynamic_rows[0])
    need(len(dynamic_raw) % 16 == 0, "elf-dynamic-table")
    dynamic: list[tuple[int, int]] = []
    saw_null = False
    for offset in range(0, len(dynamic_raw), 16):
        tag, value = struct.unpack_from("<qQ", dynamic_raw, offset)
        if tag == 0:
            saw_null = True
            break
        dynamic.append((tag, value))
    need(saw_null, "elf-dynamic-null")
    string_addresses = [value for tag, value in dynamic if tag == 5]
    string_sizes = [value for tag, value in dynamic if tag == 10]
    need(len(string_addresses) == 1 and len(string_sizes) == 1, "elf-string-table")
    string_size = string_sizes[0]
    need(0 < string_size <= len(raw), "elf-string-table")
    string_offset = virtual_to_offset(string_addresses[0], string_size)
    strings = raw[string_offset : string_offset + string_size]

    def dynamic_string(index: int) -> str:
        need(index < len(strings), "elf-dynamic-string")
        end = strings.find(b"\x00", index)
        need(end >= 0, "elf-dynamic-string")
        try:
            result = strings[index:end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise Refused("elf-dynamic-string") from error
        need(result and "\x00" not in result, "elf-dynamic-string")
        return result

    needed = [dynamic_string(value) for tag, value in dynamic if tag == 1]
    sonames = [dynamic_string(value) for tag, value in dynamic if tag == 14]
    rpath = [dynamic_string(value) for tag, value in dynamic if tag == 15]
    runpath = [dynamic_string(value) for tag, value in dynamic if tag == 29]
    need(len(needed) == len(set(needed)), "elf-needed-duplicate")
    need(len(sonames) <= 1, "elf-soname")
    need(
        not any(tag in ELF_LOADER_EXTENSION_TAGS for tag, _ in dynamic),
        "elf-loader-extension",
    )
    return {
        "elf_type": elf_type,
        "machine": machine,
        "build_id": build_ids[0],
        "interpreter": interpreter,
        "soname": sonames[0] if sonames else None,
        "needed": needed,
        "rpath": rpath,
        "runpath": runpath,
    }


def parse_ld_so_cache_x86_64(raw: bytes) -> dict[str, list[str]]:
    magic = b"glibc-ld.so.cache1.1"
    need(len(raw) >= 48 and raw.startswith(magic), "ld-cache-format")
    library_count, string_bytes = struct.unpack_from("<II", raw, len(magic))
    cache_flags = raw[28]
    padding = raw[29:32]
    extension_offset = struct.unpack_from("<I", raw, 32)[0]
    unused = raw[36:48]
    need(
        cache_flags == LD_SO_CACHE_ENDIAN_LITTLE
        and padding == b"\x00" * 3
        and unused == b"\x00" * 12,
        "ld-cache-header-flags",
    )
    need(
        0 < library_count < 1_000_000 and 0 < string_bytes <= len(raw),
        "ld-cache-library-count",
    )
    entries_offset = 48
    entry_bytes = 24
    entries_end = entries_offset + library_count * entry_bytes
    strings_end = entries_end + string_bytes
    need(entries_end <= len(raw) and strings_end <= len(raw), "ld-cache-bounds")

    if extension_offset == 0:
        need(strings_end == len(raw), "ld-cache-trailing-bytes")
    else:
        need(
            extension_offset == strings_end and extension_offset % 4 == 0,
            "ld-cache-extension-offset",
        )
        need(len(raw) - extension_offset >= 8, "ld-cache-extension-header")
        extension_magic, section_count = struct.unpack_from(
            "<II", raw, extension_offset
        )
        need(
            extension_magic == LD_SO_CACHE_EXTENSION_MAGIC
            and 0 < section_count < 1024,
            "ld-cache-extension-header",
        )
        table_end = extension_offset + 8 + section_count * 16
        need(table_end <= len(raw), "ld-cache-extension-table")
        expected_data_offset = table_end
        seen_tags: set[int] = set()
        for index in range(section_count):
            tag, flags, data_offset, data_bytes = struct.unpack_from(
                "<IIII", raw, extension_offset + 8 + index * 16
            )
            need(
                tag == LD_SO_CACHE_EXTENSION_GENERATOR
                and tag not in seen_tags
                and flags == 0,
                "ld-cache-loader-affecting-extension",
            )
            seen_tags.add(tag)
            need(
                data_offset == expected_data_offset
                and 0 < data_bytes <= len(raw) - data_offset,
                "ld-cache-extension-bounds",
            )
            generator = raw[data_offset : data_offset + data_bytes]
            try:
                generator.decode("utf-8")
            except UnicodeDecodeError as error:
                raise Refused("ld-cache-generator-encoding") from error
            expected_data_offset += data_bytes
        need(expected_data_offset == len(raw), "ld-cache-trailing-bytes")

    def cache_string(offset: int) -> str:
        need(entries_end <= offset < strings_end, "ld-cache-string-offset")
        end = raw.find(b"\x00", offset, strings_end)
        need(end >= 0, "ld-cache-string")
        try:
            result = raw[offset:end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise Refused("ld-cache-string") from error
        need(result and "\x00" not in result, "ld-cache-string")
        return result

    result: dict[str, list[str]] = {}
    for index in range(library_count):
        flags, key_offset, value_offset, os_version, hwcap = struct.unpack_from(
            "<iIIIQ", raw, entries_offset + index * entry_bytes
        )
        soname = cache_string(key_offset)
        resolved = cache_string(value_offset)
        need(resolved.startswith("/"), "ld-cache-library-path")
        if flags != LD_SO_CACHE_X86_64_FLAGS:
            continue
        need(os_version == 0 and hwcap == 0, "ld-cache-conditional-resolution")
        result.setdefault(soname, []).append(resolved)
    return result


def cache_candidate_has_exact_parent(candidate: str, expected_path: str) -> bool:
    if type(candidate) is not str or type(expected_path) is not str:
        return False
    candidate_path = PurePosixPath(candidate)
    expected = PurePosixPath(expected_path)
    return (
        candidate_path.is_absolute()
        and expected.is_absolute()
        and ".." not in candidate_path.parts
        and candidate_path.parent == expected.parent
    )


def cache_candidate_route_is_direct(
    candidate: str, expected_path: str, symlink_target: str | None
) -> bool:
    if symlink_target is None:
        return candidate == expected_path
    return (
        type(symlink_target) is str
        and symlink_target == PurePosixPath(expected_path).name
        and "/" not in symlink_target
    )


def safe_relative(value: str) -> PurePosixPath:
    result = PurePosixPath(value)
    need(
        type(value) is str
        and value
        and not result.is_absolute()
        and ".." not in result.parts
        and "." not in result.parts
        and str(result) == value,
        "unsafe-relative-path",
    )
    return result


def stable_file(
    path: Path,
    *,
    owner_uid: int | None = None,
    allow_hardlinks: bool = False,
    max_bytes: int | None = None,
) -> tuple[bytes, dict]:
    before_path = os.lstat(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode), "not-regular")
        need(before.st_nlink >= 1, "invalid-link-count")
        if max_bytes is not None:
            need(0 <= before.st_size <= max_bytes, "file-size-bound")
        if not allow_hardlinks:
            need(before.st_nlink == 1, "unexpected-hardlink")
        if owner_uid is not None:
            need(before.st_uid == owner_uid, "unexpected-owner")
        blocks: list[bytes] = []
        offset = 0
        while True:
            block = os.pread(descriptor, 1024 * 1024, offset)
            if not block:
                break
            blocks.append(block)
            offset += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    need(
        identity(before_path) == identity(before) == identity(after) == identity(after_path),
        "file-mutated-during-read",
    )
    raw = b"".join(blocks)
    need(len(raw) == before.st_size, "short-read")
    return raw, {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "device": before.st_dev,
        "inode": before.st_ino,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mode_octal": f"{stat.S_IMODE(before.st_mode):04o}",
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }


def deb_archive_members(raw: bytes) -> dict[str, bytes]:
    need(raw.startswith(b"!<arch>\n"), "deb-ar-header")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(raw):
        need(len(raw) - offset >= 60, "deb-ar-member-header")
        header = raw[offset : offset + 60]
        need(header[58:60] == b"`\n", "deb-ar-member-header")
        raw_name = header[:16].decode("ascii", "strict").strip()
        need(raw_name and not raw_name.startswith("#1/"), "deb-ar-member-name")
        name = raw_name[:-1] if raw_name.endswith("/") else raw_name
        try:
            size = int(header[48:58].decode("ascii").strip(), 10)
        except ValueError as error:
            raise Refused("deb-ar-member-size") from error
        offset += 60
        need(0 <= size <= len(raw) - offset, "deb-ar-member-size")
        need(name not in members, "deb-ar-member-duplicate")
        members[name] = raw[offset : offset + size]
        offset += size
        if offset & 1:
            need(offset < len(raw) and raw[offset : offset + 1] == b"\n",
                 "deb-ar-padding")
            offset += 1
    need(offset == len(raw), "deb-ar-trailing")
    return members


def tar_regular_member(raw: bytes, expected_name: str, max_bytes: int) -> bytes:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            matches = [
                member
                for member in archive.getmembers()
                if member.name.removeprefix("./") == expected_name
            ]
            need(len(matches) == 1 and matches[0].isfile(), "deb-tar-member")
            need(0 <= matches[0].size <= max_bytes, "deb-tar-member-size")
            extracted = archive.extractfile(matches[0])
            need(extracted is not None, "deb-tar-member")
            value = extracted.read(max_bytes + 1)
    except (tarfile.TarError, EOFError, OSError) as error:
        raise Refused("deb-tar-format") from error
    need(len(value) == matches[0].size and len(value) <= max_bytes,
         "deb-tar-member-size")
    return value


def parse_debian_control(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refused("deb-control-encoding") from error
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line:
            break
        if line[:1].isspace():
            need(current is not None, "deb-control-continuation")
            fields[current] += "\n" + line[1:]
            continue
        need(":" in line, "deb-control-field")
        name, value = line.split(":", 1)
        need(
            re.fullmatch(r"[A-Za-z0-9-]+", name) is not None
            and name not in fields,
            "deb-control-field",
        )
        fields[name] = value.lstrip()
        current = name
    return fields


def parse_reviewed_bwrap_deb(raw: bytes) -> dict[str, object]:
    members = deb_archive_members(raw)
    need(members.get("debian-binary") == b"2.0\n", "deb-format-version")
    control_names = [name for name in members if name.startswith("control.tar.")]
    data_names = [name for name in members if name.startswith("data.tar.")]
    need(len(control_names) == 1 and len(data_names) == 1, "deb-member-set")
    control_raw = tar_regular_member(
        members[control_names[0]], "control", MAX_PROVENANCE_EVIDENCE_BYTES
    )
    bwrap_raw = tar_regular_member(
        members[data_names[0]], "usr/bin/bwrap", 16 * 1024 * 1024
    )
    return {
        "control": parse_debian_control(control_raw),
        "control_sha256": sha256_bytes(control_raw),
        "bwrap_sha256": sha256_bytes(bwrap_raw),
        "bwrap_bytes": len(bwrap_raw),
    }


def validate_deb_provenance_relationship(deb: dict, provenance: dict) -> None:
    control = deb.get("control")
    need(
        type(control) is dict
        and control.get("Package") == provenance["package"]
        and control.get("Version") == provenance["package_version"]
        and control.get("Architecture") == provenance["architecture"]
        and deb.get("control_sha256") == provenance["deb_control_sha256"]
        and deb.get("bwrap_sha256") == provenance["elf_sha256"],
        "bwrap-deb-relationship",
    )


def parse_upstream_verification_evidence(raw: bytes, provenance: dict) -> dict:
    try:
        upstream = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise Refused("bwrap-upstream-evidence-json") from error
    need(
        type(upstream) is dict
        and canonical(upstream) == raw
        and set(upstream) == {
            "schema", "repository", "tag", "tag_object", "commit",
            "signature_verified", "signature_status",
        }
        and upstream["schema"] == "kpb-bwrap-upstream-verification-evidence/v1"
        and upstream["repository"] == "containers/bubblewrap"
        and upstream["tag"] == provenance["upstream_tag"]
        and upstream["tag_object"] == provenance["upstream_tag_object"]
        and upstream["commit"] == provenance["upstream_commit"]
        and upstream["signature_verified"]
        is provenance["upstream_signature_verified"]
        and upstream["signature_status"] == "valid",
        "bwrap-upstream-evidence-relationship",
    )
    return upstream


def validate_bwrap_provenance_evidence() -> dict[str, object]:
    provenance = REVIEWED_BWRAP_PROVENANCE
    need(
        type(REVIEWED_LEAF_TOOL_SHA256) is dict
        and valid_bwrap_provenance(
            provenance, REVIEWED_LEAF_TOOL_SHA256.get("bwrap")
        ),
        "bwrap-provenance-review-not-bound",
    )
    assert type(provenance) is dict
    root = BWRAP_PROVENANCE_ROOT.resolve(strict=True)
    need(root == BWRAP_PROVENANCE_ROOT, "bwrap-provenance-root")
    root_identity = os.lstat(root)
    need(
        stat.S_ISDIR(root_identity.st_mode)
        and root_identity.st_uid == 0
        and stat.S_IMODE(root_identity.st_mode) & 0o022 == 0,
        "bwrap-provenance-root",
    )

    def evidence_file(raw_path: str, expected_sha256: str, max_bytes: int):
        path = Path(raw_path)
        resolved = path.resolve(strict=True)
        need(
            path.is_absolute()
            and ".." not in path.parts
            and path == resolved
            and resolved.is_relative_to(root),
            "bwrap-provenance-evidence-path",
        )
        parent = path.parent
        while True:
            parent_identity = os.lstat(parent)
            need(
                stat.S_ISDIR(parent_identity.st_mode)
                and parent_identity.st_uid == 0
                and stat.S_IMODE(parent_identity.st_mode) & 0o022 == 0,
                "bwrap-provenance-evidence-parent",
            )
            if parent == root:
                break
            need(parent.is_relative_to(root), "bwrap-provenance-evidence-parent")
            parent = parent.parent
        raw, identity = stable_file(path, owner_uid=0, max_bytes=max_bytes)
        need(
            identity["sha256"] == expected_sha256
            and int(identity["mode_octal"], 8) & 0o022 == 0,
            "bwrap-provenance-evidence-drift",
        )
        return raw, identity

    deb_raw, deb_identity = evidence_file(
        provenance["deb_path"], provenance["deb_sha256"], MAX_BWRAP_DEB_BYTES
    )
    deb = parse_reviewed_bwrap_deb(deb_raw)
    validate_deb_provenance_relationship(deb, provenance)
    upstream_raw, upstream_identity = evidence_file(
        provenance["upstream_verification_path"],
        provenance["upstream_verification_sha256"],
        MAX_PROVENANCE_EVIDENCE_BYTES,
    )
    upstream = parse_upstream_verification_evidence(upstream_raw, provenance)
    return {
        "root": {
            "path": str(root),
            "device": root_identity.st_dev,
            "inode": root_identity.st_ino,
            "mode_octal": f"{stat.S_IMODE(root_identity.st_mode):04o}",
        },
        "deb": deb_identity | {"parsed": deb},
        "upstream_verification": upstream_identity | {"parsed": upstream},
        "upstream_signature_cryptographically_reverified_locally": False,
    }


def valid_local_source_allowlist(value: object) -> bool:
    if type(value) is not dict or not value or len(value) > 100_000:
        return False
    roots = tuple(PurePosixPath(root) for root in LOCAL_SOURCE_ROOTS)
    for path, digest in value.items():
        if type(path) is not str or not is_sha256(digest):
            return False
        try:
            relative = safe_relative(path)
        except Refused:
            return False
        if any(part in EXCLUDED_TREE_PARTS for part in relative.parts):
            return False
        if not any(relative.is_relative_to(root) and relative != root for root in roots):
            return False
    return True


def valid_elf_closure_shape(value: object, bwrap_sha256: object) -> bool:
    if type(value) is not dict or set(value) != {
        "schema", "executable", "interpreter", "interpreter_resolved",
        "ld_so_cache", "objects",
    }:
        return False
    if (
        value["schema"] != "kpb-reviewed-bwrap-elf-closure/v1"
        or value["executable"] != str(BWRAP)
        or value["interpreter"] != BWRAP_INTERPRETER_LITERAL
        or value["interpreter_resolved"] != BWRAP_INTERPRETER_RESOLVED
        or value["ld_so_cache"] != "/etc/ld.so.cache"
        or type(value["objects"]) is not dict
        or not value["objects"]
    ):
        return False
    objects = value["objects"]
    if set(objects) != {str(BWRAP), *(set(BWRAP_RUNTIME_FILES) - {"/etc/ld.so.cache"})}:
        return False
    for path, row in objects.items():
        if (
            type(path) is not str
            or not path.startswith("/")
            or type(row) is not dict
            or set(row) != {
                "sha256", "build_id", "elf_type", "machine", "interpreter", "soname",
                "needed", "needed_paths", "rpath", "runpath",
            }
            or not is_sha256(row["sha256"])
            or type(row["build_id"]) is not str
            or re.fullmatch(r"[0-9a-f]{16,128}", row["build_id"]) is None
            or row["elf_type"] not in {2, 3}
            or row["machine"] != 62
            or (row["interpreter"] is not None and type(row["interpreter"]) is not str)
            or (
                row["soname"] is not None
                and not (
                    type(row["soname"]) is str
                    and bool(row["soname"])
                    and "/" not in row["soname"]
                )
            )
            or type(row["needed"]) is not list
            or not all(type(name) is str and name and "/" not in name for name in row["needed"])
            or len(row["needed"]) != len(set(row["needed"]))
            or type(row["needed_paths"]) is not dict
            or set(row["needed_paths"]) != set(row["needed"])
            or not all(
                type(resolved) is str and resolved in objects
                for resolved in row["needed_paths"].values()
            )
            or any(
                type(objects[resolved]) is not dict
                or objects[resolved].get("soname") != soname
                for soname, resolved in row["needed_paths"].items()
            )
            or row["rpath"] != []
            or row["runpath"] != []
        ):
            return False
    executable = objects[str(BWRAP)]
    if (
        executable["sha256"] != bwrap_sha256
        or executable["interpreter"] != value["interpreter"]
        or value["interpreter_resolved"] not in objects
        or any(
            row["interpreter"] not in {None, value["interpreter"]}
            for path, row in objects.items()
            if path != str(BWRAP)
        )
    ):
        return False
    reachable = {str(BWRAP), value["interpreter_resolved"]}
    pending = list(reachable)
    while pending:
        current = pending.pop()
        for resolved in objects[current]["needed_paths"].values():
            if resolved not in reachable:
                reachable.add(resolved)
                pending.append(resolved)
    return reachable == set(objects)


def valid_apparmor_policy_shape(value: object) -> bool:
    if type(value) is not dict or set(value) != {
        "schema", "executable", "profile_name", "mode", "source_sha256",
        "include_directories", "optional_absent",
    }:
        return False
    sources = value["source_sha256"]
    optional_absent = value["optional_absent"]
    include_directories = value["include_directories"]
    return (
        value["schema"] == "kpb-reviewed-bwrap-apparmor-policy/v1"
        and value["executable"] == str(BWRAP)
        and type(value["profile_name"]) is str
        and bool(value["profile_name"])
        and value["mode"] == "enforce"
        and type(sources) is dict
        and str(APPARMOR_PROFILE_SOURCE) in sources
        and all(
            type(path) is str
            and path.startswith("/etc/apparmor.d/")
            and is_sha256(digest)
            for path, digest in sources.items()
        )
        and type(optional_absent) is list
        and len(optional_absent) == len(set(optional_absent))
        and all(
            type(path) is str and path.startswith("/etc/apparmor.d/")
            for path in optional_absent
        )
        and not set(optional_absent) & set(sources)
        and type(include_directories) is dict
        and all(
            type(path) is str
            and path.startswith("/etc/apparmor.d/")
            and type(entries) is list
            and entries == sorted(entries)
            and len(entries) == len(set(entries))
            and all(
                type(name) is str
                and name
                and "/" not in name
                and name not in {".", ".."}
                and f"{path}/{name}" in sources
                for name in entries
            )
            for path, entries in include_directories.items()
        )
        and not set(include_directories) & (set(sources) | set(optional_absent))
    )


APPARMOR_INCLUDE = re.compile(
    rb'^\s*#?include\s+(?:(if)\s+exists\s+)?(?:<([^>]+)>|"([^"]+)")\s*,?\s*(?:#.*)?$'
)
APPARMOR_ABI = re.compile(
    rb'^\s*abi\s+(?:<([^>]+)>|"([^"]+)")\s*,\s*(?:#.*)?$'
)
APPARMOR_PROFILE_ATTACHMENT = re.compile(
    rb'^\s*profile\s+(?:"([^"]+)"|([^\s{]+))\s+'
    rb'(?:"([^"]+)"|(/[^\s{]+))(?:\s+flags\s*=\s*\([^)]*\))?\s*\{',
    re.MULTILINE,
)


def apparmor_include_path(parent: Path, token: bytes, *, angled: bool) -> Path:
    try:
        decoded = token.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refused("apparmor-include-encoding") from error
    need(decoded and "\x00" not in decoded, "apparmor-include-path")
    if angled:
        result = Path("/etc/apparmor.d") / decoded
    else:
        result = parent.parent / decoded
    need(result.is_absolute() and ".." not in result.parts, "apparmor-include-path")
    return result


def inspect_apparmor_include_directory(
    path: Path, reviewed_entries: list[str]
) -> tuple[list[Path], dict[str, object]]:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        value = os.fstat(descriptor)
        need(
            stat.S_ISDIR(value.st_mode)
            and value.st_uid == 0
            and stat.S_IMODE(value.st_mode) & 0o022 == 0,
            "apparmor-include-directory",
        )
        observed_entries = sorted(os.listdir(descriptor))
        need(observed_entries == reviewed_entries, "apparmor-include-directory-drift")
        for name in observed_entries:
            child = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            need(stat.S_ISREG(child.st_mode), "apparmor-include-directory-entry")
    finally:
        os.close(descriptor)
    return [path / name for name in reviewed_entries], {
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode_octal": f"{stat.S_IMODE(value.st_mode):04o}",
        "entries": list(reviewed_entries),
    }


def validate_apparmor_policy() -> dict[str, object]:
    policy = REVIEWED_BWRAP_APPARMOR_POLICY
    need(valid_apparmor_policy_shape(policy), "bwrap-apparmor-policy-review-not-bound")
    assert type(policy) is dict
    reviewed_sources = policy["source_sha256"]
    assert type(reviewed_sources) is dict
    reviewed_absent = set(policy["optional_absent"])
    reviewed_directories = policy["include_directories"]
    assert type(reviewed_directories) is dict
    pending = [APPARMOR_PROFILE_SOURCE]
    observed: dict[str, dict] = {}
    source_raws: dict[str, bytes] = {}
    observed_directories: dict[str, dict[str, object]] = {}
    while pending:
        path = pending.pop()
        raw_path = str(path)
        if raw_path in observed:
            continue
        need(raw_path in reviewed_sources, "apparmor-include-not-reviewed")
        raw, identity = stable_file(path, owner_uid=0)
        need(
            identity["sha256"] == reviewed_sources[raw_path]
            and int(identity["mode_octal"], 8) & 0o022 == 0,
            "bwrap-apparmor-source-drift",
        )
        observed[raw_path] = identity
        source_raws[raw_path] = raw
        for line in raw.splitlines():
            include_match = APPARMOR_INCLUDE.fullmatch(line)
            abi_match = APPARMOR_ABI.fullmatch(line)
            if include_match is None and abi_match is None:
                need(
                    re.match(rb"^\s*(?:#?include|abi)\b", line) is None,
                    "apparmor-include-syntax",
                )
                continue
            optional = include_match is not None and include_match.group(1) is not None
            if include_match is not None:
                angled_token, quoted_token = include_match.group(2), include_match.group(3)
            else:
                assert abi_match is not None
                angled_token, quoted_token = abi_match.group(1), abi_match.group(2)
            included = apparmor_include_path(
                path,
                angled_token if angled_token is not None else quoted_token,
                angled=angled_token is not None,
            )
            raw_included = str(included)
            if optional and raw_included in reviewed_absent:
                need(not os.path.lexists(included), "apparmor-optional-include-appeared")
            elif raw_included in reviewed_directories:
                need(
                    raw_included not in observed_directories,
                    "apparmor-include-directory-duplicate",
                )
                children, directory_identity = inspect_apparmor_include_directory(
                    included, reviewed_directories[raw_included]
                )
                observed_directories[raw_included] = directory_identity
                pending.extend(children)
            else:
                pending.append(included)
    need(set(observed) == set(reviewed_sources), "apparmor-source-closure")
    need(
        set(observed_directories) == set(reviewed_directories),
        "apparmor-include-directory-closure",
    )
    for raw_path in reviewed_absent:
        need(not os.path.lexists(raw_path), "apparmor-optional-include-appeared")

    attachments: list[tuple[str, str]] = []
    for match in APPARMOR_PROFILE_ATTACHMENT.finditer(
        source_raws[str(APPARMOR_PROFILE_SOURCE)]
    ):
        name_raw = match.group(1) if match.group(1) is not None else match.group(2)
        path_raw = match.group(3) if match.group(3) is not None else match.group(4)
        try:
            attachments.append((name_raw.decode("utf-8"), path_raw.decode("utf-8")))
        except UnicodeDecodeError as error:
            raise Refused("apparmor-profile-attachment") from error
    need(
        attachments.count((policy["profile_name"], policy["executable"])) == 1,
        "apparmor-profile-attachment",
    )

    return {
        "profile_name": policy["profile_name"],
        "mode": "enforce",
        "source_closure": observed,
        "include_directory_closure": observed_directories,
        "optional_absent": sorted(reviewed_absent),
        # Ubuntu deliberately denies unprivileged reads of the global loaded
        # profile table on this host.  Source closure is authenticated here;
        # actual attachment is authenticated after exec from the live process'
        # /proc/<pid>/attr/current while a reviewed --block-fd barrier holds it.
        "loaded_profile_table_preflight_used": False,
        "live_exec_label_required": True,
        "loaded_policy_byte_identity_authenticated": False,
    }


def authenticate_open_executable_fd(
    descriptor: int, path: Path, reviewed: dict
) -> dict:
    """Bind the exact already-open exec FD to its reviewed path identity."""
    before_path = os.lstat(path)
    before = os.fstat(descriptor)
    blocks: list[bytes] = []
    offset = 0
    while True:
        block = os.pread(descriptor, 1024 * 1024, offset)
        if not block:
            break
        blocks.append(block)
        offset += len(block)
    after = os.fstat(descriptor)
    after_path = os.lstat(path)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and before.st_nlink == 1
        and stat.S_IMODE(before.st_mode) & 0o111 != 0
        and stat.S_IMODE(before.st_mode) & 0o022 == 0
        and identity(before_path)
        == identity(before)
        == identity(after)
        == identity(after_path),
        "bwrap-open-fd-identity",
    )
    raw = b"".join(blocks)
    need(
        len(raw) == before.st_size
        and sha256_bytes(raw) == reviewed.get("sha256")
        and before.st_dev == reviewed.get("device")
        and before.st_ino == reviewed.get("inode")
        and before.st_mtime_ns == reviewed.get("mtime_ns")
        and before.st_ctime_ns == reviewed.get("ctime_ns"),
        "bwrap-open-fd-review-binding",
    )
    return {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "device": before.st_dev,
        "inode": before.st_ino,
    }


def exact_nested_runtime_bindings(objects: dict[str, dict]) -> tuple[tuple[str, str], ...]:
    need(
        str(BWRAP) in objects and BWRAP_INTERPRETER_RESOLVED in objects,
        "nested-runtime-bwrap-object",
    )
    paths = ["/etc/ld.so.cache"] + [
        path for path in objects if path != str(BWRAP)
    ]
    need(
        all(
            type(path) is str
            and path.startswith("/")
            and ".." not in PurePosixPath(path).parts
            and "glibc-hwcaps" not in PurePosixPath(path).parts
            for path in paths
        ),
        "nested-runtime-object-path",
    )
    need(len(paths) == len(set(paths)), "nested-runtime-object-duplicate")
    bindings = [(path, path) for path in paths]
    bindings.append((BWRAP_INTERPRETER_RESOLVED, BWRAP_INTERPRETER_LITERAL))
    return tuple(sorted(bindings, key=lambda row: row[1]))


def validate_bwrap_elf_closure() -> dict[str, dict]:
    closure = REVIEWED_BWRAP_ELF_CLOSURE
    bwrap_sha = (
        REVIEWED_LEAF_TOOL_SHA256.get("bwrap")
        if type(REVIEWED_LEAF_TOOL_SHA256) is dict
        else None
    )
    need(
        valid_elf_closure_shape(closure, bwrap_sha),
        "bwrap-elf-closure-review-not-bound",
    )
    assert type(closure) is dict
    objects = closure["objects"]
    assert type(objects) is dict
    need(
        type(REVIEWED_ROOT_RUNTIME_SHA256) is dict
        and REVIEWED_ROOT_RUNTIME_SHA256.get("/etc/ld.so.cache") is not None
        and {
            path: row["sha256"]
            for path, row in objects.items()
            if path != str(BWRAP)
        }
        == {
            path: digest
            for path, digest in REVIEWED_ROOT_RUNTIME_SHA256.items()
            if path != "/etc/ld.so.cache"
        },
        "bwrap-elf-root-runtime-mismatch",
    )
    validated: dict[str, dict] = {}
    for raw_path, reviewed in objects.items():
        assert type(raw_path) is str and type(reviewed) is dict
        path = Path(raw_path)
        need(path == path.resolve(strict=True), "bwrap-elf-object-not-canonical")
        raw, identity = stable_file(path, owner_uid=0)
        parsed = parse_elf_dynamic_identity(raw)
        need(
            identity["sha256"] == reviewed["sha256"]
            and int(identity["mode_octal"], 8) & 0o022 == 0
            and parsed
            == {
                "elf_type": reviewed["elf_type"],
                "machine": reviewed["machine"],
                "build_id": reviewed["build_id"],
                "interpreter": reviewed["interpreter"],
                "soname": reviewed["soname"],
                "needed": reviewed["needed"],
                "rpath": reviewed["rpath"],
                "runpath": reviewed["runpath"],
            },
            "bwrap-elf-object-drift",
        )
        validated[raw_path] = identity | {
            "elf": parsed,
            "needed_paths": reviewed["needed_paths"],
        }
    cache_raw, cache_identity = stable_file(Path("/etc/ld.so.cache"), owner_uid=0)
    need(
        cache_identity["sha256"] == REVIEWED_ROOT_RUNTIME_SHA256["/etc/ld.so.cache"]
        and int(cache_identity["mode_octal"], 8) & 0o022 == 0,
        "ld-cache-drift",
    )
    cache = parse_ld_so_cache_x86_64(cache_raw)
    resolutions: dict[str, dict[str, str]] = {}
    cache_candidate_routes: dict[str, dict[str, object]] = {}
    nested_bindings = exact_nested_runtime_bindings(objects)
    for raw_path, reviewed in objects.items():
        per_object: dict[str, str] = {}
        for soname, expected_path in reviewed["needed_paths"].items():
            candidates = cache.get(soname, [])
            need(len(candidates) == 1, "ld-cache-resolution-count")
            candidate = Path(candidates[0])
            need(
                cache_candidate_has_exact_parent(candidates[0], expected_path)
                and candidate.parent == candidate.parent.resolve(strict=True)
                and str(candidate.resolve(strict=True)) == expected_path,
                "ld-cache-resolution-drift",
            )
            route = os.lstat(candidate)
            symlink_target = (
                os.readlink(candidate) if stat.S_ISLNK(route.st_mode) else None
            )
            need(
                route.st_uid == 0
                and route.st_nlink == 1
                and (stat.S_ISREG(route.st_mode) or stat.S_ISLNK(route.st_mode)),
                "ld-cache-candidate-route",
            )
            need(
                cache_candidate_route_is_direct(
                    candidates[0], expected_path, symlink_target
                ),
                "ld-cache-candidate-symlink-route",
            )
            route_identity = {
                "path": candidates[0],
                "device": route.st_dev,
                "inode": route.st_ino,
                "uid": route.st_uid,
                "gid": route.st_gid,
                "mode_octal": f"{stat.S_IMODE(route.st_mode):04o}",
                "symlink_target": symlink_target,
                "resolved": expected_path,
            }
            prior_route = cache_candidate_routes.setdefault(candidates[0], route_identity)
            need(prior_route == route_identity, "ld-cache-candidate-route-drift")
            per_object[soname] = candidates[0]
        resolutions[raw_path] = per_object
    interpreter = Path(closure["interpreter"])
    need(
        str(interpreter.resolve(strict=True)) == closure["interpreter_resolved"],
        "bwrap-interpreter-resolution-drift",
    )
    provenance = REVIEWED_BWRAP_PROVENANCE
    assert type(provenance) is dict
    need(
        objects[str(BWRAP)]["sha256"] == provenance["elf_sha256"]
        and objects[str(BWRAP)]["build_id"] == provenance["elf_build_id"],
        "bwrap-provenance-elf-mismatch",
    )
    return {
        "objects": validated,
        "ld_so_cache": cache_identity,
        "ld_so_cache_x86_64_flags": LD_SO_CACHE_X86_64_FLAGS,
        "ld_so_cache_header_endianness": "little",
        "ld_so_cache_allowed_extension_tags": [
            LD_SO_CACHE_EXTENSION_GENERATOR
        ],
        "ld_so_cache_loader_affecting_or_unknown_extensions_allowed": False,
        "needed_resolutions": resolutions,
        "cache_candidate_routes": cache_candidate_routes,
        "interpreter_literal": closure["interpreter"],
        "interpreter_resolved": closure["interpreter_resolved"],
        "nested_runtime_bindings": [
            {"source": source, "destination": destination}
            for source, destination in nested_bindings
        ],
    }


def tree_file_candidates(root: Path, prefix: str) -> list[tuple[Path, str]]:
    need(root.is_absolute() and root == root.resolve(strict=True), "tree-root-canonical")
    candidates: list[tuple[Path, str]] = []

    def walk_error(error: OSError) -> None:
        raise Refused("tree-walk-error") from error

    for directory, names, files in os.walk(
        root, topdown=True, onerror=walk_error, followlinks=False
    ):
        directory_path = Path(directory)
        names[:] = sorted(name for name in names if name not in EXCLUDED_TREE_PARTS)
        for name in names:
            candidate = directory_path / name
            need(not candidate.is_symlink(), "tree-directory-symlink")
        for name in sorted(files):
            candidate = directory_path / name
            relative = candidate.relative_to(root).as_posix()
            if any(part in EXCLUDED_TREE_PARTS for part in PurePosixPath(relative).parts):
                continue
            candidates.append((candidate, f"{prefix}/{relative}"))
    need(
        candidates
        and len({logical for _, logical in candidates}) == len(candidates),
        "tree-records",
    )
    return candidates


def records_from_tree_candidates(candidates: list[tuple[Path, str]]) -> list[dict]:
    records: list[dict] = []
    for candidate, logical in candidates:
        _, identity = stable_file(candidate)
        records.append(
            {
                "path": logical,
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
                "mode_octal": identity["mode_octal"],
            }
        )
    records.sort(key=lambda row: row["path"])
    need(records and len({row["path"] for row in records}) == len(records), "tree-records")
    return records


def iter_tree_records(root: Path, prefix: str) -> list[dict]:
    return records_from_tree_candidates(tree_file_candidates(root, prefix))


def local_source_manifest() -> dict:
    need(
        valid_local_source_allowlist(REVIEWED_LOCAL_SOURCE_FILES_SHA256),
        "local-source-file-review-not-bound",
    )
    assert type(REVIEWED_LOCAL_SOURCE_FILES_SHA256) is dict
    candidates: list[tuple[Path, str]] = []
    for relative in LOCAL_SOURCE_ROOTS:
        root = REPO_ROOT.joinpath(*safe_relative(relative).parts)
        candidates.extend(tree_file_candidates(root, relative))
    observed_paths = {logical for _, logical in candidates}
    need(
        len(observed_paths) == len(candidates)
        and observed_paths == set(REVIEWED_LOCAL_SOURCE_FILES_SHA256),
        "local-source-unreviewed-extra-or-drift",
    )
    records = records_from_tree_candidates(candidates)
    observed = {row["path"]: row["sha256"] for row in records}
    need(observed == REVIEWED_LOCAL_SOURCE_FILES_SHA256, "local-source-content-drift")
    return {
        "schema": "kpb-w1-local-source-tree/v1",
        "roots": list(LOCAL_SOURCE_ROOTS),
        "finite_reviewed_file_allowlist": sorted(REVIEWED_LOCAL_SOURCE_FILES_SHA256),
        "records": records,
        "tree_sha256": sha256_bytes(canonical(records)),
    }


def locked_registry_packages() -> list[str]:
    lock_raw, _ = stable_file(REPO_ROOT.joinpath(*safe_relative(LOCK_RELATIVE).parts))
    lock = tomllib.loads(lock_raw.decode("utf-8"))
    packages: set[str] = set()
    for package in lock.get("package", []):
        source = package.get("source")
        need(
            source is None
            or (
                type(source) is str
                and source.startswith("registry+")
                and "crates.io-index" in source
            ),
            "unsupported-locked-source",
        )
        if type(source) is str and source.startswith("registry+"):
            name = package.get("name")
            version = package.get("version")
            checksum = package.get("checksum")
            need(
                type(name) is str
                and re.fullmatch(r"[A-Za-z0-9_-]+", name) is not None
                and type(version) is str
                and re.fullmatch(r"[0-9A-Za-z.+-]+", version) is not None
                and is_sha256(checksum),
                "locked-registry-package",
            )
            packages.add(f"{name}-{version}")
    need(packages, "locked-registry-empty")
    return sorted(packages)


def vendor_manifest() -> dict:
    records: list[dict] = []
    packages = locked_registry_packages()
    for package in packages:
        package_root = REGISTRY_ROOT / package
        need(package_root.resolve(strict=True).parent == REGISTRY_ROOT, "vendor-package-root")
        records.extend(iter_tree_records(package_root, package))
    records.sort(key=lambda row: row["path"])
    return {
        "schema": "kpb-w1-vendor-tree/v1",
        "packages": packages,
        "records": records,
        "tree_sha256": sha256_bytes(canonical(records)),
    }


def toolchain_manifest() -> dict:
    records = iter_tree_records(TOOLCHAIN_ROOT, "toolchain")
    records.sort(key=lambda row: row["path"])
    return {
        "schema": "kpb-w1-toolchain-tree/v1",
        "records": records,
        "tree_sha256": sha256_bytes(canonical(records)),
    }


def validate_hash_gate(value: object, observed: str, category: str) -> None:
    need(is_sha256(value) and value == observed, category)


def validate_review_gates(
    local: dict, vendor: dict, toolchain: dict
) -> dict[str, dict]:
    validate_hash_gate(
        REVIEWED_LOCAL_SOURCE_TREE_SHA256,
        local["tree_sha256"],
        "local-source-review-not-bound",
    )
    validate_hash_gate(
        REVIEWED_VENDOR_TREE_SHA256,
        vendor["tree_sha256"],
        "vendor-review-not-bound",
    )
    validate_hash_gate(
        REVIEWED_TOOLCHAIN_TREE_SHA256,
        toolchain["tree_sha256"],
        "toolchain-review-not-bound",
    )
    need(
        type(REVIEWED_LEAF_TOOL_SHA256) is dict
        and set(REVIEWED_LEAF_TOOL_SHA256) == set(LEAF_TOOLS),
        "leaf-tool-review-not-bound",
    )
    identities: dict[str, dict] = {}
    for name, path in LEAF_TOOLS.items():
        raw, identity = stable_file(
            path,
            owner_uid=0 if name in {"python", "bwrap", "env"} else os.getuid(),
            allow_hardlinks=name == "env",
        )
        need(identity["sha256"] == REVIEWED_LEAF_TOOL_SHA256[name], "leaf-tool-drift")
        if name == "bwrap":
            need(
                int(identity["mode_octal"], 8) & 0o111 != 0
                and int(identity["mode_octal"], 8) & 0o022 == 0,
                "bwrap-mode",
            )
        identities[name] = identity | {"path": str(path)}
    need(
        bwrap_version_tuple(REVIEWED_BWRAP_VERSION) is not None
        and bwrap_version_tuple(REVIEWED_BWRAP_VERSION) >= MINIMUM_BWRAP_VERSION,
        "bwrap-version-review-not-bound",
    )
    need(
        REVIEWED_BWRAP_APPARMOR_EXEC_PATH == str(BWRAP),
        "bwrap-apparmor-path-review-not-bound",
    )
    need(
        is_sha256(REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256),
        "bwrap-apparmor-profile-review-not-bound",
    )
    apparmor_policy = validate_apparmor_policy()
    apparmor_profile = apparmor_policy["source_closure"][str(APPARMOR_PROFILE_SOURCE)]
    need(apparmor_profile["sha256"] == REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256,
         "bwrap-apparmor-profile-drift")
    need(
        valid_bwrap_provenance(
            REVIEWED_BWRAP_PROVENANCE, REVIEWED_LEAF_TOOL_SHA256["bwrap"]
        ),
        "bwrap-provenance-review-not-bound",
    )
    provenance_evidence = validate_bwrap_provenance_evidence()
    elf_closure = validate_bwrap_elf_closure()
    need(
        type(REVIEWED_ROOT_RUNTIME_SHA256) is dict
        and set(REVIEWED_ROOT_RUNTIME_SHA256) == set(BWRAP_RUNTIME_FILES),
        "root-runtime-review-not-bound",
    )
    root_runtime: dict[str, dict] = {}
    for raw_path, expected in REVIEWED_ROOT_RUNTIME_SHA256.items():
        need(type(raw_path) is str and raw_path.startswith("/"), "root-runtime-path")
        path = Path(raw_path)
        raw, identity = stable_file(path, owner_uid=0)
        need(
            is_sha256(expected)
            and identity["sha256"] == expected
            and int(identity["mode_octal"], 8) & 0o022 == 0,
            "root-runtime-drift",
        )
        root_runtime[raw_path] = identity
    for raw_path in BWRAP_RUNTIME_REQUIRED_ABSENT:
        need(not os.path.lexists(raw_path), "root-runtime-forbidden-preload")
    return {
        "leaf_tools": identities,
        "root_runtime": root_runtime,
        "bwrap_elf_closure": elf_closure,
        "bwrap_provenance_evidence": provenance_evidence,
        "apparmor_profile": apparmor_profile | {"path": str(APPARMOR_PROFILE_SOURCE)},
        "apparmor_policy": apparmor_policy,
    }


def seccomp_filter_bytes() -> bytes:
    # struct sock_filter: u16 code, u8 jt, u8 jf, u32 k
    load_word_abs = 0x20
    jump_equal = 0x15
    jump_bits_set = 0x45
    return_k = 0x06
    instructions: list[tuple[int, int, int, int]] = [
        (load_word_abs, 0, 0, 4),
        (jump_equal, 1, 0, AUDIT_ARCH_X86_64),
        (return_k, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (load_word_abs, 0, 0, 0),
        (jump_bits_set, 0, 1, X32_SYSCALL_BIT),
        (return_k, 0, 0, SECCOMP_RET_KILL_PROCESS),
    ]
    for number in sorted(DENIED_SYSCALLS_X86_64):
        instructions.append((jump_equal, 0, 1, number))
        instructions.append((return_k, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM))
    instructions.append((return_k, 0, 0, SECCOMP_RET_ALLOW))
    need(len(instructions) < 4096, "seccomp-program-too-large")
    return b"".join(struct.pack("HBBI", *instruction) for instruction in instructions)


def sealed_memfd(name: str, raw: bytes) -> int:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    offset = 0
    while offset < len(raw):
        offset += os.write(descriptor, raw[offset:])
    os.fsync(descriptor)
    fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
    need(fcntl.fcntl(descriptor, F_GET_SEALS) == REQUIRED_SEALS, "memfd-seals")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor


def read_sealed_fd(descriptor: int, expected_sha256: str | None = None) -> bytes:
    need(fcntl.fcntl(descriptor, F_GET_SEALS) == REQUIRED_SEALS, "sealed-fd-required")
    value = os.fstat(descriptor)
    need(stat.S_ISREG(value.st_mode), "sealed-fd-regular")
    raw = os.pread(descriptor, value.st_size, 0)
    need(len(raw) == value.st_size, "sealed-fd-short-read")
    if expected_sha256 is not None:
        need(sha256_bytes(raw) == expected_sha256, "sealed-fd-hash")
    return raw


def external_stage0_contract(source_identity: dict, source_sha256: str) -> dict:
    need(is_sha256(source_sha256), "stage0-source-sha")
    contract = {
        "schema": STAGE0_CONTRACT_SCHEMA,
        "source_path": str(SOURCE_PATH),
        "source_sha256": source_sha256,
        "source_bytes": source_identity["bytes"],
        "source_device": source_identity["device"],
        "source_inode": source_identity["inode"],
        "source_mtime_ns": source_identity["mtime_ns"],
        "source_ctime_ns": source_identity["ctime_ns"],
        "external_bootstrap_source_sha256": sha256_bytes(
            EXTERNAL_STAGE0_SOURCE.encode("utf-8")
        ),
        "authorization": False,
    }
    contract["contract_sha256"] = sha256_bytes(canonical(contract))
    return contract


EXTERNAL_STAGE0_SOURCE = r'''import base64,fcntl,hashlib,json,os,stat,sys
F_ADD_SEALS=getattr(fcntl,"F_ADD_SEALS",1033)
F_GET_SEALS=getattr(fcntl,"F_GET_SEALS",1034)
SEALS=(getattr(fcntl,"F_SEAL_SEAL",1)|getattr(fcntl,"F_SEAL_SHRINK",2)|getattr(fcntl,"F_SEAL_GROW",4)|getattr(fcntl,"F_SEAL_WRITE",8))
ENV={"HOME":"/nonexistent","PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","TZ":"UTC","PYTHONDONTWRITEBYTECODE":"1","KPB_W1_BWRAP_STAGE0":"1"}
SOURCE="/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/local-private-payment/private_batch_trial/freeze_w1_proof_build_bwrap.py"
KEYS={"schema","source_path","source_sha256","source_bytes","source_device","source_inode","source_mtime_ns","source_ctime_ns","external_bootstrap_source_sha256","authorization","contract_sha256"}
def refuse(ok,code):
    if not ok: raise SystemExit(code)
def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def stable(path,expected):
    before_path=os.lstat(path)
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    before=os.fstat(fd); h=hashlib.sha256(); blocks=[]; offset=0
    while True:
        block=os.pread(fd,1024*1024,offset)
        if not block: break
        blocks.append(block); h.update(block); offset+=len(block)
    after=os.fstat(fd); after_path=os.lstat(path)
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    refuse(stat.S_ISREG(before.st_mode) and before.st_nlink==1,21)
    refuse(identity(before_path)==identity(before)==identity(after)==identity(after_path),22)
    refuse(offset==expected["source_bytes"] and h.hexdigest()==expected["source_sha256"],23)
    refuse((before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)==(expected["source_device"],expected["source_inode"],expected["source_mtime_ns"],expected["source_ctime_ns"]),24)
    os.close(fd); return b"".join(blocks)
def memfd(name,raw):
    fd=os.memfd_create(name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING); offset=0
    while offset<len(raw): offset+=os.write(fd,raw[offset:])
    fcntl.fcntl(fd,F_ADD_SEALS,SEALS); refuse(fcntl.fcntl(fd,F_GET_SEALS)==SEALS,25); os.lseek(fd,0,0); return fd
refuse(sys.flags.isolated==1 and sys.flags.dont_write_bytecode==1 and sys.flags.no_site==1 and sys.flags.safe_path,9)
refuse(len(sys.argv)==2 and dict(os.environ)==ENV,10)
try: contract_raw=base64.b64decode(sys.argv[1],validate=True); contract=json.loads(contract_raw)
except Exception: raise SystemExit(11)
refuse(type(contract) is dict and canonical(contract)==contract_raw,12)
refuse(set(contract)==KEYS and contract.get("source_path")==SOURCE and type(contract.get("source_bytes")) is int and contract["source_bytes"]>0 and all(type(contract.get(key)) is int for key in ("source_device","source_inode","source_mtime_ns","source_ctime_ns")),13)
claimed=contract.get("contract_sha256"); unsigned=dict(contract); unsigned.pop("contract_sha256",None)
refuse(claimed==hashlib.sha256(canonical(unsigned)).hexdigest(),14)
refuse(contract.get("schema")=="kpb-w1-bwrap-build-stage0-contract/v1" and contract.get("authorization") is False,15)
source_raw=stable(contract["source_path"],contract)
source_fd=memfd("kpb-w1-bwrap-freezer-source",source_raw); contract_fd=memfd("kpb-w1-bwrap-freezer-contract",contract_raw)
os.dup2(source_fd,3); os.dup2(contract_fd,4)
for fd in (3,4): fcntl.fcntl(fd,fcntl.F_SETFD,fcntl.fcntl(fd,fcntl.F_GETFD)&~fcntl.FD_CLOEXEC)
for raw_fd in os.listdir("/proc/self/fd"):
    fd=int(raw_fd)
    if fd>4:
        try: os.close(fd)
        except OSError: pass
os.execve("/usr/bin/python3.14",["/usr/bin/python3.14","-I","-B","-S","/proc/self/fd/3","--stage0-run",claimed],ENV)
'''


def render_external_stage0() -> dict:
    """Return, but never dispatch, the exact reviewed external bootstrap."""
    source_raw, identity = stable_file(SOURCE_PATH)
    contract = external_stage0_contract(identity, sha256_bytes(source_raw))
    contract_raw = canonical(contract)
    command = [
        str(ENV),
        "-i",
        *(f"{name}={value}" for name, value in STAGE0_ENVIRONMENT.items()),
        str(PYTHON),
        "-I",
        "-B",
        "-S",
        "-c",
        EXTERNAL_STAGE0_SOURCE,
        base64.b64encode(contract_raw).decode("ascii"),
    ]
    return {
        "contract": contract,
        "contract_sha256": contract["contract_sha256"],
        "contract_bytes_sha256": sha256_bytes(contract_raw),
        "external_bootstrap_source_sha256": sha256_bytes(
            EXTERNAL_STAGE0_SOURCE.encode("utf-8")
        ),
        "command": command,
        "command_sha256": sha256_bytes(canonical(command)),
        "executed": False,
        "authorization": False,
    }


def validate_stage0_entry(contract_sha256: str) -> dict:
    need(
        sys.flags.isolated == 1
        and sys.flags.dont_write_bytecode == 1
        and sys.flags.no_site == 1
        and sys.flags.safe_path,
        "stage0-python-flags",
    )
    need(dict(os.environ) == STAGE0_ENVIRONMENT, "stage0-environment")
    source_raw = read_sealed_fd(3)
    contract_raw = read_sealed_fd(4)
    try:
        contract = json.loads(contract_raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise Refused("stage0-contract-json") from error
    need(canonical(contract) == contract_raw, "stage0-contract-canonical")
    need(
        type(contract) is dict
        and set(contract)
        == {
            "schema",
            "source_path",
            "source_sha256",
            "source_bytes",
            "source_device",
            "source_inode",
            "source_mtime_ns",
            "source_ctime_ns",
            "external_bootstrap_source_sha256",
            "authorization",
            "contract_sha256",
        }
        and type(contract.get("source_bytes")) is int
        and contract["source_bytes"] > 0
        and all(
            type(contract.get(key)) is int
            for key in (
                "source_device",
                "source_inode",
                "source_mtime_ns",
                "source_ctime_ns",
            )
        ),
        "stage0-contract-shape",
    )
    unsigned = dict(contract)
    claimed = unsigned.pop("contract_sha256", None)
    need(
        claimed == contract_sha256 == sha256_bytes(canonical(unsigned))
        and contract.get("schema") == STAGE0_CONTRACT_SCHEMA
        and contract.get("source_path") == str(SOURCE_PATH)
        and contract.get("source_sha256") == sha256_bytes(source_raw)
        and contract.get("source_bytes") == len(source_raw)
        and contract.get("external_bootstrap_source_sha256")
        == sha256_bytes(EXTERNAL_STAGE0_SOURCE.encode("utf-8"))
        and contract.get("authorization") is False,
        "stage0-contract-binding",
    )
    source_stat = os.fstat(3)
    need(
        (source_stat.st_dev, source_stat.st_ino)
        != (contract["source_device"], contract["source_inode"]),
        "stage0-source-must-be-detached-memfd",
    )
    allowed = {0, 1, 2, 3, 4}
    live: set[int] = set()
    for raw_descriptor in os.listdir("/proc/self/fd"):
        descriptor = int(raw_descriptor)
        try:
            os.fstat(descriptor)
        except OSError as error:
            need(error.errno == errno.EBADF, "stage0-fd-enumeration")
        else:
            live.add(descriptor)
    need(live == allowed, "stage0-fd-allowlist")
    return contract


INNER_BUILD_SOURCE = r'''import errno,hashlib,json,os,resource,socket,stat,struct,subprocess,sys
MAGIC=b"KPB-W1-BWRAP-BUILD\x00\x01"
ENV=__KPB_INNER_ENV__
PROVER="prove_frozen_w1_round1"; VERIFIER="verify_frozen_w1_round1_receipt"
def refuse(ok,code):
    if not ok: raise SystemExit(code)
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def stable(path):
    before_path=os.lstat(path); fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd); blocks=[]; h=hashlib.sha256(); offset=0
    while True:
        block=os.pread(fd,1024*1024,offset)
        if not block: break
        blocks.append(block); h.update(block); offset+=len(block)
    after=os.fstat(fd); after_path=os.lstat(path); os.close(fd)
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    refuse(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and identity(before_path)==identity(before)==identity(after)==identity(after_path),30)
    raw=b"".join(blocks); refuse(len(raw)==before.st_size,31); return raw,h.hexdigest(),stat.S_IMODE(before.st_mode)
refuse(sys.flags.isolated==1 and sys.flags.dont_write_bytecode==1 and sys.flags.no_site==1 and sys.flags.safe_path,9)
refuse(dict(os.environ)==ENV,10)
refuse(os.getcwd()=="/",11)
live=[]
for raw in os.listdir("/proc/self/fd"):
    try: os.fstat(int(raw)); live.append(int(raw))
    except OSError: pass
refuse(sorted(live)==[0,1,2],12)
mounts={}
for line in open("/proc/self/mountinfo","rb"):
    left,right=line.rstrip(b"\n").split(b" - ",1); fields=left.split(); tail=right.split(); mounts[fields[4]]=(set(fields[5].split(b",")),tail[0])
for mountpoint in mounts:
    refuse(not (mountpoint.startswith(b"/home/luke") or mountpoint.startswith(b"/run") or mountpoint.startswith(b"/.local") or mountpoint.startswith(b"/host-") or mountpoint.startswith(b"/stage")),13)
for required in (b"/src",b"/vendor",b"/toolchain",b"/cargo-home"):
    refuse(required in mounts and b"ro" in mounts[required][0],14)
for required in (b"/target",b"/tmp",b"/usr/local"):
    refuse(required in mounts and b"rw" in mounts[required][0] and mounts[required][1]==b"tmpfs",15)
refuse(not stat.S_ISREG(os.stat("/usr/bin/bwrap",follow_symlinks=True).st_mode),16)
for probe in (lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM),lambda:socket.socketpair()):
    try: probe()
    except OSError as error: refuse(error.errno==errno.EPERM,17)
    else: raise SystemExit(18)
ipv6_routes=[line.split() for line in open("/proc/net/ipv6_route","rb") if line.strip()]
refuse(open("/proc/net/route","rb").read().count(b"\n")<=1 and all(row[-1]==b"lo" for row in ipv6_routes),19)
resource.setrlimit(resource.RLIMIT_CORE,(0,0)); resource.setrlimit(resource.RLIMIT_AS,(__KPB_MEMORY_LIMIT__,__KPB_MEMORY_LIMIT__)); resource.setrlimit(resource.RLIMIT_FSIZE,(__KPB_FILE_LIMIT__,__KPB_FILE_LIMIT__)); resource.setrlimit(resource.RLIMIT_NOFILE,(64,64)); resource.setrlimit(resource.RLIMIT_NPROC,(4096,4096))
refuse(resource.getrlimit(resource.RLIMIT_CORE)==(0,0) and resource.getrlimit(resource.RLIMIT_AS)==(__KPB_MEMORY_LIMIT__,__KPB_MEMORY_LIMIT__) and resource.getrlimit(resource.RLIMIT_FSIZE)==(__KPB_FILE_LIMIT__,__KPB_FILE_LIMIT__) and resource.getrlimit(resource.RLIMIT_NOFILE)==(64,64) and resource.getrlimit(resource.RLIMIT_NPROC)==(4096,4096),20)
command=["/toolchain/bin/cargo","build","--manifest-path","/src/__KPB_MANIFEST__","--target-dir","/target","--release","--frozen","--offline","--no-default-features","--features","offline-w1-prover","--example",PROVER,"--example",VERIFIER]
result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False,close_fds=True)
refuse(result.returncode==0,21)
pids={int(name) for name in os.listdir("/proc") if name.isdigit()}
refuse(pids.issubset({1,os.getpid()}),22)
paths=[("prover","/target/release/examples/"+PROVER),("verifier","/target/release/examples/"+VERIFIER),("prover_dep_info","/target/release/examples/"+PROVER+".d"),("verifier_dep_info","/target/release/examples/"+VERIFIER+".d")]
entries=[]; payloads=[]; total=0
for name,path in paths:
    raw,digest,mode=stable(path); refuse(0<len(raw)<=268435456,32); total+=len(raw); refuse(total<=536870912,33); entries.append({"name":name,"bytes":len(raw),"sha256":digest,"mode_octal":format(mode,"04o")}); payloads.append(raw)
header={"schema":"kpb-w1-bwrap-build-frame/v1","entries":entries,"cargo_command":command,"proof_executed":False,"verifier_executed":False,"setup_or_pk_read":False,"network_communication":False,"authorization":False}
header_raw=canonical(header); refuse(len(header_raw)<=65536,34)
os.write(1,MAGIC+struct.pack(">Q",len(header_raw))+header_raw)
for raw in payloads: os.write(1,struct.pack(">Q",len(raw)))
for raw in payloads:
    offset=0
    while offset<len(raw): offset+=os.write(1,raw[offset:])
'''


def rendered_inner_source() -> str:
    source = INNER_BUILD_SOURCE.replace(
        "__KPB_INNER_ENV__", repr(SANDBOX_ENVIRONMENT)
    )
    source = source.replace("__KPB_MEMORY_LIMIT__", str(MEMORY_LIMIT_BYTES))
    source = source.replace("__KPB_FILE_LIMIT__", str(FILE_LIMIT_BYTES))
    source = source.replace("__KPB_MANIFEST__", MANIFEST_RELATIVE)
    return source


OUTER_COPY_SOURCE = r'''import base64,errno,hashlib,json,os,selectors,signal,socket,stat,subprocess,sys,time
ENV=__KPB_OUTER_ENV__; BWRAP="/usr/bin/bwrap"; INNER=base64.b64decode("__KPB_INNER_B64__")
FLAGS=__KPB_FINAL_FLAGS__; INNER_ENV=__KPB_INNER_ENV__; RUNTIME=__KPB_BWRAP_RUNTIME__; ROUTES=__KPB_BWRAP_ROUTES__; MAX_OUTPUT=__KPB_MAX_OUTPUT__; MAX_ERROR=__KPB_MAX_ERROR__
def refuse(ok,code):
    if not ok: raise SystemExit(code)
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def stable(path):
    before_path=os.lstat(path); fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd); blocks=[]; h=hashlib.sha256(); offset=0
    while True:
        block=os.pread(fd,1024*1024,offset)
        if not block: break
        blocks.append(block); h.update(block); offset+=len(block)
    after=os.fstat(fd); after_path=os.lstat(path); os.close(fd); identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    refuse(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and identity(before_path)==identity(before)==identity(after)==identity(after_path),30)
    raw=b"".join(blocks); refuse(len(raw)==before.st_size,31); return raw,h.hexdigest()
def allowed_system_mount(mountpoint):
    allowed={b"/usr",b"/lib",b"/usr/bin/bwrap"}|{path.encode() for path in RUNTIME}; system=any(mountpoint==root or mountpoint.startswith(root+b"/") for root in (b"/usr",b"/lib",b"/lib64")); return not system or mountpoint in allowed
def followed_digest(path):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC); value=os.fstat(fd); h=hashlib.sha256(); offset=0
    refuse(stat.S_ISREG(value.st_mode),51)
    while True:
        block=os.pread(fd,1024*1024,offset)
        if not block: break
        h.update(block); offset+=len(block)
    os.close(fd); refuse(offset==value.st_size,52); return h.hexdigest()
def load_manifest(path,expected):
    raw,digest=stable(path); refuse(digest==expected,32); value=json.loads(raw); refuse(canonical(value)==raw and value.get("tree_sha256")==hashlib.sha256(canonical(value["records"])).hexdigest(),33); return value
def copy_manifest(value,kind):
    for row in value["records"]:
        relative=row["path"]; refuse(type(relative) is str and relative and not relative.startswith("/") and ".." not in relative.split("/"),34)
        if kind=="local": source="/host-repo/"+relative; dest="/stage/src/"+relative
        elif kind=="vendor": source="/host-registry/"+relative; dest="/stage/vendor/"+relative
        else: refuse(relative.startswith("toolchain/"),35); source="/host-toolchain/"+relative[len("toolchain/"):]; dest="/stage/toolchain/"+relative[len("toolchain/"):]
        raw,digest=stable(source); refuse(len(raw)==row["bytes"] and digest==row["sha256"],36); os.makedirs(os.path.dirname(dest),mode=0o700,exist_ok=True); fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); offset=0
        while offset<len(raw): offset+=os.write(fd,raw[offset:])
        os.fsync(fd); os.close(fd); os.chmod(dest,int(row["mode_octal"],8))
def namespaces(pid):
    result={}
    for name in ("mnt","user","ipc","pid","net","uts","cgroup"):
        value=os.stat("/proc/"+str(pid)+"/ns/"+name,follow_symlinks=True); result[name]=(value.st_dev,value.st_ino)
    return result
def ppid(pid):
    for line in open("/proc/"+str(pid)+"/status","rb"):
        if line.startswith(b"PPid:"): return int(line.split(b":",1)[1].strip())
    raise SystemExit(39)
def terminate(process,child_pid,pidfd):
    if pidfd is not None:
        try: signal.pidfd_send_signal(pidfd,signal.SIGKILL)
        except (AttributeError,ProcessLookupError,OSError): pass
    for pid in (child_pid,process.pid):
        if pid:
            try: os.kill(pid,signal.SIGKILL)
            except ProcessLookupError: pass
    try: os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    try: os.wait4(process.pid,0)
    except ChildProcessError: pass
def bounded(process,status_fd,status_write_fd):
    status_stream=None; selector=None; pidfd=None; child_ns=None; child_pid=None; waited=None; exited_at=None; buffers={"stdout":bytearray(),"stderr":bytearray(),"status":bytearray()}
    try:
        os.close(status_write_fd); pidfd=os.pidfd_open(process.pid,0); status_stream=os.fdopen(status_fd,"rb",buffering=0); streams={process.stdout:"stdout",process.stderr:"stderr",status_stream:"status"}; selector=selectors.DefaultSelector()
        for stream,name in streams.items(): os.set_blocking(stream.fileno(),False); selector.register(stream,selectors.EVENT_READ,name)
        parent_ns=namespaces(os.getpid())
        while selector.get_map() or waited is None:
            for key,_ in selector.select(0.25):
                block=os.read(key.fileobj.fileno(),65536)
                if not block: selector.unregister(key.fileobj); key.fileobj.close(); continue
                buffers[key.data].extend(block); limit=MAX_OUTPUT if key.data=="stdout" else MAX_ERROR; refuse(len(buffers[key.data])<=limit,40)
                if key.data=="status" and child_ns is None and b"\n" in buffers["status"]:
                    for line in bytes(buffers["status"]).splitlines():
                        row=json.loads(line)
                        if type(row) is dict and type(row.get("child-pid")) is int and row["child-pid"]>0:
                            child_pid=row["child-pid"]; refuse(ppid(child_pid)==process.pid,41); child_ns=namespaces(child_pid); refuse(all(child_ns[name]!=parent_ns[name] for name in parent_ns),42); break
            if waited is None:
                candidate=os.wait4(process.pid,os.WNOHANG)
                if candidate[0]!=0: waited=candidate; process.returncode=os.waitstatus_to_exitcode(candidate[1]); exited_at=time.monotonic()
            if waited is not None and selector.get_map() and time.monotonic()-exited_at>2.0: raise SystemExit(43)
            if waited is not None and not selector.get_map(): break
    except BaseException:
        terminate(process,child_pid,pidfd); raise
    finally:
        if selector is not None:
            for key in list(selector.get_map().values()):
                try: key.fileobj.close()
                except OSError: pass
            selector.close()
        for stream in (process.stdout,process.stderr,status_stream):
            if stream is not None:
                try: stream.close()
                except OSError: pass
        if status_stream is None:
            try: os.close(status_fd)
            except OSError: pass
        if pidfd is not None:
            try: os.close(pidfd)
            except OSError: pass
    refuse(waited is not None and process.returncode==0,44)
    statuses=[json.loads(line) for line in buffers["status"].splitlines() if line.strip()]
    refuse(statuses and all(type(row) is dict for row in statuses),45)
    refuse(all("child-pid" not in row or (type(row["child-pid"]) is int and row["child-pid"]>0) for row in statuses),46)
    child_pids=[row["child-pid"] for row in statuses if type(row) is dict and type(row.get("child-pid")) is int and row["child-pid"]>0]
    refuse(len(child_pids)==1 and child_pids[0]==child_pid and child_ns is not None,47)
    return {name:bytes(value) for name,value in buffers.items()}
refuse(sys.flags.isolated==1 and sys.flags.dont_write_bytecode==1 and sys.flags.no_site==1 and sys.flags.safe_path,9)
refuse(dict(os.environ)==ENV,10)
refuse(os.getcwd()=="/",11)
live=[]
for raw in os.listdir("/proc/self/fd"):
    try: os.fstat(int(raw)); live.append(int(raw))
    except OSError: pass
refuse(sorted(live)==[0,1,2],12)
mounts={}
for line in open("/proc/self/mountinfo","rb"):
    left,right=line.rstrip(b"\n").split(b" - ",1); fields=left.split(); tail=right.split(); mounts[fields[4]]=(set(fields[5].split(b",")),tail[0])
for mountpoint in mounts:
    refuse(not (mountpoint.startswith(b"/home/luke") or mountpoint.startswith(b"/run") or mountpoint.startswith(b"/.local")),13)
for required in (b"/host-repo",b"/host-registry",b"/host-toolchain",b"/usr/bin/bwrap",b"/bootstrap/outer.py",b"/bootstrap/local.json",b"/bootstrap/vendor.json",b"/bootstrap/toolchain.json",b"/bootstrap/seccomp.bpf"):
    refuse(required in mounts and b"ro" in mounts[required][0],14)
for required,digest in RUNTIME.items():
    encoded=required.encode(); refuse(encoded in mounts and b"ro" in mounts[encoded][0],48); _,observed=stable(required); refuse(observed==digest,49)
for mountpoint in mounts:
    refuse(allowed_system_mount(mountpoint),50)
for candidate,row in ROUTES.items():
    value=os.lstat(candidate); target=os.readlink(candidate) if stat.S_ISLNK(value.st_mode) else None; refuse((value.st_dev,value.st_ino,format(stat.S_IMODE(value.st_mode),"04o"),target)==(row["device"],row["inode"],row["mode_octal"],row["symlink_target"]),53); refuse(os.path.realpath(candidate)==row["resolved"] and followed_digest(candidate)==row["sha256"],54)
for required in (b"/stage",b"/tmp"):
    refuse(required in mounts and b"rw" in mounts[required][0] and mounts[required][1]==b"tmpfs",15)
raw_bwrap,bwrap_digest=stable("/usr/bin/bwrap"); refuse(bwrap_digest==os.environ["KPB_BWRAP_SHA256"] and raw_bwrap.startswith(b"\x7fELF"),16)
try:
    probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM); outcome=probe.connect_ex(("1.1.1.1",53)); probe.close(); refuse(outcome in (errno.ENETUNREACH,errno.EPERM),17)
except OSError as error: refuse(error.errno in (errno.ENETUNREACH,errno.EPERM),18)
ipv6_routes=[line.split() for line in open("/proc/net/ipv6_route","rb") if line.strip()]
refuse(open("/proc/net/route","rb").read().count(b"\n")<=1 and all(row[-1]==b"lo" for row in ipv6_routes),19)
local=load_manifest("/bootstrap/local.json",os.environ["KPB_LOCAL_SHA256"]); vendor=load_manifest("/bootstrap/vendor.json",os.environ["KPB_VENDOR_SHA256"]); toolchain=load_manifest("/bootstrap/toolchain.json",os.environ["KPB_TOOLCHAIN_SHA256"])
copy_manifest(local,"local"); copy_manifest(vendor,"vendor"); copy_manifest(toolchain,"toolchain")
os.makedirs("/stage/cargo-home",mode=0o700); config=b'[source.crates-io]\nreplace-with="vendored-sources"\n[source.vendored-sources]\ndirectory="/vendor"\n[net]\noffline=true\n'; open("/stage/cargo-home/config.toml","wb").write(config)
os.makedirs("/stage/bootstrap",mode=0o700); open("/stage/bootstrap/inner.py","wb").write(INNER); os.chmod("/stage/bootstrap/inner.py",0o400)
seccomp_fd=os.open("/bootstrap/seccomp.bpf",os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); status_read,status_write=os.pipe2(os.O_CLOEXEC)
command=[BWRAP,*FLAGS,"--ro-bind","/usr","/usr","--tmpfs","/usr/local","--ro-bind","/lib","/lib","--ro-bind","/lib64","/lib64","--ro-bind","/dev/null","/usr/bin/bwrap","--proc","/proc","--dev","/dev","--tmpfs","/tmp","--tmpfs","/target","--dir","/home","--dir","/home/build","--ro-bind","/stage/src","/src","--ro-bind","/stage/vendor","/vendor","--ro-bind","/stage/toolchain","/toolchain","--ro-bind","/stage/cargo-home","/cargo-home","--ro-bind","/stage/bootstrap/inner.py","/bootstrap/inner.py","--seccomp",str(seccomp_fd),"--json-status-fd",str(status_write),"--chdir","/"]
for key,value in INNER_ENV.items(): command.extend(("--setenv",key,value))
command.extend(("--","/usr/bin/python3.14","-I","-B","-S","/bootstrap/inner.py"))
process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=(seccomp_fd,status_write),env={},start_new_session=True); result=bounded(process,status_read,status_write); os.close(seccomp_fd)
refuse(result["stdout"].startswith(b"KPB-W1-BWRAP-BUILD\x00\x01") and not result["stderr"],45)
offset=0
while offset<len(result["stdout"]): offset+=os.write(1,result["stdout"][offset:])
'''


def rendered_outer_source(
    local_sha: str,
    vendor_sha: str,
    toolchain_sha: str,
    bwrap_sha: str,
    runtime_sha256: dict[str, str],
    cache_routes: dict[str, dict[str, object]],
) -> str:
    need(
        type(runtime_sha256) is dict
        and set(runtime_sha256) == set(BWRAP_RUNTIME_MOUNT_DESTINATIONS)
        and all(is_sha256(value) for value in runtime_sha256.values()),
        "outer-runtime-hashes",
    )
    need(
        type(cache_routes) is dict
        and bool(cache_routes)
        and all(
            type(candidate) is str
            and candidate.startswith("/")
            and ".." not in PurePosixPath(candidate).parts
            and type(row) is dict
            and set(row)
            == {
                "device", "inode", "mode_octal", "symlink_target",
                "resolved", "sha256",
            }
            and type(row["device"]) is int
            and type(row["inode"]) is int
            and re.fullmatch(r"0[0-7]{3}", row["mode_octal"]) is not None
            and (row["symlink_target"] is None or type(row["symlink_target"]) is str)
            and type(row["resolved"]) is str
            and row["resolved"] in runtime_sha256
            and row["sha256"] == runtime_sha256[row["resolved"]]
            for candidate, row in cache_routes.items()
        ),
        "outer-cache-routes",
    )
    outer_environment = {
        "HOME": "/nonexistent",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "KPB_LOCAL_SHA256": local_sha,
        "KPB_VENDOR_SHA256": vendor_sha,
        "KPB_TOOLCHAIN_SHA256": toolchain_sha,
        "KPB_BWRAP_SHA256": bwrap_sha,
    }
    source = OUTER_COPY_SOURCE.replace("__KPB_OUTER_ENV__", repr(outer_environment))
    source = source.replace(
        "__KPB_INNER_B64__",
        base64.b64encode(rendered_inner_source().encode("utf-8")).decode("ascii"),
    )
    source = source.replace("__KPB_FINAL_FLAGS__", repr(MANDATORY_NAMESPACE_FLAGS))
    source = source.replace("__KPB_INNER_ENV__", repr(SANDBOX_ENVIRONMENT))
    source = source.replace("__KPB_BWRAP_RUNTIME__", repr(dict(sorted(runtime_sha256.items()))))
    source = source.replace("__KPB_BWRAP_ROUTES__", repr(dict(sorted(cache_routes.items()))))
    source = source.replace("__KPB_MAX_OUTPUT__", str(MAX_TOTAL_EXPORT_BYTES + 128 * 1024))
    source = source.replace("__KPB_MAX_ERROR__", str(MAX_STDERR_BYTES))
    return source


def open_directory_fd(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    value = os.fstat(descriptor)
    need(stat.S_ISDIR(value.st_mode), "directory-fd")
    return descriptor


def bwrap_symlink_rehearsal_command(
    bwrap_fd: int, payload_fd: int, status_fd: int
) -> list[str]:
    """A reviewed bwrap must refuse this hostile destination traversal."""
    return [
        str(BWRAP),
        *MANDATORY_NAMESPACE_FLAGS,
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--ro-bind-fd",
        str(bwrap_fd),
        "/usr/bin/bwrap",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/safe",
        "--symlink",
        "/tmp",
        "/safe/trap",
        "--ro-bind-data",
        str(payload_fd),
        "/safe/trap/kpb-rehearsal",
        "--json-status-fd",
        str(status_fd),
        "--chdir",
        "/",
        "--",
        "/usr/bin/true",
    ]


def valid_nested_runtime_bindings(value: object) -> bool:
    return (
        type(value) is tuple
        and bool(value)
        and all(
            type(row) is tuple
            and len(row) == 2
            and all(
                type(path) is str
                and path.startswith("/")
                and ".." not in PurePosixPath(path).parts
                for path in row
            )
            and (
                row[0] == row[1]
                or row
                == (BWRAP_INTERPRETER_RESOLVED, BWRAP_INTERPRETER_LITERAL)
            )
            for row in value
        )
        and tuple(sorted(value, key=lambda row: row[1])) == value
        and len({row[1] for row in value}) == len(value)
        and {row[1] for row in value} == set(BWRAP_RUNTIME_MOUNT_DESTINATIONS)
        and all("glibc-hwcaps" not in PurePosixPath(row[1]).parts for row in value)
    )


def outer_bwrap_command(
    *,
    bwrap_fd: int,
    repo_fd: int,
    registry_fd: int,
    toolchain_fd: int,
    outer_source_fd: int,
    local_manifest_fd: int,
    vendor_manifest_fd: int,
    toolchain_manifest_fd: int,
    seccomp_fd: int,
    status_fd: int,
    launch_block_fd: int,
    local_sha: str,
    vendor_sha: str,
    toolchain_sha: str,
    bwrap_sha: str,
    runtime_bindings: tuple[tuple[str, str], ...],
) -> list[str]:
    need(valid_nested_runtime_bindings(runtime_bindings), "nested-runtime-bindings")
    environment = {
        "HOME": "/nonexistent",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "KPB_LOCAL_SHA256": local_sha,
        "KPB_VENDOR_SHA256": vendor_sha,
        "KPB_TOOLCHAIN_SHA256": toolchain_sha,
        "KPB_BWRAP_SHA256": bwrap_sha,
    }
    command = [
        str(BWRAP),
        *OUTER_NAMESPACE_FLAGS,
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--dir",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/stage",
        "--dir",
        "/home",
        "--dir",
        "/bootstrap",
        "--dir",
        "/etc",
    ]
    for source, destination in runtime_bindings:
        command.extend(("--ro-bind", source, destination))
    command.extend([
        "--ro-bind-fd",
        str(repo_fd),
        "/host-repo",
        "--ro-bind-fd",
        str(registry_fd),
        "/host-registry",
        "--ro-bind-fd",
        str(toolchain_fd),
        "/host-toolchain",
        "--ro-bind-fd",
        str(bwrap_fd),
        "/usr/bin/bwrap",
        "--ro-bind-data",
        str(outer_source_fd),
        "/bootstrap/outer.py",
        "--ro-bind-data",
        str(local_manifest_fd),
        "/bootstrap/local.json",
        "--ro-bind-data",
        str(vendor_manifest_fd),
        "/bootstrap/vendor.json",
        "--ro-bind-data",
        str(toolchain_manifest_fd),
        "/bootstrap/toolchain.json",
        "--ro-bind-data",
        str(seccomp_fd),
        "/bootstrap/seccomp.bpf",
        "--block-fd",
        str(launch_block_fd),
        "--json-status-fd",
        str(status_fd),
        "--chdir",
        "/",
    ])
    for key, value in environment.items():
        command.extend(("--setenv", key, value))
    command.extend(("--", "/usr/bin/python3.14", "-I", "-B", "-S", "/bootstrap/outer.py"))
    return command


def outer_launch_contract(
    *,
    bwrap_identity: dict,
    local_sha: str,
    vendor_sha: str,
    toolchain_sha: str,
    bwrap_sha: str,
    outer_source_sha: str,
    local_manifest_sha: str,
    vendor_manifest_sha: str,
    toolchain_manifest_sha: str,
    seccomp_sha: str,
    runtime_bindings: tuple[tuple[str, str], ...],
    apparmor_profile_name: str,
) -> dict:
    need(valid_nested_runtime_bindings(runtime_bindings), "nested-runtime-bindings")
    need(
        type(apparmor_profile_name) is str
        and bool(apparmor_profile_name)
        and not any(character in apparmor_profile_name for character in "\x00\r\n"),
        "outer-apparmor-profile-name",
    )
    return {
        "schema": "kpb-w1-outer-launch-contract/v1",
        "bwrap_identity": bwrap_identity,
        "command_hashes": {
            "local": local_sha,
            "vendor": vendor_sha,
            "toolchain": toolchain_sha,
            "bwrap": bwrap_sha,
        },
        "sealed_sha256": {
            "outer_source": outer_source_sha,
            "local_manifest": local_manifest_sha,
            "vendor_manifest": vendor_manifest_sha,
            "toolchain_manifest": toolchain_manifest_sha,
            "seccomp": seccomp_sha,
        },
        "nested_runtime_bindings": [list(row) for row in runtime_bindings],
        "apparmor_exec_label": {
            "profile_name": apparmor_profile_name,
            "mode": "enforce",
        },
    }


def validate_outer_fd_contract(
    passed_fds: tuple[int, ...], launch_contract: dict, *, status_read_fd: int,
    launch_block_write_fd: int,
) -> None:
    need(
        type(passed_fds) is tuple
        and len(passed_fds) == len(OUTER_FD_ROLES)
        and all(type(descriptor) is int and descriptor >= 3 for descriptor in passed_fds)
        and len(passed_fds) == len(set(passed_fds)),
        "bwrap-passed-fd-roles",
    )
    need(
        type(launch_contract) is dict
        and set(launch_contract) == {
            "schema", "bwrap_identity", "command_hashes", "sealed_sha256",
            "nested_runtime_bindings", "apparmor_exec_label",
        }
        and launch_contract["schema"] == "kpb-w1-outer-launch-contract/v1"
        and type(launch_contract["bwrap_identity"]) is dict
        and type(launch_contract["command_hashes"]) is dict
        and set(launch_contract["command_hashes"])
        == {"local", "vendor", "toolchain", "bwrap"}
        and all(is_sha256(value) for value in launch_contract["command_hashes"].values())
        and type(launch_contract["sealed_sha256"]) is dict
        and set(launch_contract["sealed_sha256"])
        == {"outer_source", "local_manifest", "vendor_manifest", "toolchain_manifest", "seccomp"}
        and all(is_sha256(value) for value in launch_contract["sealed_sha256"].values()),
        "outer-launch-contract",
    )
    apparmor = launch_contract["apparmor_exec_label"]
    need(
        type(apparmor) is dict
        and set(apparmor) == {"profile_name", "mode"}
        and type(apparmor["profile_name"]) is str
        and bool(apparmor["profile_name"])
        and not any(
            character in apparmor["profile_name"] for character in "\x00\r\n"
        )
        and apparmor["mode"] == "enforce",
        "outer-apparmor-contract",
    )
    need(
        type(launch_contract["nested_runtime_bindings"]) is list
        and all(type(row) is list for row in launch_contract["nested_runtime_bindings"])
        and valid_nested_runtime_bindings(
            tuple(tuple(row) for row in launch_contract["nested_runtime_bindings"])
        ),
        "outer-runtime-binding-contract",
    )
    roles = dict(zip(OUTER_FD_ROLES, passed_fds, strict=True))

    def cloexec(descriptor: int) -> bool:
        return bool(fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)

    bwrap_identity = launch_contract["bwrap_identity"]
    bwrap_value = os.fstat(roles["bwrap"])
    need(
        stat.S_ISREG(bwrap_value.st_mode)
        and cloexec(roles["bwrap"])
        and fcntl.fcntl(roles["bwrap"], fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        and all(
            key in bwrap_identity
            for key in ("bytes", "sha256", "device", "inode", "mtime_ns", "ctime_ns")
        )
        and bwrap_value.st_size == bwrap_identity["bytes"]
        and bwrap_value.st_dev == bwrap_identity["device"]
        and bwrap_value.st_ino == bwrap_identity["inode"]
        and bwrap_value.st_mtime_ns == bwrap_identity["mtime_ns"]
        and bwrap_value.st_ctime_ns == bwrap_identity["ctime_ns"],
        "outer-bwrap-fd-identity",
    )
    bwrap_raw = os.pread(roles["bwrap"], bwrap_value.st_size, 0)
    need(
        len(bwrap_raw) == bwrap_value.st_size
        and sha256_bytes(bwrap_raw) == bwrap_identity["sha256"]
        == launch_contract["command_hashes"]["bwrap"],
        "outer-bwrap-fd-hash",
    )

    for role, path in (
        ("repo", REPO_ROOT),
        ("registry", REGISTRY_ROOT),
        ("toolchain", TOOLCHAIN_ROOT),
    ):
        descriptor = roles[role]
        value = os.fstat(descriptor)
        expected = os.stat(path, follow_symlinks=True)
        need(
            stat.S_ISDIR(value.st_mode)
            and cloexec(descriptor)
            and fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            and (value.st_dev, value.st_ino) == (expected.st_dev, expected.st_ino),
            f"outer-{role}-fd-identity",
        )

    for role, expected_hash in launch_contract["sealed_sha256"].items():
        descriptor = roles[role]
        need(cloexec(descriptor), f"outer-{role}-fd-cloexec")
        read_sealed_fd(descriptor, expected_hash)

    status_write = roles["status_write"]
    write_value = os.fstat(status_write)
    read_value = os.fstat(status_read_fd)
    need(
        type(status_read_fd) is int
        and status_read_fd >= 3
        and status_read_fd not in passed_fds
        and stat.S_ISFIFO(write_value.st_mode)
        and stat.S_ISFIFO(read_value.st_mode)
        and (write_value.st_dev, write_value.st_ino) == (read_value.st_dev, read_value.st_ino)
        and cloexec(status_write)
        and cloexec(status_read_fd)
        and fcntl.fcntl(status_write, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY
        and fcntl.fcntl(status_read_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
        "outer-status-pipe-identity",
    )
    launch_block_read = roles["launch_block_read"]
    block_read_value = os.fstat(launch_block_read)
    block_write_value = os.fstat(launch_block_write_fd)
    need(
        type(launch_block_write_fd) is int
        and launch_block_write_fd >= 3
        and launch_block_write_fd not in passed_fds
        and stat.S_ISFIFO(block_read_value.st_mode)
        and stat.S_ISFIFO(block_write_value.st_mode)
        and (block_read_value.st_dev, block_read_value.st_ino)
        == (block_write_value.st_dev, block_write_value.st_ino)
        and cloexec(launch_block_read)
        and cloexec(launch_block_write_fd)
        and fcntl.fcntl(launch_block_read, fcntl.F_GETFL) & os.O_ACCMODE
        == os.O_RDONLY
        and fcntl.fcntl(launch_block_write_fd, fcntl.F_GETFL) & os.O_ACCMODE
        == os.O_WRONLY,
        "outer-launch-block-pipe-identity",
    )


def validate_bwrap_command(
    command: list[str],
    passed_fds: tuple[int, ...],
    launch_contract: dict,
    *,
    status_read_fd: int,
    launch_block_write_fd: int,
) -> None:
    need(type(command) is list and all(type(item) is str for item in command), "bwrap-command")
    validate_outer_fd_contract(
        passed_fds,
        launch_contract,
        status_read_fd=status_read_fd,
        launch_block_write_fd=launch_block_write_fd,
    )
    roles = dict(zip(OUTER_FD_ROLES, passed_fds, strict=True))
    hashes = launch_contract["command_hashes"]
    expected = outer_bwrap_command(
        bwrap_fd=roles["bwrap"],
        repo_fd=roles["repo"],
        registry_fd=roles["registry"],
        toolchain_fd=roles["toolchain"],
        outer_source_fd=roles["outer_source"],
        local_manifest_fd=roles["local_manifest"],
        vendor_manifest_fd=roles["vendor_manifest"],
        toolchain_manifest_fd=roles["toolchain_manifest"],
        seccomp_fd=roles["seccomp"],
        status_fd=roles["status_write"],
        launch_block_fd=roles["launch_block_read"],
        local_sha=hashes["local"],
        vendor_sha=hashes["vendor"],
        toolchain_sha=hashes["toolchain"],
        bwrap_sha=hashes["bwrap"],
        runtime_bindings=tuple(
            tuple(row) for row in launch_contract["nested_runtime_bindings"]
        ),
    )
    need(
        command == expected,
        "outer-command-not-canonical",
    )


def parse_status_lines(raw: bytes) -> list[dict]:
    rows: list[dict] = []
    for line in raw.splitlines():
        if not line:
            continue
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError) as error:
            raise Refused("bwrap-status-json") from error
        need(type(value) is dict, "bwrap-status-row")
        rows.append(value)
    for row in rows:
        if "child-pid" in row:
            need(
                type(row["child-pid"]) is int and row["child-pid"] > 0,
                "bwrap-status-pid",
            )
    child_pids = [
        row["child-pid"]
        for row in rows
        if type(row.get("child-pid")) is int and row["child-pid"] > 0
    ]
    need(rows and len(child_pids) == 1, "bwrap-status-pid")
    return rows


def completed_status_child_pid(raw: bytes) -> int | None:
    complete_lines = raw.split(b"\n")[:-1]
    child_pids: list[int] = []
    for line in complete_lines:
        if not line:
            continue
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError) as error:
            raise Refused("bwrap-status-json") from error
        need(type(row) is dict, "bwrap-status-row")
        if "child-pid" in row:
            need(
                type(row["child-pid"]) is int and row["child-pid"] > 0,
                "bwrap-status-pid",
            )
            child_pids.append(row["child-pid"])
    need(len(child_pids) <= 1, "bwrap-status-pid")
    return child_pids[0] if child_pids else None


def process_parent_pid(pid: int) -> int:
    descriptor = os.open(
        f"/proc/{pid}/status", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        value = os.fstat(descriptor)
        need(stat.S_ISREG(value.st_mode), "bwrap-child-status-type")
        raw = os.read(descriptor, 64 * 1024)
        need(len(raw) < 64 * 1024, "bwrap-child-status-bounds")
    finally:
        os.close(descriptor)
    for line in raw.splitlines():
        if line.startswith(b"PPid:"):
            value = line.split(b":", 1)[1].strip()
            need(value.isdigit(), "bwrap-child-ppid-format")
            return int(value)
    raise Refused("bwrap-child-ppid-missing")


def live_apparmor_exec_label(pid: int, profile_name: str) -> dict[str, object]:
    """Read the kernel's exact label for the still-blocked bwrap process."""
    need(
        type(pid) is int
        and pid > 0
        and type(profile_name) is str
        and 0 < len(profile_name.encode("utf-8")) <= 2048
        and not any(character in profile_name for character in "\x00\r\n"),
        "apparmor-current-contract",
    )
    path = f"/proc/{pid}/attr/current"
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError as error:
        raise Refused("apparmor-current-unreadable") from error
    try:
        value = os.fstat(descriptor)
        need(stat.S_ISREG(value.st_mode), "apparmor-current-type")
        raw = bytearray()
        while True:
            try:
                block = os.read(descriptor, 4096)
            except OSError as error:
                raise Refused("apparmor-current-unreadable") from error
            if not block:
                break
            raw.extend(block)
            need(len(raw) <= 4096, "apparmor-current-bounds")
    finally:
        os.close(descriptor)
    expected = f"{profile_name} (enforce)\n".encode("utf-8")
    need(bytes(raw) == expected, "apparmor-current-label")
    return {
        "pid": pid,
        "profile_name": profile_name,
        "mode": "enforce",
        "raw_sha256": sha256_bytes(expected),
        "source": "/proc/<bwrap-pid>/attr/current",
        "observed_before_launch_barrier_release": True,
    }


def namespace_identity(pid: int) -> dict[str, tuple[int, int]]:
    need(type(pid) is int and pid > 0, "namespace-pid")
    result: dict[str, tuple[int, int]] = {}
    for name in ("mnt", "user", "ipc", "pid", "net", "uts", "cgroup"):
        value = os.stat(f"/proc/{pid}/ns/{name}", follow_symlinks=True)
        result[name] = (value.st_dev, value.st_ino)
    return result


def append_bounded(
    buffer: bytearray, block: bytes, limit: int, category: str
) -> None:
    need(type(limit) is int and limit >= 0, "invalid-output-limit")
    buffer.extend(block)
    need(len(buffer) <= limit, category)


def descendant_pipe_grace_expired(
    *, leader_reaped: bool, streams_open: bool, exited_at: float | None, now: float
) -> bool:
    return (
        leader_reaped
        and streams_open
        and exited_at is not None
        and now - exited_at > 2.0
    )


def successful_wait4_returncode(returncode: int | None) -> dict[str, int]:
    need(type(returncode) is int, "bwrap-wait4-missing")
    term_signal = -returncode if returncode < 0 else 0
    exit_code = returncode if returncode >= 0 else 0
    need(returncode == 0, "bwrap-exit")
    return {"exit_code": exit_code, "term_signal": term_signal}


def terminate_and_reap_bwrap(
    process: subprocess.Popen,
    *,
    pidfd: int | None,
    child_pid: int | None,
    waited: tuple[int, int, resource.struct_rusage] | None,
) -> tuple[int, int, resource.struct_rusage] | None:
    if pidfd is not None:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except (AttributeError, ProcessLookupError, OSError):
            pass
    if child_pid is not None:
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if waited is None:
        try:
            waited = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(waited[1])
        except ChildProcessError:
            pass
    return waited


def run_bounded_process(
    command: list[str],
    *,
    passed_fds: tuple[int, ...],
    launch_contract: dict,
    status_read_fd: int,
    status_write_fd: int,
    launch_block_write_fd: int,
) -> dict:
    """Run only a reviewed bwrap command with bounded pipes and wait4 evidence."""
    need(
        type(passed_fds) is tuple
        and bool(passed_fds),
        "outer-passed-fds",
    )
    validate_bwrap_command(
        command,
        passed_fds,
        launch_contract,
        status_read_fd=status_read_fd,
        launch_block_write_fd=launch_block_write_fd,
    )
    fd_roles = dict(zip(OUTER_FD_ROLES, passed_fds, strict=True))
    need(fd_roles["status_write"] == status_write_fd, "outer-status-write-role")
    process = subprocess.Popen(
        command,
        executable=command[0],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=passed_fds,
        env={},
        start_new_session=True,
    )
    waited: tuple[int, int, resource.struct_rusage] | None = None
    child_pid: int | None = None
    child_namespaces: dict[str, tuple[int, int]] | None = None
    parent_namespaces: dict[str, tuple[int, int]] | None = None
    leader_exited_at: float | None = None
    pidfd: int | None = None
    status_stream = None
    selector: selectors.BaseSelector | None = None
    apparmor_exec_label: dict[str, object] | None = None
    block_write_open = True
    buffers = {
        "stdout": bytearray(),
        "stderr": bytearray(),
        "status": bytearray(),
    }
    try:
        os.close(status_write_fd)
        os.close(fd_roles["launch_block_read"])
        need(process.stdout is not None and process.stderr is not None, "bwrap-pipes")
        pidfd = os.pidfd_open(process.pid, 0)
        apparmor_exec_label = live_apparmor_exec_label(
            process.pid,
            launch_contract["apparmor_exec_label"]["profile_name"],
        )
        need(
            os.write(launch_block_write_fd, b"\x01") == 1,
            "bwrap-launch-barrier-release",
        )
        os.close(launch_block_write_fd)
        block_write_open = False
        status_stream = os.fdopen(status_read_fd, "rb", buffering=0)
        streams = {
            process.stdout: (
                "stdout",
                MAX_TOTAL_EXPORT_BYTES + MAX_FRAME_HEADER_BYTES,
            ),
            process.stderr: ("stderr", MAX_STDERR_BYTES),
            status_stream: ("status", MAX_FRAME_HEADER_BYTES),
        }
        selector = selectors.DefaultSelector()
        for stream, (name, limit) in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, limit))
        parent_namespaces = namespace_identity(os.getpid())
        while selector.get_map() or waited is None:
            for key, _ in selector.select(0.25):
                name, limit = key.data
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                append_bounded(
                    buffers[name], block, limit, f"bwrap-{name}-overflow"
                )
                if name == "status" and child_namespaces is None and b"\n" in buffers[name]:
                    try:
                        child_pid = completed_status_child_pid(bytes(buffers[name]))
                        if child_pid is not None:
                            need(
                                process_parent_pid(child_pid) == process.pid,
                                "bwrap-status-parent-binding",
                            )
                            child_namespaces = namespace_identity(child_pid)
                            need(
                                all(
                                    child_namespaces[item] != parent_namespaces[item]
                                    for item in parent_namespaces
                                ),
                                "bwrap-namespace-not-separated",
                            )
                    except FileNotFoundError:
                        child_namespaces = None
            if waited is None:
                candidate = os.wait4(process.pid, os.WNOHANG)
                if candidate[0] != 0:
                    waited = candidate
                    process.returncode = os.waitstatus_to_exitcode(candidate[1])
                    leader_exited_at = time.monotonic()
            if descendant_pipe_grace_expired(
                leader_reaped=waited is not None,
                streams_open=bool(selector.get_map()),
                exited_at=leader_exited_at,
                now=time.monotonic(),
            ):
                raise Refused("bwrap-descendant-held-pipe")
            if waited is not None and not selector.get_map():
                break
    except BaseException:
        waited = terminate_and_reap_bwrap(
            process,
            pidfd=pidfd,
            child_pid=child_pid,
            waited=waited,
        )
        raise
    finally:
        if block_write_open:
            try:
                os.close(launch_block_write_fd)
            except OSError:
                pass
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError:
                pass
        if selector is not None:
            for key in list(selector.get_map().values()):
                try:
                    key.fileobj.close()
                except OSError:
                    pass
            selector.close()
        for stream in (process.stdout, process.stderr, status_stream):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if status_stream is None:
            try:
                os.close(status_read_fd)
            except OSError:
                pass
    need(waited is not None, "bwrap-wait4-missing")
    need(apparmor_exec_label is not None, "apparmor-current-missing")
    wait_evidence = successful_wait4_returncode(process.returncode)
    rows = parse_status_lines(bytes(buffers["status"]))
    need(child_namespaces is not None, "bwrap-live-namespace-binding")
    rusage = waited[2]
    return {
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
        "status": rows,
        "pid": process.pid,
        "status_child_pid": child_pid,
        "status_parent_pid_bound": True,
        "pidfd_opened": True,
        "apparmor_exec_label": apparmor_exec_label,
        "launch_barrier_released_after_apparmor_observation": True,
        "wait4_exit_code": wait_evidence["exit_code"],
        "wait4_term_signal": wait_evidence["term_signal"],
        "max_rss_kib": rusage.ru_maxrss,
        "child_namespaces": {name: list(value) for name, value in child_namespaces.items()},
        "parent_namespaces": {name: list(value) for name, value in parent_namespaces.items()},
    }


def parse_build_frame(raw: bytes) -> tuple[dict, dict[str, int]]:
    need(raw.startswith(FRAME_MAGIC), "frame-magic")
    offset = len(FRAME_MAGIC)
    need(len(raw) >= offset + 8, "frame-header-length")
    header_length = struct.unpack(">Q", raw[offset : offset + 8])[0]
    offset += 8
    need(0 < header_length <= MAX_FRAME_HEADER_BYTES, "frame-header-bounds")
    need(len(raw) >= offset + header_length, "frame-header-truncated")
    header_raw = raw[offset : offset + header_length]
    offset += header_length
    try:
        header = json.loads(header_raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise Refused("frame-header-json") from error
    need(canonical(header) == header_raw, "frame-header-canonical")
    entries = header.get("entries")
    expected_names = ["prover", "verifier", "prover_dep_info", "verifier_dep_info"]
    need(
        type(entries) is list
        and [row.get("name") for row in entries if type(row) is dict] == expected_names
        and header.get("schema") == FRAME_SCHEMA
        and header.get("proof_executed") is False
        and header.get("verifier_executed") is False
        and header.get("setup_or_pk_read") is False
        and header.get("network_communication") is False
        and header.get("authorization") is False,
        "frame-header-contract",
    )
    lengths: list[int] = []
    for entry in entries:
        need(
            set(entry) == {"name", "bytes", "sha256", "mode_octal"}
            and type(entry["bytes"]) is int
            and 0 < entry["bytes"] <= MAX_EXPORTED_FILE_BYTES
            and is_sha256(entry["sha256"])
            and re.fullmatch(r"0[0-7]{3}", entry["mode_octal"]) is not None,
            "frame-entry",
        )
        need(len(raw) >= offset + 8, "frame-entry-length-truncated")
        length = struct.unpack(">Q", raw[offset : offset + 8])[0]
        offset += 8
        need(length == entry["bytes"], "frame-entry-length")
        lengths.append(length)
    need(sum(lengths) <= MAX_TOTAL_EXPORT_BYTES, "frame-total-bounds")
    sealed: dict[str, int] = {}
    try:
        for entry, length in zip(entries, lengths, strict=True):
            need(len(raw) >= offset + length, "frame-payload-truncated")
            payload = raw[offset : offset + length]
            offset += length
            need(sha256_bytes(payload) == entry["sha256"], "frame-payload-hash")
            if entry["name"] in {"prover", "verifier"}:
                need(payload.startswith(b"\x7fELF"), "frame-binary-elf")
            else:
                try:
                    payload.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise Refused("frame-dep-info-utf8") from error
            sealed[entry["name"]] = sealed_memfd(f"kpb-{entry['name']}", payload)
        need(offset == len(raw), "frame-trailing-bytes")
    except BaseException:
        for descriptor in sealed.values():
            os.close(descriptor)
        raise
    return header, sealed


def expected_cargo_command() -> list[str]:
    return [
        "/toolchain/bin/cargo",
        "build",
        "--manifest-path",
        f"/src/{MANIFEST_RELATIVE}",
        "--target-dir",
        "/target",
        "--release",
        "--frozen",
        "--offline",
        "--no-default-features",
        "--features",
        FEATURE_NAME,
        "--example",
        PROVER_NAME,
        "--example",
        VERIFIER_NAME,
    ]


def require_gate_shapes() -> None:
    need(is_sha256(REVIEWED_LOCAL_SOURCE_TREE_SHA256), "local-source-review-not-bound")
    need(
        valid_local_source_allowlist(REVIEWED_LOCAL_SOURCE_FILES_SHA256),
        "local-source-file-review-not-bound",
    )
    need(is_sha256(REVIEWED_VENDOR_TREE_SHA256), "vendor-review-not-bound")
    need(is_sha256(REVIEWED_TOOLCHAIN_TREE_SHA256), "toolchain-review-not-bound")
    need(
        type(REVIEWED_LEAF_TOOL_SHA256) is dict
        and set(REVIEWED_LEAF_TOOL_SHA256) == set(LEAF_TOOLS)
        and all(is_sha256(value) for value in REVIEWED_LEAF_TOOL_SHA256.values()),
        "leaf-tool-review-not-bound",
    )
    need(
        type(REVIEWED_ROOT_RUNTIME_SHA256) is dict
        and set(REVIEWED_ROOT_RUNTIME_SHA256) == set(BWRAP_RUNTIME_FILES)
        and all(is_sha256(value) for value in REVIEWED_ROOT_RUNTIME_SHA256.values()),
        "root-runtime-review-not-bound",
    )
    need(
        bwrap_version_tuple(REVIEWED_BWRAP_VERSION) is not None
        and bwrap_version_tuple(REVIEWED_BWRAP_VERSION) >= MINIMUM_BWRAP_VERSION,
        "bwrap-version-review-not-bound",
    )
    need(
        REVIEWED_BWRAP_APPARMOR_EXEC_PATH == str(BWRAP),
        "bwrap-apparmor-path-review-not-bound",
    )
    need(
        is_sha256(REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256),
        "bwrap-apparmor-profile-review-not-bound",
    )
    need(
        valid_apparmor_policy_shape(REVIEWED_BWRAP_APPARMOR_POLICY)
        and REVIEWED_BWRAP_APPARMOR_POLICY["source_sha256"].get(
            str(APPARMOR_PROFILE_SOURCE)
        )
        == REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256,
        "bwrap-apparmor-policy-review-not-bound",
    )
    need(
        valid_bwrap_provenance(
            REVIEWED_BWRAP_PROVENANCE, REVIEWED_LEAF_TOOL_SHA256["bwrap"]
        ),
        "bwrap-provenance-review-not-bound",
    )
    need(
        valid_elf_closure_shape(
            REVIEWED_BWRAP_ELF_CLOSURE, REVIEWED_LEAF_TOOL_SHA256["bwrap"]
        ),
        "bwrap-elf-closure-review-not-bound",
    )
    need(
        REVIEWED_BWRAP_ELF_CLOSURE["objects"][str(BWRAP)]["build_id"]
        == REVIEWED_BWRAP_PROVENANCE["elf_build_id"],
        "bwrap-provenance-elf-mismatch",
    )


def validate_fixed_boundaries() -> None:
    need(os.geteuid() != 0, "root-execution-refused")
    need(Path.cwd().resolve(strict=True) == REPO_ROOT, "cwd-must-be-repo-root")
    need(
        BWRAP == Path("/usr/bin/bwrap")
        and BWRAP.is_absolute(),
        "reviewed-fixed-bwrap-required",
    )
    for parent in (BWRAP.parent, BWRAP.parent.parent):
        value = os.lstat(parent)
        need(
            stat.S_ISDIR(value.st_mode)
            and value.st_uid == 0
            and stat.S_IMODE(value.st_mode) & 0o022 == 0,
            "bwrap-admin-path-not-immutable",
        )
    need(
        PRIVATE_OUTPUT_BASE == PRIVATE_OUTPUT_BASE.resolve(strict=True)
        and not PRIVATE_OUTPUT_BASE.is_relative_to(REPO_ROOT),
        "private-output-base",
    )
    base = os.lstat(PRIVATE_OUTPUT_BASE)
    need(stat.S_ISDIR(base.st_mode) and base.st_uid == os.getuid(), "private-output-base-owner")
    need(not os.path.lexists(OUTPUT_PARENT), "output-create-new")
    for path in (REPO_ROOT, REGISTRY_ROOT, TOOLCHAIN_ROOT):
        need(path == path.resolve(strict=True) and path.is_dir(), "input-root-canonical")


def run_symlink_destination_rehearsal(bwrap_fd: int) -> dict:
    payload_fd = sealed_memfd("kpb-bwrap-symlink-payload", b"refuse\n")
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    command = bwrap_symlink_rehearsal_command(bwrap_fd, payload_fd, status_write)
    try:
        result = subprocess.run(
            command,
            executable=command[0],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(bwrap_fd, payload_fd, status_write),
            env={},
            timeout=15,
            check=False,
        )
        os.close(status_write)
        status = b""
        while True:
            block = os.read(status_read, 4096)
            if not block:
                break
            status += block
            need(len(status) <= MAX_FRAME_HEADER_BYTES, "rehearsal-status-overflow")
        status_rows: list[dict] = []
        for line in status.splitlines():
            try:
                row = json.loads(line)
            except (ValueError, UnicodeDecodeError) as error:
                raise Refused("rehearsal-status-json") from error
            need(type(row) is dict, "rehearsal-status-row")
            status_rows.append(row)
        stderr_lower = result.stderr.lower()
        refusal_markers = (
            b"symbolic link",
            b"too many levels",
            b"safe_openat",
            b"symlink",
            b"not a directory",
        )
        need(
            result.returncode != 0
            and len(result.stdout) == 0
            and 0 < len(result.stderr) <= MAX_STDERR_BYTES
            and b"/safe/trap/kpb-rehearsal" in result.stderr
            and any(marker in stderr_lower for marker in refusal_markers)
            and not any(type(row.get("child-pid")) is int for row in status_rows),
            "bwrap-symlink-destination-not-refused",
        )
        return {
            "command_sha256": sha256_bytes(canonical(command)),
            "returncode_nonzero": True,
            "stderr_sha256": sha256_bytes(result.stderr),
            "status_sha256": sha256_bytes(status),
            "installed_regressed_bwrap_used": False,
        }
    finally:
        for descriptor in (payload_fd, status_read, status_write):
            try:
                os.close(descriptor)
            except OSError:
                pass


def stable_file_at(directory_fd: int, name: str) -> tuple[bytes, dict]:
    need(re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None, "output-name")
    before_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        blocks: list[bytes] = []
        offset = 0
        while True:
            block = os.pread(descriptor, 1024 * 1024, offset)
            if not block:
                break
            blocks.append(block)
            offset += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and identity(before_path)
        == identity(before)
        == identity(after)
        == identity(after_path),
        "published-file-mutated",
    )
    raw = b"".join(blocks)
    need(len(raw) == before.st_size, "published-file-short-read")
    return raw, {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode_octal": f"{stat.S_IMODE(before.st_mode):04o}",
    }


def rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    need(renameat2 is not None, "renameat2-unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def write_sealed_file(
    directory_fd: int,
    name: str,
    descriptor: int,
    mode: int,
) -> dict:
    need(re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None, "output-name")
    raw = read_sealed_fd(descriptor)
    output_fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
        dir_fd=directory_fd,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(output_fd, raw[offset:])
        os.fchmod(output_fd, mode)
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
    post_raw, post = stable_file_at(directory_fd, name)
    digest = sha256_bytes(raw)
    need(
        post_raw == raw
        and post["sha256"] == digest
        and post["mode_octal"] == f"{mode:04o}",
        "output-post-write-mismatch",
    )
    return {
        "name": name,
        "bytes": len(raw),
        "sha256": digest,
        "sealed_memfd_sha256": digest,
        "staging_post_write_sha256": post["sha256"],
        "mode_octal": f"{mode:04o}",
        "device": post["device"],
        "inode": post["inode"],
    }


def publish_bundle(
    header: dict,
    sealed: dict[str, int],
    receipt: dict,
    manifests: dict[str, dict],
) -> dict:
    staging = PRIVATE_OUTPUT_BASE / f".{OUTPUT_NAME}.staging-{uuid.uuid4()}"
    need(not os.path.lexists(staging) and not os.path.lexists(OUTPUT_PARENT), "publish-create-new")
    os.mkdir(staging, 0o700)
    directory_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    published = False
    try:
        artifacts = {
            "prover": write_sealed_file(directory_fd, PROVER_NAME, sealed["prover"], 0o500),
            "verifier": write_sealed_file(directory_fd, VERIFIER_NAME, sealed["verifier"], 0o500),
            "prover_dep_info": write_sealed_file(
                directory_fd, f"{PROVER_NAME}.d", sealed["prover_dep_info"], 0o400
            ),
            "verifier_dep_info": write_sealed_file(
                directory_fd, f"{VERIFIER_NAME}.d", sealed["verifier_dep_info"], 0o400
            ),
        }
        file_refs = {value["name"]: value for value in artifacts.values()}
        manifest_refs: dict[str, dict] = {}
        for name, value in manifests.items():
            raw = canonical(value)
            descriptor = sealed_memfd(f"kpb-{name}-manifest", raw)
            try:
                manifest_ref = write_sealed_file(
                    directory_fd,
                    f"{name.upper()}-MANIFEST.json",
                    descriptor,
                    0o400,
                )
            finally:
                os.close(descriptor)
            manifest_refs[name] = manifest_ref
            file_refs[manifest_ref["name"]] = manifest_ref
        final_receipt = dict(receipt)
        final_receipt["artifacts"] = artifacts
        final_receipt["input_manifests"] = manifest_refs
        final_receipt["frame_header_sha256"] = sha256_bytes(canonical(header))
        final_receipt["publication_contract"] = {
            "method": "renameat2-RENAME_NOREPLACE",
            "sealed_staging_and_post_publish_hashes_required": True,
        }
        unsigned = dict(final_receipt)
        final_receipt["receipt_identity_sha256"] = sha256_bytes(canonical(unsigned))
        receipt_raw = canonical(final_receipt)
        receipt_fd = sealed_memfd("kpb-build-receipt", receipt_raw)
        try:
            receipt_ref = write_sealed_file(
                directory_fd, "BUILD-RECEIPT.json", receipt_fd, 0o400
            )
        finally:
            os.close(receipt_fd)
        file_refs[receipt_ref["name"]] = receipt_ref
        publication_manifest = {
            "schema": "kpb-w1-bwrap-publication-manifest/v1",
            "files_before_publication": [
                {
                    key: value[key]
                    for key in (
                        "name",
                        "bytes",
                        "sha256",
                        "sealed_memfd_sha256",
                        "staging_post_write_sha256",
                        "mode_octal",
                    )
                }
                for _, value in sorted(file_refs.items())
            ],
            "rename_method": "renameat2-RENAME_NOREPLACE",
            "authorization": False,
        }
        publication_fd = sealed_memfd(
            "kpb-publication-manifest", canonical(publication_manifest)
        )
        try:
            publication_ref = write_sealed_file(
                directory_fd, "PUBLICATION-MANIFEST.json", publication_fd, 0o400
            )
        finally:
            os.close(publication_fd)
        file_refs[publication_ref["name"]] = publication_ref
        os.fsync(directory_fd)
        rename_noreplace(staging, OUTPUT_PARENT)
        published = True
        base_fd = os.open(
            PRIVATE_OUTPUT_BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(base_fd)
        finally:
            os.close(base_fd)
        post_publish: dict[str, dict] = {}
        for name, expected in sorted(file_refs.items()):
            raw, observed = stable_file_at(directory_fd, name)
            need(
                observed["sha256"] == expected["sha256"]
                and observed["bytes"] == expected["bytes"]
                and observed["mode_octal"] == expected["mode_octal"]
                and observed["device"] == expected["device"]
                and observed["inode"] == expected["inode"],
                "post-publication-identity-mismatch",
            )
            post_publish[name] = {
                "bytes": len(raw),
                "pre_publish_sha256": expected["staging_post_write_sha256"],
                "post_publish_sha256": observed["sha256"],
                "mode_octal": observed["mode_octal"],
                "device": observed["device"],
                "inode": observed["inode"],
            }
        return {
            "output_parent": str(OUTPUT_PARENT),
            "receipt": receipt_ref,
            "publication_manifest": publication_ref,
            "post_publish": post_publish,
            "artifact_count": len(artifacts),
            "authorization": False,
        }
    except BaseException:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        os.close(directory_fd)


def run_freeze(contract: dict) -> dict:
    # Gate shape checks happen before tree walking, mkdir, memfd creation, bwrap,
    # or publication.  The checked-in state therefore cannot launch anything.
    require_gate_shapes()
    validate_fixed_boundaries()
    local = local_source_manifest()
    vendor = vendor_manifest()
    toolchain = toolchain_manifest()
    boundary = validate_review_gates(local, vendor, toolchain)

    manifest_raws = {
        "local": canonical(local),
        "vendor": canonical(vendor),
        "toolchain": canonical(toolchain),
    }
    manifest_shas = {name: sha256_bytes(raw) for name, raw in manifest_raws.items()}
    outer_source = rendered_outer_source(
        manifest_shas["local"],
        manifest_shas["vendor"],
        manifest_shas["toolchain"],
        boundary["leaf_tools"]["bwrap"]["sha256"],
        {
            row["destination"]: boundary["root_runtime"][row["source"]]["sha256"]
            for row in boundary["bwrap_elf_closure"]["nested_runtime_bindings"]
        },
        {
            candidate: {
                "device": route["device"],
                "inode": route["inode"],
                "mode_octal": route["mode_octal"],
                "symlink_target": route["symlink_target"],
                "resolved": route["resolved"],
                "sha256": boundary["root_runtime"][route["resolved"]]["sha256"],
            }
            for candidate, route in boundary["bwrap_elf_closure"][
                "cache_candidate_routes"
            ].items()
        },
    ).encode("utf-8")
    seccomp_raw = seccomp_filter_bytes()
    descriptors: list[int] = []
    sealed_outputs: dict[str, int] = {}
    try:
        bwrap_fd = os.open(BWRAP, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        descriptors.append(bwrap_fd)
        opened_bwrap = authenticate_open_executable_fd(
            bwrap_fd, BWRAP, boundary["leaf_tools"]["bwrap"]
        )
        rehearsal = run_symlink_destination_rehearsal(bwrap_fd)
        repo_fd = open_directory_fd(REPO_ROOT)
        registry_fd = open_directory_fd(REGISTRY_ROOT)
        toolchain_fd = open_directory_fd(TOOLCHAIN_ROOT)
        descriptors.extend((repo_fd, registry_fd, toolchain_fd))
        outer_fd = sealed_memfd("kpb-outer-copy-source", outer_source)
        local_fd = sealed_memfd("kpb-local-manifest", manifest_raws["local"])
        vendor_fd = sealed_memfd("kpb-vendor-manifest", manifest_raws["vendor"])
        toolchain_manifest_fd = sealed_memfd(
            "kpb-toolchain-manifest", manifest_raws["toolchain"]
        )
        seccomp_fd = sealed_memfd("kpb-seccomp", seccomp_raw)
        descriptors.extend(
            (outer_fd, local_fd, vendor_fd, toolchain_manifest_fd, seccomp_fd)
        )
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        launch_block_read, launch_block_write = os.pipe2(os.O_CLOEXEC)
        descriptors.extend(
            (status_read, status_write, launch_block_read, launch_block_write)
        )
        passed = (
            bwrap_fd,
            repo_fd,
            registry_fd,
            toolchain_fd,
            outer_fd,
            local_fd,
            vendor_fd,
            toolchain_manifest_fd,
            seccomp_fd,
            status_write,
            launch_block_read,
        )
        runtime_bindings = tuple(
            (row["source"], row["destination"])
            for row in boundary["bwrap_elf_closure"]["nested_runtime_bindings"]
        )
        need(valid_nested_runtime_bindings(runtime_bindings), "nested-runtime-bindings")
        command = outer_bwrap_command(
            bwrap_fd=bwrap_fd,
            repo_fd=repo_fd,
            registry_fd=registry_fd,
            toolchain_fd=toolchain_fd,
            outer_source_fd=outer_fd,
            local_manifest_fd=local_fd,
            vendor_manifest_fd=vendor_fd,
            toolchain_manifest_fd=toolchain_manifest_fd,
            seccomp_fd=seccomp_fd,
            status_fd=status_write,
            launch_block_fd=launch_block_read,
            local_sha=manifest_shas["local"],
            vendor_sha=manifest_shas["vendor"],
            toolchain_sha=manifest_shas["toolchain"],
            bwrap_sha=boundary["leaf_tools"]["bwrap"]["sha256"],
            runtime_bindings=runtime_bindings,
        )
        launch_contract = outer_launch_contract(
            bwrap_identity=boundary["leaf_tools"]["bwrap"],
            local_sha=manifest_shas["local"],
            vendor_sha=manifest_shas["vendor"],
            toolchain_sha=manifest_shas["toolchain"],
            bwrap_sha=boundary["leaf_tools"]["bwrap"]["sha256"],
            outer_source_sha=sha256_bytes(outer_source),
            local_manifest_sha=manifest_shas["local"],
            vendor_manifest_sha=manifest_shas["vendor"],
            toolchain_manifest_sha=manifest_shas["toolchain"],
            seccomp_sha=sha256_bytes(seccomp_raw),
            runtime_bindings=runtime_bindings,
            apparmor_profile_name=boundary["apparmor_policy"]["profile_name"],
        )
        runtime = run_bounded_process(
            command,
            passed_fds=passed,
            launch_contract=launch_contract,
            status_read_fd=status_read,
            status_write_fd=status_write,
            launch_block_write_fd=launch_block_write,
        )
        need(runtime["stderr"] == b"", "outer-stderr")
        header, sealed_outputs = parse_build_frame(runtime["stdout"])
        need(header.get("cargo_command") == expected_cargo_command(), "cargo-command")

        # Host inputs and tool identities must still equal the reviewed bytes.
        local_after = local_source_manifest()
        vendor_after = vendor_manifest()
        toolchain_after = toolchain_manifest()
        need(local_after == local and vendor_after == vendor and toolchain_after == toolchain,
             "input-tree-drift")
        boundary_after = validate_review_gates(local_after, vendor_after, toolchain_after)
        need(boundary_after == boundary, "runtime-boundary-drift")

        receipt = {
            "schema": RECEIPT_SCHEMA,
            "classification": CLASSIFICATION,
            "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "stage0_contract_sha256": contract["contract_sha256"],
            "freezer_source_sha256": contract["source_sha256"],
            "external_bootstrap_source_sha256": contract[
                "external_bootstrap_source_sha256"
            ],
            "local_tree_sha256": local["tree_sha256"],
            "vendor_tree_sha256": vendor["tree_sha256"],
            "toolchain_tree_sha256": toolchain["tree_sha256"],
            "leaf_tools": boundary["leaf_tools"],
            "root_runtime": boundary["root_runtime"],
            "bwrap_elf_closure": boundary["bwrap_elf_closure"],
            "apparmor_profile_source": boundary["apparmor_profile"],
            "apparmor_policy": boundary["apparmor_policy"],
            "reviewed_fixed_bwrap_path": str(BWRAP),
            "reviewed_fixed_bwrap_version": REVIEWED_BWRAP_VERSION,
            "reviewed_bwrap_apparmor_exec_path": REVIEWED_BWRAP_APPARMOR_EXEC_PATH,
            "reviewed_bwrap_apparmor_profile_source_sha256": (
                REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256
            ),
            "apparmor_loaded_policy_byte_identity_authenticated": False,
            "apparmor_global_loaded_profile_table_preflight_used": False,
            "apparmor_attachment_evidence": runtime["apparmor_exec_label"],
            "reviewed_bwrap_provenance": REVIEWED_BWRAP_PROVENANCE,
            "reviewed_bwrap_provenance_evidence": boundary[
                "bwrap_provenance_evidence"
            ],
            "opened_bwrap_fd_identity": opened_bwrap,
            "preexisting_vulnerable_bwrap_payload_admissible": False,
            "symlink_destination_rehearsal": rehearsal,
            "bwrap_command_sha256": sha256_bytes(canonical(command)),
            "seccomp_sha256": sha256_bytes(seccomp_raw),
            "x32_abi_syscalls_killed": True,
            "denied_syscalls_x86_64": sorted(DENIED_SYSCALLS_X86_64),
            "denied_syscall_names_x86_64": dict(
                sorted(DENIED_SYSCALL_NAMES_X86_64.items())
            ),
            "runtime": {
                key: value
                for key, value in runtime.items()
                if key not in {"stdout", "stderr"}
            },
            "claims": {
                "source_only_build": True,
                "finite_reviewed_source_file_allowlist_enforced": True,
                "ambient_private_material_presence_on_host_examined": False,
                "private_proving_material_mounted_into_final_build": False,
                "outer_copier_can_read_only_reviewed_input_root_mounts": True,
                "setup": False,
                "proving_key_read": False,
                "r1cs_read": False,
                "assignment_or_witness_read": False,
                "proof_executed": False,
                "verifier_executed": False,
                "network_namespace_isolated": True,
                "network_and_relay_syscalls_denied": True,
                "nested_bwrap_reviewed_ld_cache_mounted": True,
                "nested_bwrap_reviewed_runtime_objects_overlaid": True,
                "ld_cache_unknown_and_hwcaps_extensions_rejected": True,
                "final_build_ambient_host_home_run_tmp_local_mounted": False,
                "outer_copier_reviewed_input_mounts_originate_under_host_home": True,
                "whole_host_home_mounted": False,
                "build_swap_prevented": False,
                "full_dynamic_closure_reproducible": False,
                "host_root_runtime_trusted": True,
                "outer_python_and_final_build_broad_host_runtime_trusted": True,
                "bwrap_package_to_elf_relationship_verified_from_reviewed_deb": True,
                "debian_archive_repository_signature_cryptographically_reverified_locally": False,
                "upstream_provenance_depends_on_reviewed_external_evidence": True,
                "upstream_tag_signature_cryptographically_reverified_locally": False,
                "debian_package_rebuilt_from_upstream_commit_locally": False,
                "one_trusted_host_assumption": True,
                "same_uid_and_privileged_host_processes_in_tcb": True,
                "host_compromise_or_physical_state_outside_claim": True,
                "hostile_same_uid_isolation_claim": False,
                "independent_rebuild_required_before_private_proof": True,
                "private_proof_requires_enforced_swap_max_zero": True,
                "cryptographic_correctness": False,
                "privacy": False,
                "financial_acceptance": False,
                "production_authority": False,
            },
            "authorization": False,
        }
        return publish_bundle(
            header,
            sealed_outputs,
            receipt,
            {"local": local, "vendor": vendor, "toolchain": toolchain},
        )
    finally:
        for descriptor in sealed_outputs.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def stop_result(category: str) -> dict:
    return {
        "schema": SCHEMA,
        "status": "STOP",
        "category": category,
        "review_gates_bound": all(
            value is not None
            for value in (
                REVIEWED_LOCAL_SOURCE_TREE_SHA256,
                REVIEWED_LOCAL_SOURCE_FILES_SHA256,
                REVIEWED_VENDOR_TREE_SHA256,
                REVIEWED_TOOLCHAIN_TREE_SHA256,
                REVIEWED_ROOT_RUNTIME_SHA256,
                REVIEWED_LEAF_TOOL_SHA256,
                REVIEWED_BWRAP_VERSION,
                REVIEWED_BWRAP_APPARMOR_EXEC_PATH,
                REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256,
                REVIEWED_BWRAP_APPARMOR_POLICY,
                REVIEWED_BWRAP_PROVENANCE,
                REVIEWED_BWRAP_ELF_CLOSURE,
            )
        ),
        "installed_bwrap_admissible": False,
        "real_build_executed": False,
        "proof_executed": False,
        "network_or_funds": False,
        "authorization": False,
    }


def main(arguments: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if arguments is None else arguments)
    if args == ["--render-stage0"]:
        sys.stdout.buffer.write(canonical(render_external_stage0()))
        return 0
    if len(args) == 2 and args[0] == "--stage0-run" and is_sha256(args[1]):
        try:
            contract = validate_stage0_entry(args[1])
            result = run_freeze(contract)
        except (OSError, ValueError, Refused, subprocess.SubprocessError) as error:
            sys.stdout.buffer.write(canonical(stop_result(str(error))))
            return 2
        sys.stdout.buffer.write(canonical(result))
        return 0
    if not args:
        sys.stdout.buffer.write(canonical(stop_result("independent-review-gates-unbound")))
        return 2
    sys.stdout.buffer.write(canonical(stop_result("arguments-not-accepted")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
