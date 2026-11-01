#!/usr/bin/env python3
"""Inert contract for a future current-source W1 build freezer.

The production source manifest, build units, commands, and accepted binary
identities are deliberately unbound.  The CLI only reports status.  Internal
helpers implement and hostile-test a narrow filesystem core that a later fixed
build entry may use: recursively copy directly declared local path packages to
a create-new snapshot, admit test-only exact snapshot dep-info, rehash the same
source inodes, and atomically publish synthetic sealed evidence.  This is not a
complete Cargo graph derivation or a sandboxed production build boundary.

This module never opens a proving key, synthesizes a relation, generates a
proof, runs setup, accesses a network, or touches funds.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tomllib
import uuid


SCHEMA = "kpb-current-w1-source-build-freezer-contract/v1"
SOURCE_MANIFEST_SCHEMA = "kpb-current-w1-source-snapshot-manifest/v1"
BUILD_RECEIPT_SCHEMA = "kpb-current-w1-test-build-freeze-receipt/v1"
CLASSIFICATION = "SOURCE_ONLY_NO_BUILD_EXECUTION_NO_PROOF_NO_AUTHORITY"
CHUNK = 1024 * 1024

# These remain unbound until the relation-side assignment preparer and the
# source-owned low-memory runner have explicit final source hashes and a fixed
# entrypoint.  There is consequently no production build function or CLI.
PRODUCTION_SOURCE_MANIFEST_SHA256 = None
PRODUCTION_FREEZER_SOURCE_SHA256 = None
PRODUCTION_ASSIGNMENT_PREPARER_SHA256 = None
PRODUCTION_LOW_MEMORY_RUNNER_SHA256 = None
PRODUCTION_BUILD_COMMANDS = None

SOURCE_STATUS = {
    "schema": SCHEMA,
    "recursive_direct_path_package_snapshot_core": True,
    "selected_unresolved_package_features_refuse_core": True,
    "descriptor_bound_create_new_snapshot_core": True,
    "same_inode_source_rehash_core": True,
    "test_only_caller_expected_dep_info_core": True,
    "atomic_sealed_test_evidence_core": True,
    "locked_offline_cargo_metadata_graph_bound": False,
    "workspace_inherited_dependencies_resolved": False,
    "workspace_patch_replace_resolved": False,
    "cargo_config_path_sources_and_wrappers_resolved": False,
    "all_ancestor_manifest_and_cargo_config_semantics_resolved": False,
    "build_script_proc_macro_ambient_reads_sandboxed": False,
    "production_expected_dependency_set_derived": False,
    "production_filesystem_sandbox_present": False,
    "production_source_manifest_bound": False,
    "production_freezer_source_bound": False,
    "production_assignment_preparer_bound": False,
    "production_low_memory_runner_bound": False,
    "production_build_commands_bound": False,
    "production_build_execution_present": False,
    "production_binary_acceptance_present": False,
    "production_launch_enabled": False,
    "authorization": False,
}


class Refused(RuntimeError):
    """One fail-closed contract refusal."""


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


def _false_actions() -> dict:
    return {
        "source_snapshot": False,
        "build": False,
        "setup": False,
        "pk_decode": False,
        "synthesis": False,
        "proof": False,
        "verification": False,
        "publication": False,
        "network": False,
        "funds": False,
    }


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
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


def _safe_relative(value: str) -> PurePosixPath:
    need(type(value) is str and value != "", "relative-path-type")
    need(
        "\\" not in value
        and "\x00" not in value
        and not any(character.isspace() or ord(character) < 32 for character in value),
        "relative-path-encoding",
    )
    path = PurePosixPath(value)
    need(
        not path.is_absolute()
        and str(path) == value
        and all(part not in ("", ".", "..") for part in path.parts),
        "relative-path-canonical",
    )
    return path


def _directory(path: Path, mode: int | None = None) -> os.stat_result:
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        raise Refused("directory-missing") from None
    need(
        stat.S_ISDIR(value.st_mode)
        and not stat.S_ISLNK(value.st_mode)
        and value.st_uid == os.getuid(),
        "directory-stat",
    )
    if mode is not None:
        need(stat.S_IMODE(value.st_mode) == mode, "directory-mode")
    return value


def _directory_ref(path: Path, mode: int | None = None) -> dict:
    value = _directory(path, mode)
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "link_count": value.st_nlink,
        "bytes": value.st_size,
        "owner_uid": value.st_uid,
        "mode_octal": f"{stat.S_IMODE(value.st_mode):04o}",
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _require_same_directory(path: Path, reference: dict, mode: int) -> None:
    observed = _directory_ref(path, mode)
    need(observed == reference, "directory-inode-substitution")


def _require_same_directory_object(path: Path, reference: dict, mode: int) -> dict:
    """Pin the directory object while allowing an explicitly expected mutation."""
    observed = _directory_ref(path, mode)
    for key in ("device", "inode", "owner_uid", "mode_octal"):
        need(observed[key] == reference[key], "directory-object-substitution")
    return observed


def _path_components_are_real(root: Path, relative: PurePosixPath) -> None:
    current = root
    _directory(current)
    for part in relative.parts:
        current = current / part
        value = os.lstat(current)
        need(not stat.S_ISLNK(value.st_mode), "source-symlink-component")


def _hash_fd(fd: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        block = os.pread(fd, CHUNK, total)
        if not block:
            return digest.hexdigest(), total
        digest.update(block)
        total += len(block)


def _stable_file_identity(path: Path, expected_mode: int | None = None) -> dict:
    before_path = os.lstat(path)
    need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == os.getuid()
        and before_path.st_nlink == 1,
        "stable-file-stat",
    )
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(_stat_identity(before) == _stat_identity(before_path), "stable-file-open-race")
        digest, count = _hash_fd(fd)
        after = os.fstat(fd)
        after_path = os.lstat(path)
        need(
            _stat_identity(before) == _stat_identity(after)
            == _stat_identity(after_path)
            and count == after.st_size,
            "stable-file-read-race",
        )
        if expected_mode is not None:
            need(stat.S_IMODE(after.st_mode) == expected_mode, "stable-file-mode")
        return {
            "device": after.st_dev,
            "inode": after.st_ino,
            "bytes": count,
            "sha256": digest,
            "mode_octal": f"{stat.S_IMODE(after.st_mode):04o}",
        }
    finally:
        os.close(fd)


def _stable_file_bytes(
    path: Path, expected_mode: int | None = None
) -> tuple[bytes, dict]:
    before_path = os.lstat(path)
    need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == os.getuid()
        and before_path.st_nlink == 1,
        "stable-bytes-stat",
    )
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(_stat_identity(before) == _stat_identity(before_path), "stable-bytes-open-race")
        chunks = []
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            chunks.append(block)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        after_path = os.lstat(path)
        need(
            _stat_identity(before) == _stat_identity(after)
            == _stat_identity(after_path)
            and len(raw) == after.st_size,
            "stable-bytes-read-race",
        )
        if expected_mode is not None:
            need(stat.S_IMODE(after.st_mode) == expected_mode, "stable-bytes-mode")
        identity = {
            "device": after.st_dev,
            "inode": after.st_ino,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
            "mode_octal": f"{stat.S_IMODE(after.st_mode):04o}",
        }
        return raw, identity
    finally:
        os.close(fd)


def _write_new(path: Path, raw: bytes, final_mode: int) -> dict:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        original = os.fstat(descriptor)
        offset = 0
        while offset < len(raw):
            written = os.pwrite(descriptor, raw[offset:], offset)
            need(written > 0, "output-short-write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, final_mode)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        need(
            (original.st_dev, original.st_ino) == (final.st_dev, final.st_ino)
            and stat.S_ISREG(final.st_mode)
            and final.st_nlink == 1
            and final.st_uid == os.getuid()
            and final.st_size == len(raw)
            and stat.S_IMODE(final.st_mode) == final_mode,
            "output-final-stat",
        )
    finally:
        os.close(descriptor)
    observed = _stable_file_identity(path, final_mode)
    need(
        observed["bytes"] == len(raw)
        and observed["sha256"] == sha256_bytes(raw),
        "output-final-content",
    )
    return observed


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _directory_ref_from_fd(descriptor: int, mode: int | None = None) -> dict:
    value = os.fstat(descriptor)
    need(
        stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid(),
        "directory-fd-stat",
    )
    if mode is not None:
        need(stat.S_IMODE(value.st_mode) == mode, "directory-fd-mode")
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "link_count": value.st_nlink,
        "bytes": value.st_size,
        "owner_uid": value.st_uid,
        "mode_octal": f"{stat.S_IMODE(value.st_mode):04o}",
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _child_name(value: str) -> bytes:
    need(
        type(value) is str
        and value not in ("", ".", "..")
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value,
        "rename-child-name",
    )
    return os.fsencode(value)


def _rename_no_replace_at(
    parent_descriptor: int, source_name: str, destination_name: str
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    need(rename is not None, "renameat2-required")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(
        parent_descriptor,
        _child_name(source_name),
        parent_descriptor,
        _child_name(destination_name),
        1,
    ) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(destination_name)
        raise OSError(code, os.strerror(code), destination_name)


def _manifest_member(relative_path: str, identity: dict) -> dict:
    return {
        "relative_path": relative_path,
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
    }


def _dependency_sections(value: object) -> list[str]:
    found = []
    if type(value) is not dict:
        return found
    for key, item in value.items():
        if key in {"patch", "replace"} and item:
            raise Refused("cargo-patch-replace-needs-locked-graph")
        if key == "workspace" and type(item) is dict and item.get("dependencies"):
            raise Refused("cargo-workspace-dependencies-need-locked-graph")
        if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
            need(type(item) is dict, "cargo-dependency-table")
            for specification in item.values():
                if type(specification) is dict and specification.get("workspace") is True:
                    raise Refused("cargo-workspace-inherited-dependency")
                if type(specification) is dict and "path" in specification:
                    need(type(specification["path"]) is str, "cargo-path-dependency")
                    found.append(specification["path"])
        found.extend(_dependency_sections(item))
    return found


def _refuse_ambient_package_readers(package: Path, manifest: dict) -> None:
    package_table = manifest.get("package", {})
    lib_table = manifest.get("lib", {})
    need(type(package_table) is dict and type(lib_table) is dict, "cargo-table-shape")
    if os.path.lexists(package / "build.rs") or package_table.get("build") not in (
        None,
        False,
    ):
        raise Refused("cargo-build-script-needs-filesystem-sandbox")
    if lib_table.get("proc-macro") is True:
        raise Refused("cargo-proc-macro-needs-filesystem-sandbox")


def _refuse_unresolved_cargo_config(raw: bytes) -> None:
    try:
        value = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise Refused("cargo-config-parse") from None
    need(type(value) is dict, "cargo-config-shape")
    if value.get("source") or value.get("patch") or value.get("replace"):
        raise Refused("cargo-config-source-needs-locked-graph")
    build = value.get("build", {})
    need(type(build) is dict, "cargo-config-build-table")
    if any(key in build for key in ("rustc", "rustc-wrapper", "rustc-workspace-wrapper")):
        raise Refused("cargo-config-wrapper-needs-filesystem-sandbox")


def _package_files(package: Path, source_root: Path) -> list[Path]:
    relative_package = package.relative_to(source_root)
    _path_components_are_real(source_root, PurePosixPath(relative_package.as_posix()))
    found = []
    for current_raw, directories, files in os.walk(package, followlinks=False):
        current = Path(current_raw)
        kept = []
        for name in sorted(directories):
            child = current / name
            value = os.lstat(child)
            need(not stat.S_ISLNK(value.st_mode), "package-symlink-directory")
            need(stat.S_ISDIR(value.st_mode), "package-nondirectory")
            if name == ".local":
                raise Refused("package-local-tree-not-source")
            if name not in {"target", ".git"}:
                kept.append(name)
        directories[:] = kept
        for name in sorted(files):
            child = current / name
            value = os.lstat(child)
            need(
                stat.S_ISREG(value.st_mode)
                and not stat.S_ISLNK(value.st_mode)
                and value.st_uid == os.getuid()
                and value.st_nlink == 1,
                "package-source-stat",
            )
            found.append(child)
    need((package / "Cargo.toml") in found, "package-cargo-manifest")
    return found


def derive_recursive_direct_path_package_manifest(
    source_root: Path, package_roots: tuple[str, ...]
) -> dict:
    """Snapshot directly declared local Cargo path packages recursively.

    Every regular file under each package (except generated target/.git/.local
    trees) is included. Selected unresolved features in the package manifests
    (workspace inheritance, patch/replace, build scripts, proc macros) and
    selected Cargo source/wrapper configuration refuse. Ancestor manifests and
    all Cargo configuration semantics are not resolved. Production still
    requires pinned locked offline Cargo metadata plus a filesystem sandbox and
    internally derived dep-info expectations.
    """
    source_root = Path(source_root).absolute()
    need(source_root == source_root.resolve(strict=True), "source-root-canonical")
    _directory(source_root)
    need(
        type(package_roots) is tuple and package_roots,
        "package-roots-shape",
    )
    pending = []
    for raw in package_roots:
        relative = _safe_relative(raw)
        pending.append(source_root / Path(*relative.parts))
    packages = []
    all_files = set()
    while pending:
        package = pending.pop()
        package = package.absolute()
        need(package.is_relative_to(source_root), "package-outside-source-root")
        if package in packages:
            continue
        _directory(package)
        manifest_path = package / "Cargo.toml"
        manifest_raw, _ = _stable_file_bytes(manifest_path)
        try:
            manifest_value = tomllib.loads(manifest_raw.decode())
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            raise Refused("cargo-manifest-parse") from None
        _refuse_ambient_package_readers(package, manifest_value)
        packages.append(package)
        all_files.update(_package_files(package, source_root))
        for dependency in _dependency_sections(manifest_value):
            try:
                candidate = (package / dependency).resolve(strict=True)
            except (FileNotFoundError, RuntimeError):
                raise Refused("path-dependency-missing-or-loop") from None
            need(candidate.is_relative_to(source_root), "path-dependency-outside-root")
            relative = candidate.relative_to(source_root)
            _path_components_are_real(
                source_root, PurePosixPath(relative.as_posix())
            )
            pending.append(candidate)
    # Cargo can read ancestor workspace/lock/toolchain/config files. Include
    # every such existing local input up to the fixed source root.
    for package in packages:
        current = package
        while True:
            for relative in (
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain",
                "rust-toolchain.toml",
                ".cargo/config",
                ".cargo/config.toml",
            ):
                candidate = current / relative
                if os.path.lexists(candidate):
                    value = os.lstat(candidate)
                    need(
                        stat.S_ISREG(value.st_mode)
                        and not stat.S_ISLNK(value.st_mode)
                        and value.st_uid == os.getuid()
                        and value.st_nlink == 1,
                        "ambient-cargo-input-stat",
                    )
                    if relative in (".cargo/config", ".cargo/config.toml"):
                        config_raw, _ = _stable_file_bytes(candidate)
                        _refuse_unresolved_cargo_config(config_raw)
                    all_files.add(candidate)
            if current == source_root:
                break
            current = current.parent
            need(current.is_relative_to(source_root), "ambient-cargo-root-walk")
    members = []
    # Path ordering compares path components, while the manifest contract is
    # explicitly ordered by canonical POSIX relative-path strings.  Those
    # orders differ for a sibling such as ``module.rs`` and ``module/file.rs``.
    for path in sorted(
        all_files, key=lambda item: item.relative_to(source_root).as_posix()
    ):
        relative = path.relative_to(source_root).as_posix()
        identity = _stable_file_identity(path)
        members.append(_manifest_member(relative, identity))
    package_values = sorted(path.relative_to(source_root).as_posix() for path in packages)
    value = {
        "schema": SOURCE_MANIFEST_SCHEMA,
        "classification": "CURRENT_SOURCE_FINAL_CANDIDATE_NOT_AUTHORITY",
        "source_root": str(source_root),
        "package_roots": package_values,
        "derivation": (
            "recursive-direct-local-cargo-path-packages-plus-all-regular-"
            "package-files-excluding-target-git-local;not-a-locked-cargo-graph"
        ),
        "members": members,
        "member_count": len(members),
        "members_identity_sha256": sha256_bytes(canonical(members)),
        "authorization": False,
    }
    value["manifest_identity_sha256"] = sha256_bytes(canonical(value))
    return value


def _validate_manifest(value: dict) -> None:
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
        and value["schema"] == SOURCE_MANIFEST_SCHEMA
        and value["classification"]
        == "CURRENT_SOURCE_FINAL_CANDIDATE_NOT_AUTHORITY"
        and value["authorization"] is False
        and type(value["members"]) is list
        and value["member_count"] == len(value["members"])
        and value["members_identity_sha256"]
        == sha256_bytes(canonical(value["members"])),
        "source-manifest-shape",
    )
    unsigned = dict(value)
    claimed = unsigned.pop("manifest_identity_sha256")
    need(claimed == sha256_bytes(canonical(unsigned)), "source-manifest-identity")
    paths = []
    for item in value["members"]:
        need(
            set(item) == {"relative_path", "bytes", "sha256"}
            and type(item["bytes"]) is int
            and item["bytes"] >= 0
            and type(item["sha256"]) is str
            and len(item["sha256"]) == 64,
            "source-manifest-member",
        )
        paths.append(str(_safe_relative(item["relative_path"])))
    need(paths == sorted(paths) and len(set(paths)) == len(paths), "source-manifest-order")


def _mkdir_relative(root: Path, relative_parent: PurePosixPath) -> Path:
    current = root
    for part in relative_parent.parts:
        current = current / part
        if os.path.lexists(current):
            value = os.lstat(current)
            need(
                stat.S_ISDIR(value.st_mode)
                and not stat.S_ISLNK(value.st_mode)
                and value.st_uid == os.getuid()
                and stat.S_IMODE(value.st_mode) == 0o700,
                "snapshot-parent-stat",
            )
        else:
            os.mkdir(current, 0o700)
    return current


def _copy_exact_source(
    source_path: Path, destination: Path, expected: dict
) -> dict:
    before_path = os.lstat(source_path)
    need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == os.getuid()
        and before_path.st_nlink == 1,
        "copy-source-stat",
    )
    source_fd = os.open(
        source_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    destination_fd = -1
    try:
        opened = os.fstat(source_fd)
        need(
            _stat_identity(opened) == _stat_identity(before_path),
            "copy-source-open-race",
        )
        need(
            opened.st_size == expected["bytes"],
            "copy-source-expected-size",
        )
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            block = os.read(source_fd, CHUNK)
            if not block:
                break
            digest.update(block)
            offset = 0
            while offset < len(block):
                written = os.write(destination_fd, block[offset:])
                need(written > 0, "snapshot-short-write")
                offset += written
            copied += len(block)
        after = os.fstat(source_fd)
        after_path = os.lstat(source_path)
        need(
            _stat_identity(opened) == _stat_identity(after)
            == _stat_identity(after_path),
            "copy-source-read-race",
        )
        need(
            copied == expected["bytes"]
            and digest.hexdigest() == expected["sha256"],
            "copy-source-content-drift",
        )
        os.fsync(destination_fd)
        os.fchmod(destination_fd, 0o400)
        os.fsync(destination_fd)
        output = os.fstat(destination_fd)
        need(
            stat.S_ISREG(output.st_mode)
            and output.st_nlink == 1
            and output.st_uid == os.getuid()
            and stat.S_IMODE(output.st_mode) == 0o400
            and output.st_size == copied,
            "snapshot-output-stat",
        )
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
    identity = _stable_file_identity(destination, 0o400)
    need(
        identity["bytes"] == expected["bytes"]
        and identity["sha256"] == expected["sha256"],
        "snapshot-output-content",
    )
    return identity


def _seal_directories(root: Path) -> None:
    directories = []
    for current_raw, child_directories, _ in os.walk(root, followlinks=False):
        current = Path(current_raw)
        directories.append(current)
        for name in child_directories:
            child = current / name
            value = os.lstat(child)
            need(
                stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode),
                "seal-directory-symlink",
            )
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        _fsync_directory(directory)
        os.chmod(directory, 0o500, follow_symlinks=False)
        _directory(directory, 0o500)


def _snapshot_members(
    source_root: Path, snapshot_root: Path, manifest: dict
) -> list[dict]:
    _validate_manifest(manifest)
    os.mkdir(snapshot_root, 0o700)
    refs = []
    for expected in manifest["members"]:
        relative = _safe_relative(expected["relative_path"])
        source_path = source_root / Path(*relative.parts)
        _path_components_are_real(source_root, relative)
        parent = _mkdir_relative(snapshot_root, relative.parent)
        destination = parent / relative.name
        identity = _copy_exact_source(source_path, destination, expected)
        refs.append(
            {
                "relative_path": expected["relative_path"],
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
                "device": identity["device"],
                "inode": identity["inode"],
            }
        )
    _seal_directories(snapshot_root)
    return refs


def _verify_snapshot(snapshot_root: Path, refs: list[dict]) -> list[dict]:
    _directory(snapshot_root, 0o500)
    observed = []
    expected_directories = {""}
    for expected in refs:
        relative = _safe_relative(expected["relative_path"])
        for depth in range(1, len(relative.parts)):
            expected_directories.add(PurePosixPath(*relative.parts[:depth]).as_posix())
        path = snapshot_root / Path(*relative.parts)
        identity = _stable_file_identity(path, 0o400)
        need(
            identity["device"] == expected["device"]
            and identity["inode"] == expected["inode"]
            and identity["bytes"] == expected["bytes"]
            and identity["sha256"] == expected["sha256"],
            "snapshot-same-inode-content",
        )
        observed.append(expected)
    actual = []
    actual_directories = []
    for current_raw, directories, files in os.walk(snapshot_root, followlinks=False):
        current = Path(current_raw)
        _directory(current, 0o500)
        relative_directory = current.relative_to(snapshot_root)
        actual_directories.append(
            "" if relative_directory == Path(".") else relative_directory.as_posix()
        )
        for name in directories:
            _directory(current / name, 0o500)
        for name in files:
            actual.append((current / name).relative_to(snapshot_root).as_posix())
    need(
        sorted(actual) == [item["relative_path"] for item in refs],
        "snapshot-exact-file-set",
    )
    need(
        sorted(actual_directories) == sorted(expected_directories),
        "snapshot-exact-directory-set",
    )
    return observed


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
    need(target != "" and dependencies != "", "dep-info-rule-shape")
    tokens = dependencies.split(" ")
    need(all(tokens) and all(token != "" for token in tokens), "dep-info-token")
    need(len(tokens) == len(set(tokens)), "dep-info-duplicate")
    return target, tokens


def _validate_test_only_snapshot_dep_info(
    raw: bytes,
    *,
    snapshot_root: Path,
    target_root: Path,
    expected_target: Path,
    snapshot_refs: list[dict],
    caller_expected_dependency_relatives: tuple[str, ...],
    original_source_root: Path,
) -> dict:
    """Validate synthetic fixture dep-info; never derives a production set."""
    snapshot_root = snapshot_root.absolute()
    target_root = target_root.absolute()
    expected_target = expected_target.absolute()
    original_source_root = original_source_root.absolute()
    target, dependencies = _parse_dep_info(raw)
    need(Path(target).is_absolute(), "dep-info-target-absolute")
    need(Path(target) == expected_target, "dep-info-target-binding")
    need(expected_target.is_relative_to(target_root), "dep-info-target-outside-target")
    ref_paths = {item["relative_path"] for item in snapshot_refs}
    expected = []
    for raw_relative in caller_expected_dependency_relatives:
        relative = _safe_relative(raw_relative)
        need(str(relative) in ref_paths, "dep-info-expected-not-snapshot-member")
        expected.append(str(snapshot_root / Path(*relative.parts)))
    need(len(expected) == len(set(expected)), "dep-info-expected-duplicate")
    observed = []
    for raw_path in dependencies:
        path = Path(raw_path)
        need(path.is_absolute() and ".." not in path.parts, "dep-info-path-canonical")
        need(path.is_relative_to(snapshot_root), "dep-info-live-or-external-source")
        need(not path.is_relative_to(original_source_root), "dep-info-live-source")
        relative = path.relative_to(snapshot_root).as_posix()
        need(relative in ref_paths, "dep-info-unmanifested-source")
        observed.append(str(path))
    need(observed == expected, "dep-info-exact-source-set-order")
    return {
        "target": target,
        "dependencies": observed,
        "dependency_count": len(observed),
        "dep_info_sha256": sha256_bytes(raw),
        "snapshot_only": True,
        "live_path_provenance": False,
        "expected_dependency_authority": "CALLER_SUPPLIED_TEST_FIXTURE_ONLY",
        "production_expected_dependency_set_derived": False,
    }


@dataclasses.dataclass
class _TestOnlySession:
    source_root: Path
    output_parent: Path
    output_name: str
    staging_root: Path
    snapshot_root: Path
    target_root: Path
    manifest: dict
    snapshot_refs: list[dict]
    source_root_ref: dict
    output_parent_ref: dict
    staging_root_ref: dict
    target_root_ref: dict
    finalized: bool = False


def _test_only_begin_candidate(
    source_root: Path,
    package_roots: tuple[str, ...],
    output_parent: Path,
    output_name: str,
) -> _TestOnlySession:
    """Build no code; snapshot a synthetic unit for hostile unit controls."""
    need(
        re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,95}", output_name) is not None,
        "test-output-name",
    )
    source_root = Path(source_root).absolute()
    output_parent = Path(output_parent).absolute()
    need(
        source_root == source_root.resolve(strict=True)
        and output_parent == output_parent.resolve(strict=True),
        "test-root-canonical",
    )
    source_root_ref = _directory_ref(source_root)
    output_parent_initial_ref = _directory_ref(output_parent, 0o700)
    final = output_parent / output_name
    need(not os.path.lexists(final), "test-final-create-new")
    staging = output_parent / f".{output_name}.staging-{uuid.uuid4()}"
    target = output_parent / f".{output_name}.target-{uuid.uuid4()}"
    os.mkdir(staging, 0o700)
    os.mkdir(target, 0o700)
    staging_initial_ref = _directory_ref(staging, 0o700)
    target_ref = _directory_ref(target, 0o700)
    manifest = derive_recursive_direct_path_package_manifest(source_root, package_roots)
    snapshot = staging / "sources"
    refs = _snapshot_members(source_root, snapshot, manifest)
    # Re-derive the full set after the copy. This catches missing, extra, or
    # modified live members that race source enumeration/copy.
    after = derive_recursive_direct_path_package_manifest(source_root, package_roots)
    need(after == manifest, "source-set-changed-during-snapshot")
    _require_same_directory(
        source_root, source_root_ref, int(source_root_ref["mode_octal"], 8)
    )
    _require_same_directory_object(output_parent, output_parent_initial_ref, 0o700)
    _require_same_directory_object(staging, staging_initial_ref, 0o700)
    _require_same_directory(target, target_ref, 0o700)
    _verify_snapshot(snapshot, refs)
    # Capture full directory state after all intentional begin-phase mutations.
    output_parent_ref = _directory_ref(output_parent, 0o700)
    staging_ref = _directory_ref(staging, 0o700)
    return _TestOnlySession(
        source_root,
        output_parent,
        output_name,
        staging,
        snapshot,
        target,
        manifest,
        refs,
        source_root_ref,
        output_parent_ref,
        staging_ref,
        target_ref,
    )


def _copy_generated(path: Path, destination: Path, mode: int) -> dict:
    raw, _ = _stable_file_bytes(path)
    return _write_new(destination, raw, mode)


def _validate_test_bundle_tree(root: Path, root_mode: int) -> None:
    _directory(root, root_mode)
    need(
        set(os.listdir(root))
        == {
            "sources",
            "artifacts",
            "SOURCE-MANIFEST.json",
            "FREEZER-SOURCE.py",
            "BUILD-RECEIPT.json",
        },
        "test-bundle-root-file-set",
    )
    _directory(root / "sources", 0o500)
    _directory(root / "artifacts", 0o500)
    need(
        set(os.listdir(root / "artifacts"))
        == {"candidate-binary", "candidate-binary.d"},
        "test-bundle-artifact-file-set",
    )
    for name in (
        "SOURCE-MANIFEST.json",
        "FREEZER-SOURCE.py",
        "BUILD-RECEIPT.json",
        "artifacts/candidate-binary.d",
    ):
        _stable_file_identity(root / name, 0o400)
    _stable_file_identity(root / "artifacts/candidate-binary", 0o500)


def _test_only_finalize_candidate(
    session: _TestOnlySession,
    *,
    binary: Path,
    dep_info: Path,
    expected_target: Path,
    expected_dependency_relatives: tuple[str, ...],
) -> dict:
    """Freeze synthetic build outputs; never claims a production build."""
    need(not session.finalized, "test-session-finalized")
    session.finalized = True
    _require_same_directory(
        session.source_root,
        session.source_root_ref,
        int(session.source_root_ref["mode_octal"], 8),
    )
    _require_same_directory(session.output_parent, session.output_parent_ref, 0o700)
    _require_same_directory(session.staging_root, session.staging_root_ref, 0o700)
    _require_same_directory_object(session.target_root, session.target_root_ref, 0o700)
    target_ready_ref = _directory_ref(session.target_root, 0o700)
    need(
        Path(binary).absolute().is_relative_to(session.target_root)
        and Path(dep_info).absolute().is_relative_to(session.target_root)
        and Path(expected_target).absolute().is_relative_to(session.target_root),
        "test-build-output-outside-target",
    )
    need(
        Path(binary).absolute() == Path(expected_target).absolute(),
        "test-binary-target-binding",
    )
    before = _verify_snapshot(session.snapshot_root, session.snapshot_refs)
    dep_raw, _ = _stable_file_bytes(Path(dep_info))
    dep_result = _validate_test_only_snapshot_dep_info(
        dep_raw,
        snapshot_root=session.snapshot_root,
        target_root=session.target_root,
        expected_target=Path(expected_target),
        snapshot_refs=session.snapshot_refs,
        caller_expected_dependency_relatives=expected_dependency_relatives,
        original_source_root=session.source_root,
    )
    artifacts = session.staging_root / "artifacts"
    os.mkdir(artifacts, 0o700)
    binary_ref = _copy_generated(Path(binary), artifacts / "candidate-binary", 0o500)
    dep_ref = _write_new(artifacts / "candidate-binary.d", dep_raw, 0o400)
    after = _verify_snapshot(session.snapshot_root, session.snapshot_refs)
    need(before == after, "snapshot-changed-across-build")

    manifest_path = session.staging_root / "SOURCE-MANIFEST.json"
    manifest_ref = _write_new(manifest_path, canonical(session.manifest), 0o400)
    freezer_raw, _ = _stable_file_bytes(Path(__file__).resolve(strict=True))
    freezer_ref = _write_new(
        session.staging_root / "FREEZER-SOURCE.py", freezer_raw, 0o400
    )
    receipt = {
        "schema": BUILD_RECEIPT_SCHEMA,
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
        "dep_info": dep_result,
        "binary": {
            "name": "candidate-binary",
            "bytes": binary_ref["bytes"],
            "sha256": binary_ref["sha256"],
            "mode_octal": "0500",
        },
        "frozen_dep_info": {
            "name": "candidate-binary.d",
            "bytes": dep_ref["bytes"],
            "sha256": dep_ref["sha256"],
            "mode_octal": "0400",
        },
        "actual_subprocess_build_executed_by_contract": False,
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
    receipt["receipt_identity_sha256"] = sha256_bytes(canonical(receipt))
    receipt_ref = _write_new(
        session.staging_root / "BUILD-RECEIPT.json", canonical(receipt), 0o400
    )
    _seal_directories(artifacts)
    _validate_test_bundle_tree(session.staging_root, 0o700)
    # sources and artifacts are now sealed; root is sealed last after all
    # evidence leaves exist and every child directory is durable.
    _fsync_directory(session.staging_root)
    os.chmod(session.staging_root, 0o500, follow_symlinks=False)
    _directory(session.staging_root, 0o500)
    _require_same_directory(session.target_root, target_ready_ref, 0o700)
    final = session.output_parent / session.output_name
    need(
        session.staging_root.parent == session.output_parent
        and final.parent == session.output_parent,
        "test-publication-parent-binding",
    )
    parent_descriptor = os.open(
        session.output_parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        need(
            _directory_ref_from_fd(parent_descriptor, 0o700)
            == session.output_parent_ref,
            "test-publication-parent-fd-substitution",
        )
        _rename_no_replace_at(
            parent_descriptor, session.staging_root.name, session.output_name
        )
        os.fsync(parent_descriptor)
        after_parent = _directory_ref_from_fd(parent_descriptor, 0o700)
        need(
            _directory_ref(session.output_parent, 0o700) == after_parent,
            "test-publication-parent-path-substitution",
        )
        for key in ("device", "inode", "link_count", "owner_uid", "mode_octal"):
            need(
                after_parent[key] == session.output_parent_ref[key],
                "test-publication-parent-object-changed",
            )
    finally:
        os.close(parent_descriptor)
    _validate_test_bundle_tree(final, 0o500)
    final_snapshot = final / "sources"
    _verify_snapshot(final_snapshot, session.snapshot_refs)
    _directory(final / "artifacts", 0o500)
    _stable_file_identity(final / "artifacts/candidate-binary", 0o500)
    _stable_file_identity(final / "artifacts/candidate-binary.d", 0o400)
    final_receipt = _stable_file_identity(final / "BUILD-RECEIPT.json", 0o400)
    need(
        final_receipt["bytes"] == receipt_ref["bytes"]
        and final_receipt["sha256"] == receipt_ref["sha256"],
        "test-final-receipt",
    )
    return {
        "status": "TEST_ONLY_CURRENT_SOURCE_FREEZE_CONTRACT_COMPLETE",
        "root": str(final),
        "receipt_sha256": receipt_ref["sha256"],
        "source_members_identity_sha256": session.manifest[
            "members_identity_sha256"
        ],
        "source_member_count": session.manifest["member_count"],
        "production_build": False,
        "authorization": False,
    }


def status() -> dict:
    return {
        "source_status": SOURCE_STATUS,
        "pending_bindings": {
            "source_manifest_sha256": PRODUCTION_SOURCE_MANIFEST_SHA256,
            "freezer_source_sha256": PRODUCTION_FREEZER_SOURCE_SHA256,
            "assignment_preparer_sha256": PRODUCTION_ASSIGNMENT_PREPARER_SHA256,
            "low_memory_runner_sha256": PRODUCTION_LOW_MEMORY_RUNNER_SHA256,
            "build_commands": PRODUCTION_BUILD_COMMANDS,
        },
        "required_production_workflow": [
            "derive-pinned-locked-offline-cargo-metadata-package-graph",
            "resolve-workspace-inherited-patch-replace-and-cargo-config-paths",
            "copy-create-new-source-snapshot-and-rederive-live-set",
            "seal-snapshot-files-0400-and-directories-0500",
            "build-fixed-command-in-filesystem-sandbox-with-only-snapshot-toolchain-vendor-target",
            "sandbox-build-script-and-proc-macro-ambient-reads",
            "derive-and-pin-expected-dependency-set-internally",
            "require-exact-internally-derived-dep-info-paths-under-snapshot-only",
            "rehash-same-snapshot-inodes-before-and-after-build",
            "freeze-binary-0500-and-evidence-0400",
            "atomically-publish-create-new-bundle-and-fsync-parent",
        ],
        "go": False,
        "reason": (
            "locked Cargo graph, sandbox, internally derived dependency set, "
            "final source hashes, and fixed production build entries are unbound"
        ),
        "actions_performed": _false_actions(),
        "authorization": False,
    }


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    args = parser.parse_args()
    need(args.command == "status", "status-only-cli")
    print(json.dumps(status(), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "CURRENT_W1_SOURCE_BUILD_FREEZER_REFUSED",
                    "category": type(error).__name__,
                    "authorization": False,
                },
                sort_keys=True,
            )
        )
        raise SystemExit(1)
