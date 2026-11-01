#!/usr/bin/env python3
"""Create the fixed mode-0400 source used for one reviewed reconstruction."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys


ROOT = Path("/home/luke/projects/kpi-intensive-2026-10-22/continuation")
LIVE_GENERATOR = (
    ROOT
    / "poc/local-private-payment/private_batch_trial/reconstruct_historical_w1_source_closure.py"
)
PRIVATE_PARENT = (
    ROOT / ".local/private-batch-w1-historical-reconstruction-private-20261029-01"
)
SEALED_GENERATOR_NAME = "RECONSTRUCTION-SOURCE.py"
SEALED_SEALER_NAME = "SEALER-SOURCE.py"
SEAL_NAME = "GENERATOR-SEAL.json"
EXPECTED_GENERATOR_SHA256 = "cacd8dbc153263a5cd2a477d9340337bbc5531e30805cc79ee035de4ae530975"
CHUNK = 1 << 20
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
RENAME_NOREPLACE = 1

_STAGING: Path | None = None


class Refused(RuntimeError):
    pass


def need(value: bool, category: str) -> None:
    if not value:
        raise Refused(category)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def file_state(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def directory_state(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_stable(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == os.geteuid()
        and before.st_nlink == 1
        and before.st_size <= maximum,
        "source-state",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | O_CLOEXEC)
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        need(file_state(opened) == file_state(before), "source-open-race")
        total = 0
        while True:
            chunk = os.read(descriptor, CHUNK)
            if not chunk:
                break
            total += len(chunk)
            need(total <= opened.st_size, "source-grew")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        need(
            total == opened.st_size
            and file_state(after) == file_state(opened) == file_state(after_path),
            "source-read-race",
        )
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def write_at(directory: int, name: str, raw: bytes) -> dict:
    need("/" not in name and name not in {"", ".", ".."}, "output-name")
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | O_CLOEXEC,
        0o400,
        dir_fd=directory,
    )
    try:
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            count = os.write(descriptor, view[offset:])
            need(count > 0, "output-short-write")
            offset += count
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    path_state = os.stat(name, dir_fd=directory, follow_symlinks=False)
    need(file_state(path_state) == file_state(opened), "output-write-race")
    need(
        stat.S_IMODE(opened.st_mode) == 0o400
        and opened.st_uid == os.geteuid()
        and opened.st_nlink == 1,
        "output-mode-owner-link",
    )
    return {
        "bytes": len(raw),
        "sha256": digest(raw),
        "state": file_state(opened),
    }


def verify_at(directory: int, name: str, expected: dict) -> None:
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    need(file_state(before) == expected["state"], "sealed-file-substitution")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | O_CLOEXEC, dir_fd=directory)
    hasher = hashlib.sha256()
    total = 0
    try:
        need(file_state(os.fstat(descriptor)) == expected["state"], "sealed-file-open-race")
        while True:
            chunk = os.read(descriptor, CHUNK)
            if not chunk:
                break
            total += len(chunk)
            hasher.update(chunk)
        need(file_state(os.fstat(descriptor)) == expected["state"], "sealed-file-read-race")
    finally:
        os.close(descriptor)
    after = os.stat(name, dir_fd=directory, follow_symlinks=False)
    need(
        file_state(after) == expected["state"]
        and total == expected["bytes"]
        and hasher.hexdigest() == expected["sha256"],
        "sealed-file-identity",
    )


def rename_noreplace(directory: int, old_name: str, new_name: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    need(renameat2 is not None, "renameat2-unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory,
        os.fsencode(old_name),
        directory,
        os.fsencode(new_name),
        RENAME_NOREPLACE,
    )
    if result != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise Refused("fixed-private-parent-exists")
        raise Refused(f"renameat2-{number}")


def validate_tree(directory: int, expected: dict[str, dict]) -> None:
    need(sorted(os.listdir(directory)) == sorted(expected), "sealed-source-tree")
    for name in sorted(expected):
        verify_at(directory, name, expected[name])


def main() -> None:
    global _STAGING
    os.umask(0o077)
    need(len(sys.argv) == 1, "no-sealer-arguments")
    local = PRIVATE_PARENT.parent
    before = local.lstat()
    need(
        stat.S_ISDIR(before.st_mode)
        and before.st_uid == os.geteuid()
        and not (before.st_mode & stat.S_IWOTH),
        "local-parent-state",
    )
    local_descriptor = os.open(local, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC)
    root_descriptor: int | None = None
    try:
        need(directory_state(os.fstat(local_descriptor)) == directory_state(before), "local-parent-race")
        try:
            os.stat(PRIVATE_PARENT.name, dir_fd=local_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("fixed-private-parent-exists")

        generator_raw = read_stable(LIVE_GENERATOR, 1 << 20)
        need(digest(generator_raw) == EXPECTED_GENERATOR_SHA256, "reviewed-generator-hash")
        sealer_path = Path(__file__).resolve(strict=True)
        sealer_raw = read_stable(sealer_path, 1 << 20)
        staging_name = f".{PRIVATE_PARENT.name}.staging-{os.getpid()}-{secrets.token_hex(16)}"
        os.mkdir(staging_name, 0o700, dir_fd=local_descriptor)
        _STAGING = local / staging_name
        root_descriptor = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC,
            dir_fd=local_descriptor,
        )
        opened = os.fstat(root_descriptor)
        need(
            stat.S_IMODE(opened.st_mode) == 0o700
            and opened.st_uid == os.geteuid()
            and opened.st_nlink == 2,
            "private-staging-state",
        )
        expected: dict[str, dict] = {}
        expected[SEALED_GENERATOR_NAME] = write_at(root_descriptor, SEALED_GENERATOR_NAME, generator_raw)
        expected[SEALED_SEALER_NAME] = write_at(root_descriptor, SEALED_SEALER_NAME, sealer_raw)
        seal = {
            "schema": "kpb-reviewed-historical-w1-generator-seal/v1",
            "generator": {
                "path": str(PRIVATE_PARENT / SEALED_GENERATOR_NAME),
                "bytes": len(generator_raw),
                "sha256": digest(generator_raw),
            },
            "sealer": {
                "path": str(PRIVATE_PARENT / SEALED_SEALER_NAME),
                "bytes": len(sealer_raw),
                "sha256": digest(sealer_raw),
            },
            "boundaries": {
                "current_source": False,
                "build_reproduced": False,
                "authorization": False,
                "assignment_or_proof_generated": False,
                "setup_network_or_funds": False,
            },
        }
        expected[SEAL_NAME] = write_at(root_descriptor, SEAL_NAME, canonical(seal))
        os.fsync(root_descriptor)
        root_before = directory_state(os.fstat(root_descriptor))
        validate_tree(root_descriptor, expected)
        need(directory_state(os.fstat(root_descriptor)) == root_before, "private-staging-churn")
        os.fsync(local_descriptor)
        rename_noreplace(local_descriptor, staging_name, PRIVATE_PARENT.name)
        os.fsync(local_descriptor)

        final = os.open(
            PRIVATE_PARENT.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC,
            dir_fd=local_descriptor,
        )
        try:
            final_info = os.fstat(final)
            need(
                final_info.st_dev == opened.st_dev
                and final_info.st_ino == opened.st_ino
                and stat.S_IMODE(final_info.st_mode) == 0o700,
                "private-publication-inode",
            )
            final_before = directory_state(final_info)
            validate_tree(final, expected)
            need(directory_state(os.fstat(final)) == final_before, "private-publication-churn")
            os.fsync(final)
        finally:
            os.close(final)
        os.fsync(local_descriptor)
        _STAGING = None
        print(
            json.dumps(
                {
                    "status": "REVIEWED_GENERATOR_SEALED",
                    "private_parent": str(PRIVATE_PARENT),
                    "generator": seal["generator"],
                    "seal": {
                        "path": str(PRIVATE_PARENT / SEAL_NAME),
                        "bytes": expected[SEAL_NAME]["bytes"],
                        "sha256": expected[SEAL_NAME]["sha256"],
                    },
                    "next_command": (
                        f"python3 /proc/self/fd/9 "
                        f"9<{PRIVATE_PARENT / SEALED_GENERATOR_NAME}"
                    ),
                    "authorization": False,
                },
                sort_keys=True,
            )
        )
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)
        os.close(local_descriptor)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        print(
            json.dumps(
                {
                    "status": "REVIEWED_GENERATOR_SEAL_REFUSED",
                    "category": str(error) if isinstance(error, Refused) else type(error).__name__,
                    "incomplete_staging": str(_STAGING) if _STAGING else None,
                    "fixed_private_parent_absent": not os.path.lexists(PRIVATE_PARENT),
                },
                sort_keys=True,
            )
        )
        raise SystemExit(1)
