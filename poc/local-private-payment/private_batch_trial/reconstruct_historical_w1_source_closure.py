#!/usr/bin/env python3
"""Seal the exact historical 81-member W1 PLAN source closure.

Five live relation files changed after the retained component run. Their exact
historical bytes are reconstructed by unique byte transforms and must match the
hashes already frozen in PLAN.json. This is nonfinal provenance evidence only.
"""

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
PLAN = ROOT / ".local/private-batch-offline-w1-components-20261029-01/PLAN.json"
PLAN_SHA256 = "8b24a987f87d2bd9dca0b04f4622022eac0e04724af06ff761141169f0853482"
PLAN_IDENTITY = "f9ac4a37df9e50867eb01e282cf9a8c9f6ce9ff56891aa27d909a71877c7bd80"
SOURCE_IDENTITY = "8fcca654b4eb03b38a62c22648cd14323919279dc49d841751d3802683c66aae"
PLAN_BYTES = 30_403
OWNER_CLOSURE = ROOT / ".local/private-batch-owner-aux-build-20261029-04/SOURCE-CLOSURE.json"
OWNER_CLOSURE_BYTES = 8_916
OWNER_CLOSURE_SHA256 = "e100f1f244a7c14b9e8d771d54c37a99ba7b7f75f7c6b9402e010844fddd7051"
OWNER_MEMBERS_IDENTITY = "b3967d50d2de999020c9ef3dc2723ccdf31ee4fb99b3fc7e3ff35f3464cf54d4"
PRIVATE_PARENT = ROOT / ".local/private-batch-w1-historical-reconstruction-private-20261029-01"
SEALED_GENERATOR = PRIVATE_PARENT / "RECONSTRUCTION-SOURCE.py"
GENERATOR_SEAL = PRIVATE_PARENT / "GENERATOR-SEAL.json"
SEALED_SEALER = PRIVATE_PARENT / "SEALER-SOURCE.py"
EXECUTED_SOURCE_FD = 9
EXECUTED_SOURCE_PATH = Path(f"/proc/self/fd/{EXECUTED_SOURCE_FD}")
OUTPUT = PRIVATE_PARENT / "private-batch-w1-historical-reconstructed-nonfinal-20261029-01"
RELATION = ROOT / "poc/local-private-payment/private-batch-relation"
CHUNK = 1 << 20
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
RENAME_NOREPLACE = 1

_INCOMPLETE_STAGING: Path | None = None
_QUARANTINED_PUBLICATION: Path | None = None


class Refused(RuntimeError):
    pass


def need(value: bool, category: str) -> None:
    if not value:
        raise Refused(category)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_unique(raw: bytes) -> object:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, "duplicate-json-key")
            value[key] = item
        return value

    return json.loads(raw, object_pairs_hook=unique)


def replace_exact(raw: bytes, old: bytes, new: bytes, count: int = 1) -> bytes:
    need(raw.count(old) == count, "historical-transform-preimage")
    return raw.replace(old, new)


def cargo_toml(raw: bytes) -> bytes:
    raw = replace_exact(raw, b'offline-w1-preparer = ["offline-w1-verifier"]\n', b"")
    raw = replace_exact(raw, b'zeroize = "=1.9.1"\n', b"")
    return replace_exact(
        raw,
        b'''[[example]]\nname = "prepare_frozen_w1_round1_assignment"\nrequired-features = ["offline-w1-preparer"]\n\n''',
        b"",
    )


def cargo_lock(raw: bytes) -> bytes:
    return replace_exact(
        raw,
        b' "sha2",\n "zeroize",\n]\n',
        b' "sha2",\n]\n',
    )


def relation_lib(raw: bytes) -> bytes:
    raw = replace_exact(raw, b"use zeroize::Zeroize;\n", b"")
    start = b"\nfn zeroize_profile(profile: &mut Profile) {"
    end = b"        self.witness.delta_quotient.zeroize();\n    }\n}\n"
    need(raw.count(start) == 1 and raw.count(end) == 1, "lib-transform-boundary")
    first = raw.index(start)
    last = raw.index(end, first) + len(end)
    return raw[:first] + raw[last:]


def counterfactual(raw: bytes) -> bytes:
    raw = replace_exact(raw, b"use zeroize::Zeroize;\n", b"")
    raw = replace_exact(
        raw,
        b'''impl Drop for SignatureWitnessSource {\n    fn drop(&mut self) {\n        self.assignment.zeroize();\n    }\n}\n''',
        b'''impl Drop for SignatureWitnessSource {\n    fn drop(&mut self) {\n        self.assignment.fill(Fr::ZERO);\n    }\n}\n''',
    )
    return replace_exact(
        raw,
        b'''\nimpl Drop for FullW1RoundSource {\n    fn drop(&mut self) {\n        self.aggregate.verification_key.zeroize();\n        self.aggregate.proof.zeroize();\n    }\n}\n''',
        b"",
    )


def offline_verifier(raw: bytes) -> bytes:
    raw = replace_exact(raw, b"use zeroize::{Zeroize, Zeroizing};\n", b"")
    raw = replace_exact(
        raw,
        b'''#[cfg(feature = "offline-w1-preparer")]\nmod frozen_assignment;\n#[cfg(feature = "offline-w1-preparer")]\npub use frozen_assignment::{\n    FrozenRound1AssignmentRefused, write_frozen_round1_assignment_receipt,\n};\n\n''',
        b"",
    )
    raw = replace_exact(
        raw,
        b'''fn zeroize_json(value: &mut Value) {\n    match value {\n        Value::String(string) => string.zeroize(),\n        Value::Array(values) => {\n            for value in values.iter_mut() {\n                zeroize_json(value);\n            }\n            values.clear();\n        }\n        Value::Object(values) => {\n            for (mut key, mut value) in core::mem::take(values) {\n                key.zeroize();\n                zeroize_json(&mut value);\n            }\n        }\n        Value::Null | Value::Bool(_) | Value::Number(_) => {}\n    }\n    *value = Value::Null;\n}\n\nstruct SensitiveJson(Value);\n\nimpl Drop for SensitiveJson {\n    fn drop(&mut self) {\n        zeroize_json(&mut self.0);\n    }\n}\n\n''',
        b"",
    )
    raw = replace_exact(
        raw,
        b'''\nimpl Drop for LoadedRef {\n    fn drop(&mut self) {\n        self.raw.zeroize();\n        self.sha256.zeroize();\n    }\n}\n''',
        b"",
    )
    raw = replace_exact(
        raw,
        b'''    let opened = file.metadata().map_err(|_| OfflineError::Input)?;\n    need(opened.is_file(), OfflineError::Input)?;\n    #[cfg(unix)]\n    need(\n        opened.dev() == metadata.dev() && opened.ino() == metadata.ino() && opened.nlink() == 1,\n        OfflineError::Input,\n    )?;\n''',
        b"",
    )
    for old, new in [
        (
            b"    let mut raw = Zeroizing::new(Vec::with_capacity(expected_size));",
            b"    let mut raw = Vec::with_capacity(expected_size);",
        ),
        (b"        raw: core::mem::take(&mut raw),", b"        raw,"),
        (
            b"    let _witness_document = SensitiveJson(unique_json(&witness.raw)?);",
            b"    unique_json(&witness.raw)?;",
        ),
        (b"        witness.sha256.clone(),", b"        witness.sha256,"),
        (
            b"    let document = SensitiveJson(unique_json(&loaded.raw)?);",
            b"    let document = unique_json(&loaded.raw)?;",
        ),
        (b"    Ok((w0, loaded.sha256.clone()))", b"    Ok((w0, loaded.sha256))"),
        (
            b'''        let record_value = SensitiveJson(unique_json(&record.raw)?);\n        owners.push(parse_owner_record(&record_value.0, &ctx, owner_component)?);''',
            b'''        let record_value = unique_json(&record.raw)?;\n        owners.push(parse_owner_record(&record_value, &ctx, owner_component)?);''',
        ),
        (
            b'''        context_sha256: context_leaf.sha256.clone(),\n        effects_sha256: effects_leaf.sha256.clone(),\n        projection_sha256: projection_leaf.sha256.clone(),''',
            b'''        context_sha256: context_leaf.sha256,\n        effects_sha256: effects_leaf.sha256,\n        projection_sha256: projection_leaf.sha256,''',
        ),
        (b"        dep_info_sha256: dep_info.sha256.clone(),", b"        dep_info_sha256: dep_info.sha256,"),
        (
            b'''    let aggregate_vk: [u8; 328] = aggregate_vk_leaf\n        .raw\n        .as_slice()\n        .try_into()\n''',
            b'''    let aggregate_vk: [u8; 328] = aggregate_vk_leaf\n        .raw\n        .try_into()\n''',
        ),
    ]:
        raw = replace_exact(raw, old, new)
    return replace_exact(raw, b"&document.0", b"&document", 7)


TRANSFORMS = {
    str(RELATION / "Cargo.toml"): (
        1_348,
        "05bf2194f1d026dc08cf4b4f87ec81d13686d91a900a531f969f273b8cc31d65",
        "remove-preparer-feature-zeroize-example",
        cargo_toml,
    ),
    str(RELATION / "Cargo.lock"): (
        38_072,
        "9b6c43f8a188d24de5e55b9c310bb094133ffa2a276dca4d8fda6f20985bea5e",
        "remove-direct-zeroize-lock-edge",
        cargo_lock,
    ),
    str(RELATION / "src/lib.rs"): (
        6_167,
        "4c00a14b5de1317a8d209c266af0dbb6db00496ef1f74e3809c1f6a9e9d02091",
        "remove-batch-circuit-zeroization",
        relation_lib,
    ),
    str(RELATION / "src/counterfactual_w1.rs"): (
        38_650,
        "c9b5803ba8887a4f29e2285b7070fff789528b326a0fe43854f6bd7f01ca939b",
        "remove-round-source-zeroization",
        counterfactual,
    ),
    str(RELATION / "src/counterfactual_w1/offline_verifier.rs"): (
        47_558,
        "71a9906c794a9ca0972f7fadf18ef0a1e9b387ffdc13526541aa6c101cdbed7b",
        "remove-preparer-seam-and-sensitive-buffer-hardening",
        offline_verifier,
    ),
}


def _file_state(info: os.stat_result) -> tuple[int, ...]:
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


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
    )


def _directory_state(info: os.stat_result) -> tuple[int, ...]:
    return (
        *_directory_identity(info),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _safe_name(name: str) -> None:
    need(name not in {"", ".", ".."} and "/" not in name and "\x00" not in name, "unsafe-output-name")


def _path_state(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise Refused("source-path-missing") from error


def stable_open(path: Path, expected_bytes: int | None = None) -> tuple[int, os.stat_result]:
    before = _path_state(path)
    need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode), "source-not-regular")
    need(before.st_uid == os.geteuid() and before.st_nlink == 1, "source-owner-or-link")
    if expected_bytes is not None:
        need(before.st_size == expected_bytes, "source-size")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | O_CLOEXEC)
    except OSError as error:
        raise Refused("source-open") from error
    try:
        opened = os.fstat(descriptor)
        after_path = _path_state(path)
        need(_file_state(opened) == _file_state(before) == _file_state(after_path), "source-open-race")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _verify_source_after(path: Path, opened: os.stat_result, descriptor: int) -> None:
    after = os.fstat(descriptor)
    after_path = _path_state(path)
    need(_file_state(after) == _file_state(opened) == _file_state(after_path), "source-read-race")


def read_stable(path: Path, expected_bytes: int | None = None, maximum_bytes: int | None = None) -> bytes:
    descriptor, opened = stable_open(path, expected_bytes)
    if maximum_bytes is not None:
        need(opened.st_size <= maximum_bytes, "source-too-large")
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, CHUNK)
            if not chunk:
                break
            total += len(chunk)
            need(total <= opened.st_size, "source-grew-during-read")
            chunks.append(chunk)
        _verify_source_after(path, opened, descriptor)
    finally:
        os.close(descriptor)
    need(total == opened.st_size, "source-short-read")
    return b"".join(chunks)


def _pread_all(descriptor: int, expected_bytes: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_bytes:
        chunk = os.pread(descriptor, min(CHUNK, expected_bytes - offset), offset)
        need(bool(chunk), "executed-source-short-read")
        chunks.append(chunk)
        offset += len(chunk)
    need(os.pread(descriptor, 1, expected_bytes) == b"", "executed-source-grew")
    return b"".join(chunks)


def capture_executed_source(descriptor: int, executed_path: Path, pinned_path: Path) -> dict:
    need(executed_path == Path(f"/proc/self/fd/{descriptor}"), "executed-source-path")
    try:
        opened = os.fstat(descriptor)
        through_proc = os.stat(executed_path)
        pinned = pinned_path.lstat()
    except OSError as error:
        raise Refused("executed-source-open") from error
    need(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(pinned.st_mode), "executed-source-type")
    need(
        stat.S_IMODE(opened.st_mode) == 0o400
        and opened.st_uid == os.geteuid()
        and opened.st_nlink == 1,
        "executed-source-mode-owner-link",
    )
    need(_file_state(opened) == _file_state(through_proc) == _file_state(pinned), "executed-source-inode")
    raw = _pread_all(descriptor, opened.st_size)
    after = os.fstat(descriptor)
    after_proc = os.stat(executed_path)
    after_pinned = pinned_path.lstat()
    need(
        _file_state(after) == _file_state(opened)
        and _file_state(after_proc) == _file_state(opened)
        and _file_state(after_pinned) == _file_state(opened),
        "executed-source-capture-race",
    )
    return {
        "descriptor": descriptor,
        "executed_path": str(executed_path),
        "pinned_path": str(pinned_path),
        "bytes": len(raw),
        "sha256": digest(raw),
        "state": _file_state(opened),
        "raw": raw,
    }


def reverify_executed_source(binding: dict) -> None:
    descriptor = binding["descriptor"]
    try:
        opened = os.fstat(descriptor)
        through_proc = os.stat(binding["executed_path"])
        pinned = Path(binding["pinned_path"]).lstat()
    except OSError as error:
        raise Refused("executed-source-reopen") from error
    need(
        _file_state(opened) == binding["state"]
        and _file_state(through_proc) == binding["state"]
        and _file_state(pinned) == binding["state"],
        "executed-source-changed",
    )
    raw = _pread_all(descriptor, binding["bytes"])
    need(raw == binding["raw"] and digest(raw) == binding["sha256"], "executed-source-rehash")


def validate_generator_seal(binding: dict) -> dict:
    raw = read_stable(GENERATOR_SEAL, maximum_bytes=1 << 20)
    document = parse_unique(raw)
    need(type(document) is dict and canonical(document) == raw, "generator-seal-canonical")
    need(
        set(document) == {"boundaries", "generator", "schema", "sealer"}
        and document["schema"] == "kpb-reviewed-historical-w1-generator-seal/v1"
        and document["generator"]
        == {
            "bytes": binding["bytes"],
            "path": str(SEALED_GENERATOR),
            "sha256": binding["sha256"],
        }
        and document["boundaries"]
        == {
            "assignment_or_proof_generated": False,
            "authorization": False,
            "build_reproduced": False,
            "current_source": False,
            "setup_network_or_funds": False,
        },
        "generator-seal-fields",
    )
    sealer = document["sealer"]
    need(type(sealer) is dict and set(sealer) == {"bytes", "path", "sha256"}, "generator-sealer-ref")
    need(sealer["path"] == str(SEALED_SEALER), "generator-sealer-path")
    sealer_raw = read_stable(SEALED_SEALER, sealer["bytes"], 1 << 20)
    need(digest(sealer_raw) == sealer["sha256"], "generator-sealer-identity")
    for path in (GENERATOR_SEAL, SEALED_SEALER):
        info = path.lstat()
        need(
            stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.geteuid() and info.st_nlink == 1,
            "generator-seal-mode-owner-link",
        )
    return {
        "path": str(GENERATOR_SEAL),
        "bytes": len(raw),
        "sha256": digest(raw),
        "sealer": sealer,
    }


def _stat_at(directory: int, name: str) -> os.stat_result:
    _safe_name(name)
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as error:
        raise Refused("output-path-missing") from error


def _open_directory_at(directory: int, name: str) -> tuple[int, os.stat_result]:
    before = _stat_at(directory, name)
    need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode), "output-directory-type")
    need(before.st_uid == os.geteuid(), "output-directory-owner")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC,
            dir_fd=directory,
        )
    except OSError as error:
        raise Refused("output-directory-open") from error
    try:
        opened = os.fstat(descriptor)
        after_path = _stat_at(directory, name)
        need(
            _directory_state(opened) == _directory_state(before) == _directory_state(after_path),
            "output-directory-race",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _open_parent(path: Path) -> int:
    before = _path_state(path)
    need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode), "parent-not-directory")
    need(
        before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o700,
        "parent-owner-or-mode",
    )
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC)
    except OSError as error:
        raise Refused("parent-open") from error
    try:
        opened = os.fstat(descriptor)
        after = _path_state(path)
        need(
            _directory_state(opened) == _directory_state(before) == _directory_state(after),
            "parent-open-race",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _verify_directory_path(path: Path, descriptor: int, expected: tuple[int, ...]) -> None:
    try:
        path_state = path.lstat()
        opened = os.fstat(descriptor)
    except OSError as error:
        raise Refused("directory-path-recheck") from error
    need(
        stat.S_ISDIR(path_state.st_mode)
        and _directory_state(path_state) == expected == _directory_state(opened),
        "directory-path-changed",
    )


def _missing_at(directory: int, name: str) -> bool:
    _safe_name(name)
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError as error:
        raise Refused("output-presence-check") from error
    return False


def create_staging(directory: int, prefix: str) -> tuple[str, int]:
    need(prefix.startswith(".") and prefix.endswith("-"), "staging-prefix")
    for _ in range(32):
        name = f"{prefix}{os.getpid()}-{secrets.token_hex(16)}"
        _safe_name(name)
        try:
            os.mkdir(name, 0o700, dir_fd=directory)
        except FileExistsError:
            continue
        except OSError as error:
            raise Refused("staging-create") from error
        descriptor, opened = _open_directory_at(directory, name)
        need(stat.S_IMODE(opened.st_mode) == 0o700 and opened.st_nlink == 2, "staging-mode")
        os.fsync(directory)
        return name, descriptor
    raise Refused("staging-name-exhausted")


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        need(written > 0, "output-short-write")
        offset += written


def _output_expectation(info: os.stat_result, byte_count: int, sha256: str) -> dict:
    need(stat.S_ISREG(info.st_mode), "output-not-regular")
    need(
        stat.S_IMODE(info.st_mode) == 0o400
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and info.st_size == byte_count,
        "output-mode-owner-link-size",
    )
    return {"bytes": byte_count, "sha256": sha256, "state": _file_state(info)}


def write_bytes_at(directory: int, name: str, raw: bytes) -> dict:
    _safe_name(name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | O_CLOEXEC
    try:
        descriptor = os.open(name, flags, 0o400, dir_fd=directory)
    except OSError as error:
        raise Refused("output-create") from error
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = _stat_at(directory, name)
    need(_file_state(opened) == _file_state(after_path), "output-write-race")
    return _output_expectation(opened, len(raw), digest(raw))


def copy_exact_at(source_path: Path, directory: int, name: str, expected: dict) -> dict:
    need(set(expected) == {"path", "bytes", "sha256"}, "member-ref-fields")
    source, opened = stable_open(source_path, expected["bytes"])
    _safe_name(name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | O_CLOEXEC
    try:
        output = os.open(name, flags, 0o400, dir_fd=directory)
    except BaseException:
        os.close(source)
        raise
    hasher = hashlib.sha256()
    copied = 0
    try:
        while True:
            chunk = os.read(source, CHUNK)
            if not chunk:
                break
            copied += len(chunk)
            need(copied <= expected["bytes"], "source-grew-during-copy")
            hasher.update(chunk)
            _write_all(output, chunk)
        _verify_source_after(source_path, opened, source)
        os.fsync(output)
        output_opened = os.fstat(output)
    finally:
        os.close(source)
        os.close(output)
    output_path = _stat_at(directory, name)
    need(_file_state(output_opened) == _file_state(output_path), "output-copy-race")
    need(
        copied == expected["bytes"] and hasher.hexdigest() == expected["sha256"],
        "source-copy-hash",
    )
    return _output_expectation(output_opened, copied, hasher.hexdigest())


def output_reference(relative_path: str, expected: dict) -> dict:
    return {
        "path": str(OUTPUT / relative_path),
        "bytes": expected["bytes"],
        "sha256": expected["sha256"],
    }


def verify_file_at(directory: int, name: str, expected: dict) -> None:
    before = _stat_at(directory, name)
    need(_file_state(before) == expected["state"], "sealed-file-substitution")
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | O_CLOEXEC, dir_fd=directory)
    except OSError as error:
        raise Refused("sealed-file-open") from error
    hasher = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        need(_file_state(opened) == expected["state"], "sealed-file-open-race")
        while True:
            chunk = os.read(descriptor, CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
            total += len(chunk)
            need(total <= expected["bytes"], "sealed-file-grew")
        after = os.fstat(descriptor)
        need(_file_state(after) == expected["state"], "sealed-file-read-race")
    finally:
        os.close(descriptor)
    after_path = _stat_at(directory, name)
    need(_file_state(after_path) == expected["state"], "sealed-file-path-race")
    need(total == expected["bytes"] and hasher.hexdigest() == expected["sha256"], "sealed-file-hash")


def _exact_names(directory: int, expected: list[str], category: str) -> None:
    actual = os.listdir(directory)
    need(len(actual) == len(set(actual)), f"{category}-duplicates")
    need(sorted(actual) == expected, category)


def validate_tree(
    parent: int,
    root_name: str,
    root_descriptor: int,
    root_state: tuple[int, ...],
    member_state: tuple[int, ...],
    expected_files: dict[str, dict],
    member_names: list[str],
) -> None:
    root_path = _stat_at(parent, root_name)
    root_opened = os.fstat(root_descriptor)
    need(
        _directory_state(root_path) == root_state == _directory_state(root_opened),
        "sealed-root-substitution",
    )
    need(stat.S_IMODE(root_opened.st_mode) == 0o500 and root_opened.st_uid == os.geteuid(), "sealed-root-mode")
    root_file_names = sorted(name for name in expected_files if "/" not in name)
    _exact_names(root_descriptor, sorted(root_file_names + ["members"]), "sealed-root-members")
    member_descriptor, opened_members = _open_directory_at(root_descriptor, "members")
    try:
        need(
            _directory_state(opened_members) == member_state
            and stat.S_IMODE(opened_members.st_mode) == 0o500,
            "sealed-member-directory",
        )
        _exact_names(member_descriptor, member_names, "sealed-member-set-order")
        for name in member_names:
            verify_file_at(member_descriptor, name, expected_files[f"members/{name}"])
    finally:
        os.close(member_descriptor)
    for name in root_file_names:
        verify_file_at(root_descriptor, name, expected_files[name])
    need(_directory_state(os.fstat(root_descriptor)) == root_state, "sealed-root-changed-during-walk")
    need(_directory_state(_stat_at(parent, root_name)) == root_state, "sealed-root-path-changed-during-walk")


def _rename_noreplace(directory: int, old_name: str, new_name: str) -> None:
    _safe_name(old_name)
    _safe_name(new_name)
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
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise Refused("rename-target-exists")
        raise Refused(f"renameat2-{error_number}")


def _quarantine_publication(parent: int, final_name: str, root_state: tuple[int, ...]) -> None:
    global _QUARANTINED_PUBLICATION
    try:
        current = _stat_at(parent, final_name)
        if _directory_identity(current) != root_state[:6]:
            return
        for _ in range(32):
            quarantine = f".{final_name}.failed-postpublish-{os.getpid()}-{secrets.token_hex(16)}"
            try:
                _rename_noreplace(parent, final_name, quarantine)
            except Refused as error:
                if str(error) == "rename-target-exists":
                    continue
                raise
            os.fsync(parent)
            _QUARANTINED_PUBLICATION = OUTPUT.parent / quarantine
            return
    except BaseException:
        return


def _selected_owner_closure_reference(plan: dict) -> dict:
    try:
        value = plan["selected_build"]["output"]["owner_aux_build"]["source_closure"]
    except (KeyError, TypeError) as error:
        raise Refused("owner-closure-plan-reference") from error
    need(
        value
        == {
            "bytes": OWNER_CLOSURE_BYTES,
            "path": str(OWNER_CLOSURE),
            "sha256": OWNER_CLOSURE_SHA256,
        },
        "owner-closure-plan-reference",
    )
    return value


def _validate_plan_and_owner(plan_raw: bytes, owner_raw: bytes) -> tuple[dict, list[dict], dict, list[int]]:
    need(len(plan_raw) == PLAN_BYTES and digest(plan_raw) == PLAN_SHA256, "plan-identity")
    plan = parse_unique(plan_raw)
    need(type(plan) is dict and canonical(plan) == plan_raw, "plan-canonical")
    need(plan.get("plan_identity_sha256") == PLAN_IDENTITY, "plan-self-identity")
    members = plan.get("source_members")
    need(type(members) is list and len(members) == 81, "source-member-count")
    need(all(type(item) is dict and set(item) == {"path", "bytes", "sha256"} for item in members), "member-ref-fields")
    paths = [item["path"] for item in members]
    need(all(type(path) is str for path in paths), "member-path-types")
    need(len(set(paths)) == 81, "member-unique")
    need(digest(canonical(members)) == SOURCE_IDENTITY == plan.get("source_closure_sha256"), "closure-identity")
    need(set(TRANSFORMS).issubset(set(paths)), "transform-members")
    _selected_owner_closure_reference(plan)

    need(len(owner_raw) == OWNER_CLOSURE_BYTES and digest(owner_raw) == OWNER_CLOSURE_SHA256, "owner-closure-identity")
    owner = parse_unique(owner_raw)
    need(type(owner) is dict and canonical(owner) == owner_raw, "owner-closure-canonical")
    need(
        set(owner)
        == {
            "classification",
            "dep_info_sha256",
            "derivation",
            "member_count",
            "members",
            "members_identity_sha256",
            "schema",
        },
        "owner-closure-fields",
    )
    owner_members = owner["members"]
    need(type(owner_members) is list and len(owner_members) == owner["member_count"] == 37, "owner-member-count")
    need(
        owner["members_identity_sha256"] == OWNER_MEMBERS_IDENTITY
        and digest(canonical(owner_members)) == OWNER_MEMBERS_IDENTITY,
        "owner-member-identity",
    )
    need(
        all(type(item) is dict and set(item) == {"path", "bytes", "sha256"} for item in owner_members)
        and [item["path"] for item in owner_members] == sorted(item["path"] for item in owner_members),
        "owner-member-order",
    )
    plan_by_ref = {(item["path"], item["bytes"], item["sha256"]): ordinal for ordinal, item in enumerate(members)}
    try:
        owner_ordinals = [plan_by_ref[(item["path"], item["bytes"], item["sha256"])] for item in owner_members]
    except KeyError as error:
        raise Refused("owner-member-not-exact-plan-subset") from error
    need(owner_ordinals == sorted(owner_ordinals) and len(set(owner_ordinals)) == 37, "owner-member-plan-order")
    return plan, members, owner, owner_ordinals


def main() -> None:
    global _INCOMPLETE_STAGING
    os.umask(0o077)
    need(OUTPUT.parent == PRIVATE_PARENT and OUTPUT.name != PRIVATE_PARENT.name, "fixed-output-parent")
    need(Path(__file__) == EXECUTED_SOURCE_PATH, "interpreter-source-path")
    need(sys.argv == [str(EXECUTED_SOURCE_PATH)], "no-generator-arguments")
    executed_source = capture_executed_source(
        EXECUTED_SOURCE_FD,
        EXECUTED_SOURCE_PATH,
        SEALED_GENERATOR,
    )
    parent = _open_parent(PRIVATE_PARENT)
    parent_state = _directory_state(os.fstat(parent))
    root_descriptor: int | None = None
    member_descriptor: int | None = None
    published = False
    root_state: tuple[int, ...] | None = None
    try:
        _verify_directory_path(PRIVATE_PARENT, parent, parent_state)
        generator_seal = validate_generator_seal(executed_source)
        _verify_directory_path(PRIVATE_PARENT, parent, parent_state)
        need(_missing_at(parent, OUTPUT.name), "fresh-output-required")
        plan_raw = read_stable(PLAN, PLAN_BYTES, PLAN_BYTES)
        owner_raw = read_stable(OWNER_CLOSURE, OWNER_CLOSURE_BYTES, OWNER_CLOSURE_BYTES)
        plan, members, owner, owner_ordinals = _validate_plan_and_owner(plan_raw, owner_raw)

        staging_name, root_descriptor = create_staging(parent, f".{OUTPUT.name}.staging-")
        _INCOMPLETE_STAGING = OUTPUT.parent / staging_name
        parent_state = _directory_state(os.fstat(parent))
        _verify_directory_path(PRIVATE_PARENT, parent, parent_state)
        os.mkdir("members", 0o700, dir_fd=root_descriptor)
        member_descriptor, member_opened = _open_directory_at(root_descriptor, "members")
        need(stat.S_IMODE(member_opened.st_mode) == 0o700, "member-staging-mode")

        expected_files: dict[str, dict] = {}
        expected_files["PLAN.json"] = write_bytes_at(root_descriptor, "PLAN.json", plan_raw)
        expected_files["OWNER-AUX-SOURCE-CLOSURE.json"] = write_bytes_at(
            root_descriptor, "OWNER-AUX-SOURCE-CLOSURE.json", owner_raw
        )
        manifest_members: list[dict] = []
        transformed: list[dict] = []
        member_names: list[str] = []
        for ordinal, expected in enumerate(members):
            source_path = Path(expected["path"])
            snapshot_name = f"{ordinal:03d}-{expected['sha256']}"
            member_names.append(snapshot_name)
            relative = f"members/{snapshot_name}"
            if expected["path"] in TRANSFORMS:
                current_bytes, current_sha, transform_id, transform = TRANSFORMS[expected["path"]]
                current = read_stable(source_path, current_bytes, current_bytes)
                need(digest(current) == current_sha, "transform-current-identity")
                historical = transform(current)
                need(
                    len(historical) == expected["bytes"] and digest(historical) == expected["sha256"],
                    "transformed-historical-identity",
                )
                expected_files[relative] = write_bytes_at(member_descriptor, snapshot_name, historical)
                reconstruction = {
                    "kind": "unique-byte-transform",
                    "transform_id": transform_id,
                    "current_bytes": current_bytes,
                    "current_sha256": current_sha,
                }
                transformed.append({"ordinal": ordinal, "original": expected, **reconstruction})
            else:
                expected_files[relative] = copy_exact_at(source_path, member_descriptor, snapshot_name, expected)
                reconstruction = {"kind": "byte-for-byte-copy"}
            snapshot = output_reference(relative, expected_files[relative])
            need(snapshot["bytes"] == expected["bytes"] and snapshot["sha256"] == expected["sha256"], "snapshot-identity")
            manifest_members.append(
                {
                    "ordinal": ordinal,
                    "original": expected,
                    "snapshot": snapshot,
                    "reconstruction": reconstruction,
                }
            )
        need(member_names == sorted(member_names), "snapshot-member-order")

        owner_subset = []
        for owner_ordinal, (owner_member, plan_ordinal) in enumerate(zip(owner["members"], owner_ordinals, strict=True)):
            owner_subset.append(
                {
                    "owner_ordinal": owner_ordinal,
                    "plan_ordinal": plan_ordinal,
                    "original": owner_member,
                    "snapshot": manifest_members[plan_ordinal]["snapshot"],
                }
            )

        expected_files["RECONSTRUCTION-SOURCE.py"] = write_bytes_at(
            root_descriptor, "RECONSTRUCTION-SOURCE.py", executed_source["raw"]
        )
        manifest = {
            "schema": "kpb-historical-w1-source-closure-snapshot/v1",
            "classification": "HISTORICAL_RECONSTRUCTED_NONFINAL",
            "plan": output_reference("PLAN.json", expected_files["PLAN.json"]),
            "plan_identity_sha256": PLAN_IDENTITY,
            "source_members_identity_sha256": SOURCE_IDENTITY,
            "member_count": 81,
            "members": manifest_members,
            "owner_aux_source_closure": {
                "document": output_reference(
                    "OWNER-AUX-SOURCE-CLOSURE.json",
                    expected_files["OWNER-AUX-SOURCE-CLOSURE.json"],
                ),
                "members_identity_sha256": OWNER_MEMBERS_IDENTITY,
                "member_count": 37,
                "ordered_exact_plan_subset": True,
                "ordered_plan_ordinals": owner_ordinals,
                "members": owner_subset,
            },
            "reconstruction_generator": {
                "executed_source": {
                    "bytes": executed_source["bytes"],
                    "path": str(SEALED_GENERATOR),
                    "sha256": executed_source["sha256"],
                },
                "seal": generator_seal,
            },
            "non_authoritative_provenance": {
                "original_plan": {"path": str(PLAN), "bytes": PLAN_BYTES, "sha256": PLAN_SHA256},
                "original_owner_aux_source_closure": _selected_owner_closure_reference(plan),
            },
            "boundaries": {
                "current_source": False,
                "build_reproduced": False,
                "binary_reproduced": False,
                "authorization": False,
                "assignment_or_proof_generated": False,
                "setup_network_or_funds": False,
            },
        }
        manifest_raw = canonical(manifest)
        expected_files["MANIFEST.json"] = write_bytes_at(root_descriptor, "MANIFEST.json", manifest_raw)

        receipt = {
            "schema": "kpb-historical-w1-source-reconstruction/v1",
            "classification": "HISTORICAL_RECONSTRUCTED_NONFINAL",
            "manifest": output_reference("MANIFEST.json", expected_files["MANIFEST.json"]),
            "generator": output_reference(
                "RECONSTRUCTION-SOURCE.py", expected_files["RECONSTRUCTION-SOURCE.py"]
            ),
            "executed_generator_source": {
                "bytes": executed_source["bytes"],
                "path": str(SEALED_GENERATOR),
                "sha256": executed_source["sha256"],
            },
            "generator_seal": generator_seal,
            "sealed_plan": output_reference("PLAN.json", expected_files["PLAN.json"]),
            "sealed_owner_aux_source_closure": output_reference(
                "OWNER-AUX-SOURCE-CLOSURE.json",
                expected_files["OWNER-AUX-SOURCE-CLOSURE.json"],
            ),
            "transformed_members": transformed,
            "copied_members": 76,
            "all_plan_members_exact": True,
            "owner_aux_members_are_ordered_exact_plan_subset": True,
            "owner_aux_member_count": 37,
            "source_members_identity_sha256": SOURCE_IDENTITY,
            "owner_aux_members_identity_sha256": OWNER_MEMBERS_IDENTITY,
            "seal_controls": {
                "fresh_private_staging": True,
                "source_path_inode_size_mtime_ctime_stable": True,
                "files_mode_0400_owner_nlink1": True,
                "directories_mode_0500": True,
                "exact_tree_no_extra_members": True,
                "same_inode_full_rehash_before_and_after_publication": True,
                "fsync_files_and_directories_bottom_up": True,
                "atomic_rename_noreplace": True,
                "success_emitted_only_after_postpublication_validation": True,
                "partial_staging_retained_on_failure": True,
                "fixed_fd_interpreter_source_captured_and_rehashed": True,
                "private_mode_0700_publication_parent_rechecked": True,
            },
            "current_source": False,
            "build_reproduced": False,
            "binary_reproduced": False,
            "authorization": False,
            "assignment_or_proof_generated": False,
            "setup_network_or_funds": False,
        }
        receipt["receipt_identity_sha256"] = digest(canonical(receipt))
        expected_files["TRANSFORMATION-RECEIPT.json"] = write_bytes_at(
            root_descriptor, "TRANSFORMATION-RECEIPT.json", canonical(receipt)
        )

        os.fchmod(member_descriptor, 0o500)
        os.fsync(member_descriptor)
        member_state = _directory_state(os.fstat(member_descriptor))
        os.fchmod(root_descriptor, 0o500)
        os.fsync(root_descriptor)
        root_state = _directory_state(os.fstat(root_descriptor))
        need(stat.S_IMODE(root_state[2]) == 0o500 and stat.S_IMODE(member_state[2]) == 0o500, "sealed-directory-mode")

        validate_tree(
            parent,
            staging_name,
            root_descriptor,
            root_state,
            member_state,
            expected_files,
            member_names,
        )
        reverify_executed_source(executed_source)
        _verify_directory_path(PRIVATE_PARENT, parent, parent_state)
        os.fsync(member_descriptor)
        os.fsync(root_descriptor)
        need(_missing_at(parent, OUTPUT.name), "publication-target-created-during-build")
        _rename_noreplace(parent, staging_name, OUTPUT.name)
        published = True
        os.fsync(parent)
        parent_state = _directory_state(os.fstat(parent))
        _verify_directory_path(PRIVATE_PARENT, parent, parent_state)

        final_descriptor, final_opened = _open_directory_at(parent, OUTPUT.name)
        try:
            need(_directory_identity(final_opened) == root_state[:6], "publication-inode-changed")
            root_state = _directory_state(final_opened)
            validate_tree(
                parent,
                OUTPUT.name,
                final_descriptor,
                root_state,
                member_state,
                expected_files,
                member_names,
            )
            os.fsync(final_descriptor)
        finally:
            os.close(final_descriptor)
        reverify_executed_source(executed_source)
        _verify_directory_path(PRIVATE_PARENT, parent, parent_state)
        os.fsync(parent)
        _INCOMPLETE_STAGING = None
        print(
            json.dumps(
                {
                    "status": "HISTORICAL_RECONSTRUCTED_NONFINAL_SEALED",
                    "root": str(OUTPUT),
                    "manifest": output_reference("MANIFEST.json", expected_files["MANIFEST.json"]),
                    "receipt": output_reference(
                        "TRANSFORMATION-RECEIPT.json",
                        expected_files["TRANSFORMATION-RECEIPT.json"],
                    ),
                    "members": 81,
                    "owner_aux_members": 37,
                    "transformed": 5,
                    "authorization": False,
                },
                sort_keys=True,
            )
        )
    except BaseException:
        if published and root_state is not None:
            _quarantine_publication(parent, OUTPUT.name, root_state)
        raise
    finally:
        if member_descriptor is not None:
            os.close(member_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        os.close(parent)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        print(
            json.dumps(
                {
                    "status": "HISTORICAL_RECONSTRUCTION_REFUSED",
                    "category": str(error) if isinstance(error, Refused) else type(error).__name__,
                    "incomplete_staging": str(_INCOMPLETE_STAGING) if _INCOMPLETE_STAGING else None,
                    "quarantined_publication": (
                        str(_QUARANTINED_PUBLICATION) if _QUARANTINED_PUBLICATION else None
                    ),
                    "final_output_absent": not os.path.lexists(OUTPUT),
                },
                sort_keys=True,
            )
        )
        raise SystemExit(1)
