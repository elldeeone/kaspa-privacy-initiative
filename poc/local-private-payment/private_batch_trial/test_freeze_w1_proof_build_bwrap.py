#!/usr/bin/env python3
"""Source-only hostile controls for the inert bwrap W1 build freezer."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock


sys.dont_write_bytecode = True
SHA = "a" * 64
SOURCE = Path(__file__).with_name("freeze_w1_proof_build_bwrap.py")
SPEC = importlib.util.spec_from_file_location("freeze_w1_proof_build_bwrap", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load bwrap freezer source")
target = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = target
SPEC.loader.exec_module(target)
SYNTHETIC_RUNTIME_BINDINGS = tuple(
    sorted(
        [(path, path) for path in target.BWRAP_RUNTIME_FILES]
        + [
            (
                target.BWRAP_INTERPRETER_RESOLVED,
                target.BWRAP_INTERPRETER_LITERAL,
            )
        ],
        key=lambda row: row[1],
    )
)
SYNTHETIC_RUNTIME_SHA256 = {
    destination: SHA for _, destination in SYNTHETIC_RUNTIME_BINDINGS
}
SYNTHETIC_CACHE_ROUTES = {
    "/usr/lib/x86_64-linux-gnu/libc.so.6": {
        "device": 1,
        "inode": 2,
        "mode_octal": "0644",
        "symlink_target": None,
        "resolved": "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "sha256": SHA,
    }
}


def frame_for(
    payloads: list[bytes] | None = None,
    *,
    names: list[str] | None = None,
    hashes: list[str] | None = None,
    modes: list[str] | None = None,
) -> bytes:
    payloads = payloads or [b"\x7fELF-prover", b"\x7fELF-verifier", b"p.d\n", b"v.d\n"]
    names = names or ["prover", "verifier", "prover_dep_info", "verifier_dep_info"]
    hashes = hashes or [hashlib.sha256(raw).hexdigest() for raw in payloads]
    modes = modes or ["0500", "0500", "0400", "0400"]
    entries = [
        {
            "name": name,
            "bytes": len(raw),
            "sha256": digest,
            "mode_octal": mode,
        }
        for name, raw, digest, mode in zip(names, payloads, hashes, modes, strict=True)
    ]
    header = {
        "schema": target.FRAME_SCHEMA,
        "entries": entries,
        "cargo_command": target.expected_cargo_command(),
        "proof_executed": False,
        "verifier_executed": False,
        "setup_or_pk_read": False,
        "network_communication": False,
        "authorization": False,
    }
    header_raw = target.canonical(header)
    return b"".join(
        [
            target.FRAME_MAGIC,
            struct.pack(">Q", len(header_raw)),
            header_raw,
            *(struct.pack(">Q", len(raw)) for raw in payloads),
            *payloads,
        ]
    )


def outer_command() -> tuple[list[str], tuple[int, ...]]:
    descriptors = tuple(range(10, 21))
    command = target.outer_bwrap_command(
        bwrap_fd=10,
        repo_fd=11,
        registry_fd=12,
        toolchain_fd=13,
        outer_source_fd=14,
        local_manifest_fd=15,
        vendor_manifest_fd=16,
        toolchain_manifest_fd=17,
        seccomp_fd=18,
        status_fd=19,
        launch_block_fd=20,
        local_sha=SHA,
        vendor_sha=SHA,
        toolchain_sha=SHA,
        bwrap_sha=SHA,
        runtime_bindings=SYNTHETIC_RUNTIME_BINDINGS,
    )
    return command, descriptors


def live_outer_resources(root: Path) -> dict[str, object]:
    repo = root / "repo"
    registry = root / "registry"
    toolchain = root / "toolchain"
    for directory in (repo, registry, toolchain):
        directory.mkdir()
    fake_bwrap = root / "reviewed-bwrap"
    fake_bwrap.write_bytes(b"reviewed-fixed-bwrap-elf")
    bwrap_fd = os.open(fake_bwrap, os.O_RDONLY | os.O_CLOEXEC)
    repo_fd = target.open_directory_fd(repo)
    registry_fd = target.open_directory_fd(registry)
    toolchain_fd = target.open_directory_fd(toolchain)
    sealed_raw = {
        "outer_source": b"outer-source",
        "local_manifest": b"local-manifest",
        "vendor_manifest": b"vendor-manifest",
        "toolchain_manifest": b"toolchain-manifest",
        "seccomp": b"seccomp",
    }
    sealed = {
        name: target.sealed_memfd(f"test-{name}", raw)
        for name, raw in sealed_raw.items()
    }
    status_read, status_write = os.pipe2(os.O_CLOEXEC)
    launch_block_read, launch_block_write = os.pipe2(os.O_CLOEXEC)
    passed = (
        bwrap_fd,
        repo_fd,
        registry_fd,
        toolchain_fd,
        sealed["outer_source"],
        sealed["local_manifest"],
        sealed["vendor_manifest"],
        sealed["toolchain_manifest"],
        sealed["seccomp"],
        status_write,
        launch_block_read,
    )
    bwrap_value = os.fstat(bwrap_fd)
    bwrap_sha = hashlib.sha256(fake_bwrap.read_bytes()).hexdigest()
    bwrap_identity = {
        "bytes": bwrap_value.st_size,
        "sha256": bwrap_sha,
        "device": bwrap_value.st_dev,
        "inode": bwrap_value.st_ino,
        "mtime_ns": bwrap_value.st_mtime_ns,
        "ctime_ns": bwrap_value.st_ctime_ns,
    }
    contract = target.outer_launch_contract(
        bwrap_identity=bwrap_identity,
        local_sha=SHA,
        vendor_sha=SHA,
        toolchain_sha=SHA,
        bwrap_sha=bwrap_sha,
        outer_source_sha=hashlib.sha256(sealed_raw["outer_source"]).hexdigest(),
        local_manifest_sha=hashlib.sha256(sealed_raw["local_manifest"]).hexdigest(),
        vendor_manifest_sha=hashlib.sha256(sealed_raw["vendor_manifest"]).hexdigest(),
        toolchain_manifest_sha=hashlib.sha256(
            sealed_raw["toolchain_manifest"]
        ).hexdigest(),
        seccomp_sha=hashlib.sha256(sealed_raw["seccomp"]).hexdigest(),
        runtime_bindings=SYNTHETIC_RUNTIME_BINDINGS,
        apparmor_profile_name="bwrap",
    )
    command = target.outer_bwrap_command(
        bwrap_fd=bwrap_fd,
        repo_fd=repo_fd,
        registry_fd=registry_fd,
        toolchain_fd=toolchain_fd,
        outer_source_fd=sealed["outer_source"],
        local_manifest_fd=sealed["local_manifest"],
        vendor_manifest_fd=sealed["vendor_manifest"],
        toolchain_manifest_fd=sealed["toolchain_manifest"],
        seccomp_fd=sealed["seccomp"],
        status_fd=status_write,
        launch_block_fd=launch_block_read,
        local_sha=SHA,
        vendor_sha=SHA,
        toolchain_sha=SHA,
        bwrap_sha=bwrap_sha,
        runtime_bindings=SYNTHETIC_RUNTIME_BINDINGS,
    )
    return {
        "repo": repo,
        "registry": registry,
        "toolchain": toolchain,
        "command": command,
        "passed": passed,
        "contract": contract,
        "status_read": status_read,
        "status_write": status_write,
        "launch_block_read": launch_block_read,
        "launch_block_write": launch_block_write,
        "all_fds": (*passed, status_read, launch_block_write),
    }


def synthetic_dynamic_elf(*, loader_extension: bool = False) -> tuple[bytes, str]:
    base = 0x400000
    program_offset = 64
    program_count = 4
    cursor = program_offset + program_count * 56
    interpreter = b"/lib64/ld-linux-x86-64.so.2\x00"
    interpreter_offset = cursor
    cursor += len(interpreter)
    cursor = (cursor + 3) & ~3
    build_id = bytes(range(1, 21))
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\x00" + build_id
    note_offset = cursor
    cursor += len(note)
    cursor = (cursor + 7) & ~7
    strings = b"\x00libc.so.6\x00/review-rpath\x00/review-runpath\x00"
    needed_index = strings.index(b"libc.so.6")
    rpath_index = strings.index(b"/review-rpath")
    runpath_index = strings.index(b"/review-runpath")
    strings_offset = cursor
    cursor += len(strings)
    cursor = (cursor + 7) & ~7
    dynamic_rows = [
        (5, base + strings_offset),
        (10, len(strings)),
        (1, needed_index),
        (15, rpath_index),
        (29, runpath_index),
    ]
    if loader_extension:
        dynamic_rows.append((0x6FFFFEFC, rpath_index))
    dynamic_rows.append((0, 0))
    dynamic = b"".join(
        struct.pack("<qQ", tag, value)
        for tag, value in dynamic_rows
    )
    dynamic_offset = cursor
    cursor += len(dynamic)
    raw = bytearray(cursor)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        raw,
        0,
        ident,
        3,
        62,
        1,
        0,
        program_offset,
        0,
        0,
        64,
        56,
        program_count,
        0,
        0,
        0,
    )
    programs = (
        (1, 5, 0, base, 0, len(raw), len(raw), 0x1000),
        (
            3,
            4,
            interpreter_offset,
            base + interpreter_offset,
            0,
            len(interpreter),
            len(interpreter),
            1,
        ),
        (4, 4, note_offset, base + note_offset, 0, len(note), len(note), 4),
        (
            2,
            6,
            dynamic_offset,
            base + dynamic_offset,
            0,
            len(dynamic),
            len(dynamic),
            8,
        ),
    )
    for index, program in enumerate(programs):
        struct.pack_into("<IIQQQQQQ", raw, program_offset + index * 56, *program)
    raw[interpreter_offset : interpreter_offset + len(interpreter)] = interpreter
    raw[note_offset : note_offset + len(note)] = note
    raw[strings_offset : strings_offset + len(strings)] = strings
    raw[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    return bytes(raw), build_id.hex()


def synthetic_deb(bwrap_raw: bytes) -> tuple[bytes, bytes]:
    control_raw = b"Package: bubblewrap\nVersion: 0.12.0-1\nArchitecture: amd64\n\n"

    def tar_with(name: str, value: bytes) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            member = tarfile.TarInfo(name)
            member.size = len(value)
            member.mode = 0o755 if name.endswith("bwrap") else 0o644
            member.mtime = 0
            archive.addfile(member, io.BytesIO(value))
        return output.getvalue()

    members = (
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", tar_with("./control", control_raw)),
        ("data.tar.gz", tar_with("./usr/bin/bwrap", bwrap_raw)),
    )
    result = bytearray(b"!<arch>\n")
    for name, value in members:
        header = (
            f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{len(value):<10}`\n"
        ).encode("ascii")
        if len(header) != 60:
            raise AssertionError("bad synthetic ar header")
        result.extend(header)
        result.extend(value)
        if len(value) & 1:
            result.extend(b"\n")
    return bytes(result), control_raw


class InertEntryTests(unittest.TestCase):
    def test_default_entry_is_stop_before_every_side_effect(self) -> None:
        output = io.BytesIO()
        fake_stdout = types.SimpleNamespace(buffer=output)
        forbidden = AssertionError("inert gate crossed")
        with (
            mock.patch.object(target, "local_source_manifest", side_effect=forbidden),
            mock.patch.object(target, "sealed_memfd", side_effect=forbidden),
            mock.patch.object(target.os, "mkdir", side_effect=forbidden),
            mock.patch.object(target.subprocess, "Popen", side_effect=forbidden),
            mock.patch.object(target.subprocess, "run", side_effect=forbidden),
            mock.patch.object(target.sys, "stdout", fake_stdout),
        ):
            self.assertEqual(target.main([]), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "STOP")
        self.assertFalse(result["review_gates_bound"])
        self.assertFalse(result["real_build_executed"])
        self.assertFalse(result["proof_executed"])

    def test_run_freeze_rejects_unbound_gate_before_tree_or_process(self) -> None:
        forbidden = AssertionError("unbound gate crossed")
        with (
            mock.patch.object(target, "validate_fixed_boundaries", side_effect=forbidden),
            mock.patch.object(target, "local_source_manifest", side_effect=forbidden),
            mock.patch.object(target, "sealed_memfd", side_effect=forbidden),
            mock.patch.object(target.subprocess, "Popen", side_effect=forbidden),
            self.assertRaisesRegex(target.Refused, "local-source-review-not-bound"),
        ):
            target.run_freeze({})

    def test_all_authority_gates_are_checked_in_unbound(self) -> None:
        self.assertIsNone(target.REVIEWED_LOCAL_SOURCE_TREE_SHA256)
        self.assertIsNone(target.REVIEWED_LOCAL_SOURCE_FILES_SHA256)
        self.assertIsNone(target.REVIEWED_VENDOR_TREE_SHA256)
        self.assertIsNone(target.REVIEWED_TOOLCHAIN_TREE_SHA256)
        self.assertIsNone(target.REVIEWED_ROOT_RUNTIME_SHA256)
        self.assertIsNone(target.REVIEWED_LEAF_TOOL_SHA256)
        self.assertIsNone(target.REVIEWED_BWRAP_VERSION)
        self.assertIsNone(target.REVIEWED_BWRAP_APPARMOR_EXEC_PATH)
        self.assertIsNone(target.REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256)
        self.assertIsNone(target.REVIEWED_BWRAP_APPARMOR_POLICY)
        self.assertIsNone(target.REVIEWED_BWRAP_PROVENANCE)
        self.assertIsNone(target.REVIEWED_BWRAP_ELF_CLOSURE)


class StageZeroTests(unittest.TestCase):
    def test_rendered_stage0_is_external_inert_and_exactly_bound(self) -> None:
        rendered = target.render_external_stage0()
        contract = rendered["contract"]
        unsigned = dict(contract)
        claimed = unsigned.pop("contract_sha256")
        self.assertEqual(claimed, target.sha256_bytes(target.canonical(unsigned)))
        self.assertEqual(rendered["contract_sha256"], claimed)
        self.assertEqual(
            rendered["contract_bytes_sha256"],
            target.sha256_bytes(target.canonical(contract)),
        )
        self.assertFalse(rendered["executed"])
        self.assertFalse(rendered["authorization"])
        command = rendered["command"]
        self.assertEqual(command[:2], [str(target.ENV), "-i"])
        self.assertIn("-I", command)
        self.assertIn("-B", command)
        self.assertIn("-S", command)

    def test_external_bootstrap_seals_detached_source_and_contract(self) -> None:
        source = target.EXTERNAL_STAGE0_SOURCE
        for required in (
            "os.O_NOFOLLOW",
            "os.MFD_ALLOW_SEALING",
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "os.dup2(source_fd,3)",
            "os.dup2(contract_fd,4)",
            '"/proc/self/fd/3"',
            '"-I","-B"',
            '"-B","-S"',
            "dict(os.environ)==ENV",
        ):
            self.assertIn(required, source)
        self.assertNotIn("subprocess", source)

    def test_stage0_contract_validation_accepts_detached_mocked_fds(self) -> None:
        source_raw = SOURCE.read_bytes()
        source_identity = {
            "bytes": len(source_raw),
            "device": 101,
            "inode": 202,
            "mtime_ns": 303,
            "ctime_ns": 404,
        }
        contract = target.external_stage0_contract(
            source_identity, target.sha256_bytes(source_raw)
        )
        contract_raw = target.canonical(contract)
        real_fstat = os.fstat

        def fake_fstat(descriptor: int):
            if descriptor == 3:
                return types.SimpleNamespace(st_dev=999, st_ino=998)
            if descriptor == 4:
                return types.SimpleNamespace(st_dev=997, st_ino=996)
            return real_fstat(descriptor)

        def fake_read(descriptor: int, expected_sha256: str | None = None) -> bytes:
            self.assertIsNone(expected_sha256)
            return source_raw if descriptor == 3 else contract_raw

        with (
            mock.patch.dict(target.os.environ, target.STAGE0_ENVIRONMENT, clear=True),
            mock.patch.object(
                target.sys,
                "flags",
                types.SimpleNamespace(
                    isolated=1,
                    dont_write_bytecode=1,
                    no_site=1,
                    safe_path=True,
                ),
            ),
            mock.patch.object(target, "read_sealed_fd", side_effect=fake_read),
            mock.patch.object(target.os, "fstat", side_effect=fake_fstat),
            mock.patch.object(target.os, "listdir", return_value=["0", "1", "2", "3", "4"]),
        ):
            observed = target.validate_stage0_entry(contract["contract_sha256"])
        self.assertEqual(observed, contract)

    def test_source_has_no_repository_import_or_ambient_bytecode_path(self) -> None:
        raw = SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(raw)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        expected_stdlib = {
            "__future__", "base64", "ctypes", "datetime", "errno", "fcntl",
            "hashlib", "io", "json", "os", "pathlib", "re", "resource", "selectors",
            "shutil", "signal", "stat", "struct", "subprocess", "sys",
            "tarfile", "time", "tomllib", "uuid",
        }
        self.assertEqual(imported, expected_stdlib)
        self.assertNotIn("sys.path.append", raw)
        self.assertNotIn("sys.path.insert", raw)
        self.assertEqual(target.STAGE0_ENVIRONMENT["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertIn('"-I","-B"', target.EXTERNAL_STAGE0_SOURCE)
        self.assertIn('"-B","-S"', target.EXTERNAL_STAGE0_SOURCE)


class ReviewGateAndCommandTests(unittest.TestCase):
    def test_bwrap_authority_requires_future_fixed_bytes_at_apparmor_path(self) -> None:
        self.assertEqual(str(target.BWRAP), "/usr/bin/bwrap")
        self.assertEqual(target.MINIMUM_BWRAP_VERSION, (0, 12, 0))
        self.assertEqual(target.bwrap_version_tuple("0.12.0"), (0, 12, 0))
        self.assertGreater(target.bwrap_version_tuple("0.13.1"), target.MINIMUM_BWRAP_VERSION)
        self.assertIsNone(target.bwrap_version_tuple("0.12"))

    def test_gate_shapes_require_exact_runtime_closure_and_apparmor_path(self) -> None:
        leaf = {name: SHA for name in target.LEAF_TOOLS}
        runtime = {path: SHA for path in target.BWRAP_RUNTIME_FILES}
        provenance = {
            "schema": "kpb-reviewed-bwrap-provenance/v3",
            "distribution": "Debian",
            "suite": "sid",
            "architecture": "amd64",
            "package": "bubblewrap",
            "package_version": "0.12.0-1",
            "package_filename": "bubblewrap_0.12.0-1_amd64.deb",
            "deb_path": "/var/lib/kpb-reviewed-bwrap/bubblewrap_0.12.0-1_amd64.deb",
            "runtime_version": "0.12.0",
            "deb_sha256": "b" * 64,
            "deb_control_sha256": "9" * 64,
            "elf_sha256": SHA,
            "elf_build_id": "c" * 16,
            "upstream_tag": "v0.12.0",
            "upstream_tag_object": "f" * 40,
            "upstream_commit": "d" * 40,
            "upstream_signature_verified": True,
            "upstream_verification_path": (
                "/var/lib/kpb-reviewed-bwrap/upstream-v0.12.0.json"
            ),
            "upstream_verification_sha256": "8" * 64,
        }
        runtime_objects = set(target.BWRAP_RUNTIME_FILES) - {"/etc/ld.so.cache"}
        interpreter_resolved = next(
            path for path in runtime_objects if "ld-linux" in path
        )
        sonames = {
            path: (
                "ld-linux-x86-64.so.2" if "ld-linux" in path
                else "libcap.so.2" if "libcap.so" in path
                else "libpcre2-8.so.0" if "libpcre2-8.so" in path
                else Path(path).name
            )
            for path in runtime_objects
        }
        needed_paths = {
            sonames[path]: path
            for path in sorted(runtime_objects - {interpreter_resolved})
        }
        objects = {
            path: {
                "sha256": SHA,
                "build_id": "c" * 16,
                "elf_type": 3,
                "machine": 62,
                "interpreter": None,
                "soname": sonames[path],
                "needed": [],
                "needed_paths": {},
                "rpath": [],
                "runpath": [],
            }
            for path in runtime_objects
        }
        for path in runtime_objects:
            if Path(path).name in {"libc.so.6", "libcap.so.2.75"}:
                objects[path]["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
        objects[str(target.BWRAP)] = {
            "sha256": SHA,
            "build_id": "c" * 16,
            "elf_type": 3,
            "machine": 62,
            "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "soname": None,
            "needed": list(needed_paths),
            "needed_paths": needed_paths,
            "rpath": [],
            "runpath": [],
        }
        elf_closure = {
            "schema": "kpb-reviewed-bwrap-elf-closure/v1",
            "executable": str(target.BWRAP),
            "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "interpreter_resolved": interpreter_resolved,
            "ld_so_cache": "/etc/ld.so.cache",
            "objects": objects,
        }
        apparmor_policy = {
            "schema": "kpb-reviewed-bwrap-apparmor-policy/v1",
            "executable": str(target.BWRAP),
            "profile_name": str(target.BWRAP),
            "mode": "enforce",
            "source_sha256": {str(target.APPARMOR_PROFILE_SOURCE): "e" * 64},
            "include_directories": {},
            "optional_absent": [],
        }
        valid = {
            "REVIEWED_LOCAL_SOURCE_TREE_SHA256": SHA,
            "REVIEWED_LOCAL_SOURCE_FILES_SHA256": {
                f"{target.RELATION_RELATIVE}/Cargo.toml": SHA,
            },
            "REVIEWED_VENDOR_TREE_SHA256": SHA,
            "REVIEWED_TOOLCHAIN_TREE_SHA256": SHA,
            "REVIEWED_LEAF_TOOL_SHA256": leaf,
            "REVIEWED_ROOT_RUNTIME_SHA256": runtime,
            "REVIEWED_BWRAP_VERSION": "0.12.0",
            "REVIEWED_BWRAP_APPARMOR_EXEC_PATH": str(target.BWRAP),
            "REVIEWED_BWRAP_APPARMOR_PROFILE_SHA256": "e" * 64,
            "REVIEWED_BWRAP_APPARMOR_POLICY": apparmor_policy,
            "REVIEWED_BWRAP_PROVENANCE": provenance,
            "REVIEWED_BWRAP_ELF_CLOSURE": elf_closure,
        }
        with mock.patch.multiple(target, **valid):
            target.require_gate_shapes()
            with (
                mock.patch.object(
                    target,
                    "REVIEWED_ROOT_RUNTIME_SHA256",
                    {next(iter(runtime)): SHA},
                ),
                self.assertRaisesRegex(target.Refused, "root-runtime-review-not-bound"),
            ):
                target.require_gate_shapes()
            self.assertEqual(
                target.exact_nested_runtime_bindings(objects),
                SYNTHETIC_RUNTIME_BINDINGS,
            )
            shared_with_interpreter = next(
                path
                for path, row in objects.items()
                if path != str(target.BWRAP) and row["interpreter"] is not None
            )
            bad_interpreter_objects = dict(objects)
            bad_interpreter_objects[shared_with_interpreter] = (
                objects[shared_with_interpreter]
                | {"interpreter": "/unreviewed/ld.so"}
            )
            self.assertFalse(
                target.valid_elf_closure_shape(
                    elf_closure | {"objects": bad_interpreter_objects}, SHA
                )
            )
            hwcap_path = (
                "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/"
                "x86-64-v3/libc.so.6"
            )
            with self.assertRaisesRegex(
                target.Refused, "nested-runtime-object-path"
            ):
                target.exact_nested_runtime_bindings(
                    objects | {hwcap_path: objects[interpreter_resolved]}
                )
            alternate_bindings = list(SYNTHETIC_RUNTIME_BINDINGS)
            alternate_bindings[-1] = (
                "/usr/lib/x86_64-linux-gnu/reviewer-alternate.so",
                "/usr/lib/x86_64-linux-gnu/reviewer-alternate.so",
            )
            self.assertFalse(
                target.valid_nested_runtime_bindings(
                    tuple(sorted(alternate_bindings, key=lambda row: row[1]))
                )
            )
            with (
                mock.patch.object(target, "REVIEWED_BWRAP_VERSION", "0.11.9"),
                self.assertRaisesRegex(target.Refused, "bwrap-version-review-not-bound"),
            ):
                target.require_gate_shapes()
            with (
                mock.patch.object(target, "REVIEWED_BWRAP_APPARMOR_EXEC_PATH", "/tmp/bwrap"),
                self.assertRaisesRegex(target.Refused, "bwrap-apparmor-path-review-not-bound"),
            ):
                target.require_gate_shapes()
            bad_tag = provenance | {"upstream_tag": "v0.13.1"}
            with (
                mock.patch.object(target, "REVIEWED_BWRAP_PROVENANCE", bad_tag),
                self.assertRaisesRegex(target.Refused, "bwrap-provenance-review-not-bound"),
            ):
                target.require_gate_shapes()
            first_needed = next(iter(needed_paths))
            bad_objects = dict(objects)
            bad_objects[str(target.BWRAP)] = objects[str(target.BWRAP)] | {
                "needed_paths": needed_paths | {first_needed: interpreter_resolved}
            }
            with (
                mock.patch.object(
                    target,
                    "REVIEWED_BWRAP_ELF_CLOSURE",
                    elf_closure | {"objects": bad_objects},
                ),
                self.assertRaisesRegex(
                    target.Refused, "bwrap-elf-closure-review-not-bound"
                ),
            ):
                target.require_gate_shapes()

    def test_local_source_manifest_refuses_every_file_outside_finite_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source_root = root / "reviewed-source"
            source_root.mkdir()
            reviewed = source_root / "Cargo.toml"
            reviewed.write_text("[package]\nname='reviewed'\n", encoding="utf-8")
            relative = "reviewed-source/Cargo.toml"
            allowlist = {relative: hashlib.sha256(reviewed.read_bytes()).hexdigest()}
            with mock.patch.multiple(
                target,
                REPO_ROOT=root,
                LOCAL_SOURCE_ROOTS=("reviewed-source",),
                REVIEWED_LOCAL_SOURCE_FILES_SHA256=allowlist,
            ):
                manifest = target.local_source_manifest()
                self.assertEqual(
                    manifest["finite_reviewed_file_allowlist"], [relative]
                )
                (source_root / ".untracked-secret").write_text(
                    "must not be copied", encoding="utf-8"
                )
                with (
                    mock.patch.object(
                        target,
                        "stable_file",
                        side_effect=AssertionError("no file content may be opened"),
                    ) as stable,
                    self.assertRaisesRegex(
                        target.Refused, "local-source-unreviewed-extra-or-drift"
                    ),
                ):
                    target.local_source_manifest()
                stable.assert_not_called()

                def denied_walk(*_: object, **keywords: object):
                    keywords["onerror"](PermissionError("denied child"))
                    return iter(())

                with (
                    mock.patch.object(target.os, "walk", side_effect=denied_walk),
                    self.assertRaisesRegex(target.Refused, "tree-walk-error"),
                ):
                    target.local_source_manifest()

    def test_elf_parser_binds_interpreter_needed_paths_and_build_id(self) -> None:
        raw, build_id = synthetic_dynamic_elf()
        observed = target.parse_elf_dynamic_identity(raw)
        self.assertEqual(observed["machine"], 62)
        self.assertEqual(observed["build_id"], build_id)
        self.assertEqual(observed["interpreter"], "/lib64/ld-linux-x86-64.so.2")
        self.assertIsNone(observed["soname"])
        self.assertEqual(observed["needed"], ["libc.so.6"])
        self.assertEqual(observed["rpath"], ["/review-rpath"])
        self.assertEqual(observed["runpath"], ["/review-runpath"])
        wrong_arch = bytearray(raw)
        struct.pack_into("<H", wrong_arch, 18, 3)
        with self.assertRaisesRegex(target.Refused, "elf-architecture"):
            target.parse_elf_dynamic_identity(bytes(wrong_arch))
        extension_raw, _ = synthetic_dynamic_elf(loader_extension=True)
        with self.assertRaisesRegex(target.Refused, "elf-loader-extension"):
            target.parse_elf_dynamic_identity(extension_raw)

        soname = b"libreviewed.so.1\x00"
        library_path = b"/usr/lib/libreviewed.so.1\x00"
        strings = soname + library_path
        strings += b"\x00" * (-(48 + 24 + len(strings)) % 4)
        cache = bytearray(48 + 24 + len(strings))
        cache[:20] = b"glibc-ld.so.cache1.1"
        struct.pack_into("<II", cache, 20, 1, len(strings))
        cache[28] = target.LD_SO_CACHE_ENDIAN_LITTLE
        struct.pack_into(
            "<iIIIQ",
            cache,
            48,
            target.LD_SO_CACHE_X86_64_FLAGS,
            72,
            72 + len(soname),
            0,
            0,
        )
        cache[72:] = strings
        self.assertEqual(
            target.parse_ld_so_cache_x86_64(bytes(cache)),
            {"libreviewed.so.1": ["/usr/lib/libreviewed.so.1"]},
        )
        self.assertTrue(
            target.cache_candidate_has_exact_parent(
                "/usr/lib/x86_64-linux-gnu/libcap.so.2",
                "/usr/lib/x86_64-linux-gnu/libcap.so.2.75",
            )
        )
        self.assertFalse(
            target.cache_candidate_has_exact_parent(
                "/lib/x86_64-linux-gnu/libc.so.6",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
            )
        )
        self.assertTrue(
            target.cache_candidate_route_is_direct(
                "/usr/lib/x86_64-linux-gnu/libcap.so.2",
                "/usr/lib/x86_64-linux-gnu/libcap.so.2.75",
                "libcap.so.2.75",
            )
        )
        for unsafe_target in (
            "/lib/x86_64-linux-gnu/libcap.so.2.75",
            "../libcap.so.2.75",
            "libcap-intermediate.so",
        ):
            with self.subTest(unsafe_target=unsafe_target):
                self.assertFalse(
                    target.cache_candidate_route_is_direct(
                        "/usr/lib/x86_64-linux-gnu/libcap.so.2",
                        "/usr/lib/x86_64-linux-gnu/libcap.so.2.75",
                        unsafe_target,
                    )
                )
        with self.assertRaisesRegex(target.Refused, "ld-cache-trailing-bytes"):
            target.parse_ld_so_cache_x86_64(bytes(cache) + b"unowned")
        wrong_endian = bytearray(cache)
        wrong_endian[28] = 3
        with self.assertRaisesRegex(target.Refused, "ld-cache-header-flags"):
            target.parse_ld_so_cache_x86_64(bytes(wrong_endian))

        extension_offset = len(cache)
        extension_data = b"reviewed-generator"
        extension = bytearray(8 + 16 + len(extension_data))
        struct.pack_into(
            "<II", extension, 0, target.LD_SO_CACHE_EXTENSION_MAGIC, 1
        )
        struct.pack_into(
            "<IIII",
            extension,
            8,
            target.LD_SO_CACHE_EXTENSION_GENERATOR,
            0,
            extension_offset + 24,
            len(extension_data),
        )
        extension[24:] = extension_data
        with_extension = bytearray(cache + extension)
        struct.pack_into("<I", with_extension, 32, extension_offset)
        self.assertEqual(
            target.parse_ld_so_cache_x86_64(bytes(with_extension)),
            {"libreviewed.so.1": ["/usr/lib/libreviewed.so.1"]},
        )
        struct.pack_into("<I", with_extension, extension_offset + 8, 1)
        with self.assertRaisesRegex(
            target.Refused, "ld-cache-loader-affecting-extension"
        ):
            target.parse_ld_so_cache_x86_64(bytes(with_extension))
        struct.pack_into(
            "<II", with_extension, extension_offset + 8,
            target.LD_SO_CACHE_EXTENSION_GENERATOR, 1,
        )
        with self.assertRaisesRegex(
            target.Refused, "ld-cache-loader-affecting-extension"
        ):
            target.parse_ld_so_cache_x86_64(bytes(with_extension))
        struct.pack_into("<I", with_extension, extension_offset + 12, 0)
        struct.pack_into(
            "<I", with_extension, extension_offset + 16, extension_offset + 25
        )
        with self.assertRaisesRegex(target.Refused, "ld-cache-extension-bounds"):
            target.parse_ld_so_cache_x86_64(bytes(with_extension))

    def test_provenance_evidence_binds_deb_payload_and_tag_commit_relationships(self) -> None:
        bwrap_raw = b"\x7fELF-reviewed-bwrap"
        deb_raw, control_raw = synthetic_deb(bwrap_raw)
        deb = target.parse_reviewed_bwrap_deb(deb_raw)
        provenance = {
            "package": "bubblewrap",
            "package_version": "0.12.0-1",
            "architecture": "amd64",
            "deb_control_sha256": hashlib.sha256(control_raw).hexdigest(),
            "elf_sha256": hashlib.sha256(bwrap_raw).hexdigest(),
            "upstream_tag": "v0.12.0",
            "upstream_tag_object": "a" * 40,
            "upstream_commit": "b" * 40,
            "upstream_signature_verified": True,
        }
        target.validate_deb_provenance_relationship(deb, provenance)
        with self.assertRaisesRegex(target.Refused, "bwrap-deb-relationship"):
            target.validate_deb_provenance_relationship(
                deb, provenance | {"elf_sha256": "0" * 64}
            )

        upstream = {
            "schema": "kpb-bwrap-upstream-verification-evidence/v1",
            "repository": "containers/bubblewrap",
            "tag": provenance["upstream_tag"],
            "tag_object": provenance["upstream_tag_object"],
            "commit": provenance["upstream_commit"],
            "signature_verified": True,
            "signature_status": "valid",
        }
        upstream_raw = target.canonical(upstream)
        self.assertEqual(
            target.parse_upstream_verification_evidence(upstream_raw, provenance),
            upstream,
        )
        with self.assertRaisesRegex(
            target.Refused, "bwrap-upstream-evidence-relationship"
        ):
            target.parse_upstream_verification_evidence(
                upstream_raw, provenance | {"upstream_commit": "c" * 40}
            )

    def test_apparmor_gate_closes_sources_without_global_profile_table(self) -> None:
        profile = target.APPARMOR_PROFILE_SOURCE
        included = Path("/etc/apparmor.d/tunables/reviewed-global")
        abi = Path("/etc/apparmor.d/abi/reviewed")
        include_directory = Path("/etc/apparmor.d/tunables/reviewed.d")
        directory_child = include_directory / "site"
        source_raw = {
            str(profile): (
                b"abi\t<abi/reviewed>,\n"
                b"include <tunables/reviewed-global>\n"
                b"include if exists <tunables/reviewed.d>\n"
                b"profile /usr/bin/bwrap /usr/bin/bwrap flags=(mediate_deleted) {\n}\n"
            ),
            str(included): b"# exact reviewed include\n",
            str(abi): b"# exact reviewed ABI\n",
            str(directory_child): b"# exact reviewed directory member\n",
        }
        source_sha = {
            path: hashlib.sha256(raw).hexdigest() for path, raw in source_raw.items()
        }
        policy = {
            "schema": "kpb-reviewed-bwrap-apparmor-policy/v1",
            "executable": str(target.BWRAP),
            "profile_name": str(target.BWRAP),
            "mode": "enforce",
            "source_sha256": source_sha,
            "include_directories": {str(include_directory): ["site"]},
            "optional_absent": [],
        }

        def stable(path: Path, *, owner_uid: int | None = None, **_: object):
            raw = source_raw[str(path)]
            return raw, {
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mode_octal": "0644",
            }

        with (
            mock.patch.object(target, "REVIEWED_BWRAP_APPARMOR_POLICY", policy),
            mock.patch.object(target, "stable_file", side_effect=stable),
            mock.patch.object(
                target,
                "inspect_apparmor_include_directory",
                return_value=(
                    [directory_child],
                    {"mode_octal": "0755", "entries": ["site"]},
                ),
            ),
        ):
            observed = target.validate_apparmor_policy()
            self.assertEqual(set(observed["source_closure"]), set(source_raw))
            self.assertFalse(observed["loaded_policy_byte_identity_authenticated"])
            self.assertFalse(observed["loaded_profile_table_preflight_used"])
            self.assertTrue(observed["live_exec_label_required"])
            with self.assertRaisesRegex(
                target.Refused, "bwrap-apparmor-source-drift"
            ):
                source_raw[str(profile)] = source_raw[str(profile)] + b"# tampered\n"
                target.validate_apparmor_policy()
        self.assertNotIn(
            "/sys/kernel/security/apparmor/profiles",
            SOURCE.read_text(encoding="utf-8"),
        )

    def test_live_apparmor_exec_label_is_exact_and_unreadable_fails_closed(self) -> None:
        expected = b"bwrap (enforce)\n"

        def exercise(raw: bytes) -> dict[str, object]:
            with tempfile.TemporaryFile() as stream:
                stream.write(raw)
                stream.flush()
                stream.seek(0)
                descriptor = os.dup(stream.fileno())
                with mock.patch.object(target.os, "open", return_value=descriptor):
                    return target.live_apparmor_exec_label(321, "bwrap")

        observed = exercise(expected)
        self.assertEqual(observed["profile_name"], "bwrap")
        self.assertEqual(observed["mode"], "enforce")
        for wrong in (
            b"bwrap (complain)\n",
            b"unconfined\n",
            b"bwrap//unreviewed (enforce)\n",
        ):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(
                target.Refused, "apparmor-current-label"
            ):
                exercise(wrong)
        with (
            mock.patch.object(
                target.os,
                "open",
                side_effect=PermissionError(13, "Permission denied"),
            ),
            self.assertRaisesRegex(target.Refused, "apparmor-current-unreadable"),
        ):
            target.live_apparmor_exec_label(321, "bwrap")

    def test_namespace_contract_is_literal_complete_and_non_overridable(self) -> None:
        expected = (
            "--unshare-all", "--unshare-user", "--disable-userns",
            "--assert-userns-disabled", "--unshare-ipc", "--unshare-pid",
            "--unshare-net", "--unshare-uts", "--unshare-cgroup",
            "--die-with-parent", "--new-session", "--clearenv",
        )
        self.assertEqual(target.MANDATORY_NAMESPACE_FLAGS, expected)
        outer = target.rendered_outer_source(
            SHA, SHA, SHA, SHA, SYNTHETIC_RUNTIME_SHA256, SYNTHETIC_CACHE_ROUTES
        )
        self.assertIn(f"FLAGS={expected!r}", outer)
        for flag in expected:
            self.assertEqual(expected.count(flag), 1)
        self.assertNotIn("--share-net", outer)

    def test_outer_command_exact_fd_contract_and_override_controls(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            resources = live_outer_resources(Path(raw_root))
            command = resources["command"]
            descriptors = resources["passed"]
            contract = resources["contract"]
            status_read = resources["status_read"]
            launch_block_write = resources["launch_block_write"]
            try:
                with mock.patch.multiple(
                    target,
                    REPO_ROOT=resources["repo"],
                    REGISTRY_ROOT=resources["registry"],
                    TOOLCHAIN_ROOT=resources["toolchain"],
                ):
                    target.validate_bwrap_command(
                        command,
                        descriptors,
                        contract,
                        status_read_fd=status_read,
                        launch_block_write_fd=launch_block_write,
                    )
                    bwrap_mount = command.index("/usr/bin/bwrap", 1)
                    self.assertEqual(
                        command[bwrap_mount - 2 : bwrap_mount + 1],
                        ["--ro-bind-fd", str(descriptors[0]), "/usr/bin/bwrap"],
                    )
                    self.assertIn(["--dir", "/etc"], [
                        command[index : index + 2]
                        for index in range(len(command) - 1)
                    ])
                    self.assertIn(["--dir", "/lib64"], [
                        command[index : index + 2]
                        for index in range(len(command) - 1)
                    ])
                    self.assertFalse(
                        any(
                            command[index : index + 3]
                            == ["--ro-bind", "/lib64", "/lib64"]
                            for index in range(len(command) - 2)
                        )
                    )
                    for source, destination in SYNTHETIC_RUNTIME_BINDINGS:
                        self.assertEqual(
                            sum(
                                command[index : index + 3]
                                == ["--ro-bind", source, destination]
                                for index in range(len(command) - 2)
                            ),
                            1,
                        )
                    self.assertFalse(
                        any("glibc-hwcaps" in item for item in command)
                    )
                    block_option = command.index("--block-fd")
                    self.assertEqual(
                        command[block_option : block_option + 2],
                        ["--block-fd", str(descriptors[10])],
                    )
                    mutations = []
                    repo_destination = command.index("/host-repo")
                    changed_destination = list(command)
                    changed_destination[repo_destination] = "/"
                    mutations.append(changed_destination)
                    changed_role = list(command)
                    repo_fd_argument = changed_role.index("--ro-bind-fd") + 1
                    changed_role[repo_fd_argument] = str(descriptors[2])
                    mutations.append(changed_role)
                    changed_block = list(command)
                    changed_block[block_option + 1] = str(descriptors[9])
                    mutations.append(changed_block)
                    mutations.extend(
                        (
                            command + ["--share-net"],
                            command + ["--bind", "/tmp", "/escape"],
                            command + ["--unshare-net"],
                        )
                    )
                    alternate_mount = list(command)
                    insertion = alternate_mount.index("--json-status-fd")
                    alternate_mount[insertion:insertion] = [
                        "--ro-bind",
                        "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6",
                        "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6",
                    ]
                    mutations.append(alternate_mount)
                    for mutation in mutations:
                        with self.subTest(mutation=mutation), self.assertRaisesRegex(
                            target.Refused, "outer-command-not-canonical"
                        ):
                            target.validate_bwrap_command(
                                mutation,
                                descriptors,
                                contract,
                                status_read_fd=status_read,
                                launch_block_write_fd=launch_block_write,
                            )
                    swapped = list(descriptors)
                    swapped[1], swapped[2] = swapped[2], swapped[1]
                    with self.assertRaisesRegex(
                        target.Refused, "outer-repo-fd-identity"
                    ):
                        target.validate_bwrap_command(
                            command,
                            tuple(swapped),
                            contract,
                            status_read_fd=status_read,
                            launch_block_write_fd=launch_block_write,
                        )
                    wrong_hash = contract | {
                        "sealed_sha256": contract["sealed_sha256"]
                        | {"seccomp": "0" * 64}
                    }
                    with self.assertRaisesRegex(target.Refused, "sealed-fd-hash"):
                        target.validate_bwrap_command(
                            command,
                            descriptors,
                            wrong_hash,
                            status_read_fd=status_read,
                            launch_block_write_fd=launch_block_write,
                        )
                    unsealed = os.memfd_create(
                        "test-unsealed", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
                    )
                    try:
                        unsealed_roles = list(descriptors)
                        unsealed_roles[8] = unsealed
                        with self.assertRaisesRegex(
                            target.Refused, "sealed-fd-required"
                        ):
                            target.validate_outer_fd_contract(
                                tuple(unsealed_roles),
                                contract,
                                status_read_fd=status_read,
                                launch_block_write_fd=launch_block_write,
                            )
                    finally:
                        os.close(unsealed)
            finally:
                for descriptor in resources["all_fds"]:
                    os.close(descriptor)

    def test_inner_and_outer_sources_hold_build_and_mount_contract(self) -> None:
        inner = target.rendered_inner_source()
        outer = target.rendered_outer_source(
            SHA, SHA, SHA, SHA, SYNTHETIC_RUNTIME_SHA256, SYNTHETIC_CACHE_ROUTES
        )
        ast.parse(target.EXTERNAL_STAGE0_SOURCE)
        ast.parse(inner)
        outer_tree = ast.parse(outer)
        mount_function = next(
            node
            for node in outer_tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "allowed_system_mount"
        )
        mount_namespace = {"RUNTIME": SYNTHETIC_RUNTIME_SHA256}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=[mount_function], type_ignores=[])),
                "<outer-mount-control>",
                "exec",
            ),
            mount_namespace,
        )
        allowed_mount = mount_namespace["allowed_system_mount"]
        self.assertTrue(allowed_mount(b"/usr"))
        self.assertTrue(allowed_mount(target.BWRAP_INTERPRETER_LITERAL.encode()))
        self.assertTrue(allowed_mount(b"/proc"))
        self.assertFalse(
            allowed_mount(
                b"/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6"
            )
        )
        self.assertFalse(
            allowed_mount(b"/usr/lib/x86_64-linux-gnu/reviewer-alternate.so")
        )
        outer_command_value, _ = outer_command()
        self.assertIn('refuse(dict(os.environ)==ENV', inner)
        self.assertIn('refuse(sorted(live)==[0,1,2]', inner)
        self.assertIn('os.getcwd()=="/"', inner)
        self.assertIn('/toolchain/bin/cargo","build"', inner)
        self.assertIn('"--manifest-path","/src/', inner)
        self.assertIn('"--frozen","--offline"', inner)
        self.assertIn('"--target-dir","/target"', inner)
        self.assertIn('not stat.S_ISREG(os.stat("/usr/bin/bwrap"', inner)
        for mountpoint in (b"/src", b"/vendor", b"/toolchain", b"/cargo-home"):
            self.assertIn(mountpoint.decode(), inner)
        for token in (
            '"--ro-bind","/dev/null","/usr/bin/bwrap"',
            '"--tmpfs","/tmp"',
            '"--tmpfs","/target"',
            '"--seccomp"',
            '"--json-status-fd"',
            "os.pidfd_open",
            "os.wait4",
            "child_ns=namespaces(child_pid)",
            "for required,digest in RUNTIME.items()",
            "observed==digest",
        ):
            self.assertIn(token, outer)
        for runtime_path in target.BWRAP_RUNTIME_FILES:
            self.assertIn(runtime_path, outer)
        self.assertNotIn("/home/luke", outer_command_value)
        self.assertNotIn("/run/user", outer_command_value)
        self.assertNotIn("/.local", outer_command_value)

    def test_overflow_descendant_signal_and_rlimit_controls_are_retained(self) -> None:
        host_monitor = inspect.getsource(target.run_bounded_process) + inspect.getsource(
            target.terminate_and_reap_bwrap
        )
        outer = target.rendered_outer_source(
            SHA, SHA, SHA, SHA, SYNTHETIC_RUNTIME_SHA256, SYNTHETIC_CACHE_ROUTES
        )
        inner = target.rendered_inner_source()
        for token in (
            "bwrap-{name}-overflow",
            "bwrap-descendant-held-pipe",
            "pidfd_send_signal",
            "os.killpg",
            "os.wait4",
        ):
            self.assertIn(token, host_monitor)
        for token in (
            "len(buffers[key.data])<=limit",
            "time.monotonic()-exited_at>2.0",
            "signal.pidfd_send_signal",
            "os.killpg",
            "os.wait4",
        ):
            self.assertIn(token, outer)
        for limit in (
            "RLIMIT_CORE", "RLIMIT_AS", "RLIMIT_FSIZE", "RLIMIT_NOFILE", "RLIMIT_NPROC"
        ):
            self.assertIn(limit, inner)

    def test_overflow_descendant_and_signal_controls_fail_closed(self) -> None:
        buffer = bytearray(b"ab")
        target.append_bounded(buffer, b"c", 3, "synthetic-overflow")
        self.assertEqual(buffer, b"abc")
        with self.assertRaisesRegex(target.Refused, "synthetic-overflow"):
            target.append_bounded(buffer, b"d", 3, "synthetic-overflow")
        self.assertFalse(
            target.descendant_pipe_grace_expired(
                leader_reaped=True,
                streams_open=True,
                exited_at=10.0,
                now=12.0,
            )
        )
        self.assertTrue(
            target.descendant_pipe_grace_expired(
                leader_reaped=True,
                streams_open=True,
                exited_at=10.0,
                now=12.001,
            )
        )
        self.assertEqual(
            target.successful_wait4_returncode(0),
            {"exit_code": 0, "term_signal": 0},
        )
        for returncode in (1, -target.signal.SIGTERM):
            with self.subTest(returncode=returncode), self.assertRaisesRegex(
                target.Refused, "bwrap-exit"
            ):
                target.successful_wait4_returncode(returncode)

    def test_failure_cleanup_signals_pidfd_group_child_and_reaps(self) -> None:
        process = types.SimpleNamespace(pid=321, returncode=None)
        reaped = (321, 0, types.SimpleNamespace(ru_maxrss=0))
        with (
            mock.patch.object(target.signal, "pidfd_send_signal") as pidfd_signal,
            mock.patch.object(target.os, "kill") as kill_child,
            mock.patch.object(target.os, "killpg") as kill_group,
            mock.patch.object(target.os, "wait4", return_value=reaped) as wait4,
        ):
            observed = target.terminate_and_reap_bwrap(
                process,
                pidfd=88,
                child_pid=654,
                waited=None,
            )
        self.assertIs(observed, reaped)
        pidfd_signal.assert_called_once_with(88, target.signal.SIGKILL)
        kill_child.assert_called_once_with(654, target.signal.SIGKILL)
        kill_group.assert_called_once_with(321, target.signal.SIGKILL)
        wait4.assert_called_once_with(321, 0)
        self.assertEqual(process.returncode, 0)

    def test_post_spawn_monitor_setup_failure_always_enters_cleanup(self) -> None:
        command, descriptors = outer_command()
        process = types.SimpleNamespace(
            pid=321,
            returncode=None,
            stdout=types.SimpleNamespace(close=mock.Mock()),
            stderr=types.SimpleNamespace(close=mock.Mock()),
        )
        with (
            mock.patch.object(target, "validate_bwrap_command"),
            mock.patch.object(target.subprocess, "Popen", return_value=process),
            mock.patch.object(target.os, "close"),
            mock.patch.object(target.os, "pidfd_open", side_effect=OSError("pidfd")),
            mock.patch.object(
                target, "terminate_and_reap_bwrap", return_value=None
            ) as cleanup,
            self.assertRaisesRegex(OSError, "pidfd"),
        ):
            target.run_bounded_process(
                command,
                passed_fds=descriptors,
                launch_contract={},
                status_read_fd=90,
                status_write_fd=descriptors[-2],
                launch_block_write_fd=91,
            )
        cleanup.assert_called_once_with(
            process,
            pidfd=None,
            child_pid=None,
            waited=None,
        )

    def test_wrong_live_apparmor_label_never_releases_launch_barrier(self) -> None:
        command, descriptors = outer_command()
        process = types.SimpleNamespace(
            pid=321,
            returncode=None,
            stdout=types.SimpleNamespace(close=mock.Mock()),
            stderr=types.SimpleNamespace(close=mock.Mock()),
        )
        contract = {
            "apparmor_exec_label": {"profile_name": "bwrap", "mode": "enforce"}
        }
        with (
            mock.patch.object(target, "validate_bwrap_command"),
            mock.patch.object(target.subprocess, "Popen", return_value=process),
            mock.patch.object(target.os, "close"),
            mock.patch.object(target.os, "pidfd_open", return_value=88),
            mock.patch.object(
                target,
                "live_apparmor_exec_label",
                side_effect=target.Refused("apparmor-current-label"),
            ),
            mock.patch.object(target.os, "write") as release,
            mock.patch.object(
                target, "terminate_and_reap_bwrap", return_value=None
            ) as cleanup,
            self.assertRaisesRegex(target.Refused, "apparmor-current-label"),
        ):
            target.run_bounded_process(
                command,
                passed_fds=descriptors,
                launch_contract=contract,
                status_read_fd=90,
                status_write_fd=descriptors[-2],
                launch_block_write_fd=91,
            )
        release.assert_not_called()
        cleanup.assert_called_once_with(
            process,
            pidfd=88,
            child_pid=None,
            waited=None,
        )

    def test_receipt_source_keeps_honest_non_privacy_limitations(self) -> None:
        raw = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn('"private_material_present": False', raw)
        for statement in (
            '"build_swap_prevented": False',
            '"full_dynamic_closure_reproducible": False',
            '"host_root_runtime_trusted": True',
            '"outer_python_and_final_build_broad_host_runtime_trusted": True',
            '"debian_archive_repository_signature_cryptographically_reverified_locally": False',
            '"upstream_tag_signature_cryptographically_reverified_locally": False',
            '"debian_package_rebuilt_from_upstream_commit_locally": False',
            '"apparmor_loaded_policy_byte_identity_authenticated": False',
            '"apparmor_global_loaded_profile_table_preflight_used": False',
            '"launch_barrier_released_after_apparmor_observation": True',
            '"one_trusted_host_assumption": True',
            '"same_uid_and_privileged_host_processes_in_tcb": True',
            '"hostile_same_uid_isolation_claim": False',
            '"outer_copier_reviewed_input_mounts_originate_under_host_home": True',
            '"private_proving_material_mounted_into_final_build": False',
            '"independent_rebuild_required_before_private_proof": True',
            '"private_proof_requires_enforced_swap_max_zero": True',
            '"cryptographic_correctness": False',
            '"privacy": False',
            '"production_authority": False',
        ):
            self.assertIn(statement, raw)


class SeccompAndStatusTests(unittest.TestCase):
    @staticmethod
    def evaluate_seccomp(raw: bytes, *, arch: int, syscall_number: int) -> int:
        """Evaluate the small classic-BPF subset emitted by the freezer."""
        instructions = [
            struct.unpack("HBBI", raw[offset : offset + 8])
            for offset in range(0, len(raw), 8)
        ]
        accumulator = 0
        program_counter = 0
        data = struct.pack(
            "=IIQQQQQQ", syscall_number & 0xFFFFFFFF, arch, 0, 0, 0, 0, 0, 0
        )
        while program_counter < len(instructions):
            code, jump_true, jump_false, constant = instructions[program_counter]
            if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
                accumulator = struct.unpack_from("=I", data, constant)[0]
                program_counter += 1
            elif code == 0x15:  # BPF_JMP | BPF_JEQ | BPF_K
                program_counter += 1 + (
                    jump_true if accumulator == constant else jump_false
                )
            elif code == 0x45:  # BPF_JMP | BPF_JSET | BPF_K
                program_counter += 1 + (
                    jump_true if accumulator & constant else jump_false
                )
            elif code == 0x06:  # BPF_RET | BPF_K
                return constant
            else:
                raise AssertionError(f"unsupported test BPF opcode: {code:#x}")
        raise AssertionError("seccomp program fell off the end")

    def test_seccomp_program_kills_wrong_arch_and_denies_every_named_syscall(self) -> None:
        raw = target.seccomp_filter_bytes()
        self.assertEqual(len(raw) % 8, 0)
        instructions = [
            struct.unpack("HBBI", raw[offset : offset + 8])
            for offset in range(0, len(raw), 8)
        ]
        self.assertEqual(instructions[0], (0x20, 0, 0, 4))
        self.assertEqual(instructions[1], (0x15, 1, 0, target.AUDIT_ARCH_X86_64))
        self.assertEqual(instructions[2], (0x06, 0, 0, target.SECCOMP_RET_KILL_PROCESS))
        self.assertEqual(instructions[3], (0x20, 0, 0, 0))
        self.assertEqual(instructions[4], (0x45, 0, 1, target.X32_SYSCALL_BIT))
        self.assertEqual(instructions[5], (0x06, 0, 0, target.SECCOMP_RET_KILL_PROCESS))
        denied = {
            instructions[index][3]
            for index in range(6, len(instructions) - 1, 2)
            if instructions[index][:3] == (0x15, 0, 1)
            and instructions[index + 1][3] == target.SECCOMP_RET_ERRNO | target.errno.EPERM
        }
        self.assertEqual(denied, target.DENIED_SYSCALLS_X86_64)
        required = {
            "socket", "socketpair", "connect", "ptrace", "process_vm_readv",
            "process_vm_writev", "pidfd_getfd", "io_uring_setup", "bpf",
            "perf_event_open", "keyctl", "userfaultfd", "mount", "unshare", "setns",
        }
        self.assertTrue(required.issubset(target.DENIED_SYSCALL_NAMES_X86_64))
        self.assertEqual(instructions[-1], (0x06, 0, 0, target.SECCOMP_RET_ALLOW))

    def test_seccomp_evaluator_kills_x32_without_rejecting_native_build_calls(self) -> None:
        raw = target.seccomp_filter_bytes()
        evaluate = lambda arch, number: self.evaluate_seccomp(
            raw, arch=arch, syscall_number=number
        )
        denied = target.SECCOMP_RET_ERRNO | target.errno.EPERM

        self.assertEqual(evaluate(0x40000003, 41), target.SECCOMP_RET_KILL_PROCESS)
        for number in target.DENIED_SYSCALLS_X86_64:
            with self.subTest(native_denied=number):
                self.assertEqual(evaluate(target.AUDIT_ARCH_X86_64, number), denied)
            with self.subTest(x32_tagged=number):
                self.assertEqual(
                    evaluate(
                        target.AUDIT_ARCH_X86_64,
                        target.X32_SYSCALL_BIT | number,
                    ),
                    target.SECCOMP_RET_KILL_PROCESS,
                )

        # ABI-layout-specific x32 slots are not the tagged native numbers, but
        # must be killed by the same ABI-bit boundary.
        for number in (0x40000205, 0x40000206, 0x40000207, 0x40000209,
                       0x40000210, 0x40000219, 0x4000021A, 0x4000021B,
                       0x4000021C, 0x4000021D, 0x4000021E, 0xFFFFFFFF):
            with self.subTest(x32_specific=number):
                self.assertEqual(
                    evaluate(target.AUDIT_ARCH_X86_64, number),
                    target.SECCOMP_RET_KILL_PROCESS,
                )

        for number in (0, 1, 9, 56, 59, 202, 231, 257, 435):
            with self.subTest(native_allowed=number):
                self.assertEqual(
                    evaluate(target.AUDIT_ARCH_X86_64, number),
                    target.SECCOMP_RET_ALLOW,
                )

    def test_status_requires_one_positive_non_boolean_child_pid(self) -> None:
        self.assertEqual(
            target.parse_status_lines(b'{"child-pid":123}\n'),
            [{"child-pid": 123}],
        )
        self.assertIsNone(target.completed_status_child_pid(b'{"child-pid":123}'))
        self.assertEqual(
            target.completed_status_child_pid(b'{"phase":"ready"}\n{"child-pid":123}\n'),
            123,
        )
        for raw in (
            b"",
            b"not-json\n",
            b'{"child-pid":0}\n',
            b'{"child-pid":true}\n',
            b'{"child-pid":1}\n{"child-pid":2}\n',
        ):
            with self.subTest(raw=raw), self.assertRaises(target.Refused):
                target.parse_status_lines(raw)


class FrameTests(unittest.TestCase):
    def test_valid_frame_is_copied_into_four_sealed_memfds(self) -> None:
        header, sealed = target.parse_build_frame(frame_for())
        try:
            self.assertEqual(header["cargo_command"], target.expected_cargo_command())
            self.assertEqual(set(sealed), {"prover", "verifier", "prover_dep_info", "verifier_dep_info"})
            self.assertTrue(target.read_sealed_fd(sealed["prover"]).startswith(b"\x7fELF"))
            for descriptor in sealed.values():
                self.assertEqual(
                    target.fcntl.fcntl(descriptor, target.F_GET_SEALS),
                    target.REQUIRED_SEALS,
                )
        finally:
            for descriptor in sealed.values():
                os.close(descriptor)

    def test_frame_rejects_order_hash_truncation_trailing_and_payload_types(self) -> None:
        cases = {
            "order": frame_for(names=["verifier", "prover", "prover_dep_info", "verifier_dep_info"]),
            "hash": frame_for(hashes=["0" * 64, hashlib.sha256(b"\x7fELF-verifier").hexdigest(), hashlib.sha256(b"p.d\n").hexdigest(), hashlib.sha256(b"v.d\n").hexdigest()]),
            "truncated": frame_for()[:-1],
            "trailing": frame_for() + b"x",
            "non-elf": frame_for(payloads=[b"not-elf", b"\x7fELF-verifier", b"p.d\n", b"v.d\n"]),
            "non-utf8": frame_for(payloads=[b"\x7fELF-prover", b"\x7fELF-verifier", b"\xff", b"v.d\n"]),
        }
        for name, raw in cases.items():
            with self.subTest(name=name), self.assertRaises(target.Refused):
                target.parse_build_frame(raw)


class RehearsalAndPublicationTests(unittest.TestCase):
    def test_symlink_rehearsal_accepts_only_specific_pre_child_refusal(self) -> None:
        accepted = subprocess.CompletedProcess(
            [],
            1,
            b"",
            b"Too many levels of symbolic links: /safe/trap/kpb-rehearsal",
        )
        with mock.patch.object(target.subprocess, "run", return_value=accepted) as run:
            result = target.run_symlink_destination_rehearsal(77)
        self.assertTrue(result["returncode_nonzero"])
        command = run.call_args.args[0]
        self.assertEqual(command[0], str(target.BWRAP))
        self.assertIn("/usr/bin/true", command)
        self.assertIn("/proc", command)
        self.assertIn("/safe/trap/kpb-rehearsal", command)
        self.assertEqual(command.count("--ro-bind-fd"), 1)

        rejected = (
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 1, b"", b"Permission denied"),
        )
        for completed in rejected:
            with (
                self.subTest(returncode=completed.returncode, stderr=completed.stderr),
                mock.patch.object(target.subprocess, "run", return_value=completed),
                self.assertRaisesRegex(target.Refused, "bwrap-symlink-destination-not-refused"),
            ):
                target.run_symlink_destination_rehearsal(77)

    def test_symlink_rehearsal_rejects_any_started_child(self) -> None:
        completed = subprocess.CompletedProcess([], 1, b"", b"symlink refused")

        def fake_run(*args, **kwargs):
            os.write(kwargs["pass_fds"][-1], b'{"child-pid":999}\n')
            return completed

        with (
            mock.patch.object(target.subprocess, "run", side_effect=fake_run),
            self.assertRaisesRegex(target.Refused, "bwrap-symlink-destination-not-refused"),
        ):
            target.run_symlink_destination_rehearsal(77)

    def test_rename_noreplace_never_replaces_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kpb-bwrap-rename-test-") as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            with self.assertRaises(FileExistsError):
                target.rename_noreplace(source, destination)
            self.assertTrue(source.is_dir())
            self.assertTrue(destination.is_dir())
            destination.rmdir()
            target.rename_noreplace(source, destination)
            self.assertFalse(source.exists())
            self.assertTrue(destination.is_dir())

    def test_atomic_publication_records_matching_pre_and_post_hashes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kpb-bwrap-publish-test-") as temporary:
            base = Path(temporary)
            output = base / "published"
            payloads = {
                "prover": b"synthetic-prover",
                "verifier": b"synthetic-verifier",
                "prover_dep_info": b"synthetic-prover.d\n",
                "verifier_dep_info": b"synthetic-verifier.d\n",
            }
            sealed = {
                name: target.sealed_memfd(f"test-{name}", raw)
                for name, raw in payloads.items()
            }
            try:
                with mock.patch.multiple(
                    target,
                    PRIVATE_OUTPUT_BASE=base,
                    OUTPUT_PARENT=output,
                    OUTPUT_NAME="synthetic-build",
                ):
                    result = target.publish_bundle(
                        {"synthetic": True},
                        sealed,
                        {"schema": target.RECEIPT_SCHEMA, "authorization": False},
                        {
                            "local": {"records": [], "tree_sha256": SHA},
                            "vendor": {"records": [], "tree_sha256": SHA},
                            "toolchain": {"records": [], "tree_sha256": SHA},
                        },
                    )
            finally:
                for descriptor in sealed.values():
                    os.close(descriptor)
            self.assertEqual(result["output_parent"], str(output))
            self.assertTrue((output / "BUILD-RECEIPT.json").is_file())
            self.assertTrue((output / "PUBLICATION-MANIFEST.json").is_file())
            self.assertEqual(result["artifact_count"], 4)
            for evidence in result["post_publish"].values():
                self.assertEqual(
                    evidence["pre_publish_sha256"], evidence["post_publish_sha256"]
                )
            self.assertFalse(result["authorization"])


if __name__ == "__main__":
    unittest.main()
