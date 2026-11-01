#!/usr/bin/env python3
"""Build and verify the source-owned worker without executing setup."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parents[3]
CONTRACT = ROOT / "build_contract.json"
BUILD_DOMAIN = b"kpb-bounded-setup-build-material/v1\0"
SOURCE_CLOSURE_DOMAIN = b"kpb-bounded-setup-local-source-closure/v1\0"
BUILD_CLOSURE_DOMAIN = b"kpb-bounded-setup-build-closure/v1\0"


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def verify_materials(contract: dict) -> None:
    identity = hashlib.sha256()
    identity.update(BUILD_DOMAIN)
    for material in contract["worker_build_controls"]:
        path = material["path"]
        body = (ROOT / path).read_bytes()
        if sha256(body) != material["sha256"]:
            raise RuntimeError(f"build material mismatch: {path}")
        identity.update(path.encode())
        identity.update(b"\0")
        identity.update(body)
    if identity.hexdigest() != contract["worker_build_control_identity"]:
        raise RuntimeError("worker build control identity mismatch")


def local_source_files(metadata: dict) -> tuple[list[dict], list[str], set[Path]]:
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    packages = sorted(
        (package for package in metadata["packages"]
         if package["id"] in resolved and package["source"] is None),
        key=lambda package: package["manifest_path"])
    package_rows = []
    build_scripts = []
    files: set[Path] = set()
    for package in packages:
        manifest = Path(package["manifest_path"])
        if manifest.is_symlink():
            raise RuntimeError(f"symlinked local manifest: {manifest}")
        manifest = manifest.resolve()
        try:
            relative_manifest = manifest.relative_to(WORKSPACE).as_posix()
        except ValueError as error:
            raise RuntimeError("local package escaped the workspace") from error
        package_rows.append({
            "name": package["name"], "version": package["version"],
            "manifest_path": relative_manifest,
        })
        package_root = manifest.parent
        files.add(manifest)
        lock = package_root / "Cargo.lock"
        if lock.is_file():
            if lock.is_symlink():
                raise RuntimeError(f"symlinked local lockfile: {lock}")
            files.add(lock.resolve())
        source = package_root / "src"
        if source.is_dir():
            for path in source.rglob("*.rs"):
                if path.is_symlink():
                    raise RuntimeError(f"symlinked local source: {path}")
                if path.is_file():
                    files.add(path.resolve())
        for target in package["targets"]:
            if "custom-build" in target["kind"]:
                build = Path(target["src_path"])
                if build.is_symlink():
                    raise RuntimeError(f"symlinked local build script: {build}")
                build = build.resolve()
                files.add(build)
                build_scripts.append(build.relative_to(WORKSPACE).as_posix())
    for path in (ROOT / ".cargo/config.toml", ROOT / "rust-toolchain.toml"):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"missing or symlinked build control: {path}")
        files.add(path.resolve())

    # Admit literal compile-time file inputs and refuse opaque include macros.
    include = re.compile(
        r'include(?:_bytes|_str)?!\s*\(\s*"([^"\n]+)"\s*\)')
    path_attribute = re.compile(r'#\s*\[path\s*=\s*"([^"\n]+)"\s*\]')
    pending = list(files)
    inspected: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in inspected or path.suffix != ".rs":
            continue
        inspected.add(path)
        text = path.read_text()
        literal_starts = {match.start() for match in include.finditer(text)}
        macro_starts = {match.start() for match in re.finditer(
            r'include(?:_bytes|_str)?!\s*\(', text)}
        if literal_starts != macro_starts:
            raise RuntimeError(f"non-literal include macro: {path}")
        references = [match.group(1) for match in include.finditer(text)]
        references += [match.group(1) for match in path_attribute.finditer(text)]
        for reference in references:
            target = path.parent / reference
            if target.is_symlink() or not target.is_file():
                raise RuntimeError(f"missing or symlinked compile input: {target}")
            target = target.resolve()
            try:
                target.relative_to(WORKSPACE)
            except ValueError as error:
                raise RuntimeError("compile input escaped the workspace") from error
            if target not in files:
                files.add(target)
                pending.append(target)
    return package_rows, sorted(build_scripts), files


def verify_local_source_closure(contract: dict) -> str:
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout)
    packages, build_scripts, discovered = local_source_files(metadata)
    closure_contract = contract["local_source_closure"]
    manifest_path = ROOT / closure_contract["manifest"]
    manifest_body = manifest_path.read_bytes()
    if sha256(manifest_body) != closure_contract["manifest_sha256"]:
        raise RuntimeError("source closure manifest identity mismatch")
    manifest = json.loads(manifest_body)
    if manifest["resolved_local_packages"] != packages:
        raise RuntimeError("resolved local package set mismatch")
    if build_scripts or manifest["local_build_scripts"] != build_scripts:
        raise RuntimeError("local build scripts are not admitted")
    expected_paths = [row["path"] for row in manifest["files"]]
    discovered_paths = sorted(
        path.relative_to(WORKSPACE).as_posix() for path in discovered)
    if expected_paths != discovered_paths or manifest["file_count"] != len(discovered):
        raise RuntimeError("local source closure file set mismatch")
    identity = hashlib.sha256()
    identity.update(SOURCE_CLOSURE_DOMAIN)
    for row in manifest["files"]:
        path = WORKSPACE / row["path"]
        body = path.read_bytes()
        if sha256(body) != row["sha256"]:
            raise RuntimeError(f"local source changed: {row['path']}")
        identity.update(row["path"].encode())
        identity.update(b"\0")
        identity.update(body)
    result = identity.hexdigest()
    if (result != manifest["closure_identity"] or
            result != closure_contract["closure_identity"] or
            len(packages) != closure_contract["resolved_local_packages"] or
            len(discovered) != closure_contract["files"]):
        raise RuntimeError("local source closure identity mismatch")
    build = hashlib.sha256()
    build.update(BUILD_CLOSURE_DOMAIN)
    for value in (result, contract["toolchain"]["rustc_commit"],
                  contract["toolchain"]["target"]):
        build.update(value.encode())
        build.update(b"\0")
    if build.hexdigest() != contract["build_closure_identity"]:
        raise RuntimeError("build closure identity mismatch")
    return result


def verify_toolchain(contract: dict) -> None:
    version = subprocess.run(
        ["rustc", "-Vv"], cwd=ROOT, check=True,
        capture_output=True, text=True).stdout
    expected = contract["toolchain"]
    required = (
        f"release: {expected['rustc_release']}",
        f"commit-hash: {expected['rustc_commit']}",
        f"LLVM version: {expected['llvm']}",
    )
    if not all(value in version for value in required):
        raise RuntimeError("Rust toolchain mismatch")


def verify_elf(body: bytes) -> None:
    header_format = "<16sHHIQQQIHHHHHH"
    header = struct.unpack_from(header_format, body)
    ident, elf_type, machine = header[:3]
    phoff, ehsize, phentsize, phnum = header[5], header[8], header[9], header[10]
    if ident[:7] != b"\x7fELF\x02\x01\x01" or elf_type != 2 or machine != 62:
        raise RuntimeError("worker is not x86_64 ET_EXEC")
    if ehsize != struct.calcsize(header_format) or phentsize != 56 or phnum == 0:
        raise RuntimeError("invalid ELF program header table")
    if phoff + phentsize * phnum > len(body):
        raise RuntimeError("truncated ELF program header table")
    executable_load = False
    for index in range(phnum):
        p_type, p_flags, p_offset, _, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", body, phoff + index * phentsize)
        if (p_offset + p_filesz > len(body) or p_type in (2, 3) or
                (p_type == 1 and (p_flags & 3) == 3) or
                (p_type == 0x6474E551 and (p_flags & 1))):
            raise RuntimeError("dynamic or malformed ELF is forbidden")
        executable_load |= p_type == 1 and bool(p_flags & 1)
    if not executable_load:
        raise RuntimeError("ELF has no executable load segment")


def verify_source() -> None:
    source = (ROOT / "src/main.rs").read_text()
    required = ("OsRng", "AGGREGATE_CONTEXT_FD", "AGGREGATE_SIGNATURE_FD",
                "PR_SET_DUMPABLE", "POLICY_ERASURE_ATTEMPTED")
    forbidden = ("seed_from_u64", "from_seed", "StdRng", "std::env::args",
                 "std::env::args_os")
    if not all(value in source for value in required):
        raise RuntimeError("worker source is missing a required fixed boundary")
    if any(value in source for value in forbidden):
        raise RuntimeError("worker source exposes caller entropy or arguments")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    arguments = parser.parse_args()
    contract = json.loads(CONTRACT.read_text())
    verify_materials(contract)
    local_source_closure = verify_local_source_closure(contract)
    verify_toolchain(contract)
    verify_source()
    if arguments.build:
        subprocess.run(
            ["cargo", "build", "--release", "--locked", "--offline"],
            cwd=ROOT, check=True)
    selected = contract["selected_worker"]
    artifact = ROOT / selected["relative_path"]
    body = artifact.read_bytes()
    if len(body) != selected["bytes"] or sha256(body) != selected["sha256"]:
        raise RuntimeError("selected worker identity mismatch")
    verify_elf(body)
    print(json.dumps({
        "schema": "kpb-bounded-static-setup-worker-verification/v1",
        "build_closure_identity": contract["build_closure_identity"],
        "local_source_closure_identity": local_source_closure,
        "resolved_local_packages":
            contract["local_source_closure"]["resolved_local_packages"],
        "local_source_files": contract["local_source_closure"]["files"],
        "local_build_scripts": 0,
        "worker_identity": selected["sha256"],
        "source_closed_static_worker": True,
        "setup_executed": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
