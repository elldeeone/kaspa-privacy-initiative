#!/usr/bin/env python3
"""Immutable, network-free two-round W1 feasibility fixture orchestration.

This is a clear-witness research harness.  It creates fresh synthetic owners,
genuine Output proofs and signature witnesses, but it is not a wallet, an MPC
dealer, a setup ceremony, a chain adapter, or an admission authority.  Its JSON
files and hashes can never substitute for the live one-shot W0, C1 and Close
authorities required by the counterfactual feasibility bridge.

The aggregate proof stages are deliberately separate.  ``components`` stops
after two exact Effects cores and placeholder projections whose final 128 bytes
are zero.  A later, resource-qualified prover must create two genuine c023
proofs and ``finalize`` must rebuild and revalidate the final projections.
"""

from __future__ import annotations

import argparse
import ast
import copy
import concurrent.futures
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

import component_run
import exit_wire
import output_producer
import prepare_unfunded_batch as retained
import wallet_history
import wallet_profile as wallet


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RELATION = ROOT / "poc/local-private-payment/private-batch-relation"


def _dynamic_module(name, path):
    """Load one exact repository-local module used by the fixture semantics."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("dynamic-module-spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


intent_codec = _dynamic_module(
    "_kpb_offline_w1_restricted_intent",
    HERE.parent / "private_batch/intent.py",
)
PUBLIC_PROFILE = ROOT / (
    "poc/local-private-payment/private-batch-public/evidence/"
    "2026-10-28-real-role-selection/PROFILE-DESCRIPTOR.json"
)
PUBLIC_REHEARSAL = ROOT / (
    "poc/local-private-payment/private-batch-public/evidence/"
    "2026-10-28-real-role-selection/UNFUNDED-REHEARSAL.json"
)
OUTPUT_BINARY = ROOT / ".local/private-batch-auth-exit-execution/admission-01/auth-exit"
OUTPUT_PARAMETERS = ROOT / ".local/private-batch-component-parameters/output-01"
OWNER_AUX_BUILD = ROOT / ".local/private-batch-owner-aux-build-20261029-04"
OWNER_AUX = OWNER_AUX_BUILD / "owner_aux"
OWNER_AUX_DEP_INFO = OWNER_AUX_BUILD / "owner_aux.d"
OWNER_AUX_BUILD_RECEIPT = OWNER_AUX_BUILD / "BUILD-RECEIPT.json"
OWNER_AUX_SOURCE_CLOSURE = OWNER_AUX_BUILD / "SOURCE-CLOSURE.json"
OWNER_AUX_BUILD_COMMAND = OWNER_AUX_BUILD / "BUILD-COMMAND.json"
OWNER_AUX_BUILD_STDOUT = OWNER_AUX_BUILD / "BUILD.stdout"
OWNER_AUX_BUILD_STDERR = OWNER_AUX_BUILD / "BUILD.stderr"
OWNER_AUX_BUILD_TIME = OWNER_AUX_BUILD / "BUILD-TIME.txt"
AGGREGATE_PARAMETERS = ROOT / ".local/private-batch-stock-setup-20261028-02/artifact"
VERIFIER_BUILD = ROOT / ".local/private-batch-w1-verifier-build-20261029-03"
VERIFIER_BINARY = VERIFIER_BUILD / "verify_offline_w1_aggregate"
VERIFIER_DEP_INFO = VERIFIER_BUILD / "verify_offline_w1_aggregate.d"
VERIFIER_BUILD_RECEIPT = VERIFIER_BUILD / "BUILD-RECEIPT.json"
VERIFIER_SOURCE_CLOSURE = VERIFIER_BUILD / "SOURCE-CLOSURE.json"
VERIFIER_BUILD_COMMAND = VERIFIER_BUILD / "BUILD-COMMAND.json"
NATIVE_TAIL = ROOT / ".local/private-batch-public-native-final-parameters-01/IMMUTABLE-TAIL.bin"
PROBE_DEP_INFO = ROOT / (
    ".local/private-batch-w1-public-probe-target-01/release/examples/"
    "probe_public_invalid_proof.d"
)
AUTH_EXIT_DEP_INFO = ROOT / (
    ".local/private-batch-auth-exit-target/release/kpi-private-batch-auth-exit.d"
)

PROFILE_SHA = "d07d66d7668b94df7a003ed7cd289f2805f46a96206824e8af4279b632d76546"
REHEARSAL_SHA = "34b4d30dfdcb5d72c852c049a788400978571d09d21eb728eeb16f86833b9ed5"
OUTPUT_BINARY_SHA = "930972ac461ec4d9300836d4127212a594c55b90b56b8732bc9bfd98507a6fa6"
OUTPUT_MANIFEST_SHA = "1e24b8d3e22692b7445822d533b28f8ab7a09ddc4050c6e785941717e3e6fc82"
OUTPUT_PK_SHA = "1c2d02992ae89810b8a95ede7bf38aefd503f4984e7b82b27db452141752339a"
OUTPUT_VK_SHA = "8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119"
OUTPUT_MATRIX_SHA = "d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31"
OWNER_AUX_SHA = "5ba3d65d26811aaafebf5b707a620ccdec2970301f3ff203e45611dc01df166d"
OWNER_AUX_DEP_INFO_SHA = "9a21783f4c3b48cc7455e35e9a284299f3354ad235a16cf66de72ab0d30075ac"
OWNER_AUX_BUILD_RECEIPT_SHA = "18dd2f5a0878187f3db9c4391a6dce4ad29794a59aebcd983d897ea2a62c3b65"
OWNER_AUX_SOURCE_CLOSURE_SHA = "e100f1f244a7c14b9e8d771d54c37a99ba7b7f75f7c6b9402e010844fddd7051"
OWNER_AUX_BUILD_COMMAND_SHA = "335446ff54ff6c3e2d71a8e2168993a1327444224479c87fd49f0cb71dfc759a"
OWNER_AUX_BUILD_STDOUT_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
OWNER_AUX_BUILD_STDERR_SHA = "fab0a48ed0028f2b25098c03b583f0f04ef0f79813d461ffc38c55b7599b57b8"
OWNER_AUX_BUILD_TIME_SHA = "bb4e3c58478ef923f292325555a9cdd8ad1a530dbe24b7a0ff16cb9da36521b4"
OWNER_AUX_SOURCE_MEMBERS_SHA = "b3967d50d2de999020c9ef3dc2723ccdf31ee4fb99b3fc7e3ff35f3464cf54d4"
AGGREGATE_MANIFEST_SHA = "c933d85b5f9489f99931e57804cc5e7530d9a14247fbe40101180de0bd401ae4"
AGGREGATE_PK_GZ_SHA = "4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff"
AGGREGATE_PK_SHA = "170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945"
AGGREGATE_VK_SHA = "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102"
AGGREGATE_MATRIX_SHA = "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab"
VERIFIER_BINARY_SHA = "915d4fde9e6b28d9569bb61d2629c8b01c09ab78f4acfdf841c55856c4748b9b"
VERIFIER_DEP_INFO_SHA = "7bf1a37ce99c8326630f853489823633d4020f0fe8583f8b841c13b0dbdab56d"
VERIFIER_BUILD_RECEIPT_SHA = "ea2840748243fb30416cdf4eefee2d33bf06da2bfa54d3a0d04a645a93712a90"
VERIFIER_SOURCE_CLOSURE_SHA = "1bb9b967fd0336e29c5bb5ca56ea0d8b39818e8e31c146b733871b94dcce0348"
VERIFIER_BUILD_COMMAND_SHA = "a98f7780552f839f0fb9b9ca672ce5aa8e94aea56e3dce6351068bb1a942333f"
VERIFIER_SOURCE_MEMBERS_SHA = "57c1820f556cea3e88be5c768600ad5ebf5f0e5df6c2a5be3821644f96132b32"
VERIFIER_RUSTC_VV_SHA = "4fdff2578428e9c5c08ddd7a0d3079c1a106b1cdaa46e73e46f7cd32b0fb9cad"
VERIFIER_CARGO_VERSION = "cargo 1.95.0 (f2d3ce0bd 2026-03-21)"
NATIVE_TAIL_SHA = "4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d"
SIGNATURE_MATRIX_SHA = "b573a68be539426b1165e4f1b1d01f054a3ca275c7d7a1811ece99280bf17d11"
SIGNATURE_MAP_SHA = "dfff3a6a7063aef13b053ad3e5ba96fc46c2b306c4d984747b0ddbb135290712"
SIGNATURE_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SIGNATURE_VARIABLES = 10_049
SIGNATURE_INSTANCES = 67
SIGNATURE_ROWS = 10_065
OWNER_PRIVATE_VALUES = 2_635_409
OWNER_PRIVATE_BYTES = 84_333_120
OWNER_PRIVATE_MAGIC = b"KPB_OWNER_FR32V2"

# These byte domains and layouts are copied from the live C1 source.  They are
# interoperability identities, not evidence that this offline harness ever
# possessed the corresponding move-only production authorities.
C1_CAPTURE_ATTEMPT_DOMAIN = b"KPB_CAPTURE_ATTEMPT_ID_V1\n"
C1_CONTACT_VALUE_AUTHORITY_DOMAIN = b"KPB_C1_CONTACT_VALUE_AUTHORITY_V1\n"
C1_STAGE_CONFIG_DOMAIN = b"KPB_C1_CONTACT_VALUE_STAGE_CONFIG_V1\n"
C1_STAGE_PLAN_DOMAIN = b"KPB_C1_CONTACT_VALUE_STAGE_PLAN_V1\n"
C1_ROUTE_DOMAIN = b"KPB_C1_AUTHENTICATED_INVOICE_ROUTE_V1\n"

CLASSIFICATION = "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_FEASIBILITY_ONLY"
RUST_RECEIPT_CLASSIFICATION = "CALLER_SUPPLIED_CLEAR_WITNESS_RELATION_EVIDENCE_ONLY"
PLAN_SCHEMA = "kpb-offline-w1-plan/v1"
CHECKPOINT_SCHEMA = "kpb-offline-w1-checkpoint/v1"
HANDOFF_SCHEMA = "kpb-offline-w1-hybrid-handoff/v1"
RUST_REQUEST_SCHEMA = "kpb-offline-w1-rust-aggregate-verifier-request/v1"
RUST_RECEIPT_SCHEMA = "kpb-offline-w1-rust-aggregate-verification/v1"
OWNER_COUNT = 3
OUTPUT_COUNT = 6
FEE = 7_000_000
ROUND_VALUES = {
    1: {
        "input": [2_000_000_000] * 3,
        "payment": [500_000_000] * 3,
        "change": [1_493_000_000] * 3,
        "offset": 1,
    },
    2: {
        "input": [500_000_000, 1_493_000_000, 500_000_000],
        "payment": [200_000_000] * 3,
        "change": [293_000_000, 1_286_000_000, 293_000_000],
        "offset": 2,
    },
}
STAGES = (
    "bootstrap",
    "round-1-inputs",
    "round-1-components",
    "round-1-close",
    "round-2-inputs",
    "round-2-components",
    "round-2-close",
    "round-1-aggregate",
    "round-2-aggregate",
    "handoff",
)


class Refused(ValueError):
    """One bounded failure shape for orchestration and validation."""


def need(value, category):
    if not value:
        raise Refused(category)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    def invalid(_):
        raise Refused("nonfinite-json-number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        if isinstance(error, Refused):
            raise
        raise Refused("invalid-json") from None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def word(value, category="word"):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), category)
    return value


def exact_uuid(value, category="uuid"):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        parsed = None
    need(parsed is not None and parsed.version == 4 and str(parsed) == value, category)
    return value


def checked_file(path, *, mode=None, size=None):
    path = Path(path).absolute()
    need(".." not in path.parts and not path.is_symlink(), "canonical-file-path")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular-single-link-file")
    need(mode is None or stat.S_IMODE(info.st_mode) == mode, "exact-file-mode")
    need(size is None or info.st_size == size, "exact-file-size")
    return path


def checked_directory(path, *, exists=True):
    path = Path(path).absolute()
    need(".." not in path.parts and not path.is_symlink(), "canonical-directory-path")
    if exists:
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode), "directory-required")
    return path


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rename_no_replace(source, target):
    """Atomically publish one directory without replacement on Linux."""
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    need(renameat2 is not None, "renameat2-required")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    source_raw, target_raw = os.fsencode(source), os.fsencode(target)
    if renameat2(-100, source_raw, -100, target_raw, 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(os.fsdecode(target_raw))
        raise OSError(code, os.strerror(code), os.fsdecode(target_raw))


def write_new(path, value, mode=0o400):
    """Publish one complete leaf atomically without overwrite semantics."""
    path = Path(path)
    raw = value if type(value) is bytes else canonical(value)
    temporary = path.parent / ("." + path.name + ".tmp-" + str(uuid.uuid4()))
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return sha(raw)


def read_exact(path, expected=None):
    path = checked_file(path)
    raw = path.read_bytes()
    if expected is not None:
        need(sha(raw) == expected, "selected-file-identity")
    return raw


def ref(path, expected=None):
    path = checked_file(path)
    raw_sha = sha_file(path)
    need(expected is None or raw_sha == expected, "selected-artifact-pin")
    return {"path": str(path), "sha256": raw_sha, "bytes": path.stat().st_size}


def manifest_declared_ref(path, expected, size):
    """Bind a large artifact by an already content-pinned manifest and size.

    This deliberately does not read the artifact.  Any stage that consumes it
    must call ``read_ref`` and therefore rehash the complete bytes first.
    """
    path = checked_file(path)
    word(expected, "manifest-declared-ref-sha")
    need(type(size) is int and size > 0 and path.stat().st_size == size,
         "manifest-declared-ref-size")
    return {"path": str(path), "sha256": expected, "bytes": size}


def read_ref(value, *, expected_bytes=None):
    need(type(value) is dict and set(value) == {"path", "sha256", "bytes"}, "artifact-ref-fields")
    path = checked_file(value["path"])
    word(value["sha256"], "artifact-ref-sha")
    need(type(value["bytes"]) is int and value["bytes"] >= 0, "artifact-ref-size")
    need(path.stat().st_size == value["bytes"], "artifact-size-substitution")
    need(expected_bytes is None or value["bytes"] == expected_bytes, "artifact-exact-width")
    raw = path.read_bytes()
    need(sha(raw) == value["sha256"], "artifact-content-substitution")
    return path, raw


def _python_module_path(name):
    """Resolve one repository-local import without importing or executing it."""
    relative = Path(*name.split("."))
    for base in (HERE, HERE.parent, ROOT):
        for candidate in (base / relative.with_suffix(".py"),
                          base / relative / "__init__.py"):
            if candidate.is_file():
                return candidate.absolute()
    return None


def _python_import_closure(entrypoints):
    """AST-derive the recursive local Python import closure."""
    pending = [Path(path).absolute() for path in entrypoints]
    found = []
    while pending:
        path = pending.pop()
        if path in found:
            continue
        need(path.is_file(), "python-entrypoint-source-required")
        found.append(path)
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            raise Refused("python-source-parse") from None
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.append(node.module)
        for name in names:
            local = _python_module_path(name)
            if local is not None and local not in found:
                pending.append(local)
    return sorted(found)


def _cargo_dep_info_sources(path):
    """Read Cargo's link dep-info and retain only current repository sources."""
    path = checked_file(path)
    first = path.read_text().splitlines()[0]
    need(":" in first, "cargo-dep-info-shape")
    values = first.split(":", 1)[1].strip().split()
    sources = []
    for value in values:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = RELATION / candidate
        candidate = candidate.resolve(strict=True)
        if candidate.is_relative_to(ROOT) and candidate.is_file():
            sources.append(candidate)
    need(sources, "cargo-dep-info-repository-source")
    return sources


def _rust_path_module_closure(paths):
    """Follow explicit ``#[path = ...]`` source edges absent in stale dep-info."""
    pending = [Path(path).resolve(strict=True) for path in paths
               if Path(path).suffix == ".rs"]
    found = set(pending)
    while pending:
        path = pending.pop()
        for relative in re.findall(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]',
                                   path.read_text()):
            child = (path.parent / relative).resolve(strict=True)
            need(child.suffix == ".rs" and child.is_file(),
                 "rust-explicit-path-source")
            if child not in found:
                found.add(child)
                pending.append(child)
    return sorted(found)


def source_paths():
    """Return the finite import/dep-info-derived executed-source closure.

    Generated Cargo outputs and archived evidence are inputs to separate build
    receipts, never silently admitted as source.  Dynamic imports, subprocess
    adapters and authenticated runtime assets are explicit because AST/Cargo
    dep-info cannot discover those edges.
    """
    entrypoints = [
        HERE / "offline_w1_fixture.py",
        HERE / "offline_w1_components.py",
        HERE / "freeze_offline_w1_rust_build.py",
        HERE / "freeze_offline_w1_verifier_build.py",
    ]
    paths = _python_import_closure(entrypoints)
    paths += [
        # importlib-loaded Python modules
        HERE.parent / "private_batch/intent.py",
        HERE.parent / "integration/trees.py",
        HERE.parent / "verification/wire.py",
        HERE.parents[1] / "future-recipient/v2/recipient.py",
        # C1 production identity/preimage definitions mirrored by the fixture
        HERE / "c1_capture_supervisor.py",
        HERE / "c1_contact_value_authority.cpp",
        HERE / "c1_contact_value_authority.hpp",
        # JS/native subprocess adapters and their authenticated runtime inputs
        HERE / "owner_authority.mjs",
        retained.LEAF_MAP,
        retained.NODE,
        retained.CRYPTO,
        component_run.AUTH / "harness/worker.mjs",
        component_run.AUTH / "source-bridge/signature-component-adapter-selected.mjs",
    ]
    paths += [component_run.BUILD / name for name in sorted(component_run.PINS)]
    for dep_info in (
        PROBE_DEP_INFO,
        OWNER_AUX_DEP_INFO,
        AUTH_EXIT_DEP_INFO,
        VERIFIER_DEP_INFO,
    ):
        paths += _cargo_dep_info_sources(dep_info)
    paths += _rust_path_module_closure(paths)
    rust_roots = {
        RELATION,
        ROOT / "poc/local-private-payment/native-authority/native-core",
        ROOT / "poc/local-private-payment/native-authority/vendor/native-relation",
        HERE / "auth_exit",
    }
    for root in rust_roots:
        paths += [path for name in ("Cargo.toml", "Cargo.lock", "build.rs")
                  if (path := root / name).is_file()]
    paths = sorted(set(Path(path).resolve(strict=True) for path in paths))
    need(all(path.is_file() and not path.is_symlink() for path in paths),
         "source-closure-member-file")
    # Repository sources may not come from generated/archive trees. External
    # authenticated binaries/assets are separately content-pinned above.
    repository_paths = [path for path in paths
                        if path.is_relative_to(ROOT / "poc")
                        or path.is_relative_to(ROOT / "research")]
    need(all(not ({"target", "evidence", ".git"} & set(path.parts))
             for path in repository_paths),
         "source-closure-no-generated-or-archive-path")
    return paths


def source_refs():
    return [ref(path) for path in source_paths()]


def owner_aux_build_bundle():
    """Reverify the exact current-source FR32V2 owner-aux build bundle."""
    checked_file(OWNER_AUX, mode=0o500)
    binary = ref(OWNER_AUX, OWNER_AUX_SHA)
    dep_info = ref(OWNER_AUX_DEP_INFO, OWNER_AUX_DEP_INFO_SHA)
    build_receipt = ref(
        OWNER_AUX_BUILD_RECEIPT, OWNER_AUX_BUILD_RECEIPT_SHA)
    source_closure = ref(
        OWNER_AUX_SOURCE_CLOSURE, OWNER_AUX_SOURCE_CLOSURE_SHA)
    build_command = ref(
        OWNER_AUX_BUILD_COMMAND, OWNER_AUX_BUILD_COMMAND_SHA)
    build_stdout = ref(
        OWNER_AUX_BUILD_STDOUT, OWNER_AUX_BUILD_STDOUT_SHA)
    build_stderr = ref(
        OWNER_AUX_BUILD_STDERR, OWNER_AUX_BUILD_STDERR_SHA)
    build_time = ref(OWNER_AUX_BUILD_TIME, OWNER_AUX_BUILD_TIME_SHA)
    receipt_raw = read_exact(
        OWNER_AUX_BUILD_RECEIPT, OWNER_AUX_BUILD_RECEIPT_SHA)
    source_raw = read_exact(
        OWNER_AUX_SOURCE_CLOSURE, OWNER_AUX_SOURCE_CLOSURE_SHA)
    command_raw = read_exact(
        OWNER_AUX_BUILD_COMMAND, OWNER_AUX_BUILD_COMMAND_SHA)
    receipt, source, command = map(
        parse, (receipt_raw, source_raw, command_raw))
    need(receipt_raw == canonical(receipt)
         and source_raw == canonical(source)
         and command_raw == canonical(command),
         "owner-aux-build-canonical-json")

    expected_command = {
        "schema": "kpb-offline-w1-owner-aux-build-command/v1",
        "cwd": str(RELATION),
        "executable": (
            "/home/luke/.rustup/toolchains/"
            "stable-x86_64-unknown-linux-gnu/bin/cargo"
        ),
        "argv": [
            "/home/luke/.rustup/toolchains/"
            "stable-x86_64-unknown-linux-gnu/bin/cargo",
            "build", "--locked", "--offline", "--release",
            "--bin", "owner_aux",
        ],
        "environment": {
            "PATH": (
                "/home/luke/.rustup/toolchains/"
                "stable-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin"
            ),
            "CARGO_HOME": "/home/luke/.cargo",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(
                ROOT / ".local/private-batch-owner-aux-target-20261029-04"
            ),
            "LANG": "C.UTF-8",
            "TZ": "UTC",
        },
    }
    need(command == expected_command,
         "owner-aux-exact-build-command")
    need(set(source) == {
        "schema", "classification", "derivation", "dep_info_sha256",
        "member_count", "members_identity_sha256", "members",
    } and source["schema"]
         == "kpb-offline-w1-owner-aux-source-closure/v1"
         and source["classification"] == CLASSIFICATION
         and source["derivation"] == (
             "cargo-link-dep-info-plus-local-package-manifests-lockfiles-and-build-scripts"
         )
         and source["dep_info_sha256"] == OWNER_AUX_DEP_INFO_SHA
         and source["member_count"] == 37
         and source["members_identity_sha256"]
         == OWNER_AUX_SOURCE_MEMBERS_SHA
         and sha(canonical(source["members"]))
         == OWNER_AUX_SOURCE_MEMBERS_SHA,
         "owner-aux-source-closure-header")
    expected_sources = set(_cargo_dep_info_sources(OWNER_AUX_DEP_INFO))
    for package in (
        RELATION,
        ROOT / "poc/local-private-payment/native-authority/native-core",
        ROOT / "poc/local-private-payment/native-authority/vendor/native-relation",
    ):
        for name in ("Cargo.toml", "Cargo.lock", "build.rs"):
            path = package / name
            if path.is_file():
                expected_sources.add(path.resolve(strict=True))
    actual_sources = []
    for member in source["members"]:
        path, _ = read_ref(member)
        actual_sources.append(path.resolve(strict=True))
    need(actual_sources == sorted(actual_sources)
         and len(actual_sources) == len(set(actual_sources)) == 37
         and set(actual_sources) == expected_sources,
         "owner-aux-dep-info-exact-source-set")

    toolchain = receipt.get("toolchain", {})
    need(receipt == {
        "schema": "kpb-offline-w1-owner-aux-build-receipt/v1",
        "classification": CLASSIFICATION,
        "build_profile": "release",
        "locked": True,
        "offline": True,
        "binary": binary,
        "dep_info": dep_info,
        "source_closure": {
            **source_closure,
            "members_identity_sha256": OWNER_AUX_SOURCE_MEMBERS_SHA,
            "member_count": 37,
        },
        "build_command": build_command,
        "build_stdout": build_stdout,
        "build_stderr": build_stderr,
        "build_time": build_time,
        "toolchain": toolchain,
        "source_snapshot_equal_before_after_build": True,
        "all_source_mtimes_not_newer_than_binary": True,
        "proving_key_read": False,
        "matrix_synthesized": False,
        "fixture_or_trial_read": False,
        "network_enabled": False,
        "authorization": False,
        "privacy_or_financial_acceptance": False,
    } and toolchain["cargo_version"] == VERIFIER_CARGO_VERSION
         and toolchain["rustc_vv_sha256"] == VERIFIER_RUSTC_VV_SHA
         and sha(toolchain["rustc_vv"].encode()) == VERIFIER_RUSTC_VV_SHA,
         "owner-aux-build-receipt-exact")
    need(sha(subprocess.run(
        ["rustc", "-Vv"], check=True, capture_output=True,
    ).stdout) == VERIFIER_RUSTC_VV_SHA
         and subprocess.run(
             ["cargo", "-V"], check=True, capture_output=True, text=True,
         ).stdout.strip() == VERIFIER_CARGO_VERSION,
         "owner-aux-current-toolchain")
    return {
        "binary": binary,
        "dep_info": dep_info,
        "build_receipt": build_receipt,
        "source_closure": source_closure,
        "build_command": build_command,
        "build_stdout": build_stdout,
        "build_stderr": build_stderr,
        "build_time": build_time,
        "source_members_identity_sha256": OWNER_AUX_SOURCE_MEMBERS_SHA,
        "rustc_vv_sha256": VERIFIER_RUSTC_VV_SHA,
        "cargo_version": VERIFIER_CARGO_VERSION,
        "current_source_build_reverified": True,
        "verification_or_proof_claim": False,
    }


def verifier_build_bundle():
    """Reverify the exact Rust verifier build; its own receipt is not authority."""
    binary = ref(VERIFIER_BINARY, VERIFIER_BINARY_SHA)
    dep_info = ref(VERIFIER_DEP_INFO, VERIFIER_DEP_INFO_SHA)
    build_receipt = ref(VERIFIER_BUILD_RECEIPT, VERIFIER_BUILD_RECEIPT_SHA)
    source_closure = ref(VERIFIER_SOURCE_CLOSURE, VERIFIER_SOURCE_CLOSURE_SHA)
    build_command = ref(VERIFIER_BUILD_COMMAND, VERIFIER_BUILD_COMMAND_SHA)

    receipt_raw = read_exact(VERIFIER_BUILD_RECEIPT, VERIFIER_BUILD_RECEIPT_SHA)
    source_raw = read_exact(VERIFIER_SOURCE_CLOSURE, VERIFIER_SOURCE_CLOSURE_SHA)
    command_raw = read_exact(VERIFIER_BUILD_COMMAND, VERIFIER_BUILD_COMMAND_SHA)
    receipt, source, command = map(parse, (receipt_raw, source_raw, command_raw))
    need(receipt_raw == canonical(receipt)
         and source_raw == canonical(source)
         and command_raw == canonical(command),
         "verifier-build-canonical-json")

    expected_command = {
        "schema": "kpb-offline-w1-verifier-build-command/v1",
        "cwd": str(RELATION),
        "argv": [
            "cargo", "build", "--locked", "--offline", "--release",
            "--features", "offline-w1-verifier", "--example",
            "verify_offline_w1_aggregate",
        ],
        "environment": {
            "CARGO_TARGET_DIR": str(
                ROOT / ".local/private-batch-w1-verifier-target-20261029-03"
            ),
            "KPB_CARGO_VERSION": VERIFIER_CARGO_VERSION,
            "KPB_RUSTC_VV_SHA256": VERIFIER_RUSTC_VV_SHA,
            "KPB_SOURCE_CLOSURE_SHA256": VERIFIER_SOURCE_MEMBERS_SHA,
        },
        "self_hash_environment_name": "KPB_BUILD_COMMAND_SHA256",
    }
    need(command == expected_command
         and sha(command_raw) == VERIFIER_BUILD_COMMAND_SHA,
         "verifier-exact-build-command")

    need(set(source) == {
        "schema", "classification", "derivation", "dep_info_sha256",
        "member_count", "members_identity_sha256", "members",
    }
         and source["schema"] == "kpb-offline-w1-verifier-source-closure/v1"
         and source["classification"] == RUST_RECEIPT_CLASSIFICATION
         and source["derivation"] == (
             "cargo-link-dep-info-plus-local-package-manifests-lockfiles-and-build-scripts"
         )
         and source["dep_info_sha256"] == VERIFIER_DEP_INFO_SHA
         and source["member_count"] == 46
         and source["members_identity_sha256"] == VERIFIER_SOURCE_MEMBERS_SHA
         and sha(canonical(source["members"])) == VERIFIER_SOURCE_MEMBERS_SHA,
         "verifier-source-closure-header")
    expected_sources = set(_cargo_dep_info_sources(VERIFIER_DEP_INFO))
    for package in (
        RELATION,
        ROOT / "poc/local-private-payment/native-authority/native-core",
        ROOT / "poc/local-private-payment/native-authority/vendor/native-relation",
        HERE / "auth_exit",
    ):
        for name in ("Cargo.toml", "Cargo.lock", "build.rs"):
            path = package / name
            if path.is_file():
                expected_sources.add(path.resolve(strict=True))
    actual_sources = []
    for member in source["members"]:
        path, _ = read_ref(member)
        actual_sources.append(path.resolve(strict=True))
    need(actual_sources == sorted(actual_sources)
         and len(actual_sources) == len(set(actual_sources)) == 46
         and set(actual_sources) == expected_sources,
         "verifier-dep-info-exact-source-set")

    expected_receipt_keys = {
        "schema", "classification", "feature", "build_profile", "locked",
        "offline", "binary", "dep_info", "build_command", "source_closure",
        "toolchain", "compiled_bindings", "running_inode_hash_source",
        "offline_synthetic_provenance_enforced",
        "build_bundle_reverified_by_binary", "network_enabled",
        "proving_key_read", "proof_generated", "private_fixture_read",
        "authorization", "privacy_or_financial_acceptance",
    }
    need(set(receipt) == expected_receipt_keys
         and receipt["schema"] == "kpb-offline-w1-verifier-build-receipt/v1"
         and receipt["classification"] == RUST_RECEIPT_CLASSIFICATION
         and receipt["feature"] == "offline-w1-verifier"
         and receipt["build_profile"] == "release"
         and receipt["locked"] is receipt["offline"] is True
         and receipt["binary"] == binary
         and receipt["dep_info"] == dep_info
         and receipt["build_command"] == build_command
         and receipt["source_closure"] == {
             **source_closure,
             "members_identity_sha256": VERIFIER_SOURCE_MEMBERS_SHA,
             "member_count": 46,
         }
         and receipt["compiled_bindings"] == {
             "rustc_vv_sha256": VERIFIER_RUSTC_VV_SHA,
             "cargo_version": VERIFIER_CARGO_VERSION,
             "source_closure_sha256": VERIFIER_SOURCE_MEMBERS_SHA,
             "build_command_sha256": VERIFIER_BUILD_COMMAND_SHA,
         }
         and receipt["toolchain"]["rustc_vv_sha256"] == VERIFIER_RUSTC_VV_SHA
         and receipt["toolchain"]["cargo_version"] == VERIFIER_CARGO_VERSION
         and sha(receipt["toolchain"]["rustc_vv"].encode()) == VERIFIER_RUSTC_VV_SHA
         and receipt["running_inode_hash_source"] == "/proc/self/exe"
         and receipt["offline_synthetic_provenance_enforced"] is False
         and receipt["build_bundle_reverified_by_binary"] is False
         and all(receipt[name] is False for name in (
             "network_enabled", "proving_key_read", "proof_generated",
             "private_fixture_read", "authorization",
             "privacy_or_financial_acceptance",
         )), "verifier-build-receipt-exact")
    need(sha(subprocess.run(
        ["rustc", "-Vv"], check=True, capture_output=True,
    ).stdout) == VERIFIER_RUSTC_VV_SHA
         and subprocess.run(
             ["cargo", "-V"], check=True, capture_output=True, text=True,
         ).stdout.strip() == VERIFIER_CARGO_VERSION,
         "verifier-current-toolchain")
    return {
        "binary": binary,
        "dep_info": dep_info,
        "build_receipt": build_receipt,
        "source_closure": source_closure,
        "build_command": build_command,
        "feature": "offline-w1-verifier",
        "source_members_identity_sha256": VERIFIER_SOURCE_MEMBERS_SHA,
        "rustc_vv_sha256": VERIFIER_RUSTC_VV_SHA,
        "cargo_version": VERIFIER_CARGO_VERSION,
        "verification_only": True,
        "offline_synthetic_provenance_enforced_by_binary": False,
    }


def selected_build():
    owner_aux = owner_aux_build_bundle()
    output_manifest_raw = read_exact(OUTPUT_PARAMETERS / "MANIFEST.json", OUTPUT_MANIFEST_SHA)
    output_manifest = parse(output_manifest_raw)
    need(
        output_manifest["schema"] == "kpb-new-wallet-parameters/v1"
        and output_manifest["role"] == "new-output"
        and output_manifest["pk_sha256"] == OUTPUT_PK_SHA
        and output_manifest["vk_sha256"] == OUTPUT_VK_SHA
        and output_manifest["matrix_sha256"] == OUTPUT_MATRIX_SHA
        and len(bytes.fromhex(output_manifest["vk_hex328"])) == 328
        and sha(bytes.fromhex(output_manifest["vk_hex328"])) == OUTPUT_VK_SHA,
        "one-exact-output-build",
    )
    aggregate_manifest_raw = read_exact(
        AGGREGATE_PARAMETERS / "PUBLIC-AGGREGATE-PARAMS.json", AGGREGATE_MANIFEST_SHA
    )
    aggregate_manifest = parse(aggregate_manifest_raw)
    need(
        aggregate_manifest["schema"] == "kpi-stock-financial-aggregate-setup/v1"
        and aggregate_manifest["canonical_r1cs_fingerprint"] == AGGREGATE_MATRIX_SHA
        and aggregate_manifest["num_constraints"] == 13_093_029
        and aggregate_manifest["model_variables"] == 12_949_821
        and aggregate_manifest["pk"]["compressed_sha256"] == AGGREGATE_PK_GZ_SHA
        and aggregate_manifest["pk"]["uncompressed_sha256"] == AGGREGATE_PK_SHA
        and aggregate_manifest["vk"]["sha256"] == AGGREGATE_VK_SHA
        and aggregate_manifest["aggregate_proof_generated"] is False
        and aggregate_manifest["native_financial_acceptance"] is False,
        "one-exact-aggregate-feasibility-build",
    )
    output = {
        "schema": "kpb-offline-w1-selected-build/v1",
        "output": {
            "binary": ref(OUTPUT_BINARY, OUTPUT_BINARY_SHA),
            "manifest": ref(OUTPUT_PARAMETERS / "MANIFEST.json", OUTPUT_MANIFEST_SHA),
            "proving_key": ref(OUTPUT_PARAMETERS / "parameters.pk", OUTPUT_PK_SHA),
            "verification_key": {
                "hex328": output_manifest["vk_hex328"],
                "sha256": OUTPUT_VK_SHA,
                "bytes": 328,
            },
            "matrix_sha256": OUTPUT_MATRIX_SHA,
            "owner_aux_binary": owner_aux["binary"],
            "owner_aux_build": owner_aux,
        },
        "signature": {
            "matrix_sha256": SIGNATURE_MATRIX_SHA,
            "mapping_sha256": SIGNATURE_MAP_SHA,
        },
        "aggregate_feasibility_only": {
            "manifest": ref(
                AGGREGATE_PARAMETERS / "PUBLIC-AGGREGATE-PARAMS.json",
                AGGREGATE_MANIFEST_SHA,
            ),
            "proving_key_gzip": manifest_declared_ref(
                AGGREGATE_PARAMETERS / "AGGREGATE-PK.bin.gz",
                AGGREGATE_PK_GZ_SHA,
                aggregate_manifest["pk"]["compressed_bytes"],
            ),
            "proving_key_gzip_content_rehashed_during_selection": False,
            "canonical_decoded_pk_sha256": AGGREGATE_PK_SHA,
            "canonical_decoded_pk_bytes": 2_608_842_576,
            "verification_key": ref(
                AGGREGATE_PARAMETERS / "AGGREGATE-VK.bin", AGGREGATE_VK_SHA
            ),
            "matrix_sha256": AGGREGATE_MATRIX_SHA,
            "native_tail": ref(NATIVE_TAIL, NATIVE_TAIL_SHA),
            "privacy_security_or_ceremony_eligible": False,
        },
        "offline_aggregate_verifier": verifier_build_bundle(),
        "historical_binary_provenance": {
            "pinned_artifact_content_hashes_verified": True,
            "current_source_closure_build_receipt_present": False,
            "current_source_closure_builds_pinned_binaries_claimed": False,
            "source_runtime_freshness_proven": False,
            "rebuild_and_repin_required_for_fresh_provenance": True,
            "owner_aux_current_source_build_separately_reverified": True,
        },
    }
    output["build_identity_sha256"] = sha(canonical(output))
    return output


def output_verifier_from_plan(plan):
    """Construct the exact pinned Output verifier; no proving key is mounted on verify."""
    _, profile_raw = read_ref(plan["profile"])
    profile_value = parse(profile_raw)
    profile = wallet.Profile(
        bytes.fromhex(profile_value["profile_descriptor"]["domain_hex32"]),
        bytes.fromhex(profile_value["profile_id_hex32"]),
    )
    build = plan["selected_build"]["output"]
    binary, manifest, proving_key = (
        checked_file(build[name]["path"])
        for name in ("binary", "manifest", "proving_key")
    )

    def read_public(path, expected=None):
        return read_exact(path, expected)

    return output_producer.OutputProver(
        profile,
        binary,
        build["binary"]["sha256"],
        manifest,
        build["manifest"]["sha256"],
        proving_key,
        read_public=read_public,
    )


def fresh_id():
    return str(uuid.uuid4())


def fixed_rewire():
    value = {
        "schema": "kpb-fixed-w1-rewire/v1",
        "rule": "swap-logical-owner-0-and-2 input and change destinations; keep all payment destinations and owner-1 fixed",
        "input_owner_swap": [2, 1, 0],
        "payment_owner_map": [0, 1, 2],
        "change_owner_swap": [2, 1, 0],
        "round2_selected_round1_outputs": [
            {"round2_owner": 0, "round1_creator": 2, "output": "payment"},
            {"round2_owner": 1, "round1_creator": 1, "output": "change"},
            {"round2_owner": 2, "round1_creator": 1, "output": "payment"},
        ],
    }
    value["identity_sha256"] = sha(canonical(value))
    return value


def make_plan(root, label):
    need(type(label) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label), "canonical-run-label")
    root = checked_directory(root, exists=False)
    need(not root.exists(), "fresh-run-root")
    root.mkdir(parents=True, mode=0o700)
    fsync_directory(root.parent)
    build = selected_build()
    sources = source_refs()
    source_identity = sha(canonical(sources))
    run_id, epoch_id = fresh_id(), fresh_id()
    owner_generation_ids = [fresh_id() for _ in range(OWNER_COUNT)]
    rounds = []
    for number in (1, 2):
        rounds.append(
            {
                "round": number,
                "input_attempt_id": fresh_id(),
                "invoice_operation_id": fresh_id(),
                "payment_operation_id": fresh_id(),
                "scan_operation_id": fresh_id(),
                "c1_capture_attempt_id": fresh_id(),
                "c1_capture_identity_id": fresh_id(),
                "c1_cohort_hex32": secrets.token_hex(32),
                "c1_financial_run_hex32": secrets.token_hex(32),
                "aggregate_attempt_id": fresh_id(),
            }
        )
    all_ids = [run_id, epoch_id, *owner_generation_ids]
    for item in rounds:
        all_ids += [item[name] for name in item if name.endswith("_id")]
    need(len(all_ids) == len(set(all_ids)), "all-attempt-identities-fresh")
    plan = {
        "schema": PLAN_SCHEMA,
        "classification": CLASSIFICATION,
        "label": label,
        "run_id": run_id,
        "source_instance_epoch_id": epoch_id,
        "source_instance_epoch_is_authority": False,
        "owner_generation_ids": owner_generation_ids,
        "rounds": rounds,
        "selected_build": build,
        "source_members": sources,
        "source_closure_sha256": source_identity,
        "source_closure_derivation": {
            "python": "recursive-local-imports-plus-explicit-dynamic-and-subprocess-inputs",
            "rust": "cargo-link-dep-info-plus-package-manifests-locks-and-build-scripts",
            "validation_recomputes_exact_current_path_set_and_content": True,
        },
        "profile": ref(PUBLIC_PROFILE, PROFILE_SHA),
        "rehearsal": ref(PUBLIC_REHEARSAL, REHEARSAL_SHA),
        "fixed_rewire": fixed_rewire(),
        "workload": {
            "fee_sompi_each": FEE,
            "rounds": [{"round": number, **ROUND_VALUES[number]} for number in (1, 2)],
            "genuine_transfer_output_proofs": 12,
            "genuine_signature_witnesses": 6,
            "required_aggregate_proofs": 2,
        },
        "stage_order": list(STAGES),
        "boundaries": {
            "network_enabled": False,
            "funding_or_real_funds": False,
            "backing_or_chain_acceptance": False,
            "old_setup_privacy_assumption_eligible": False,
            "historical_binary_matches_current_source_proven": False,
            "fixture_possession_authorizes_v4": False,
            "future_atomic_minter_must_consume_live_w0_c1_close_sources": True,
            "caller_digest_is_common_origin_authority": False,
            "aggregate_checkpoint_enabled": True,
            "aggregate_checkpoint_requires_pinned_in_process_verifier": True,
            "aggregate_proof_generation_authorized": False,
            "aggregate_pk_content_read_during_plan_selection": False,
            "handoff_requires_two_pinned_verifier_receipts": True,
        },
    }
    plan["plan_identity_sha256"] = sha(canonical(plan))
    write_new(root / "PLAN.json", plan)
    return plan


def load_plan(root):
    root = checked_directory(root)
    raw = read_exact(root / "PLAN.json")
    plan = parse(raw)
    need(type(plan) is dict and plan.get("schema") == PLAN_SCHEMA, "plan-schema")
    identity = plan.pop("plan_identity_sha256", None)
    need(word(identity, "plan-identity") == sha(canonical(plan)), "plan-self-identity")
    plan["plan_identity_sha256"] = identity
    validate_plan(plan)
    return root, plan, sha(raw)


def validate_plan(plan):
    need(plan["classification"] == CLASSIFICATION, "plan-classification")
    exact_uuid(plan["run_id"], "plan-run-id")
    exact_uuid(plan["source_instance_epoch_id"], "plan-epoch-id")
    need(plan["source_instance_epoch_is_authority"] is False, "epoch-not-authority")
    need(len(plan["owner_generation_ids"]) == 3, "three-owner-generation-ids")
    ids = [plan["run_id"], plan["source_instance_epoch_id"], *plan["owner_generation_ids"]]
    for value in plan["owner_generation_ids"]:
        exact_uuid(value, "owner-generation-id")
    need([row["round"] for row in plan["rounds"]] == [1, 2], "two-exact-round-plans")
    for row in plan["rounds"]:
        need(set(row) == {"round", "input_attempt_id", "invoice_operation_id",
                          "payment_operation_id", "scan_operation_id",
                          "c1_capture_attempt_id", "c1_capture_identity_id",
                          "c1_cohort_hex32", "c1_financial_run_hex32",
                          "aggregate_attempt_id"}, "round-plan-fields")
        for name in row:
            if name.endswith("_id"):
                exact_uuid(row[name], "round-fresh-id")
                ids.append(row[name])
        word(row["c1_cohort_hex32"], "round-c1-cohort")
        word(row["c1_financial_run_hex32"], "round-c1-financial-run")
    need(len(ids) == len(set(ids)), "plan-replay-id")
    c1_words = [row[name] for row in plan["rounds"]
                for name in ("c1_cohort_hex32", "c1_financial_run_hex32")]
    need(len(c1_words) == len(set(c1_words)), "plan-c1-word-replay")
    need(plan["stage_order"] == list(STAGES), "fixed-stage-order")
    boundaries = plan["boundaries"]
    need(
        boundaries == {
            "network_enabled": False,
            "funding_or_real_funds": False,
            "backing_or_chain_acceptance": False,
            "old_setup_privacy_assumption_eligible": False,
            "historical_binary_matches_current_source_proven": False,
            "fixture_possession_authorizes_v4": False,
            "future_atomic_minter_must_consume_live_w0_c1_close_sources": True,
            "caller_digest_is_common_origin_authority": False,
            "aggregate_checkpoint_enabled": True,
            "aggregate_checkpoint_requires_pinned_in_process_verifier": True,
            "aggregate_proof_generation_authorized": False,
            "aggregate_pk_content_read_during_plan_selection": False,
            "handoff_requires_two_pinned_verifier_receipts": True,
        },
        "non-authoritative-boundary",
    )
    current_build = selected_build()
    need(plan["selected_build"] == current_build, "mixed-or-substituted-build")
    for value, expected in ((plan["profile"], PROFILE_SHA), (plan["rehearsal"], REHEARSAL_SHA)):
        _, raw = read_ref(value)
        need(sha(raw) == expected, "profile-rehearsal-pin")
    need(plan["source_closure_derivation"] == {
        "python": "recursive-local-imports-plus-explicit-dynamic-and-subprocess-inputs",
        "rust": "cargo-link-dep-info-plus-package-manifests-locks-and-build-scripts",
        "validation_recomputes_exact_current_path_set_and_content": True,
    }, "source-closure-derivation")
    current_sources = source_refs()
    need(plan["source_members"] == current_sources,
         "source-closure-current-exact-set-and-content")
    need(sha(canonical(plan["source_members"])) == plan["source_closure_sha256"], "source-closure")
    need(plan["fixed_rewire"] == fixed_rewire(), "fixed-rewire-substitution")
    need(plan["workload"]["rounds"] == [{"round": n, **ROUND_VALUES[n]} for n in (1, 2)], "fixed-workload")


def stage_path(root, stage):
    need(stage in STAGES, "known-stage")
    return root / (f"{STAGES.index(stage) + 1:02d}-" + stage)


def checkpoint_ref(path):
    return ref(path)


def previous_checkpoint(root, stage):
    index = STAGES.index(stage)
    if index == 0:
        return None
    previous = stage_path(root, STAGES[index - 1]) / "CHECKPOINT.json"
    need(previous.exists(), "previous-checkpoint-required")
    return checkpoint_ref(previous)


def write_checkpoint(root, plan, stage, artifacts, facts):
    """Seal a stage after semantic validation; never mint an authority."""
    target = stage_path(root, stage)
    need(not target.exists(), "fresh-stage-checkpoint")
    temporary = root / ("." + target.name + ".tmp-" + str(uuid.uuid4()))
    temporary.mkdir(mode=0o700)
    copied = {}
    try:
        for name, source in sorted(artifacts.items()):
            need(type(name) is str and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,95}", name), "artifact-name")
            source = checked_file(source)
            destination = temporary / name
            with source.open("rb") as input_file:
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                with os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(input_file, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
            copied[name] = ref(destination)
        checkpoint = {
            "schema": CHECKPOINT_SCHEMA,
            "classification": CLASSIFICATION,
            "run_id": plan["run_id"],
            "source_instance_epoch_id": plan["source_instance_epoch_id"],
            "stage": stage,
            "ordinal": STAGES.index(stage) + 1,
            "previous": previous_checkpoint(root, stage),
            "artifacts": copied,
            "facts": facts,
            "fixture_possession_authorizes_v4": False,
        }
        validate_checkpoint_semantics(checkpoint, plan, allow_temporary=temporary)
        # The admitted checkpoint names the immutable canonical route, not the
        # temporary assembly directory.  Content identities were checked above;
        # the directory rename publishes every named leaf at once.
        checkpoint["artifacts"] = {
            name: {**value, "path": str(target / name)}
            for name, value in copied.items()
        }
        checkpoint["checkpoint_identity_sha256"] = sha(canonical(checkpoint))
        write_new(temporary / "CHECKPOINT.json", checkpoint)
        fsync_directory(temporary)
        rename_no_replace(temporary, target)
        fsync_directory(root)
        return checkpoint
    except BaseException:
        # Preserve a failed temporary stage for diagnosis. It is never admitted
        # because it has no canonical stage name/checkpoint chain position.
        raise


def round_attempt(plan, round_number):
    need(round_number in (1, 2), "round-number")
    return plan["rounds"][round_number - 1]


def validate_checkpoint_semantics(checkpoint, plan, allow_temporary=None):
    need(checkpoint["schema"] == CHECKPOINT_SCHEMA and checkpoint["classification"] == CLASSIFICATION, "checkpoint-header")
    need(checkpoint["run_id"] == plan["run_id"] and checkpoint["source_instance_epoch_id"] == plan["source_instance_epoch_id"], "checkpoint-run-epoch")
    stage = checkpoint["stage"]
    need(stage in STAGES and checkpoint["ordinal"] == STAGES.index(stage) + 1, "checkpoint-stage")
    need(checkpoint["fixture_possession_authorizes_v4"] is False, "checkpoint-not-authority")
    roots = [allow_temporary] if allow_temporary is not None else []
    for value in checkpoint["artifacts"].values():
        path, _ = read_ref(value)
        if roots:
            need(path.parent == roots[0], "stage-artifact-route")
    facts = checkpoint["facts"]
    need(type(facts) is dict, "checkpoint-facts")
    if stage == "bootstrap":
        validate_bootstrap(checkpoint["artifacts"], facts, plan)
    elif stage.endswith("-inputs"):
        number = int(stage[6])
        validate_round_inputs(checkpoint["artifacts"], facts, plan, number)
    elif stage.endswith("-components"):
        number = int(stage[6])
        validate_round_components(checkpoint["artifacts"], facts, plan, number, aggregate=False)
    elif stage.endswith("-close"):
        number = int(stage[6])
        validate_round_close(checkpoint["artifacts"], facts, plan, number)
    elif stage.endswith("-aggregate"):
        number = int(stage[6])
        validate_aggregate(checkpoint["artifacts"], facts, plan, number)
    elif stage == "handoff":
        raise Refused("handoff-disabled-until-both-aggregate-proofs-cryptographically-verified")


def json_artifact(artifacts, name):
    need(name in artifacts, "required-artifact-" + name)
    _, raw = read_ref(artifacts[name])
    return parse(raw), raw


def bytes_artifact(artifacts, name, size=None):
    need(name in artifacts, "required-artifact-" + name)
    _, raw = read_ref(artifacts[name], expected_bytes=size)
    return raw


def validate_bootstrap(artifacts, facts, plan):
    need(set(artifacts) == {
        "public-history.json", "native-tail.bin",
        *{f"owner-{owner}-{leaf}.json" for owner in range(3)
          for leaf in ("backup", "initial")},
    }, "bootstrap-exact-artifact-set")
    need(set(facts) == {"owner_generation_ids", "physical_to_w1_logical", "genuine_initial_output_proofs"}, "bootstrap-facts")
    need(facts["owner_generation_ids"] == plan["owner_generation_ids"], "bootstrap-owner-generation-binding")
    need(facts["physical_to_w1_logical"] == [2, 1, 0], "bootstrap-fixed-honest-role-swap")
    need(facts["genuine_initial_output_proofs"] == 3, "bootstrap-three-output-proofs")
    seeds, cms, backups, initials = [], [], [], []
    for owner in range(3):
        backup, _ = json_artifact(artifacts, f"owner-{owner}-backup.json")
        initial, _ = json_artifact(artifacts, f"owner-{owner}-initial.json")
        need(
            set(backup) == {"schema", "owner_generation_id",
                            "logical_owner", "seed_hex32",
                            "synthetic_unfunded"}
            and set(initial) == {"schema", "owner_generation_id",
                                 "logical_owner", "invoice_hex208",
                                 "tuple_hex520", "note_hex168",
                                 "blind_hex32", "genuine_output_proof",
                                 "funding_or_backing"}
            and backup["schema"] == "kpb-offline-w1-fresh-owner/v1"
            and backup["owner_generation_id"] == plan["owner_generation_ids"][owner]
            and backup["logical_owner"] == owner
            and backup["synthetic_unfunded"] is True
            and initial["schema"] == "kpb-offline-w1-initial-output/v1"
            and initial["owner_generation_id"] == backup["owner_generation_id"]
            and initial["logical_owner"] == owner
            and initial["genuine_output_proof"] is True
            and initial["funding_or_backing"] is False,
            "fresh-owner-source-binding",
        )
        seed = bytes.fromhex(backup["seed_hex32"])
        row = bytes.fromhex(initial["tuple_hex520"])
        need(len(seed) == 32 and seed != bytes(32) and len(row) == 520, "fresh-owner-width")
        seeds.append(seed)
        cms.append(row[:32])
        backups.append(backup)
        initials.append(initial)
    need(len(set(seeds)) == 3 and len(set(cms)) == 3, "fresh-distinct-owners-and-initial-cms")
    verifier = output_verifier_from_plan(plan)
    modules = wallet.authenticate_js(
        retained.LEAF_MAP, retained.LEAF_MAP_SHA, retained.JS_ROOT)
    crypto = wallet.Crypto(retained.CRYPTO)
    try:
        with wallet.Authority(retained.NODE, modules) as authority:
            for owner, (backup, initial) in enumerate(zip(backups, initials)):
                receiver = wallet.Receiver(
                    bytes.fromhex(backup["seed_hex32"]), verifier.profile,
                    crypto, authority)
                row = bytes.fromhex(initial["tuple_hex520"])
                note = bytes.fromhex(initial["note_hex168"])
                invoice = bytes.fromhex(initial["invoice_hex208"])
                blind = bytes.fromhex(initial["blind_hex32"])
                receipt = receiver.open(row[96:360])
                derived = verifier._call("derive-output", b"", {
                    "note_hex168": note.hex(),
                    "blinding_hex32": blind.hex(),
                    "cf_hash_hex32": row[360:392].hex(),
                })
                statement = bytes.fromhex(derived["statement_hex168"])
                need(len(invoice) == 208 and len(note) == 168
                     and blind == bytes(32)
                     and invoice == receiver.invoice(0).encode()
                     and receipt.index == 0
                     and receipt.note_bytes() == note
                     and receipt.commitment() == row[:32]
                     and statement[40:136] == row[:96]
                     and verifier.verify(row),
                     "bootstrap-output-proof-cryptographic-verification")
    except (wallet.Invalid, ValueError, TypeError, KeyError):
        raise Refused("bootstrap-source-owner-rederivation") from None
    history, history_raw = json_artifact(artifacts, "public-history.json")
    tail = bytes_artifact(artifacts, "native-tail.bin")
    _, selected_tail = read_ref(
        plan["selected_build"]["aggregate_feasibility_only"]["native_tail"])
    replayed = replay_public_history(history, plan, verifier, {})
    need(history_raw == canonical(history) and tail == selected_tail
         and history["transitions"] == []
         and history["genesis"]["outputs_hex520"]
         == [initial["tuple_hex520"] for initial in initials]
         and history["head"] == {
             name: history["genesis"][name] for name in (
                 "outpoint_hex36", "state_hex112", "reserve_sompi")}
         and replayed.head.encode()[160:196].hex()
         == history["head"]["outpoint_hex36"],
         "bootstrap-public-history-rederivation")


def validate_round_inputs(artifacts, facts, plan, round_number):
    expected = round_attempt(plan, round_number)
    need(facts == {"round": round_number, "attempt": expected, "input_count": 3}, "round-input-facts")
    seen, values = [], []
    required = {
        "schema", "round", "logical_owner", "input_attempt_id",
        "note_hex168", "nk_hex32", "position", "path_hex32",
        "cv_hex64", "blind_hex32", "ak_hex64", "nf_hex32",
        "selected_tuple_sha256", "input_value_sompi", "receipt_index",
        "source_history_sha256",
    }
    for owner in range(3):
        value, _ = json_artifact(artifacts, f"owner-{owner}-input.json")
        need(
            set(value) == required
            and value["schema"] == "kpb-offline-w1-owner-input/v1"
            and value["round"] == round_number
            and value["logical_owner"] == owner
            and value["input_attempt_id"] == expected["input_attempt_id"],
            "round-input-source-binding",
        )
        seen.append(bytes.fromhex(value["nf_hex32"]))
        values.append(value)
    need(all(len(value) == 32 and value != bytes(32) for value in seen) and len(set(seen)) == 3, "round-distinct-input-nfs")
    any_path = Path(next(iter(artifacts.values()))["path"])
    root = any_path.parent.parent
    bootstrap = checkpoint_from_root(root, "bootstrap")
    if round_number == 1:
        history_value, history_raw = json_artifact(
            bootstrap["artifacts"], "public-history.json")
    else:
        prior = checkpoint_from_root(root, "round-1-close")
        history_value, history_raw = json_artifact(
            prior["artifacts"], "public-history-after.json")
    verifier = output_verifier_from_plan(plan)
    history = replay_public_history(history_value, plan, verifier, {})
    modules = wallet.authenticate_js(
        retained.LEAF_MAP, retained.LEAF_MAP_SHA, retained.JS_ROOT)
    crypto = wallet.Crypto(retained.CRYPTO)
    try:
        with wallet.Authority(retained.NODE, modules) as authority:
            for owner, selected in enumerate(values):
                backup, _ = json_artifact(
                    bootstrap["artifacts"], f"owner-{owner}-backup.json")
                receiver = wallet.Receiver(
                    bytes.fromhex(backup["seed_hex32"]), verifier.profile,
                    crypto, authority)
                claim = wallet_history.select_for_round(
                    history.recover(receiver), round_number, owner)
                row = history.rows[claim.position]
                keys = receiver.keys(claim.receipt.index)
                blind = bytes.fromhex(selected["blind_hex32"])
                derived = verifier._call("derive-output", b"", {
                    "note_hex168": claim.receipt.note_bytes().hex(),
                    "blinding_hex32": blind.hex(),
                    "cf_hash_hex32": row[360:392].hex(),
                })
                statement = bytes.fromhex(derived["statement_hex168"])
                need(selected == {
                    "schema": "kpb-offline-w1-owner-input/v1",
                    "round": round_number,
                    "logical_owner": owner,
                    "input_attempt_id": expected["input_attempt_id"],
                    "note_hex168": claim.receipt.note_bytes().hex(),
                    "nk_hex32": keys.nf_secret.hex(),
                    "position": claim.position,
                    "path_hex32": [part.hex() for part in claim.path],
                    "cv_hex64": statement[72:136].hex(),
                    "blind_hex32": blind.hex(),
                    "ak_hex64": keys.owner_key.hex(),
                    "nf_hex32": claim.nf.hex(),
                    "selected_tuple_sha256": sha(row),
                    "input_value_sompi": claim.receipt.value_sompi,
                    "receipt_index": claim.receipt.index,
                    "source_history_sha256": sha(history_raw),
                } and len(blind) == 32
                     and int.from_bytes(blind, "little") < output_producer.Q,
                     "round-input-source-history-rederivation")
    except (wallet.Invalid, ValueError, TypeError, KeyError):
        raise Refused("round-input-source-history-rederivation") from None


def strict_owner_record(value, round_number, owner):
    """Parse the exact clear owner record without treating it as authority."""
    need(type(value) is dict and set(value) == {
        "schema", "owner_component", "input", "fee_sompi", "nonce_hex32",
        "outputs", "private_delta_hex32", "intent_hex1460", "signature",
        "signature_inputs",
    }, "owner-record-fields")
    need(value["schema"] == "kpb-private-original-owner-record/v1",
         "owner-record-schema")
    need(value["owner_component"] == owner and round_number in (1, 2),
         "owner-record-round-owner")
    need(value["fee_sompi"] == FEE, "owner-record-fee")
    need(type(value["input"]) is dict and set(value["input"]) == {
        "note_hex168", "nk_hex32", "position", "path_hex32", "cv_hex64",
        "blind_hex32", "ak_hex64", "nf_hex32",
    }, "owner-record-input-fields")
    need(type(value["outputs"]) is list and len(value["outputs"]) == 2
         and all(type(row) is dict and set(row) == {
             "tuple_hex520", "note_hex168", "blind_hex32",
         } for row in value["outputs"]), "owner-record-output-fields")
    try:
        raw_intent = bytes.fromhex(value["intent_hex1460"])
        nonce = bytes.fromhex(value["nonce_hex32"])
        delta = bytes.fromhex(value["private_delta_hex32"])
        output_rows = [bytes.fromhex(row["tuple_hex520"])
                       for row in value["outputs"]]
        output_notes = [bytes.fromhex(row["note_hex168"])
                        for row in value["outputs"]]
        output_blinds = [bytes.fromhex(row["blind_hex32"])
                         for row in value["outputs"]]
    except (TypeError, ValueError):
        raise Refused("owner-record-canonical-hex") from None
    need(len(raw_intent) == 1460 and len(nonce) == 32
         and nonce != bytes(32) and len(delta) == 32
         and int.from_bytes(delta, "little") < output_producer.Q
         and all(len(row) == 520 for row in output_rows)
         and len(set(row[:32] for row in output_rows)) == 2
         and all(len(note) == 168 for note in output_notes)
         and all(len(blind) == 32
                 and int.from_bytes(blind, "little") < output_producer.Q
                 for blind in output_blinds), "owner-record-width-range")
    need(type(value["signature"]) is dict
         and set(value["signature"]) == {"owner_key_hex64", "R8", "S"}
         and type(value["signature_inputs"]) is dict
         and set(value["signature_inputs"]) == {
             "digestLimbs", "ownerKeyBytes", "sigR8", "sigS",
             "preimageA", "preimageR8",
         }, "owner-record-signature-fields")
    return value


def _canonical_field_decimal(value, category):
    need(type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value),
         category)
    number = int(value)
    need(number < SIGNATURE_FIELD, category)
    return number


def parse_signature_model(matrix_raw, mapping_raw):
    """Strictly parse the one pinned normalized EdDSA R1CS and public map."""
    need(sha(matrix_raw) == SIGNATURE_MATRIX_SHA
         and sha(mapping_raw) == SIGNATURE_MAP_SHA,
         "signature-model-pins")
    matrix, mapping = parse(matrix_raw), parse(mapping_raw)
    need(matrix_raw == canonical(matrix) and mapping_raw == canonical(mapping),
         "signature-model-canonical-json")
    need(type(matrix) is dict and set(matrix) == {
        "schema", "field", "n8", "nVars", "nInstances", "nWitnesses",
        "nOutputs", "nPublicInputs", "nDeclaredPrivateInputs", "nLabels",
        "nConstraints", "rows", "wireToLabel", "mappingSha256",
    } and matrix["schema"] == "kpi-signature-normalized-r1cs/v1"
         and matrix["field"] == str(SIGNATURE_FIELD)
         and matrix["n8"] == 32
         and matrix["nVars"] == SIGNATURE_VARIABLES
         and matrix["nInstances"] == SIGNATURE_INSTANCES
         and matrix["nWitnesses"] == SIGNATURE_VARIABLES - SIGNATURE_INSTANCES
         and matrix["nOutputs"] == 0 and matrix["nPublicInputs"] == 66
         and matrix["nDeclaredPrivateInputs"] == 7
         and matrix["nConstraints"] == SIGNATURE_ROWS
         and matrix["mappingSha256"] == SIGNATURE_MAP_SHA
         and type(matrix["rows"]) is list
         and len(matrix["rows"]) == SIGNATURE_ROWS
         and type(matrix["wireToLabel"]) is list
         and len(matrix["wireToLabel"]) == SIGNATURE_VARIABLES,
         "signature-matrix-exact-shape")
    need(type(mapping) is dict and set(mapping) == {
        "schema", "one", "publicMap", "privateSuffixStart",
        "privateSuffixPolicy",
    } and mapping["schema"] == "kpi-signature-public-permutation/v1"
         and mapping["one"] == 0 and mapping["privateSuffixStart"] == 67
         and mapping["privateSuffixPolicy"] == "identity",
         "signature-map-exact-shape")
    expected_public = [
        {"canonical": index + 1, "name": name, "raw": index + 1}
        for index, name in enumerate([
            "main.digestLimbs[0]", "main.digestLimbs[1]",
            *(f"main.ownerKeyBytes[{at}]" for at in range(64)),
        ])
    ]
    need(mapping["publicMap"] == expected_public,
         "signature-map-exact-public-prefix")
    rows = []
    try:
        for row in matrix["rows"]:
            need(type(row) is list and len(row) == 3,
                 "signature-matrix-row-arity")
            parsed_row = []
            for sparse in row:
                need(type(sparse) is list, "signature-matrix-sparse-row")
                seen, terms = set(), []
                for term in sparse:
                    need(type(term) is list and len(term) == 2
                         and type(term[0]) is int
                         and 0 <= term[0] < SIGNATURE_VARIABLES
                         and term[0] not in seen,
                         "signature-matrix-term")
                    seen.add(term[0])
                    terms.append((term[0], _canonical_field_decimal(
                        term[1], "signature-matrix-coefficient")))
                parsed_row.append(terms)
            rows.append(parsed_row)
    except (TypeError, ValueError):
        raise Refused("signature-matrix-parse") from None
    return rows


def validate_signature_witness(matrix_rows, witness_raw, signature_inputs):
    """Check every pinned signature row and its exact statement/key prefix."""
    witness = parse(witness_raw)
    need(witness_raw == canonical(witness)
         and type(witness) is dict and set(witness) == {
             "schema", "field", "nVars", "nInstances", "nWitnesses",
             "mappingSha256", "normalizedMatrixSha256", "values",
         } and witness["schema"] == "kpi-signature-normalized-witness/v1"
         and witness["field"] == str(SIGNATURE_FIELD)
         and witness["nVars"] == SIGNATURE_VARIABLES
         and witness["nInstances"] == SIGNATURE_INSTANCES
         and witness["nWitnesses"] == SIGNATURE_VARIABLES - SIGNATURE_INSTANCES
         and witness["mappingSha256"] == SIGNATURE_MAP_SHA
         and witness["normalizedMatrixSha256"] == SIGNATURE_MATRIX_SHA
         and type(witness["values"]) is list
         and len(witness["values"]) == SIGNATURE_VARIABLES,
         "signature-witness-exact-shape")
    try:
        values = [_canonical_field_decimal(
            value, "signature-witness-canonical-field")
                  for value in witness["values"]]
    except (TypeError, ValueError):
        raise Refused("signature-witness-field-parse") from None
    need(values[0] == 1 and type(signature_inputs) is dict
         and set(signature_inputs) == {
             "digestLimbs", "ownerKeyBytes", "sigR8", "sigS",
             "preimageA", "preimageR8",
         }, "signature-witness-one-input-fields")
    expected_prefix = [
        _canonical_field_decimal(value, "signature-public-input")
        for value in [*signature_inputs["digestLimbs"],
                      *signature_inputs["ownerKeyBytes"]]
    ]
    need(values[1:SIGNATURE_INSTANCES] == expected_prefix,
         "signature-witness-exact-statement-key-prefix")

    def dot(terms):
        return sum(coefficient * values[index]
                   for index, coefficient in terms) % SIGNATURE_FIELD

    need(len(matrix_rows) == SIGNATURE_ROWS
         and all((dot(row[0]) * dot(row[1]) - dot(row[2]))
                 % SIGNATURE_FIELD == 0 for row in matrix_rows),
         "signature-witness-all-rows-satisfied")


def validate_owner_record_source(record, context, round_number, owner,
                                 receivers, crypto, authority, verifier):
    """Rederive the signed clear intent, output openings and private delta."""
    try:
        head = exit_wire.HeadContext.parse(context)
        raw_intent = bytes.fromhex(record["intent_hex1460"])
        intent = intent_codec.RestrictedIntent.decode(raw_intent)
        nonce = bytes.fromhex(record["nonce_hex32"])
        input_nf = bytes.fromhex(record["input"]["nf_hex32"])
        input_cv = bytes.fromhex(record["input"]["cv_hex64"])
        input_blind = bytes.fromhex(record["input"]["blind_hex32"])
        output_rows = [bytes.fromhex(item["tuple_hex520"])
                       for item in record["outputs"]]
        output_blinds = [bytes.fromhex(item["blind_hex32"])
                         for item in record["outputs"]]
        signature_key = bytes.fromhex(record["signature"]["owner_key_hex64"])
    except (ValueError, TypeError, KeyError):
        raise Refused("owner-record-source-decode") from None
    need(intent == intent_codec.RestrictedIntent(
        head.chain, head.pool, head.profile, head.domain, head.service,
        head.point, head.cm_root, head.nf_root, head.cm_count, head.nf_count,
        head.reserve, input_nf, input_cv, FEE, nonce, tuple(output_rows)),
        "owner-record-exact-signed-context-effects")
    need(signature_key == bytes.fromhex(record["input"]["ak_hex64"])
         and authority.verify(raw_intent, record["signature"]),
         "owner-record-genuine-restricted-intent-signature")
    derived_inputs = authority.signature_inputs(raw_intent,
                                                 record["signature"])
    need(record["signature_inputs"] == derived_inputs,
         "owner-record-exact-signature-inputs")

    expected_target = (owner + round_number) % 3
    expected = (
        (expected_target, 2 * round_number - 1,
         ROUND_VALUES[round_number]["payment"][owner]),
        (owner, 2 * round_number,
         ROUND_VALUES[round_number]["change"][owner]),
    )
    for index, (target, invoice_index, amount) in enumerate(expected):
        row = output_rows[index]
        item = record["outputs"][index]
        blind = output_blinds[index]
        try:
            receipt = receivers[target].open(row[96:360])
            derived = verifier._call("derive-output", b"", {
                "note_hex168": receipt.note_bytes().hex(),
                "blinding_hex32": blind.hex(),
                "cf_hash_hex32": row[360:392].hex(),
            })
            statement = bytes.fromhex(derived["statement_hex168"])
        except (wallet.Invalid, ValueError, TypeError, KeyError):
            raise Refused("owner-record-output-opening") from None
        need(receipt.index == invoice_index
             and receipt.value_sompi == amount
             and receipt.invoice(receivers[target].invoice(
                 invoice_index).delivery_pk)
             == receivers[target].invoice(invoice_index)
             and receipt.note_bytes().hex() == item["note_hex168"]
             and receipt.commitment() == row[:32]
             and len(statement) == 168
             and statement[40:136] == row[:96],
             "owner-record-exact-output-descriptor-value")
    expected_delta = (int.from_bytes(input_blind, "little")
                      - sum(int.from_bytes(value, "little")
                            for value in output_blinds)) % output_producer.Q
    need(record["private_delta_hex32"]
         == expected_delta.to_bytes(32, "little").hex(),
         "owner-record-private-delta-rederived")
    return derived_inputs


def checkpoint_from_root(root, stage):
    raw = read_exact(stage_path(root, stage) / "CHECKPOINT.json")
    value = parse(raw)
    need(value["schema"] == CHECKPOINT_SCHEMA and value["stage"] == stage,
         "selected-prior-checkpoint")
    return value


def validated_checkpoint_from_root(root, stage, plan):
    """Re-admit one immutable checkpoint through its complete validation path.

    This is intentionally stronger than ``checkpoint_from_root``.  Aggregate
    round 2 uses it for round 1 so a copied projection or a caller-edited
    receipt cannot stand in for the exact prior cryptographic verification.
    """
    directory = stage_path(root, stage)
    raw = read_exact(directory / "CHECKPOINT.json")
    value = parse(raw)
    need(type(value) is dict and set(value) == {
        "schema", "classification", "run_id", "source_instance_epoch_id",
        "stage", "ordinal", "previous", "artifacts", "facts",
        "fixture_possession_authorizes_v4", "checkpoint_identity_sha256",
    }, "validated-prior-checkpoint-fields")
    identity = value.pop("checkpoint_identity_sha256", None)
    need(word(identity, "validated-prior-checkpoint-identity") ==
         sha(canonical(value)), "validated-prior-checkpoint-self-identity")
    value["checkpoint_identity_sha256"] = identity
    need(raw == canonical(value), "validated-prior-checkpoint-canonical")
    need(value["schema"] == CHECKPOINT_SCHEMA
         and value["classification"] == CLASSIFICATION
         and value["run_id"] == plan["run_id"]
         and value["source_instance_epoch_id"] ==
             plan["source_instance_epoch_id"]
         and value["stage"] == stage
         and value["ordinal"] == STAGES.index(stage) + 1,
         "validated-prior-checkpoint-header")
    need(value["previous"] == previous_checkpoint(root, stage),
         "validated-prior-checkpoint-exact-predecessor")
    need(type(value["artifacts"]) is dict and all(
        Path(artifact["path"]).parent == directory
        for artifact in value["artifacts"].values()
    ), "validated-prior-checkpoint-artifact-route")
    validate_checkpoint_semantics(value, plan)
    return value


def validate_record_against_input(record, selected, round_number, owner):
    expected = {
        "note_hex168": selected["note_hex168"],
        "nk_hex32": selected["nk_hex32"],
        "position": selected["position"],
        "path_hex32": selected["path_hex32"],
        "cv_hex64": selected["cv_hex64"],
        "blind_hex32": selected["blind_hex32"],
        "ak_hex64": selected["ak_hex64"],
        "nf_hex32": selected["nf_hex32"],
    }
    need(record["input"] == expected
         and selected["schema"] == "kpb-offline-w1-owner-input/v1"
         and selected["round"] == round_number
         and selected["logical_owner"] == owner,
         "owner-record-exact-preceding-input")


def validate_round2_note_continuity(root, records, inputs):
    prior = checkpoint_from_root(root, "round-1-components")
    prior_core = bytes_artifact(prior["artifacts"], "effects-core.bin", 10_364)
    prior_records = [json_artifact(prior["artifacts"],
                                   f"owner-{owner}-record.json")[0]
                     for owner in range(3)]
    _, graph = derive_graph(prior_records, prior_core)
    selected = ((2, 0), (1, 1), (1, 0))
    domain = prior_core[104:136]
    for owner, (creator, output_index) in enumerate(selected):
        output = prior_records[creator]["outputs"][output_index]
        row = bytes.fromhex(output["tuple_hex520"])
        expected_position = 3 + graph[
            "payment" if output_index == 0 else "change"
        ][creator]
        need(inputs[owner]["note_hex168"] == output["note_hex168"]
             and records[owner]["input"]["note_hex168"] == output["note_hex168"]
             and inputs[owner]["selected_tuple_sha256"] == sha(row)
             and inputs[owner]["position"] == expected_position
             and wallet.legacy.h(wallet.legacy.NOTE_TAG, domain,
                                 bytes.fromhex(output["note_hex168"])) == row[:32],
             "round2-exact-selected-round1-note-continuity")


def derive_graph(records, core):
    inputs = [core[404 + at * 96 : 500 + at * 96] for at in range(3)]
    outputs = [core[692 + at * 520 : 1212 + at * 520] for at in range(6)]
    fixture_inputs = [bytes.fromhex(record["input"]["nf_hex32"]
                                    + record["input"]["cv_hex64"])
                      for record in records]
    fixture_outputs = [bytes.fromhex(output["tuple_hex520"])
                       for record in records for output in record["outputs"]]
    need(len(set(inputs)) == 3 and len(set(outputs)) == 6
         and len(set(fixture_inputs)) == 3 and len(set(fixture_outputs)) == 6
         and set(inputs) == set(fixture_inputs)
         and set(outputs) == set(fixture_outputs),
         "graph-exact-unique-input-output-sets")
    actual = {"input": [], "payment": [], "change": []}
    for record, input_row in zip(records, fixture_inputs):
        actual["input"].append(inputs.index(input_row))
        actual["payment"].append(outputs.index(bytes.fromhex(record["outputs"][0]["tuple_hex520"])))
        actual["change"].append(outputs.index(bytes.fromhex(record["outputs"][1]["tuple_hex520"])))
    need(sorted(actual["input"]) == list(range(3))
         and sorted(actual["payment"] + actual["change"]) == list(range(6)),
         "graph-exact-permutations")
    w0 = {name: list(values) for name, values in actual.items()}
    w0["input"][0], w0["input"][2] = w0["input"][2], w0["input"][0]
    w0["change"][0], w0["change"][2] = w0["change"][2], w0["change"][0]
    return w0, actual


def operation_word(value, label="operation"):
    """Production C1 operation identity: SHA256(canonical UUID text bytes)."""
    exact_uuid(value, label + "-uuid")
    return sha(value.encode("ascii"))


def capture_attempt_word(value):
    exact_uuid(value, "capture-attempt-uuid")
    return sha(C1_CAPTURE_ATTEMPT_DOMAIN + value.encode("ascii"))


def stage_plan_word(round_number, operations):
    need(round_number in (1, 2) and len(operations) == 3,
         "c1-stage-plan-shape")
    checked = [exact_uuid(value, "c1-stage-plan-operation")
               for value in operations]
    need(len(set(checked)) == 3, "c1-stage-plan-distinct-operations")
    raw = bytearray(C1_STAGE_PLAN_DOMAIN)
    raw.extend((round_number, 1))
    for sequence, operation in enumerate(checked):
        raw.extend((sequence, sequence + 1))
        raw.extend(operation.encode("ascii"))
        raw.append(1 if sequence == 1 else 0)
        raw.extend(checked[0].encode("ascii") if sequence == 1 else bytes(36))
    return sha(bytes(raw))


def route_word(round_number, contacts, operations, route_source_hex32):
    need(round_number in (1, 2) and len(contacts) == len(operations) == 3,
         "c1-route-shape")
    need(all(type(contact) is int and 0 <= contact < 3 and contact != 1
             for contact in contacts)
         and contacts[0] == contacts[2] and contacts[0] != contacts[1],
         "c1-route-contacts")
    checked = [exact_uuid(value, "c1-route-operation")
               for value in operations]
    need(len(set(checked)) == 3, "c1-route-distinct-operations")
    raw = bytearray(C1_ROUTE_DOMAIN)
    raw.extend((round_number, 1))
    raw.extend(bytes.fromhex(word(route_source_hex32, "c1-route-source")))
    for sequence, operation in enumerate(checked):
        raw.extend((sequence, contacts[sequence]))
        raw.extend(operation.encode("ascii"))
        raw.append(1 if sequence == 1 else 0)
        raw.extend(checked[0].encode("ascii") if sequence == 1 else bytes(36))
    return sha(bytes(raw))


def offline_provenance_word(label, value):
    """Domain-separated evidence identity; explicitly never a live authority."""
    return sha(b"KPB-OFFLINE-W1-PROVENANCE\0" + label.encode("ascii") + b"\0"
               + canonical(value))


def expected_c1_lineage(value, plan, projection):
    """Recompute exact C1 byte identities and label every offline-only hash."""
    semantic = {key: item for key, item in value.items()
                if key not in ("lineage", "contact_value_authority_preimage",
                               "contact_value_authority_preimage_sha256",
                               "manifest_or_digest_is_authority")}
    stages = value["stages"]
    operations = [stage["operation_id"] for stage in stages]
    contacts = [stage["contact_owner"] for stage in stages]
    route_source = offline_provenance_word("c1-route-source", value["invoices"])
    production = {
        "round_attempt_hex32": capture_attempt_word(value["capture_attempt_id"]),
        "operation_hex32": [operation_word(item) for item in operations],
        "stage_plan_hex32": stage_plan_word(value["round"], operations),
        # The route algorithm is production-exact, but its route-source input is
        # an offline provenance digest.  It therefore cannot be a live route cap.
        "route_manifest_hex32": route_word(
            value["round"], contacts, operations, route_source),
    }
    offline = {
        "artifact_sha256": offline_provenance_word("c1-artifact", semantic),
        "capture_plan_sha256": offline_provenance_word("c1-capture-plan", {
            "round": value["round"],
            "capture_attempt_id": value["capture_attempt_id"],
            "capture_identity_id": value["capture_identity_id"],
            "operations": operations,
            "contacts": contacts,
        }),
        "projection_sha256": sha(projection),
        "route_source_sha256": route_source,
        "role_launch_sha256": offline_provenance_word("c1-role-launch", {
            "source_closure_sha256": plan["source_closure_sha256"],
            "run_id": plan["run_id"],
        }),
        "process_sha256": offline_provenance_word("c1-process", {
            "source_closure_sha256": plan["source_closure_sha256"],
            "run_id": plan["run_id"], "round": value["round"],
        }),
        "child_exit_sha256": offline_provenance_word("c1-child-exit", {
            "round": value["round"],
            "retry_history_closed": value["retry_history_closed"],
            "retries": value["retries"],
        }),
    }
    return {
        "schema": "kpb-offline-w1-c1-lineage/v2",
        "production_preimage_equivalents": production,
        "offline_provenance_only": offline,
        "route_manifest_uses_live_route_source_authority": False,
        "live_authority_identity_claimed": False,
    }


C1_STAGE_CONFIG_FIELDS = (
    "schema", "capture_identity", "attempt_id", "cohort_sha256",
    "financial_run_id", "round", "owner_component", "stage",
    "stage_sequence", "operation_id", "target_invoice_operation_id",
    "contact_owner_component", "fixed_fd",
    "contact_value_authority_sha256",
)


def expected_c1_authority_preimage(value, plan):
    """Build the production JSON preimage over explicitly offline inputs."""
    attempt = round_attempt(plan, value["round"])
    stages = value["stages"]
    operations = [row["operation_id"] for row in stages]
    contacts = [row["contact_owner"] for row in stages]
    route_source = offline_provenance_word("c1-route-source", value["invoices"])
    stage_plan = stage_plan_word(value["round"], operations)
    route_manifest = route_word(value["round"], contacts, operations,
                                route_source)
    worker = {
        "source_sha256": plan["source_closure_sha256"],
        "build_sha256": plan["selected_build"]["build_identity_sha256"],
        "runtime_sha256": offline_provenance_word("c1-worker-runtime", {
            "source_closure_sha256": plan["source_closure_sha256"],
        }),
        "assets_sha256": offline_provenance_word("c1-worker-assets", {
            "profile_sha256": plan["profile"]["sha256"],
            "rehearsal_sha256": plan["rehearsal"]["sha256"],
        }),
        "pinned_executable_sha256": offline_provenance_word(
            "c1-worker-pinned-executable", {
                "source_closure_sha256": plan["source_closure_sha256"],
            }),
        "launcher_sha256": offline_provenance_word("c1-worker-launcher", {
            "source_closure_sha256": plan["source_closure_sha256"],
            "classification": CLASSIFICATION,
        }),
    }
    return {
        "schema": "kpb-c1-contact-value-authority-preimage/v2",
        "round": value["round"],
        "financial_run_id": attempt["c1_financial_run_hex32"],
        "attempt_id": attempt["c1_capture_attempt_id"],
        "cohort_sha256": attempt["c1_cohort_hex32"],
        "capture_identity": attempt["c1_capture_identity_id"],
        "owner_component": 1,
        "fixed_fd": 24 if value["round"] == 1 else 29,
        "contact_owner_components": contacts,
        **worker,
        "route_manifest_sha256": route_manifest,
        "route_source_sha256": route_source,
        "role_launch_sha256": offline_provenance_word("c1-role-launch", {
            "source_closure_sha256": plan["source_closure_sha256"],
            "run_id": plan["run_id"],
        }),
        "process_sha256": offline_provenance_word("c1-process", {
            "source_closure_sha256": plan["source_closure_sha256"],
            "run_id": plan["run_id"], "round": value["round"],
        }),
        "stage_plan_sha256": stage_plan,
        "operation_id_sha256": [operation_word(item) for item in operations],
    }


def c1_authority_preimage_word(preimage):
    return sha(C1_CONTACT_VALUE_AUTHORITY_DOMAIN + canonical(preimage))


def expected_stage_config(value, plan, sequence, authority_sha256):
    attempt = round_attempt(plan, value["round"])
    row = value["stages"][sequence]
    return {
        "schema": "kpb-c1-capture-stage/v1",
        "capture_identity": attempt["c1_capture_identity_id"],
        "attempt_id": attempt["c1_capture_attempt_id"],
        "cohort_sha256": attempt["c1_cohort_hex32"],
        "financial_run_id": attempt["c1_financial_run_hex32"],
        "round": value["round"],
        "owner_component": 1,
        "stage": row["stage"],
        "stage_sequence": sequence,
        "operation_id": row["operation_id"],
        "target_invoice_operation_id": (
            value["stages"][0]["operation_id"] if sequence == 1 else None),
        "contact_owner_component": row["contact_owner"],
        "fixed_fd": 24 if value["round"] == 1 else 29,
        "contact_value_authority_sha256": authority_sha256,
    }


def stage_config_word(value):
    need(type(value) is dict and set(value) == set(C1_STAGE_CONFIG_FIELDS),
         "c1-stage-config-fields")
    return sha(C1_STAGE_CONFIG_DOMAIN + canonical(value))


def validate_c1(value, records, round_number, attempt, plan, projection):
    required = {
        "schema", "round", "c1_owner", "capture_attempt_id",
        "capture_attempt_hex32", "capture_identity_id", "c1_cohort_hex32",
        "c1_financial_run_hex32", "contact_value_authority_preimage",
        "contact_value_authority_preimage_sha256",
        "contact_value_authority_was_live", "stages",
        "original", "invoices", "receipts", "incoming_key_commitment_hex32",
        "incoming_ciphertext_hex264", "retry_history_closed", "retries",
        "lineage", "manifest_or_digest_is_authority",
    }
    need(set(value) == required
         and value["schema"] == "kpb-offline-w1-c1-residual/v2",
         "c1-residual-fields")
    creator = 0 if round_number == 1 else 2
    outgoing_target = (1 + round_number) % 3
    expected_operations = [attempt[name] for name in
                           ("invoice_operation_id", "payment_operation_id",
                            "scan_operation_id")]
    expected_contacts = [creator, outgoing_target, creator]
    need(
        value["round"] == round_number
        and value["c1_owner"] == 1
        and value["capture_attempt_id"] == attempt["c1_capture_attempt_id"]
        and value["capture_attempt_hex32"] == capture_attempt_word(
            attempt["c1_capture_attempt_id"])
        and value["capture_identity_id"] == attempt["c1_capture_identity_id"]
        and value["c1_cohort_hex32"] == attempt["c1_cohort_hex32"]
        and value["c1_financial_run_hex32"] == attempt["c1_financial_run_hex32"]
        and type(value["stages"]) is list and len(value["stages"]) == 3
        and [row["stage"] for row in value["stages"]] == ["invoice", "pay", "scan"]
        and [row["operation_id"] for row in value["stages"]] == expected_operations
        and [row["operation_hex32"] for row in value["stages"]] == [
            operation_word(operation, stage)
            for operation, stage in zip(expected_operations, ("invoice", "pay", "scan"))]
        and [row["contact_owner"] for row in value["stages"]] == expected_contacts
        and len(set(expected_operations)) == 3
        and value["retry_history_closed"] is True
        and value["retries"] == []
        and value["contact_value_authority_was_live"] is False
        and value["manifest_or_digest_is_authority"] is False,
        "c1-exact-operation-contact-attempt-value",
    )
    precursor = expected_c1_authority_preimage(value, plan)
    authority_sha256 = c1_authority_preimage_word(precursor)
    need(value["contact_value_authority_preimage"] == precursor
         and value["contact_value_authority_preimage_sha256"] == authority_sha256,
         "c1-contact-value-authority-production-preimage-equivalent")
    need(all(
        set(row) == {"stage", "operation_id", "operation_hex32",
                     "stage_config", "stage_config_hex32", "contact_owner"}
        and row["stage_config"] == expected_stage_config(
            value, plan, sequence, authority_sha256)
        and row["stage_config_hex32"] == stage_config_word(row["stage_config"])
        for sequence, row in enumerate(value["stages"])
    ), "c1-stage-config-lineage")
    outgoing = bytes.fromhex(records[1]["outputs"][0]["tuple_hex520"])
    change = bytes.fromhex(records[1]["outputs"][1]["tuple_hex520"])
    incoming = bytes.fromhex(records[creator]["outputs"][0]["tuple_hex520"])
    original = value["original"]
    need(
        set(original) == {"source_operation_id", "source_operation_hex32",
                          "input_nf_hex32", "input_value_sompi", "created"}
        and original["source_operation_id"] == attempt["payment_operation_id"]
        and original["source_operation_hex32"] == operation_word(
            attempt["payment_operation_id"], "pay")
        and original["input_nf_hex32"] == records[1]["input"]["nf_hex32"]
        and original["input_value_sompi"] == ROUND_VALUES[round_number]["input"][1]
        and original["created"] == [
            {"kind": "outgoing-payment", "tuple_sha256": sha(outgoing),
             "cm_hex32": outgoing[:32].hex(),
             "value_sompi": ROUND_VALUES[round_number]["payment"][1]},
            {"kind": "own-change", "tuple_sha256": sha(change),
             "cm_hex32": change[:32].hex(),
             "value_sompi": ROUND_VALUES[round_number]["change"][1]},
        ], "c1-original-input-created-facts")
    need(type(value["invoices"]) is list and len(value["invoices"]) == 2,
         "c1-two-invoices")
    for item in value["invoices"]:
        invoice = bytes.fromhex(item["invoice_hex208"])
        need(set(item) == {"kind", "source_operation_id", "invoice_operation_id",
                           "source_owner", "target_owner", "invoice_index",
                           "value_sompi", "invoice_hex208", "invoice_sha256"}
             and len(invoice) == 208 and sha(invoice) == item["invoice_sha256"],
             "c1-authenticated-invoice-bytes")
    need(value["invoices"][0]["kind"] == "issued-incoming"
         and value["invoices"][0]["source_operation_id"] == attempt["invoice_operation_id"]
         and value["invoices"][0]["invoice_operation_id"] == attempt["invoice_operation_id"]
         and value["invoices"][0]["source_owner"] == 1
         and value["invoices"][0]["target_owner"] == creator
         and value["invoices"][0]["invoice_index"] == 2 * round_number - 1
         and value["invoices"][0]["value_sompi"] == ROUND_VALUES[round_number]["payment"][creator]
         and value["invoices"][1]["kind"] == "accepted-outgoing"
         and value["invoices"][1]["source_operation_id"] == attempt["payment_operation_id"]
         and value["invoices"][1]["invoice_operation_id"] == attempt["invoice_operation_id"]
         and value["invoices"][1]["source_owner"] == outgoing_target
         and value["invoices"][1]["target_owner"] == 1
         and value["invoices"][1]["invoice_index"] == 2 * round_number - 1
         and value["invoices"][1]["value_sompi"] == ROUND_VALUES[round_number]["payment"][1],
         "c1-issued-accepted-invoice-routing")
    receipts = value["receipts"]
    need(type(receipts) is list and len(receipts) == 2
         and receipts == [
             {"kind": "decrypted-incoming", "source_operation_id": attempt["scan_operation_id"],
              "receipt_index": 2 * round_number - 1, "creator_owner": creator,
              "tuple_sha256": sha(incoming), "cm_hex32": incoming[:32].hex(),
              "note_sha256": sha(bytes.fromhex(records[creator]["outputs"][0]["note_hex168"])),
              "value_sompi": ROUND_VALUES[round_number]["payment"][creator]},
             {"kind": "decrypted-own-change", "source_operation_id": attempt["scan_operation_id"],
              "receipt_index": 2 * round_number, "creator_owner": 1,
              "tuple_sha256": sha(change), "cm_hex32": change[:32].hex(),
              "note_sha256": sha(bytes.fromhex(records[1]["outputs"][1]["note_hex168"])),
              "value_sompi": ROUND_VALUES[round_number]["change"][1]},
         ], "c1-both-decrypted-receipts")
    ciphertext = bytes.fromhex(value["incoming_ciphertext_hex264"])
    incoming_note = bytes.fromhex(records[creator]["outputs"][0]["note_hex168"])
    need(len(bytes.fromhex(value["incoming_key_commitment_hex32"])) == 32
         and value["incoming_key_commitment_hex32"] == incoming_note[104:136].hex()
         and len(ciphertext) == 264 and ciphertext == incoming[96:360]
         and hashlib.sha256(ciphertext).digest() == incoming[360:392],
         "c1-incoming-key-ciphertext")
    need(value["lineage"] == expected_c1_lineage(value, plan, projection),
         "c1-full-lineage-rederived")


def component_artifact_names():
    shared = {
        "context.bin", "effects-core.bin", "projection.bin",
        "w0-selection.json", "joint-ordering.json", "c1-residual.json",
    }
    owner = {
        "record.json", "signature-matrix.json", "signature-map.json",
        "signature-witness.json", "owner-aux-request.json",
        "private-input-v2.bin", "aux-receipt.json",
    }
    return shared | {
        f"owner-{selected}-{leaf}"
        for selected in range(3) for leaf in owner
    }


def validate_owner_aux_artifacts(artifacts, owner, context, witness_sha256):
    request, _ = json_artifact(
        artifacts, f"owner-{owner}-owner-aux-request.json")
    private = bytes_artifact(
        artifacts, f"owner-{owner}-private-input-v2.bin",
        OWNER_PRIVATE_BYTES)
    receipt, _ = json_artifact(
        artifacts, f"owner-{owner}-aux-receipt.json")
    need(request == {
        "schema": "kpi-owner-local-aux-request/v1",
        "owner_component": owner,
        "context_hex": context.hex(),
        "owner_record_path": "OWNER-LOCAL-RECORD.json",
        "signature_matrix_path": "SIGNATURE-MATRIX.json",
        "signature_witness_path": "SIGNATURE-WITNESS.json",
        "expected_matrix_sha256": SIGNATURE_MATRIX_SHA,
        "expected_mapping_sha256": SIGNATURE_MAP_SHA,
        "expected_witness_sha256": witness_sha256,
    }, "owner-aux-exact-request")
    start = 83_440 + owner * 2_625_295
    need(receipt == {
        "schema": "kpi-owner-local-aux-public-receipt/v2",
        "owner_component": owner,
        "owner_file_encoding": "KPB_OWNER_FR32V2",
        "owner_file_bytes": OWNER_PRIVATE_BYTES,
        "context_sha256": sha(context),
        "core_variables": 12_919_677,
        "native_edges": 66,
        "native_auxiliary": 2_625_295,
        "native_auxiliary_range": {
            "start": start, "end": start + 2_625_295,
        },
        "signature_variables": SIGNATURE_VARIABLES,
        "signature_rows": SIGNATURE_ROWS,
        "signature_rows_checked": True,
        "signature_matrix_sha256": SIGNATURE_MATRIX_SHA,
        "signature_mapping_sha256": SIGNATURE_MAP_SHA,
        "ordered_private_values": OWNER_PRIVATE_VALUES,
        "private_values_output": True,
        "combined_dealer": False,
        "proof_or_mpc_claim": False,
    }, "owner-aux-exact-v2-receipt")
    need(private[:16] == OWNER_PRIVATE_MAGIC
         and int.from_bytes(private[16:24], "little") == owner
         and int.from_bytes(private[24:32], "little")
         == OWNER_PRIVATE_VALUES,
         "owner-aux-fr32v2-header")


def validate_round_components(artifacts, facts, plan, round_number, aggregate=False):
    attempt = round_attempt(plan, round_number)
    need(set(artifacts) == component_artifact_names(),
         "round-component-exact-artifact-set")
    need(
        facts == {
            "round": round_number,
            "attempt": attempt,
            "genuine_output_proofs": 6,
            "genuine_signature_witnesses": 3,
            "aggregate_proof_present": aggregate,
        },
        "round-component-facts",
    )
    context = bytes_artifact(artifacts, "context.bin", 276)
    core = bytes_artifact(artifacts, "effects-core.bin", 10_364)
    projection = bytes_artifact(artifacts, "projection.bin", 10_685)
    need(core[:8] == b"KPBAEF01" and core[8:284] == context, "effects-context-binding")
    need(projection[:8] == b"KPBAFX01" and projection[193:10_557] == core, "projection-effects-binding")
    if not aggregate:
        need(projection[-128:] == bytes(128), "component-stage-zero-proof-placeholder")

    any_path = Path(next(iter(artifacts.values()))["path"])
    root = any_path.parent.parent
    bootstrap = checkpoint_from_root(root, "bootstrap")
    if round_number == 1:
        history_value, _ = json_artifact(
            bootstrap["artifacts"], "public-history.json")
    else:
        prior_close = checkpoint_from_root(root, "round-1-close")
        history_value, _ = json_artifact(
            prior_close["artifacts"], "public-history-after.json")
    output_verifier = output_verifier_from_plan(plan)
    proof_cache = {}
    history = replay_public_history(
        history_value, plan, output_verifier, proof_cache)
    need(history.head.encode() == context,
         "component-exact-prior-public-history-context")

    def verify_output(row):
        digest = sha(row)
        if digest not in proof_cache:
            proof_cache[digest] = output_verifier.verify(row)
        return proof_cache[digest]

    _, tail = read_ref(
        plan["selected_build"]["aggregate_feasibility_only"]["native_tail"])
    try:
        _, appended, _ = wallet_history.payment(
            projection, history.head, history.state, tail, verify_output)
    except (wallet.Invalid, ValueError, TypeError, KeyError):
        raise Refused("component-exact-effects-history-replay") from None

    records = []
    witness_rows = []
    matrix_rows = None
    matrix_identity = None
    mapping_identity = None
    for owner in range(3):
        record, _ = json_artifact(artifacts, f"owner-{owner}-record.json")
        records.append(strict_owner_record(record, round_number, owner))
        matrix_raw = bytes_artifact(
            artifacts, f"owner-{owner}-signature-matrix.json")
        mapping_raw = bytes_artifact(
            artifacts, f"owner-{owner}-signature-map.json")
        witness_raw = bytes_artifact(
            artifacts, f"owner-{owner}-signature-witness.json")
        need(sha(matrix_raw) == SIGNATURE_MATRIX_SHA
             and sha(mapping_raw) == SIGNATURE_MAP_SHA,
             "signature-matrix-map-pin")
        if matrix_rows is None:
            matrix_rows = parse_signature_model(matrix_raw, mapping_raw)
            matrix_identity, mapping_identity = matrix_raw, mapping_raw
        else:
            need(matrix_raw == matrix_identity
                 and mapping_raw == mapping_identity,
                 "signature-model-identical-across-owners")
        witness_rows.append(witness_raw)

    prior_inputs = checkpoint_from_root(root, f"round-{round_number}-inputs")
    inputs = [json_artifact(prior_inputs["artifacts"],
                           f"owner-{owner}-input.json")[0]
              for owner in range(3)]
    for owner in range(3):
        validate_record_against_input(records[owner], inputs[owner],
                                      round_number, owner)
    if round_number == 2:
        validate_round2_note_continuity(root, records, inputs)

    modules = wallet.authenticate_js(
        retained.LEAF_MAP, retained.LEAF_MAP_SHA, retained.JS_ROOT)
    crypto = wallet.Crypto(retained.CRYPTO)
    try:
        with wallet.Authority(retained.NODE, modules) as authority:
            receivers = []
            for owner in range(3):
                backup, _ = json_artifact(
                    bootstrap["artifacts"], f"owner-{owner}-backup.json")
                receivers.append(wallet.Receiver(
                    bytes.fromhex(backup["seed_hex32"]),
                    output_verifier.profile, crypto, authority))
            for owner in range(3):
                signature_inputs = validate_owner_record_source(
                    records[owner], context, round_number, owner,
                    receivers, crypto, authority, output_verifier)
                validate_signature_witness(
                    matrix_rows, witness_rows[owner], signature_inputs)
                validate_owner_aux_artifacts(
                    artifacts, owner, context, sha(witness_rows[owner]))
    except (wallet.Invalid, ValueError, TypeError, KeyError):
        raise Refused("component-owner-source-rederivation") from None

    w0, actual = derive_graph(records, core)
    input_order = sorted(range(3), key=lambda owner: actual["input"][owner])
    output_slots = []
    for owner in range(3):
        output_slots.extend((actual["payment"][owner],
                             actual["change"][owner]))
    output_order = sorted(range(6), key=lambda source: output_slots[source])
    delta_sum = sum(int.from_bytes(bytes.fromhex(
        record["private_delta_hex32"]), "little") for record in records)
    quotient, delta = divmod(delta_sum, output_producer.Q)
    ordering, _ = json_artifact(artifacts, "joint-ordering.json")
    need(ordering == {
        "schema": "kpb-offline-w1-joint-ordering/v1",
        "round": round_number,
        "input_source_order": input_order,
        "output_source_order": output_order,
        "delta_quotient": quotient,
        "random_output_keys_retained": False,
        "ordering_is_live_w0_authority": False,
    } and quotient in (0, 1, 2)
         and core[372:404] == delta.to_bytes(32, "little")
         and list(appended) == [
             bytes.fromhex(records[source // 2]["outputs"][source % 2]
                           ["tuple_hex520"])
             for source in output_order
         ], "component-joint-ordering-delta-rederived")
    selected, _ = json_artifact(artifacts, "w0-selection.json")
    need(
        selected["schema"] == "kpb-offline-w1-selected-w0/v1"
        and selected["round"] == round_number
        and selected["fixed_rewire_identity_sha256"] == plan["fixed_rewire"]["identity_sha256"]
        and selected["w0_graph"] == w0
        and selected["w1_graph"] == actual
        and selected["caller_digest_is_common_origin_authority"] is False,
        "rederived-w0-fixed-w1-graph",
    )
    c1, _ = json_artifact(artifacts, "c1-residual.json")
    validate_c1(c1, records, round_number, attempt, plan, projection)
    creator = 0 if round_number == 1 else 2
    outgoing_target = (1 + round_number) % 3
    invoice_index = 2 * round_number - 1
    need(c1["invoices"][0]["invoice_hex208"]
         == receivers[1].invoice(invoice_index).encode().hex()
         and c1["invoices"][1]["invoice_hex208"]
         == receivers[outgoing_target].invoice(invoice_index).encode().hex()
         and c1["receipts"][0]["creator_owner"] == creator,
         "c1-exact-source-owned-invoice-descriptors")


def expected_history_identity(plan):
    _, profile_raw = read_ref(plan["profile"])
    _, rehearsal_raw = read_ref(plan["rehearsal"])
    profile_value, rehearsal = parse(profile_raw), parse(rehearsal_raw)
    descriptor = profile_value["profile_descriptor"]
    identity = tuple(bytes.fromhex(value) for value in (
        descriptor["chain_genesis_hex32"],
        rehearsal["pool_lineage_hex32"],
        profile_value["profile_id_hex32"],
        descriptor["domain_hex32"],
        descriptor["service_policy_hex32"],
    ))
    need(all(len(value) == 32 for value in identity),
         "history-selected-profile-identity")
    return identity


def replay_public_history(value, plan, verifier, cache):
    identity = expected_history_identity(plan)
    profile = wallet.Profile(identity[3], identity[2])
    genesis = value.get("genesis") if type(value) is dict else None
    rows = genesis.get("outputs_hex520") if type(genesis) is dict else None
    need(type(rows) is list and len(rows) == 3,
         "history-three-genesis-outputs")
    decoded = [bytes.fromhex(row) for row in rows]
    need(all(len(row) == 520 for row in decoded),
         "history-genesis-output-width")
    initial_cv = decoded[0][32:96]
    tail_ref = plan["selected_build"]["aggregate_feasibility_only"]["native_tail"]
    _, tail = read_ref(tail_ref)

    def verify(row):
        digest = sha(row)
        if digest not in cache:
            cache[digest] = verifier.verify(row)
        return cache[digest]

    try:
        return wallet_history.load_supplied(
            value, profile, identity, tail, verify, initial_cv)
    except Exception:
        raise Refused("close-public-history-replay") from None


def validate_public_history_pair(before, after, context, projection,
                                 successor, plan):
    need(len(context) == 276 and len(projection) == 10_685
         and len(successor) == 36
         and projection[193:201] == b"KPBAEF01"
         and projection[201:477] == context,
         "close-history-projection-context")
    for field in ("chain_hex32", "pool_hex32", "profile_hex32",
                  "domain_hex32", "service_hex32", "genesis"):
        need(after.get(field) == before.get(field),
             "close-history-exact-identity-genesis")
    prior_outpoints = {
        bytes.fromhex(before["genesis"]["outpoint_hex36"]),
        *(bytes.fromhex(event["successor_outpoint_hex36"])
          for event in before["transitions"]
          if event["successor_outpoint_hex36"] is not None),
    }
    need(successor not in prior_outpoints,
         "close-fresh-successor-outpoint")
    need(after["transitions"][:-1] == before["transitions"]
         and after["transitions"][-1] == {
             "kind": "payment",
             "projection_hex": projection.hex(),
             "successor_outpoint_hex36": successor.hex(),
         }, "close-exact-projection-successor")
    verifier = output_verifier_from_plan(plan)
    cache = {}
    replayed_before = replay_public_history(before, plan, verifier, cache)
    replayed_after = replay_public_history(after, plan, verifier, cache)
    need(replayed_before.head.encode() == context,
         "close-before-full-history-context")
    core = projection[193:10_557]
    expected_after_context = (
        context[:160] + successor + core[284:316] + core[316:348]
        + core[348:352] + core[352:356] + core[356:364]
    )
    need(len(expected_after_context) == 276
         and replayed_after.head.encode() == expected_after_context,
         "close-after-derived-head-state-reserve")


def validate_round_close(artifacts, facts, plan, round_number):
    attempt = round_attempt(plan, round_number)
    need(
        facts == {
            "round": round_number,
            "attempt": attempt,
            "structural_close_only": True,
            "aggregate_verified": False,
            "accepted_close_authority_minted": False,
        },
        "round-close-facts",
    )
    before, before_raw = json_artifact(artifacts, "public-history-before.json")
    after, after_raw = json_artifact(artifacts, "public-history-after.json")
    projection = bytes_artifact(artifacts, "projection.bin", 10_685)
    context = bytes_artifact(artifacts, "context.bin", 276)
    successor = bytes_artifact(artifacts, "successor-outpoint.bin", 36)
    close, _ = json_artifact(artifacts, "close-source.json")
    need(
        close == {
            "schema": "kpb-offline-w1-structural-close-source/v1",
            "round": round_number,
            "context_sha256": sha(context),
            "projection_sha256": sha(projection),
            "history_before_sha256": sha(before_raw),
            "history_after_sha256": sha(after_raw),
            "successor_outpoint_hex36": successor.hex(),
            "aggregate_proof_verified": False,
            "accepted_public_terminal_projection_history_close": False,
            "manifest_or_digest_mints_close_authority": False,
        },
        "rederived-structural-close-lineage",
    )
    need(before["head"]["outpoint_hex36"] == context[160:196].hex(), "close-before-context-head")
    validate_public_history_pair(before, after, context, projection,
                                 successor, plan)
    if round_number == 2:
        any_path = Path(next(iter(artifacts.values()))["path"])
        prior = checkpoint_from_root(any_path.parent.parent,
                                     "round-1-close")
        _, prior_after_raw = json_artifact(
            prior["artifacts"], "public-history-after.json")
        need(before_raw == prior_after_raw,
             "component-round-history-byte-continuity")


def final_public_history_pair(round_number, component_before,
                              component_after, previous_final_after,
                              projection, successor):
    """Rederive proof-bearing history without breaking round continuity."""
    need(round_number in (1, 2), "aggregate-final-history-round")
    need(type(component_before) is dict and type(component_after) is dict
         and type(component_before.get("transitions")) is list
         and type(component_after.get("transitions")) is list
         and component_after["transitions"][:-1]
         == component_before["transitions"],
         "aggregate-close-history-transition")
    if round_number == 1:
        need(previous_final_after is None,
             "aggregate-round1-history-has-no-predecessor")
        expected_before = copy.deepcopy(component_before)
    else:
        need(type(previous_final_after) is dict
             and type(previous_final_after.get("transitions")) is list,
             "aggregate-round2-final-history-predecessor")
        expected_before = copy.deepcopy(previous_final_after)
    expected_after = copy.deepcopy(component_after)
    expected_after["transitions"] = [
        *copy.deepcopy(expected_before["transitions"]),
        {
            "kind": "payment",
            "projection_hex": projection.hex(),
            "successor_outpoint_hex36": successor.hex(),
        },
    ]
    return expected_before, expected_after


def validate_final_public_history_chain(component_histories, final_histories,
                                        projections, successors):
    """Validate both rounds together, including the exact transition join."""
    need(set(component_histories) == set(final_histories)
         == set(projections) == set(successors) == {1, 2},
         "aggregate-two-round-final-history-shape")
    previous_component_after = None
    previous_final_after = None
    for number in (1, 2):
        component_before, component_after = component_histories[number]
        final_before, final_after = final_histories[number]
        if number == 2:
            need(component_before == previous_component_after,
                 "aggregate-component-cross-round-public-history-lineage")
        expected_before, expected_after = final_public_history_pair(
            number, component_before, component_after,
            previous_final_after, projections[number], successors[number])
        need(final_before == expected_before and final_after == expected_after,
             "aggregate-final-cross-round-public-history-lineage")
        if number == 2:
            need(canonical(final_before) == canonical(previous_final_after),
                 "aggregate-final-round-history-byte-continuity")
        previous_component_after = component_after
        previous_final_after = final_after


def validate_aggregate(artifacts, facts, plan, round_number):
    attempt = round_attempt(plan, round_number)
    need(facts == {
        "round": round_number,
        "attempt": attempt,
        "aggregate_proof_verified": True,
        "rust_receipt_classification": RUST_RECEIPT_CLASSIFICATION,
        "offline_synthetic_provenance_upgraded_by_checkpoint": True,
        "build_bundle_reverified_by_python": True,
        "authorization": False,
        "old_setup_privacy_assumption_eligible": False,
    }, "aggregate-facts-not-caller-validity")

    def round_name(number, leaf, owner=None):
        middle = "" if owner is None else f"owner-{owner}-"
        return f"round-{number}-{middle}{leaf}"

    round_leaves = {
        "context.bin", "effects-core.bin", "projection.bin",
        "w0-selection.json",
    }
    lineage_leaves = {
        "c1-residual.json", "public-history-before.json",
        "public-history-after.json", "successor-outpoint.bin",
        "close-source.json",
    }
    owner_leaves = {
        "record.json", "signature-matrix.json", "signature-witness.json",
    }
    expected_names = {
        "verifier-request.json", "verification-receipt.json",
        "aggregate-vk.bin", "native-tail.bin", "verifier-dep-info.d",
        "verifier-build-receipt.json", "verifier-source-closure.json",
        "verifier-build-command.json",
    }
    for number in (1, 2):
        expected_names |= {round_name(number, leaf) for leaf in round_leaves}
        expected_names |= {round_name(number, leaf) for leaf in lineage_leaves}
        expected_names |= {
            round_name(number, leaf, owner)
            for owner in range(3) for leaf in owner_leaves
        }
    need(set(artifacts) == expected_names, "aggregate-exact-artifact-set")

    verifier = plan["selected_build"]["offline_aggregate_verifier"]
    need(verifier == verifier_build_bundle(), "aggregate-verifier-build-current")
    for name, selected in (
        ("aggregate-vk.bin", plan["selected_build"]
         ["aggregate_feasibility_only"]["verification_key"]),
        ("native-tail.bin", plan["selected_build"]
         ["aggregate_feasibility_only"]["native_tail"]),
        ("verifier-dep-info.d", verifier["dep_info"]),
        ("verifier-build-receipt.json", verifier["build_receipt"]),
        ("verifier-source-closure.json", verifier["source_closure"]),
        ("verifier-build-command.json", verifier["build_command"]),
    ):
        _, raw = read_ref(artifacts[name])
        need(sha(raw) == selected["sha256"] and len(raw) == selected["bytes"],
             "aggregate-selected-build-leaf")

    any_path = Path(next(iter(artifacts.values()))["path"])
    checkpoint_root = any_path.parent.parent
    prior_verified_aggregate = None
    if round_number == 2:
        # Re-run the exact round-1 verifier receipt and all source checks now;
        # parsing or copying its projection is not proof that it was admitted.
        prior_verified_aggregate = validated_checkpoint_from_root(
            checkpoint_root, "round-1-aggregate", plan)
    component_checkpoints = {
        number: checkpoint_from_root(checkpoint_root,
                                     f"round-{number}-components")
        for number in (1, 2)
    }
    for number, checkpoint in component_checkpoints.items():
        validate_round_components(checkpoint["artifacts"], checkpoint["facts"],
                                  plan, number, aggregate=False)
        for leaf in ("context.bin", "effects-core.bin", "w0-selection.json"):
            _, raw = read_ref(artifacts[round_name(number, leaf)])
            _, prior_raw = read_ref(checkpoint["artifacts"][leaf])
            need(raw == prior_raw, "aggregate-exact-component-source-leaf")
        for owner in range(3):
            for leaf in owner_leaves:
                aggregate_name = round_name(number, leaf, owner)
                component_name = f"owner-{owner}-{leaf}"
                _, raw = read_ref(artifacts[aggregate_name])
                _, prior_raw = read_ref(checkpoint["artifacts"][component_name])
                need(raw == prior_raw,
                     "aggregate-exact-component-owner-source-leaf")

    projections = {}
    for number in (1, 2):
        projections[number] = bytes_artifact(
            artifacts, round_name(number, "projection.bin"), 10_685)
        prior_projection = bytes_artifact(
            component_checkpoints[number]["artifacts"], "projection.bin", 10_685)
        need(projections[number][:10_557] == prior_projection[:10_557],
             "aggregate-projection-prefix-substitution")
        if number == round_number:
            need(projections[number][-128:] != bytes(128),
                 "aggregate-proof-required")
        elif round_number == 1:
            need(projections[number] == prior_projection,
                 "round1-aggregate-cannot-change-round2")
        else:
            previous_projection = bytes_artifact(
                prior_verified_aggregate["artifacts"],
                round_name(1, "projection.bin"), 10_685)
            need(number == 1 and projections[number] == previous_projection,
                 "round2-aggregate-must-retain-verified-round1")
    if round_number == 2:
        need(projections[1][-128:] != projections[2][-128:],
             "cross-round-aggregate-proof-replay")

    component_histories = {}
    final_histories = {}
    history_successors = {}
    for number in (1, 2):
        close_checkpoint = checkpoint_from_root(
            checkpoint_root, f"round-{number}-close")
        component_histories[number] = (
            json_artifact(close_checkpoint["artifacts"],
                          "public-history-before.json")[0],
            json_artifact(close_checkpoint["artifacts"],
                          "public-history-after.json")[0],
        )
        final_histories[number] = (
            json_artifact(artifacts, round_name(
                number, "public-history-before.json"))[0],
            json_artifact(artifacts, round_name(
                number, "public-history-after.json"))[0],
        )
        history_successors[number] = bytes_artifact(
            artifacts, round_name(number, "successor-outpoint.bin"), 36)
    validate_final_public_history_chain(
        component_histories, final_histories, projections,
        history_successors)

    # A final proof changes the projection hash retained by C1 and Close. Keep
    # those source records exact and rederived, while remaining explicitly
    # non-authoritative and not accepted by a live runtime.
    previous_component_after = None
    previous_final_after = None
    previous_final_after_raw = None
    for number in (1, 2):
        component = component_checkpoints[number]
        close_checkpoint = checkpoint_from_root(
            checkpoint_root, f"round-{number}-close")
        records = [json_artifact(
            component["artifacts"], f"owner-{owner}-record.json"
        )[0] for owner in range(3)]
        prior_c1, _ = json_artifact(component["artifacts"], "c1-residual.json")
        final_c1, final_c1_raw = json_artifact(
            artifacts, round_name(number, "c1-residual.json"))
        expected_c1 = copy.deepcopy(prior_c1)
        expected_c1["lineage"] = expected_c1_lineage(
            expected_c1, plan, projections[number])
        need(final_c1_raw == canonical(final_c1)
             and final_c1 == expected_c1,
             "aggregate-c1-final-projection-lineage")
        validate_c1(final_c1, records, number, round_attempt(plan, number),
                    plan, projections[number])

        before, before_raw = json_artifact(
            close_checkpoint["artifacts"], "public-history-before.json")
        prior_after, _ = json_artifact(
            close_checkpoint["artifacts"], "public-history-after.json")
        if number == 2:
            need(before == previous_component_after,
                 "aggregate-component-cross-round-public-history-lineage")
        final_before, final_before_raw = json_artifact(
            artifacts, round_name(number, "public-history-before.json"))
        final_after, final_after_raw = json_artifact(
            artifacts, round_name(number, "public-history-after.json"))
        successor = bytes_artifact(
            artifacts, round_name(number, "successor-outpoint.bin"), 36)
        prior_successor = bytes_artifact(
            close_checkpoint["artifacts"], "successor-outpoint.bin", 36)
        expected_before, expected_after = final_public_history_pair(
            number, before, prior_after, previous_final_after,
            projections[number], successor)
        need(final_before_raw == canonical(final_before)
             and final_after_raw == canonical(final_after)
             and final_before == expected_before
             and successor == prior_successor
             and final_after == expected_after,
             "aggregate-final-public-history-lineage")
        context = bytes_artifact(
            artifacts, round_name(number, "context.bin"), 276)
        validate_public_history_pair(
            final_before, final_after, context, projections[number],
            successor, plan)
        if number == 2:
            need(final_before_raw == previous_final_after_raw,
                 "aggregate-final-round-history-byte-continuity")
        previous_component_after = prior_after
        previous_final_after = final_after
        previous_final_after_raw = final_after_raw
        close_source, close_source_raw = json_artifact(
            artifacts, round_name(number, "close-source.json"))
        expected_close = {
            "schema": "kpb-offline-w1-structural-close-source/v1",
            "round": number,
            "context_sha256": sha(context),
            "projection_sha256": sha(projections[number]),
            "history_before_sha256": sha(final_before_raw),
            "history_after_sha256": sha(final_after_raw),
            "successor_outpoint_hex36": successor.hex(),
            "aggregate_proof_verified": (
                number == 1 if round_number == 1 else True
            ),
            "accepted_public_terminal_projection_history_close": False,
            "manifest_or_digest_mints_close_authority": False,
        }
        need(close_source_raw == canonical(close_source)
             and close_source == expected_close,
             "aggregate-final-structural-close-source")

    def local_ref(name):
        value = artifacts[name]
        return {"path": name, "sha256": value["sha256"],
                "bytes": value["bytes"]}

    request_value, request_raw = json_artifact(artifacts,
                                               "verifier-request.json")
    need(request_raw == canonical(request_value),
         "aggregate-canonical-verifier-request")
    expected_rounds = []
    for number in (1, 2):
        expected_rounds.append({
            "round": number,
            "context": local_ref(round_name(number, "context.bin")),
            "effects_core": local_ref(round_name(number, "effects-core.bin")),
            "projection": local_ref(round_name(number, "projection.bin")),
            "w0_selection": local_ref(round_name(number, "w0-selection.json")),
            "owners": [{
                "record": local_ref(round_name(number, "record.json", owner)),
                "signature_matrix": local_ref(
                    round_name(number, "signature-matrix.json", owner)),
                "signature_witness": local_ref(
                    round_name(number, "signature-witness.json", owner)),
            } for owner in range(3)],
        })
    expected_request = {
        "schema": RUST_REQUEST_SCHEMA,
        "classification": RUST_RECEIPT_CLASSIFICATION,
        "run_id": plan["run_id"],
        "source_instance_epoch_id": plan["source_instance_epoch_id"],
        "selected_round": round_number,
        "authorization": False,
        "old_setup_privacy_assumption_eligible": False,
        "build": {
            "feature": verifier["feature"],
            "binary_sha256": verifier["binary"]["sha256"],
            "dep_info": local_ref("verifier-dep-info.d"),
            "source_closure_sha256": verifier[
                "source_members_identity_sha256"],
            "rustc_vv_sha256": verifier["rustc_vv_sha256"],
            "cargo_version": verifier["cargo_version"],
            "build_command_sha256": verifier["build_command"]["sha256"],
        },
        "aggregate_verification_key": local_ref("aggregate-vk.bin"),
        "output_verification_key_hex328": plan["selected_build"]
        ["output"]["verification_key"]["hex328"],
        "tail": local_ref("native-tail.bin"),
        "rounds": expected_rounds,
    }
    need(request_value == expected_request,
         "aggregate-request-not-independently-rederived")

    receipt_value, receipt_raw = json_artifact(
        artifacts, "verification-receipt.json")
    need(receipt_raw == canonical(receipt_value),
         "aggregate-canonical-verification-receipt")
    request_path = Path(artifacts["verifier-request.json"]["path"])
    with tempfile.TemporaryDirectory(prefix="kpb-w1-verify-") as temporary:
        repeated = Path(temporary) / "receipt.json"
        result = subprocess.run(
            [verifier["binary"]["path"], str(request_path), str(repeated)],
            cwd=request_path.parent,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"LC_ALL": "C"},
            check=False,
        )
        need(result.returncode == 0
             and result.stdout == b"OFFLINE_W1_AGGREGATE_VERIFICATION_RECEIPT_WRITTEN\n"
             and result.stderr == b""
             and repeated.is_file()
             and repeated.read_bytes() == receipt_raw,
             "aggregate-pinned-verifier-rerun")

    identity = receipt_value.pop("receipt_identity_sha256", None)
    need(word(identity, "aggregate-receipt-identity") ==
         sha(canonical(receipt_value)), "aggregate-receipt-self-identity")
    expected_receipt_rounds = []
    for number in (1, 2):
        expected_receipt_rounds.append({
            "round": number,
            "context_sha256": artifacts[
                round_name(number, "context.bin")]["sha256"],
            "effects_sha256": artifacts[
                round_name(number, "effects-core.bin")]["sha256"],
            "projection_sha256": artifacts[
                round_name(number, "projection.bin")]["sha256"],
            "aggregate_proof_sha256": sha(projections[number][-128:]),
            "w0_selection_sha256": artifacts[
                round_name(number, "w0-selection.json")]["sha256"],
            "signature_witness_sha256": [artifacts[
                round_name(number, "signature-witness.json", owner)
            ]["sha256"] for owner in range(3)],
        })
    effects_digest = hashlib.sha256(bytes_artifact(
        artifacts, round_name(round_number, "effects-core.bin"), 10_364)
    ).digest()
    expected_receipt = {
        "schema": RUST_RECEIPT_SCHEMA,
        "classification": RUST_RECEIPT_CLASSIFICATION,
        "run_id": plan["run_id"],
        "source_instance_epoch_id": plan["source_instance_epoch_id"],
        "selected_round": round_number,
        "request_sha256": sha(request_raw),
        "rounds": expected_receipt_rounds,
        "aggregate_verification_key_sha256": AGGREGATE_VK_SHA,
        "output_verification_key_sha256": OUTPUT_VK_SHA,
        "selected_round_output_proofs_verified": 6,
        "signature_relations_satisfied": 3,
        "instances": 3,
        "rows": 13_093_029,
        "variables": 12_949_821,
        "matrix_sha256": AGGREGATE_MATRIX_SHA,
        "effects_digest_public_inputs_decimal": [
            str(int.from_bytes(effects_digest[:16], "little")),
            str(int.from_bytes(effects_digest[16:], "little")),
        ],
        "aggregate_cryptographic_verification": "ACCEPTED",
        "cross_round_note_state_continuity_rederived": True,
        "build": {
            "feature": verifier["feature"],
            "binary_sha256": verifier["binary"]["sha256"],
            "dep_info_sha256": verifier["dep_info"]["sha256"],
            "source_closure_sha256": verifier[
                "source_members_identity_sha256"],
            "rustc_vv_sha256": verifier["rustc_vv_sha256"],
            "cargo_version": verifier["cargo_version"],
            "build_command_sha256": verifier["build_command"]["sha256"],
        },
        "authorization": False,
        "receipt_is_authority": False,
        "fixture_possession_authorizes_v4": False,
        "offline_synthetic_provenance_enforced": False,
        "build_bundle_reverified": False,
        "old_setup_privacy_assumption_eligible": False,
        "production_source_authority_or_closure_minted": False,
    }
    need(receipt_value == expected_receipt,
         "aggregate-receipt-not-exact-verifier-result")
    receipt_value["receipt_identity_sha256"] = identity


def validate_handoff(artifacts, facts, plan):
    need(
        facts == {
            "rounds": 2,
            "output_proofs": 12,
            "signature_witnesses": 6,
            "aggregate_proofs": 2,
            "authorization": False,
        },
        "handoff-facts",
    )
    value, _ = json_artifact(artifacts, "HANDOFF.json")
    need(
        value["schema"] == HANDOFF_SCHEMA
        and value["classification"] == CLASSIFICATION
        and value["run_id"] == plan["run_id"]
        and value["source_instance_epoch_id"] == plan["source_instance_epoch_id"]
        and value["authorization"] is False
        and value["fixture_possession_authorizes_v4"] is False
        and value["atomic_minter_must_rederive_live_sources"] is True,
        "handoff-boundary",
    )


def validate_chain(root):
    root, plan, plan_sha = load_plan(root)
    prior_sha = None
    completed = []
    for stage in STAGES:
        path = stage_path(root, stage) / "CHECKPOINT.json"
        if not path.exists():
            break
        raw = read_exact(path)
        value = parse(raw)
        identity = value.pop("checkpoint_identity_sha256", None)
        need(word(identity, "checkpoint-identity") == sha(canonical(value)), "checkpoint-self-identity")
        value["checkpoint_identity_sha256"] = identity
        previous = value["previous"]
        if prior_sha is None:
            need(previous is None, "first-checkpoint-no-previous")
        else:
            need(previous is not None and previous["sha256"] == prior_sha, "checkpoint-chain")
            read_ref(previous)
        validate_checkpoint_semantics(value, plan)
        prior_sha = sha(raw)
        completed.append(stage)
    for stage in STAGES[len(completed) :]:
        need(not stage_path(root, stage).exists(), "no-checkpoint-gap-or-partial-canonical-stage")
    return {
        "schema": "kpb-offline-w1-validation/v1",
        "classification": CLASSIFICATION,
        "run_id": plan["run_id"],
        "plan_sha256": plan_sha,
        "completed_stages": completed,
        "next_stage": None if len(completed) == len(STAGES) else STAGES[len(completed)],
        "aggregate_proofs_started": any(stage.endswith("-aggregate") for stage in completed),
        "fixture_possession_authorizes_v4": False,
    }


def preflight():
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, raw = line.split(":", 1)
        memory[name] = int(raw.strip().split()[0]) * 1024
    disk = shutil.disk_usage(ROOT)
    setup_time = ROOT / ".local/private-batch-stock-setup-20261028-02/TIME.txt"
    return {
        "schema": "kpb-offline-w1-resource-preflight/v1",
        "cpus": len(os.sched_getaffinity(0)),
        "memory_total_bytes": memory["MemTotal"],
        "memory_available_bytes": memory["MemAvailable"],
        "swap_total_bytes": memory["SwapTotal"],
        "swap_free_bytes": memory["SwapFree"],
        "disk_free_bytes": disk.free,
        "component_checkpoint_estimate_bytes": 550_000_000,
        "component_resume_cache_plus_checkpoint_estimate_bytes": 1_100_000_000,
        "aggregate_pk_gzip_bytes": 1_749_414_110,
        "aggregate_pk_decoded_bytes": 2_608_842_576,
        "aggregate_constraints_each": 13_093_029,
        "aggregate_proofs": 2,
        "closest_measured_workload": {
            "operation": "same-relation-stock-setup",
            "evidence": ref(
                setup_time,
                "3077fac4a1bea16e27fb71d9fc04c9741660abe8d307dce7c6177edf72f2e073",
            ),
            "wall_seconds": 97.47,
            "max_rss_kib": 10_384_760,
            "swaps": 0,
            "proof_peak_rss_measured": False,
        },
        "aggregate_execution_authorized": False,
        "quiet_window_conditions": {
            "no_compiler_or_other_prover_jobs": True,
            "swap_not_exhausted": True,
            "memory_available_minimum_bytes_estimate": 18_000_000_000,
            "run_rounds_sequentially": True,
            "retain_decoded_pk_and_round_checkpoints": True,
        },
        "estimate_is_measurement": False,
    }


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--root", required=True)
    init.add_argument("--label", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--root", required=True)
    commands.add_parser("preflight")
    args = parser.parse_args()
    try:
        if args.command == "init":
            plan = make_plan(args.root, args.label)
            result = {
                "status": "OFFLINE_W1_PLAN_FROZEN",
                "root": str(Path(args.root).absolute()),
                "run_id": plan["run_id"],
                "plan_identity_sha256": plan["plan_identity_sha256"],
                "next_stage": "bootstrap",
                "aggregate_execution_authorized": False,
            }
        elif args.command == "validate":
            result = validate_chain(args.root)
        else:
            result = preflight()
        print(json.dumps(result, sort_keys=True))
    except BaseException as error:
        print(json.dumps({"status": "OFFLINE_W1_REFUSED", "category": type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
