#!/usr/bin/env python3
"""Inert, fail-closed contract for a future offline W1 aggregate prover.

This file deliberately has no setup, proving-key-open, synthesis, proving,
verification-authority, or stage-08 path. Its CLI can only report status or
revalidate the already sealed component source. The internal child supervisor
is a fixed-program test seam for hostile state-machine controls; its bytes are
never a proving key or proof and can never become a canonical aggregate output.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import uuid


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT_ROOT = ROOT / ".local/private-batch-offline-w1-components-20261029-01"
ATTEMPT_PARENT = ROOT / ".local/private-batch-offline-w1-aggregate-attempts-20261029"

# Exact sealed preflight and source identities. These values are constraints,
# not authority to open a PK or launch a proof.
PREFLIGHT_SHA256 = "87b3ab338d30bbfecfd0dcabfdbd56c1263245f2cc5a0e7c5d0160d32113fdd0"
PREFLIGHT_BYTES = 9_190
PLAN_SHA256 = "8b24a987f87d2bd9dca0b04f4622022eac0e04724af06ff761141169f0853482"
PLAN_BYTES = 30_403
PLAN_SOURCE_MEMBER_COUNT = 81
PLAN_SOURCE_MEMBER_BYTES = 143_536_017
RUN_ID = "2904ab69-cc9e-40ce-834f-07a56cd15bbc"
SOURCE_INSTANCE_EPOCH_ID = "d3d47403-5350-414d-a133-2447bb28da5a"
PLAN_IDENTITY_SHA256 = "f9ac4a37df9e50867eb01e282cf9a8c9f6ce9ff56891aa27d909a71877c7bd80"
W1_SOURCE_CLOSURE_SHA256 = "8fcca654b4eb03b38a62c22648cd14323919279dc49d841751d3802683c66aae"
W1_SELECTED_BUILD_IDENTITY_SHA256 = "eee5536d5bcab041c7f98476ba6a5b8c4e8632373cc51b7087a568866072a55a"
CURRENT_RELATION_SOURCE_TABLE_SHA256 = "04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7"
FIXTURE_SOURCE_SHA256 = "89e05932c5937e580b90863739a3a583e35b6881be4d17490f8c138777bfb828"
FIXTURE_SOURCE_BYTES = 135_404

# The retained component plan names live absolute source paths. Those paths are
# drift evidence, not authority after worktree changes. The exact immutable
# historical reconstruction below is accepted only as nonfinal provenance for
# revalidating the retained components. It is never current source, a reproduced
# build, relation-satisfaction authority, or proof-launch authority.
OWNER_AUX_SOURCE_CLOSURE = (
    ROOT / ".local/private-batch-owner-aux-build-20261029-04/SOURCE-CLOSURE.json"
)
OWNER_AUX_SOURCE_CLOSURE_SHA256 = (
    "e100f1f244a7c14b9e8d771d54c37a99ba7b7f75f7c6b9402e010844fddd7051"
)
OWNER_AUX_SOURCE_CLOSURE_BYTES = 8_916
OWNER_AUX_SOURCE_MEMBERS_SHA256 = (
    "b3967d50d2de999020c9ef3dc2723ccdf31ee4fb99b3fc7e3ff35f3464cf54d4"
)
OWNER_AUX_SOURCE_MEMBER_COUNT = 37
HISTORICAL_SOURCE_BUNDLE_ROOT = (
    ROOT
    / ".local/private-batch-w1-historical-reconstruction-private-20261029-01"
    / "private-batch-w1-historical-reconstructed-nonfinal-20261029-01"
)
HISTORICAL_MANIFEST_SHA256 = (
    "8db2a202c0c2547af841bade48f49168d093fa74ff18620573f041f6fcfbcfbd"
)
HISTORICAL_MANIFEST_BYTES = 82_856
HISTORICAL_RECEIPT_SHA256 = (
    "14fcfa0ddeaa3f8bfc6eede6b571be9d9f555be2977c1e79c0e81b0b485d8e26"
)
HISTORICAL_RECEIPT_BYTES = 5_616
HISTORICAL_GENERATOR_SHA256 = (
    "cacd8dbc153263a5cd2a477d9340337bbc5531e30805cc79ee035de4ae530975"
)
HISTORICAL_GENERATOR_BYTES = 43_242
HISTORICAL_GENERATOR_SEAL_SHA256 = (
    "82501ed4eb181bf0c4f6ee8c826c2133da82cade6dcdc8ada758b045244ef806"
)
HISTORICAL_GENERATOR_SEAL_BYTES = 733
HISTORICAL_SEALER_SHA256 = (
    "1b450bee9e86c6e5984cca4a1885f738ecab0f186533345fa507ba841c55083e"
)
HISTORICAL_SEALER_BYTES = 11_389
HISTORICAL_FIXTURE_MEMBER_NAME = (
    "067-89e05932c5937e580b90863739a3a583e35b6881be4d17490f8c138777bfb828"
)
FRESH_SOURCE_FINAL_ROOT = (
    ROOT / ".local/private-batch-w1-current-source-final-20261029-01"
)
CONDITIONAL_OWNER_AUX_TARGET = (
    ROOT / ".local/private-batch-owner-aux-target-20261029-05"
)
CONDITIONAL_OWNER_AUX_BUILD = (
    ROOT / ".local/private-batch-owner-aux-build-20261029-05"
)
CONDITIONAL_COMPONENT_ROOT = (
    ROOT / ".local/private-batch-offline-w1-components-20261029-02"
)

# Exact sealed output descriptors, not line numbers, are the acceptance
# conditions. All five deterministic inverses are independently reproduced and
# bound by the exact reconstruction receipt above.
HISTORICAL_RECONSTRUCTION_RECIPES = {
    "poc/local-private-payment/private-batch-relation/Cargo.toml": {
        "expected_bytes": 1_181,
        "expected_sha256": (
            "3d9b8b5cab53b3680f2ac5e1fb00d0d88293acecf65cb90dc74d21dfcd6c7ca6"
        ),
        "recipe_evidence": "remove-current-lines-11-32-38-through-41",
        "independently_reproduced": True,
        "receipt_bound": True,
    },
    "poc/local-private-payment/private-batch-relation/Cargo.lock": {
        "expected_bytes": 38_060,
        "expected_sha256": (
            "fe0af1b1ff77eba2acf57ea069b8942d0884b2b8e5ce728647373d5f768ec09f"
        ),
        "recipe_evidence": (
            "remove-current-line-865-zeroize-dependency-member"
        ),
        "independently_reproduced": True,
        "receipt_bound": True,
    },
    "poc/local-private-payment/private-batch-relation/src/lib.rs": {
        "expected_bytes": 3_383,
        "expected_sha256": (
            "716b238068027ad2d90f47838dd1fe178d4409fc91ef31c5986d722be109bc5a"
        ),
        "recipe_evidence": (
            "remove-current-line-26-and-current-lines-109-through-178"
        ),
        "independently_reproduced": True,
        "receipt_bound": True,
    },
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1.rs": {
        "expected_bytes": 38_474,
        "expected_sha256": (
            "d6e97d109f054541163fe27e966c7f6afd7e383b189ac199c34c3c2f230804b1"
        ),
        "recipe_evidence": (
            "delete-zeroize-import-restore-fill-zero-delete-full-round-drop"
        ),
        "independently_reproduced": True,
        "receipt_bound": True,
    },
    (
        "poc/local-private-payment/private-batch-relation/src/"
        "counterfactual_w1/offline_verifier.rs"
    ): {
        "expected_bytes": 46_020,
        "expected_sha256": (
            "19593b80dd32d7582486b1595d2b677c27697a02de2ff48ce2b9240b53210a83"
        ),
        "recipe_evidence": "exact-unique-byte-inverses-in-sealed-generator",
        "independently_reproduced": True,
        "receipt_bound": True,
    },
}

HISTORICAL_TRANSFORMS = {
    "poc/local-private-payment/private-batch-relation/Cargo.toml": {
        "current_bytes": 1_348,
        "current_sha256": "05bf2194f1d026dc08cf4b4f87ec81d13686d91a900a531f969f273b8cc31d65",
        "transform_id": "remove-preparer-feature-zeroize-example",
    },
    "poc/local-private-payment/private-batch-relation/Cargo.lock": {
        "current_bytes": 38_072,
        "current_sha256": "9b6c43f8a188d24de5e55b9c310bb094133ffa2a276dca4d8fda6f20985bea5e",
        "transform_id": "remove-direct-zeroize-lock-edge",
    },
    "poc/local-private-payment/private-batch-relation/src/lib.rs": {
        "current_bytes": 6_167,
        "current_sha256": "4c00a14b5de1317a8d209c266af0dbb6db00496ef1f74e3809c1f6a9e9d02091",
        "transform_id": "remove-batch-circuit-zeroization",
    },
    "poc/local-private-payment/private-batch-relation/src/counterfactual_w1.rs": {
        "current_bytes": 38_650,
        "current_sha256": "c9b5803ba8887a4f29e2285b7070fff789528b326a0fe43854f6bd7f01ca939b",
        "transform_id": "remove-round-source-zeroization",
    },
    (
        "poc/local-private-payment/private-batch-relation/src/"
        "counterfactual_w1/offline_verifier.rs"
    ): {
        "current_bytes": 47_558,
        "current_sha256": "71a9906c794a9ca0972f7fadf18ef0a1e9b387ffdc13526541aa6c101cdbed7b",
        "transform_id": "remove-preparer-seam-and-sensitive-buffer-hardening",
    },
}

COMPONENT_BUILD_MEASUREMENTS = (
    ("init", 0.33, 44_524),
    ("bootstrap", 7.86, 123_036),
    ("round-1-inputs", 5.24, 125_148),
    ("round-1-components", 27.85, 143_412),
    ("round-1-close", 8.27, 143_208),
    ("round-2-inputs", 10.62, 143_296),
    ("round-2-components", 33.13, 157_104),
    ("round-2-close", 14.15, 143_316),
)

CHECKPOINTS = (
    ("01-bootstrap", "eee34d50f0876c500700ebf90d99c30c735ff5e601c6696c38e47320d8139763"),
    ("02-round-1-inputs", "9acb95ae0e2b901918951392b5415903e760dd513a11581a84eba20f76bb5516"),
    ("03-round-1-components", "4c5e4155a9d6b41c6a79b8dc278a0fcd93b258a7653bac4f9f1b516de2daa264"),
    ("04-round-1-close", "a9a4c0c741e9f3f6c05c735c3f6e9e261815c8be8307a0d17543180b99cb49eb"),
    ("05-round-2-inputs", "1caff42c40cad980df71d4fc7df58029a622ae5765a9b2fc6c1a62c1cd564588"),
    ("06-round-2-components", "d11d815e42e1ef892e247f83fd237251edb787f8420976511cbc683bc11fb2a1"),
    ("07-round-2-close", "d787de9f71e206850f3d30c45628d5f0affbbc0d55149605117a9fec2a9abdd2"),
)
ROUND_1_ARTIFACT_MANIFEST_SHA256 = {
    "02-round-1-inputs": "14fa09b9364cee7d73c8731af57052d09f82311350eba335796e2cb82627d197",
    "03-round-1-components": "4e338986a9aed7418aecd67dda89bc50e4a3cc3b66680bfcc4a5159e862ddda1",
    "04-round-1-close": "9058a761635dd6858b6d3dddc74a09536b47098bbbbd5b12a6563bb9fdf76076",
}
ROUND_1_EFFECTS_SHA256 = "7983de2691ae57b60167c780436e780a4af9a6a2104134804f9afcdfc1d77219"
ROUND_1_EFFECTS_BYTES = 10_364
ROUND_1_PUBLIC_INPUTS_DECIMAL = (
    "13917591994071772114488105153423377273",
    "33826997814916552742078018202966096202",
)

STANDARD_R1CS_SHA256 = "cc76d603d0cb184f4e43b99d3af9f215274c0a67bdbec28ed435046c2b9c42bc"
STANDARD_R1CS_BYTES = 2_840_345_392
MATRIX_SHA256 = "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab"
ROWS = 13_093_029
VARIABLES = 12_949_821
INSTANCES = 3

PARAMETER_MANIFEST_SHA256 = "c933d85b5f9489f99931e57804cc5e7530d9a14247fbe40101180de0bd401ae4"
COMPRESSED_PK_SHA256 = "4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff"
COMPRESSED_PK_BYTES = 1_749_414_110
DECODED_PK_SHA256 = "170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945"
DECODED_PK_BYTES = 2_608_842_576
VK_SHA256 = "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102"
VK_BYTES = 328
QUERY_SHAPE = {
    "a_query": 12_949_821,
    "b_g1_query": 12_949_821,
    "b_g2_query": 12_949_821,
    "h_query": 16_777_215,
    "l_query": 12_949_818,
    "gamma_abc_g1": 3,
}

PINNED_VERIFIER_BINARY_SHA256 = "915d4fde9e6b28d9569bb61d2629c8b01c09ab78f4acfdf841c55856c4748b9b"
PINNED_VERIFIER_BUILD_RECEIPT_SHA256 = "ea2840748243fb30416cdf4eefee2d33bf06da2bfa54d3a0d04a645a93712a90"
PINNED_VERIFIER_SOURCE_MEMBERS_SHA256 = "57c1820f556cea3e88be5c768600ad5ebf5f0e5df6c2a5be3821644f96132b32"

# The retained stock path hit this exact cap after Ark prover entry. A future
# launch must have a successful bound; the 20 GiB number is an admission floor,
# not a claim that the proof will fit.
RETAINED_STOCK_OOM_MEMORY_MAX = 12 * 1024**3
MINIMUM_MEMORY_AVAILABLE = 20 * 1024**3
MINIMUM_DISK_FREE = 12 * 1024**3
RAYON_THREADS = 8

SOURCE_STATUS = {
    "schema": "kpb-offline-w1-aggregate-attempt-source-status/v2",
    "exact_w1_identity_contract_present": True,
    "descriptor_bound_control_output_core": True,
    "bounded_control_logs_core": True,
    "durable_control_terminal_core": True,
    "preallocated_fallback_terminal_core": True,
    "control_crash_recovery_core": True,
    "control_one_use_prepare_resume_core": True,
    "control_accepted_invalid_fatal_core": True,
    "historical_reconstructed_nonfinal_source_bound": True,
    "current_assignment_and_prover_source_bound": False,
    "source_owned_child_binary_present": False,
    "eligible_inner_prover_binary_present": False,
    "eligible_inner_prover_build_receipt_present": False,
    "source_owned_assignment_bridge_present": False,
    "production_relation_satisfaction_authority_present": False,
    "production_independent_verification_authority_present": False,
    "production_pk_open_path_present": False,
    "production_typed_pk_authority_present": False,
    "production_internal_osrng_enforced": False,
    "production_caller_randomness_entry_present": False,
    "production_prepare_enabled": False,
    "production_proof_enabled": False,
    "canonical_proof_writer_present": False,
    "canonical_stage_08_writer_present": False,
    "network_namespace_launch_path_present": False,
    "current_successful_memory_bound_present": False,
    "authorization": False,
}


class Refused(RuntimeError):
    """A bounded fail-closed refusal."""


def need(value: bool, category: str) -> None:
    if not value:
        raise Refused(category)


def canonical(value) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_fd(fd: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        block = os.pread(fd, 1024 * 1024, total)
        if not block:
            return digest.hexdigest(), total
        digest.update(block)
        total += len(block)


def _stable_file_state(value: os.stat_result) -> tuple[int, ...]:
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


def _stable_directory_state(value: os.stat_result) -> tuple[int, ...]:
    return _stable_file_state(value)


def _safe_directory_fd(path: Path, expected_mode: int) -> dict:
    before = os.lstat(path)
    need(
        stat.S_ISDIR(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and before.st_uid == os.getuid()
        and stat.S_IMODE(before.st_mode) == expected_mode,
        "frozen-directory-stat",
    )
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        opened = os.fstat(descriptor)
        after_path = os.lstat(path)
        need(
            _stable_directory_state(before)
            == _stable_directory_state(opened)
            == _stable_directory_state(after_path),
            "frozen-directory-open-race",
        )
        return {
            "fd": descriptor,
            "path": path,
            "state": _stable_directory_state(opened),
        }
    except BaseException:
        os.close(descriptor)
        raise


def _recheck_directory(reference: dict) -> None:
    need(
        _stable_directory_state(os.fstat(reference["fd"]))
        == reference["state"]
        == _stable_directory_state(os.lstat(reference["path"])),
        "frozen-directory-changed",
    )


def _read_fd(fd: int, maximum: int) -> bytes:
    value = os.fstat(fd)
    need(0 <= value.st_size <= maximum, "bounded-read-size")
    raw = os.pread(fd, value.st_size, 0)
    need(len(raw) == value.st_size, "bounded-read-short")
    return raw


def _safe_regular_fd(
    path: Path,
    expected_sha256: str,
    expected_bytes: int | None = None,
    expected_mode: int | None = None,
) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        need(stat.S_ISREG(value.st_mode), "frozen-ref-not-regular")
        need(value.st_nlink == 1, "frozen-ref-link-count")
        need(value.st_uid == os.getuid(), "frozen-ref-owner")
        need(value.st_mode & 0o022 == 0, "frozen-ref-writable")
        if expected_mode is not None:
            need(stat.S_IMODE(value.st_mode) == expected_mode, "frozen-ref-mode")
        if expected_bytes is not None:
            need(value.st_size == expected_bytes, "frozen-ref-size")
        digest, count = _sha256_fd(fd)
        need(count == value.st_size and digest == expected_sha256, "frozen-ref-content")
        return {
            "fd": fd,
            "device": value.st_dev,
            "inode": value.st_ino,
            "bytes": count,
            "sha256": digest,
        }
    except BaseException:
        os.close(fd)
        raise


def _safe_live_validator_transport_fd(
    path: Path, expected_sha256: str, expected_bytes: int
) -> dict:
    """Pin exact live bytes only as an execution transport, never authority."""
    before_path = os.lstat(path)
    need(
        stat.S_ISREG(before_path.st_mode)
        and not stat.S_ISLNK(before_path.st_mode)
        and before_path.st_uid == os.getuid()
        and before_path.st_nlink == 1,
        "validator-transport-stat",
    )
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        need(
            _stable_file_state(before_path) == _stable_file_state(opened),
            "validator-transport-open-race",
        )
        digest, count = _sha256_fd(fd)
        need(
            count == expected_bytes
            and opened.st_size == expected_bytes
            and digest == expected_sha256,
            "validator-transport-content",
        )
        return {
            "fd": fd,
            "path": path,
            "state": _stable_file_state(opened),
            "bytes": count,
            "sha256": digest,
        }
    except BaseException:
        os.close(fd)
        raise


def _recheck_live_validator_transport(reference: dict) -> None:
    need(
        _stable_file_state(os.fstat(reference["fd"]))
        == reference["state"]
        == _stable_file_state(os.lstat(reference["path"])),
        "validator-transport-changed",
    )
    digest, count = _sha256_fd(reference["fd"])
    need(
        count == reference["bytes"] and digest == reference["sha256"],
        "validator-transport-rehash",
    )


def _safe_regular_at(
    directory_fd: int,
    name: str,
    expected_sha256: str,
    expected_bytes: int,
    expected_mode: int = 0o400,
) -> dict:
    need("/" not in name and name not in ("", ".", ".."), "frozen-name")
    before_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    fd = os.open(
        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
    )
    try:
        value = os.fstat(fd)
        need(
            _stable_file_state(before_path) == _stable_file_state(value)
            and
            stat.S_ISREG(value.st_mode)
            and value.st_nlink == 1
            and value.st_uid == os.getuid()
            and stat.S_IMODE(value.st_mode) == expected_mode
            and value.st_size == expected_bytes,
            "frozen-artifact-stat",
        )
        digest, count = _sha256_fd(fd)
        after = os.fstat(fd)
        after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        need(
            _stable_file_state(value)
            == _stable_file_state(after)
            == _stable_file_state(after_path),
            "frozen-artifact-race",
        )
        need(
            digest == expected_sha256 and count == expected_bytes,
            "frozen-artifact-content",
        )
        return {
            "fd": fd,
            "device": value.st_dev,
            "inode": value.st_ino,
            "bytes": count,
            "sha256": digest,
        }
    except BaseException:
        os.close(fd)
        raise


def close_refs(refs: list[dict]) -> None:
    for item in refs:
        fd = item.pop("fd", -1)
        if fd >= 0:
            os.close(fd)


def _safe_directory_at(parent: dict, name: str, expected_mode: int) -> dict:
    need("/" not in name and name not in ("", ".", ".."), "frozen-directory-name")
    before = os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
    need(
        stat.S_ISDIR(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and before.st_uid == os.getuid()
        and stat.S_IMODE(before.st_mode) == expected_mode,
        "frozen-child-directory-stat",
    )
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent["fd"],
    )
    try:
        opened = os.fstat(descriptor)
        after = os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
        need(
            _stable_directory_state(before)
            == _stable_directory_state(opened)
            == _stable_directory_state(after),
            "frozen-child-directory-race",
        )
        return {
            "fd": descriptor,
            "path": parent["path"] / name,
            "state": _stable_directory_state(opened),
        }
    except BaseException:
        os.close(descriptor)
        raise


def _load_canonical_json_at(
    directory_fd: int, name: str, expected_sha256: str, expected_bytes: int
) -> tuple[dict, dict]:
    reference = _safe_regular_at(
        directory_fd, name, expected_sha256, expected_bytes, 0o400
    )
    try:
        raw = _read_fd(reference["fd"], expected_bytes)
        value = json.loads(raw)
        need(type(value) is dict and raw == canonical(value), "frozen-json-canonical")
        return value, {key: item for key, item in reference.items() if key != "fd"}
    finally:
        close_refs([reference])


def _false_actions() -> dict:
    return {
        "setup": False,
        "pk_decode": False,
        "synthesis": False,
        "proof": False,
        "independent_verification": False,
        "stage_08": False,
        "network": False,
        "funds": False,
    }


def _observe_regular(path: Path) -> dict:
    """Hash one path without following symlinks or treating it as authority."""
    result = {
        "path": str(path),
        "exists": False,
        "symlink": False,
        "regular": False,
        "owner_uid": None,
        "link_count": None,
        "mode_octal": None,
        "bytes": None,
        "sha256": None,
        "stable_during_observation": False,
        "error": None,
    }
    try:
        before_path = os.lstat(path)
    except FileNotFoundError:
        return result
    except BaseException as error:
        result["error"] = type(error).__name__
        return result
    result.update(
        {
            "exists": True,
            "symlink": stat.S_ISLNK(before_path.st_mode),
            "regular": stat.S_ISREG(before_path.st_mode),
            "owner_uid": before_path.st_uid,
            "link_count": before_path.st_nlink,
            "mode_octal": f"{stat.S_IMODE(before_path.st_mode):04o}",
        }
    )
    if not result["regular"] or result["symlink"]:
        return result
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            digest, count = _sha256_fd(fd)
            after = os.fstat(fd)
            stable = (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                    after.st_ctime_ns)
                and (before.st_dev, before.st_ino)
                == (before_path.st_dev, before_path.st_ino)
                and count == after.st_size
            )
            result.update(
                {
                    "owner_uid": after.st_uid,
                    "link_count": after.st_nlink,
                    "mode_octal": f"{stat.S_IMODE(after.st_mode):04o}",
                    "bytes": count,
                    "sha256": digest,
                    "stable_during_observation": stable,
                }
            )
        finally:
            os.close(fd)
    except BaseException as error:
        result["error"] = type(error).__name__
    return result


def _load_pinned_json(
    path: Path, expected_sha256: str, expected_bytes: int
) -> dict:
    reference = _safe_regular_fd(
        path, expected_sha256, expected_bytes, expected_mode=0o400
    )
    try:
        raw = _read_fd(reference["fd"], expected_bytes)
        value = json.loads(raw)
        need(raw == canonical(value), "pinned-json-canonical")
        return value
    finally:
        close_refs([reference])


def _validate_diagnostic_plan(plan: dict) -> None:
    members = plan.get("source_members")
    need(
        plan.get("run_id") == RUN_ID
        and plan.get("source_instance_epoch_id") == SOURCE_INSTANCE_EPOCH_ID
        and plan.get("plan_identity_sha256") == PLAN_IDENTITY_SHA256
        and plan.get("source_closure_sha256") == W1_SOURCE_CLOSURE_SHA256
        and plan.get("selected_build", {}).get("build_identity_sha256")
        == W1_SELECTED_BUILD_IDENTITY_SHA256
        and type(members) is list
        and len(members) == PLAN_SOURCE_MEMBER_COUNT
        and sum(item.get("bytes", -1) for item in members)
        == PLAN_SOURCE_MEMBER_BYTES
        and sha256_bytes(canonical(members)) == W1_SOURCE_CLOSURE_SHA256,
        "diagnostic-plan-binding",
    )
    paths = []
    for item in members:
        need(
            set(item) == {"path", "sha256", "bytes"}
            and type(item["path"]) is str
            and Path(item["path"]).is_absolute()
            and type(item["sha256"]) is str
            and len(item["sha256"]) == 64
            and type(item["bytes"]) is int
            and item["bytes"] >= 0,
            "diagnostic-plan-source-member",
        )
        paths.append(item["path"])
    need(len(set(paths)) == len(paths), "diagnostic-plan-source-duplicate")


def _validate_diagnostic_owner_closure(value: dict) -> None:
    members = value.get("members")
    need(
        set(value)
        == {
            "schema",
            "classification",
            "derivation",
            "dep_info_sha256",
            "member_count",
            "members_identity_sha256",
            "members",
        }
        and value.get("schema")
        == "kpb-offline-w1-owner-aux-source-closure/v1"
        and value.get("member_count") == OWNER_AUX_SOURCE_MEMBER_COUNT
        and value.get("members_identity_sha256")
        == OWNER_AUX_SOURCE_MEMBERS_SHA256
        and type(members) is list
        and len(members) == OWNER_AUX_SOURCE_MEMBER_COUNT
        and sha256_bytes(canonical(members)) == OWNER_AUX_SOURCE_MEMBERS_SHA256,
        "diagnostic-owner-closure-binding",
    )
    paths = []
    for item in members:
        need(
            set(item) == {"path", "sha256", "bytes"}
            and type(item["path"]) is str
            and Path(item["path"]).is_absolute()
            and type(item["sha256"]) is str
            and len(item["sha256"]) == 64
            and type(item["bytes"]) is int
            and item["bytes"] >= 0,
            "diagnostic-owner-closure-member",
        )
        paths.append(item["path"])
    need(len(set(paths)) == len(paths), "diagnostic-owner-closure-duplicate")


def _bundle_reference(relative: str, byte_count: int, digest: str) -> dict:
    return {
        "path": str(HISTORICAL_SOURCE_BUNDLE_ROOT / relative),
        "bytes": byte_count,
        "sha256": digest,
    }


def _generator_seal_reference() -> dict:
    private_parent = HISTORICAL_SOURCE_BUNDLE_ROOT.parent
    return {
        "path": str(private_parent / "GENERATOR-SEAL.json"),
        "bytes": HISTORICAL_GENERATOR_SEAL_BYTES,
        "sha256": HISTORICAL_GENERATOR_SEAL_SHA256,
        "sealer": {
            "path": str(private_parent / "SEALER-SOURCE.py"),
            "bytes": HISTORICAL_SEALER_BYTES,
            "sha256": HISTORICAL_SEALER_SHA256,
        },
    }


def _validate_historical_documents(
    manifest: dict, receipt: dict, plan: dict, owner: dict
) -> list[str]:
    """Bind exact nonfinal provenance semantics; mint no current authority."""
    boundaries = {
        "current_source": False,
        "build_reproduced": False,
        "binary_reproduced": False,
        "authorization": False,
        "assignment_or_proof_generated": False,
        "setup_network_or_funds": False,
    }
    plan_reference = _bundle_reference("PLAN.json", PLAN_BYTES, PLAN_SHA256)
    owner_reference = _bundle_reference(
        "OWNER-AUX-SOURCE-CLOSURE.json",
        OWNER_AUX_SOURCE_CLOSURE_BYTES,
        OWNER_AUX_SOURCE_CLOSURE_SHA256,
    )
    generator_reference = _bundle_reference(
        "RECONSTRUCTION-SOURCE.py",
        HISTORICAL_GENERATOR_BYTES,
        HISTORICAL_GENERATOR_SHA256,
    )
    executed_generator_reference = {
        "path": str(HISTORICAL_SOURCE_BUNDLE_ROOT.parent / "RECONSTRUCTION-SOURCE.py"),
        "bytes": HISTORICAL_GENERATOR_BYTES,
        "sha256": HISTORICAL_GENERATOR_SHA256,
    }
    generator_seal = _generator_seal_reference()
    need(
        set(manifest)
        == {
            "schema",
            "classification",
            "plan",
            "plan_identity_sha256",
            "source_members_identity_sha256",
            "member_count",
            "members",
            "owner_aux_source_closure",
            "reconstruction_generator",
            "non_authoritative_provenance",
            "boundaries",
        }
        and manifest["schema"]
        == "kpb-historical-w1-source-closure-snapshot/v1"
        and manifest["classification"] == "HISTORICAL_RECONSTRUCTED_NONFINAL"
        and manifest["plan"] == plan_reference
        and manifest["plan_identity_sha256"] == PLAN_IDENTITY_SHA256
        and manifest["source_members_identity_sha256"]
        == W1_SOURCE_CLOSURE_SHA256
        and manifest["member_count"] == PLAN_SOURCE_MEMBER_COUNT
        and manifest["boundaries"] == boundaries
        and manifest["non_authoritative_provenance"]
        == {
            "original_plan": {
                "path": str(COMPONENT_ROOT / "PLAN.json"),
                "bytes": PLAN_BYTES,
                "sha256": PLAN_SHA256,
            },
            "original_owner_aux_source_closure": {
                "path": str(OWNER_AUX_SOURCE_CLOSURE),
                "bytes": OWNER_AUX_SOURCE_CLOSURE_BYTES,
                "sha256": OWNER_AUX_SOURCE_CLOSURE_SHA256,
            },
        }
        and manifest["reconstruction_generator"]
        == {
            "executed_source": executed_generator_reference,
            "seal": generator_seal,
        },
        "historical-manifest-binding",
    )

    plan_members = plan["source_members"]
    manifest_members = manifest["members"]
    need(
        type(manifest_members) is list
        and len(manifest_members) == PLAN_SOURCE_MEMBER_COUNT,
        "historical-manifest-members",
    )
    expected_names = []
    expected_transformed = []
    snapshots = []
    for ordinal, original in enumerate(plan_members):
        name = f"{ordinal:03d}-{original['sha256']}"
        expected_names.append(name)
        snapshot = _bundle_reference(
            f"members/{name}", original["bytes"], original["sha256"]
        )
        snapshots.append(snapshot)
        try:
            relative = Path(original["path"]).relative_to(ROOT).as_posix()
        except ValueError:
            relative = None
        transform = HISTORICAL_TRANSFORMS.get(relative) if relative else None
        reconstruction = (
            {"kind": "byte-for-byte-copy"}
            if transform is None
            else {"kind": "unique-byte-transform", **transform}
        )
        need(
            manifest_members[ordinal]
            == {
                "ordinal": ordinal,
                "original": original,
                "snapshot": snapshot,
                "reconstruction": reconstruction,
            },
            "historical-manifest-member-binding",
        )
        if transform is not None:
            expected_transformed.append(
                {"ordinal": ordinal, "original": original, **reconstruction}
            )
    need(len(expected_transformed) == 5, "historical-transform-count")

    owner_members = owner["members"]
    plan_index = {
        (item["path"], item["bytes"], item["sha256"]): ordinal
        for ordinal, item in enumerate(plan_members)
    }
    try:
        owner_ordinals = [
            plan_index[(item["path"], item["bytes"], item["sha256"])]
            for item in owner_members
        ]
    except KeyError:
        raise Refused("historical-owner-not-plan-subset") from None
    expected_owner_members = [
        {
            "owner_ordinal": owner_ordinal,
            "plan_ordinal": plan_ordinal,
            "original": owner_members[owner_ordinal],
            "snapshot": snapshots[plan_ordinal],
        }
        for owner_ordinal, plan_ordinal in enumerate(owner_ordinals)
    ]
    need(
        manifest["owner_aux_source_closure"]
        == {
            "document": owner_reference,
            "members_identity_sha256": OWNER_AUX_SOURCE_MEMBERS_SHA256,
            "member_count": OWNER_AUX_SOURCE_MEMBER_COUNT,
            "ordered_exact_plan_subset": True,
            "ordered_plan_ordinals": owner_ordinals,
            "members": expected_owner_members,
        },
        "historical-owner-subset-binding",
    )

    receipt_keys = {
        "schema",
        "classification",
        "manifest",
        "generator",
        "executed_generator_source",
        "generator_seal",
        "sealed_plan",
        "sealed_owner_aux_source_closure",
        "transformed_members",
        "copied_members",
        "all_plan_members_exact",
        "owner_aux_members_are_ordered_exact_plan_subset",
        "owner_aux_member_count",
        "source_members_identity_sha256",
        "owner_aux_members_identity_sha256",
        "seal_controls",
        "current_source",
        "build_reproduced",
        "binary_reproduced",
        "authorization",
        "assignment_or_proof_generated",
        "setup_network_or_funds",
        "receipt_identity_sha256",
    }
    need(
        set(receipt) == receipt_keys
        and receipt["schema"] == "kpb-historical-w1-source-reconstruction/v1"
        and receipt["classification"] == "HISTORICAL_RECONSTRUCTED_NONFINAL"
        and receipt["manifest"]
        == _bundle_reference(
            "MANIFEST.json", HISTORICAL_MANIFEST_BYTES, HISTORICAL_MANIFEST_SHA256
        )
        and receipt["generator"] == generator_reference
        and receipt["executed_generator_source"] == executed_generator_reference
        and receipt["generator_seal"] == generator_seal
        and receipt["sealed_plan"] == plan_reference
        and receipt["sealed_owner_aux_source_closure"] == owner_reference
        and receipt["transformed_members"] == expected_transformed
        and receipt["copied_members"] == 76
        and receipt["all_plan_members_exact"] is True
        and receipt["owner_aux_members_are_ordered_exact_plan_subset"] is True
        and receipt["owner_aux_member_count"] == OWNER_AUX_SOURCE_MEMBER_COUNT
        and receipt["source_members_identity_sha256"] == W1_SOURCE_CLOSURE_SHA256
        and receipt["owner_aux_members_identity_sha256"]
        == OWNER_AUX_SOURCE_MEMBERS_SHA256
        and all(receipt[key] is False for key in boundaries),
        "historical-receipt-binding",
    )
    need(
        receipt["seal_controls"]
        == {
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
        "historical-receipt-controls",
    )
    unsigned_receipt = dict(receipt)
    receipt_identity = unsigned_receipt.pop("receipt_identity_sha256")
    need(
        receipt_identity == sha256_bytes(canonical(unsigned_receipt)),
        "historical-receipt-self-identity",
    )
    return expected_names


def validate_historical_source_bundle() -> dict:
    """Rehash the full immutable bundle without using live source paths."""
    root = _safe_directory_fd(HISTORICAL_SOURCE_BUNDLE_ROOT, 0o500)
    members = None
    try:
        need(
            sorted(os.listdir(root["fd"]))
            == sorted(
                [
                    "MANIFEST.json",
                    "OWNER-AUX-SOURCE-CLOSURE.json",
                    "PLAN.json",
                    "RECONSTRUCTION-SOURCE.py",
                    "TRANSFORMATION-RECEIPT.json",
                    "members",
                ]
            ),
            "historical-root-exact-set",
        )
        members = _safe_directory_at(root, "members", 0o500)
        manifest, _ = _load_canonical_json_at(
            root["fd"],
            "MANIFEST.json",
            HISTORICAL_MANIFEST_SHA256,
            HISTORICAL_MANIFEST_BYTES,
        )
        receipt, _ = _load_canonical_json_at(
            root["fd"],
            "TRANSFORMATION-RECEIPT.json",
            HISTORICAL_RECEIPT_SHA256,
            HISTORICAL_RECEIPT_BYTES,
        )
        plan, _ = _load_canonical_json_at(
            root["fd"], "PLAN.json", PLAN_SHA256, PLAN_BYTES
        )
        owner, _ = _load_canonical_json_at(
            root["fd"],
            "OWNER-AUX-SOURCE-CLOSURE.json",
            OWNER_AUX_SOURCE_CLOSURE_SHA256,
            OWNER_AUX_SOURCE_CLOSURE_BYTES,
        )
        generator = _safe_regular_at(
            root["fd"],
            "RECONSTRUCTION-SOURCE.py",
            HISTORICAL_GENERATOR_SHA256,
            HISTORICAL_GENERATOR_BYTES,
            0o400,
        )
        close_refs([generator])
        _validate_diagnostic_plan(plan)
        _validate_diagnostic_owner_closure(owner)
        expected_names = _validate_historical_documents(
            manifest, receipt, plan, owner
        )
        need(
            sorted(os.listdir(members["fd"])) == expected_names,
            "historical-member-exact-set",
        )
        for ordinal, item in enumerate(plan["source_members"]):
            reference = _safe_regular_at(
                members["fd"],
                expected_names[ordinal],
                item["sha256"],
                item["bytes"],
                0o400,
            )
            close_refs([reference])
        _recheck_directory(members)
        _recheck_directory(root)
        return {
            "path": str(HISTORICAL_SOURCE_BUNDLE_ROOT),
            "classification": "HISTORICAL_RECONSTRUCTED_NONFINAL",
            "manifest_sha256": HISTORICAL_MANIFEST_SHA256,
            "receipt_sha256": HISTORICAL_RECEIPT_SHA256,
            "generator_sha256": HISTORICAL_GENERATOR_SHA256,
            "plan_sha256": PLAN_SHA256,
            "owner_aux_source_closure_sha256": OWNER_AUX_SOURCE_CLOSURE_SHA256,
            "member_count": PLAN_SOURCE_MEMBER_COUNT,
            "member_bytes": PLAN_SOURCE_MEMBER_BYTES,
            "all_members_rehashed": True,
            "current_source": False,
            "build_reproduced": False,
            "authorization": False,
            "accepted_by_this_source": True,
        }
    finally:
        if members is not None:
            close_refs([members])
        close_refs([root])


def _source_member_drift(expected: list[dict], observed: list[dict]) -> list[dict]:
    """Return every missing, substituted, raced, or extra source member."""
    expected_by_path = {item["path"]: item for item in expected}
    observed_by_path = {item["path"]: item for item in observed}
    need(
        len(expected_by_path) == len(expected)
        and len(observed_by_path) == len(observed),
        "source-observation-duplicate",
    )
    drift = []
    for path in sorted(set(expected_by_path) | set(observed_by_path)):
        wanted = expected_by_path.get(path)
        actual = observed_by_path.get(path)
        reasons = []
        if wanted is None:
            reasons.append("unexpected-member")
        elif actual is None or not actual.get("exists"):
            reasons.append("missing-member")
        else:
            if actual.get("symlink"):
                reasons.append("symlink-member")
            if not actual.get("regular"):
                reasons.append("non-regular-member")
            if actual.get("error") is not None:
                reasons.append("member-read-error")
            if not actual.get("stable_during_observation"):
                reasons.append("member-raced")
            if actual.get("bytes") != wanted["bytes"]:
                reasons.append("member-size-drift")
            if actual.get("sha256") != wanted["sha256"]:
                reasons.append("member-content-drift")
        if reasons:
            drift.append(
                {
                    "path": path,
                    "expected": wanted,
                    "observed": actual,
                    "reasons": reasons,
                }
            )
    return drift


def _directory_observation(path: Path) -> dict:
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return {
            "path": str(path),
            "exists": False,
            "directory": False,
            "symlink": False,
            "mode_octal": None,
        }
    return {
        "path": str(path),
        "exists": True,
        "directory": stat.S_ISDIR(value.st_mode),
        "symlink": stat.S_ISLNK(value.st_mode),
        "mode_octal": f"{stat.S_IMODE(value.st_mode):04o}",
    }


def component_source_diagnostics() -> dict:
    """Report why live paths cannot authorize exact component validation.

    This reads and hashes source only. Live-path drift remains diagnostic; only
    the exact sealed historical bundle can support component revalidation. It
    never claims current source or opens the aggregate PK.
    """
    blockers = []
    live_path_diagnostics = []
    plan_observed = _observe_regular(COMPONENT_ROOT / "PLAN.json")
    owner_closure_observed = _observe_regular(OWNER_AUX_SOURCE_CLOSURE)
    fixture_observed = _observe_regular(HERE / "offline_w1_fixture.py")
    plan = None
    owner_closure = None
    try:
        plan = _load_pinned_json(
            COMPONENT_ROOT / "PLAN.json", PLAN_SHA256, PLAN_BYTES
        )
        _validate_diagnostic_plan(plan)
    except BaseException as error:
        blockers.append(
            {
                "code": "sealed-plan-record-invalid",
                "category": type(error).__name__,
                "observed": plan_observed,
            }
        )
    try:
        owner_closure = _load_pinned_json(
            OWNER_AUX_SOURCE_CLOSURE,
            OWNER_AUX_SOURCE_CLOSURE_SHA256,
            OWNER_AUX_SOURCE_CLOSURE_BYTES,
        )
        _validate_diagnostic_owner_closure(owner_closure)
    except BaseException as error:
        blockers.append(
            {
                "code": "retained-owner-aux-source-closure-record-invalid",
                "category": type(error).__name__,
                "observed": owner_closure_observed,
            }
        )

    fixture_exact = (
        fixture_observed["exists"]
        and fixture_observed["regular"]
        and not fixture_observed["symlink"]
        and fixture_observed["owner_uid"] == os.getuid()
        and fixture_observed["link_count"] == 1
        and fixture_observed["mode_octal"] == "0400"
        and fixture_observed["bytes"] == FIXTURE_SOURCE_BYTES
        and fixture_observed["sha256"] == FIXTURE_SOURCE_SHA256
        and fixture_observed["stable_during_observation"]
        and fixture_observed["error"] is None
    )
    if not fixture_exact:
        live_path_diagnostics.append(
            {
                "code": "fixture-live-source-not-immutable-exact",
                "expected": {
                    "path": str(HERE / "offline_w1_fixture.py"),
                    "mode_octal": "0400",
                    "bytes": FIXTURE_SOURCE_BYTES,
                    "sha256": FIXTURE_SOURCE_SHA256,
                    "owner_uid": os.getuid(),
                    "link_count": 1,
                },
                "observed": fixture_observed,
            }
        )

    plan_drift = []
    if plan is not None:
        plan_observations = [
            _observe_regular(Path(item["path"])) for item in plan["source_members"]
        ]
        plan_drift = _source_member_drift(plan["source_members"], plan_observations)
        if plan_drift:
            live_path_diagnostics.append(
                {
                    "code": "sealed-plan-live-source-member-drift",
                    "drift_count": len(plan_drift),
                    "members": plan_drift,
                }
            )

    owner_drift = []
    if owner_closure is not None:
        owner_observations = [
            _observe_regular(Path(item["path"]))
            for item in owner_closure["members"]
        ]
        owner_drift = _source_member_drift(
            owner_closure["members"], owner_observations
        )
        if owner_drift:
            live_path_diagnostics.append(
                {
                    "code": "retained-owner-aux-live-source-member-drift",
                    "drift_count": len(owner_drift),
                    "members": owner_drift,
                }
            )

    historical_observation = _directory_observation(HISTORICAL_SOURCE_BUNDLE_ROOT)
    historical = None
    try:
        historical = validate_historical_source_bundle()
    except BaseException as error:
        blockers.append(
            {
                "code": "immutable-historical-source-bundle-invalid",
                "category": type(error).__name__,
                "path_observation": historical_observation,
                "required_manifest_sha256": HISTORICAL_MANIFEST_SHA256,
                "required_receipt_sha256": HISTORICAL_RECEIPT_SHA256,
            }
        )
    ready = plan is not None and owner_closure is not None and historical is not None
    return {
        "schema": "kpb-offline-w1-component-source-diagnostics/v1",
        "status": (
            "HISTORICAL_COMPONENT_SOURCE_BOUND_NONFINAL"
            if ready
            else "COMPONENT_SOURCE_BINDING_BLOCKED"
        ),
        "ready_for_exact_component_validation": ready,
        "validation_policy": {
            "live_path_match_sufficient": False,
            "immutable_full_81_member_historical_bundle_required": True,
            "canonical_reconstruction_receipt_required": True,
            "historical_bundle_may_claim_current_source": False,
            "historical_bundle_may_claim_build_reproduced": False,
        },
        "fixture_source": fixture_observed,
        "sealed_plan": {
            "observed": plan_observed,
            "trusted": plan is not None,
            "expected_source_members": PLAN_SOURCE_MEMBER_COUNT,
            "expected_source_bytes": PLAN_SOURCE_MEMBER_BYTES,
            "live_exact_members": (
                None if plan is None else PLAN_SOURCE_MEMBER_COUNT - len(plan_drift)
            ),
            "live_drift_members": plan_drift,
        },
        "retained_owner_aux_source_closure": {
            "observed": owner_closure_observed,
            "trusted": owner_closure is not None,
            "expected_source_members": OWNER_AUX_SOURCE_MEMBER_COUNT,
            "live_exact_members": (
                None
                if owner_closure is None
                else OWNER_AUX_SOURCE_MEMBER_COUNT - len(owner_drift)
            ),
            "live_drift_members": owner_drift,
        },
        "historical_source_bundle": (
            {
                **historical_observation,
                "receipt_sha256_bound_by_this_source": HISTORICAL_RECEIPT_SHA256,
                "accepted_by_this_source": False,
            }
            if historical is None
            else {**historical_observation, **historical}
        ),
        "live_path_diagnostics": live_path_diagnostics,
        "blockers": blockers,
        "actions_performed": _false_actions(),
        "authorization": False,
    }


def source_closure_plan(diagnostics: dict | None = None) -> dict:
    """Return a non-executable full-source freeze/regeneration design."""
    diagnostics = diagnostics or component_source_diagnostics()
    plan = _load_pinned_json(
        COMPONENT_ROOT / "PLAN.json", PLAN_SHA256, PLAN_BYTES
    )
    _validate_diagnostic_plan(plan)
    owner = _load_pinned_json(
        OWNER_AUX_SOURCE_CLOSURE,
        OWNER_AUX_SOURCE_CLOSURE_SHA256,
        OWNER_AUX_SOURCE_CLOSURE_BYTES,
    )
    _validate_diagnostic_owner_closure(owner)
    measurements = [
        {
            "stage": stage,
            "wall_seconds": wall,
            "max_rss_kib": rss,
        }
        for stage, wall, rss in COMPONENT_BUILD_MEASUREMENTS
    ]
    proposed_tool = HERE / "offline_w1_source_bundle.py"
    return {
        "schema": "kpb-offline-w1-source-closure-plan/v1",
        "classification": "DESIGN_ONLY_NO_SETUP_NO_PK_OPEN_NO_SYNTHESIS_NO_PROOF",
        "execution_enabled": False,
        "exact_command_ready": False,
        "historical_component_validation": {
            "bundle_root": str(HISTORICAL_SOURCE_BUNDLE_ROOT),
            "complete_sealed_plan_member_count": PLAN_SOURCE_MEMBER_COUNT,
            "complete_sealed_plan_member_bytes": PLAN_SOURCE_MEMBER_BYTES,
            "expected_source_closure_sha256": W1_SOURCE_CLOSURE_SHA256,
            "source_members": plan["source_members"],
            "reconstruction_recipes": HISTORICAL_RECONSTRUCTION_RECIPES,
            "required_receipt_flags": {
                "historical_reconstructed_nonfinal": True,
                "current_source": False,
                "build_reproduced": False,
                "authorization": False,
            },
            "requirements": [
                "copy-all-81-exact-member-bytes-into-create-new-tree",
                "canonical-original-path-to-bundle-path-map",
                "ordered-transforms-with-unique-match-assertions",
                "exact-result-hash-and-byte-count-for-every-transform",
                "mode-0400-files-and-no-symlinks",
                "fsync-each-file-and-directory-before-noreplace-publication",
                "rehash-same-inodes-before-and-after-validation",
                "read-only-no-network-namespace-for-historical-validator",
                "never-substitute-reconstruction-as-current-source",
            ],
            "manifest_sha256": HISTORICAL_MANIFEST_SHA256,
            "receipt_sha256": HISTORICAL_RECEIPT_SHA256,
            "accepted_by_current_source": diagnostics[
                "historical_source_bundle"
            ]["accepted_by_this_source"],
        },
        "retained_owner_aux_inputs": {
            "source_closure_sha256": OWNER_AUX_SOURCE_CLOSURE_SHA256,
            "source_members_identity_sha256": OWNER_AUX_SOURCE_MEMBERS_SHA256,
            "source_members": owner["members"],
        },
        "fresh_assignment_and_prover_source": {
            "bundle_root": str(FRESH_SOURCE_FINAL_ROOT),
            "assignment_preparer_final_sha256": None,
            "waiting_for_assignment_preparer_final_hash": True,
            "must_be_separate_from_historical_bundle": True,
            "requirements": [
                "derive-complete-transitive-local-source-set",
                "copy-members-create-new-and-seal-mode-0400",
                "build-from-the-sealed-snapshot-with-writable-target-elsewhere",
                "bind-dep-info-paths-back-to-snapshot-members",
                "rehash-same-snapshot-inodes-before-and-after-build",
                "refuse-missing-extra-mutated-or-raced-members",
                "cargo-locked-offline-and-network-disabled",
            ],
            "receipt_sha256": None,
            "accepted_by_current_source": False,
        },
        "planned_command_path": [
            {
                "phase": "freeze-historical-source",
                "implemented": proposed_tool.is_file(),
                "command": [
                    sys.executable,
                    str(proposed_tool),
                    "freeze-historical",
                    "--sealed-plan",
                    str(COMPONENT_ROOT / "PLAN.json"),
                    "--output",
                    str(HISTORICAL_SOURCE_BUNDLE_ROOT),
                ],
                "may_execute_now": False,
            },
            {
                "phase": "freeze-current-source-final",
                "implemented": proposed_tool.is_file(),
                "command": [
                    sys.executable,
                    str(proposed_tool),
                    "freeze-current",
                    "--output",
                    str(FRESH_SOURCE_FINAL_ROOT),
                ],
                "may_execute_now": False,
            },
            {
                "phase": "conditional-owner-aux-rebuild",
                "implemented": False,
                "command": None,
                "target_root": str(CONDITIONAL_OWNER_AUX_TARGET),
                "build_bundle_root": str(CONDITIONAL_OWNER_AUX_BUILD),
                "may_execute_now": False,
            },
            {
                "phase": "conditional-component-regeneration",
                "implemented": False,
                "command": None,
                "component_root": str(CONDITIONAL_COMPONENT_ROOT),
                "reason": "hold-until-historical-bundle-review-decides-if-needed",
                "may_execute_now": False,
            },
        ],
        "resource_evidence": {
            "retained_component_root_bytes": 1_054_158_726,
            "retained_component_published_file_bytes": 526_139_935,
            "retained_owner_aux_target_bytes": 294_666_117,
            "retained_owner_aux_build_bundle_bytes": 2_384_346,
            "retained_component_measurements": measurements,
            "retained_component_total_wall_seconds": 107.45,
            "retained_component_peak_rss_kib": 157_104,
            "retained_owner_aux_build_was_cached": True,
            "retained_cached_owner_aux_wall_seconds": 0.06,
            "retained_cached_owner_aux_peak_rss_kib": 48_936,
            "fresh_owner_aux_build_bound_present": False,
            "proof_peak_rss_measured": False,
            "component_only_planning_free_disk_bytes": 4 * 1024**3,
            "component_only_planning_memory_available_bytes": 4 * 1024**3,
            "planning_floor_is_measurement": False,
            "wall_timeout_allowed": False,
            "stages_must_run_sequentially": True,
        },
        "current_diagnostics": diagnostics,
        "actions_performed": _false_actions(),
        "authorization": False,
    }


def validate_frozen_component_descriptors() -> list[dict]:
    """Hash exact preflight, plan, fixture source, and seven checkpoints.

    The proving key is intentionally not opened. This function creates no
    relation-satisfaction authority.
    """
    refs: list[dict] = []
    try:
        preflight = _safe_regular_fd(
            COMPONENT_ROOT / "AGGREGATE-PROOF-PREFLIGHT.json",
            PREFLIGHT_SHA256,
            PREFLIGHT_BYTES,
            0o400,
        )
        preflight["semantic"] = "sealed-preflight"
        refs.append(preflight)
        plan = _safe_regular_fd(
            COMPONENT_ROOT / "PLAN.json", PLAN_SHA256, expected_mode=0o400
        )
        plan["semantic"] = "plan"
        refs.append(plan)
        plan_value = json.loads(_read_fd(plan["fd"], 64 * 1024))
        need(
            plan_value["run_id"] == RUN_ID
            and plan_value["source_instance_epoch_id"] == SOURCE_INSTANCE_EPOCH_ID
            and plan_value["plan_identity_sha256"] == PLAN_IDENTITY_SHA256
            and plan_value["source_closure_sha256"] == W1_SOURCE_CLOSURE_SHA256
            and plan_value["selected_build"]["build_identity_sha256"]
            == W1_SELECTED_BUILD_IDENTITY_SHA256,
            "plan-exact-identity",
        )
        fixture = _safe_regular_fd(
            HISTORICAL_SOURCE_BUNDLE_ROOT
            / "members"
            / HISTORICAL_FIXTURE_MEMBER_NAME,
            FIXTURE_SOURCE_SHA256,
            expected_mode=0o400,
        )
        fixture["semantic"] = "fixture-source"
        refs.append(fixture)
        for directory, digest in CHECKPOINTS:
            item = _safe_regular_fd(
                COMPONENT_ROOT / directory / "CHECKPOINT.json",
                digest,
                expected_mode=0o400,
            )
            item["semantic"] = directory
            refs.append(item)
        return refs
    except BaseException:
        close_refs(refs)
        raise


def validate_exact_round_1_artifacts(refs: list[dict]) -> dict:
    """Rehash exact round-1 content referenced by sealed checkpoints.

    This is content validation only: it does not synthesize the circuit, test
    satisfaction, open parameters, or mint any authority.
    """
    by_semantic = {item["semantic"]: item for item in refs}
    observed = {}
    for stage in ROUND_1_ARTIFACT_MANIFEST_SHA256:
        checkpoint = json.loads(_read_fd(by_semantic[stage]["fd"], 64 * 1024))
        artifacts = checkpoint["artifacts"]
        need(
            sha256_bytes(canonical(artifacts))
            == ROUND_1_ARTIFACT_MANIFEST_SHA256[stage],
            "round-1-artifact-manifest",
        )
        stage_fd = os.open(
            COMPONENT_ROOT / stage,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            for name, descriptor in artifacts.items():
                item = _safe_regular_at(
                    stage_fd, name, descriptor["sha256"], descriptor["bytes"]
                )
                os.close(item.pop("fd"))
            observed[stage] = {
                "artifacts": len(artifacts),
                "manifest_sha256": ROUND_1_ARTIFACT_MANIFEST_SHA256[stage],
            }
        finally:
            os.close(stage_fd)
    effects = bytes.fromhex(ROUND_1_EFFECTS_SHA256)
    derived = (
        str(int.from_bytes(effects[:16], "little")),
        str(int.from_bytes(effects[16:], "little")),
    )
    need(derived == ROUND_1_PUBLIC_INPUTS_DECIMAL, "round-1-public-input-binding")
    return {
        "round_1_artifacts": observed,
        "effects_sha256": ROUND_1_EFFECTS_SHA256,
        "public_inputs_decimal": list(derived),
        "relation_satisfaction_checked": False,
        "pk_opened": False,
    }


def rerun_component_validator() -> dict:
    """Run exact fixture bytes as nonauthoritative read-only transport."""
    source = _safe_live_validator_transport_fd(
        HERE / "offline_w1_fixture.py",
        FIXTURE_SOURCE_SHA256,
        FIXTURE_SOURCE_BYTES,
    )
    try:
        result = subprocess.run(
            [
                sys.executable,
                f"/proc/self/fd/{source['fd']}",
                "validate",
                "--root",
                str(COMPONENT_ROOT),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(HERE),
            },
            pass_fds=(source["fd"],),
            close_fds=True,
            check=False,
        )
        need(
            result.returncode == 0
            and result.stderr == b""
            and len(result.stdout) <= 64 * 1024,
            "component-validator-failed",
        )
        value = json.loads(result.stdout)
        need(
            value["run_id"] == RUN_ID
            and value["plan_sha256"] == PLAN_SHA256
            and value["completed_stages"]
            == [directory.split("-", 1)[1] for directory, _ in CHECKPOINTS]
            and value["next_stage"] == "round-1-aggregate"
            and value["aggregate_proofs_started"] is False
            and value["fixture_possession_authorizes_v4"] is False,
            "component-validator-result",
        )
        _recheck_live_validator_transport(source)
        value["validator_transport_live_path_immutable_authority"] = False
        value["historical_bundle_source_authority"] = True
        return value
    finally:
        close_refs([source])


def _unified_cgroup() -> Path:
    root = Path("/sys/fs/cgroup")
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            return root / fields[2].lstrip("/")
    return root


def _oom_kill_count() -> int:
    path = _unified_cgroup() / "memory.events"
    if not path.is_file():
        raise Refused("cgroup-memory-events")
    values = {}
    for line in path.read_text().splitlines():
        key, raw = line.split()
        values[key] = int(raw)
    need(type(values.get("oom_kill")) is int, "cgroup-oom-kill")
    return values["oom_kill"]


def current_resources() -> dict:
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, raw = line.split(":", 1)
        memory[key] = int(raw.strip().split()[0]) * 1024
    filesystem = os.statvfs(ROOT)
    cgroup = _unified_cgroup()
    swap_path = cgroup / "memory.swap.max"
    swap_max = swap_path.read_text().strip() if swap_path.is_file() else None
    interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    exact_conflicts = {
        "cargo",
        "rustc",
        "cc1",
        "cc1plus",
        "ld",
        "ld.lld",
        "probe_public_invalid_proof",
        "prove_offline_w1_aggregate",
    }
    conflicts = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            name = (entry / "comm").read_text().strip()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if name in exact_conflicts:
            conflicts.append({"pid": int(entry.name), "comm": name})
    try:
        init_network_inode = os.stat("/proc/1/ns/net").st_ino
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        init_network_inode = None
    return {
        "memory_available_bytes": memory["MemAvailable"],
        "swap_total_bytes": memory["SwapTotal"],
        "swap_free_bytes": memory["SwapFree"],
        "disk_free_bytes": filesystem.f_bavail * filesystem.f_frsize,
        "effective_memory_swap_max": swap_max,
        "network_interfaces": interfaces,
        "network_namespace_inode": os.stat("/proc/self/ns/net").st_ino,
        "init_network_namespace_inode": init_network_inode,
        "conflicting_processes": sorted(conflicts, key=lambda item: item["pid"]),
        "core_soft_limit": resource.getrlimit(resource.RLIMIT_CORE)[0],
        "core_hard_limit": resource.getrlimit(resource.RLIMIT_CORE)[1],
    }


def admit_resources(value: dict) -> None:
    required = {
        "memory_available_bytes",
        "swap_total_bytes",
        "swap_free_bytes",
        "disk_free_bytes",
        "effective_memory_swap_max",
        "network_interfaces",
        "network_namespace_inode",
        "init_network_namespace_inode",
        "conflicting_processes",
        "core_soft_limit",
        "core_hard_limit",
    }
    need(set(value) == required, "resource-snapshot-shape")
    need(
        type(value["memory_available_bytes"]) is int
        and value["memory_available_bytes"] >= MINIMUM_MEMORY_AVAILABLE,
        "memory-admission",
    )
    need(
        type(value["swap_total_bytes"]) is int
        and type(value["swap_free_bytes"]) is int
        and value["swap_total_bytes"] == value["swap_free_bytes"],
        "host-swap-already-used",
    )
    need(value["effective_memory_swap_max"] == "0", "cgroup-swap-max")
    need(
        type(value["disk_free_bytes"]) is int
        and value["disk_free_bytes"] >= MINIMUM_DISK_FREE,
        "disk-admission",
    )
    need(
        value["network_interfaces"] in ([], ["lo"])
        and type(value["network_namespace_inode"]) is int
        and type(value["init_network_namespace_inode"]) is int
        and value["network_namespace_inode"] != value["init_network_namespace_inode"],
        "network-namespace-enabled",
    )
    need(value["conflicting_processes"] == [], "conflicting-heavy-process")
    need(
        value["core_soft_limit"] == 0 and value["core_hard_limit"] == 0,
        "core-dump-limit",
    )


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.pwrite(fd, raw[offset:], offset)
        need(written > 0, "short-write")
        offset += written


def _fsync_directory(fd: int) -> None:
    os.fsync(fd)


def _valid_name(name: str) -> bool:
    return type(name) is str and "/" not in name and name not in ("", ".", "..")


def _reopen_exact_at(
    directory_fd: int,
    name: str,
    expected_sha256: str,
    expected_bytes: int,
    mode: int,
) -> dict:
    need(_valid_name(name), "reopen-name")
    fd = os.open(
        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
    )
    try:
        value = os.fstat(fd)
        digest, count = _sha256_fd(fd)
        need(
            stat.S_ISREG(value.st_mode)
            and value.st_nlink == 1
            and value.st_uid == os.getuid()
            and stat.S_IMODE(value.st_mode) == mode
            and count == expected_bytes
            and digest == expected_sha256,
            "reopen-content",
        )
        return {
            "name": name,
            "device": value.st_dev,
            "inode": value.st_ino,
            "bytes": count,
            "sha256": digest,
        }
    finally:
        os.close(fd)


def _create_sealed_at(directory_fd: int, name: str, raw: bytes) -> dict:
    need(_valid_name(name), "output-name")
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        original = os.fstat(fd)
        _write_all(fd, raw)
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        value = os.fstat(fd)
        need(
            stat.S_ISREG(value.st_mode)
            and value.st_nlink == 1
            and (value.st_dev, value.st_ino) == (original.st_dev, original.st_ino),
            "sealed-output-stat",
        )
    finally:
        os.close(fd)
    _fsync_directory(directory_fd)
    return _reopen_exact_at(directory_fd, name, sha256_bytes(raw), len(raw), 0o400)


def _publish_noreplace_at(directory_fd: int, partial: str, final: str) -> None:
    need(_valid_name(partial) and _valid_name(final), "publish-name")
    os.link(
        partial,
        final,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    _fsync_directory(directory_fd)
    os.unlink(partial, dir_fd=directory_fd)
    _fsync_directory(directory_fd)
    fd = os.open(
        final, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
    )
    try:
        value = os.fstat(fd)
        need(
            stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
            "published-output-stat",
        )
    finally:
        os.close(fd)


def _exists_at(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _attempt_identity(plan: dict) -> str:
    return sha256_bytes(canonical(plan))


def _current_source_identity() -> dict:
    fd = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        digest, count = _sha256_fd(fd)
        need(
            stat.S_ISREG(value.st_mode) and count == value.st_size,
            "control-source-stat",
        )
        return {"sha256": digest, "bytes": count, "authority": False}
    finally:
        os.close(fd)


def _runtime_file_identity(path: str) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        digest, count = _sha256_fd(fd)
        need(
            stat.S_ISREG(value.st_mode) and count == value.st_size,
            "control-runtime-stat",
        )
        return {"path": path, "sha256": digest, "bytes": count}
    finally:
        os.close(fd)


@dataclasses.dataclass
class Attempt:
    root: Path
    directory_fd: int
    terminal_fd: int
    fallback_terminal_fd: int
    attempt_id: str
    terminal: bool = False
    prepare_consumed: bool = False
    terminal_outcome: str | None = None
    terminal_record_name: str | None = None

    def close(self) -> None:
        for attribute in ("terminal_fd", "fallback_terminal_fd", "directory_fd"):
            fd = getattr(self, attribute)
            if fd >= 0:
                os.close(fd)
                setattr(self, attribute, -1)


def _attempt_plan(attempt_id: str) -> dict:
    plan = {
        "schema": "kpb-offline-w1-aggregate-attempt-plan/v2",
        "classification": "CONTROL_ONLY_NO_SETUP_NO_PK_OPEN_NO_PROOF_NO_GO",
        "attempt_id": attempt_id,
        "selected_round": 1,
        "sealed_preflight": {
            "sha256": PREFLIGHT_SHA256,
            "bytes": PREFLIGHT_BYTES,
        },
        "w1_source": {
            "run_id": RUN_ID,
            "source_instance_epoch_id": SOURCE_INSTANCE_EPOCH_ID,
            "plan_sha256": PLAN_SHA256,
            "plan_identity_sha256": PLAN_IDENTITY_SHA256,
            "checkpoint_sha256": [digest for _, digest in CHECKPOINTS],
            "round_1_artifact_manifest_sha256": ROUND_1_ARTIFACT_MANIFEST_SHA256,
            "source_closure_sha256": W1_SOURCE_CLOSURE_SHA256,
            "selected_build_identity_sha256": W1_SELECTED_BUILD_IDENTITY_SHA256,
            "current_relation_source_table_sha256": CURRENT_RELATION_SOURCE_TABLE_SHA256,
        },
        "exact_relation": {
            "standard_r1cs_sha256": STANDARD_R1CS_SHA256,
            "standard_r1cs_bytes": STANDARD_R1CS_BYTES,
            "matrix_sha256": MATRIX_SHA256,
            "rows": ROWS,
            "variables": VARIABLES,
            "instances": INSTANCES,
            "round_1_effects_sha256": ROUND_1_EFFECTS_SHA256,
            "round_1_effects_bytes": ROUND_1_EFFECTS_BYTES,
            "public_inputs_decimal": list(ROUND_1_PUBLIC_INPUTS_DECIMAL),
            "relation_satisfaction_checked": False,
        },
        "historical_parameters": {
            "manifest_sha256": PARAMETER_MANIFEST_SHA256,
            "compressed_pk_sha256": COMPRESSED_PK_SHA256,
            "compressed_pk_bytes": COMPRESSED_PK_BYTES,
            "decoded_pk_sha256": DECODED_PK_SHA256,
            "decoded_pk_bytes": DECODED_PK_BYTES,
            "required_query_shape": QUERY_SHAPE,
            "vk_sha256": VK_SHA256,
            "vk_bytes": VK_BYTES,
            "privacy_or_ceremony_eligible": False,
            "pk_opened": False,
        },
        "independent_verifier_identity": {
            "binary_sha256": PINNED_VERIFIER_BINARY_SHA256,
            "build_receipt_sha256": PINNED_VERIFIER_BUILD_RECEIPT_SHA256,
            "source_members_sha256": PINNED_VERIFIER_SOURCE_MEMBERS_SHA256,
            "invoked": False,
        },
        "candidate_prover": {
            "binary_sha256": None,
            "build_receipt_sha256": None,
            "source_closure_sha256": None,
            "exact_command": None,
            "typed_pk_authority_present": False,
            "internal_osrng_enforced": False,
            "caller_randomness_entry_present": False,
            "present": False,
        },
        "source_owned_assignment_bridge_present": False,
        "control_supervisor_source": _current_source_identity(),
        "inert_control_child": {
            "interpreter": _CONTROL_INTERPRETER_IDENTITY,
            "program_sha256": _CONTROL_CHILD_CODE_SHA256,
            "argument_shape": ["-I", "-S", "-c", "<fixed-program>", "<allowlisted-behavior>"],
            "caller_command_allowed": False,
            "caller_path_allowed": False,
            "caller_output_name_allowed": False,
            "production_child": False,
        },
        "resource_contract": {
            "retained_stock_oom_memory_max_bytes": RETAINED_STOCK_OOM_MEMORY_MAX,
            "minimum_memory_available_bytes": MINIMUM_MEMORY_AVAILABLE,
            "minimum_disk_free_bytes": MINIMUM_DISK_FREE,
            "memory_swap_max_bytes": 0,
            "wall_timeout_allowed": False,
            "one_round_only": True,
        },
        "actions": {
            "setup": False,
            "pk_decode": False,
            "synthesis": False,
            "proof": False,
            "independent_verification": False,
            "stage_08": False,
            "network": False,
            "funds": False,
        },
        "authorization": False,
    }
    plan["attempt_identity_sha256"] = _attempt_identity(plan)
    return plan


def _validate_attempt_plan(plan: dict, attempt_id: str) -> None:
    need(plan == _attempt_plan(attempt_id), "attempt-plan-binding")


def _allocate_attempt(parent: Path, attempt_id: str | None = None) -> Attempt:
    """Allocate one private create-new round-1 control attempt."""
    if os.path.lexists(parent):
        parent_lstat = parent.lstat()
        need(stat.S_ISDIR(parent_lstat.st_mode), "attempt-parent-not-directory")
    else:
        parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    parent_fd = os.open(
        parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    directory_fd = -1
    terminal_fd = -1
    fallback_terminal_fd = -1
    try:
        parent_stat = os.fstat(parent_fd)
        need(
            stat.S_ISDIR(parent_stat.st_mode)
            and stat.S_IMODE(parent_stat.st_mode) == 0o700
            and parent_stat.st_uid == os.getuid(),
            "attempt-parent-mode",
        )
        selected = attempt_id or str(uuid.uuid4())
        need(
            str(uuid.UUID(selected)) == selected and selected[14] == "4",
            "attempt-uuid",
        )
        name = f"round-1-{selected}"
        root = parent / name
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        directory_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        _create_sealed_at(
            directory_fd, "ATTEMPT-PLAN.json", canonical(_attempt_plan(selected))
        )
        terminal_fd = os.open(
            "TERMINAL.partial",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        fallback_terminal_fd = os.open(
            "TERMINAL-FALLBACK.partial",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        fallback_raw = canonical(_preallocated_fallback_value(selected))
        _write_all(fallback_terminal_fd, fallback_raw)
        os.fsync(fallback_terminal_fd)
        os.fchmod(fallback_terminal_fd, 0o400)
        os.fsync(fallback_terminal_fd)
        need(
            _sha256_fd(fallback_terminal_fd)
            == (sha256_bytes(fallback_raw), len(fallback_raw)),
            "fallback-terminal-seal",
        )
        _fsync_directory(directory_fd)
        return Attempt(
            root,
            directory_fd,
            terminal_fd,
            fallback_terminal_fd,
            selected,
        )
    except BaseException:
        if fallback_terminal_fd >= 0:
            os.close(fallback_terminal_fd)
        if terminal_fd >= 0:
            os.close(terminal_fd)
        if directory_fd >= 0:
            os.close(directory_fd)
        raise
    finally:
        os.close(parent_fd)


def _publish_reserved_terminal(
    attempt: Attempt,
    attribute: str,
    partial_name: str,
    final_name: str,
    raw: bytes | None = None,
) -> None:
    fd = getattr(attempt, attribute)
    need(fd >= 0, "terminal-fd-missing")
    try:
        before = os.fstat(fd)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == os.getuid(),
            "terminal-partial-stat",
        )
        if raw is not None:
            need(before.st_size == 0, "terminal-partial-not-empty")
            _write_all(fd, raw)
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        digest, count = _sha256_fd(fd)
        need(
            count > 0
            and digest == sha256_bytes(os.pread(fd, count, 0)),
            "terminal-hash",
        )
        _publish_noreplace_at(
            attempt.directory_fd, partial_name, final_name
        )
    finally:
        os.close(fd)
        setattr(attempt, attribute, -1)


def _arm_fallback_terminal(attempt: Attempt) -> None:
    need(attempt.fallback_terminal_fd >= 0, "fallback-terminal-fd-missing")
    value = os.fstat(attempt.fallback_terminal_fd)
    need(
        stat.S_ISREG(value.st_mode)
        and value.st_nlink == 1
        and value.st_uid == os.getuid()
        and stat.S_IMODE(value.st_mode) == 0o400
        and 0 < value.st_size <= 256 * 1024,
        "fallback-terminal-arm-binding",
    )
    os.link(
        "TERMINAL-FALLBACK.partial",
        "TERMINAL-FALLBACK.json",
        src_dir_fd=attempt.directory_fd,
        dst_dir_fd=attempt.directory_fd,
        follow_symlinks=False,
    )
    _fsync_directory(attempt.directory_fd)


def _discard_fallback_reservation(attempt: Attempt) -> None:
    if attempt.fallback_terminal_fd >= 0:
        os.close(attempt.fallback_terminal_fd)
        attempt.fallback_terminal_fd = -1
    _remove_all_fallback_files(attempt.directory_fd, attempt.attempt_id)


def _terminal_value(
    attempt_id: str, outcome: str, phase: str, result: dict
) -> dict:
    value = {
        "schema": "kpb-offline-w1-aggregate-control-terminal/v2",
        "attempt_id": attempt_id,
        "outcome": outcome,
        "phase": phase,
        "result": result,
        "fresh_attempt_required": outcome != "CONTROL_COMPLETE_NO_PROOF",
        "mid_ark_resume_supported": False,
        "ark_prover_entered": False,
        "pk_opened": False,
        "canonical_proof_published": False,
        "canonical_stage_08_created": False,
        "authorization": False,
    }
    value["terminal_identity_sha256"] = sha256_bytes(canonical(value))
    return value


def _preallocated_fallback_value(attempt_id: str) -> dict:
    return _terminal_value(
        attempt_id,
        "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
        "preallocated-terminal-fallback",
        {
            "reason": "primary-terminal-write-fsync-or-publication-failure",
        },
    )


def _terminal(attempt: Attempt, outcome: str, phase: str, result: dict) -> None:
    need(not attempt.terminal, "attempt-already-terminal")
    attempt.terminal = True
    try:
        _arm_fallback_terminal(attempt)
    except BaseException:
        if _exists_at(attempt.directory_fd, "TERMINAL-FALLBACK.json"):
            try:
                _finish_terminal_dual_link(
                    attempt.directory_fd,
                    "TERMINAL-FALLBACK.partial",
                    "TERMINAL-FALLBACK.json",
                )
            finally:
                if attempt.fallback_terminal_fd >= 0:
                    os.close(attempt.fallback_terminal_fd)
                    attempt.fallback_terminal_fd = -1
            attempt.terminal_outcome = "QUARANTINED_FRESH_ATTEMPT_REQUIRED"
            attempt.terminal_record_name = "TERMINAL-FALLBACK.json"
            raise Refused("fallback-arm-failed-stop-published") from None
        try:
            _publish_reserved_terminal(
                attempt,
                "fallback_terminal_fd",
                "TERMINAL-FALLBACK.partial",
                "TERMINAL-FALLBACK.json",
            )
        except BaseException:
            raise Refused("fallback-arm-and-fallback-publish-failed") from None
        attempt.terminal_outcome = "QUARANTINED_FRESH_ATTEMPT_REQUIRED"
        attempt.terminal_record_name = "TERMINAL-FALLBACK.json"
        raise Refused("fallback-arm-failed-stop-published") from None
    try:
        value = _terminal_value(attempt.attempt_id, outcome, phase, result)
        raw = canonical(value)
        _publish_reserved_terminal(
            attempt,
            "terminal_fd",
            "TERMINAL.partial",
            "TERMINAL.json",
            raw,
        )
    except BaseException:
        try:
            _finish_terminal_dual_link(
                attempt.directory_fd,
                "TERMINAL-FALLBACK.partial",
                "TERMINAL-FALLBACK.json",
            )
        finally:
            if attempt.fallback_terminal_fd >= 0:
                os.close(attempt.fallback_terminal_fd)
                attempt.fallback_terminal_fd = -1
        attempt.terminal_outcome = "QUARANTINED_FRESH_ATTEMPT_REQUIRED"
        attempt.terminal_record_name = "TERMINAL-FALLBACK.json"
        raise Refused("terminal-primary-failed-fallback-quarantined") from None
    _discard_fallback_reservation(attempt)
    attempt.terminal_outcome = outcome
    attempt.terminal_record_name = "TERMINAL.json"


def _quarantine(attempt: Attempt, phase: str, result: dict) -> None:
    _terminal(attempt, "QUARANTINED_FRESH_ATTEMPT_REQUIRED", phase, result)


def _validate_terminal_record(value: dict, attempt_id: str) -> None:
    claimed = value.get("terminal_identity_sha256")
    unsigned = dict(value)
    unsigned.pop("terminal_identity_sha256", None)
    outcome = value.get("outcome")
    need(
        set(value)
        == {
            "schema",
            "attempt_id",
            "outcome",
            "phase",
            "result",
            "fresh_attempt_required",
            "mid_ark_resume_supported",
            "ark_prover_entered",
            "pk_opened",
            "canonical_proof_published",
            "canonical_stage_08_created",
            "authorization",
            "terminal_identity_sha256",
        }
        and value.get("schema")
        == "kpb-offline-w1-aggregate-control-terminal/v2"
        and value.get("attempt_id") == attempt_id
        and outcome
        in {"QUARANTINED_FRESH_ATTEMPT_REQUIRED", "CONTROL_COMPLETE_NO_PROOF"}
        and type(value.get("phase")) is str
        and type(value.get("result")) is dict
        and value.get("fresh_attempt_required")
        is (outcome != "CONTROL_COMPLETE_NO_PROOF")
        and value.get("mid_ark_resume_supported") is False
        and value.get("ark_prover_entered") is False
        and value.get("pk_opened") is False
        and value.get("canonical_proof_published") is False
        and value.get("canonical_stage_08_created") is False
        and value.get("authorization") is False
        and claimed == sha256_bytes(canonical(unsigned)),
        "terminal-record-binding",
    )


def _read_json_at(
    directory_fd: int, name: str, maximum: int = 256 * 1024
) -> dict:
    fd = os.open(
        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
    )
    try:
        value = os.fstat(fd)
        need(
            stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
            "json-stat",
        )
        raw = _read_fd(fd, maximum)
        parsed = json.loads(raw)
        need(raw == canonical(parsed), "json-not-canonical")
        return parsed
    finally:
        os.close(fd)


def _read_terminal_at(
    directory_fd: int, name: str, allowed_links: set[int]
) -> tuple[dict, os.stat_result]:
    fd = os.open(
        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
    )
    try:
        value = os.fstat(fd)
        need(
            stat.S_ISREG(value.st_mode)
            and value.st_uid == os.getuid()
            and value.st_nlink in allowed_links,
            "terminal-json-stat",
        )
        raw = _read_fd(fd, 256 * 1024)
        parsed = json.loads(raw)
        need(raw == canonical(parsed), "terminal-json-not-canonical")
        return parsed, value
    finally:
        os.close(fd)


def _finish_terminal_dual_link(
    directory_fd: int, partial_name: str, final_name: str
) -> None:
    if not _exists_at(directory_fd, partial_name):
        return
    partial = os.open(
        partial_name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    final = os.open(
        final_name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        partial_stat = os.fstat(partial)
        final_stat = os.fstat(final)
        need(
            stat.S_ISREG(partial_stat.st_mode)
            and (partial_stat.st_dev, partial_stat.st_ino)
            == (final_stat.st_dev, final_stat.st_ino)
            and partial_stat.st_nlink == 2
            and final_stat.st_nlink == 2
            and _sha256_fd(partial) == _sha256_fd(final),
            "recover-terminal-substitution",
        )
    finally:
        os.close(partial)
        os.close(final)
    os.unlink(partial_name, dir_fd=directory_fd)
    _fsync_directory(directory_fd)


def _remove_fallback_reservation(
    directory_fd: int, attempt_id: str
) -> None:
    name = "TERMINAL-FALLBACK.partial"
    if not _exists_at(directory_fd, name):
        return
    value, _ = _read_terminal_at(directory_fd, name, {1})
    _validate_terminal_record(value, attempt_id)
    need(
        value == _preallocated_fallback_value(attempt_id),
        "fallback-reservation-binding",
    )
    os.unlink(name, dir_fd=directory_fd)
    _fsync_directory(directory_fd)


def _remove_all_fallback_files(directory_fd: int, attempt_id: str) -> None:
    final_name = "TERMINAL-FALLBACK.json"
    if _exists_at(directory_fd, final_name):
        value, _ = _read_terminal_at(directory_fd, final_name, {1, 2})
        _validate_terminal_record(value, attempt_id)
        need(
            value == _preallocated_fallback_value(attempt_id),
            "fallback-final-binding",
        )
        _finish_terminal_dual_link(
            directory_fd, "TERMINAL-FALLBACK.partial", final_name
        )
        os.unlink(final_name, dir_fd=directory_fd)
        _fsync_directory(directory_fd)
        return
    _remove_fallback_reservation(directory_fd, attempt_id)


def _directory_names(directory_fd: int) -> set[str]:
    return set(os.listdir(directory_fd))


def _validate_control_entry(
    directory_fd: int, attempt_id: str, phase: str, output: dict
) -> None:
    marker = _read_json_at(
        directory_fd, f"CONTROL-{phase.upper()}-ENTERED.json"
    )
    need(
        marker.get("schema") == "kpb-offline-w1-control-child-entry/v2"
        and marker.get("attempt_id") == attempt_id
        and marker.get("phase") == phase
        and marker.get("selected_round") == 1
        and marker.get("fixed_program_sha256") == _CONTROL_CHILD_CODE_SHA256
        and marker.get("output_device") == output["device"]
        and marker.get("output_inode") == output["inode"]
        and marker.get("output_name_not_passed_to_child") is True
        and marker.get("attempt_directory_fd_passed_to_child") is False
        and marker.get("cwd_is_attempt_directory") is False
        and marker.get("core_dump_limit_bytes") == 0
        and marker.get("log_file_limit_bytes") == MAX_CONTROL_LOG_BYTES
        and marker.get("production_child") is False
        and marker.get("authorization") is False,
        "control-entry-binding",
    )


def _validate_prepare_receipt(directory_fd: int, attempt_id: str, name: str) -> None:
    receipt = _read_json_at(directory_fd, name)
    claimed = receipt.get("receipt_identity_sha256")
    unsigned = dict(receipt)
    unsigned.pop("receipt_identity_sha256", None)
    need(
        receipt.get("schema")
        == "kpb-offline-w1-aggregate-control-prepare-result/v2"
        and receipt.get("attempt_id") == attempt_id
        and receipt.get("selected_round") == 1
        and receipt.get("control_bytes_sha256")
        == sha256_bytes(_CONTROL_PREPARE_BYTES)
        and receipt.get("control_bytes") == len(_CONTROL_PREPARE_BYTES)
        and receipt.get("exact_w1_plan_bound") is True
        and receipt.get("relation_satisfaction_checked") is False
        and receipt.get("query_shape_checked") is False
        and receipt.get("pk_opened") is False
        and receipt.get("pk_decode") is False
        and receipt.get("synthesis") is False
        and receipt.get("proof") is False
        and receipt.get("production_resume_eligible") is False
        and receipt.get("receipt_is_authority") is False
        and receipt.get("stage_08") is False
        and receipt.get("authorization") is False
        and claimed == sha256_bytes(canonical(unsigned)),
        "prepare-receipt-binding",
    )


def _validate_prepare_files(directory_fd: int, attempt_id: str, receipt_name: str) -> None:
    prepared = _reopen_exact_at(
        directory_fd,
        "CONTROL-PREPARED-BYTES.bin",
        sha256_bytes(_CONTROL_PREPARE_BYTES),
        len(_CONTROL_PREPARE_BYTES),
        0o400,
    )
    _reopen_exact_at(
        directory_fd,
        "CONTROL-PREPARE.stdout",
        sha256_bytes(b""),
        0,
        0o400,
    )
    _reopen_exact_at(
        directory_fd,
        "CONTROL-PREPARE.stderr",
        sha256_bytes(b""),
        0,
        0o400,
    )
    _validate_control_entry(directory_fd, attempt_id, "prepare", prepared)
    _validate_prepare_receipt(directory_fd, attempt_id, receipt_name)


def _validate_consumed_control_state(directory_fd: int, attempt_id: str) -> None:
    _validate_prepare_files(
        directory_fd, attempt_id, "CONTROL-PREPARE-RECEIPT.CONSUMED.json"
    )
    intent = _read_json_at(directory_fd, "CONTROL-CONSUME-INTENT.json")
    ready = _read_json_at(directory_fd, "CONTROL-PROVE-READY.json")
    need(
        intent
        == {
            "schema": "kpb-offline-w1-control-consume-intent/v2",
            "attempt_id": attempt_id,
            "selected_round": 1,
            "ark_prover_entered": False,
            "authorization": False,
        }
        and ready
        == {
            "schema": "kpb-offline-w1-control-prove-ready/v2",
            "attempt_id": attempt_id,
            "selected_round": 1,
            "control_only": True,
            "ark_prover_entered": False,
            "mid_ark_resume_supported": False,
            "authorization": False,
        },
        "consumed-control-state-binding",
    )


def _open_terminal_reservation(directory_fd: int, name: str) -> int:
    observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    need(
        stat.S_ISREG(observed.st_mode)
        and observed.st_nlink == 1
        and observed.st_uid == os.getuid(),
        "terminal-reservation-stat",
    )
    flags = os.O_RDWR if observed.st_size == 0 else os.O_RDONLY
    return os.open(name, flags | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)


def _recover_control_attempt(root: Path) -> Attempt:
    """Recover a control attempt or quarantine any ambiguous entered state."""
    directory_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    terminal_fd = -1
    fallback_terminal_fd = -1
    try:
        value = os.fstat(directory_fd)
        need(
            stat.S_ISDIR(value.st_mode)
            and stat.S_IMODE(value.st_mode) == 0o700
            and value.st_uid == os.getuid(),
            "recover-directory-stat",
        )
        plan = _read_json_at(directory_fd, "ATTEMPT-PLAN.json")
        attempt_id = plan["attempt_id"]
        need(root.name == f"round-1-{attempt_id}", "recover-attempt-id")
        _validate_attempt_plan(plan, attempt_id)

        # A valid fallback is a dominant STOP, even if a primary final also
        # exists. This makes post-commit cleanup faults fail closed.
        if _exists_at(directory_fd, "TERMINAL-FALLBACK.json"):
            terminal, _ = _read_terminal_at(
                directory_fd, "TERMINAL-FALLBACK.json", {1, 2}
            )
            _validate_terminal_record(terminal, attempt_id)
            need(
                terminal == _preallocated_fallback_value(attempt_id),
                "fallback-terminal-binding",
            )
            _finish_terminal_dual_link(
                directory_fd,
                "TERMINAL-FALLBACK.partial",
                "TERMINAL-FALLBACK.json",
            )
            if _exists_at(directory_fd, "TERMINAL.json"):
                try:
                    primary, _ = _read_terminal_at(
                        directory_fd, "TERMINAL.json", {1, 2}
                    )
                    _validate_terminal_record(primary, attempt_id)
                    _finish_terminal_dual_link(
                        directory_fd,
                        "TERMINAL.partial",
                        "TERMINAL.json",
                    )
                except BaseException:
                    # Retain a malformed/substituted primary for forensics;
                    # the exact fallback already makes the attempt terminal.
                    pass
            return Attempt(
                root,
                directory_fd,
                -1,
                -1,
                attempt_id,
                terminal=True,
                terminal_outcome=terminal["outcome"],
                terminal_record_name="TERMINAL-FALLBACK.json",
            )

        if _exists_at(directory_fd, "TERMINAL.json"):
            try:
                terminal, _ = _read_terminal_at(
                    directory_fd, "TERMINAL.json", {1, 2}
                )
                _validate_terminal_record(terminal, attempt_id)
                _finish_terminal_dual_link(
                    directory_fd, "TERMINAL.partial", "TERMINAL.json"
                )
                _remove_fallback_reservation(directory_fd, attempt_id)
                return Attempt(
                    root,
                    directory_fd,
                    -1,
                    -1,
                    attempt_id,
                    terminal=True,
                    terminal_outcome=terminal["outcome"],
                    terminal_record_name="TERMINAL.json",
                )
            except BaseException:
                fallback_terminal_fd = _open_terminal_reservation(
                    directory_fd, "TERMINAL-FALLBACK.partial"
                )
                fallback_raw = _read_fd(fallback_terminal_fd, 256 * 1024)
                fallback = json.loads(fallback_raw)
                need(
                    fallback_raw == canonical(fallback)
                    and fallback == _preallocated_fallback_value(attempt_id),
                    "recover-invalid-primary-fallback-binding",
                )
                _validate_terminal_record(fallback, attempt_id)
                attempt = Attempt(
                    root,
                    directory_fd,
                    -1,
                    fallback_terminal_fd,
                    attempt_id,
                    terminal=True,
                    terminal_outcome="QUARANTINED_FRESH_ATTEMPT_REQUIRED",
                    terminal_record_name="TERMINAL-FALLBACK.json",
                )
                _publish_reserved_terminal(
                    attempt,
                    "fallback_terminal_fd",
                    "TERMINAL-FALLBACK.partial",
                    "TERMINAL-FALLBACK.json",
                )
                return attempt

        terminal_fd = _open_terminal_reservation(
            directory_fd, "TERMINAL.partial"
        )
        fallback_terminal_fd = _open_terminal_reservation(
            directory_fd, "TERMINAL-FALLBACK.partial"
        )
        attempt = Attempt(
            root,
            directory_fd,
            terminal_fd,
            fallback_terminal_fd,
            attempt_id,
        )

        fallback_raw = _read_fd(fallback_terminal_fd, 256 * 1024)
        fallback = json.loads(fallback_raw)
        need(
            fallback_raw == canonical(fallback)
            and fallback == _preallocated_fallback_value(attempt_id),
            "recover-fallback-reservation",
        )
        _validate_terminal_record(fallback, attempt_id)

        primary_size = os.fstat(terminal_fd).st_size
        if primary_size:
            try:
                raw = _read_fd(terminal_fd, 256 * 1024)
                terminal = json.loads(raw)
                need(raw == canonical(terminal), "recover-primary-canonical")
                _validate_terminal_record(terminal, attempt_id)
                attempt.terminal = True
                _publish_reserved_terminal(
                    attempt,
                    "terminal_fd",
                    "TERMINAL.partial",
                    "TERMINAL.json",
                )
                _discard_fallback_reservation(attempt)
                attempt.terminal_outcome = terminal["outcome"]
                attempt.terminal_record_name = "TERMINAL.json"
                return attempt
            except BaseException:
                if attempt.terminal_fd >= 0:
                    os.close(attempt.terminal_fd)
                    attempt.terminal_fd = -1
                attempt.terminal = True
                _publish_reserved_terminal(
                    attempt,
                    "fallback_terminal_fd",
                    "TERMINAL-FALLBACK.partial",
                    "TERMINAL-FALLBACK.json",
                )
                attempt.terminal_outcome = (
                    "QUARANTINED_FRESH_ATTEMPT_REQUIRED"
                )
                attempt.terminal_record_name = "TERMINAL-FALLBACK.json"
                return attempt

        fresh_names = {
            "ATTEMPT-PLAN.json",
            "TERMINAL.partial",
            "TERMINAL-FALLBACK.partial",
        }
        prepared_names = fresh_names | {
            "CONTROL-PREPARE-ENTERED.json",
            "CONTROL-PREPARE.stdout",
            "CONTROL-PREPARE.stderr",
            "CONTROL-PREPARED-BYTES.bin",
            "CONTROL-PREPARE-RECEIPT.json",
        }
        consumed_names = (prepared_names - {"CONTROL-PREPARE-RECEIPT.json"}) | {
            "CONTROL-PREPARE-RECEIPT.CONSUMED.json",
            "CONTROL-CONSUME-INTENT.json",
            "CONTROL-PROVE-READY.json",
        }
        names = _directory_names(directory_fd)
        if names == consumed_names:
            try:
                _validate_consumed_control_state(directory_fd, attempt_id)
            except BaseException as error:
                _quarantine(
                    attempt,
                    "crash-recovery",
                    {
                        "state": "consumed",
                        "validation_error": type(error).__name__,
                    },
                )
                return attempt
            attempt.prepare_consumed = True
            return attempt
        if names == prepared_names:
            try:
                _validate_prepare_files(
                    directory_fd,
                    attempt_id,
                    "CONTROL-PREPARE-RECEIPT.json",
                )
            except BaseException as error:
                _quarantine(
                    attempt,
                    "crash-recovery",
                    {
                        "state": "prepared",
                        "validation_error": type(error).__name__,
                    },
                )
            return attempt
        if names == fresh_names:
            return attempt
        _quarantine(
            attempt,
            "crash-recovery",
            {
                "observed_names_sha256": sha256_bytes(
                    canonical(sorted(names))
                ),
                "state_was_exact_fresh": False,
                "state_was_exact_prepared": False,
                "state_was_exact_consumed": False,
            },
        )
        return attempt
    except BaseException:
        if terminal_fd >= 0:
            try:
                os.close(terminal_fd)
            except OSError:
                pass
        if fallback_terminal_fd >= 0:
            try:
                os.close(fallback_terminal_fd)
            except OSError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass
        raise


# Fixed inert child program. The API accepts no path, command, output name,
# expected digest, or public input. It writes only through KPB_OUTPUT_FD and
# standard output/error. It has no proving, setup, PK, filesystem, or network
# implementation.
_CONTROL_PREPARE_BYTES = b"KPB_CONTROL_PREPARE_V2\n"
_CONTROL_PROVE_BYTES = b"KPB_CONTROL_PROVE_V2\n"
_CONTROL_CHILD_CODE = r'''
import os, signal, sys
behavior = sys.argv[1]
fd = int(os.environ["KPB_OUTPUT_FD"])
if behavior == "prepare-ok":
    os.write(fd, b"KPB_CONTROL_PREPARE_V2\n")
elif behavior == "prove-ok":
    os.write(fd, b"KPB_CONTROL_PROVE_V2\n")
elif behavior == "exit-nonzero":
    os.write(fd, b"KPB_CONTROL_PREPARE_V2\n")
    raise SystemExit(19)
elif behavior == "signal-term":
    os.kill(os.getpid(), signal.SIGTERM)
elif behavior == "wrong-output":
    os.write(fd, b"WRONG\n")
elif behavior == "stdout-overflow":
    os.write(1, b"X" * 131072)
elif behavior == "path-attack":
    os.close(fd)
    try:
        with open("CONTROL-PREPARE-BYTES.partial", "wb") as target:
            target.write(b"KPB_CONTROL_PREPARE_V2\n")
    except OSError:
        raise SystemExit(73)
else:
    raise SystemExit(97)
'''.strip()
_CONTROL_CHILD_CODE_SHA256 = sha256_bytes(_CONTROL_CHILD_CODE.encode())
_CONTROL_INTERPRETER = str(Path(sys.executable).resolve())
_CONTROL_INTERPRETER_IDENTITY = _runtime_file_identity(_CONTROL_INTERPRETER)
_CONTROL_COMMAND = (
    _CONTROL_INTERPRETER,
    "-I",
    "-S",
    "-c",
    _CONTROL_CHILD_CODE,
)
_CONTROL_BEHAVIORS = {
    "prepare-ok",
    "prove-ok",
    "exit-nonzero",
    "signal-term",
    "wrong-output",
    "stdout-overflow",
    "path-attack",
}
_CONTROL_OUTPUT = {
    "prepare": ("CONTROL-PREPARE-BYTES.partial", _CONTROL_PREPARE_BYTES),
    "prove": ("CONTROL-PROVE-BYTES.partial", _CONTROL_PROVE_BYTES),
}
MAX_CONTROL_LOG_BYTES = 64 * 1024


def _control_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_CONTROL_LOG_BYTES, MAX_CONTROL_LOG_BYTES),
    )


def _control_environment(output_fd: int) -> dict[str, str]:
    return {
        "LC_ALL": "C",
        "RAYON_NUM_THREADS": str(RAYON_THREADS),
        "KPB_OUTPUT_FD": str(output_fd),
        "KPB_SELECTED_ROUND": "1",
        "KPB_AUTHORIZATION": "0",
    }


def _open_control_file(attempt: Attempt, name: str) -> int:
    need(_valid_name(name), "control-file-name")
    return os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=attempt.directory_fd,
    )


def _seal_control_fd(
    attempt: Attempt,
    fd: int,
    name: str,
    original: os.stat_result,
    maximum: int,
) -> dict:
    os.fsync(fd)
    os.fchmod(fd, 0o400)
    os.fsync(fd)
    value = os.fstat(fd)
    digest, count = _sha256_fd(fd)
    need(
        stat.S_ISREG(value.st_mode)
        and value.st_nlink == 1
        and value.st_uid == os.getuid()
        and stat.S_IMODE(value.st_mode) == 0o400
        and (value.st_dev, value.st_ino) == (original.st_dev, original.st_ino)
        and count <= maximum,
        "control-file-postprocess",
    )
    _fsync_directory(attempt.directory_fd)
    reopened = _reopen_exact_at(
        attempt.directory_fd, name, digest, count, 0o400
    )
    need(
        (reopened["device"], reopened["inode"])
        == (original.st_dev, original.st_ino),
        "control-file-substitution",
    )
    return reopened


def _test_only_run_inert_child(
    attempt: Attempt, phase: str, behavior: str
) -> dict:
    """Run the fixed inert control child; never a prover or verifier."""
    need(phase in _CONTROL_OUTPUT, "child-phase")
    need(behavior in _CONTROL_BEHAVIORS, "control-behavior")
    need(not attempt.terminal, "attempt-not-live")
    need(
        (phase == "prepare" and not attempt.prepare_consumed)
        or (phase == "prove" and attempt.prepare_consumed),
        "child-phase-order",
    )
    output_name, expected = _CONTROL_OUTPUT[phase]
    stdout_name = f"CONTROL-{phase.upper()}.stdout"
    stderr_name = f"CONTROL-{phase.upper()}.stderr"
    fds: list[int] = []
    try:
        try:
            output_fd = _open_control_file(attempt, output_name)
            fds.append(output_fd)
            stdout_fd = _open_control_file(attempt, stdout_name)
            fds.append(stdout_fd)
            stderr_fd = _open_control_file(attempt, stderr_name)
            fds.append(stderr_fd)
            originals = {fd: os.fstat(fd) for fd in fds}
            marker = {
                "schema": "kpb-offline-w1-control-child-entry/v2",
                "attempt_id": attempt.attempt_id,
                "phase": phase,
                "selected_round": 1,
                "fixed_program_sha256": _CONTROL_CHILD_CODE_SHA256,
                "output_device": originals[output_fd].st_dev,
                "output_inode": originals[output_fd].st_ino,
                "output_name_not_passed_to_child": True,
                "attempt_directory_fd_passed_to_child": False,
                "cwd_is_attempt_directory": False,
                "core_dump_limit_bytes": 0,
                "log_file_limit_bytes": MAX_CONTROL_LOG_BYTES,
                "production_child": False,
                "authorization": False,
            }
            _create_sealed_at(
                attempt.directory_fd,
                f"CONTROL-{phase.upper()}-ENTERED.json",
                canonical(marker),
            )
            oom_before = _oom_kill_count()
            result = subprocess.run(
                [*_CONTROL_COMMAND, behavior],
                cwd="/",
                stdin=subprocess.DEVNULL,
                stdout=stdout_fd,
                stderr=stderr_fd,
                env=_control_environment(output_fd),
                pass_fds=(output_fd,),
                close_fds=True,
                preexec_fn=_control_limits,
                check=False,
            )
            oom_after = _oom_kill_count()
        except BaseException as error:
            _quarantine(
                attempt,
                phase,
                {
                    "error": type(error).__name__,
                    "returncode": None,
                    "signal": 0,
                    "oom_kill_delta": None,
                    "post_child_failure": "result" in locals(),
                },
            )
            raise Refused("control-child-exec-or-entry-quarantined") from None

        try:
            output = _seal_control_fd(
                attempt,
                output_fd,
                output_name,
                originals[output_fd],
                MAX_CONTROL_LOG_BYTES,
            )
            stdout = _seal_control_fd(
                attempt,
                stdout_fd,
                stdout_name,
                originals[stdout_fd],
                MAX_CONTROL_LOG_BYTES,
            )
            stderr = _seal_control_fd(
                attempt,
                stderr_fd,
                stderr_name,
                originals[stderr_fd],
                MAX_CONTROL_LOG_BYTES,
            )
        except BaseException as error:
            _quarantine(
                attempt,
                f"{phase}-postprocess",
                {
                    "error": type(error).__name__,
                    "returncode": result.returncode,
                    "signal": -result.returncode if result.returncode < 0 else 0,
                    "oom_kill_delta": max(0, oom_after - oom_before),
                },
            )
            raise Refused("control-child-postprocess-quarantined") from None

        child_result = {
            "schema": "kpb-offline-w1-inert-child-result/v2",
            "attempt_id": attempt.attempt_id,
            "phase": phase,
            "fixed_program_sha256": _CONTROL_CHILD_CODE_SHA256,
            "returncode": result.returncode,
            "signal": -result.returncode if result.returncode < 0 else 0,
            "oom_kill_delta": max(0, oom_after - oom_before),
            "output": output,
            "stdout": stdout,
            "stderr": stderr,
            "production_artifact": False,
            "authorization": False,
        }
        if (
            result.returncode != 0
            or child_result["oom_kill_delta"] != 0
            or output["sha256"] != sha256_bytes(expected)
            or output["bytes"] != len(expected)
        ):
            _quarantine(attempt, phase, child_result)
            raise Refused("control-child-quarantined")
        return child_result
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


def _test_only_publish_prepare_control(
    attempt: Attempt, child_result: dict
) -> dict:
    """Publish inert control bytes and a non-authoritative prepare receipt."""
    need(
        not attempt.terminal and not attempt.prepare_consumed,
        "prepare-attempt-live",
    )
    output_name, expected = _CONTROL_OUTPUT["prepare"]
    expected_sha = sha256_bytes(expected)
    need(
        child_result.get("schema") == "kpb-offline-w1-inert-child-result/v2"
        and child_result.get("attempt_id") == attempt.attempt_id
        and child_result.get("phase") == "prepare"
        and child_result.get("fixed_program_sha256") == _CONTROL_CHILD_CODE_SHA256
        and child_result.get("returncode") == 0
        and child_result.get("signal") == 0
        and child_result.get("oom_kill_delta") == 0
        and child_result.get("output", {}).get("name") == output_name
        and child_result.get("output", {}).get("sha256") == expected_sha
        and child_result.get("output", {}).get("bytes") == len(expected),
        "prepare-control-result",
    )
    try:
        _reopen_exact_at(
            attempt.directory_fd, output_name, expected_sha, len(expected), 0o400
        )
        _publish_noreplace_at(
            attempt.directory_fd,
            output_name,
            "CONTROL-PREPARED-BYTES.bin",
        )
        value = {
            "schema": "kpb-offline-w1-aggregate-control-prepare-result/v2",
            "attempt_id": attempt.attempt_id,
            "selected_round": 1,
            "control_bytes_sha256": expected_sha,
            "control_bytes": len(expected),
            "exact_w1_plan_bound": True,
            "relation_satisfaction_checked": False,
            "query_shape_checked": False,
            "pk_opened": False,
            "pk_decode": False,
            "synthesis": False,
            "proof": False,
            "production_resume_eligible": False,
            "receipt_is_authority": False,
            "stage_08": False,
            "authorization": False,
        }
        value["receipt_identity_sha256"] = sha256_bytes(canonical(value))
        _create_sealed_at(
            attempt.directory_fd,
            "CONTROL-PREPARE-RECEIPT.json",
            canonical(value),
        )
        return value
    except BaseException as error:
        _quarantine(
            attempt,
            "prepare-publication",
            {
                "error": type(error).__name__,
                "canonical_proof_published": False,
            },
        )
        raise Refused("prepare-control-publication-quarantined") from None


def _test_only_consume_prepare_control_once(attempt: Attempt) -> None:
    """Consume a control receipt exactly once; never enter Ark."""
    need(
        not attempt.terminal and not attempt.prepare_consumed,
        "prepare-already-consumed",
    )
    try:
        _create_sealed_at(
            attempt.directory_fd,
            "CONTROL-CONSUME-INTENT.json",
            canonical(
                {
                    "schema": "kpb-offline-w1-control-consume-intent/v2",
                    "attempt_id": attempt.attempt_id,
                    "selected_round": 1,
                    "ark_prover_entered": False,
                    "authorization": False,
                }
            ),
        )
        _publish_noreplace_at(
            attempt.directory_fd,
            "CONTROL-PREPARE-RECEIPT.json",
            "CONTROL-PREPARE-RECEIPT.CONSUMED.json",
        )
        _create_sealed_at(
            attempt.directory_fd,
            "CONTROL-PROVE-READY.json",
            canonical(
                {
                    "schema": "kpb-offline-w1-control-prove-ready/v2",
                    "attempt_id": attempt.attempt_id,
                    "selected_round": 1,
                    "control_only": True,
                    "ark_prover_entered": False,
                    "mid_ark_resume_supported": False,
                    "authorization": False,
                }
            ),
        )
        attempt.prepare_consumed = True
    except BaseException as error:
        _quarantine(
            attempt,
            "resume",
            {
                "error": type(error).__name__,
                "prepare_receipt_may_be_consumed": _exists_at(
                    attempt.directory_fd,
                    "CONTROL-PREPARE-RECEIPT.CONSUMED.json",
                ),
                "ark_prover_entered": False,
            },
        )
        raise Refused("prepare-control-resume-quarantined") from None


def _test_only_evaluate_verification_control(
    attempt: Attempt, child_result: dict, outcome: str
) -> dict:
    """Exercise terminal policy without verifying or publishing a proof."""
    need(
        outcome
        in {
            "accepted-valid-control",
            "rejected-control",
            "accepted-wrong-input-control",
            "accepted-mutated-control",
        },
        "verification-control-outcome",
    )
    need(
        attempt.prepare_consumed and not attempt.terminal,
        "proof-control-attempt-live",
    )
    output_name, expected = _CONTROL_OUTPUT["prove"]
    expected_sha = sha256_bytes(expected)
    need(
        child_result.get("schema") == "kpb-offline-w1-inert-child-result/v2"
        and child_result.get("attempt_id") == attempt.attempt_id
        and child_result.get("phase") == "prove"
        and child_result.get("returncode") == 0
        and child_result.get("output", {}).get("name") == output_name
        and child_result.get("output", {}).get("sha256") == expected_sha
        and child_result.get("output", {}).get("bytes") == len(expected),
        "proof-control-result",
    )
    if outcome in (
        "accepted-wrong-input-control",
        "accepted-mutated-control",
    ):
        _quarantine(
            attempt,
            "fatal-invalid-acceptance",
            {
                "control_outcome": outcome,
                "production_verification_performed": False,
                "canonical_proof_published": False,
            },
        )
        raise Refused("fatal-invalid-acceptance-control")
    if outcome == "rejected-control":
        _quarantine(
            attempt,
            "verification",
            {
                "control_outcome": outcome,
                "production_verification_performed": False,
                "canonical_proof_published": False,
            },
        )
        raise Refused("verification-rejected-control")
    try:
        _reopen_exact_at(
            attempt.directory_fd, output_name, expected_sha, len(expected), 0o400
        )
        _publish_noreplace_at(
            attempt.directory_fd,
            output_name,
            "CONTROL-VERIFIED-BYTES.bin",
        )
        value = {
            "schema": "kpb-offline-w1-aggregate-control-verification-result/v2",
            "attempt_id": attempt.attempt_id,
            "selected_round": 1,
            "control_outcome": outcome,
            "production_independent_verification": False,
            "proof_generated": False,
            "canonical_proof_published": False,
            "canonical_stage_08_created": False,
            "authorization": False,
        }
        value["receipt_identity_sha256"] = sha256_bytes(canonical(value))
        _create_sealed_at(
            attempt.directory_fd,
            "CONTROL-VERIFICATION-RESULT.json",
            canonical(value),
        )
        _terminal(
            attempt,
            "CONTROL_COMPLETE_NO_PROOF",
            "control-verification",
            {
                "control_result_sha256": value["receipt_identity_sha256"],
                "production_independent_verification": False,
            },
        )
        return value
    except BaseException as error:
        if not attempt.terminal:
            _quarantine(
                attempt,
                "control-verification-publication",
                {
                    "error": type(error).__name__,
                    "canonical_proof_published": False,
                },
            )
        raise Refused("control-verification-publication-quarantined") from None


def validate_components_report() -> tuple[dict, int]:
    diagnostics = component_source_diagnostics()
    if not diagnostics["ready_for_exact_component_validation"]:
        return (
            {
                "status": "COMPONENT_SOURCE_BINDING_BLOCKED",
                "source_binding": diagnostics,
                "relation_satisfaction_checked": False,
                "pk_opened": False,
                "proof": False,
                "stage_08": False,
                "actions_performed": _false_actions(),
                "authorization": False,
            },
            1,
        )
    refs = validate_frozen_component_descriptors()
    try:
        round_1 = validate_exact_round_1_artifacts(refs)
        validated = {
            "run_id": RUN_ID,
            "plan_sha256": PLAN_SHA256,
            "completed_stages": [
                directory.split("-", 1)[1] for directory, _ in CHECKPOINTS
            ],
            "next_stage": "round-1-aggregate",
            "aggregate_proofs_started": False,
            "historical_source_bundle_validated": True,
            "legacy_live_source_validator_run": False,
            "legacy_live_source_validator_reason": (
                "it recursively binds drifted live build source; the exact sealed "
                "historical bundle is validated independently instead"
            ),
        }
    finally:
        close_refs(refs)
    return (
        {
            "status": "EXACT_COMPONENT_CONTENT_VALID_NO_PROOF_AUTHORITY",
            "validation": validated,
            "round_1_content": round_1,
            "relation_satisfaction_checked": False,
            "pk_opened": False,
            "proof": False,
            "stage_08": False,
            "actions_performed": _false_actions(),
            "authorization": False,
        },
        0,
    )


def status() -> dict:
    resources = current_resources()
    source_diagnostics = component_source_diagnostics()
    gates = {}
    for name, function in (
        ("resources", lambda: admit_resources(resources)),
        (
            "component_descriptors",
            lambda: close_refs(validate_frozen_component_descriptors()),
        ),
    ):
        try:
            function()
            gates[name] = True
        except BaseException:
            gates[name] = False
    return {
        "source_status": SOURCE_STATUS,
        "current_resources": resources,
        "component_source_diagnostics": source_diagnostics,
        "gates": gates,
        "go": False,
        "reason": (
            "eligible prover binary/build, source-owned assignment bridge, "
            "typed PK/OsRng production authorities, isolation, and successful "
            "memory bound are absent"
        ),
        "actions_performed": _false_actions(),
    }


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("validate-components")
    commands.add_parser("source-closure-plan")
    args = parser.parse_args()
    exit_code = 0
    try:
        if args.command == "status":
            result = status()
        elif args.command == "validate-components":
            result, exit_code = validate_components_report()
        else:
            result = source_closure_plan()
    except BaseException as error:
        result = {
            "status": "OFFLINE_W1_AGGREGATE_ATTEMPT_REFUSED",
            "category": type(error).__name__,
            "actions_performed": _false_actions(),
            "authorization": False,
        }
        exit_code = 1
    print(json.dumps(result, sort_keys=True))
    if exit_code:
        raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
