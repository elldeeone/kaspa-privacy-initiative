#!/usr/bin/env python3
"""Hostile, no-execution controls for the inert direct-bwrap W1 supervisor."""

from __future__ import annotations

import copy
import inspect
import io
import os
from pathlib import Path
import resource
import struct
import time
import unittest
from unittest import mock

import run_frozen_w1_proof_bwrap as target


def file_ref(path: str, *, size: int = 1, digest: str = "1" * 64, mode: str = "0500") -> dict:
    return {
        "path": path,
        "device": 11,
        "inode": abs(hash(path)) % 1_000_000 + 1,
        "bytes": size,
        "sha256": digest,
        "mode_octal": mode,
        "owner_uid": 0,
        "owner_gid": 0,
        "link_count": 1,
        "mtime_ns": 20,
        "ctime_ns": 21,
    }


def cgroup_binding() -> dict:
    return {
        "parent": {
            "path": "/sys/fs/cgroup/kpb-reviewed",
            "device": 32,
            "inode": 90,
            "owner_uid": os.getuid(),
            "owner_gid": 0,
            "mode_octal": "0755",
            "memory_max": 24 * 1024**3,
            "memory_swap_max": 0,
            "pids_max": 512,
            "cgroup_type": "domain",
            "controllers": ["memory", "pids"],
            "trusted_preexisting": True,
        },
        "worker_leaf": {
            "path": "/sys/fs/cgroup/kpb-reviewed/w1",
            "device": 32,
            "inode": 91,
            "owner_uid": os.getuid(),
            "owner_gid": 0,
            "mode_octal": "0755",
            "cgroup_type": "domain",
            "cgroup_kill": True,
            "trusted_preexisting": True,
            "parent_path": "/sys/fs/cgroup/kpb-reviewed",
        },
        "trusted_host_tcb": True,
        "manager_and_same_uid_in_tcb": True,
        "limits_authenticated_pre_post": True,
        "assignment_protocol": (
            "parent-enter-authenticate-pdeathsig-sigstop-leaf-assign-"
            "pidfd-sigcont"
        ),
    }


def parent_cgroup_snapshot(*, procs: list[int] | None = None) -> dict:
    value = dict(cgroup_binding()["parent"])
    value.pop("trusted_preexisting")
    value.update(
        memory_swap_current=0,
        memory_swap_peak=0,
        populated=1 if procs else 0,
        procs=[] if procs is None else list(procs),
        oom=0,
        oom_kill=0,
    )
    return value


def leaf_cgroup_snapshot(*, procs: list[int] | None = None) -> dict:
    value = dict(cgroup_binding()["worker_leaf"])
    value.pop("trusted_preexisting")
    value.pop("parent_path")
    value.update(
        populated=1 if procs else 0,
        procs=[] if procs is None else list(procs),
    )
    return value


def cgroup_snapshot() -> dict:
    return {"parent": parent_cgroup_snapshot(), "leaf": leaf_cgroup_snapshot()}


def parent_entry_base() -> dict:
    pid = os.getpid()
    return {
        "schema": "kpb-w1-parent-cgroup-entry/v1",
        "pid": pid,
        "starttime": 12345,
        "observed_proc_cgroup": "/kpb-reviewed",
        "before": parent_cgroup_snapshot(),
        "after": parent_cgroup_snapshot(procs=[pid]),
        "swap_zero_before_private_reads": True,
    }


def parent_entry() -> dict:
    value = parent_entry_base()
    value.update(
        sealed_reexec_completed=True,
        sealed_transition_sha256="f" * 64,
        post_reexec_starttime=12345,
        post_reexec_proc_cgroup="/kpb-reviewed",
        post_reexec_parent_snapshot=parent_cgroup_snapshot(
            procs=[value["pid"]]
        ),
    )
    return value


def artifact_refs() -> dict:
    result = {}
    for name, expected in target.EXPECTED_ARTIFACTS.items():
        result[name] = {
            "file": file_ref(
                expected["path"],
                size=expected["bytes"],
                digest=expected["sha256"],
                mode=expected["mode_octal"],
            ),
            "fsverity": {
                "enabled": True,
                "algorithm": "sha256",
                "descriptor_digest": (str(len(name) % 10) * 64),
            },
        }
    return result


def assignment_binding() -> dict:
    return {
        "launch_receipt": file_ref(
            "/reviewed/LAUNCH-RECEIPT.json", size=1200, digest="2" * 64, mode="0400"
        ),
        "assignment_receipt": file_ref(
            "/reviewed/ASSIGNMENT-RECEIPT.json",
            size=900,
            digest="3" * 64,
            mode="0400",
        ),
    }


def review_bindings() -> dict:
    def runtime(role: str) -> tuple[dict, ...]:
        return (
            {
                "label": f"{role}-python",
                "destination": str(target.PYTHON),
                "file": file_ref(str(target.PYTHON), mode="0555"),
            },
            {
                "label": f"{role}-loader",
                "destination": "/lib64/ld-linux-x86-64.so.2",
                "file": file_ref("/lib64/ld-linux-x86-64.so.2", mode="0555"),
            },
        )

    seccomp_sha = target.sha256_bytes(target.seccomp_filter_bytes())
    loader_destinations = {
        "PT_INTERP": target.FIXED_DEBIAN_BWRAP_PT_INTERP,
        "libselinux.so.1": "/lib/x86_64-linux-gnu/libselinux.so.1",
        "libcap.so.2": "/lib/x86_64-linux-gnu/libcap.so.2",
        "libc.so.6": "/lib/x86_64-linux-gnu/libc.so.6",
        "libpcre2-8.so.0": "/lib/x86_64-linux-gnu/libpcre2-8.so.0",
    }
    bwrap_loader_closure = (
        *(
            {
                "elf_name": name,
                "elf_build_id": f"{index + 1:x}" * 40,
                "elf_pt_interp": None,
                "elf_needed": target.FIXED_DEBIAN_BWRAP_DEPENDENCY_GRAPH[
                    "ld-linux-x86-64.so.2" if name == "PT_INTERP" else name
                ],
                "destination": loader_destinations[name],
                "file": file_ref(loader_destinations[name], mode="0555"),
            }
            for index, name in enumerate(target.FIXED_DEBIAN_BWRAP_CLOSURE_NAMES)
        ),
    )
    apparmor_closure = (
        file_ref(
            target.FIXED_BWRAP_APPARMOR_ROOT,
            size=5000,
            digest="6" * 64,
            mode="0444",
        ),
    )
    role_runtimes = {role: runtime(role) for role in ("proof", "verifier")}

    def live_mount_allowlist(role: str) -> tuple[str, ...]:
        labels = (
            target.PROOF_PRIVATE_LABELS
            if role == "proof"
            else target.VERIFIER_PRIVATE_LABELS
        )
        return tuple(
            sorted(
                {
                    "/", "/proc", "/dev", "/tmp", "/out",
                    f"/payload/{role}", "/supervisor/worker.py",
                    *(item["destination"] for item in role_runtimes[role]),
                    *(target.EXPECTED_ARTIFACTS[label]["path"] for label in labels),
                }
            )
        )

    return {
        "supervisor_source": {
            "sha256": "4" * 64,
            "externally_authenticated": True,
        },
        "external_stage0": target.sha256_bytes(target.EXTERNAL_STAGE0_SOURCE.encode()),
        "worker_source": target.sha256_bytes(target.WORKER_SOURCE.encode()),
        "bwrap": {
            "executable": file_ref(
                str(target.APPROVED_BWRAP_PATH),
                size=target.FIXED_DEBIAN_BWRAP_ELF_BYTES,
                digest=target.FIXED_DEBIAN_BWRAP_ELF_SHA256,
                mode="0755",
            ),
            "version": [0, 13, 1],
            "package_release": target.FIXED_DEBIAN_BWRAP_PACKAGE,
            "package_sha256": target.FIXED_DEBIAN_BWRAP_PACKAGE_SHA256,
            "elf_build_id": target.FIXED_DEBIAN_BWRAP_BUILD_ID,
            "elf_pt_interp": target.FIXED_DEBIAN_BWRAP_PT_INTERP,
            "elf_dt_needed": list(target.FIXED_DEBIAN_BWRAP_DT_NEEDED),
            "elf_dependency_graph": target.FIXED_DEBIAN_BWRAP_DEPENDENCY_GRAPH,
            "cve_2026_87766_safe_openat_fix_present": True,
            "symlink_destination_rehearsal_refused": True,
            "json_status_block_fd_observation_rehearsal_passed": True,
            "fd_exec_apparmor_attachment_rehearsal_passed": True,
            "expected_apparmor_label": target.FIXED_BWRAP_APPARMOR_LABEL,
            "independently_reviewed": True,
            "admin_installed": True,
            "user_writable": False,
            "apparmor_profile_name": target.FIXED_BWRAP_APPARMOR_PROFILE,
            "apparmor_mode": "enforce",
            "apparmor_exact_exec_path": str(target.APPROVED_BWRAP_PATH),
            "apparmor_exact_path_authorized": True,
            "apparmor_profile_loaded": True,
            "apparmor_root_path": target.FIXED_BWRAP_APPARMOR_ROOT,
            "apparmor_source_closure": apparmor_closure,
            "apparmor_source_closure_sha256": target.sha256_bytes(
                target.canonical(apparmor_closure)
            ),
            "apparmor_include_graph": {
                target.FIXED_BWRAP_APPARMOR_ROOT: []
            },
            "apparmor_optional_missing": [],
            "upstream_tag_object": "4" * 40,
            "upstream_commit": "3" * 40,
            "upstream_tag_api_verified": True,
            "upstream_tag_signature_verified": True,
            "loader_closure": bwrap_loader_closure,
            "loader_closure_sha256": target.sha256_bytes(
                target.canonical(bwrap_loader_closure)
            ),
            "rehearsed_live_mount_allowlists": {
                role: live_mount_allowlist(role)
                for role in ("proof", "verifier")
            },
        },
        "build": {
            "proof": {
                "binary": file_ref("/reviewed/prover", digest="7" * 64),
                "source_closure_sha256": "b" * 64,
                "build_receipt": file_ref(
                    "/reviewed/prover-build.json",
                    size=500,
                    digest="9" * 64,
                    mode="0400",
                ),
            },
            "verifier": {
                "binary": file_ref("/reviewed/verifier", digest="8" * 64),
                "source_closure_sha256": "c" * 64,
                "build_receipt": file_ref(
                    "/reviewed/verifier-build.json",
                    size=500,
                    digest="a" * 64,
                    mode="0400",
                ),
            },
        },
        "runtime_closure": role_runtimes,
        "artifacts": artifact_refs(),
        "assignment": assignment_binding(),
        "seccomp": {
            role: {
                "architecture": "x86_64",
                "sha256": seccomp_sha,
                "sealed": True,
                "independently_reviewed": True,
                "expected_filter_count": 1,
                "required_probes": ["getpid", "pidfd_open", "socket"],
            }
            for role in ("proof", "verifier")
        },
        "cgroup": cgroup_binding(),
        "publication": {
            "output": str(target.FINAL_OUTPUT),
            "create_new": True,
            "rename_noreplace": True,
            "commit_marker": True,
            "final_reopen": True,
            "exact_entries": True,
        },
    }


def proof_receipt() -> dict:
    proof = bytes(range(128))
    value = {
        "schema": target.PROOF_SCHEMA,
        "classification": target.CLASSIFICATION,
        "selected_round": 1,
        "prepared_instances": 3,
        "prepared_witnesses": 12_949_818,
        "prepared_variables": 12_949_821,
        "prepared_constraints": 13_093_029,
        "public_inputs_decimal": list(target.EXPECTED_PUBLIC_INPUTS),
        "proof_ark_compressed_hex": proof.hex(),
        "proof_bytes": 128,
        "proof_sha256": target.sha256_bytes(proof),
        "r1cs_bytes": target.EXPECTED_ARTIFACTS["r1cs"]["bytes"],
        "r1cs_sha256": target.EXPECTED_ARTIFACTS["r1cs"]["sha256"],
        "decoded_pk_bytes": target.EXPECTED_ARTIFACTS["decoded_pk"]["bytes"],
        "decoded_pk_sha256": target.EXPECTED_ARTIFACTS["decoded_pk"]["sha256"],
        "compressed_pk_bytes": target.EXPECTED_ARTIFACTS["compressed_pk"]["bytes"],
        "compressed_pk_sha256": target.EXPECTED_ARTIFACTS["compressed_pk"]["sha256"],
        "decode_receipt_bytes": target.EXPECTED_ARTIFACTS["decode_receipt"]["bytes"],
        "decode_receipt_sha256": target.EXPECTED_ARTIFACTS["decode_receipt"]["sha256"],
        "vk_bytes": target.EXPECTED_ARTIFACTS["vk"]["bytes"],
        "vk_sha256": target.EXPECTED_ARTIFACTS["vk"]["sha256"],
    }
    for key in (
        "historical_sources_rehashed",
        "r1cs_satisfaction_checked",
        "proof_parameter_descriptors_opened_after_satisfaction",
        "historical_source_vk_opened_during_assignment_preparation",
        "decoded_pk_rehashed_before_deserialization",
        "internal_osrng_nonzero_blinding",
        "proof_generated",
        "independent_vk_rehashed",
        "independent_verification",
        "wrong_public_inputs_rejected",
        "mutated_proof_rejected",
    ):
        value[key] = True
    for key in (
        "assignment_serialized",
        "secret_fingerprint_emitted",
        "setup_executed",
        "network_communication",
        "funds",
        "testnet",
        "full_secret_zeroization",
        "error_path_source_zeroization_complete",
        "abort_oom_zeroization",
        "receipt_is_authority",
        "public_or_production_authority",
    ):
        value[key] = False
    return value


def sandbox_plan(role: str = "proof") -> dict:
    labels = target.PROOF_PRIVATE_LABELS if role == "proof" else target.VERIFIER_PRIVATE_LABELS
    return target.build_sandbox_plan(
        role,
        bwrap_fd=10,
        binary_fd=11,
        runtime_fds=((str(target.PYTHON), 12), ("/lib64/ld-linux-x86-64.so.2", 13)),
        artifact_fds={label: 20 + index for index, label in enumerate(sorted(labels))},
        worker_fd=30,
        seccomp_fd=31,
        status_fd=32,
        barrier_fd=33,
    )


def namespaces(seed: int) -> dict:
    return {name: [7, seed + index] for index, name in enumerate(target.NAMESPACE_NAMES)}


def mount_evidence(plan: dict) -> dict:
    destinations: dict[str, str] = {}
    for item in plan["mount_requirements"]:
        destinations[item["destination"]] = item["mode"]
    entries = [
        {
            "mount_id": index + 1,
            "parent_id": 0 if destination == "/" else 1,
            "device": "0:1",
            "root": "/",
            "mount_point": destination,
            "mount_options": [mode],
            "optional_fields": [],
            "fs_type": "tmpfs" if destination in {"/", "/tmp", "/out"} else "bind",
            "mount_source": "none",
            "super_options": [mode],
        }
        for index, (destination, mode) in enumerate(destinations.items())
    ]
    return {
        "schema": "kpb-w1-proc-mountinfo/v1",
        "raw_sha256": "d" * 64,
        "entries": entries,
        "entries_sha256": target.sha256_bytes(target.canonical(entries)),
    }


def cgroup_assignment() -> dict:
    snapshot = leaf_cgroup_snapshot(procs=[1001])
    return {
        "schema": "kpb-w1-cgroup-assignment/v1",
        "pid": 1001,
        "starttime_before": 900,
        "starttime_after": 900,
        "pidfd_opened": True,
        "leaf_path": "/sys/fs/cgroup/kpb-reviewed/w1",
        "observed_proc_cgroup": "/kpb-reviewed/w1",
        "leaf_snapshot": snapshot,
        "pdeathsig": "SIGKILL-before-SIGSTOP",
        "assignment_verified": True,
    }


def loaded_elf_evidence() -> dict:
    bwrap = review_bindings()["bwrap"]
    expected = [
        ("bwrap", bwrap["executable"]),
        *((item["elf_name"], item["file"]) for item in bwrap["loader_closure"]),
    ]
    objects = [
        {
            "elf_name": name,
            "device": reference["device"],
            "inode": reference["inode"],
            "segments": [
                {
                    "address": "1000-2000",
                    "permissions": "r-xp",
                    "offset": "00000000",
                    "path": reference["path"],
                }
            ],
        }
        for name, reference in expected
    ]
    return {
        "schema": "kpb-w1-bwrap-loaded-elf-mappings/v1",
        "raw_sha256": "e" * 64,
        "objects": objects,
        "objects_sha256": target.sha256_bytes(target.canonical(objects)),
        "executable_identities": [
            {
                "elf_name": name,
                "device": reference["device"],
                "inode": reference["inode"],
            }
            for name, reference in expected
        ],
    }


def launch_evidence(plan: dict, stdin_raw: bytes = b"") -> dict:
    host = namespaces(100)
    child = namespaces(200)
    return {
        "bwrap_pid": 1001,
        "bwrap_starttime_before": 900,
        "bwrap_starttime_after": 900,
        "bwrap_pidfd_opened": True,
        "payload_pid": 1002,
        "payload_starttime_before": 901,
        "payload_starttime_after": 901,
        "payload_pidfd_opened": True,
        "status_child_pid": 1002,
        "host_namespaces": host,
        "payload_namespaces": child,
        "capabilities": {
            "CapInh": 0,
            "CapPrm": 0,
            "CapEff": 0,
            "CapBnd": 0,
            "CapAmb": 0,
        },
        "no_new_privs": 1,
        "seccomp_mode": 2,
        "seccomp_filter_count": 1,
        "cgroup_path": "/kpb-reviewed/w1",
        "expected_cgroup_path": "/kpb-reviewed/w1",
        "cgroup_assignment": cgroup_assignment(),
        "payload_cmdline": list(plan["payload_argv"]),
        "payload_fds": [0, 1, 2],
        "bwrap_executable_sha256": "a" * 64,
        "expected_bwrap_sha256": "a" * 64,
        "bwrap_executable_device": 11,
        "expected_bwrap_device": 11,
        "bwrap_executable_inode": 12,
        "expected_bwrap_inode": 12,
        "bwrap_apparmor_label": target.FIXED_BWRAP_APPARMOR_LABEL,
        "expected_bwrap_apparmor_label": target.FIXED_BWRAP_APPARMOR_LABEL,
        "barrier_release_sequence": "bwrap-block-then-worker-ready-then-pidfd-namespace-capability-cgroup-fd-checks",
        "status_json_unique_keys": True,
        "launch_contract": target.canonical_launch_contract(plan, stdin_raw),
        "mount_evidence": mount_evidence(plan),
        "mount_target_identities": [
            {
                "label": item["label"],
                "fd": item["fd"],
                "destination": item["destination"],
                "source_device": 50,
                "source_inode": 1000 + item["fd"],
                "target_device": 50,
                "target_inode": 1000 + item["fd"],
            }
            for item in plan["mounts"]
        ],
        "loaded_elf_mappings": loaded_elf_evidence(),
    }


def wait_evidence() -> dict:
    return {
        "wait4_pid": 1001,
        "exited": True,
        "exit_code": 0,
        "term_signal": 0,
        "status_exit_code": 0,
        "stdout_eof": True,
        "stderr_eof": True,
        "status_eof": True,
        "zero_descendants": True,
        "cgroup_populated": 0,
        "cgroup_procs": [],
        "parent_memory_swap_current": 0,
        "parent_memory_swap_peak": 0,
        "group_kill_armed": True,
        "max_rss_kib": 123,
        "pidfd_death_observed": True,
        "payload_pidfd_death_observed": True,
        "wait4_exactly_once": True,
        "leaf_empty_supplemental": True,
        "cgroup_assignment_verified": True,
    }


class InertGateTests(unittest.TestCase):
    def test_every_execution_binding_is_none(self) -> None:
        self.assertEqual(set(target.current_review_bindings()), set(target.REVIEW_GATE_NAMES))
        self.assertTrue(all(value is None for value in target.current_review_bindings().values()))

    def test_direct_entry_is_inert_before_any_side_effect(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(target, "validate_stage0_entry") as stage0,
            mock.patch.object(target.os, "open") as opened,
            mock.patch.object(target.os, "fork", create=True) as forked,
            mock.patch.object(target.Path, "mkdir") as mkdir,
            mock.patch("sys.stderr", stderr),
        ):
            self.assertEqual(target.main([]), 2)
        stage0.assert_not_called()
        opened.assert_not_called()
        forked.assert_not_called()
        mkdir.assert_not_called()
        self.assertEqual(stderr.getvalue(), "STOP:external-sealed-stage0-required\n")

    def test_unbound_stage1_stops_before_runtime(self) -> None:
        with (
            mock.patch.object(target, "validate_stage0_entry", return_value={}),
            mock.patch.object(target, "_execute_bound_pipeline") as execute,
            self.assertRaisesRegex(target.Refused, "review-binding-unbound"),
        ):
            target.run_sealed_stage1("1" * 64)
        execute.assert_not_called()

    def test_stage1_enters_swap_zero_parent_before_sealed_reexec(self) -> None:
        class Transitioned(BaseException):
            pass

        bindings = review_bindings()
        contract_sha256 = "1" * 64
        contract = {
            "review_bindings_sha256": target.sha256_bytes(
                target.canonical(bindings)
            ),
            "supervisor_source": {"sha256": "4" * 64},
            "external_stage0_source_sha256": bindings["external_stage0"],
        }
        events: list[str] = []

        def enter(_binding: dict) -> dict:
            events.append("parent-cgroup-entered")
            return parent_entry_base()

        def transition(*_args) -> None:
            events.append("sealed-reexec")
            raise Transitioned

        with (
            mock.patch.object(target, "validate_stage0_entry", return_value=contract),
            mock.patch.object(target, "require_review_bindings", return_value=bindings),
            mock.patch.object(
                target, "harden_parent_process", side_effect=lambda: events.append("harden")
            ),
            mock.patch.object(
                target, "enter_and_authenticate_parent_cgroup", side_effect=enter
            ),
            mock.patch.object(target, "_reexec_sealed_stage2", side_effect=transition),
            mock.patch.object(target, "authenticate_assignment_pair") as private_read,
            self.assertRaises(Transitioned),
        ):
            target.run_sealed_stage1(contract_sha256)
        self.assertEqual(events, ["harden", "parent-cgroup-entered", "sealed-reexec"])
        private_read.assert_not_called()


class Stage0AndFilterTests(unittest.TestCase):
    def test_embedded_sources_compile_without_importing_workspace_code(self) -> None:
        compile(target.EXTERNAL_STAGE0_SOURCE, "<external-stage0>", "exec")
        compile(target.WORKER_SOURCE, "<sandbox-worker>", "exec")

    def test_external_stage0_is_isolated_sealed_and_descriptor_executed(self) -> None:
        source = target.EXTERNAL_STAGE0_SOURCE
        for token in (
            "O_NOFOLLOW",
            "MFD_ALLOW_SEALING",
            "F_ADD_SEALS",
            "F_SEAL_WRITE",
            str(target.EXTERNAL_STAGE0_AUTHORITY),
            "st_uid==0",
            '"-I","-S","-B"',
            '"/proc/self/fd/3"',
            "os.execve",
        ):
            self.assertIn(token, source)
        self.assertNotIn("run_frozen_w1_proof", source)
        self.assertNotIn("__pycache__", source)

    def test_stage1_transition_is_sealed_then_execs_same_source_as_stage2(self) -> None:
        class Execed(BaseException):
            pass

        bindings = review_bindings()
        contract_sha256 = "1" * 64
        contract = {"supervisor_source": {"sha256": "4" * 64}}
        captured: dict[str, object] = {}

        def seal(_name: str, raw: bytes) -> int:
            captured["transition"] = target.decode_canonical_json(
                raw, category="test-transition"
            )
            return 5

        def execute(path: str, argv: list[str], environment: dict) -> None:
            captured.update(path=path, argv=argv, environment=environment)
            raise Execed

        with (
            mock.patch.object(target, "sealed_memfd", side_effect=seal),
            mock.patch.object(target, "_live_fds", return_value={0, 1, 2, 3, 4, 5}),
            mock.patch.object(target.os, "set_inheritable"),
            mock.patch.object(target.os, "close"),
            mock.patch.object(target.os, "execve", side_effect=execute),
            self.assertRaises(Execed),
        ):
            target._reexec_sealed_stage2(
                contract_sha256, contract, bindings, parent_entry_base()
            )
        transition = captured["transition"]
        self.assertIsInstance(transition, dict)
        self.assertFalse(transition["private_content_opened_or_hashed"])
        self.assertEqual(transition["next_stage"], "sealed-stage2-post-cgroup-reexec")
        self.assertEqual(captured["path"], str(target.PYTHON))
        self.assertEqual(captured["argv"][5], "--sealed-stage2")
        self.assertEqual(captured["environment"], target.STAGE2_ENVIRONMENT)

    def test_stage2_transition_revalidates_live_swap_zero_membership(self) -> None:
        bindings = review_bindings()
        contract_sha256 = "1" * 64
        contract = {"supervisor_source": {"sha256": "4" * 64}}
        transition = target._stage1_transition_value(
            contract_sha256, contract, bindings, parent_entry_base()
        )
        raw = target.canonical(transition)
        digest = target.sha256_bytes(raw)
        with (
            mock.patch.object(target, "read_sealed_fd", return_value=raw),
            mock.patch.object(target, "_proc_starttime", return_value=12345),
            mock.patch.object(target, "_proc_cgroup_path", return_value="/kpb-reviewed"),
            mock.patch.object(
                target,
                "read_parent_cgroup_snapshot",
                return_value=parent_cgroup_snapshot(procs=[os.getpid()]),
            ),
            mock.patch.object(
                target, "read_cgroup_snapshot", return_value=leaf_cgroup_snapshot()
            ),
        ):
            final = target._validate_stage1_transition(
                digest, contract_sha256, contract, bindings
            )
        self.assertTrue(final["sealed_reexec_completed"])
        self.assertEqual(final["sealed_transition_sha256"], digest)

    def test_stage2_refuses_transition_claiming_private_preexec_read(self) -> None:
        bindings = review_bindings()
        contract_sha256 = "1" * 64
        contract = {"supervisor_source": {"sha256": "4" * 64}}
        transition = target._stage1_transition_value(
            contract_sha256, contract, bindings, parent_entry_base()
        )
        transition["private_content_opened_or_hashed"] = True
        raw = target.canonical(transition)
        with (
            mock.patch.object(target, "read_sealed_fd", return_value=raw),
            mock.patch.object(target, "_proc_starttime", return_value=12345),
            mock.patch.object(target, "_proc_cgroup_path", return_value="/kpb-reviewed"),
            mock.patch.object(
                target,
                "read_parent_cgroup_snapshot",
                return_value=parent_cgroup_snapshot(procs=[os.getpid()]),
            ),
            mock.patch.object(
                target, "read_cgroup_snapshot", return_value=leaf_cgroup_snapshot()
            ),
            self.assertRaisesRegex(target.Refused, "stage1-transition-values"),
        ):
            target._validate_stage1_transition(
                target.sha256_bytes(raw), contract_sha256, contract, bindings
            )

    def test_seccomp_is_architecture_checking_and_denies_required_surfaces(self) -> None:
        raw = target.seccomp_filter_bytes()
        self.assertGreater(len(raw), 8)
        self.assertIn(struct.pack("I", target.AUDIT_ARCH_X86_64), raw)
        self.assertIn(struct.pack("HBBI", 0x45, 0, 1, target.X32_SYSCALL_BIT), raw)
        for syscall in (41, 53, 101, 250, 298, 321, 323, 425, 438, 165, 272, 308):
            self.assertIn(syscall, target.DENIED_SYSCALLS_X86_64)
        self.assertNotIn(56, target.DENIED_SYSCALLS_X86_64)  # clone: proof threads remain possible
        self.assertNotIn(435, target.DENIED_SYSCALLS_X86_64)  # clone3

    def test_status_json_rejects_duplicate_key(self) -> None:
        raw = b'{"child-pid":1,"child-pid":2}\n{"exit-code":0}\n'
        with self.assertRaises(target.Refused):
            target.parse_status_stream(raw)


class ReviewBindingTests(unittest.TestCase):
    def test_synthetic_complete_review_contract_validates(self) -> None:
        value = review_bindings()
        self.assertIs(target.validate_review_bindings(value), value)

    def test_installed_vulnerable_bwrap_is_explicitly_refused(self) -> None:
        value = review_bindings()
        value["bwrap"]["executable"]["path"] = str(target.REJECTED_HOST_BWRAP)
        value["bwrap"]["version"] = [0, 11, 1]
        value["bwrap"]["package_release"] = target.REJECTED_HOST_BWRAP_PACKAGE
        with self.assertRaisesRegex(target.Refused, "bwrap-exact-debian-artifact"):
            target.validate_review_bindings(value)

    def test_fixed_debian_bwrap_at_system_apparmor_path_is_permitted(self) -> None:
        value = review_bindings()
        bwrap = value["bwrap"]
        self.assertIs(target.validate_review_bindings(value), value)

    def test_filter_hash_substitution_is_refused(self) -> None:
        value = review_bindings()
        value["seccomp"]["proof"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(target.Refused, "seccomp-review-binding"):
            target.validate_review_bindings(value)

    def test_artifact_without_fsverity_is_refused(self) -> None:
        value = review_bindings()
        value["artifacts"]["r1cs"]["fsverity"]["enabled"] = False
        with self.assertRaisesRegex(target.Refused, "artifact-r1cs-immutable-binding"):
            target.validate_review_bindings(value)

    def test_private_artifact_hidden_in_runtime_closure_is_refused(self) -> None:
        value = review_bindings()
        private = value["artifacts"]["decoded_pk"]["file"]
        value["runtime_closure"]["proof"][0]["file"]["bytes"] = private["bytes"]
        value["runtime_closure"]["proof"][0]["file"]["sha256"] = private["sha256"]
        with self.assertRaisesRegex(target.Refused, "runtime-closure-private-input-leak"):
            target.validate_review_bindings(value)

    def test_custom_bwrap_path_is_refused(self) -> None:
        value = review_bindings()
        value["bwrap"]["executable"]["path"] = "/usr/local/libexec/bwrap"
        with self.assertRaisesRegex(target.Refused, "bwrap-exact-debian-artifact"):
            target.validate_review_bindings(value)

    def test_unconfined_or_complain_apparmor_is_refused(self) -> None:
        for field, replacement in (
            ("expected_apparmor_label", "unconfined"),
            ("apparmor_mode", "complain"),
        ):
            value = review_bindings()
            value["bwrap"][field] = replacement
            with self.assertRaisesRegex(target.Refused, "bwrap-apparmor-enforce-authority"):
                target.validate_review_bindings(value)

    def test_apparmor_include_closure_drift_is_refused(self) -> None:
        value = review_bindings()
        value["bwrap"]["apparmor_source_closure"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(target.Refused, "apparmor-source-closure-hash"):
            target.validate_review_bindings(value)

    def test_unrelated_file_cannot_authenticate_as_apparmor_profile(self) -> None:
        bwrap = review_bindings()["bwrap"]
        with (
            mock.patch.object(
                target,
                "stable_read",
                return_value=(b"127.0.0.1 localhost\n", bwrap["apparmor_source_closure"][0]),
            ),
            self.assertRaisesRegex(target.Refused, "apparmor-root-attachment"),
        ):
            target._authenticate_apparmor_closure(bwrap)

    def test_non_enforce_apparmor_source_attachment_is_refused(self) -> None:
        bwrap = review_bindings()["bwrap"]
        reference = bwrap["apparmor_source_closure"][0]
        for flag in ("unconfined", "complain"):
            raw = (
                f"profile bwrap /usr/bin/bwrap flags=({flag}) {{\n}}\n"
            ).encode("ascii")
            with (
                self.subTest(flag=flag),
                mock.patch.object(
                    target,
                    "stable_read",
                    return_value=(raw, reference),
                ),
                self.assertRaisesRegex(
                    target.Refused, "apparmor-root-attachment"
                ),
            ):
                target._authenticate_apparmor_closure(bwrap)

    def test_build_id_or_derived_dependency_graph_drift_is_refused(self) -> None:
        for field, replacement in (
            ("elf_build_id", "0" * 40),
            ("elf_dependency_graph", {}),
            ("version", [999, 999, 999]),
        ):
            value = review_bindings()
            value["bwrap"][field] = replacement
            with self.assertRaisesRegex(target.Refused, "bwrap-exact-debian-artifact"):
                target.validate_review_bindings(value)

    def test_non_elf_cannot_authenticate_as_loader_closure(self) -> None:
        bwrap = review_bindings()["bwrap"]
        descriptor = os.memfd_create("synthetic-not-elf", os.MFD_CLOEXEC)
        os.write(descriptor, b"not an ELF loader\n" * 16)
        with (
            mock.patch.object(
                target,
                "stable_open",
                return_value=(descriptor, bwrap["loader_closure"][0]["file"]),
            ),
            self.assertRaisesRegex(target.Refused, "elf-x86-64-little-endian"),
        ):
            target._authenticate_loader_closure(bwrap)

    def test_prover_and_verifier_build_authorities_must_be_distinct(self) -> None:
        value = review_bindings()
        value["build"]["verifier"] = copy.deepcopy(value["build"]["proof"])
        with self.assertRaisesRegex(target.Refused, "role-distinct-build-authority"):
            target.validate_review_bindings(value)

    def test_same_binary_content_under_distinct_paths_is_refused(self) -> None:
        value = review_bindings()
        value["build"]["verifier"]["binary"]["sha256"] = (
            value["build"]["proof"]["binary"]["sha256"]
        )
        with self.assertRaisesRegex(target.Refused, "role-distinct-build-content"):
            target.validate_review_bindings(value)

    def test_cross_role_build_receipt_is_refused(self) -> None:
        bindings = review_bindings()
        proof = bindings["build"]["proof"]
        receipt = {
            "schema": "kpb-frozen-w1-role-build-receipt/v1",
            "role": "verifier",
            "binary": proof["binary"],
            "source_closure_sha256": proof["source_closure_sha256"],
            "runtime_closure_sha256": target.sha256_bytes(
                target.canonical(bindings["runtime_closure"]["proof"])
            ),
            "independently_reviewed": True,
            "test_only": True,
        }
        with (
            mock.patch.object(
                target,
                "stable_read",
                return_value=(target.canonical(receipt), proof["build_receipt"]),
            ),
            self.assertRaisesRegex(target.Refused, "proof-build-receipt-values"),
        ):
            target.authenticate_role_build_receipt("proof", bindings)

    def test_artifact_substitution_is_refused(self) -> None:
        value = review_bindings()
        value["artifacts"]["decoded_pk"]["file"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(target.Refused, "artifact-decoded_pk-fixed"):
            target.validate_review_bindings(value)


class SandboxPlanTests(unittest.TestCase):
    def test_explicit_namespace_and_start_barrier_contract(self) -> None:
        plan = sandbox_plan("proof")
        for option in target.MANDATORY_NAMESPACE_FLAGS:
            self.assertEqual(plan["command"].count(option), 1)
        self.assertIn("--seccomp", plan["command"])
        self.assertIn("--json-status-fd", plan["command"])
        self.assertIn("--block-fd", plan["command"])
        self.assertFalse(target.FORBIDDEN_BWRAP_OPTIONS.intersection(plan["command"]))

    def test_proof_gets_exact_five_private_artifacts(self) -> None:
        plan = sandbox_plan("proof")
        self.assertEqual(set(plan["private_input_labels"]), set(target.PROOF_PRIVATE_LABELS))
        worker = next(item for item in plan["mounts"] if item["label"] == "worker")
        self.assertEqual(worker["kind"], "ro-bind-fd")
        self.assertNotIn("--ro-bind-data", plan["command"])

    def test_verifier_gets_only_vk_and_receipt_is_stdin(self) -> None:
        plan = sandbox_plan("verifier")
        self.assertEqual(plan["private_input_labels"], ["vk"])
        destinations = {item["destination"] for item in plan["mounts"]}
        for name in ("r1cs", "decoded_pk", "decode_receipt", "compressed_pk"):
            self.assertNotIn(target.EXPECTED_ARTIFACTS[name]["path"], destinations)
        self.assertNotIn("assignment", " ".join(plan["command"]).lower())
        self.assertNotIn("PROOF-RECEIPT.json", destinations)

    def test_verifier_input_leakage_is_refused(self) -> None:
        plan = sandbox_plan("verifier")
        plan["mounts"].append(
            {
                "kind": "ro-bind-fd",
                "label": "decoded_pk",
                "fd": 99,
                "destination": target.EXPECTED_ARTIFACTS["decoded_pk"]["path"],
            }
        )
        with self.assertRaisesRegex(target.Refused, "sandbox-canonical-reconstruction"):
            target.validate_sandbox_plan(plan)

    def test_extra_passed_fd_reference_is_refused(self) -> None:
        plan = sandbox_plan("proof")
        index = plan["command"].index("--seccomp") + 1
        plan["command"][index] = "999"
        with self.assertRaisesRegex(target.Refused, "sandbox-canonical-reconstruction"):
            target.validate_sandbox_plan(plan)

    def test_unreferenced_extra_passed_fd_is_refused(self) -> None:
        plan = sandbox_plan("proof")
        plan["passed_fds"] = tuple(sorted((*plan["passed_fds"], 998)))
        with self.assertRaisesRegex(target.Refused, "sandbox-canonical-reconstruction"):
            target.validate_sandbox_plan(plan)

    def test_every_argv_position_is_canonically_reconstructed(self) -> None:
        original = sandbox_plan("proof")
        for index in range(len(original["command"])):
            plan = copy.deepcopy(original)
            plan["command"][index] += "-substituted"
            with self.subTest(index=index), self.assertRaisesRegex(
                target.Refused, "sandbox-canonical-reconstruction"
            ):
                target.validate_sandbox_plan(plan)

    def test_mount_destination_and_payload_substitution_are_refused(self) -> None:
        for field in ("mounts", "payload_argv"):
            plan = copy.deepcopy(sandbox_plan("verifier"))
            if field == "mounts":
                plan[field][0]["destination"] = "/payload/substituted"
            else:
                plan[field][-1] = "/payload/substituted"
            with self.subTest(field=field), self.assertRaisesRegex(
                target.Refused, "sandbox-canonical-reconstruction"
            ):
                target.validate_sandbox_plan(plan)

    def test_ld_preload_and_hidden_verifier_fd_are_refused(self) -> None:
        plan = sandbox_plan("verifier")
        plan["environment"]["LD_PRELOAD"] = "/tmp/injected.so"
        with self.assertRaisesRegex(target.Refused, "sandbox-canonical-reconstruction"):
            target.validate_sandbox_plan(plan)
        plan = sandbox_plan("verifier")
        marker = plan["command"].index("--seccomp")
        plan["command"][marker:marker] = [
            "--ro-bind-fd", "99", target.EXPECTED_ARTIFACTS["decoded_pk"]["path"]
        ]
        plan["passed_fds"] = tuple(sorted((*plan["passed_fds"], 99)))
        with self.assertRaisesRegex(target.Refused, "sandbox-canonical-reconstruction"):
            target.validate_sandbox_plan(plan)


class LaunchEvidenceTests(unittest.TestCase):
    def test_valid_launch_evidence(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        target.validate_launch_evidence(
            evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
        )

    def test_unreviewed_live_mount_is_refused_even_if_required_mounts_exist(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        injected = copy.deepcopy(evidence["mount_evidence"]["entries"][0])
        injected.update(mount_id=999, mount_point="/unreviewed-host-mount")
        evidence["mount_evidence"]["entries"].append(injected)
        evidence["mount_evidence"]["entries_sha256"] = target.sha256_bytes(
            target.canonical(evidence["mount_evidence"]["entries"])
        )
        with self.assertRaisesRegex(
            target.Refused, "mount-evidence-exact-rehearsed-allowlist"
        ):
            target.validate_launch_evidence(
                evidence,
                plan,
                evidence["host_namespaces"],
                cgroup_binding(),
                review_bindings()["bwrap"],
            )

    def test_pid_starttime_substitution_is_refused(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        evidence["payload_starttime_after"] += 1
        with self.assertRaisesRegex(target.Refused, "launch-pid-substitution"):
            target.validate_launch_evidence(
                evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
            )

    def test_extra_payload_fd_is_refused(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        evidence["payload_fds"].append(7)
        with self.assertRaisesRegex(target.Refused, "launch-boundary-substitution"):
            target.validate_launch_evidence(
                evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
            )

    def test_namespace_failure_is_refused(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        evidence["payload_namespaces"]["net"] = evidence["host_namespaces"]["net"]
        with self.assertRaisesRegex(target.Refused, "launch-namespace-separation"):
            target.validate_launch_evidence(
                evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
            )

    def test_seccomp_or_capability_failure_is_refused(self) -> None:
        for field, replacement in (
            ("seccomp_mode", 0),
            ("seccomp_filter_count", 2),
        ):
            plan = sandbox_plan()
            evidence = launch_evidence(plan)
            evidence[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                target.Refused, "launch-capability-or-seccomp"
            ):
                target.validate_launch_evidence(
                    evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
                )
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        evidence["capabilities"]["CapBnd"] = 1
        with self.assertRaisesRegex(target.Refused, "launch-capability-or-seccomp"):
            target.validate_launch_evidence(
                evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
            )

    def test_argv_substitution_is_refused(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        evidence["payload_cmdline"][-1] = "/host/replacement"
        with self.assertRaisesRegex(target.Refused, "launch-boundary-substitution"):
            target.validate_launch_evidence(
                evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
            )

    def test_mount_destination_mode_and_apparmor_substitution_are_refused(self) -> None:
        plan = sandbox_plan()
        for mutation, category in (
            ("mount-point", "mount-evidence-destination-missing"),
            ("mount-mode", "mount-evidence-mode"),
            ("mount-inode", "mount-target-identity"),
            ("loader-inode", "loaded-elf-mapping-identity"),
            ("apparmor", "launch-boundary-substitution"),
        ):
            evidence = launch_evidence(plan)
            if mutation == "mount-point":
                evidence["mount_evidence"]["entries"][0]["mount_point"] = "/wrong"
                evidence["mount_evidence"]["entries_sha256"] = target.sha256_bytes(
                    target.canonical(evidence["mount_evidence"]["entries"])
                )
            elif mutation == "mount-mode":
                private = next(
                    item for item in evidence["mount_evidence"]["entries"]
                    if item["mount_point"] == "/payload/proof"
                )
                private["mount_options"] = ["rw"]
                private["super_options"] = ["rw"]
                evidence["mount_evidence"]["entries_sha256"] = target.sha256_bytes(
                    target.canonical(evidence["mount_evidence"]["entries"])
                )
            elif mutation == "mount-inode":
                evidence["mount_target_identities"][0]["target_inode"] += 1
            elif mutation == "loader-inode":
                evidence["loaded_elf_mappings"]["objects"][0]["inode"] += 1
                evidence["loaded_elf_mappings"]["objects_sha256"] = (
                    target.sha256_bytes(
                        target.canonical(
                            evidence["loaded_elf_mappings"]["objects"]
                        )
                    )
                )
            else:
                evidence["bwrap_apparmor_label"] = "unconfined"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                target.Refused, category
            ):
                target.validate_launch_evidence(
                    evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
                )

    def test_unexpected_loaded_executable_is_refused(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        evidence["loaded_elf_mappings"]["executable_identities"].append(
            {"elf_name": "preload.so", "device": 99, "inode": 100}
        )
        with self.assertRaisesRegex(
            target.Refused, "loaded-elf-executable-closure"
        ):
            target.validate_launch_evidence(
                evidence,
                plan,
                evidence["host_namespaces"],
                cgroup_binding(),
                review_bindings()["bwrap"],
            )

    def test_cgroup_assignment_receipt_is_required(self) -> None:
        plan = sandbox_plan()
        evidence = launch_evidence(plan)
        evidence["cgroup_assignment"]["assignment_verified"] = False
        with self.assertRaisesRegex(target.Refused, "cgroup-assignment-values"):
            target.validate_launch_evidence(
                evidence, plan, evidence["host_namespaces"], cgroup_binding(), review_bindings()["bwrap"]
            )

    def test_second_worker_readiness_barrier_is_exact(self) -> None:
        read_fd, write_fd = os.pipe()
        ready = {
            "schema": "kpb-w1-worker-ready/v1",
            "role": "verify",
            "namespace_pid": 1,
            "fds": [0, 1, 2],
            "caps_zero": True,
            "no_new_privs": 1,
            "seccomp": 2,
            "seccomp_filters": 1,
            "seccomp_probes": {
                "getpid": True,
                "pidfd_open": True,
                "socket": True,
            },
        }
        os.write(write_fd, target.WORKER_READY_PREFIX + target.canonical(ready))
        os.close(write_fd)
        try:
            self.assertEqual(
                target._read_worker_ready(
                    read_fd,
                    role="verify",
                    deadline=time.monotonic() + 1.0,
                ),
                ready,
            )
        finally:
            os.close(read_fd)

    def test_failed_seccomp_probe_is_refused_at_readiness_barrier(self) -> None:
        read_fd, write_fd = os.pipe()
        ready = {
            "schema": "kpb-w1-worker-ready/v1",
            "role": "proof",
            "namespace_pid": 1,
            "fds": [0, 1, 2],
            "caps_zero": True,
            "no_new_privs": 1,
            "seccomp": 2,
            "seccomp_filters": 1,
            "seccomp_probes": {
                "getpid": True,
                "pidfd_open": True,
                "socket": False,
            },
        }
        os.write(write_fd, target.WORKER_READY_PREFIX + target.canonical(ready))
        os.close(write_fd)
        try:
            with self.assertRaisesRegex(target.Refused, "worker-ready-values"):
                target._read_worker_ready(
                    read_fd,
                    role="proof",
                    deadline=time.monotonic() + 1.0,
                )
        finally:
            os.close(read_fd)


class WaitAndCgroupTests(unittest.TestCase):
    def test_valid_exact_wait_eof_and_zero_descendants(self) -> None:
        target.validate_wait_evidence(wait_evidence(), expected_pid=1001)
        target.validate_cgroup_pair(cgroup_snapshot(), cgroup_snapshot(), cgroup_binding())

    def test_signal_is_refused(self) -> None:
        value = wait_evidence()
        value.update(exited=False, exit_code=None, term_signal=9)
        with self.assertRaisesRegex(target.Refused, "wait4-exit-status"):
            target.validate_wait_evidence(value, expected_pid=1001)

    def test_missing_eof_is_refused(self) -> None:
        value = wait_evidence()
        value["status_eof"] = False
        with self.assertRaisesRegex(target.Refused, "wait4-stream-eof"):
            target.validate_wait_evidence(value, expected_pid=1001)

    def test_surviving_descendant_is_refused(self) -> None:
        value = wait_evidence()
        value.update(zero_descendants=False, cgroup_populated=1, cgroup_procs=[1003])
        with self.assertRaisesRegex(target.Refused, "wait4-descendants-or-swap"):
            target.validate_wait_evidence(value, expected_pid=1001)

    def test_swap_drift_is_refused(self) -> None:
        after = cgroup_snapshot()
        after["parent"]["memory_swap_current"] = 4096
        with self.assertRaisesRegex(target.Refused, "parent-cgroup-swap-contract"):
            target.validate_cgroup_pair(cgroup_snapshot(), after, cgroup_binding())

    def test_cgroup_identity_drift_is_refused(self) -> None:
        after = cgroup_snapshot()
        after["leaf"]["inode"] += 1
        with self.assertRaisesRegex(target.Refused, "leaf-cgroup-contract-drift"):
            target.validate_cgroup_pair(cgroup_snapshot(), after, cgroup_binding())

    def test_group_kill_reap_and_empty_are_mandatory_and_kill_error_is_not_ignored(self) -> None:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        with (
            mock.patch.object(
                target.signal,
                "pidfd_send_signal",
                side_effect=PermissionError(13, "synthetic"),
                create=True,
            ),
            mock.patch.object(target, "trigger_cgroup_kill") as group_kill,
            mock.patch.object(target, "_wait_pidfd_death") as death,
            mock.patch.object(target.os, "wait4", return_value=(1001, 9, usage)) as wait4,
            mock.patch.object(
                target,
                "verify_cgroup_empty_bounded",
                return_value=leaf_cgroup_snapshot(),
            ) as empty,
            self.assertRaisesRegex(target.Refused, "failure-direct-kill-error"),
        ):
            target.contain_failed_sandbox(
                payload_pidfd=40,
                bwrap_pidfd=41,
                payload_pid=1002,
                bwrap_pid=1001,
                cgroup_kill_fd=42,
                cgroup_binding=cgroup_binding(),
            )
        group_kill.assert_called_once_with(42)
        self.assertEqual(death.call_count, 2)
        wait4.assert_called_once_with(1001, 0)
        empty.assert_called_once()

    def test_reap_error_is_not_ignored_and_leaf_empty_is_still_checked(self) -> None:
        with (
            mock.patch.object(target.signal, "pidfd_send_signal", create=True),
            mock.patch.object(target, "trigger_cgroup_kill") as group_kill,
            mock.patch.object(target, "_wait_pidfd_death"),
            mock.patch.object(target.os, "wait4", side_effect=OSError(5, "synthetic")),
            mock.patch.object(
                target,
                "verify_cgroup_empty_bounded",
                return_value=leaf_cgroup_snapshot(),
            ) as empty,
            self.assertRaisesRegex(target.Refused, "failure-containment-unproven"),
        ):
            target.contain_failed_sandbox(
                payload_pidfd=40,
                bwrap_pidfd=41,
                payload_pid=1002,
                bwrap_pid=1001,
                cgroup_kill_fd=42,
                cgroup_binding=cgroup_binding(),
            )
        group_kill.assert_called_once_with(42)
        empty.assert_called_once()

    def test_started_payload_without_pidfd_can_never_prove_containment(self) -> None:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        with (
            mock.patch.object(target.signal, "pidfd_send_signal", create=True),
            mock.patch.object(target.os, "kill"),
            mock.patch.object(target, "trigger_cgroup_kill") as group_kill,
            mock.patch.object(target, "_wait_pidfd_death") as death,
            mock.patch.object(target.os, "wait4", return_value=(1001, 9, usage)) as wait4,
            mock.patch.object(
                target,
                "verify_cgroup_empty_bounded",
                return_value=leaf_cgroup_snapshot(),
            ) as empty,
            self.assertRaisesRegex(target.Refused, "failure-containment-unproven"),
        ):
            target.contain_failed_sandbox(
                payload_pidfd=-1,
                bwrap_pidfd=41,
                payload_pid=1002,
                bwrap_pid=1001,
                cgroup_kill_fd=42,
                cgroup_binding=cgroup_binding(),
            )
        death.assert_called_once_with(41, seconds=target.POST_EXIT_DRAIN_SECONDS)
        wait4.assert_called_once_with(1001, 0)
        group_kill.assert_called_once_with(42)
        empty.assert_called_once()

    def test_oom_counters_do_not_block_empty_leaf_containment_evidence(self) -> None:
        snapshot = parent_cgroup_snapshot()
        snapshot["oom"] = 2
        snapshot["oom_kill"] = 1
        self.assertIs(
            target.validate_parent_cgroup_snapshot(snapshot, cgroup_binding()),
            snapshot,
        )
        target.validate_cgroup_snapshot(
            leaf_cgroup_snapshot(), cgroup_binding(), empty=True
        )

    def test_unreturned_fork_child_is_pidfd_killed_and_exactly_reaped(self) -> None:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        with (
            mock.patch.object(target.os, "pidfd_open", return_value=80) as pidfd_open,
            mock.patch.object(
                target.signal, "pidfd_send_signal", create=True
            ) as pidfd_kill,
            mock.patch.object(target, "_wait_pidfd_death") as death,
            mock.patch.object(
                target,
                "_reap_child_bounded",
                return_value=(222, 9, usage),
            ) as reap,
            mock.patch.object(target.os, "close") as close,
        ):
            target._contain_unreturned_fork_child(222)
        pidfd_open.assert_called_once_with(222, 0)
        pidfd_kill.assert_called_once_with(80, target.signal.SIGKILL)
        death.assert_called_once_with(80, seconds=target.POST_EXIT_DRAIN_SECONDS)
        reap.assert_called_once_with(222, seconds=target.POST_EXIT_DRAIN_SECONDS)
        close.assert_called_once_with(80)

    def test_already_dead_unreturned_child_is_still_exactly_reaped(self) -> None:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        with (
            mock.patch.object(target.os, "pidfd_open", return_value=80),
            mock.patch.object(
                target.signal,
                "pidfd_send_signal",
                side_effect=ProcessLookupError(3, "already dead"),
                create=True,
            ),
            mock.patch.object(target, "_wait_pidfd_death") as death,
            mock.patch.object(
                target,
                "_reap_child_bounded",
                return_value=(222, 0, usage),
            ) as reap,
            mock.patch.object(target.os, "close"),
        ):
            target._contain_unreturned_fork_child(222)
        death.assert_called_once_with(80, seconds=target.POST_EXIT_DRAIN_SECONDS)
        reap.assert_called_once_with(222, seconds=target.POST_EXIT_DRAIN_SECONDS)

    def test_parent_pipe_close_failure_cannot_lose_forked_child_pid(self) -> None:
        close_failed = False

        def close(descriptor: int) -> None:
            nonlocal close_failed
            if descriptor == 71 and not close_failed:
                close_failed = True
                raise OSError(5, "synthetic parent close failure")

        with (
            mock.patch.object(target.os, "pipe2", return_value=(70, 71)),
            mock.patch.object(target.os, "fork", return_value=222),
            mock.patch.object(target.os, "getpid", return_value=111),
            mock.patch.object(target.os, "close", side_effect=close),
            mock.patch.object(target, "_contain_unreturned_fork_child") as contain,
            self.assertRaisesRegex(OSError, "synthetic parent close failure"),
        ):
            target._fork_stopped_bwrap(
                sandbox_plan(), stdin_fd=60, stdout_fd=61, stderr_fd=62
            )
        contain.assert_called_once_with(222)

    def test_pdeathsig_receipt_is_armed_before_child_sigstop(self) -> None:
        events: list[str] = []

        class StopChild(BaseException):
            pass

        def pdeath(_pid: int) -> None:
            events.append("pdeath")

        def write(_fd: int, _raw: bytes) -> int:
            events.append("receipt")
            return 1

        def kill(_pid: int, _sig: int) -> None:
            events.append("sigstop")
            raise StopChild

        with (
            mock.patch.object(target.os, "pipe2", return_value=(70, 71)),
            mock.patch.object(target.os, "fork", return_value=0),
            mock.patch.object(target.os, "getpid", return_value=222),
            mock.patch.object(target.os, "close"),
            mock.patch.object(target, "_set_parent_death_signal", side_effect=pdeath),
            mock.patch.object(target.os, "write", side_effect=write),
            mock.patch.object(target.os, "kill", side_effect=kill),
            mock.patch.object(target.os, "_exit", side_effect=StopChild),
            self.assertRaises(StopChild),
        ):
            target._fork_stopped_bwrap(
                sandbox_plan(), stdin_fd=60, stdout_fd=61, stderr_fd=62
            )
        self.assertEqual(events, ["pdeath", "receipt", "sigstop"])


class LifecycleAndDeadlineTests(unittest.TestCase):
    def test_post_cgroup_sealed_reexec_precedes_all_private_reads(self) -> None:
        receipt_raw = target.canonical(proof_receipt())
        frame = target.FRAME_MAGIC + struct.pack(">I", len(receipt_raw)) + receipt_raw
        marker = (
            target.VERIFIED_MARKER
            + target.sha256_bytes(receipt_raw).encode("ascii")
            + b"\n"
        )
        events: list[str] = []

        def validate_reexec(entry: dict, _binding: dict) -> dict:
            events.append("post-cgroup-sealed-reexec")
            return entry

        def assignment(_binding: dict) -> dict:
            events.append("assignment-read")
            return {"stable": True}

        def role(name: str, **_kwargs) -> dict:
            events.append(f"role-{name}")
            return {"stdout": frame if name == "proof" else marker}

        with (
            mock.patch.object(target.os, "geteuid", return_value=1000),
            mock.patch.object(
                target,
                "_revalidate_live_parent_cgroup_entry",
                side_effect=validate_reexec,
            ),
            mock.patch.object(target, "enter_and_authenticate_parent_cgroup") as enter,
            mock.patch.object(target, "authenticate_assignment_pair", side_effect=assignment),
            mock.patch.object(target, "execute_role", side_effect=role),
            mock.patch.object(target, "atomic_publish", return_value={"published": True}) as publish,
        ):
            result = target._execute_bound_pipeline(
                {"mainnet": False, "funds": False, "test_only": True},
                {"cgroup": {}, "assignment": {}},
                {"sealed_reexec_completed": True},
            )
        self.assertEqual(result, {"published": True})
        self.assertEqual(events[0], "post-cgroup-sealed-reexec")
        self.assertLess(
            events.index("post-cgroup-sealed-reexec"),
            events.index("assignment-read"),
        )
        self.assertLess(
            events.index("post-cgroup-sealed-reexec"), events.index("role-proof")
        )
        enter.assert_not_called()
        publish.assert_called_once()

    def test_worker_leaf_must_be_a_strict_child_of_swap_zero_parent(self) -> None:
        value = cgroup_binding()
        value["worker_leaf"]["path"] = "/sys/fs/cgroup/sibling/w1"
        with self.assertRaisesRegex(target.Refused, "cgroup-binding-values"):
            target.validate_cgroup_binding(value)

    def test_post_reexec_cgroup_migration_before_private_io_is_refused(self) -> None:
        with (
            mock.patch.object(target, "_proc_starttime", return_value=12345),
            mock.patch.object(target, "_proc_cgroup_path", return_value="/migrated"),
            mock.patch.object(
                target,
                "read_parent_cgroup_snapshot",
                return_value=parent_cgroup_snapshot(procs=[os.getpid()]),
            ),
            mock.patch.object(
                target, "read_cgroup_snapshot", return_value=leaf_cgroup_snapshot()
            ),
            self.assertRaisesRegex(
                target.Refused, "parent-cgroup-live-post-reexec-drift"
            ),
        ):
            target._revalidate_live_parent_cgroup_entry(
                parent_entry(), cgroup_binding()
            )

    def test_prestart_readiness_has_a_finite_deadline(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            with self.assertRaisesRegex(target.Refused, "synthetic-readiness-timeout"):
                target._read_deadline(
                    read_fd,
                    deadline=time.monotonic() - 0.001,
                    maximum=8,
                    complete=lambda _raw: False,
                    category="synthetic-readiness-timeout",
                )
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_final_worker_release_recheck_refuses_expired_deadline(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(
                target.Refused,
                "bwrap-prestart-deadline-expired-before-worker-release",
            ):
                target._assert_prestart_release_allowed(
                    read_fd, deadline=time.monotonic() - 0.001
                )
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_final_worker_release_recheck_refuses_queued_owner_cancel(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            os.write(write_fd, b"\x0f")
            with self.assertRaisesRegex(
                target.OwnerCancelled,
                "explicit-owner-cancellation-before-worker-release",
            ):
                target._assert_prestart_release_allowed(
                    read_fd, deadline=time.monotonic() + 60
                )
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_launch_evidence_precedes_last_check_and_start_frame_release(self) -> None:
        source = inspect.getsource(target.supervise_sandbox)
        launch = source.index("launch = _collect_launch_evidence(")
        final_check = source.index("_assert_prestart_release_allowed(")
        release = source.index("os.write(stdin_write, start_frame)")
        self.assertLess(launch, final_check)
        self.assertLess(final_check, release)

    def test_live_proof_has_no_elapsed_deadline_and_owner_cancel_is_explicit(self) -> None:
        class FakeSelector:
            instances: list["FakeSelector"] = []

            def __init__(self) -> None:
                self.rows = {}
                self.timeouts = []
                self.__class__.instances.append(self)

            def register(self, fd, _events, data=None):
                self.rows[fd] = type("Key", (), {"fd": fd, "data": data})()

            def unregister(self, fd):
                return self.rows.pop(fd)

            def get_map(self):
                return self.rows

            def select(self, timeout=None):
                self.timeouts.append(timeout)
                key = next(row for row in self.rows.values() if row.data[0] == "owner-cancel")
                return [(key, 1)]

            def close(self):
                return None

        with (
            mock.patch.object(target.selectors, "DefaultSelector", FakeSelector),
            mock.patch.object(target.os, "set_blocking"),
            mock.patch.object(target.os, "read", return_value=b"\x0f"),
            mock.patch.object(target.os, "close"),
            mock.patch.object(target.os, "wait4") as wait4,
            self.assertRaisesRegex(target.OwnerCancelled, "explicit-owner-cancellation"),
        ):
            target._drain_and_wait4(
                1001,
                90,
                91,
                {92: ("stdout", 16)},
            )
        self.assertIsNone(FakeSelector.instances[0].timeouts[0])
        wait4.assert_not_called()
        self.assertIsNone(target.LIVE_PROOF_DEADLINE_SECONDS)

    def test_post_exit_stream_drain_deadline_is_finite(self) -> None:
        class FakeSelector:
            def __init__(self) -> None:
                self.rows = {}
                self.calls = 0
                self.timeouts = []

            def register(self, fd, _events, data=None):
                self.rows[fd] = type("Key", (), {"fd": fd, "data": data})()

            def unregister(self, fd):
                return self.rows.pop(fd)

            def get_map(self):
                return self.rows

            def select(self, timeout=None):
                self.timeouts.append(timeout)
                self.calls += 1
                if self.calls == 1:
                    key = next(row for row in self.rows.values() if row.data[0] == "pidfd")
                    return [(key, 1)]
                return []

            def close(self):
                return None

        fake = FakeSelector()
        with (
            mock.patch.object(target.selectors, "DefaultSelector", return_value=fake),
            mock.patch.object(target.os, "set_blocking"),
            mock.patch.object(target.os, "close"),
            self.assertRaisesRegex(target.Refused, "post-exit-stream-drain-timeout"),
        ):
            target._drain_and_wait4(1001, 90, 91, {92: ("stdout", 16)})
        self.assertIsNone(fake.timeouts[0])
        self.assertGreater(fake.timeouts[1], 0)
        self.assertLessEqual(fake.timeouts[1], target.POST_EXIT_DRAIN_SECONDS)


class OutputAndPublicationTests(unittest.TestCase):
    @staticmethod
    def staged_publication() -> tuple[dict[str, bytes], dict]:
        staged = {
            "PROOF-RECEIPT.json": b"proof\n",
            "EVIDENCE-MANIFEST.json": b"manifest\n",
            "VERIFICATION.json": b"verification\n",
        }
        commit = {
            "schema": "kpb-frozen-w1-publication-commit/v1",
            "committed": True,
            "manifest_sha256": target.sha256_bytes(
                staged["EVIDENCE-MANIFEST.json"]
            ),
            "files": {
                name: {"bytes": len(raw), "sha256": target.sha256_bytes(raw)}
                for name, raw in sorted(staged.items())
            },
            "expected_entries": sorted((*staged, "PUBLICATION-COMMIT.json")),
            "commit_protocol": "create-new-marker-last-fsync-reopen-exact",
            "marker_alone_is_not_authority": True,
            "remaining_uncertainty": "trusted-host storage remains in the TCB",
        }
        return staged, commit

    def test_exact_proof_frame_and_verifier_marker(self) -> None:
        receipt_raw = target.canonical(proof_receipt())
        frame = target.FRAME_MAGIC + struct.pack(">I", len(receipt_raw)) + receipt_raw
        parsed_raw, parsed = target.parse_proof_frame(frame)
        self.assertEqual(parsed_raw, receipt_raw)
        self.assertEqual(parsed, proof_receipt())
        marker = target.VERIFIED_MARKER + target.sha256_bytes(receipt_raw).encode() + b"\n"
        self.assertEqual(target.parse_verified_marker(marker, receipt_raw), target.sha256_bytes(receipt_raw))

    def test_output_overflow_is_refused(self) -> None:
        with self.assertRaisesRegex(target.Refused, "proof-output-overflow"):
            target.parse_proof_frame(b"x" * (target.MAX_PROOF_STDOUT_BYTES + 1))
        buffer = bytearray(b"abc")
        with self.assertRaisesRegex(target.Refused, "pipe-overflow"):
            target.bounded_append(buffer, b"def", limit=5, category="pipe-overflow")

    def test_trailing_frame_bytes_are_refused(self) -> None:
        receipt_raw = target.canonical(proof_receipt())
        frame = target.FRAME_MAGIC + struct.pack(">I", len(receipt_raw)) + receipt_raw + b"x"
        with self.assertRaisesRegex(target.Refused, "proof-frame-trailing-or-truncated"):
            target.parse_proof_frame(frame)

    def test_fake_verifier_marker_cannot_publish(self) -> None:
        receipt = proof_receipt()
        receipt_raw = target.canonical(receipt)
        with (
            mock.patch.object(target, "_write_new") as write,
            mock.patch.object(target.Path, "mkdir") as mkdir,
            self.assertRaisesRegex(target.Refused, "verifier-marker"),
        ):
            target.atomic_publish(
                receipt_raw=receipt_raw,
                receipt_value=receipt,
                verifier_stdout=b"FROZEN_W1_VERIFIED_PROOF_RECEIPT_SHA256=" + b"0" * 64 + b"\n",
                assignment_before={"x": 1},
                assignment_after_proof={"x": 1},
                assignment_after={"x": 1},
                proof_runtime={"verified_wait_evidence": True},
                verifier_runtime={"verified_wait_evidence": True},
                bindings=review_bindings(),
                parent_cgroup_entry=parent_entry(),
                stage0_contract={"test_only": True},
            )
        write.assert_not_called()
        mkdir.assert_not_called()

    def test_marker_alone_cannot_publish_without_full_runtime_evidence(self) -> None:
        receipt = proof_receipt()
        receipt_raw = target.canonical(receipt)
        marker = (
            target.VERIFIED_MARKER
            + target.sha256_bytes(receipt_raw).encode()
            + b"\n"
        )
        with (
            mock.patch.object(target, "_write_new") as write,
            mock.patch.object(target.Path, "mkdir") as mkdir,
            self.assertRaisesRegex(target.Refused, "publication-runtime-role"),
        ):
            target.atomic_publish(
                receipt_raw=receipt_raw,
                receipt_value=receipt,
                verifier_stdout=marker,
                assignment_before={"x": 1},
                assignment_after_proof={"x": 1},
                assignment_after={"x": 1},
                proof_runtime={"verified_wait_evidence": True},
                verifier_runtime={"verified_wait_evidence": True},
                bindings=review_bindings(),
                parent_cgroup_entry=parent_entry(),
                stage0_contract={"test_only": True},
            )
        write.assert_not_called()
        mkdir.assert_not_called()

    def test_manifest_tampering_invalidates_commit_marker(self) -> None:
        staged, commit = self.staged_publication()
        self.assertIs(target.validate_publication_commit(commit, staged), commit)
        staged["EVIDENCE-MANIFEST.json"] += b"tampered"
        with self.assertRaisesRegex(target.Refused, "commit-marker-bindings"):
            target.validate_publication_commit(commit, staged)

    def test_missing_or_extra_final_entries_are_refused(self) -> None:
        staged, _commit = self.staged_publication()
        for listed in ([], [*staged, "EXTRA"]):
            with (
                self.subTest(listed=listed),
                mock.patch.object(target.os, "listdir", return_value=listed),
                self.assertRaisesRegex(target.Refused, "publish-final-entry-set"),
            ):
                target._reopen_exact_publication(Path("/synthetic"), staged)

    def test_post_rename_byte_substitution_is_refused(self) -> None:
        expected = {"EVIDENCE-MANIFEST.json": b"expected\n"}
        stat_value = mock.Mock(
            st_mode=0o100400,
            st_nlink=1,
            st_dev=1,
            st_ino=2,
            st_uid=os.getuid(),
            st_gid=os.getgid(),
            st_size=len(b"tampered\n"),
            st_mtime_ns=3,
            st_ctime_ns=4,
        )
        with (
            mock.patch.object(target.os, "listdir", return_value=list(expected)),
            mock.patch.object(target.os, "open", return_value=70),
            mock.patch.object(target.os, "fstat", return_value=stat_value),
            mock.patch.object(target, "_read_small_fd", return_value=b"tampered\n"),
            mock.patch.object(target.os, "close"),
            self.assertRaisesRegex(target.Refused, "publish-final-byte-substitution"),
        ):
            target._reopen_exact_publication(Path("/synthetic"), expected)

    def test_fsync_failure_cannot_be_reported_as_committed(self) -> None:
        with (
            mock.patch.object(target.os, "open", return_value=70),
            mock.patch.object(target.os, "fsync", side_effect=OSError(5, "synthetic")),
            mock.patch.object(target.os, "close") as close,
            self.assertRaises(OSError),
        ):
            target._fsync_directory(Path("/synthetic"))
        close.assert_called_once_with(70)

    def test_assignment_reopen_drift_blocks_publication(self) -> None:
        with self.assertRaisesRegex(target.Refused, "assignment-pre-post-drift"):
            target.validate_assignment_reopen({"sha256": "1" * 64}, {"sha256": "2" * 64})

    def test_assignment_launch_and_actual_receipt_are_reopened_pre_post(self) -> None:
        binding = assignment_binding()
        launch = {
            "schema": "kpb-frozen-w1-assignment-launch-receipt/v2",
            "assignment_receipt": binding["assignment_receipt"],
            "assignment_public_inputs_decimal": list(target.EXPECTED_PUBLIC_INPUTS),
            "assignment_serialized": False,
            "network_communication": False,
            "funds": False,
            "setup": False,
            "proving_key_opened": False,
            "aggregate_proof_generated": False,
        }
        assignment = {
            "schema": "kpb-frozen-w1-round1-assignment-preparation/v3",
            "derived_public_inputs_decimal": list(target.EXPECTED_PUBLIC_INPUTS),
            "assignment_serialized": False,
            "setup_network_or_funds": False,
            "proving_key_opened": False,
            "aggregate_proof_generated": False,
            "receipt_is_authority": False,
            "public_or_production_authority": False,
        }
        reads = [
            (target.canonical(launch), binding["launch_receipt"]),
            (target.canonical(assignment), binding["assignment_receipt"]),
        ] * 2
        with mock.patch.object(target, "stable_read", side_effect=reads) as stable:
            before = target.authenticate_assignment_pair(binding)
            after = target.authenticate_assignment_pair(binding)
        self.assertEqual(stable.call_count, 4)
        target.validate_assignment_reopen(before, after)


class NoExecutionRegressionTests(unittest.TestCase):
    def test_suite_does_not_expose_execution_apis(self) -> None:
        # The test module never invokes these; this guard catches accidental
        # future tests that try to turn hostile controls into an execution run.
        source = Path(__file__).read_text(encoding="utf-8")
        for forbidden in (
            "subprocess." + "run(",
            "subprocess." + "Popen(",
            "system" + "ctl",
            "systemd" + "-run",
            "cgroup" + ".procs",
            "cgroup" + ".kill",
            "prove_frozen_w1" + "_round1(",
            "verify_frozen_w1" + "_round1_receipt(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
