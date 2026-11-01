#!/usr/bin/env python3
"""Hostile controls for the inert fixed W1 proof supervisor."""

from __future__ import annotations

import ast
import contextlib
import base64
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import run_frozen_w1_proof as target


def identified(value: dict) -> dict:
    result = dict(value)
    result["receipt_identity_sha256"] = target.sha256_bytes(target.canonical(value))
    return result


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
        "r1cs_bytes": target.FIXED_ARTIFACTS["r1cs"][1],
        "r1cs_sha256": target.FIXED_ARTIFACTS["r1cs"][2],
        "decoded_pk_bytes": target.FIXED_ARTIFACTS["decoded_pk"][1],
        "decoded_pk_sha256": target.FIXED_ARTIFACTS["decoded_pk"][2],
        "compressed_pk_bytes": target.FIXED_ARTIFACTS["compressed_pk"][1],
        "compressed_pk_sha256": target.FIXED_ARTIFACTS["compressed_pk"][2],
        "decode_receipt_bytes": target.FIXED_ARTIFACTS["decode_receipt"][1],
        "decode_receipt_sha256": target.FIXED_ARTIFACTS["decode_receipt"][2],
        "vk_bytes": target.FIXED_ARTIFACTS["independent_vk"][1],
        "vk_sha256": target.FIXED_ARTIFACTS["independent_vk"][2],
    }
    for key in (
        "historical_sources_rehashed", "r1cs_satisfaction_checked",
        "proof_parameter_descriptors_opened_after_satisfaction",
        "historical_source_vk_opened_during_assignment_preparation",
        "decoded_pk_rehashed_before_deserialization",
        "internal_osrng_nonzero_blinding", "proof_generated", "independent_vk_rehashed",
        "independent_verification", "wrong_public_inputs_rejected", "mutated_proof_rejected",
    ):
        value[key] = True
    for key in (
        "assignment_serialized", "secret_fingerprint_emitted", "setup_executed",
        "network_communication", "funds", "testnet", "full_secret_zeroization",
        "error_path_source_zeroization_complete", "abort_oom_zeroization",
        "receipt_is_authority", "public_or_production_authority",
    ):
        value[key] = False
    return value


def assignment_launch() -> dict:
    binary = {
        "bytes": 3_756_792,
        "ctime_ns": 10,
        "device": 64_512,
        "inode": 118_112_418,
        "link_count": 1,
        "mode_octal": "0500",
        "mtime_ns": 9,
        "owner_uid": os.getuid(),
        "path": "/synthetic/assignment-candidate",
        "sha256": "1" * 64,
    }
    assignment_receipt = {
        "bytes": 2_594,
        "ctime_ns": 12,
        "device": 64_512,
        "inode": 118_112_429,
        "link_count": 1,
        "mode_octal": "0400",
        "mtime_ns": 11,
        "owner_uid": os.getuid(),
        "path": str(target.ASSIGNMENT_RUN_ROOT / "ASSIGNMENT-RECEIPT.json"),
        "sha256": "2" * 64,
    }
    helper = {
        "interpreter": "/usr/bin/python3",
        "source_bytes": 4_613,
        "source_sha256": "3" * 64,
        "exec_primitive": "sealed-memfd-os.execve-by-file-descriptor",
        "memfd_seals": [
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        ],
        "sealed_memfd_rehashed_before_exec": True,
        "binary_path": binary["path"],
        "binary_device": binary["device"],
        "binary_inode": binary["inode"],
        "binary_bytes": binary["bytes"],
        "binary_sha256": binary["sha256"],
        "binary_mode_octal": "0500",
        "binary_link_count": 1,
        "binary_owner_uid": binary["owner_uid"],
        "binary_argv": [binary["path"], assignment_receipt["path"]],
        "exact_environment": list(target.FIXED_ENVIRONMENT),
        "stdout_and_stderr_inherited_null": True,
    }
    properties = {
        "denied_network_syscalls": sorted(target.STRICT_DENIED_NETWORK_SYSCALLS),
        "limit_core_bytes": 0,
        "memory_swap_max_bytes": 0,
        "memory_swap_peak_bytes": 0,
        "no_new_privileges": True,
        "restart_count": 0,
        "standard_input": "null",
        "standard_output": "null",
        "standard_error": "null",
    }
    return identified({
        "schema": "kpb-frozen-w1-assignment-launch-receipt/v2",
        "classification": "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_ASSIGNMENT_PREPARATION_ONLY_NOT_AUTHORITY",
        "fixed_no_argument_entrypoint": True,
        "build_bundle": {"synthetic": True},
        "binary": binary,
        "strict_network_preflight": {
            "identity_bound_exec_helper": None,
            "result": "success",
            "exec_main_status": 0,
            "unit_stopped_after_capture": True,
            "af_inet_af_inet6_af_unix_socket_denied_with_eperm": True,
            "exact_fixed_environment_observed": True,
            "network_communication_performed": False,
        },
        "assignment_runtime": {
            "identity_bound_exec_helper": helper,
            "result": "success",
            "exec_main_status": 0,
            "unit_stopped_after_capture": True,
            "properties": properties,
        },
        "assignment_receipt": assignment_receipt,
        "assignment_receipt_validation": {
            "all_required_false_flags_validated": True,
            "all_required_true_flags_validated": True,
            "current_preparer_constraint_rows_recorded": False,
            "current_preparer_constraint_satisfaction_checked": False,
            "current_preparer_observed_constraints": 0,
            "exact_key_set_sha256": target.EXPECTED_ASSIGNMENT_RECEIPT_KEYS_SHA256,
            "exact_schema": "kpb-frozen-w1-round1-assignment-preparation/v3",
            "historical_component_expected_constraints": 13_093_029,
            "output_proofs_verified": 12,
            "prepared_instances": 3,
            "prepared_variables": 12_949_821,
            "prepared_witnesses": 12_949_818,
            "rounds_validated": 2,
            "selected_round": 1,
            "signature_relations_satisfied": 6,
            "unexpected_or_fingerprint_fields_absent": True,
        },
        "assignment_public_inputs_decimal": list(target.EXPECTED_PUBLIC_INPUTS),
        "assignment_public_inputs_derivation": {
            "round1_effects_core_sha256": target.EXPECTED_ROUND1_EFFECTS_CORE_SHA256,
            "split": "two-16-byte-little-endian-unsigned-integers",
            "independently_derived": list(target.EXPECTED_PUBLIC_INPUTS),
        },
        "assignment_peak_rss_kib": 2_000_000,
        "assignment_current_swap_kib": 0,
        "identity_bound_exec_helper": helper,
        "manager_environment": {
            "all_manager_entries_removed_or_replaced": True,
            "all_observed_systemd_injected_entries_removed": True,
            "entry_count": 14,
            "environment_sha256": "4" * 64,
            "fixed_runtime_environment": list(target.FIXED_ENVIRONMENT),
        },
        "supervisor_source": {"synthetic": True},
        "full_secret_zeroization": False,
        "error_path_source_zeroization_complete": False,
        "abort_oom_zeroization": False,
        "assignment_serialized": False,
        "proving_key_opened": False,
        "aggregate_proof_generated": False,
        "network_communication": False,
        "setup": False,
        "funds": False,
        "privacy_acceptance": False,
        "financial_acceptance": False,
        "production_authority": False,
        "authorization": False,
        "actions": dict(target.ASSIGNMENT_ACTIONS),
    })


def systemd_values(*, final: bool = True) -> dict[str, str]:
    return {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "exited" if final else "running",
        "Result": "success",
        "ExecMainStatus": "0",
        "InvocationID": "1" * 32,
        "ExecMainPID": "12345",
        "TriggeredBy": "",
        "Triggers": "",
        "RestrictAddressFamilies": "AF_UNIX",
        "SystemCallFilter": "~" + " ".join(sorted(target.STRICT_DENIED_NETWORK_SYSCALLS)),
        "SystemCallErrorNumber": "1",
        "SystemCallArchitectures": "native",
        "NoNewPrivileges": "yes",
        "LimitCORE": "0",
        "MemoryMax": str(target.MEMORY_MAX_BYTES),
        "MemorySwapMax": "0",
        "MemoryPeak": str(8 * 1024**3),
        "MemorySwapCurrent": "0",
        "MemorySwapPeak": "0",
        "OOMPolicy": "stop",
        "RuntimeMaxUSec": "infinity",
        "TimeoutStopUSec": "30s",
        "KillMode": "control-group",
        "NRestarts": "0",
        "UMask": "0077",
        "UnsetEnvironment": " ".join(target.BOOTSTRAP_UNSET_ENVIRONMENT),
        "StandardInput": "null",
        "StandardOutput": "null",
        "StandardError": "null",
    }


def write(path: Path, raw: bytes, mode: int) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return {"bytes": len(raw), "sha256": target.sha256_bytes(raw), "mode_octal": f"{mode:04o}"}


def journal_export(*records: dict[str, bytes | str]) -> bytes:
    output = bytearray()
    for record in records:
        for key, value in record.items():
            raw = value.encode() if isinstance(value, str) else value
            encoded_key = key.encode()
            if b"\n" not in raw and all(32 <= byte < 127 for byte in raw):
                output.extend(encoded_key + b"=" + raw + b"\n")
            else:
                output.extend(encoded_key + b"\n")
                output.extend(len(raw).to_bytes(8, "little"))
                output.extend(raw + b"\n")
        output.extend(b"\n")
    return bytes(output)


class FixedSurfaceControls(unittest.TestCase):
    def test_cli_is_no_argument_and_tests_never_execute_proof(self):
        with mock.patch.object(target, "run_proof") as run:
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(target.main(["--help"]), 2)
            self.assertIn("arguments-not-accepted", stderr.getvalue())
            run.assert_not_called()

        result = {"status": "synthetic", "authorization": False}
        with mock.patch.object(target, "run_proof", return_value=result) as run:
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(target.main([]), 0)
            self.assertEqual(json.loads(stdout.getvalue()), result)
            run.assert_called_once_with()

    def test_all_artifact_constants_are_initially_unbound(self):
        constants = (
            target.EXPECTED_BUILD_FREEZER_SOURCE_SHA256,
            target.EXPECTED_BUILD_CORE_SOURCE_SHA256,
            target.EXPECTED_MANIFEST_SHA256,
            target.EXPECTED_INNER_RECEIPT_SHA256,
            target.EXPECTED_DEP_INFO_SHA256,
            target.EXPECTED_BINARY_SHA256,
            target.EXPECTED_BINARY_BYTES,
            target.EXPECTED_OUTER_RECEIPT_SHA256,
            target.EXPECTED_ASSIGNMENT_LAUNCH_RECEIPT_SHA256,
            target.EXPECTED_VERIFIER_BINARY_SHA256,
            target.EXPECTED_VERIFIER_BINARY_BYTES,
            target.EXPECTED_VERIFIER_DEP_INFO_SHA256,
            target.EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256,
            target.EXPECTED_VERIFIER_DEPENDENCY_RELATIVES,
        )
        self.assertEqual(len(constants), 14)
        self.assertTrue(all(value is None for value in constants))
        with self.assertRaisesRegex(target.Refused, "artifact-constants-unbound"):
            target._require_bound_constants()

    def test_direct_launch_refuses_without_external_sealed_stage0(self):
        with self.assertRaisesRegex(target.Refused, "stage0-entry-contract"):
            target._stage0_contract_reference()
        with self.assertRaisesRegex(target.Refused, "stage0-render-entry-contract"):
            target._run_stage0_renderer(["--stage0-render"])

    def test_stage0_command_is_inline_exact_environment_and_compilable(self):
        reference = {
            "path": str(target.SUPERVISOR_WORKSPACE_SOURCE),
            "device": 7,
            "inode": 11,
            "bytes": 123,
            "sha256": "a" * 64,
            "mode_octal": "0400",
            "link_count": 1,
            "owner_uid": os.getuid(),
            "mtime_ns": 17,
            "ctime_ns": 19,
        }
        bootstrap_command = target._stage0_bootstrap_command(reference)
        bootstrap = bootstrap_command[-2]
        compile(bootstrap, "<reviewed-external-stage0-bootstrap>", "exec")
        self.assertEqual(
            bootstrap_command[-1], target.sha256_bytes(bootstrap.encode())
        )
        self.assertNotIn("import run_frozen_w1_proof", bootstrap)
        for required in (
            "os.O_NOFOLLOW", "os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC",
            "os.set_inheritable(SOURCE_FD, True)",
            "os.set_inheritable(BOOTSTRAP_CONTRACT_FD, True)",
            target.STAGE0_BOOTSTRAP_CONTRACT_SCHEMA,
            'os.stat("/proc/self/exe")',
            '"--stage0-render"',
        ):
            self.assertIn(required, bootstrap)
        bootstrap_sha256 = target.sha256_bytes(bootstrap.encode())
        bootstrap_argv_sha256 = target.sha256_bytes(
            target.canonical(bootstrap_command)
        )
        command = target._stage0_command(
            reference, bootstrap_sha256, bootstrap_argv_sha256
        )
        helper = command[-4]
        compile(helper, "<reviewed-inline-stage0>", "exec")
        tree = ast.parse(helper)
        canonical_function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "canonical"
        )
        canonical_scope: dict[str, object] = {}
        exec(
            compile(
                ast.fix_missing_locations(
                    ast.Module(
                        body=[ast.Import(names=[ast.alias(name="json")]), canonical_function],
                        type_ignores=[],
                    )
                ),
                "<stage0-canonical-only>",
                "exec",
            ),
            canonical_scope,
        )
        self.assertEqual(
            canonical_scope["canonical"]({"b": 2, "a": 1}),
            target.canonical({"b": 2, "a": 1}),
        )
        self.assertEqual(command[-3], target.sha256_bytes(helper.encode()))
        self.assertEqual(command[-2], bootstrap_sha256)
        self.assertEqual(command[-1], bootstrap_argv_sha256)
        self.assertEqual(command[:5], [
            str(target.SYSTEMD_RUN), "--user", "--quiet", "--no-block",
            f"--unit={target.STAGE0_UNIT}",
        ])
        env_index = command.index(str(target.ENV))
        self.assertEqual(command[env_index + 1], "-i")
        self.assertEqual(
            command[env_index + 2:env_index + 2 + len(target.FIXED_ENVIRONMENT)],
            list(target.FIXED_ENVIRONMENT),
        )
        self.assertEqual(
            command[env_index + 2 + len(target.FIXED_ENVIRONMENT):][:4],
            [str(target.PYTHON), "-I", "-c", helper],
        )
        for required in (
            "os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC",
            "os.set_inheritable(SOURCE_FD, True)",
            "os.set_inheritable(CONTRACT_FD, True)",
            "[PYTHON, \"-I\", f\"/proc/self/fd/{SOURCE_FD}\"]",
            "no_historical_foreign_invocation_observed",
            "local_af_unix_system_manager_and_journal_ipc_performed",
            "ip_address_family_socket_creation_denied",
            "standard_fds_all_dev_null",
            'values["SystemCallArchitectures"] == "native"',
            "io_uring_setup",
        ):
            self.assertIn(required, helper)
        self.assertIn(
            "SystemCallFilter=~io_uring_enter io_uring_register io_uring_setup "
            "pidfd_getfd process_vm_readv process_vm_writev ptrace",
            command,
        )
        self.assertNotIn(
            "SystemCallFilter=~@network-io io_uring_enter io_uring_register "
            "io_uring_setup pidfd_getfd process_vm_readv process_vm_writev ptrace",
            command,
        )
        self.assertIn("StandardOutput=null", command)
        self.assertIn("StandardError=null", command)

    def test_runtime_command_is_direct_strict_and_fixed(self):
        binary = {
            "path": str(target.BUILD_BINARY),
            "device": 7,
            "inode": 11,
            "bytes": 13,
            "sha256": "a" * 64,
            "owner_uid": os.getuid(),
            "mode_octal": "0500",
            "link_count": 1,
        }
        command = target._run_command(binary)
        helper = command[-1]
        self.assertNotIn("/bin/sh", command)
        self.assertNotIn("bash", command)
        for required in (
            (
                "SystemCallFilter=~@network-io io_uring_enter "
                "io_uring_register io_uring_setup pidfd_getfd "
                "process_vm_readv process_vm_writev ptrace"
            ),
            "SystemCallErrorNumber=EPERM",
            "MemoryMax=20G", "MemorySwapMax=0", "LimitCORE=0",
            "StandardOutput=journal", "StandardError=null",
        ):
            self.assertIn(required, command)
        self.assertFalse(any(value.startswith("RuntimeMaxSec=") for value in command))
        self.assertFalse(any(value == "--setenv" for value in command))
        for required in ("--no-block", "--remain-after-exit", "--service-type=exec"):
            self.assertIn(required, command)
        env_index = command.index(str(target.ENV))
        self.assertEqual(command[env_index + 1], "-i")
        self.assertEqual(
            command[env_index + 2:env_index + 2 + len(target.FIXED_ENVIRONMENT)],
            list(target.FIXED_ENVIRONMENT),
        )
        self.assertEqual(
            command[env_index + 2 + len(target.FIXED_ENVIRONMENT):][:3],
            [str(target.PYTHON), "-I", "-c"],
        )
        self.assertEqual(command[-1], helper)
        self.assertNotIn(str(target.BUILD_BINARY), command[:-1])
        self.assertIn("os.memfd_create(", helper)
        self.assertIn("os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC", helper)
        self.assertIn(
            "os.execve(sealed_descriptor, [BINARY, *ARGUMENTS], ENVIRONMENT)",
            helper,
        )
        for seal in (
            "fcntl.F_SEAL_WRITE",
            "fcntl.F_SEAL_GROW",
            "fcntl.F_SEAL_SHRINK",
            "fcntl.F_SEAL_SEAL",
        ):
            self.assertIn(seal, helper)

    def test_exec_launcher_seals_rehashes_and_rebuilds_exact_environment(self):
        binary = {
            "path": str(target.BUILD_BINARY),
            "device": 7,
            "inode": 11,
            "bytes": 13,
            "sha256": "a" * 64,
            "owner_uid": os.getuid(),
            "mode_octal": "0500",
            "link_count": 1,
        }
        source = target._run_command(binary)[-1]
        for required in (
            "os.O_NOFOLLOW", "os.fstat(source_descriptor)", "os.pread", "digest.hexdigest()",
            "before_path.st_dev != expected_device", "before_path.st_ino != expected_inode",
            "os.memfd_create", "fcntl.F_ADD_SEALS", "sealed_digest.hexdigest()",
            "open_descriptors() != [0, 1, 2]",
            "open_descriptors() != [0, 1, 2, sealed_descriptor]",
            "os.execve(sealed_descriptor", "ENVIRONMENT",
        ):
            self.assertIn(required.replace("expected_device", "EXPECTED_DEVICE").replace("expected_inode", "EXPECTED_INODE"), source)
        for value in target.FIXED_ENVIRONMENT:
            key, expected = value.split("=", 1)
            self.assertIn(repr(key), source)
            self.assertIn(repr(expected), source)
        for leaked in ("DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "NODE_OPTIONS"):
            self.assertNotIn(leaked, source)

    def test_parent_verifier_gets_exact_receipt_stdin_and_sealed_executable(self):
        binary = {
            "path": str(target.BUILD_VERIFIER_BINARY),
            "device": 7,
            "inode": 12,
            "bytes": 17,
            "sha256": "b" * 64,
            "owner_uid": os.getuid(),
            "mode_octal": "0500",
            "link_count": 1,
        }
        raw = target.canonical(proof_receipt())
        command = target._verifier_command(binary, raw)
        encoded = next(
            value.removeprefix("StandardInputData=")
            for value in command
            if value.startswith("StandardInputData=")
        )
        self.assertEqual(base64.b64decode(encoded, validate=True), raw)
        self.assertIn("StandardInput=data", command)
        self.assertIn("StandardOutput=journal", command)
        self.assertIn("StandardError=null", command)
        helper = command[-1]
        self.assertIn("ARGUMENTS = ()", helper)
        self.assertIn("os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC", helper)
        self.assertIn("os.execve(sealed_descriptor, [BINARY, *ARGUMENTS]", helper)

        value = proof_receipt()
        raw = target.canonical(value)
        receipt_sha = target.sha256_bytes(raw)
        proof_reference = {"sha256": receipt_sha}
        vk_reference = {
            "path": str(target.VK_PATH),
            "bytes": 328,
            "sha256": target.FIXED_ARTIFACTS["independent_vk"][2],
        }
        runtime = {"journal_commitment": {"receipt_sha256": receipt_sha}}
        with mock.patch.object(target, "_run_transient", return_value=runtime) as run:
            evidence = target._parent_cryptographic_verification(
                raw,
                proof_reference,
                value,
                binary,
                vk_reference,
            )
        attested = evidence[
            "cryptographic_results_attested_by_exact_verifier_success_marker"
        ]
        self.assertTrue(attested["valid_proof_accepted"])
        self.assertTrue(attested["wrong_public_inputs_rejected"])
        self.assertTrue(attested["mutated_proof_rejected"])
        self.assertEqual(
            evidence["supervisor_preflight_vk_reference"],
            vk_reference,
        )
        self.assertEqual(run.call_args.kwargs["standard_input_data"], raw)
        self.assertEqual(run.call_args.kwargs["expected_journal_digest"], receipt_sha)
        with self.assertRaises(target.Refused):
            target._parent_cryptographic_verification(
                raw,
                {"sha256": "0" * 64},
                value,
                binary,
                vk_reference,
            )

    def test_wrong_or_incomplete_binary_launch_reference_refuses(self):
        honest = {
            "path": str(target.BUILD_BINARY), "device": 1, "inode": 2,
            "bytes": 3, "sha256": "a" * 64,
            "owner_uid": os.getuid(), "mode_octal": "0500", "link_count": 1,
        }
        for key in honest:
            changed = dict(honest)
            changed.pop(key)
            with self.subTest(key=key), self.assertRaises(target.Refused):
                target._run_command(changed)

    def test_env_and_python_launchers_are_exact_root_owned_identities(self):
        references = target._fixed_tool_references()
        self.assertEqual(
            set(references),
            {"env", "python", "journalctl", "systemd-run", "systemctl"},
        )
        for name, reference in references.items():
            self.assertEqual(reference["owner_uid"], 0)
            self.assertEqual(reference["sha256"], target.TOOL_IDENTITIES[name][2])
        path, size, _, links = target.TOOL_IDENTITIES["python"]
        with self.assertRaises(target.Refused):
            target._stable_root_tool(path, size, "0" * 64, links)

    def test_probe_requires_all_three_socket_families_to_fail_eperm(self):
        self.assertIn("dict(os.environ) != expected_environment", target.NETWORK_PROBE_SOURCE)
        for family in ("socket.AF_INET", "socket.AF_INET6", "socket.AF_UNIX"):
            self.assertIn(family, target.NETWORK_PROBE_SOURCE)
        self.assertIn("errno.EPERM", target.NETWORK_PROBE_SOURCE)
        self.assertIn("sorted(live_descriptors) != [0, 1, 2]", target.NETWORK_PROBE_SOURCE)
        self.assertIn('!= "/dev/null"', target.NETWORK_PROBE_SOURCE)
        for syscall_number in (425, 426, 427):
            self.assertIn(str(syscall_number), target.NETWORK_PROBE_SOURCE)
        for syscall_name in (
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
        ):
            self.assertIn(syscall_name, target.STRICT_DENIED_NETWORK_SYSCALLS)
        for forbidden in ("connect(", "bind(", "listen(", "send(", "recv("):
            self.assertNotIn(forbidden, target.NETWORK_PROBE_SOURCE)


class ReceiptControls(unittest.TestCase):
    def test_exact_proof_receipt_is_admitted(self):
        target.validate_proof_receipt(proof_receipt())

    def test_every_required_boolean_is_enforced(self):
        original = proof_receipt()
        for key, current in original.items():
            if type(current) is bool:
                changed = proof_receipt()
                changed[key] = not current
                with self.subTest(key=key), self.assertRaises(target.Refused):
                    target.validate_proof_receipt(changed)

    def test_proof_public_inputs_artifacts_and_encoding_are_exact(self):
        mutations = (
            ("public_inputs_decimal", ["0", target.EXPECTED_PUBLIC_INPUTS[1]]),
            ("public_inputs_decimal", list(target.EXPECTED_PUBLIC_INPUTS) + ["0"]),
            ("public_inputs_decimal", [int(target.EXPECTED_PUBLIC_INPUTS[0]), target.EXPECTED_PUBLIC_INPUTS[1]]),
            ("public_inputs_decimal", tuple(target.EXPECTED_PUBLIC_INPUTS)),
            ("proof_bytes", 127),
            ("proof_sha256", "0" * 64),
            ("proof_ark_compressed_hex", "00" * 127),
            ("r1cs_sha256", "0" * 64),
            ("decoded_pk_bytes", 1),
            ("vk_sha256", "0" * 64),
        )
        for key, changed_value in mutations:
            value = proof_receipt()
            value[key] = changed_value
            with self.subTest(key=key), self.assertRaises(target.Refused):
                target.validate_proof_receipt(value)

    def test_extra_secret_fingerprint_and_missing_field_refuse(self):
        extras = []
        for key, value in (
            ("assignment_sha256", "0" * 64),
            ("elapsed_seconds", 3.5),
            ("peak_rss_kib", 1234),
            ("current_swap_kib", 0),
        ):
            extra = proof_receipt()
            extra[key] = value
            extras.append(extra)
        missing = proof_receipt()
        missing.pop("proof_sha256")
        for value in (*extras, missing):
            with self.assertRaises(target.Refused):
                target.validate_proof_receipt(value)

    def test_assignment_launch_gate_enforces_identity_and_no_proof_claim(self):
        target.validate_assignment_launch(assignment_launch())
        original = assignment_launch()
        for key, current in original.items():
            if type(current) is bool:
                changed = assignment_launch()
                changed.pop("receipt_identity_sha256")
                changed[key] = not current
                with self.subTest(key=key), self.assertRaises(target.Refused):
                    target.validate_assignment_launch(identified(changed))
        changed = assignment_launch()
        changed["receipt_identity_sha256"] = "0" * 64
        with self.assertRaises(target.Refused):
            target.validate_assignment_launch(changed)

    def test_assignment_launch_exact_keys_actions_and_resources_are_enforced(self):
        cases = []
        extra = assignment_launch()
        extra.pop("receipt_identity_sha256")
        extra["secret_fingerprint"] = "0" * 64
        cases.append(identified(extra))
        missing = assignment_launch()
        missing.pop("receipt_identity_sha256")
        missing.pop("assignment_receipt")
        cases.append(identified(missing))
        action = assignment_launch()
        action.pop("receipt_identity_sha256")
        action["actions"] = dict(action["actions"])
        action["actions"]["aggregate_proof_verification"] = True
        cases.append(identified(action))
        rss = assignment_launch()
        rss.pop("receipt_identity_sha256")
        rss["assignment_peak_rss_kib"] = 0
        cases.append(identified(rss))
        swap = assignment_launch()
        swap.pop("receipt_identity_sha256")
        swap["assignment_current_swap_kib"] = 1
        cases.append(identified(swap))
        old_schema = assignment_launch()
        old_schema.pop("receipt_identity_sha256")
        old_schema["schema"] = "kpb-frozen-w1-assignment-launch-receipt/v1"
        cases.append(identified(old_schema))
        satisfied = assignment_launch()
        satisfied.pop("receipt_identity_sha256")
        satisfied["assignment_receipt_validation"] = dict(
            satisfied["assignment_receipt_validation"]
        )
        satisfied["assignment_receipt_validation"][
            "current_preparer_constraint_satisfaction_checked"
        ] = True
        cases.append(identified(satisfied))
        unsealed = assignment_launch()
        unsealed.pop("receipt_identity_sha256")
        unsealed["identity_bound_exec_helper"] = dict(
            unsealed["identity_bound_exec_helper"]
        )
        unsealed["assignment_runtime"] = dict(unsealed["assignment_runtime"])
        unsealed["assignment_runtime"]["identity_bound_exec_helper"] = dict(
            unsealed["assignment_runtime"]["identity_bound_exec_helper"]
        )
        unsealed["identity_bound_exec_helper"][
            "sealed_memfd_rehashed_before_exec"
        ] = False
        unsealed["assignment_runtime"]["identity_bound_exec_helper"][
            "sealed_memfd_rehashed_before_exec"
        ] = False
        cases.append(identified(unsealed))
        old_receipt = assignment_launch()
        old_receipt.pop("receipt_identity_sha256")
        old_receipt["assignment_receipt"] = dict(old_receipt["assignment_receipt"])
        old_receipt["assignment_receipt"]["path"] = str(
            target.LOCAL_ROOT
            / "private-batch-w1-assignment-run-private-20261029-01"
            / "ASSIGNMENT-RECEIPT.json"
        )
        cases.append(identified(old_receipt))
        for value in cases:
            with self.assertRaises(target.Refused):
                target.validate_assignment_launch(value)


class SystemdControls(unittest.TestCase):
    @staticmethod
    def completed(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    def test_exact_final_properties_and_timespans_are_admitted(self):
        evidence = target._validate_systemd_properties(systemd_values(), final=True)
        self.assertEqual(evidence["memory_max_bytes"], target.MEMORY_MAX_BYTES)
        self.assertEqual(evidence["memory_swap_peak_bytes"], 0)
        self.assertFalse(evidence["automatic_runtime_timeout"])
        self.assertEqual(evidence["standard_output"], "null")
        self.assertEqual(evidence["standard_error"], "null")
        self.assertTrue(evidence["bootstrap_loader_environment_unset"])
        self.assertEqual(target._timespan_usec("30s"), 30_000_000)

    def test_stage0_allows_only_local_manager_ipc_and_denies_io_uring(self):
        values = systemd_values(final=False)
        values["SystemCallFilter"] = "~" + " ".join(
            sorted(target.STAGE0_DENIED_SYSCALLS)
        )
        evidence = target._validate_systemd_properties(
            values,
            final=False,
            expected_denied_syscalls=target.STAGE0_DENIED_SYSCALLS,
            denied_evidence_key="denied_stage0_syscalls",
        )
        self.assertEqual(
            evidence["denied_stage0_syscalls"],
            sorted(target.STAGE0_DENIED_SYSCALLS),
        )
        self.assertNotIn("socket", evidence["denied_stage0_syscalls"])
        self.assertEqual(values["RestrictAddressFamilies"], "AF_UNIX")

    def test_yama_boundary_is_exact_and_weaker_value_refuses(self):
        evidence = target._yama_ptrace_scope_reference()
        self.assertEqual(evidence["value"], 1)
        self.assertTrue(evidence["same_uid_non_ancestor_ptrace_denied"])
        self.assertTrue(evidence["trusted_direct_ancestor_and_root_boundary_remains"])
        with mock.patch.object(
            target.os,
            "read",
            side_effect=[b"0\n", b""],
        ), self.assertRaisesRegex(target.Refused, "yama-ptrace-scope-value"):
            target._yama_ptrace_scope_reference()

    def test_service_and_socket_names_must_be_pristine_before_start(self):
        show = b"LoadState=not-found\nTriggeredBy=\nTriggers=\n"
        passing = [
            self.completed(),
            self.completed(show), self.completed(),
            self.completed(show), self.completed(),
        ]
        with mock.patch.object(target.subprocess, "run", side_effect=passing):
            evidence = target._pristine_unit_observation(target.PROBE_UNIT)
        self.assertTrue(evidence["service_and_socket_unit_names_pristine"])
        hostile = [
            self.completed(),
            self.completed(show), self.completed(b"historical-record"),
            self.completed(show), self.completed(),
        ]
        with mock.patch.object(
            target.subprocess, "run", side_effect=hostile
        ), self.assertRaisesRegex(
            target.Refused, "pristine-unit-historical-journal"
        ):
            target._pristine_unit_observation(target.PROBE_UNIT)

    def test_each_boundary_weakening_or_bad_result_refuses(self):
        mutations = {
            "network": ("SystemCallFilter", "~socket"),
            "families": ("RestrictAddressFamilies", "~"),
            "errno": ("SystemCallErrorNumber", "13"),
            "alternate-abi": ("SystemCallArchitectures", ""),
            "socket-activation": ("TriggeredBy", "kpb-hostile.socket"),
            "privileges": ("NoNewPrivileges", "no"),
            "core": ("LimitCORE", "infinity"),
            "memory": ("MemoryMax", "infinity"),
            "swap": ("MemorySwapMax", "infinity"),
            "oom": ("OOMPolicy", "continue"),
            "runtime": ("RuntimeMaxUSec", "6h"),
            "stop": ("TimeoutStopUSec", "1s"),
            "kill": ("KillMode", "process"),
            "restart": ("NRestarts", "1"),
            "result": ("Result", "timeout"),
            "exit": ("ExecMainStatus", "1"),
            "swap-peak": ("MemorySwapPeak", "4096"),
            "loader-env": ("UnsetEnvironment", ""),
            "stdin": ("StandardInput", "tty"),
            "stdout": ("StandardOutput", "journal"),
            "stderr": ("StandardError", "journal"),
        }
        for name, (key, changed) in mutations.items():
            value = systemd_values()
            value[key] = changed
            with self.subTest(name=name), self.assertRaises(target.Refused):
                target._validate_systemd_properties(value, final=True)

        no_negative_form = systemd_values()
        no_negative_form["SystemCallFilter"] = no_negative_form["SystemCallFilter"][1:]
        with self.assertRaises(target.Refused):
            target._validate_systemd_properties(no_negative_form, final=True)

    def test_show_parser_rejects_missing_duplicate_and_unknown(self):
        values = systemd_values()
        good = "".join(f"{key}={values[key]}\n" for key in target.SHOW_PROPERTIES)
        self.assertEqual(target._parse_show(good.encode()), values)
        for raw in (
            good.replace("LoadState=loaded\n", ""),
            good + "LoadState=loaded\n",
            good + "PrivateNetwork=yes\n",
            "not-a-property\n",
        ):
            with self.assertRaises(target.Refused):
                target._parse_show(raw.encode())

    def test_cleared_probe_command_never_relies_on_manager_environment(self):
        command = target._probe_command()
        env_index = command.index(str(target.ENV))
        self.assertEqual(command[env_index + 1], "-i")
        self.assertNotIn("--setenv", command)
        self.assertIn("StandardOutput=null", command)
        self.assertIn("StandardError=null", command)
        manager = target._manager_tool_environment()
        self.assertEqual(
            set(manager),
            {
                "HOME", "PATH", "LANG", "LC_ALL", "TZ",
                "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
            },
        )
        for unsafe in target.BOOTSTRAP_UNSET_ENVIRONMENT:
            self.assertNotIn(unsafe, manager)


class JournalCommitmentControls(unittest.TestCase):
    unit = target.RUN_UNIT
    invocation = "1" * 32
    pid = 12345
    digest = "a" * 64

    def child(self, **changes) -> dict[str, str]:
        value = {
            "MESSAGE": target.PROOF_RECEIPT_MARKER + self.digest,
            "_PID": str(self.pid),
            "_UID": str(os.getuid()),
            "_SYSTEMD_UNIT": f"user@{os.getuid()}.service",
            "_SYSTEMD_USER_UNIT": f"{self.unit}.service",
            "_SYSTEMD_INVOCATION_ID": self.invocation,
            "_TRANSPORT": "stdout",
            "_STREAM_ID": "2" * 32,
            "PRIORITY": "6",
        }
        value.update(changes)
        return value

    @staticmethod
    def lifecycle() -> dict[str, str]:
        return {
            "MESSAGE": "Started unit containing FROZEN_W1_PROOF_RECEIPT_SHA256=quoted",
            "_PID": "1538",
            "_UID": str(os.getuid()),
            "_SYSTEMD_UNIT": f"user@{os.getuid()}.service",
            "_SYSTEMD_USER_UNIT": "init.scope",
            "_TRANSPORT": "journal",
            "PRIORITY": "6",
        }

    def contract(self) -> dict:
        return {
            "unit": self.unit,
            "invocation_id": self.invocation,
            "exec_main_pid": self.pid,
            "marker": target.PROOF_RECEIPT_MARKER,
            "expected_digest": self.digest,
        }

    def test_exact_trusted_record_and_current_pid_relation_pass(self):
        before = journal_export(self.lifecycle(), self.child())
        after = journal_export(self.lifecycle(), self.child(), self.lifecycle())
        evidence = target._journal_commitment_pair(before, after, **self.contract())
        self.assertEqual(evidence["receipt_sha256"], self.digest)
        self.assertEqual(
            evidence["pid_relation"],
            "journal-_PID-equals-ExecMainPID",
        )
        self.assertTrue(evidence["pid_relation_checked_in_current_runtime_record"])

    def test_missing_extra_duplicate_foreign_and_delayed_records_refuse(self):
        good = self.child()
        cases = [
            journal_export(self.lifecycle()),
            journal_export(good, good),
            journal_export(good, self.child(MESSAGE="unexpected-child-stdout")),
            journal_export(self.child(_PID="999")),
            journal_export(self.child(_SYSTEMD_INVOCATION_ID="3" * 32)),
            journal_export(self.child(_SYSTEMD_USER_UNIT="foreign.service")),
            journal_export(self.child(_UID="0")),
            journal_export(self.child(_TRANSPORT="journal")),
            journal_export(self.child(_LINE_BREAK="eof")),
            journal_export(self.child(MESSAGE=target.PROOF_RECEIPT_MARKER + "A" * 64)),
        ]
        for index, raw in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(target.Refused):
                target._journal_commitment(raw, **self.contract())

        before = journal_export(good)
        delayed = journal_export(good, self.child(MESSAGE=target.PROOF_RECEIPT_MARKER + "b" * 64))
        with self.assertRaises(target.Refused):
            target._journal_commitment_pair(before, delayed, **self.contract())

    def test_benign_pid_rehearsal_is_bound_to_exact_export(self):
        rehearsal_child = self.child(
            _PID=str(target.JOURNAL_PID_REHEARSAL_EXEC_MAIN_PID),
            _SYSTEMD_USER_UNIT=f"{target.JOURNAL_PID_REHEARSAL_UNIT}.service",
            _SYSTEMD_INVOCATION_ID=target.JOURNAL_PID_REHEARSAL_INVOCATION_ID,
        )
        raw = journal_export(self.lifecycle(), rehearsal_child)
        with mock.patch.object(
            target,
            "_journal_export",
            return_value=raw,
        ), mock.patch.multiple(
            target,
            JOURNAL_PID_REHEARSAL_EXPORT_BYTES=len(raw),
            JOURNAL_PID_REHEARSAL_EXPORT_SHA256=target.sha256_bytes(raw),
        ):
            evidence = target._journal_pid_rehearsal_reference()
        self.assertEqual(
            evidence["journal_pid"],
            target.JOURNAL_PID_REHEARSAL_EXEC_MAIN_PID,
        )
        self.assertFalse(evidence["proof_executed"])
        with mock.patch.object(
            target,
            "_journal_export",
            return_value=raw + b"\n",
        ), self.assertRaisesRegex(target.Refused, "journal-pid-rehearsal-export"):
            target._journal_pid_rehearsal_reference()

    def test_export_parser_accepts_binary_fields_and_rejects_malformed(self):
        value = journal_export({"MESSAGE": b"binary\nvalue", "_PID": "1"})
        self.assertEqual(target._parse_journal_export(value)[0][b"MESSAGE"], b"binary\nvalue")
        for raw in (b"MESSAGE=unterminated", b"MESSAGE\n\x05\x00", b"\n"):
            with self.assertRaises(target.Refused):
                target._parse_journal_export(raw)


class ExecutionSequenceControls(unittest.TestCase):
    def _run_with_assignment_sequence(self, sequence, proof_sequence=None):
        binary = {
            "path": str(target.BUILD_BINARY),
            "device": 7,
            "inode": 11,
            "bytes": 13,
            "sha256": "a" * 64,
            "owner_uid": os.getuid(),
            "mode_octal": "0500",
            "link_count": 1,
        }
        verifier = dict(binary, path=str(target.BUILD_VERIFIER_BINARY), inode=12)
        build = {
            "references": {
                "binary": binary,
                "parent_verifier_binary": verifier,
            }
        }
        proof_runtime = {
            "journal_commitment": {"receipt_sha256": "c" * 64},
            "properties": {"memory_peak_bytes": 1024, "memory_swap_peak_bytes": 0}
        }
        probe_runtime = {
            "properties": {"memory_peak_bytes": 64, "memory_swap_peak_bytes": 0}
        }
        proof = proof_receipt()
        proof_raw = target.canonical(proof)
        proof_ref = {"path": str(target.PROOF_RECEIPT), "sha256": "c" * 64}
        if proof_sequence is None:
            proof_sequence = [
                (proof_raw, proof, proof_ref),
                (proof_raw, proof, proof_ref),
                (proof_raw, proof, proof_ref),
            ]
        artifacts = {
            "independent_vk": {
                "path": str(target.VK_PATH),
                "bytes": 328,
                "sha256": target.FIXED_ARTIFACTS["independent_vk"][2],
            }
        }
        parent = {
            "cryptographic_results_attested_by_exact_verifier_success_marker": {
                "valid_proof_accepted": True,
                "wrong_public_inputs_rejected": True,
                "mutated_proof_rejected": True,
            },
        }
        source_ref = {"path": str(Path(target.__file__).resolve()), "sha256": "b" * 64}
        stage0 = {"contract": {"schema": target.STAGE0_CONTRACT_SCHEMA}}
        patches = {
            "REPO_ROOT": Path.cwd().resolve(),
            "_stage0_contract_reference": mock.Mock(
                return_value=(b"source\n", source_ref, stage0)
            ),
            "_recheck_stage0_fds": mock.Mock(),
            "_require_bound_constants": mock.Mock(),
            "_fixed_tool_references": mock.Mock(side_effect=[{"tools": True}, {"tools": True}]),
            "_journal_pid_rehearsal_reference": mock.Mock(
                return_value={"pid_relation": "journal-_PID-equals-ExecMainPID"}
            ),
            "_assignment_launch_reference": mock.Mock(side_effect=sequence),
            "validate_build_bundle": mock.Mock(side_effect=[build, build]),
            "_fixed_artifact_references": mock.Mock(side_effect=[artifacts, artifacts]),
            "_create_run_root": mock.Mock(),
            "_run_transient": mock.Mock(side_effect=[probe_runtime, proof_runtime]),
            "_proof_receipt_reference": mock.Mock(side_effect=proof_sequence),
            "_parent_cryptographic_verification": mock.Mock(return_value=parent),
            "_publish": mock.Mock(return_value={"sealed": True}),
        }
        with mock.patch.object(target.os, "geteuid", return_value=1000), mock.patch.multiple(
            target, **patches
        ):
            result = target.run_proof()
            return result, patches

    def test_assignment_evidence_is_revalidated_after_proof_process(self):
        assignment = {"assignment": "same"}
        result, patches = self._run_with_assignment_sequence([assignment, assignment])
        self.assertEqual(result["status"], "FROZEN_W1_ROUND1_PROOF_VERIFIED")
        self.assertEqual(patches["_assignment_launch_reference"].call_count, 2)
        self.assertEqual(patches["_fixed_tool_references"].call_count, 2)
        self.assertEqual(patches["_proof_receipt_reference"].call_count, 3)
        patches["_parent_cryptographic_verification"].assert_called_once()

    def test_assignment_substitution_after_run_refuses_before_publication(self):
        with self.assertRaisesRegex(target.Refused, "assignment-changed-during-run"):
            self._run_with_assignment_sequence([
                {"assignment": "before"},
                {"assignment": "after"},
            ])

    def test_post_verifier_in_place_or_replaced_receipt_refuses(self):
        assignment = {"assignment": "same"}
        proof = proof_receipt()
        raw = target.canonical(proof)
        before = {
            "path": str(target.PROOF_RECEIPT),
            "sha256": "c" * 64,
            "inode": 1,
            "mtime_ns": 1,
            "ctime_ns": 1,
        }
        for after_raw, after_ref in (
            (raw.replace(b'"proof_bytes":128', b'"proof_bytes":127'), before),
            (raw, dict(before, inode=2)),
            (raw, dict(before, ctime_ns=2)),
        ):
            for phase, sequence, reason in (
                (
                    "after-parent-verification",
                    [(raw, proof, before), (after_raw, proof, after_ref)],
                    "proof-receipt-changed-after-parent-verification",
                ),
                (
                    "before-publication",
                    [
                        (raw, proof, before),
                        (raw, proof, before),
                        (after_raw, proof, after_ref),
                    ],
                    "proof-receipt-changed-before-publication",
                ),
            ):
                with self.subTest(phase=phase, after_ref=after_ref), self.assertRaisesRegex(
                    target.Refused,
                    reason,
                ):
                    self._run_with_assignment_sequence(
                        [assignment, assignment],
                        proof_sequence=sequence,
                    )


class FilesystemControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kpb-w1-proof-controls-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        for current_raw, directories, files in os.walk(self.root, topdown=False, followlinks=False):
            current = Path(current_raw)
            for name in files:
                try:
                    os.chmod(current / name, 0o600, follow_symlinks=False)
                except (FileNotFoundError, NotImplementedError):
                    pass
            for name in directories:
                try:
                    os.chmod(current / name, 0o700, follow_symlinks=False)
                except (FileNotFoundError, NotImplementedError):
                    pass
        self.temporary.cleanup()

    def test_stable_file_rejects_symlink_hardlink_mode_and_hash(self):
        path = self.root / "value"
        path.write_bytes(b"value")
        path.chmod(0o400)
        target._stable_file(path, 0o400, expected_sha256=target.sha256_bytes(b"value"))
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(target.Refused):
            target._stable_file(link, 0o400)
        hard = self.root / "hard"
        os.link(path, hard)
        with self.assertRaises(target.Refused):
            target._stable_file(path, 0o400)
        hard.unlink()
        path.chmod(0o600)
        with self.assertRaises(target.Refused):
            target._stable_file(path, 0o400)
        path.chmod(0o400)
        with self.assertRaises(target.Refused):
            target._stable_file(path, 0o400, expected_sha256="0" * 64)

    def test_run_root_creation_fsyncs_its_parent(self):
        run = self.root / "fresh-run"
        with mock.patch.multiple(target, RUN_ROOT=run, LOCAL_ROOT=self.root), mock.patch.object(
            target, "_fsync_directory", wraps=target._fsync_directory
        ) as fsync:
            target._create_run_root()
            fsync.assert_called_once_with(self.root)
        self.assertEqual(stat.S_IMODE(os.lstat(run).st_mode), 0o700)

    def test_sealed_memfd_launcher_uses_authenticated_inode_and_exact_cleared_environment(self):
        binary = self.root / "python-candidate"
        binary.write_bytes(target.PYTHON.read_bytes())
        binary.chmod(0o500)
        output = self.root / "observed-environment.json"
        script = self.root / "observe.py"
        script.write_text(
            "import json, os\n"
            f"open({str(output)!r}, 'w').write(json.dumps(dict(os.environ), sort_keys=True))\n"
        )
        script.chmod(0o400)
        observed = os.lstat(binary)
        digest = target.sha256_bytes(binary.read_bytes())
        source = target._render_identity_bound_exec_source(
            binary_path=binary,
            receipt_path=script,
            expected_device=observed.st_dev,
            expected_inode=observed.st_ino,
            expected_bytes=observed.st_size,
            expected_sha256=digest,
            expected_owner_uid=observed.st_uid,
        )
        command = target._cleared_python_command(
            source,
            (),
        )
        completed = subprocess.run(
            command,
            env={
                "DBUS_SESSION_BUS_ADDRESS": "must-not-survive",
                "SSH_AUTH_SOCK": "must-not-survive",
                "GPG_AGENT_INFO": "must-not-survive",
                "NODE_OPTIONS": "must-not-survive",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr), (0, b"", b""))
        self.assertEqual(
            json.loads(output.read_text()),
            dict(value.split("=", 1) for value in target.FIXED_ENVIRONMENT),
        )

        wrong_source = target._render_identity_bound_exec_source(
            binary_path=binary,
            receipt_path=script,
            expected_device=observed.st_dev,
            expected_inode=observed.st_ino,
            expected_bytes=observed.st_size,
            expected_sha256="0" * 64,
            expected_owner_uid=observed.st_uid,
        )
        wrong = target._cleared_python_command(wrong_source, ())
        refused = subprocess.run(
            wrong,
            env={"DBUS_SESSION_BUS_ADDRESS": "must-not-survive"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual((refused.stdout, refused.stderr), (b"", b""))

    def test_unique_json_rejects_duplicate_key_and_nonfinite(self):
        for raw in (b'{"a":1,"a":2}\n', b'{"a":NaN}\n'):
            with self.assertRaises(target.Refused):
                target._unique_json(raw)

    def test_assignment_and_proof_receipts_require_exact_canonical_raw(self):
        assignment_path = self.root / "assignment.json"
        assignment_value = assignment_launch()
        assignment_raw = target.canonical(assignment_value)
        write(assignment_path, assignment_raw, 0o400)
        proof_path = self.root / "proof.json"
        proof_value = proof_receipt()
        write(proof_path, target.canonical(proof_value), 0o400)
        with mock.patch.multiple(
            target,
            ASSIGNMENT_LAUNCH_RECEIPT=assignment_path,
            EXPECTED_ASSIGNMENT_LAUNCH_RECEIPT_SHA256=target.sha256_bytes(assignment_raw),
            PROOF_RECEIPT=proof_path,
        ):
            target._assignment_launch_reference()
            target._proof_receipt_reference(target.sha256_bytes(target.canonical(proof_value)))

        for path, value, assignment in (
            (assignment_path, assignment_value, True),
            (proof_path, proof_value, False),
        ):
            path.chmod(0o600)
            noncanonical = (json.dumps(value, indent=2) + "\n").encode()
            path.write_bytes(noncanonical)
            path.chmod(0o400)
            replacements = {"PROOF_RECEIPT": path}
            if assignment:
                replacements = {
                    "ASSIGNMENT_LAUNCH_RECEIPT": path,
                    "EXPECTED_ASSIGNMENT_LAUNCH_RECEIPT_SHA256": target.sha256_bytes(noncanonical),
                }
            with mock.patch.multiple(target, **replacements):
                with self.assertRaises(target.Refused):
                    if assignment:
                        target._assignment_launch_reference()
                    else:
                        target._proof_receipt_reference(target.sha256_bytes(noncanonical))

    def test_atomic_publication_reauthenticates_proof_and_seals_only_three_files(self):
        run = self.root / "run"
        run.mkdir(mode=0o700)
        proof = target.canonical(proof_receipt())
        write(run / "PROOF-RECEIPT.json", proof, 0o400)
        with mock.patch.multiple(
            target,
            RUN_ROOT=run,
            PROOF_RECEIPT=run / "PROOF-RECEIPT.json",
            SUPERVISOR_SOURCE=run / "SUPERVISOR-SOURCE.py",
            LAUNCH_RECEIPT=run / "LAUNCH-RECEIPT.json",
            LOCAL_ROOT=self.root,
        ):
            proof_raw, _, proof_ref = target._proof_receipt_reference(
                target.sha256_bytes(proof)
            )
            evidence = target._publish(
                b"source\n",
                identified({"schema": "test"}),
                proof_raw,
                proof_ref,
            )
            self.assertEqual(len(evidence["launch_receipt_sha256"]), 64)
            self.assertTrue(
                evidence["proof_receipt_reauthenticated_inside_publication"]
            )
            self.assertEqual(stat.S_IMODE(os.lstat(run).st_mode), 0o500)
            with self.assertRaises((FileExistsError, target.Refused)):
                target._publish(
                    b"source\n",
                    identified({"schema": "test"}),
                    proof_raw,
                    proof_ref,
                )

    def test_publication_refuses_entry_and_mid_publication_proof_mutation(self):
        for phase in ("entry", "mid"):
            with self.subTest(phase=phase):
                run = self.root / f"run-{phase}"
                run.mkdir(mode=0o700)
                proof = target.canonical(proof_receipt())
                proof_path = run / "PROOF-RECEIPT.json"
                write(proof_path, proof, 0o400)
                with mock.patch.multiple(
                    target,
                    RUN_ROOT=run,
                    PROOF_RECEIPT=proof_path,
                    SUPERVISOR_SOURCE=run / "SUPERVISOR-SOURCE.py",
                    LAUNCH_RECEIPT=run / "LAUNCH-RECEIPT.json",
                    LOCAL_ROOT=self.root,
                ):
                    proof_raw, _, proof_ref = target._proof_receipt_reference(
                        target.sha256_bytes(proof)
                    )
                    if phase == "entry":
                        proof_path.chmod(0o600)
                        proof_path.write_bytes(proof + b" ")
                        proof_path.chmod(0o400)
                        with self.assertRaisesRegex(
                            target.Refused,
                            "file-at-hash|changed-at-publication-entry",
                        ):
                            target._publish(
                                b"source\n",
                                identified({"schema": "test"}),
                                proof_raw,
                                proof_ref,
                            )
                        continue
                    original = target._write_new_at
                    calls = 0

                    def mutate_after_staging(*arguments, **keywords):
                        nonlocal calls
                        result = original(*arguments, **keywords)
                        calls += 1
                        if calls == 2:
                            proof_path.chmod(0o600)
                            proof_path.write_bytes(proof + b" ")
                            proof_path.chmod(0o400)
                        return result

                    with mock.patch.object(
                        target,
                        "_write_new_at",
                        side_effect=mutate_after_staging,
                    ), self.assertRaisesRegex(
                        target.Refused,
                        "file-at-hash|changed-during-publication",
                    ):
                        target._publish(
                            b"source\n",
                            identified({"schema": "test"}),
                            proof_raw,
                            proof_ref,
                        )


class IdentityBoundExecControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-w1-proof-identity-bound-exec-controls-"
        )
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def reference(path: Path) -> dict:
        raw = path.read_bytes()
        value = os.lstat(path)
        return {
            "device": value.st_dev,
            "inode": value.st_ino,
            "bytes": value.st_size,
            "sha256": target.sha256_bytes(raw),
            "owner_uid": value.st_uid,
        }

    def source(self, path: Path, reference: dict) -> str:
        return target._render_identity_bound_exec_source(
            binary_path=path,
            receipt_path=self.root / "unused-receipt",
            expected_device=reference["device"],
            expected_inode=reference["inode"],
            expected_bytes=reference["bytes"],
            expected_sha256=reference["sha256"],
            expected_owner_uid=reference["owner_uid"],
        )

    def fresh_true_binary(self, name: str) -> tuple[Path, dict]:
        path = self.root / name
        shutil.copyfile("/bin/true", path)
        os.chmod(path, 0o500)
        return path, self.reference(path)

    def test_helper_executes_only_the_sealed_rehashed_memfd(self):
        path, reference = self.fresh_true_binary("candidate")
        source = self.source(path, reference)
        completed = subprocess.run(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr), (0, b"", b""))
        for weakened in (
            source.replace("fcntl.F_SEAL_WRITE\n", "0\n", 1),
            source.replace("fcntl.F_SEAL_GROW\n", "0\n", 1),
            source.replace("fcntl.F_SEAL_SHRINK\n", "0\n", 1),
            source.replace("fcntl.F_SEAL_SEAL\n", "0\n", 1),
        ):
            completed = subprocess.run(
                [str(target.PYTHON), "-I", "-c", weakened],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual((completed.returncode, completed.stdout, completed.stderr), (70, b"", b""))

    def test_no_argument_sealed_exec_preserves_exact_verifier_stdin(self):
        path = self.root / "stdin-python"
        shutil.copyfile(target.PYTHON, path)
        os.chmod(path, 0o500)
        reference = self.reference(path)
        source = target._render_identity_bound_exec_source(
            binary_path=path,
            receipt_path=None,
            expected_device=reference["device"],
            expected_inode=reference["inode"],
            expected_bytes=reference["bytes"],
            expected_sha256=reference["sha256"],
            expected_owner_uid=reference["owner_uid"],
        )
        raw = b'import sys\nsys.stdout.write("stdin-preserved\\n")\n'
        completed = subprocess.run(
            [str(target.PYTHON), "-I", "-c", source],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(completed.stdout, b"stdin-preserved\n")

    def test_in_place_mutation_held_across_exec_cannot_change_sealed_bytes(self):
        path, reference = self.fresh_true_binary("in-place-mutation")
        original = path.read_bytes()
        original_inode = os.lstat(path).st_ino
        ready = self.root / "sealed-memfd-ready"
        release = self.root / "release-sealed-exec"
        source = self.source(path, reference)
        source = source.replace("import stat\n", "import stat\nimport time\n", 1)
        needle = "    os.execve(sealed_descriptor, [BINARY, *ARGUMENTS], ENVIRONMENT)"
        self.assertEqual(source.count(needle), 1)
        source = source.replace(
            needle,
            f"    open({str(ready)!r}, 'x').close()\n"
            f"    while not os.path.exists({str(release)!r}):\n"
            "        time.sleep(0.01)\n"
            + needle,
            1,
        )
        process = subprocess.Popen(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout = b""
        stderr = b""
        try:
            for _ in range(500):
                if ready.exists():
                    break
                target.time.sleep(0.01)
            self.assertTrue(ready.exists())
            os.chmod(path, 0o700)
            with path.open("r+b", buffering=0) as stream:
                stream.write(b"\x00" * 64)
                os.fsync(stream.fileno())
            os.chmod(path, 0o500)
            self.assertEqual(os.lstat(path).st_ino, original_inode)
            self.assertNotEqual(target.sha256_bytes(path.read_bytes()), reference["sha256"])
            release.touch(exist_ok=False)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual((process.returncode, stdout, stderr), (0, b"", b""))

        finally:
            release.touch(exist_ok=True)
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
            os.chmod(path, 0o700)
            with path.open("r+b", buffering=0) as stream:
                stream.seek(0)
                stream.write(original)
                stream.truncate()
                os.fsync(stream.fileno())
            os.chmod(path, 0o500)
        self.assertEqual(os.lstat(path).st_ino, original_inode)
        self.assertEqual(target.sha256_bytes(path.read_bytes()), reference["sha256"])

    def test_stage0_fd_reader_requires_full_seals_and_sets_cloexec(self):
        source = f"""\
import fcntl
import os
import sys
sys.path.insert(0, {str(Path(target.__file__).resolve().parent)!r})
import run_frozen_w1_proof as target
raw = b'reviewed-supervisor-source-control'
descriptor = os.memfd_create('stage0-control', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
os.write(descriptor, raw)
os.fchmod(descriptor, 0o400)
seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
os.dup2(descriptor, target.STAGE0_SUPERVISOR_FD, inheritable=True)
observed, reference = target._sealed_stage0_fd(
    target.STAGE0_SUPERVISOR_FD,
    'control',
    4096,
)
if observed != raw or reference['sha256'] != target.sha256_bytes(raw):
    raise SystemExit(3)
if not (fcntl.fcntl(target.STAGE0_SUPERVISOR_FD, fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
    raise SystemExit(4)
"""
        completed = subprocess.run(
            [sys.executable, "-c", source],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            (completed.returncode, completed.stdout, completed.stderr),
            (0, b"", b""),
        )

    def test_wrong_inode_and_swap_restore_refuse(self):
        path, reference = self.fresh_true_binary("wrong-inode")
        source = self.source(path, reference)
        original = self.root / "wrong-inode-original"
        path.replace(original)
        shutil.copyfile(original, path)
        os.chmod(path, 0o500)
        self.assertEqual(target.sha256_bytes(path.read_bytes()), reference["sha256"])
        self.assertNotEqual(os.lstat(path).st_ino, reference["inode"])
        completed = subprocess.run(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr), (70, b"", b""))

        path, reference = self.fresh_true_binary("swap-restore")
        source = self.source(path, reference)
        before_open = self.root / "before-open"
        after_open = self.root / "after-open"
        self.assertEqual(source.count("source_descriptor = os.open("), 1)
        self.assertEqual(source.count("    opened = os.fstat(source_descriptor)"), 1)
        source = source.replace(
            "source_descriptor = os.open(",
            f"open({str(before_open)!r}, 'x').close()\n"
            "import time\ntime.sleep(0.50)\nsource_descriptor = os.open(",
        ).replace(
            "    opened = os.fstat(source_descriptor)",
            f"    open({str(after_open)!r}, 'x').close()\n"
            "    time.sleep(0.50)\n    opened = os.fstat(source_descriptor)",
        )
        process = subprocess.Popen(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(200):
            if before_open.exists():
                break
            target.time.sleep(0.01)
        self.assertTrue(before_open.exists())
        saved = self.root / "swap-restore-original"
        path.replace(saved)
        shutil.copyfile("/bin/false", path)
        os.chmod(path, 0o500)
        for _ in range(200):
            if after_open.exists():
                break
            target.time.sleep(0.01)
        self.assertTrue(after_open.exists())
        path.unlink()
        saved.replace(path)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual((process.returncode, stdout, stderr), (70, b"", b""))
        self.assertEqual(target.sha256_bytes(path.read_bytes()), reference["sha256"])
        self.assertEqual(os.lstat(path).st_ino, reference["inode"])


class SyntheticBuildBundleControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kpb-w1-proof-build-controls-")
        self.root = Path(self.temporary.name)
        self.parent = self.root / "private"
        self.bundle = self.parent / "w1-proof-build"
        self.evidence = self.parent / "w1-proof-build-contract"
        self.sources = self.bundle / "sources"
        self.artifacts = self.bundle / "artifacts"
        self.sources.mkdir(parents=True, mode=0o700)
        self.artifacts.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)

    def tearDown(self):
        for current_raw, directories, files in os.walk(self.root, topdown=False, followlinks=False):
            current = Path(current_raw)
            for name in files:
                try:
                    os.chmod(current / name, 0o600, follow_symlinks=False)
                except FileNotFoundError:
                    pass
            for name in directories:
                try:
                    os.chmod(current / name, 0o700, follow_symlinks=False)
                except FileNotFoundError:
                    pass
        self.temporary.cleanup()

    def _build(self) -> dict[str, str | int]:
        members = []
        required_sources = sorted(
            set(target.REQUIRED_PROOF_DEPENDENCIES)
            | set(target.REQUIRED_VERIFIER_DEPENDENCIES)
            | set(target.REVIEWED_BUILD_SOURCES)
        )
        for index, relative in enumerate(required_sources):
            if relative == target.VERIFIER_CONTRACT_SOURCE:
                raw = (
                    "const VK_BYTES: usize = 328;\n"
                    f'const VK_SHA256_HEX: &str = "{target.FIXED_ARTIFACTS["independent_vk"][2]}";\n'
                    f'const VK_PATH: &str = "{target.VK_PATH}";\n'
                    "let owned_vk = read_authenticated_exact::<VK_BYTES>(\n"
                    "verify_proof_with_hostile_controls(&vk, &proof, &public_inputs)?;\n"
                ).encode()
            else:
                raw = f"source-{index}\n".encode()
            write(self.sources / relative, raw, 0o400)
            members.append({"relative_path": relative, "bytes": len(raw), "sha256": target.sha256_bytes(raw)})
        manifest_unsigned = {
            "schema": "kpb-current-w1-source-snapshot-manifest/v1",
            "classification": "CURRENT_SOURCE_FINAL_CANDIDATE_NOT_AUTHORITY",
            "source_root": "/synthetic/source",
            "package_roots": list(target.EXPECTED_PACKAGE_ROOTS),
            "derivation": "synthetic-control",
            "members": members,
            "member_count": len(members),
            "members_identity_sha256": target.sha256_bytes(target.canonical(members)),
            "authorization": False,
        }
        manifest = dict(manifest_unsigned)
        manifest["manifest_identity_sha256"] = target.sha256_bytes(target.canonical(manifest_unsigned))
        manifest_raw = target.canonical(manifest)
        manifest_ref = write(self.bundle / "SOURCE-MANIFEST.json", manifest_raw, 0o400)
        binary_ref = write(self.artifacts / "candidate-binary", b"binary\n", 0o500)
        verifier_ref = write(
            self.artifacts / "verify_frozen_w1_round1_receipt",
            b"verifier\n",
            0o500,
        )
        verifier_ref.update({
            "path": str(self.artifacts / "verify_frozen_w1_round1_receipt"),
            "link_count": 1,
        })
        dependency_paths = [f"sources/{value}" for value in target.REQUIRED_PROOF_DEPENDENCIES]
        dep_raw = ("artifacts/candidate-binary: " + " ".join(dependency_paths) + "\n").encode()
        dep_ref = write(self.artifacts / "candidate-binary.d", dep_raw, 0o400)
        verifier_dependency_paths = [
            f"sources/{value}" for value in target.REQUIRED_VERIFIER_DEPENDENCIES
        ]
        verifier_dep_raw = (
            "artifacts/verify_frozen_w1_round1_receipt: "
            + " ".join(verifier_dependency_paths)
            + "\n"
        ).encode()
        verifier_dep_ref = write(
            self.artifacts / "verify_frozen_w1_round1_receipt.d",
            verifier_dep_raw,
            0o400,
        )
        verifier_dep_ref.update({
            "path": str(self.artifacts / "verify_frozen_w1_round1_receipt.d"),
            "link_count": 1,
        })
        core_ref = write(self.bundle / "FREEZER-SOURCE.py", b"core\n", 0o400)
        freezer_ref = write(self.evidence / "FREEZER-SOURCE.py", b"outer\n", 0o400)
        proof_dependencies = list(target.REQUIRED_PROOF_DEPENDENCIES)
        verifier_dependencies = list(target.REQUIRED_VERIFIER_DEPENDENCIES)
        inner = identified({
            "schema": "kpb-current-w1-test-build-freeze-receipt/v1",
            "classification": "TEST_ONLY_FILESYSTEM_CONTRACT_NOT_A_BUILD_AUTHORITY",
            "authorization": False, "setup": False, "pk_decode": False,
            "synthesis": False, "proof": False, "network": False, "funds": False,
            "source_manifest": manifest_ref,
            "built_examples": list(target.BUILD_EXAMPLES),
            "dep_info": {
                "target": "artifacts/candidate-binary",
                "dependencies": [f"sources/{value}" for value in proof_dependencies],
                "dependency_count": len(proof_dependencies),
                "dep_info_sha256": dep_ref["sha256"],
                "snapshot_only": True,
                "live_path_provenance": False,
            },
            "verifier_dep_info": {
                "target": "artifacts/verify_frozen_w1_round1_receipt",
                "dependencies": [
                    f"sources/{value}" for value in verifier_dependencies
                ],
                "dependency_count": len(verifier_dependencies),
                "dep_info_sha256": verifier_dep_ref["sha256"],
                "snapshot_only": True,
                "live_path_provenance": False,
            },
            "binary": dict(binary_ref, name="candidate-binary"),
            "verifier_binary": dict(
                verifier_ref,
                name="verify_frozen_w1_round1_receipt",
            ),
            "frozen_dep_info": dict(dep_ref, name="candidate-binary.d"),
            "frozen_verifier_dep_info": dict(
                verifier_dep_ref,
                name="verify_frozen_w1_round1_receipt.d",
            ),
            "actual_subprocess_build_executed_by_contract": True,
            "production_source_manifest_bound": False,
            "production_binary_accepted": False,
        })
        inner_raw = target.canonical(inner)
        inner_ref = write(self.bundle / "BUILD-RECEIPT.json", inner_raw, 0o400)
        staging_root = self.parent / (
            ".w1-proof-build.staging-"
            "00000000-0000-4000-8000-000000000010"
        )
        build_cwd = str(
            staging_root
            / "sources"
            / "poc/local-private-payment/private-batch-relation"
        )
        target_directory = str(
            self.parent
            / (
                ".w1-proof-build.target-"
                "00000000-0000-4000-8000-000000000011"
            )
        )
        build_command = [
            str(target.SYSTEMD_RUN),
            "--user", "--quiet", "--no-block", "--remain-after-exit",
            "--unit=kpb-w1-proof-freeze-build-20261029-02",
            "--service-type=exec", "--expand-environment=no",
            "--property",
            "SystemCallFilter=~" + " ".join(target.BUILD_DENIED_NETWORK_SYSCALLS),
            "--property", "SystemCallErrorNumber=EPERM",
            "--property", "RestrictAddressFamilies=AF_UNIX",
            "--property", "NoNewPrivileges=yes",
            "--property", "LimitCORE=0",
            "--property", "MemoryMax=20G",
            "--property", "MemorySwapMax=0",
            "--property", "UMask=0077",
            "--property",
            "UnsetEnvironment=" + " ".join(
                target.BUILD_BOOTSTRAP_UNSET_ENVIRONMENT
            ),
            "--property", "StandardInput=null",
            "--property", "StandardOutput=null",
            "--property", "StandardError=null",
            f"--working-directory={build_cwd}",
            "/usr/bin/env", "-i",
        ]
        for value in (
            "HOME=/home/luke",
            "PATH=/home/luke/.cargo/bin:/usr/bin:/bin",
            "CARGO_HOME=/home/luke/.cargo",
            "RUSTUP_HOME=/home/luke/.rustup",
            "CARGO_NET_OFFLINE=true",
            f"CARGO_TARGET_DIR={target_directory}",
            "CARGO_INCREMENTAL=0",
            "CARGO_TERM_COLOR=never",
            "RUSTC_WRAPPER=",
            "RUSTC_WORKSPACE_WRAPPER=",
            "RUSTFLAGS=",
            "CARGO_ENCODED_RUSTFLAGS=",
            "HTTP_PROXY=",
            "HTTPS_PROXY=",
            "ALL_PROXY=",
            "NO_PROXY=",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "TZ=UTC",
        ):
            build_command.append(value)
        build_command.extend((
            "/home/luke/.cargo/bin/cargo", "build", "--release", "--locked",
            "--offline", "--no-default-features", "--features",
            "offline-w1-prover", "--example", target.BUILD_EXAMPLES[0],
            "--example", target.BUILD_EXAMPLES[1],
        ))
        cargo_proof_ref = dict(
            binary_ref,
            path=str(
                Path(target_directory)
                / "release" / "examples" / target.BUILD_EXAMPLES[0]
            ),
        )
        cargo_verifier_ref = dict(
            verifier_ref,
            path=str(
                Path(target_directory)
                / "release" / "examples" / target.BUILD_EXAMPLES[1]
            ),
        )
        reviewed_sources = {
            relative: {
                "bytes": member["bytes"],
                "sha256": member["sha256"],
            }
            for relative in target.REVIEWED_BUILD_SOURCES
            for member in members
            if member["relative_path"] == relative
        }
        review_binding = {
            "schema": target.BUILD_REVIEW_SNAPSHOT_BINDING_SCHEMA,
            "reviewed_member_count": len(target.REVIEWED_BUILD_SOURCES),
            "reviewed_manifest_snapshot_exact_match": True,
            "entries": [
                {
                    "relative_path": relative,
                    "bytes": reviewed_sources[relative]["bytes"],
                    "sha256": reviewed_sources[relative]["sha256"],
                    "snapshot_device": 1,
                    "snapshot_inode": index + 1,
                }
                for index, relative in enumerate(target.REVIEWED_BUILD_SOURCES)
            ],
            "authorization": False,
        }
        review_binding["binding_identity_sha256"] = target.sha256_bytes(
            target.canonical(review_binding)
        )

        ledger_root = self.parent / "UNIT-IDENTITY-LEDGER"
        ledger_root.mkdir(mode=0o700)

        def unit_material(unit_name, role, command_sha256, reservation_id):
            unit_root = ledger_root / f"{unit_name}.identity"
            unit_root.mkdir(mode=0o700)
            reservation = {
                "schema": target.BUILD_UNIT_RESERVATION_SCHEMA,
                "unit_name": unit_name,
                "service_unit": f"{unit_name}.service",
                "role": role,
                "reservation_id": reservation_id,
                "command_sha256": command_sha256,
                "private_output_parent": str(self.parent),
                "identity_reserved_create_new": True,
                "systemd_start_dispatched": False,
                "authorization": False,
            }
            reservation["record_identity_sha256"] = target.sha256_bytes(
                target.canonical(reservation)
            )
            reservation_ref = write(
                unit_root / "RESERVATION.json",
                target.canonical(reservation),
                0o400,
            )
            reservation_claim = dict(
                reservation_ref,
                name="RESERVATION.json",
                link_count=1,
            )
            consumption = {
                "schema": target.BUILD_UNIT_CONSUMPTION_SCHEMA,
                "unit_name": unit_name,
                "service_unit": f"{unit_name}.service",
                "role": role,
                "reservation_id": reservation_id,
                "reservation_sha256": reservation_ref["sha256"],
                "command_sha256": command_sha256,
                "identity_consumed_before_start": True,
                "pristine_observation_required_after_consumption": True,
                "systemd_start_dispatched": False,
                "authorization": False,
            }
            consumption["record_identity_sha256"] = target.sha256_bytes(
                target.canonical(consumption)
            )
            consumption_ref = write(
                unit_root / "CONSUMPTION.json",
                target.canonical(consumption),
                0o400,
            )
            consumption_claim = dict(
                consumption_ref,
                name="CONSUMPTION.json",
                link_count=1,
            )
            show_command = [
                str(target.SYSTEMCTL), "--user", "show", f"{unit_name}.service",
                "--property=LoadState", "--value", "--no-pager",
            ]
            journal_command = [
                str(target.JOURNALCTL), "--user", "--unit",
                f"{unit_name}.service", "--no-pager", "--quiet",
                "--output=export",
            ]
            pristine = {
                "load_state": "not-found",
                "systemctl_command_sha256": target.sha256_bytes(
                    target.canonical(show_command)
                ),
                "systemctl_stdout_bytes": len(b"not-found\n"),
                "systemctl_stdout_sha256": target.sha256_bytes(b"not-found\n"),
                "historical_journal_command_sha256": target.sha256_bytes(
                    target.canonical(journal_command)
                ),
                "historical_journal_bytes": 0,
                "historical_journal_sha256": target.sha256_bytes(b""),
                "historical_journal_empty": True,
            }
            identity = {
                "unit_root": str(unit_root),
                "unit_name": unit_name,
                "service_unit": f"{unit_name}.service",
                "role": role,
                "reservation_id": reservation_id,
                "reservation": reservation_claim,
                "consumption": consumption_claim,
                "first_pristine_observation": pristine,
                "second_pristine_observation": dict(pristine),
                "reservation_and_consumption_durable_before_start": True,
                "prestart_load_state_not_found": True,
                "prestart_historical_journal_empty": True,
                "start_dispatched_after_consumption": True,
            }
            unit_root.chmod(0o500)
            ledger_member = {
                "unit_root": str(unit_root),
                "reservation": reservation_claim,
                "consumption": consumption_claim,
            }
            runtime = {
                "unit": f"{unit_name}.service",
                "unit_identity": identity,
                "unit_identity_was_fresh_and_consumed_before_start": True,
                "command_sha256": command_sha256,
                "properties": {
                    "restrict_address_families": "AF_UNIX",
                    "denied_network_syscalls": sorted(
                        target.BUILD_DENIED_NETWORK_SYSCALLS
                    ),
                    "system_call_error_number": 1,
                    "no_new_privileges": True,
                    "limit_core_bytes": 0,
                    "memory_max_bytes": target.MEMORY_MAX_BYTES,
                    "memory_swap_max_bytes": 0,
                    "umask_octal": "0077",
                    "unset_environment": sorted(
                        target.BUILD_BOOTSTRAP_UNSET_ENVIRONMENT
                    ),
                    "standard_input": "null",
                    "standard_output": "null",
                    "standard_error": "null",
                    "inherited_communication_fds": False,
                },
                "show_sha256": "1" * 64,
                "show_bytes": 1,
                "journal_sha256": target.sha256_bytes(b""),
                "journal_bytes": 0,
                "result": "success",
                "exec_main_status": 0,
                "unit_stopped_after_capture": True,
            }
            return ledger_member, runtime

        build_command_sha256 = target.sha256_bytes(target.canonical(build_command))
        probe_command_sha256 = target.sha256_bytes(
            target.canonical(["synthetic-fixed-network-probe"])
        )
        probe_member, probe_runtime = unit_material(
            target.BUILD_FREEZE_PROBE_UNIT,
            "network_probe",
            probe_command_sha256,
            "00000000-0000-4000-8000-000000000001",
        )
        build_member, build_runtime = unit_material(
            target.BUILD_FREEZE_BUILD_UNIT,
            "cargo_build",
            build_command_sha256,
            "00000000-0000-4000-8000-000000000002",
        )
        ledger = {
            "root": str(ledger_root),
            "mode_octal": "0500",
            "unit_count": 2,
            "units": {
                target.BUILD_FREEZE_PROBE_UNIT: probe_member,
                target.BUILD_FREEZE_BUILD_UNIT: build_member,
            },
            "reservations_and_consumptions_retained": True,
            "authorization": False,
        }
        ledger["ledger_identity_sha256"] = target.sha256_bytes(
            target.canonical(ledger)
        )
        ledger_root.chmod(0o500)
        outer = identified({
            "schema": "kpb-w1-proof-build-receipt/v1",
            "classification": "TEST_ONLY_COMBINED_W1_PROOF_BUILD_NOT_AUTHORITY",
            "private_output_parent": str(self.parent),
            "authorization": False, "privacy_acceptance": False,
            "financial_acceptance": False, "setup": False, "pk_decode": False,
            "proving_key_read": False, "synthesis": False, "proof": False,
            "verification": False, "network_communication": False, "funds": False,
            "actions": dict(target.BUILD_ACTIONS),
            "review_gate": {
                "independent_review_explicitly_bound_before_execution": True,
                "review_manifest_snapshot_binding": review_binding,
                "review_manifest_snapshot_rechecked_after_build": True,
                "review_manifest_snapshot_rechecked_after_publication": True,
                "reviewed_sources_equal_after_atomic_freeze": True,
                "reviewed_sources": reviewed_sources,
            },
            "source_snapshot": {
                "package_roots": list(target.EXPECTED_PACKAGE_ROOTS),
                "member_count": len(members),
                "members_identity_sha256": manifest["members_identity_sha256"],
                "manifest": manifest_ref,
            },
            "build": {
                "actual_subprocess_executed": True,
                "command": build_command,
                "command_sha256": build_command_sha256,
                "environment_launcher": "/usr/bin/env",
                "environment_cleared_with_i": True,
                "exact_cargo_environment": [
                    "HOME=/home/luke",
                    "PATH=/home/luke/.cargo/bin:/usr/bin:/bin",
                    "CARGO_HOME=/home/luke/.cargo",
                    "RUSTUP_HOME=/home/luke/.rustup",
                    "CARGO_NET_OFFLINE=true",
                    f"CARGO_TARGET_DIR={target_directory}",
                    "CARGO_INCREMENTAL=0",
                    "CARGO_TERM_COLOR=never",
                    "RUSTC_WRAPPER=",
                    "RUSTC_WORKSPACE_WRAPPER=",
                    "RUSTFLAGS=",
                    "CARGO_ENCODED_RUSTFLAGS=",
                    "HTTP_PROXY=",
                    "HTTPS_PROXY=",
                    "ALL_PROXY=",
                    "NO_PROXY=",
                    "LANG=C.UTF-8",
                    "LC_ALL=C.UTF-8",
                    "TZ=UTC",
                ],
                "ambient_manager_environment_inherited_by_cargo": False,
                "bootstrap_unset_environment": list(
                    target.BUILD_BOOTSTRAP_UNSET_ENVIRONMENT
                ),
                "cwd": build_cwd,
                "profile": "release",
                "binary_was_not_executed": True,
                "both_binaries_were_not_executed": True,
                "no_binary_execution_command_dispatched": True,
                "locked": True,
                "offline": True,
                "default_features": False,
                "features": ["offline-w1-prover"],
                "example": target.BUILD_EXAMPLES[0],
                "examples": list(target.BUILD_EXAMPLES),
                "single_cargo_invocation_for_both_examples": True,
                "cargo_original_binary": cargo_proof_ref,
                "cargo_original_verifier_binary": cargo_verifier_ref,
                "detached_create_new_verifier_binary": verifier_ref,
                "detached_binaries_byte_identical": True,
                "unit": build_runtime,
                "unit_identity_ledger": ledger,
            },
            "network_boundary": {
                "denied_network_syscalls": list(
                    target.BUILD_DENIED_NETWORK_SYSCALLS
                ),
                "system_call_error": "EPERM",
                "restrict_address_families": "AF_UNIX",
                "socket_and_socketpair_allowed_for_local_process_spawn": True,
                "socketpair_connected_write_read_classified_as_local_ipc_only": True,
                "sendto_recvfrom_denied": True,
                "sendmsg_recvmsg_mmsg_denied": True,
                "af_unix_connect_bind_listen_accept_denied": True,
                "io_uring_setup_enter_register_denied": True,
                "inherited_communication_fds": False,
                "ip_address_families_available": False,
                "local_af_unix_ipc_permitted": True,
                "local_af_unix_ipc_observed": True,
                "af_unix_external_relay_surface_observed": False,
                "strict_no_socket_runtime_boundary_is_not_this_build_boundary": True,
                "probe": dict(
                    probe_runtime,
                    af_inet_and_af_inet6_socket_calls_denied_with_eafnosupport=True,
                    af_unix_socket_and_socketpair_available_for_process_spawn=True,
                    local_af_unix_ipc_observed=True,
                    af_unix_seqpacket_connected_write_and_read_observed=True,
                    fixed_subprocess_spawn_succeeded=True,
                    af_unix_connect_attempt_denied_with_eperm=True,
                    af_unix_datagram_sendto_denied_with_eperm=True,
                    af_unix_recvfrom_denied_with_eperm=True,
                    io_uring_setup_enter_register_denied_with_eperm_or_enosys=True,
                    initial_standard_fds_are_dev_null=True,
                    no_other_inherited_fds_observed=True,
                    network_communication_performed=False,
                ),
                "network_communication_performed": False,
            },
            "closure_scope": {
                "combined_assignment_plus_prover_closure_frozen": True,
                "proof_entry_source_present": True,
                "verifier_entry_source_present": True,
                "private_prover_source_present": True,
                "reviewed_low_memory_source_present": True,
                "parent_verifier_closure_frozen": True,
            },
            "dep_info": {
                "target_relative": "artifacts/candidate-binary",
                "dependency_relatives": proof_dependencies,
                "dependency_count": len(proof_dependencies),
            },
            "verifier_dep_info": {
                "target_relative": "artifacts/verify_frozen_w1_round1_receipt",
                "dependency_relatives": verifier_dependencies,
                "dependency_count": len(verifier_dependencies),
                "frozen": verifier_dep_ref,
            },
            "atomic_core_bundle": {
                "source_binary_receipt_atomically_published": True,
                "binary": binary_ref,
                "receipt": inner_ref,
                "parent_verifier_binary": verifier_ref,
                "parent_verifier_dep_info": verifier_dep_ref,
                "result": {
                    "verifier_binary_sha256": verifier_ref["sha256"],
                    "verifier_dep_info_sha256": verifier_dep_ref["sha256"],
                },
            },
            "freezer_source": freezer_ref,
            "executed_core_source": {"frozen_inner_copy": core_ref},
            "limitations": {
                "proof_executed": False,
                "verifier_binary_executed": False,
                "cryptographic_correctness_proved": False,
                "privacy_proved": False,
            },
        })
        outer_raw = target.canonical(outer)
        outer_ref = write(self.evidence / "PROOF-BUILD-RECEIPT.json", outer_raw, 0o400)
        for path in (self.sources, self.artifacts, self.bundle, self.evidence):
            path.chmod(0o500)
        self.parent.chmod(0o700)
        return {
            "manifest": manifest_ref["sha256"], "inner": inner_ref["sha256"],
            "dep": dep_ref["sha256"], "binary": binary_ref["sha256"],
            "binary_bytes": binary_ref["bytes"], "core": core_ref["sha256"],
            "verifier": verifier_ref["sha256"],
            "verifier_bytes": verifier_ref["bytes"],
            "verifier_dep": verifier_dep_ref["sha256"],
            "verifier_dependencies": tuple(verifier_dependencies),
            "verifier_contract_source": next(
                member["sha256"]
                for member in members
                if member["relative_path"] == target.VERIFIER_CONTRACT_SOURCE
            ),
            "freezer": freezer_ref["sha256"], "outer": outer_ref["sha256"],
        }

    def test_dependency_contract_rejects_unsafe_nonmember_reorder_and_wrong_target(self):
        paths = list(target.REQUIRED_PROOF_DEPENDENCIES)
        dependencies = list(paths)
        info = {
            "target_relative": "artifacts/candidate-binary",
            "dependency_count": len(dependencies),
            "dependency_relatives": dependencies,
        }
        raw = (
            "artifacts/candidate-binary: "
            + " ".join(f"sources/{value}" for value in dependencies)
            + "\n"
        ).encode()
        self.assertEqual(
            target._validate_dependency_contract(info, dependencies, paths, raw),
            len(dependencies),
        )
        cases = []
        unsafe = list(dependencies)
        unsafe[0] = "../escape.rs"
        cases.append((info, unsafe, paths, raw))
        nonmember = list(dependencies) + ["poc/not-in-manifest.rs"]
        nonmember_info = dict(info, dependency_count=len(nonmember))
        cases.append((nonmember_info, nonmember, paths, raw))
        reordered = list(reversed(dependencies))
        cases.append((info, reordered, paths, raw))
        wrong_info = dict(info, target_relative="artifacts/other")
        cases.append((wrong_info, dependencies, paths, raw))
        wrong_raw = raw.replace(b"artifacts/candidate-binary", b"target/release/example", 1)
        cases.append((info, dependencies, paths, wrong_raw))
        absolute_raw = (
            b"artifacts/candidate-binary: /tmp/source.rs\n"
        )
        cases.append((info, dependencies, paths, absolute_raw))
        for index, case in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(target.Refused):
                target._validate_dependency_contract(*case)

    def test_verifier_dependency_closure_is_exactly_digest_bound(self):
        manifest_paths = sorted(
            set(target.REVIEWED_BUILD_SOURCES)
            | set(target.REQUIRED_VERIFIER_DEPENDENCIES)
        )
        dependency_set = set(target.REQUIRED_VERIFIER_DEPENDENCIES)
        dependencies = [
            relative for relative in manifest_paths if relative in dependency_set
        ]
        info = {
            "target_relative": "artifacts/verify_frozen_w1_round1_receipt",
            "dependency_relatives": dependencies,
            "dependency_count": len(dependencies),
        }
        raw = (
            "artifacts/verify_frozen_w1_round1_receipt: "
            + " ".join(f"sources/{relative}" for relative in dependencies)
            + "\n"
        ).encode()
        self.assertEqual(
            target._validate_verifier_dependency_contract(
                info,
                dependencies,
                manifest_paths,
                raw,
                target.sha256_bytes(raw),
                tuple(dependencies),
            ),
            len(dependencies),
        )
        extra_set = dependency_set | {
            "poc/local-private-payment/private-batch-relation/Cargo.toml"
        }
        extra_dependencies = [
            relative for relative in manifest_paths if relative in extra_set
        ]
        extra_info = dict(
            info,
            dependency_relatives=extra_dependencies,
            dependency_count=len(extra_dependencies),
        )
        extra_raw = (
            "artifacts/verify_frozen_w1_round1_receipt: "
            + " ".join(f"sources/{relative}" for relative in extra_dependencies)
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            target.Refused,
            "verifier-dependency-membership-order",
        ):
            target._validate_verifier_dependency_contract(
                extra_info,
                extra_dependencies,
                manifest_paths,
                extra_raw,
                target.sha256_bytes(extra_raw),
                tuple(dependencies),
            )

    def test_exact_synthetic_combined_bundle_passes_and_mutation_refuses(self):
        values = self._build()
        replacements = {
            "PRIVATE_BUILD_PARENT": self.parent,
            "BUILD_UNIT_LEDGER": self.parent / "UNIT-IDENTITY-LEDGER",
            "BUILD_BUNDLE": self.bundle,
            "BUILD_EVIDENCE": self.evidence,
            "BUILD_BINARY": self.artifacts / "candidate-binary",
            "BUILD_DEP_INFO": self.artifacts / "candidate-binary.d",
            "BUILD_VERIFIER_BINARY": self.artifacts / "verify_frozen_w1_round1_receipt",
            "BUILD_VERIFIER_DEP_INFO": self.artifacts / "verify_frozen_w1_round1_receipt.d",
            "BUILD_MANIFEST": self.bundle / "SOURCE-MANIFEST.json",
            "BUILD_INNER_RECEIPT": self.bundle / "BUILD-RECEIPT.json",
            "BUILD_CORE_SOURCE": self.bundle / "FREEZER-SOURCE.py",
            "BUILD_OUTER_RECEIPT": self.evidence / "PROOF-BUILD-RECEIPT.json",
            "BUILD_FREEZER_SOURCE": self.evidence / "FREEZER-SOURCE.py",
            "EXPECTED_MANIFEST_SHA256": values["manifest"],
            "EXPECTED_INNER_RECEIPT_SHA256": values["inner"],
            "EXPECTED_DEP_INFO_SHA256": values["dep"],
            "EXPECTED_BINARY_SHA256": values["binary"],
            "EXPECTED_BINARY_BYTES": values["binary_bytes"],
            "EXPECTED_VERIFIER_BINARY_SHA256": values["verifier"],
            "EXPECTED_VERIFIER_BINARY_BYTES": values["verifier_bytes"],
            "EXPECTED_VERIFIER_DEP_INFO_SHA256": values["verifier_dep"],
            "EXPECTED_VERIFIER_DEPENDENCY_RELATIVES": values[
                "verifier_dependencies"
            ],
            "EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256": values[
                "verifier_contract_source"
            ],
            "EXPECTED_BUILD_CORE_SOURCE_SHA256": values["core"],
            "EXPECTED_BUILD_FREEZER_SOURCE_SHA256": values["freezer"],
            "EXPECTED_OUTER_RECEIPT_SHA256": values["outer"],
            "EXPECTED_ASSIGNMENT_LAUNCH_RECEIPT_SHA256": "a" * 64,
        }
        with mock.patch.multiple(target, **replacements):
            result = target.validate_build_bundle()
            self.assertTrue(
                result["combined_assignment_plus_prover_and_parent_verifier"]
            )
            self.assertEqual(result["dependency_count"], len(target.REQUIRED_PROOF_DEPENDENCIES))
            self.assertEqual(
                result["parent_verifier_dependency_count"],
                len(target.REQUIRED_VERIFIER_DEPENDENCIES),
            )
            binary = result["references"]["binary"]
            self.assertEqual(binary["owner_uid"], os.getuid())
            self.assertEqual(binary["link_count"], 1)
            self.assertIn(
                "os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC",
                target._run_command(binary)[-1],
            )
            os.chmod(self.bundle, 0o700)
            os.chmod(self.artifacts, 0o700)
            os.chmod(self.artifacts / "candidate-binary.d", 0o600)
            with (self.artifacts / "candidate-binary.d").open("ab") as output:
                output.write(b"mutation")
            os.chmod(self.artifacts / "candidate-binary.d", 0o400)
            os.chmod(self.artifacts, 0o500)
            os.chmod(self.bundle, 0o500)
            with self.assertRaises(target.Refused):
                target.validate_build_bundle()


if __name__ == "__main__":
    unittest.main()
