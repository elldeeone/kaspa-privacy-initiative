#!/usr/bin/env python3
"""Hostile controls for the fixed assignment-only launch supervisor."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

import run_frozen_assignment_measurement as target


def assignment_receipt() -> dict:
    value = {
        "schema": "kpb-frozen-w1-round1-assignment-preparation/v3",
        "classification": "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_PREPARATION_ONLY",
        "historical_component_run_id": "2904ab69-cc9e-40ce-834f-07a56cd15bbc",
        "historical_component_source_instance_epoch_id": "d3d47403-5350-414d-a133-2447bb28da5a",
        "historical_component_source_closure_sha256": "8fcca654b4eb03b38a62c22648cd14323919279dc49d841751d3802683c66aae",
        "historical_component_selected_build_identity_sha256": "eee5536d5bcab041c7f98476ba6a5b8c4e8632373cc51b7087a568866072a55a",
        "historical_component_plan_sha256": "8b24a987f87d2bd9dca0b04f4622022eac0e04724af06ff761141169f0853482",
        "historical_source_bundle_manifest_sha256": "8db2a202c0c2547af841bade48f49168d093fa74ff18620573f041f6fcfbcfbd",
        "historical_component_expected_matrix_sha256": "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab",
        "selected_round": 1,
        "prepared_instances": 3,
        "prepared_witnesses": 12_949_818,
        "prepared_variables": 12_949_821,
        "historical_component_expected_constraints": 13_093_029,
        "current_preparer_observed_constraints": 0,
        "derived_public_inputs_decimal": list(target.EXPECTED_PUBLIC_INPUTS),
        "elapsed_seconds": 12.5,
        "peak_rss_kib": 2_000_000,
        "current_swap_kib": 0,
        "rounds_validated": 2,
        "output_proofs_verified": 12,
        "signature_relations_satisfied": 6,
    }
    for key in target.ASSIGNMENT_FALSE_FIELDS:
        value[key] = False
    for key in target.ASSIGNMENT_TRUE_FIELDS:
        value[key] = True
    assert set(value) == target.ASSIGNMENT_KEYS
    return value


def systemd_values(*, assignment_run: bool = True) -> dict[str, str]:
    output = "null" if assignment_run else "journal"
    return {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "exited",
        "Result": "success",
        "ExecMainStatus": "0",
        "RestrictAddressFamilies": "AF_UNIX",
        "SystemCallFilter": "~" + " ".join(sorted(target.STRICT_DENIED_NETWORK_SYSCALLS)),
        "SystemCallErrorNumber": "1",
        "NoNewPrivileges": "yes",
        "LimitCORE": "0",
        "MemoryMax": str(12 * 1024**3),
        "MemorySwapMax": "0",
        "MemoryPeak": str(3 * 1024**3),
        "MemorySwapCurrent": "0",
        "MemorySwapPeak": "0",
        "OOMPolicy": "stop",
        "NRestarts": "0",
        "UMask": "0077",
        "UnsetEnvironment": " ".join(target.ALL_UNSET_ENVIRONMENT),
        "Environment": " ".join(target.FIXED_ENVIRONMENT),
        "StandardInput": "null",
        "StandardOutput": output,
        "StandardError": output,
    }


class FixedInterfaceControls(unittest.TestCase):
    def test_cli_is_no_argument_and_does_not_execute_in_control(self):
        with mock.patch.object(target, "run_measurement") as run:
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(target.main(["--help"]), 2)
            self.assertIn("arguments-not-accepted", stderr.getvalue())
            run.assert_not_called()

        result = {
            "status": "synthetic-control",
            "proof": False,
            "authorization": False,
        }
        with mock.patch.object(target, "run_measurement", return_value=result) as run:
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(target.main([]), 0)
            self.assertEqual(json.loads(stdout.getvalue()), result)
            run.assert_called_once_with()

    def test_fixed_runtime_command_is_direct_and_strict(self):
        command = target._run_command()
        self.assertEqual(command[-4:-1], [str(target.PYTHON), "-I", "-c"])
        helper_source = command[-1]
        self.assertNotIn(str(target.BUILD_BINARY), command[:-1])
        self.assertIn(str(target.BUILD_BINARY), helper_source)
        self.assertIn(str(target.ASSIGNMENT_RECEIPT), helper_source)
        self.assertIn("os.memfd_create(", helper_source)
        self.assertIn("os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC", helper_source)
        for seal in (
            "fcntl.F_SEAL_WRITE",
            "fcntl.F_SEAL_GROW",
            "fcntl.F_SEAL_SHRINK",
            "fcntl.F_SEAL_SEAL",
        ):
            self.assertIn(seal, helper_source)
        self.assertIn(
            "os.execve(sealed_descriptor, [BINARY, RECEIPT], ENVIRONMENT)",
            helper_source,
        )
        self.assertNotIn("/bin/sh", command)
        self.assertNotIn("bash", command)
        self.assertIn("SystemCallFilter=~@network-io", command)
        self.assertIn("SystemCallErrorNumber=EPERM", command)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", command)
        self.assertIn("MemorySwapMax=0", command)
        self.assertIn("LimitCORE=0", command)
        self.assertIn("RAYON_NUM_THREADS=1", command)
        self.assertIn("MALLOC_ARENA_MAX=2", command)
        self.assertTrue(any("UnsetEnvironment=LD_PRELOAD" in value for value in command))
        self.assertTrue(
            any("DBUS_SESSION_BUS_ADDRESS" in value for value in command)
        )
        self.assertTrue(any("INVOCATION_ID" in value for value in command))
        self.assertIn("StandardInput=null", command)
        self.assertIn("StandardOutput=null", command)
        self.assertIn("StandardError=null", command)
        probe = target._probe_command()
        self.assertIn("StandardOutput=journal", probe)
        self.assertIn("StandardError=journal", probe)
        self.assertEqual(
            target.BUILD_PARENT,
            Path(
                "/home/luke/projects/kpi-intensive-2026-10-22/"
                "private-batch-w1-assignment-measurement-build-private-20261029-06"
            ),
        )
        self.assertFalse(target.BUILD_PARENT.is_relative_to(target.REPO_ROOT))
        self.assertEqual(
            target.sha256_bytes(target.canonical(command)),
            target.EXPECTED_RUN_COMMAND_SHA256,
        )
        self.assertEqual(
            target.sha256_bytes(helper_source.encode()),
            target.EXPECTED_IDENTITY_BOUND_HELPER_SHA256,
        )

    def test_preflight_opens_no_successful_socket_or_connection(self):
        source = target.NETWORK_PROBE_SOURCE
        self.assertIn("dict(os.environ) != expected_environment", source)
        for family in ("socket.AF_INET", "socket.AF_INET6", "socket.AF_UNIX"):
            self.assertIn(family, source)
        self.assertIn("errno.EPERM", source)
        for forbidden in ("connect(", "bind(", "listen(", "send(", "recv("):
            self.assertNotIn(forbidden, source)

    def test_artifact_hashes_must_be_fully_bound(self):
        with mock.patch.object(target, "EXPECTED_MANIFEST_SHA256", None):
            with self.assertRaises(target.Refused):
                target._require_bound_artifact_constants()

    def test_manager_environment_is_exact_then_fully_scrubbed(self):
        raw = ("\n".join(target.EXPECTED_MANAGER_ENVIRONMENT) + "\n").encode()
        completed = mock.Mock(returncode=0, stdout=raw, stderr=b"")
        with mock.patch.object(target.subprocess, "run", return_value=completed):
            evidence = target._validate_manager_environment()
        self.assertEqual(
            evidence["entry_count"], len(target.EXPECTED_MANAGER_ENVIRONMENT)
        )
        self.assertTrue(evidence["all_manager_entries_removed_or_replaced"])
        self.assertTrue(evidence["all_observed_systemd_injected_entries_removed"])
        self.assertEqual(
            set(value.split("=", 1)[0] for value in target.EXPECTED_MANAGER_ENVIRONMENT),
            set(
                value.split("=", 1)[0]
                for value in target.MANAGER_ENVIRONMENT_UNSETS
            ),
        )

        completed.stdout += b"UNEXPECTED_SOCKET=/tmp/ambient\n"
        with mock.patch.object(target.subprocess, "run", return_value=completed):
            with self.assertRaises(target.Refused):
                target._validate_manager_environment()


class AssignmentReceiptControls(unittest.TestCase):
    def test_outer_actions_preserve_matrix_free_assignment_boundary(self):
        actions = target._fixed_actions()
        self.assertTrue(actions["assignment_synthesis"])
        self.assertTrue(actions["assignment_shape_validation"])
        self.assertFalse(actions["current_r1cs_constraint_rows_recorded"])
        self.assertFalse(actions["current_r1cs_constraint_satisfaction"])
        self.assertFalse(actions["current_r1cs_lc_assignments_generated"])
        self.assertFalse(actions["aggregate_proof_generation"])
        self.assertFalse(actions["authorization"])

    def test_exact_honest_receipt_is_admitted(self):
        target.validate_assignment_receipt(assignment_receipt())
        self.assertEqual(
            target._derived_expected_public_inputs(), target.EXPECTED_PUBLIC_INPUTS
        )

    def test_extra_missing_fingerprint_and_wrong_public_inputs_refuse(self):
        cases = []
        extra = assignment_receipt()
        extra["secret_fingerprint"] = "0" * 64
        cases.append(extra)
        missing = assignment_receipt()
        missing.pop("schema")
        cases.append(missing)
        public = assignment_receipt()
        public["derived_public_inputs_decimal"][0] = "0" + public["derived_public_inputs_decimal"][0]
        cases.append(public)
        for value in cases:
            with self.assertRaises(target.Refused):
                target.validate_assignment_receipt(value)

    def test_every_false_and_true_security_claim_is_enforced(self):
        for key in target.ASSIGNMENT_FALSE_FIELDS:
            value = assignment_receipt()
            value[key] = True
            with self.subTest(key=key), self.assertRaises(target.Refused):
                target.validate_assignment_receipt(value)
        for key in target.ASSIGNMENT_TRUE_FIELDS:
            value = assignment_receipt()
            value[key] = False
            with self.subTest(key=key), self.assertRaises(target.Refused):
                target.validate_assignment_receipt(value)

    def test_wrong_counts_resources_and_nonfinite_elapsed_refuse(self):
        mutations = (
            ("historical_component_expected_constraints", 13_093_028),
            ("current_preparer_observed_constraints", 1),
            ("selected_round", True),
            ("prepared_variables", 12_949_820),
            ("peak_rss_kib", 0),
            ("current_swap_kib", 1),
            ("elapsed_seconds", float("nan")),
            ("elapsed_seconds", float("inf")),
            ("elapsed_seconds", -0.1),
        )
        for key, changed in mutations:
            value = assignment_receipt()
            value[key] = changed
            with self.subTest(key=key, changed=changed), self.assertRaises(target.Refused):
                target.validate_assignment_receipt(value)


class SystemdControls(unittest.TestCase):
    def test_exact_final_properties_are_admitted(self):
        evidence = target._validate_systemd_properties(
            systemd_values(), final=True, assignment_run=True
        )
        self.assertEqual(
            set(evidence["denied_network_syscalls"]),
            target.STRICT_DENIED_NETWORK_SYSCALLS,
        )
        self.assertEqual(evidence["memory_swap_max_bytes"], 0)
        self.assertEqual(evidence["memory_swap_peak_bytes"], 0)
        self.assertEqual(evidence["restart_count"], 0)

    def test_each_weakened_boundary_or_failed_result_refuses(self):
        mutations = {
            "families": ("RestrictAddressFamilies", "~"),
            "filter": ("SystemCallFilter", "~socket"),
            "errno": ("SystemCallErrorNumber", "13"),
            "privileges": ("NoNewPrivileges", "no"),
            "core": ("LimitCORE", "infinity"),
            "memory": ("MemoryMax", "infinity"),
            "swap": ("MemorySwapMax", "infinity"),
            "oom": ("OOMPolicy", "continue"),
            "restarts": ("NRestarts", "1"),
            "result": ("Result", "oom-kill"),
            "exit": ("ExecMainStatus", "1"),
            "swap-peak": ("MemorySwapPeak", "4096"),
            "preload": ("UnsetEnvironment", ""),
            "environment": ("Environment", "HOME=/tmp"),
            "stdin": ("StandardInput", "tty"),
            "stdout-journal": ("StandardOutput", "journal"),
            "stderr-journal": ("StandardError", "journal"),
        }
        for name, (key, changed) in mutations.items():
            values = systemd_values()
            values[key] = changed
            with self.subTest(name=name), self.assertRaises(target.Refused):
                target._validate_systemd_properties(
                    values, final=True, assignment_run=True
                )

    def test_show_parser_rejects_missing_duplicate_and_unknown(self):
        values = systemd_values()
        good = "".join(f"{key}={values[key]}\n" for key in target.SHOW_PROPERTIES)
        for raw in (
            good.replace("LoadState=loaded\n", ""),
            good + "LoadState=loaded\n",
            good + "PrivateNetwork=yes\n",
            "not-a-property\n",
        ):
            with self.assertRaises(target.Refused):
                target._parse_show(raw.encode())

    def test_journal_rejects_unsupported_oom_and_core_dump(self):
        for message in (
            b"proceeding without namespace",
            b"failed to apply sandbox",
            b"out of memory",
            b"oom-kill",
            b"code=dumped",
        ):
            completed = mock.Mock(returncode=0, stdout=message, stderr=b"")
            with mock.patch.object(target.subprocess, "run", return_value=completed):
                with self.subTest(message=message), self.assertRaises(target.Refused):
                    target._journal(target.RUN_UNIT)

    def test_transient_captures_distinct_live_final_and_stdout(self):
        running = systemd_values()
        running["SubState"] = "running"
        running["MemoryPeak"] = "1048576"
        final = systemd_values()
        started = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with (
            mock.patch.object(target.subprocess, "run", return_value=started),
            mock.patch.object(
                target,
                "_show_unit",
                side_effect=[(running, b"live\n"), (final, b"final\n")],
            ),
            mock.patch.object(target, "_journal", return_value=b"systemd lifecycle\n"),
            mock.patch.object(target, "_stop_unit"),
            mock.patch.object(target.time, "sleep"),
        ):
            evidence = target._run_transient(
                target.RUN_UNIT,
                target._run_command(),
                require_running_observation=True,
            )
        self.assertTrue(evidence["live"]["running_observed"])
        self.assertEqual(evidence["live"]["properties"]["sub_state"], "running")
        self.assertEqual(evidence["final"]["properties"]["sub_state"], "exited")
        self.assertEqual(evidence["stdout"]["transport"], "null")
        self.assertFalse(evidence["stdout"]["child_output_persisted"])
        self.assertFalse(evidence["stdout"]["success_marker_reliance"])
        self.assertEqual(evidence["stderr"]["transport"], "null")

        with self.assertRaises(TypeError):
            target._run_transient(
                target.RUN_UNIT,
                target._run_command(),
                marker="forbidden-marker-reliance",
                require_running_observation=True,
            )

        with (
            mock.patch.object(target.subprocess, "run", return_value=started),
            mock.patch.object(target, "_show_unit", return_value=(final, b"final\n")),
            mock.patch.object(target, "_stop_unit"),
            mock.patch.object(target.time, "sleep"),
        ):
            with self.assertRaises(target.Refused):
                target._run_transient(
                    target.RUN_UNIT,
                    target._run_command(),
                    require_running_observation=True,
                )


class IdentityBoundExecControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-assignment-identity-bound-exec-controls-"
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
        completed = target.subprocess.run(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=target.subprocess.PIPE,
            stderr=target.subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        for weakened in (
            source.replace("fcntl.F_SEAL_WRITE\n", "0\n", 1),
            source.replace("fcntl.F_SEAL_GROW\n", "0\n", 1),
            source.replace("fcntl.F_SEAL_SHRINK\n", "0\n", 1),
            source.replace("fcntl.F_SEAL_SEAL\n", "0\n", 1),
        ):
            completed = target.subprocess.run(
                [str(target.PYTHON), "-I", "-c", weakened],
                stdout=target.subprocess.PIPE,
                stderr=target.subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 70)

    def test_in_place_mutate_restore_cannot_change_sealed_exec(self):
        path, reference = self.fresh_true_binary("in-place-mutation")
        original = path.read_bytes()
        original_inode = os.lstat(path).st_ino
        ready = self.root / "sealed-memfd-ready"
        release = self.root / "release-sealed-exec"
        source = self.source(path, reference)
        source = source.replace("import stat\n", "import stat\nimport time\n", 1)
        needle = (
            "    os.execve(sealed_descriptor, [BINARY, RECEIPT], ENVIRONMENT)"
        )
        self.assertEqual(source.count(needle), 1)
        source = source.replace(
            needle,
            f"    open({str(ready)!r}, 'x').close()\n"
            f"    while not os.path.exists({str(release)!r}):\n"
            "        time.sleep(0.01)\n"
            + needle,
            1,
        )
        process = target.subprocess.Popen(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=target.subprocess.PIPE,
            stderr=target.subprocess.PIPE,
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
            self.assertEqual(process.returncode, 0)
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"")
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

    def test_wrong_inode_and_swap_restore_refuse(self):
        path, reference = self.fresh_true_binary("wrong-inode")
        source = self.source(path, reference)
        original = self.root / "wrong-inode-original"
        path.replace(original)
        shutil.copyfile(original, path)
        os.chmod(path, 0o500)
        self.assertEqual(target.sha256_bytes(path.read_bytes()), reference["sha256"])
        self.assertNotEqual(os.lstat(path).st_ino, reference["inode"])
        completed = target.subprocess.run(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=target.subprocess.PIPE,
            stderr=target.subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 70)

        path, reference = self.fresh_true_binary("swap-restore")
        source = self.source(path, reference)
        before_open = self.root / "before-open"
        after_open = self.root / "after-open"
        self.assertEqual(source.count("source_descriptor = os.open("), 1)
        self.assertEqual(
            source.count("    opened = os.fstat(source_descriptor)"), 1
        )
        source = source.replace(
            "source_descriptor = os.open(",
            f"open({str(before_open)!r}, 'x').close()\n"
            "import time\ntime.sleep(0.50)\nsource_descriptor = os.open(",
        ).replace(
            "    opened = os.fstat(source_descriptor)",
            f"    open({str(after_open)!r}, 'x').close()\n"
            "    time.sleep(0.50)\n    opened = os.fstat(source_descriptor)",
        )
        process = target.subprocess.Popen(
            [str(target.PYTHON), "-I", "-c", source],
            stdout=target.subprocess.PIPE,
            stderr=target.subprocess.PIPE,
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
        self.assertEqual(process.returncode, 70)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")
        self.assertEqual(target.sha256_bytes(path.read_bytes()), reference["sha256"])
        self.assertEqual(os.lstat(path).st_ino, reference["inode"])


class FilesystemControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kpb-assignment-launch-controls-")
        self.root = Path(self.temporary.name) / "run"
        self.root.mkdir(mode=0o700)

    def tearDown(self):
        for current_raw, directories, files in os.walk(
            self.temporary.name, topdown=False, followlinks=False
        ):
            current = Path(current_raw)
            try:
                os.chmod(current, 0o700, follow_symlinks=False)
            except FileNotFoundError:
                pass
            for name in files:
                path = current / name
                try:
                    os.chmod(path, 0o600, follow_symlinks=False)
                except FileNotFoundError:
                    pass
            for name in directories:
                path = current / name
                if path.is_symlink():
                    path.unlink(missing_ok=True)
        self.temporary.cleanup()

    def test_stable_file_rejects_symlink_hardlink_and_wrong_mode(self):
        good = self.root / "good"
        good.write_bytes(b"fixed\n")
        os.chmod(good, 0o400)
        target._stable_file(good, 0o400)

        linked = self.root / "linked"
        os.link(good, linked)
        with self.assertRaises(target.Refused):
            target._stable_file(good, 0o400)
        linked.unlink()

        symlink = self.root / "symlink"
        symlink.symlink_to(good)
        with self.assertRaises(target.Refused):
            target._stable_file(symlink, 0o400)
        symlink.unlink()

        os.chmod(good, 0o600)
        with self.assertRaises(target.Refused):
            target._stable_file(good, 0o400)

    def test_launch_receipt_publication_is_create_new_and_sealed(self):
        assignment = self.root / target.ASSIGNMENT_RECEIPT.name
        assignment.write_bytes(b"synthetic assignment evidence\n")
        os.chmod(assignment, 0o400)
        source = self.root / target.SUPERVISOR_SOURCE.name
        launch = self.root / target.LAUNCH_RECEIPT.name
        receipt = target._receipt_identity(
            {
                "schema": target.RECEIPT_SCHEMA,
                "classification": target.CLASSIFICATION,
                "authorization": False,
            }
        )
        with (
            mock.patch.object(target, "RUN_ROOT", self.root),
            mock.patch.object(target, "ASSIGNMENT_RECEIPT", assignment),
            mock.patch.object(target, "SUPERVISOR_SOURCE", source),
            mock.patch.object(target, "LAUNCH_RECEIPT", launch),
            mock.patch.object(target, "LOCAL_ROOT", Path(self.temporary.name)),
        ):
            result = target._publish_launch_evidence(b"fixed supervisor\n", receipt)
            self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o500)
            self.assertEqual(set(os.listdir(self.root)), {assignment.name, source.name, launch.name})
            for path in (assignment, source, launch):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(result["launch_receipt_sha256"], target.sha256_bytes(target.canonical(receipt)))
            with self.assertRaises((target.Refused, FileExistsError, PermissionError)):
                target._publish_launch_evidence(b"replacement\n", receipt)


class JsonAndDependencyControls(unittest.TestCase):
    def test_duplicate_json_key_refuses(self):
        with self.assertRaises(target.Refused):
            target._unique_json(b'{"a":1,"a":2}\n')

    def test_dep_info_requires_one_unique_absolute_rule(self):
        target_name = "/tmp/target"
        good = f"{target_name}: /tmp/source-a /tmp/source-b\n".encode()
        self.assertEqual(target._parse_dep_info(good), (target_name, ["/tmp/source-a", "/tmp/source-b"]))
        for raw in (
            b"relative-without-rule\n",
            f"{target_name}: /tmp/source-a /tmp/source-a\n".encode(),
            f"{target_name}: /tmp/source-a\nextra: /tmp/source-b\n".encode(),
            f"{target_name}: /tmp/source-a".encode(),
        ):
            with self.assertRaises(target.Refused):
                target._parse_dep_info(raw)


class SealedBuildControls(unittest.TestCase):
    def test_exact_reviewed_build_is_admitted_read_only(self):
        result = target.validate_build_bundle()
        self.assertEqual(
            result["references"]["binary"]["sha256"],
            target.EXPECTED_BINARY_SHA256,
        )
        self.assertEqual(result["source_snapshot"]["member_count"], 93)
        self.assertEqual(result["dependency_count"], 43)
        self.assertEqual(result["raw_dependency_count"], 47)
        self.assertEqual(result["canonical_duplicate_count"], 4)
        self.assertTrue(result["assignment_only"])
        self.assertTrue(result["prover_sources_absent"])

    def test_hostile_dep_mapping_and_prover_inclusion_refuse(self):
        manifest_raw, _ = target._stable_file(target.BUILD_MANIFEST, 0o400)
        inner_raw, _ = target._stable_file(target.BUILD_RECEIPT, 0o400)
        outer_raw, _ = target._stable_file(target.BUILD_OUTER_RECEIPT, 0o400)
        normalized_raw, _ = target._stable_file(target.BUILD_DEP_INFO, 0o400)
        original_raw, _ = target._stable_file(
            target.BUILD_ORIGINAL_DEP_INFO, 0o400
        )
        manifest, _ = target._validate_manifest(manifest_raw)
        inner = target._unique_json(inner_raw)
        original = target._unique_json(outer_raw)

        changed = copy.deepcopy(original)
        changed["dep_info"]["raw_cargo_derivation"]["mappings"][0][
            "inode"
        ] += 1
        with self.assertRaises(target.Refused):
            target._validate_dep_info_derivation(
                changed, inner, manifest, normalized_raw, original_raw
            )

        changed = copy.deepcopy(original)
        changed["dep_info"]["dependency_relatives"][0] = (
            target.FORBIDDEN_PROVER_SOURCE
        )
        with self.assertRaises(target.Refused):
            target._validate_dep_info_derivation(
                changed, inner, manifest, normalized_raw, original_raw
            )


if __name__ == "__main__":
    unittest.main()
