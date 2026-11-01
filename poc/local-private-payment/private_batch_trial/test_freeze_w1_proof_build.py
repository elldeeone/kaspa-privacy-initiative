#!/usr/bin/env python3
"""Hostile synthetic controls for the inert fixed W1 proof-build freezer."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import freeze_current_w1_source_build as core
import freeze_w1_proof_build as target
import run_frozen_w1_proof as supervisor


TEST_PROBE_UNIT = target.PROBE_UNIT_PREFIX + "1" * 32
TEST_BUILD_UNIT = target.BUILD_UNIT_PREFIX + "2" * 32
TEST_CARGO_IDENTITY = {
    "bytes": 123456,
    "sha256": "a" * 64,
    "mtime_ns": 123456789,
    "ctime_ns": 123456790,
}


class SyntheticSource:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-proof-build-freezer-controls-"
        )
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.output = self.root / "output"
        self.source.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        self._write(
            "poc/local-private-payment/private-batch-relation/Cargo.toml",
            b'''[package]\nname="relation"\nversion="0.1.0"\nedition="2024"\n\n[dependencies]\nauth={path="../native-authority/native-core"}\nnative={path="../native-authority/vendor/native-relation"}\noutput={path="../private_batch_trial/auth_exit"}\n''',
        )
        self._write(
            "poc/local-private-payment/private-batch-relation/Cargo.lock",
            b"# synthetic reviewed lock\nversion = 4\n",
        )
        self._write(
            "poc/local-private-payment/native-authority/native-core/Cargo.toml",
            b'''[package]\nname="native-core"\nversion="0.1.0"\nedition="2024"\n\n[dependencies]\nnative={path="../vendor/native-relation"}\n''',
        )
        self._write(
            "poc/local-private-payment/native-authority/vendor/native-relation/Cargo.toml",
            b'''[package]\nname="native-relation"\nversion="0.1.0"\nedition="2024"\n''',
        )
        self._write(
            "poc/local-private-payment/private_batch_trial/auth_exit/Cargo.toml",
            b'''[package]\nname="auth-exit"\nversion="0.1.0"\nedition="2024"\n\n[dependencies]\nauthority={path="../../native-authority/native-core"}\nnative={path="../../native-authority/vendor/native-relation"}\n''',
        )
        for relative in sorted(target.REQUIRED_DEPENDENCY_RELATIVES):
            self._write(relative, f"// synthetic {relative}\n".encode())

    def _write(self, relative: str, raw: bytes) -> Path:
        path = self.source / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def begin(self):
        with mock.patch.object(target, "REPO_ROOT", self.source):
            return target._begin_proof_candidate(
                self.source, self.output, target.OUTPUT_NAME
            )

    def reviewed(self):
        result = {}
        for relative in target.REVIEWED_PROOF_SEAM_RELATIVES:
            identity = target._stable_file_metadata_identity(
                self.source / relative
            )
            result[relative] = {
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
                "device": identity["device"],
                "inode": identity["inode"],
                "mtime_ns": identity["mtime_ns"],
                "ctime_ns": identity["ctime_ns"],
            }
        return result

    @staticmethod
    def _unseal(root: Path) -> None:
        if not root.exists():
            return
        for current_raw, directories, files in os.walk(root, topdown=True):
            current = Path(current_raw)
            try:
                os.chmod(current, 0o700, follow_symlinks=False)
            except FileNotFoundError:
                pass
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

    def close(self):
        self._unseal(self.root)
        self.temporary.cleanup()


class SyntheticCase(unittest.TestCase):
    def setUp(self):
        self.fixture = SyntheticSource()

    def tearDown(self):
        self.fixture.close()

    def cargo_output(
        self,
        session,
        example_name,
        required_dependencies,
        dependencies=None,
        target_path=None,
    ):
        release = session.target_root / "release" / "examples"
        release.mkdir(mode=0o700, parents=True, exist_ok=True)
        binary = release / example_name
        binary.write_bytes(
            f"synthetic {example_name} build; never executed\n".encode()
        )
        os.chmod(binary, 0o700)
        os.link(binary, release / f"{example_name}-hash")
        if dependencies is None:
            dependencies = sorted(required_dependencies)
        dependency_paths = [
            str(session.snapshot_root / relative) for relative in dependencies
        ]
        dep_info = binary.with_suffix(".d")
        dep_info.write_text(
            f"{target_path or binary}: {' '.join(dependency_paths)}\n"
        )
        return binary, dep_info

    def cargo_outputs(self, session, dependencies=None, target_path=None):
        return self.cargo_output(
            session,
            target.PROOF_EXAMPLE_NAME,
            target.REQUIRED_PROOF_DEPENDENCY_RELATIVES,
            dependencies,
            target_path,
        )

    def verifier_cargo_outputs(self, session, dependencies=None, target_path=None):
        return self.cargo_output(
            session,
            target.VERIFIER_EXAMPLE_NAME,
            target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES,
            dependencies,
            target_path,
        )

    def derive(
        self,
        session,
        binary,
        dep_info,
        required_dependencies=None,
        closure_label="proof",
    ):
        if required_dependencies is None:
            required_dependencies = target.REQUIRED_PROOF_DEPENDENCY_RELATIVES
        return target._derive_dep_info_members(
            dep_info.read_bytes(),
            snapshot_root=session.snapshot_root,
            target_root=session.target_root,
            original_source_root=session.source_root,
            snapshot_refs=session.snapshot_refs,
            expected_target=binary,
            required_dependency_relatives=required_dependencies,
            closure_label=closure_label,
        )

    def detached_output(self, session, binary, relatives, stem):
        admission = session.target_root / "admission"
        admission.mkdir(mode=0o700, exist_ok=True)
        detached = admission / stem
        raw, _ = target._stable_cargo_hardlinked_binary(binary)
        core._write_new(detached, raw, 0o500)
        dep_raw = target._admission_dep_info(
            detached_target=detached,
            snapshot_root=session.snapshot_root,
            relatives=relatives,
        )
        dep_info = admission / f"{stem}.d"
        core._write_new(dep_info, dep_raw, 0o400)
        return detached, dep_info

    def detached_outputs(self, session, binary, relatives):
        return self.detached_output(session, binary, relatives, "proof-binary")

    def dual_outputs(self, session):
        proof_cargo, proof_cargo_dep = self.cargo_outputs(session)
        verifier_cargo, verifier_cargo_dep = self.verifier_cargo_outputs(session)
        proof_relatives, _ = self.derive(
            session, proof_cargo, proof_cargo_dep
        )
        verifier_relatives, _ = self.derive(
            session,
            verifier_cargo,
            verifier_cargo_dep,
            target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES,
            "verifier",
        )
        proof_binary, proof_dep = self.detached_output(
            session, proof_cargo, proof_relatives, "proof-binary"
        )
        verifier_binary, verifier_dep = self.detached_output(
            session, verifier_cargo, verifier_relatives, "verifier-binary"
        )
        return {
            "proof_cargo": proof_cargo,
            "verifier_cargo": verifier_cargo,
            "proof_relatives": proof_relatives,
            "verifier_relatives": verifier_relatives,
            "proof_binary": proof_binary,
            "proof_dep": proof_dep,
            "verifier_binary": verifier_binary,
            "verifier_dep": verifier_dep,
        }

    @staticmethod
    def finalize(session, outputs):
        return target._finalize_proof_candidate(
            session,
            proof_binary=outputs["proof_binary"],
            proof_admission_dep_info=outputs["proof_dep"],
            proof_dependency_relatives=outputs["proof_relatives"],
            verifier_binary=outputs["verifier_binary"],
            verifier_admission_dep_info=outputs["verifier_dep"],
            verifier_dependency_relatives=outputs["verifier_relatives"],
        )


class ReviewGateControls(unittest.TestCase):
    def test_gate_is_unbound_and_refuses_before_any_side_effect(self):
        self.assertIsNone(target.REVIEWED_PROOF_SEAM_SHA256)
        self.assertFalse(target._review_gate_status()["bound"])
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/examples/"
            "verify_frozen_w1_round1_receipt.rs",
            target.REVIEWED_PROOF_SEAM_RELATIVES,
        )
        with mock.patch.object(target, "_validate_fixed_host_paths") as validate:
            with mock.patch.object(target, "_create_private_parent") as create:
                with mock.patch.object(target, "_run_transient_unit") as run:
                    with self.assertRaisesRegex(
                        core.Refused, "proof-seam-review-go-not-bound"
                    ):
                        target.run_freeze()
        validate.assert_not_called()
        create.assert_not_called()
        run.assert_not_called()

    def test_main_reports_stop_without_running_freezer(self):
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = target.main([])
        self.assertEqual(result, 2)
        value = json.loads(stderr.getvalue())
        self.assertEqual(value["status"], "REFUSED")
        self.assertIn("proof-seam-review-go-not-bound", value["reason"])
        self.assertFalse(value["review_gate"]["bound"])

    def test_malformed_or_partial_review_bindings_refuse(self):
        cases = ({}, {target.REVIEWED_PROOF_SEAM_RELATIVES[0]: "0" * 64})
        for bindings in cases:
            with self.subTest(bindings=bindings):
                with mock.patch.object(
                    target, "REVIEWED_PROOF_SEAM_SHA256", bindings
                ):
                    with self.assertRaises(core.Refused):
                        target._require_reviewed_source_bindings()


class FixedInterfaceControls(unittest.TestCase):
    def test_cli_accepts_only_no_arguments(self):
        with mock.patch.object(target, "run_freeze") as run:
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                result = target.main(["--help"])
        self.assertEqual(result, 2)
        self.assertIn("arguments-not-accepted", stderr.getvalue())
        run.assert_not_called()

    def test_fixed_command_is_exact_build_only(self):
        snapshot = Path("/tmp/fixed-proof-snapshot")
        build_target = Path("/tmp/fixed-proof-target")
        command = target._cargo_build_command(
            snapshot, build_target, TEST_BUILD_UNIT, TEST_CARGO_IDENTITY
        )
        python = command.index(str(target.PYTHON))
        environment = command.index(str(target.ENV))
        self.assertEqual(command.count(str(target.CARGO)), 0)
        self.assertEqual(command.count(str(target.PYTHON)), 1)
        self.assertEqual(command.count(str(target.ENV)), 1)
        self.assertEqual(
            command[environment:python],
            [str(target.ENV), "-i", *target._cargo_environment(build_target)],
        )
        self.assertNotIn("--setenv", command)
        self.assertIn(
            "UnsetEnvironment=" + " ".join(target.BOOTSTRAP_UNSET_ENVIRONMENT),
            command,
        )
        for stream in ("StandardInput", "StandardOutput", "StandardError"):
            self.assertIn(f"{stream}=null", command)
        self.assertEqual(
            command[python:],
            [
                str(target.PYTHON), "-I", "-c",
                target.BUILD_BOOTSTRAP_SOURCE, str(build_target),
                TEST_CARGO_IDENTITY["sha256"],
                str(TEST_CARGO_IDENTITY["bytes"]),
                str(TEST_CARGO_IDENTITY["mtime_ns"]),
                str(TEST_CARGO_IDENTITY["ctime_ns"]),
            ],
        )
        self.assertIn(str(target.CARGO), target.BUILD_BOOTSTRAP_SOURCE)
        self.assertIn(repr(target.CARGO_BUILD_ARGUMENTS), target.BUILD_BOOTSTRAP_SOURCE)
        self.assertIn("CARGO_NET_OFFLINE=true", command)
        self.assertIn(f"CARGO_TARGET_DIR={build_target}", command)
        self.assertIn("PATH=/usr/bin:/bin", command)
        self.assertNotIn("PATH=/home/luke/.cargo/bin:/usr/bin:/bin", command)

    def test_wrong_feature_example_or_verb_refuses(self):
        snapshot = Path("/tmp/fixed-proof-snapshot")
        build_target = Path("/tmp/fixed-proof-target")
        good = target._cargo_build_command(
            snapshot, build_target, TEST_BUILD_UNIT, TEST_CARGO_IDENTITY
        )
        bootstrap = good.index(target.BUILD_BOOTSTRAP_SOURCE)
        mutations = []
        wrong_feature = list(good)
        wrong_feature[bootstrap] = target.BUILD_BOOTSTRAP_SOURCE.replace(
            target.FEATURE_NAME, "offline-w1-preparer"
        )
        mutations.append(wrong_feature)
        wrong_example = list(good)
        wrong_example[bootstrap] = target.BUILD_BOOTSTRAP_SOURCE.replace(
            target.PROOF_EXAMPLE_NAME, "wrong-example"
        )
        mutations.append(wrong_example)
        wrong_verifier = list(good)
        wrong_verifier[bootstrap] = target.BUILD_BOOTSTRAP_SOURCE.replace(
            target.VERIFIER_EXAMPLE_NAME, "wrong-verifier"
        )
        mutations.append(wrong_verifier)
        run = list(good)
        run[bootstrap] = target.BUILD_BOOTSTRAP_SOURCE.replace(
            "build", "run", 1
        )
        mutations.append(run)
        no_clean_environment = list(good)
        no_clean_environment.remove("-i")
        mutations.append(no_clean_environment)
        inherited_environment = list(good)
        inherited_environment.insert(
            good.index(str(target.PYTHON)), "HOSTILE_INHERITED_VALUE=1"
        )
        mutations.append(inherited_environment)
        wrong_launcher = list(good)
        wrong_launcher[wrong_launcher.index(str(target.ENV))] = "/bin/env"
        mutations.append(wrong_launcher)
        relaxed_syscalls = list(good)
        filter_index = next(
            index
            for index, value in enumerate(relaxed_syscalls)
            if value.startswith("SystemCallFilter=")
        )
        relaxed_syscalls[filter_index] = "SystemCallFilter=~connect"
        mutations.append(relaxed_syscalls)
        for command in mutations:
            with self.subTest(command=command[-8:]), self.assertRaises(core.Refused):
                target._assert_build_only_command(
                    command, snapshot, build_target,
                    TEST_BUILD_UNIT, TEST_CARGO_IDENTITY,
                )

    def test_probe_exercises_denied_ip_and_local_spawn(self):
        source = target._network_probe_command(TEST_PROBE_UNIT)[-1]
        self.assertIn("socket.AF_INET", source)
        self.assertIn("socket.AF_INET6", source)
        self.assertIn("socket.socketpair", source)
        self.assertIn("os.write(left.fileno()", source)
        self.assertIn("os.read(right.fileno()", source)
        self.assertNotIn("left.send", source)
        self.assertNotIn("right.recv", source)
        self.assertIn('subprocess.run(["/bin/true"], check=True)', source)
        self.assertIn("standalone.connect", source)
        self.assertIn('os.listdir("/proc/self/fd")', source)
        self.assertIn('!= "/dev/null"', source)
        self.assertIn("sorted(live_descriptors) != [0, 1, 2]", source)
        self.assertIn("datagram.sendto", source)
        self.assertIn("datagram.recvfrom", source)
        self.assertIn("ctypes.CDLL", source)
        for number in (425, 426, 427):
            self.assertIn(f"({number},", source)
        self.assertIn("errno.EPERM, errno.ENOSYS", source)


class SystemdPropertyControls(unittest.TestCase):
    @staticmethod
    def values() -> dict[str, str]:
        return {
            "LoadState": "loaded", "ActiveState": "active",
            "SubState": "exited", "Result": "success", "ExecMainStatus": "0",
            "RestrictAddressFamilies": "AF_UNIX",
            "SystemCallFilter": "~" + " ".join(target.DENIED_BUILD_NETWORK_SYSCALLS),
            "SystemCallErrorNumber": "1", "SystemCallArchitectures": "native",
            "NoNewPrivileges": "yes",
            "LimitCORE": "0", "MemoryMax": str(20 * 1024**3),
            "MemorySwapMax": "0", "UMask": "0077",
            "UnsetEnvironment": " ".join(target.BOOTSTRAP_UNSET_ENVIRONMENT),
            "StandardInput": "null", "StandardOutput": "null",
            "StandardError": "null",
            "InvocationID": "3" * 32, "ExecMainPID": "12345",
            "Sockets": "", "TriggeredBy": "", "Triggers": "",
        }

    def test_exact_properties_admit_and_each_relaxation_refuses(self):
        good = self.values()
        evidence = target._validate_active_unit_properties(good)
        self.assertEqual(evidence["restrict_address_families"], "AF_UNIX")
        self.assertTrue(
            {
                "connect", "bind", "listen", "accept", "accept4",
                "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg",
                "recvmmsg", "io_uring_setup", "io_uring_enter",
                "io_uring_register", "pidfd_getfd", "ptrace",
                "process_vm_readv", "process_vm_writev",
            }.issubset(target.DENIED_BUILD_NETWORK_SYSCALLS)
        )
        self.assertTrue(
            {"socket", "socketpair"}.isdisjoint(
                target.DENIED_BUILD_NETWORK_SYSCALLS
            )
        )
        cases = {
            "families": ("RestrictAddressFamilies", "AF_UNIX AF_INET"),
            "filter": ("SystemCallFilter", "~connect"),
            "errno": ("SystemCallErrorNumber", "13"),
            "architectures": ("SystemCallArchitectures", "native x86"),
            "privilege": ("NoNewPrivileges", "no"),
            "core": ("LimitCORE", "infinity"),
            "memory": ("MemoryMax", "infinity"),
            "swap": ("MemorySwapMax", "infinity"),
            "umask": ("UMask", "0022"),
            "unset": ("UnsetEnvironment", "LD_PRELOAD"),
            "stdin": ("StandardInput", "tty"),
            "stdout": ("StandardOutput", "journal"),
            "stderr": ("StandardError", "journal"),
            "invocation": ("InvocationID", ""),
            "pid": ("ExecMainPID", "0"),
            "sockets": ("Sockets", "hostile.socket"),
            "triggered": ("TriggeredBy", "hostile.socket"),
        }
        for name, (key, value) in cases.items():
            values = dict(good)
            values[key] = value
            with self.subTest(name=name), self.assertRaises(core.Refused):
                target._validate_active_unit_properties(values)

    def test_parse_requires_exact_unique_properties(self):
        values = self.values()
        good = "".join(f"{key}={values[key]}\n" for key in target.SHOW_PROPERTIES)
        self.assertEqual(target._parse_show(good.encode()), values)
        for raw in (
            good.replace("LoadState=loaded\n", ""),
            good + "LoadState=loaded\n",
            good + "PrivateNetwork=yes\n",
        ):
            with self.assertRaises(core.Refused):
                target._parse_show(raw.encode())

    def test_warning_loaded_or_historical_unit_refuses(self):
        synchronized = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        warning = mock.Mock(returncode=0, stdout=b"failed to apply sandbox", stderr=b"")
        with mock.patch.object(
            target.subprocess, "run",
            side_effect=(synchronized, warning, warning),
        ):
            with self.assertRaisesRegex(core.Refused, "systemd-restriction-warning"):
                target._unit_journal(TEST_PROBE_UNIT, "3" * 32, 12345)
        loaded = mock.Mock(returncode=0, stdout=b"loaded\n", stderr=b"")
        with mock.patch.object(target.subprocess, "run", return_value=loaded):
            with self.assertRaisesRegex(core.Refused, "transient-unit-loaded-used"):
                target._inspect_pristine_unit(TEST_BUILD_UNIT)
        not_found = mock.Mock(returncode=0, stdout=b"not-found\n", stderr=b"")
        historical = mock.Mock(returncode=0, stdout=b"prior journal\n", stderr=b"")
        with mock.patch.object(
            target.subprocess, "run", side_effect=(not_found, historical)
        ):
            with self.assertRaisesRegex(
                core.Refused, "transient-unit-historical-journal-not-empty"
            ):
                target._inspect_pristine_unit(TEST_BUILD_UNIT)

    def test_unit_ids_are_unpredictable_per_run_not_fixed_suffixes(self):
        with mock.patch.object(target.secrets, "token_hex", return_value="a" * 32):
            probe = target._fresh_unit_name(target.PROBE_UNIT_PREFIX)
        with mock.patch.object(target.secrets, "token_hex", return_value="b" * 32):
            build = target._fresh_unit_name(target.BUILD_UNIT_PREFIX)
        self.assertEqual(probe, target.PROBE_UNIT_PREFIX + "a" * 32)
        self.assertEqual(build, target.BUILD_UNIT_PREFIX + "b" * 32)
        self.assertEqual(target._unit_role(probe), "network_probe")
        self.assertEqual(target._unit_role(build), "cargo_build")
        for stale in (
            "kpb-w1-proof-freeze-netprobe-20261029-02",
            "kpb-w1-proof-freeze-build-20261029-02",
        ):
            with self.assertRaises(core.Refused):
                target._unit_role(stale)


class UnitIdentityLedgerControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-proof-unit-ledger-controls-"
        )
        self.root = Path(self.temporary.name)
        self.ledger = self.root / target.UNIT_LEDGER_NAME
        self.ledger.mkdir(mode=0o700)
        self.run_identity = target._unit_record_identity(
            {
                "schema": target.UNIT_RUN_IDENTITY_SCHEMA,
                "run_id": "00000000-0000-4000-8000-000000000000",
                "probe_unit_name": TEST_PROBE_UNIT,
                "build_unit_name": TEST_BUILD_UNIT,
                "unit_names_cryptographically_unpredictable": True,
                "unit_names_reserved_before_inspection_or_start": True,
                "authorization": False,
            }
        )
        core._write_new(
            self.ledger / "RUN-IDENTITY.json",
            core.canonical(self.run_identity),
            0o400,
        )

    def tearDown(self):
        SyntheticSource._unseal(self.root)
        self.temporary.cleanup()

    @staticmethod
    def pristine():
        show = [
            str(target.SYSTEMCTL), "--user", "show",
            f"{TEST_BUILD_UNIT}.service", "--property=LoadState", "--value",
            "--no-pager",
        ]
        journal = [
            str(target.JOURNALCTL), "--user", "--unit",
            f"{TEST_BUILD_UNIT}.service", "--no-pager", "--quiet",
            "--output=export",
        ]
        return {
            "load_state": "not-found",
            "systemctl_command_sha256": core.sha256_bytes(core.canonical(show)),
            "systemctl_stdout_bytes": len(b"not-found\n"),
            "systemctl_stdout_sha256": core.sha256_bytes(b"not-found\n"),
            "historical_journal_command_sha256": core.sha256_bytes(
                core.canonical(journal)
            ),
            "historical_journal_bytes": 0,
            "historical_journal_sha256": core.sha256_bytes(b""),
            "historical_journal_empty": True,
        }

    def test_reservation_and_consumption_are_durable_before_start(self):
        command = target._cargo_build_command(
            Path("/tmp/snapshot"), Path("/tmp/target"),
            TEST_BUILD_UNIT, TEST_CARGO_IDENTITY,
        )
        pristine = self.pristine()
        with mock.patch.object(
            target, "_inspect_pristine_unit", side_effect=(pristine, pristine)
        ) as inspect:
            evidence = target._reserve_unit_identity(
                TEST_BUILD_UNIT, command, self.ledger
            )
        self.assertEqual(inspect.call_count, 2)
        unit_root = Path(evidence["unit_root"])
        self.assertEqual(stat.S_IMODE(unit_root.stat().st_mode), 0o500)
        self.assertEqual(
            set(os.listdir(unit_root)), {"RESERVATION.json", "CONSUMPTION.json"}
        )
        for name in os.listdir(unit_root):
            path = unit_root / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertEqual(path.stat().st_nlink, 1)
        consumption = json.loads((unit_root / "CONSUMPTION.json").read_bytes())
        self.assertTrue(consumption["identity_consumed_before_start"])
        self.assertFalse(consumption["systemd_start_dispatched"])
        self.assertFalse(evidence["start_dispatched_after_consumption"])

    def test_not_found_with_prior_reservation_refuses(self):
        command = target._cargo_build_command(
            Path("/tmp/snapshot"), Path("/tmp/target"),
            TEST_BUILD_UNIT, TEST_CARGO_IDENTITY,
        )
        unit_root = self.ledger / f"{TEST_BUILD_UNIT}.identity"
        unit_root.mkdir(mode=0o500)
        with mock.patch.object(target, "_inspect_pristine_unit") as inspect:
            with self.assertRaisesRegex(core.Refused, "unit-identity-prior-reservation"):
                target._reserve_unit_identity(TEST_BUILD_UNIT, command, self.ledger)
        inspect.assert_not_called()

    def test_not_found_with_historical_journal_retains_reservation(self):
        command = target._cargo_build_command(
            Path("/tmp/snapshot"), Path("/tmp/target"),
            TEST_BUILD_UNIT, TEST_CARGO_IDENTITY,
        )
        not_found = mock.Mock(returncode=0, stdout=b"not-found\n", stderr=b"")
        historical = mock.Mock(returncode=0, stdout=b"old entry\n", stderr=b"")
        with mock.patch.object(
            target.subprocess, "run", side_effect=(not_found, historical)
        ):
            with self.assertRaisesRegex(
                core.Refused, "transient-unit-historical-journal-not-empty"
            ):
                target._reserve_unit_identity(TEST_BUILD_UNIT, command, self.ledger)
        unit_root = self.ledger / f"{TEST_BUILD_UNIT}.identity"
        self.assertEqual(stat.S_IMODE(unit_root.stat().st_mode), 0o500)
        self.assertEqual(
            set(os.listdir(unit_root)), {"RESERVATION.json", "CONSUMPTION.json"}
        )
        for name in os.listdir(unit_root):
            self.assertEqual(stat.S_IMODE((unit_root / name).stat().st_mode), 0o400)

    def test_start_failure_retains_consumed_identity_records(self):
        command = target._cargo_build_command(
            Path("/tmp/snapshot"), Path("/tmp/target"),
            TEST_BUILD_UNIT, TEST_CARGO_IDENTITY,
        )
        pristine = self.pristine()
        failed_start = mock.Mock(returncode=1, stdout=b"", stderr=b"start refused")
        with mock.patch.object(
            target, "_inspect_pristine_unit", side_effect=(pristine, pristine)
        ):
            with mock.patch.object(
                target.subprocess, "run", return_value=failed_start
            ):
                with self.assertRaisesRegex(core.Refused, "systemd-unit-start"):
                    target._run_transient_unit(
                        TEST_BUILD_UNIT, command, self.ledger
                    )
        unit_root = self.ledger / f"{TEST_BUILD_UNIT}.identity"
        self.assertEqual(stat.S_IMODE(unit_root.stat().st_mode), 0o500)
        self.assertEqual(
            set(os.listdir(unit_root)), {"RESERVATION.json", "CONSUMPTION.json"}
        )


class ManifestControls(SyntheticCase):
    def test_full_reviewed_union_binds_manifest_snapshot_and_metadata(self):
        reviewed = self.fixture.reviewed()
        session = self.fixture.begin()
        binding = target._review_snapshot_binding(reviewed, session)
        self.assertEqual(
            binding["reviewed_member_count"],
            len(target.REVIEWED_PROOF_SEAM_RELATIVES),
        )
        self.assertEqual(len(target.REVIEWED_PROOF_SEAM_RELATIVES), 14)
        self.assertEqual(
            [entry["relative_path"] for entry in binding["entries"]],
            list(target.REVIEWED_PROOF_SEAM_RELATIVES),
        )
        self.assertEqual(
            target._require_review_snapshot_binding_unchanged(
                binding, reviewed, session
            ),
            binding,
        )

    def test_transient_snapshot_modify_restore_during_build_refuses(self):
        reviewed = self.fixture.reviewed()
        session = self.fixture.begin()
        binding = target._review_snapshot_binding(reviewed, session)
        relative = target.REVIEWED_PROOF_SEAM_RELATIVES[2]
        path = session.snapshot_root / relative
        original = path.read_bytes()
        original_stat = path.stat()
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
        path.write_bytes(original + b"// transient hostile build mutation\n")
        path.write_bytes(original)
        os.utime(
            path,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        os.chmod(path, 0o400)
        os.chmod(path.parent, 0o500)
        with self.assertRaises(core.Refused):
            target._require_review_snapshot_binding_unchanged(
                binding, reviewed, session
            )

    def test_review_snapshot_aba_restore_refuses(self):
        reviewed = self.fixture.reviewed()
        relative = target.REVIEWED_PROOF_SEAM_RELATIVES[3]
        source = self.fixture.source / relative
        original = source.read_bytes()
        source.write_bytes(original + b"// hostile ABA snapshot version\n")
        session = self.fixture.begin()
        source.write_bytes(original)
        with self.assertRaisesRegex(
            core.Refused, "review-snapshot-content-or-inode"
        ):
            target._review_snapshot_binding(reviewed, session)

    def test_manifest_keeps_four_packages_and_adds_path_compiled_sources(self):
        session = self.fixture.begin()
        target._validate_manifest_packages(session.manifest)
        self.assertEqual(
            tuple(session.manifest["package_roots"]), target.EXPECTED_PACKAGE_ROOTS
        )
        paths = {item["relative_path"] for item in session.manifest["members"]}
        self.assertTrue(set(target.PATH_COMPILED_SOURCE_RELATIVES).issubset(paths))
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/examples/"
            "verify_frozen_w1_round1_receipt.rs",
            paths,
        )
        self.assertIn("plus-fixed-path-compiled-low-memory", session.manifest["derivation"])
        core._validate_manifest(session.manifest)

    def test_package_omission_extra_or_reordering_refuses(self):
        session = self.fixture.begin()
        cases = (
            list(target.EXPECTED_PACKAGE_ROOTS[:-1]),
            list(target.EXPECTED_PACKAGE_ROOTS) + ["extra/package"],
            list(reversed(target.EXPECTED_PACKAGE_ROOTS)),
        )
        for roots in cases:
            manifest = dict(session.manifest)
            manifest["package_roots"] = roots
            with self.subTest(roots=roots), self.assertRaises(core.Refused):
                target._validate_manifest_packages(manifest)

    def test_live_source_mutation_refuses_exact_rehash(self):
        session = self.fixture.begin()
        changed = self.fixture.source / target.PATH_COMPILED_SOURCE_RELATIVES[0]
        changed.write_bytes(changed.read_bytes() + b"// hostile mutation\n")
        with mock.patch.object(target, "REPO_ROOT", self.fixture.source):
            with self.assertRaisesRegex(
                core.Refused, "live-source-changed-during-build"
            ):
                target._require_live_manifest_unchanged(
                    session.manifest, "live-source-changed-during-build"
                )

    def test_verifier_entry_mutation_refuses_exact_rehash(self):
        session = self.fixture.begin()
        relative = (
            "poc/local-private-payment/private-batch-relation/examples/"
            "verify_frozen_w1_round1_receipt.rs"
        )
        changed = self.fixture.source / relative
        changed.write_bytes(changed.read_bytes() + b"// hostile verifier mutation\n")
        with mock.patch.object(target, "REPO_ROOT", self.fixture.source):
            with self.assertRaisesRegex(
                core.Refused, "live-source-changed-during-build"
            ):
                target._require_live_manifest_unchanged(
                    session.manifest, "live-source-changed-during-build"
                )

    def test_mutation_during_snapshot_refuses(self):
        original = core._snapshot_members

        def mutate_after_copy(source_root, snapshot_root, manifest):
            refs = original(source_root, snapshot_root, manifest)
            path = Path(source_root) / target.PATH_COMPILED_SOURCE_RELATIVES[1]
            path.write_bytes(path.read_bytes() + b"// raced\n")
            return refs

        with mock.patch.object(core, "_snapshot_members", side_effect=mutate_after_copy):
            with mock.patch.object(target, "REPO_ROOT", self.fixture.source):
                with self.assertRaisesRegex(
                    core.Refused, "source-set-changed-during-snapshot"
                ):
                    target._begin_proof_candidate(
                        self.fixture.source, self.fixture.output, target.OUTPUT_NAME
                    )

    def test_missing_path_compiled_source_refuses_manifest_derivation(self):
        (self.fixture.source / target.PATH_COMPILED_SOURCE_RELATIVES[1]).unlink()
        with self.assertRaises((core.Refused, FileNotFoundError)):
            target._derive_proof_manifest(self.fixture.source)


class DependencyControls(SyntheticCase):
    def test_required_combined_closure_and_manifest_order(self):
        session = self.fixture.begin()
        binary, dep_info = self.cargo_outputs(session)
        relatives, evidence = self.derive(session, binary, dep_info)
        manifest_order = [item["relative_path"] for item in session.snapshot_refs]
        self.assertEqual(
            list(relatives),
            [value for value in manifest_order if value in set(relatives)],
        )
        self.assertTrue(
            target.REQUIRED_PROOF_DEPENDENCY_RELATIVES.issubset(relatives)
        )
        self.assertEqual(evidence["canonical_unique_dependency_count"], len(relatives))
        self.assertEqual(evidence["publication_order"], "SOURCE_MANIFEST_RELATIVE_PATH_ORDER")
        publication = target._publication_dep_info(relatives)
        dep_target, dependencies = core._parse_dep_info(publication)
        self.assertEqual(dep_target, "artifacts/candidate-binary")
        self.assertEqual(dependencies, [f"sources/{value}" for value in relatives])

    def test_missing_required_or_path_compiled_member_refuses(self):
        for missing in (
            sorted(target.REQUIRED_PROOF_DEPENDENCY_RELATIVES)[0],
            target.PATH_COMPILED_SOURCE_RELATIVES[0],
            target.PATH_COMPILED_SOURCE_RELATIVES[1],
        ):
            self.fixture.close()
            self.fixture = SyntheticSource()
            session = self.fixture.begin()
            members = sorted(target.REQUIRED_PROOF_DEPENDENCY_RELATIVES - {missing})
            binary, dep_info = self.cargo_outputs(session, members)
            with self.subTest(missing=missing), self.assertRaises(core.Refused):
                self.derive(session, binary, dep_info)

    def test_live_external_relative_unmanifested_and_wrong_target_refuse(self):
        for case in ("live", "external", "relative", "unmanifested", "target"):
            self.fixture.close()
            self.fixture = SyntheticSource()
            session = self.fixture.begin()
            binary, dep_info = self.cargo_outputs(session)
            dep_target, dependencies = core._parse_dep_info(dep_info.read_bytes())
            if case == "live":
                dependencies[0] = str(
                    session.source_root
                    / sorted(target.REQUIRED_PROOF_DEPENDENCY_RELATIVES)[0]
                )
            elif case == "external":
                dependencies[0] = "/etc/passwd"
            elif case == "relative":
                dependencies[0] = "relative.rs"
            elif case == "unmanifested":
                dependencies[0] = str(session.snapshot_root / "not-manifested.rs")
            else:
                dep_target = str(session.target_root / "wrong-binary")
            dep_info.write_text(f"{dep_target}: {' '.join(dependencies)}\n")
            with self.subTest(case=case), self.assertRaises(core.Refused):
                self.derive(session, binary, dep_info)

    def test_alias_is_canonicalized_inode_bound_and_deduplicated(self):
        session = self.fixture.begin()
        members = sorted(target.REQUIRED_PROOF_DEPENDENCY_RELATIVES)
        alias = (
            "poc/local-private-payment/private_batch_trial/auth_exit/src/"
            "../../../native-authority/native-core/src/lib.rs"
        )
        binary, dep_info = self.cargo_outputs(session, members + [alias])
        relatives, evidence = self.derive(session, binary, dep_info)
        self.assertEqual(len(relatives), len(members))
        self.assertEqual(evidence["lexical_alias_count"], 1)
        self.assertEqual(evidence["duplicate_canonical_member_count"], 1)
        mapping = evidence["mappings"][-1]
        self.assertTrue(mapping["lexical_alias"])
        self.assertTrue(mapping["duplicate_canonical_member"])
        self.assertIsNotNone(mapping["duplicate_of_raw_index"])

    def test_exact_raw_duplicate_refuses_before_alias_mapping(self):
        session = self.fixture.begin()
        members = sorted(target.REQUIRED_PROOF_DEPENDENCY_RELATIVES)
        binary, dep_info = self.cargo_outputs(session, members + [members[-1]])
        with self.assertRaisesRegex(core.Refused, "dep-info-duplicate"):
            self.derive(session, binary, dep_info)

    def test_publication_contract_matches_proof_supervisor_validator(self):
        session = self.fixture.begin()
        binary, dep_info = self.cargo_outputs(session)
        relatives, _ = self.derive(session, binary, dep_info)
        manifest_raw = core.canonical(session.manifest)
        verifier_contract = next(
            member
            for member in session.manifest["members"]
            if member["relative_path"] == supervisor.VERIFIER_CONTRACT_SOURCE
        )
        with mock.patch.object(
            supervisor,
            "EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256",
            verifier_contract["sha256"],
        ):
            manifest, paths = supervisor._validate_manifest(manifest_raw)
        self.assertEqual(manifest, session.manifest)
        publication = target._publication_dep_info(relatives)
        count = supervisor._validate_dependency_contract(
            {
                "dependency_count": len(relatives),
                "target_relative": "artifacts/candidate-binary",
            },
            list(relatives),
            paths,
            publication,
        )
        self.assertEqual(count, len(relatives))

    def test_verifier_closure_matches_supervisor_validator(self):
        session = self.fixture.begin()
        binary, dep_info = self.verifier_cargo_outputs(session)
        relatives, evidence = self.derive(
            session,
            binary,
            dep_info,
            target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES,
            "verifier",
        )
        self.assertTrue(
            target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES.issubset(relatives)
        )
        self.assertEqual(evidence["closure_label"], "verifier")
        verifier_contract = next(
            member
            for member in session.manifest["members"]
            if member["relative_path"] == supervisor.VERIFIER_CONTRACT_SOURCE
        )
        with mock.patch.object(
            supervisor,
            "EXPECTED_VERIFIER_CONTRACT_SOURCE_SHA256",
            verifier_contract["sha256"],
        ):
            manifest, paths = supervisor._validate_manifest(
                core.canonical(session.manifest)
            )
        self.assertEqual(manifest, session.manifest)
        publication = target._publication_dep_info(
            relatives, "artifacts/verify_frozen_w1_round1_receipt"
        )
        count = supervisor._validate_verifier_dependency_contract(
            {
                "dependency_count": len(relatives),
                "target_relative": "artifacts/verify_frozen_w1_round1_receipt",
                "dependency_relatives": list(relatives),
            },
            list(relatives),
            paths,
            publication,
            core.sha256_bytes(publication),
            tuple(relatives),
        )
        self.assertEqual(count, len(relatives))

    def test_verifier_omission_alias_and_wrong_target_controls(self):
        session = self.fixture.begin()
        members = sorted(target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES)
        missing = target.REVIEWED_PROOF_SEAM_RELATIVES[3]
        binary, dep_info = self.verifier_cargo_outputs(
            session, [member for member in members if member != missing]
        )
        with self.assertRaisesRegex(
            core.Refused, "dep-info-exact-reviewed-local-closure"
        ):
            self.derive(
                session,
                binary,
                dep_info,
                target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES,
                "verifier",
            )

        self.fixture.close()
        self.fixture = SyntheticSource()
        session = self.fixture.begin()
        alias = (
            "poc/local-private-payment/private_batch_trial/auth_exit/src/"
            "../../../native-authority/native-core/src/lib.rs"
        )
        binary, dep_info = self.verifier_cargo_outputs(
            session, members + [alias]
        )
        relatives, evidence = self.derive(
            session,
            binary,
            dep_info,
            target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES,
            "verifier",
        )
        self.assertEqual(len(relatives), len(members))
        self.assertEqual(evidence["lexical_alias_count"], 1)
        self.assertEqual(evidence["duplicate_canonical_member_count"], 1)

        dep_target, dependencies = core._parse_dep_info(dep_info.read_bytes())
        dep_info.write_text(
            f"{session.target_root / 'wrong-verifier'}: {' '.join(dependencies)}\n"
        )
        with self.assertRaisesRegex(core.Refused, "dep-info-target-binding"):
            self.derive(
                session,
                binary,
                dep_info,
                target.REQUIRED_VERIFIER_DEPENDENCY_RELATIVES,
                "verifier",
            )


class PublicationControls(SyntheticCase):
    def test_synthetic_combined_bundle_is_atomic_and_supervisor_shaped(self):
        reviewed = self.fixture.reviewed()
        session = self.fixture.begin()
        binding = target._review_snapshot_binding(reviewed, session)
        outputs = self.dual_outputs(session)
        result = self.finalize(session, outputs)
        self.assertFalse(result["production_build"])
        self.assertFalse(result["authorization"])
        frozen = Path(result["root"])
        self.assertEqual(
            target._require_review_snapshot_binding_unchanged(
                binding,
                reviewed,
                session,
                snapshot_root=frozen / "sources",
            ),
            binding,
        )
        self.assertEqual(stat.S_IMODE(frozen.stat().st_mode), 0o500)
        self.assertEqual(
            set(os.listdir(frozen)),
            {
                "sources", "artifacts", "SOURCE-MANIFEST.json",
                "FREEZER-SOURCE.py", "BUILD-RECEIPT.json",
            },
        )
        candidate = frozen / "artifacts" / "candidate-binary"
        verifier = frozen / "artifacts" / target.VERIFIER_EXAMPLE_NAME
        self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(verifier.stat().st_mode), 0o500)
        self.assertEqual(candidate.stat().st_nlink, 1)
        self.assertEqual(verifier.stat().st_nlink, 1)
        frozen_dep = frozen / "artifacts" / "candidate-binary.d"
        verifier_dep = frozen / "artifacts" / f"{target.VERIFIER_EXAMPLE_NAME}.d"
        self.assertEqual(
            frozen_dep.read_bytes(),
            target._publication_dep_info(outputs["proof_relatives"]),
        )
        self.assertEqual(
            verifier_dep.read_bytes(),
            target._publication_dep_info(
                outputs["verifier_relatives"],
                "artifacts/verify_frozen_w1_round1_receipt",
            ),
        )
        self.assertEqual(
            set(os.listdir(frozen / "artifacts")),
            {
                "candidate-binary",
                "candidate-binary.d",
                "verify_frozen_w1_round1_receipt",
                "verify_frozen_w1_round1_receipt.d",
            },
        )
        receipt = json.loads((frozen / "BUILD-RECEIPT.json").read_bytes())
        self.assertEqual(receipt["schema"], core.BUILD_RECEIPT_SCHEMA)
        self.assertEqual(receipt["built_examples"], list(target.EXAMPLE_NAMES))
        self.assertEqual(receipt["verifier_binary"]["mode_octal"], "0500")
        self.assertEqual(receipt["verifier_binary"]["link_count"], 1)
        self.assertFalse(receipt["proof"])
        self.assertFalse(receipt["network"])

    def test_reused_output_and_reused_session_refuse(self):
        session = self.fixture.begin()
        outputs = self.dual_outputs(session)
        self.finalize(session, outputs)
        with self.assertRaisesRegex(core.Refused, "test-session-finalized"):
            self.finalize(session, outputs)
        with mock.patch.object(target, "REPO_ROOT", self.fixture.source):
            with self.assertRaisesRegex(core.Refused, "test-final-create-new"):
                target._begin_proof_candidate(
                    self.fixture.source, self.fixture.output, target.OUTPUT_NAME
                )

    def test_proof_execution_marker_refuses_publication(self):
        session = self.fixture.begin()
        marker = session.target_root / "PROOF-RECEIPT.json"
        marker.write_bytes(b"hostile execution evidence\n")
        with self.assertRaisesRegex(core.Refused, "proof-execution-marker-observed"):
            target._refuse_proof_execution_markers(session.target_root)

    def test_swapped_proof_and_verifier_outputs_refuse(self):
        session = self.fixture.begin()
        outputs = self.dual_outputs(session)
        with self.assertRaises(core.Refused):
            target._finalize_proof_candidate(
                session,
                proof_binary=outputs["verifier_binary"],
                proof_admission_dep_info=outputs["proof_dep"],
                proof_dependency_relatives=outputs["proof_relatives"],
                verifier_binary=outputs["proof_binary"],
                verifier_admission_dep_info=outputs["verifier_dep"],
                verifier_dependency_relatives=outputs["verifier_relatives"],
            )

    def test_output_parent_inode_swap_refuses(self):
        session = self.fixture.begin()
        outputs = self.dual_outputs(session)
        moved = self.fixture.root / "output-moved"
        self.fixture.output.rename(moved)
        self.fixture.output.mkdir(mode=0o700)
        with self.assertRaises(core.Refused):
            self.finalize(session, outputs)


class InodeAndPathControls(SyntheticCase):
    def test_cargo_binary_must_be_exact_two_link_then_detaches(self):
        session = self.fixture.begin()
        binary, _ = self.cargo_outputs(session)
        raw, reference = target._stable_cargo_hardlinked_binary(binary)
        self.assertEqual(reference["link_count"], 2)
        detached = session.target_root / "detached"
        detached_reference = core._write_new(detached, raw, 0o500)
        self.assertEqual(detached_reference["sha256"], reference["sha256"])
        self.assertEqual(os.lstat(detached).st_nlink, 1)
        os.link(binary, binary.with_name("third-link"))
        with self.assertRaisesRegex(core.Refused, "cargo-binary-hardlink-shape"):
            target._stable_cargo_hardlinked_binary(binary)

    def test_verifier_binary_path_swap_refuses_hardlink_binding(self):
        session = self.fixture.begin()
        binary, _ = self.verifier_cargo_outputs(session)
        raw, reference = target._stable_cargo_hardlinked_binary(binary)
        self.assertEqual(reference["link_count"], 2)
        binary.unlink()
        binary.write_bytes(raw)
        os.chmod(binary, 0o700)
        with self.assertRaisesRegex(core.Refused, "cargo-binary-hardlink-shape"):
            target._stable_cargo_hardlinked_binary(binary)

    def test_snapshot_member_inode_replacement_refuses_dep_admission(self):
        session = self.fixture.begin()
        binary, dep_info = self.cargo_outputs(session)
        relative = sorted(target.REQUIRED_PROOF_DEPENDENCY_RELATIVES)[0]
        path = session.snapshot_root / relative
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
        original = path.read_bytes()
        replacement = path.with_name(path.name + ".hostile-replacement")
        replacement.write_bytes(original)
        replacement.replace(path)
        os.chmod(path, 0o400)
        os.chmod(path.parent, 0o500)
        with self.assertRaisesRegex(core.Refused, "dep-info-resolved-member-identity"):
            self.derive(session, binary, dep_info)

    def test_executed_python_source_mutation_and_inode_swap_refuse(self):
        source = self.fixture.root / "freezer.py"
        source.write_bytes(b"version-one\n")
        initial_raw, initial_reference = target._capture_python_source(source)
        target._require_python_source_unchanged(
            source, initial_raw, initial_reference
        )
        replacement = self.fixture.root / "replacement.py"
        replacement.write_bytes(initial_raw)
        replacement.replace(source)
        with self.assertRaisesRegex(
            core.Refused, "python-source-changed-during-build"
        ):
            target._require_python_source_unchanged(
                source, initial_raw, initial_reference
            )


class OuterEvidenceControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-proof-build-outer-controls-"
        )
        self.parent = Path(self.temporary.name) / "parent"
        self.parent.mkdir(mode=0o700)
        self.output_patcher = mock.patch.object(target, "OUTPUT_PARENT", self.parent)
        self.output_patcher.start()
        self.reviewed_tools = {
            name: {
                "bytes": TEST_CARGO_IDENTITY["bytes"],
                "sha256": TEST_CARGO_IDENTITY["sha256"],
                "version_stdout_sha256": "b" * 64,
                "version_stderr_sha256": "c" * 64,
            }
            for name in target.BUILD_TOOL_PATHS
        }
        self.tool_patcher = mock.patch.object(
            target, "REVIEWED_BUILD_TOOL_IDENTITIES", self.reviewed_tools
        )
        self.tool_patcher.start()
        self.cargo_home_patcher = mock.patch.object(
            target, "_require_isolated_cargo_home_unchanged"
        )
        self.cargo_home_patcher.start()
        with mock.patch.object(
            target.secrets, "token_hex", side_effect=("1" * 32, "2" * 32)
        ):
            self.ledger_root, self.run_identity = (
                target._create_unit_identity_ledger()
            )
        self.probe_command = target._network_probe_command(TEST_PROBE_UNIT)
        self.build_command = target._cargo_build_command(
            Path("/synthetic/proof-snapshot"),
            Path("/synthetic/proof-target"),
            TEST_BUILD_UNIT,
            TEST_CARGO_IDENTITY,
        )
        with mock.patch.object(
            target, "_inspect_pristine_unit",
            side_effect=(
                self.pristine(TEST_PROBE_UNIT), self.pristine(TEST_PROBE_UNIT),
                self.pristine(TEST_BUILD_UNIT), self.pristine(TEST_BUILD_UNIT),
            ),
        ):
            self.probe_identity = target._reserve_unit_identity(
                TEST_PROBE_UNIT, self.probe_command, self.ledger_root
            )
            self.build_identity = target._reserve_unit_identity(
                TEST_BUILD_UNIT, self.build_command, self.ledger_root
            )
        self.probe_identity["start_dispatched_after_consumption"] = True
        self.build_identity["start_dispatched_after_consumption"] = True
        self.ledger_evidence = target._seal_unit_identity_ledger(
            self.ledger_root
        )

    def tearDown(self):
        self.cargo_home_patcher.stop()
        self.tool_patcher.stop()
        self.output_patcher.stop()
        SyntheticSource._unseal(Path(self.temporary.name))
        self.temporary.cleanup()

    @staticmethod
    def record_reference(unit_name, name):
        raw = f"{unit_name}:{name}\n".encode()
        return {
            "name": name,
            "bytes": len(raw),
            "sha256": core.sha256_bytes(raw),
            "mode_octal": "0400",
            "link_count": 1,
        }

    @staticmethod
    def pristine(unit_name):
        return {
            "load_state": "not-found",
            "systemctl_command_sha256": core.sha256_bytes(
                f"show:{unit_name}".encode()
            ),
            "systemctl_stdout_bytes": len(b"not-found\n"),
            "systemctl_stdout_sha256": core.sha256_bytes(b"not-found\n"),
            "historical_journal_command_sha256": core.sha256_bytes(
                f"journal:{unit_name}".encode()
            ),
            "historical_journal_bytes": 0,
            "historical_journal_sha256": core.sha256_bytes(b""),
            "historical_journal_empty": True,
        }

    @classmethod
    def unit_identity(cls, unit_name, reservation_id):
        pristine = cls.pristine(unit_name)
        return {
            "unit_root": str(
                target.OUTPUT_PARENT
                / target.UNIT_LEDGER_NAME
                / f"{unit_name}.identity"
            ),
            "unit_name": unit_name,
            "service_unit": f"{unit_name}.service",
            "role": "network_probe" if unit_name == target.PROBE_UNIT else "cargo_build",
            "reservation_id": reservation_id,
            "reservation": cls.record_reference(unit_name, "RESERVATION.json"),
            "consumption": cls.record_reference(unit_name, "CONSUMPTION.json"),
            "first_pristine_observation": pristine,
            "second_pristine_observation": pristine,
            "reservation_and_consumption_durable_before_start": True,
            "prestart_load_state_not_found": True,
            "prestart_historical_journal_empty": True,
            "start_dispatched_after_consumption": True,
        }

    @classmethod
    def ledger(cls, probe, build):
        value = {
            "root": str(target.OUTPUT_PARENT / target.UNIT_LEDGER_NAME),
            "mode_octal": "0500",
            "unit_count": 2,
            "units": {
                target.PROBE_UNIT: {
                    "unit_root": probe["unit_root"],
                    "reservation": probe["reservation"],
                    "consumption": probe["consumption"],
                },
                target.BUILD_UNIT: {
                    "unit_root": build["unit_root"],
                    "reservation": build["reservation"],
                    "consumption": build["consumption"],
                },
            },
            "reservations_and_consumptions_retained": True,
            "authorization": False,
        }
        value["ledger_identity_sha256"] = core.sha256_bytes(core.canonical(value))
        return value

    @staticmethod
    def active_properties():
        return {
            "restrict_address_families": "AF_UNIX",
            "denied_network_syscalls": sorted(
                target.DENIED_BUILD_NETWORK_SYSCALLS
            ),
            "system_call_error_number": 1,
            "system_call_architectures": "native",
            "no_new_privileges": True,
            "limit_core_bytes": 0,
            "memory_max_bytes": 20 * 1024**3,
            "memory_swap_max_bytes": 0,
            "umask_octal": "0077",
            "unset_environment": sorted(target.BOOTSTRAP_UNSET_ENVIRONMENT),
            "standard_input": "null",
            "standard_output": "null",
            "standard_error": "null",
            "inherited_communication_fds": False,
            "socket_unit_associations": [],
        }

    @classmethod
    def transient_unit(cls, unit_name, identity, command_sha256):
        return {
            "unit": f"{unit_name}.service",
            "unit_identity": identity,
            "unit_identity_was_fresh_and_consumed_before_start": True,
            "command_sha256": command_sha256,
            "properties": cls.active_properties(),
            "show_sha256": core.sha256_bytes(f"show:{unit_name}".encode()),
            "show_bytes": 1,
            "journal_sha256": core.sha256_bytes(b""),
            "journal_bytes": 0,
            "journal": {
                "show_invocation_id": "3" * 32,
                "show_exec_main_pid": 12345,
                "unfiltered_command_sha256": "d" * 64,
                "invocation_filtered_command_sha256": "e" * 64,
                "unfiltered_equals_invocation_filtered": True,
                "record_count": 0,
                "exec_main_pid_record_count": 0,
                "all_records_current_invocation": True,
                "all_records_current_unit": True,
                "export_bytes": 0,
                "export_sha256": core.sha256_bytes(b""),
            },
            "invocation_id": "3" * 32,
            "exec_main_pid": 12345,
            "result": "success",
            "exec_main_status": 0,
            "unit_stopped_after_capture": True,
        }

    @staticmethod
    def review_gate():
        reviewed = {}
        entries = []
        for index, relative in enumerate(target.REVIEWED_PROOF_SEAM_RELATIVES):
            raw = f"reviewed:{relative}\n".encode()
            member = {
                "bytes": len(raw), "sha256": core.sha256_bytes(raw),
                "device": 10, "inode": 100 + index,
                "mtime_ns": 1000 + index, "ctime_ns": 2000 + index,
            }
            reviewed[relative] = member
            entries.append(
                {
                    "relative_path": relative,
                    "bytes": member["bytes"],
                    "sha256": member["sha256"],
                    "live_device": member["device"],
                    "live_inode": member["inode"],
                    "live_mtime_ns": member["mtime_ns"],
                    "live_ctime_ns": member["ctime_ns"],
                    "snapshot_device": 100,
                    "snapshot_inode": 200 + index,
                    "snapshot_mtime_ns": 3000 + index,
                    "snapshot_ctime_ns": 4000 + index,
                }
            )
        live_directories = {
            "directory_count": 0,
            "directories": [],
            "all_relevant_directories_bind_mtime_and_ctime": True,
        }
        live_directories["metadata_identity_sha256"] = core.sha256_bytes(
            core.canonical(live_directories)
        )
        snapshot_metadata = {
            "member_count": 0,
            "members": [],
            "directory_count": 0,
            "directories": [],
            "all_members_bind_mtime_and_ctime": True,
            "all_relevant_directories_bind_mtime_and_ctime": True,
        }
        snapshot_metadata["metadata_identity_sha256"] = core.sha256_bytes(
            core.canonical(snapshot_metadata)
        )
        binding = {
            "schema": target.REVIEW_SNAPSHOT_BINDING_SCHEMA,
            "reviewed_member_count": len(target.REVIEWED_PROOF_SEAM_RELATIVES),
            "reviewed_manifest_snapshot_exact_match": True,
            "entries": entries,
            "reviewed_live_directories": live_directories,
            "snapshot_tree_metadata": snapshot_metadata,
            "authorization": False,
        }
        binding["binding_identity_sha256"] = core.sha256_bytes(
            core.canonical(binding)
        )
        return {
            "independent_review_explicitly_bound_before_execution": True,
            "reviewed_sources": reviewed,
            "review_manifest_snapshot_binding": binding,
            "review_manifest_snapshot_rechecked_after_build": True,
            "review_manifest_snapshot_rechecked_after_publication": True,
            "reviewed_sources_equal_after_atomic_freeze": True,
        }

    def receipt(self):
        probe_identity = self.probe_identity
        build_identity = self.build_identity
        snapshot = Path("/synthetic/proof-snapshot")
        build_target = Path("/synthetic/proof-target")
        build_command = self.build_command
        build_command_sha256 = core.sha256_bytes(core.canonical(build_command))
        build_unit = self.transient_unit(
            TEST_BUILD_UNIT, build_identity, build_command_sha256
        )
        probe_command_sha256 = core.sha256_bytes(
            core.canonical(target._network_probe_command(TEST_PROBE_UNIT))
        )
        probe = self.transient_unit(
            TEST_PROBE_UNIT, probe_identity, probe_command_sha256
        )
        probe.update(
            {
                "af_inet_and_af_inet6_socket_calls_denied_with_eafnosupport": True,
                "af_unix_socket_and_socketpair_available_for_process_spawn": True,
                "local_af_unix_ipc_observed": True,
                "af_unix_seqpacket_connected_write_and_read_observed": True,
                "fixed_subprocess_spawn_succeeded": True,
                "af_unix_connect_attempt_denied_with_eperm": True,
                "af_unix_datagram_sendto_denied_with_eperm": True,
                "af_unix_recvfrom_denied_with_eperm": True,
                "io_uring_setup_enter_register_denied_with_eperm_or_enosys": True,
                "same_uid_descriptor_and_memory_relay_syscalls_denied": True,
                "initial_standard_fds_are_dev_null": True,
                "no_other_inherited_fds_observed": True,
                "network_communication_performed": False,
            }
        )
        return target._receipt_identity(
            {
                "schema": target.RECEIPT_SCHEMA,
                "classification": target.CLASSIFICATION,
                "review_gate": self.review_gate(),
                "build": {
                    "actual_subprocess_executed": True,
                    "command": build_command,
                    "command_sha256": build_command_sha256,
                    "environment_launcher": str(target.ENV),
                    "environment_cleared_with_i": True,
                    "exact_cargo_environment": list(
                        target._cargo_environment(build_target)
                    ),
                    "ambient_manager_environment_inherited_by_cargo": False,
                    "bootstrap_unset_environment": list(
                        target.BOOTSTRAP_UNSET_ENVIRONMENT
                    ),
                    "bootstrap": {
                        "schema": target.BUILD_BOOTSTRAP_SCHEMA,
                        "interpreter": str(target.PYTHON),
                        "source_bytes": len(target.BUILD_BOOTSTRAP_SOURCE.encode()),
                        "source_sha256": core.sha256_bytes(
                            target.BUILD_BOOTSTRAP_SOURCE.encode()
                        ),
                        "exact_environment_verified_in_build_unit": True,
                        "inherited_fds_exactly_0_1_2_dev_null_verified_in_build_unit": True,
                        "cargo_opened_and_rehashed_after_inherited_fd_check": True,
                        "cargo_exec_primitive": "os.execve-authenticated-fd",
                        "cargo_argv": [
                            str(target.CARGO), *target.CARGO_BUILD_ARGUMENTS
                        ],
                        "cargo_identity": TEST_CARGO_IDENTITY,
                        "proof_or_verifier_binary_executed": False,
                    },
                    "build_tools": {
                        "before": {"tools": {"cargo": TEST_CARGO_IDENTITY}},
                        "after": {"tools": {"cargo": TEST_CARGO_IDENTITY}},
                        "exactly_equal_across_build": True,
                        "reviewed_identity_map": self.reviewed_tools,
                        "toolchain_dynamic_library_closure_bound": False,
                    },
                    "isolated_cargo_home": {},
                    "cwd": str(snapshot / target.RELATION_RELATIVE),
                    "profile": "release",
                    "binary_was_not_executed": True,
                    "locked": True,
                    "offline": True,
                    "default_features": False,
                    "features": [target.FEATURE_NAME],
                    "example": target.PROOF_EXAMPLE_NAME,
                    "examples": list(target.EXAMPLE_NAMES),
                    "single_cargo_invocation_for_both_examples": True,
                    "both_binaries_were_not_executed": True,
                    "unit": build_unit,
                    "unit_identity_ledger": self.ledger_evidence,
                },
                "network_boundary": {
                    "denied_network_syscalls": list(
                        target.DENIED_BUILD_NETWORK_SYSCALLS
                    ),
                    "system_call_error": "EPERM",
                    "system_call_architectures": "native",
                    "restrict_address_families": "AF_UNIX",
                    "socket_and_socketpair_allowed_for_local_process_spawn": True,
                    "socketpair_connected_write_read_classified_as_local_ipc_only": True,
                    "sendto_recvfrom_denied": True,
                    "sendmsg_recvmsg_mmsg_denied": True,
                    "af_unix_connect_bind_listen_accept_denied": True,
                    "io_uring_setup_enter_register_denied": True,
                    "same_uid_descriptor_and_memory_relay_syscalls_denied": True,
                    "inherited_communication_fds": False,
                    "ip_address_families_available": False,
                    "local_af_unix_ipc_permitted": True,
                    "local_af_unix_ipc_observed": True,
                    "af_unix_external_relay_surface_observed": False,
                    "strict_no_socket_runtime_boundary_is_not_this_build_boundary": True,
                    "probe": probe,
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
                "actions": target._fixed_actions(),
                "verification": False,
                "privacy_acceptance": False,
                "financial_acceptance": False,
                "authorization": False,
            }
        )

    def test_outer_contract_atomically_copies_unit_identity_records(self):
        receipt = self.receipt()
        result = target._publish_outer_evidence(
            self.parent, b"synthetic proof freezer source\n", receipt
        )
        root = Path(result["root"])
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o500)
        self.assertEqual(
            set(os.listdir(root)),
            {
                "FREEZER-SOURCE.py", "PROOF-BUILD-RECEIPT.json",
                "UNIT-IDENTITY-EVIDENCE",
            },
        )
        for name in ("FREEZER-SOURCE.py", "PROOF-BUILD-RECEIPT.json"):
            self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o400)
        target._validate_atomic_unit_identity_evidence(
            root / "UNIT-IDENTITY-EVIDENCE", self.ledger_evidence
        )
        observed = json.loads((root / "PROOF-BUILD-RECEIPT.json").read_bytes())
        target._validate_outer_receipt(observed)
        with self.assertRaises(core.Refused):
            target._publish_outer_evidence(
                self.parent, b"replacement refused\n", receipt
            )

    def test_authority_proof_network_or_wrong_build_claim_refuses(self):
        cases = (
            ("top", "authorization", True),
            ("top", "privacy_acceptance", True),
            ("top", "verification", True),
            ("action", "proof", True),
            ("action", "network_communication", True),
            ("build", "binary_was_not_executed", False),
            ("build", "features", ["wrong-feature"]),
            ("build", "examples", [target.PROOF_EXAMPLE_NAME]),
            ("build", "environment_launcher", "/bin/env"),
            ("build", "environment_cleared_with_i", False),
            ("build", "ambient_manager_environment_inherited_by_cargo", True),
            ("network", "sendto_recvfrom_denied", False),
            ("network", "inherited_communication_fds", True),
            ("network", "af_unix_external_relay_surface_observed", True),
            ("probe", "no_other_inherited_fds_observed", False),
            ("probe", "af_unix_datagram_sendto_denied_with_eperm", False),
            ("closure", "reviewed_low_memory_source_present", False),
            ("closure", "verifier_entry_source_present", False),
        )
        for scope, field, value in cases:
            receipt = self.receipt()
            if scope == "top":
                receipt[field] = value
            elif scope == "action":
                receipt["actions"] = dict(receipt["actions"])
                receipt["actions"][field] = value
            elif scope == "build":
                receipt["build"] = dict(receipt["build"])
                receipt["build"][field] = value
            elif scope == "network":
                receipt["network_boundary"] = dict(
                    receipt["network_boundary"]
                )
                receipt["network_boundary"][field] = value
            elif scope == "probe":
                receipt["network_boundary"] = dict(
                    receipt["network_boundary"]
                )
                receipt["network_boundary"]["probe"] = dict(
                    receipt["network_boundary"]["probe"]
                )
                receipt["network_boundary"]["probe"][field] = value
            else:
                receipt["closure_scope"] = dict(receipt["closure_scope"])
                receipt["closure_scope"][field] = value
            unsigned = dict(receipt)
            unsigned.pop("receipt_identity_sha256")
            receipt["receipt_identity_sha256"] = core.sha256_bytes(
                core.canonical(unsigned)
            )
            with self.subTest(scope=scope, field=field), self.assertRaises(core.Refused):
                target._validate_outer_receipt(receipt)

    def test_inherited_environment_relaxed_unit_or_stale_network_claim_refuses(self):
        mutations = []

        receipt = self.receipt()
        receipt["build"] = dict(receipt["build"])
        receipt["build"]["exact_cargo_environment"] = [
            *receipt["build"]["exact_cargo_environment"],
            "HOSTILE_INHERITED_VALUE=1",
        ]
        mutations.append(receipt)

        receipt = self.receipt()
        receipt["build"] = dict(receipt["build"])
        receipt["build"]["bootstrap_unset_environment"] = receipt["build"][
            "bootstrap_unset_environment"
        ][1:]
        mutations.append(receipt)

        receipt = self.receipt()
        receipt["build"] = dict(receipt["build"])
        receipt["build"]["command"] = list(receipt["build"]["command"])
        receipt["build"]["command"].remove("-i")
        receipt["build"]["command_sha256"] = core.sha256_bytes(
            core.canonical(receipt["build"]["command"])
        )
        receipt["build"]["unit"] = dict(receipt["build"]["unit"])
        receipt["build"]["unit"]["command_sha256"] = receipt["build"][
            "command_sha256"
        ]
        mutations.append(receipt)

        receipt = self.receipt()
        receipt["build"] = dict(receipt["build"])
        receipt["build"]["unit"] = dict(receipt["build"]["unit"])
        receipt["build"]["unit"]["properties"] = dict(
            receipt["build"]["unit"]["properties"]
        )
        receipt["build"]["unit"]["properties"]["standard_output"] = "journal"
        mutations.append(receipt)

        receipt = self.receipt()
        receipt["network_boundary"] = dict(receipt["network_boundary"])
        receipt["network_boundary"]["sendto_recvfrom_allowed"] = True
        mutations.append(receipt)

        for index, receipt in enumerate(mutations):
            unsigned = dict(receipt)
            unsigned.pop("receipt_identity_sha256")
            receipt["receipt_identity_sha256"] = core.sha256_bytes(
                core.canonical(unsigned)
            )
            with self.subTest(index=index), self.assertRaises(core.Refused):
                target._validate_outer_receipt(receipt)

    def test_review_snapshot_or_unit_ledger_claim_mutation_refuses(self):
        receipt = self.receipt()
        receipt["review_gate"] = dict(receipt["review_gate"])
        receipt["review_gate"][
            "review_manifest_snapshot_rechecked_after_publication"
        ] = False
        unsigned = dict(receipt)
        unsigned.pop("receipt_identity_sha256")
        receipt["receipt_identity_sha256"] = core.sha256_bytes(
            core.canonical(unsigned)
        )
        with self.assertRaises(core.Refused):
            target._validate_outer_receipt(receipt)

        receipt = self.receipt()
        receipt["build"] = dict(receipt["build"])
        ledger = dict(receipt["build"]["unit_identity_ledger"])
        ledger["reservations_and_consumptions_retained"] = False
        unsigned_ledger = dict(ledger)
        unsigned_ledger.pop("ledger_identity_sha256")
        ledger["ledger_identity_sha256"] = core.sha256_bytes(
            core.canonical(unsigned_ledger)
        )
        receipt["build"]["unit_identity_ledger"] = ledger
        unsigned = dict(receipt)
        unsigned.pop("receipt_identity_sha256")
        receipt["receipt_identity_sha256"] = core.sha256_bytes(
            core.canonical(unsigned)
        )
        with self.assertRaises(core.Refused):
            target._validate_outer_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
