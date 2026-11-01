#!/usr/bin/env python3
"""Hostile controls for the fixed assignment-measurement build freezer."""

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

import freeze_assignment_measurement_build as target
import freeze_current_w1_source_build as core


class SyntheticSource:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-assignment-build-freezer-controls-"
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
            "poc/local-private-payment/native-authority/native-core/Cargo.toml",
            b'''[package]\nname="native-core"\nversion="0.1.0"\nedition="2024"\n\n[dependencies]\nnative={path="../vendor/native-relation"}\n''',
        )
        self._write(
            "poc/local-private-payment/native-authority/vendor/native-relation/"
            "Cargo.toml",
            b'''[package]\nname="native-relation"\nversion="0.1.0"\nedition="2024"\n''',
        )
        self._write(
            "poc/local-private-payment/private_batch_trial/auth_exit/Cargo.toml",
            b'''[package]\nname="auth-exit"\nversion="0.1.0"\nedition="2024"\n\n[dependencies]\nauthority={path="../../native-authority/native-core"}\nnative={path="../../native-authority/vendor/native-relation"}\n''',
        )
        for relative in sorted(target.REQUIRED_DEPENDENCY_RELATIVES):
            self._write(relative, f"// synthetic {relative}\n".encode())
        self._write(
            target.FORBIDDEN_ASSIGNMENT_DEPENDENCY_RELATIVE,
            b"// synthetic prover-only source\n",
        )

    def _write(self, relative: str, raw: bytes) -> Path:
        path = self.source / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def begin(self):
        return core._test_only_begin_candidate(
            self.source,
            target.PACKAGE_ROOTS,
            self.output,
            "assignment-measurement-build",
        )

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
                path = current / name
                try:
                    os.chmod(path, 0o600, follow_symlinks=False)
                except FileNotFoundError:
                    pass
            for name in directories:
                path = current / name
                try:
                    os.chmod(path, 0o700, follow_symlinks=False)
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


class FixedInterfaceControls(unittest.TestCase):
    def test_cli_accepts_only_no_arguments(self):
        with mock.patch.object(target, "run_freeze") as run:
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                result = target.main(["--help"])
            self.assertEqual(result, 2)
            self.assertIn("arguments-not-accepted", stderr.getvalue())
            run.assert_not_called()

        frozen = {
            "status": "TEST_ONLY_ASSIGNMENT_MEASUREMENT_BUILD_FROZEN",
            "authorization": False,
        }
        with mock.patch.object(target, "run_freeze", return_value=frozen) as run:
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                result = target.main([])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(stdout.getvalue()), frozen)
            run.assert_called_once_with()

    def test_fixed_build_command_is_locked_offline_and_not_an_execution(self):
        self.assertEqual(target.OUTPUT_PARENT.parent, target.PRIVATE_OUTPUT_BASE)
        self.assertFalse(target.OUTPUT_PARENT.is_relative_to(target.REPO_ROOT))
        snapshot = Path("/tmp/fixed-snapshot")
        build_target = Path("/tmp/fixed-target")
        command = target._cargo_build_command(snapshot, build_target)
        expected_filter = "SystemCallFilter=~" + " ".join(
            target.DENIED_BUILD_NETWORK_SYSCALLS
        )
        self.assertIn(expected_filter, command)
        self.assertIn("SystemCallErrorNumber=EPERM", command)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", command)
        self.assertIn("NoNewPrivileges=yes", command)
        self.assertNotIn("PrivateNetwork=yes", command)
        self.assertFalse(any("IPAddressDeny" in value for value in command))
        self.assertIn(f"CARGO_TARGET_DIR={build_target}", command)
        cargo = command.index(str(target.CARGO))
        self.assertEqual(
            command[cargo:],
            [
                str(target.CARGO),
                "build",
                "--release",
                "--locked",
                "--offline",
                "--no-default-features",
                "--features",
                "offline-w1-preparer",
                "--example",
                "prepare_frozen_w1_round1_assignment",
            ],
        )
        self.assertNotIn("offline-w1-prover", command)
        self.assertNotIn("run", command[cargo:])
        denied = set(target.DENIED_BUILD_NETWORK_SYSCALLS)
        for allowed in (
            "socket",
            "socketpair",
            "send",
            "recv",
            "sendto",
            "recvfrom",
        ):
            self.assertNotIn(allowed, denied)
        for required in (
            "connect",
            "bind",
            "listen",
            "accept",
            "sendmsg",
            "recvmsg",
        ):
            self.assertIn(required, denied)

    def test_probe_proves_fixed_spawn_families_and_denied_connect(self):
        command = target._network_probe_command()
        self.assertEqual(command[-3:-1], ["-I", "-c"])
        source = command[-1]
        self.assertIn("socket.socket", source)
        self.assertIn("socket.socketpair", source)
        self.assertIn("socket.SOCK_SEQPACKET", source)
        self.assertIn("left.send", source)
        self.assertIn("right.recv", source)
        self.assertIn('subprocess.run(["/bin/true"], check=True)', source)
        self.assertIn("standalone.connect", source)
        for forbidden in ("sendto(", "recvfrom("):
            self.assertNotIn(forbidden, source)


class SystemdPropertyControls(unittest.TestCase):
    @staticmethod
    def values() -> dict[str, str]:
        return {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "exited",
            "Result": "success",
            "ExecMainStatus": "0",
            "RestrictAddressFamilies": "AF_UNIX",
            "SystemCallFilter": "~" + " ".join(
                target.DENIED_BUILD_NETWORK_SYSCALLS
            ),
            "SystemCallErrorNumber": "1",
            "NoNewPrivileges": "yes",
            "LimitCORE": "0",
            "MemoryMax": str(12 * 1024**3),
            "MemorySwapMax": "0",
            "UMask": "0077",
        }

    def test_exact_enforced_property_shape_is_admitted(self):
        values = self.values()
        raw = "".join(f"{key}={values[key]}\n" for key in target.SHOW_PROPERTIES)
        parsed = target._parse_show(raw.encode())
        evidence = target._validate_active_unit_properties(parsed)
        self.assertEqual(
            set(evidence["denied_network_syscalls"]),
            set(target.DENIED_BUILD_NETWORK_SYSCALLS),
        )
        self.assertTrue(evidence["no_new_privileges"])
        self.assertEqual(evidence["memory_swap_max_bytes"], 0)

    def test_missing_duplicate_or_unknown_show_properties_refuse(self):
        values = self.values()
        good = "".join(f"{key}={values[key]}\n" for key in target.SHOW_PROPERTIES)
        cases = {
            "missing": good.replace("LoadState=loaded\n", ""),
            "duplicate": good + "LoadState=loaded\n",
            "unknown": good + "PrivateNetwork=yes\n",
            "invalid": "not-a-property\n",
        }
        for name, raw in cases.items():
            with self.subTest(name=name), self.assertRaises(core.Refused):
                target._parse_show(raw.encode())

    def test_each_weakened_runtime_property_refuses(self):
        cases = {
            "load": ("LoadState", "not-found"),
            "families": ("RestrictAddressFamilies", "~"),
            "errno": ("SystemCallErrorNumber", "13"),
            "privileges": ("NoNewPrivileges", "no"),
            "core": ("LimitCORE", "infinity"),
            "memory": ("MemoryMax", "infinity"),
            "swap": ("MemorySwapMax", "infinity"),
            "umask": ("UMask", "0002"),
            "filter": ("SystemCallFilter", "~socket"),
        }
        for name, (key, value) in cases.items():
            values = self.values()
            values[key] = value
            with self.subTest(name=name), self.assertRaises(core.Refused):
                target._validate_active_unit_properties(values)

    def test_ignored_restriction_warnings_refuse(self):
        warnings = (
            "proceeding without network namespace",
            "kernel does not support setting",
            "failed to apply sandbox",
            "unknown lvalue",
            "invalid argument",
        )
        for warning in warnings:
            completed = mock.Mock(returncode=0, stdout=warning.encode(), stderr=b"")
            with mock.patch.object(target.subprocess, "run", return_value=completed):
                with self.subTest(warning=warning), self.assertRaises(core.Refused):
                    target._unit_journal(target.PROBE_UNIT)


class DependencyControls(SyntheticCase):
    def _outputs(self, session, dependencies=None, dep_target=None):
        release = session.target_root / "release" / "examples"
        release.mkdir(mode=0o700, parents=True)
        binary = release / target.EXAMPLE_NAME
        binary.write_bytes(b"synthetic assignment build; never executed\n")
        dependencies = dependencies or sorted(target.REQUIRED_DEPENDENCY_RELATIVES)
        dependency_paths = [
            str(session.snapshot_root / relative) for relative in dependencies
        ]
        dep_info = binary.with_suffix(".d")
        dep_info.write_text(
            f"{dep_target or binary}: {' '.join(dependency_paths)}\n"
        )
        return binary, dep_info

    def _derive(self, session, binary, dep_info):
        relatives, evidence = target._derive_dep_info_members(
            dep_info.read_bytes(),
            snapshot_root=session.snapshot_root,
            target_root=session.target_root,
            original_source_root=session.source_root,
            snapshot_refs=session.snapshot_refs,
            expected_target=binary,
        )
        self.dep_evidence = evidence
        return relatives

    def test_synthetic_four_package_build_outputs_atomically_freeze(self):
        session = self.fixture.begin()
        target._validate_manifest_packages(session.manifest)
        self.assertEqual(
            tuple(session.manifest["package_roots"]),
            target.EXPECTED_PACKAGE_ROOTS,
        )
        binary, dep_info = self._outputs(session)
        relatives = self._derive(session, binary, dep_info)
        result = core._test_only_finalize_candidate(
            session,
            binary=binary,
            dep_info=dep_info,
            expected_target=binary,
            expected_dependency_relatives=relatives,
        )
        self.assertFalse(result["production_build"])
        self.assertFalse(result["authorization"])
        frozen = Path(result["root"])
        self.assertEqual(stat.S_IMODE(frozen.stat().st_mode), 0o500)
        receipt = json.loads((frozen / "BUILD-RECEIPT.json").read_bytes())
        self.assertEqual(
            receipt["classification"],
            "TEST_ONLY_FILESYSTEM_CONTRACT_NOT_A_BUILD_AUTHORITY",
        )
        self.assertFalse(receipt["actual_subprocess_build_executed_by_contract"])
        self.assertFalse(receipt["proof"])
        self.assertFalse(receipt["network"])

    def test_manifest_must_have_exact_four_recursive_packages(self):
        session = self.fixture.begin()
        for roots in (
            list(target.EXPECTED_PACKAGE_ROOTS[:-1]),
            list(target.EXPECTED_PACKAGE_ROOTS) + ["extra/package"],
            list(reversed(target.EXPECTED_PACKAGE_ROOTS)),
        ):
            manifest = dict(session.manifest)
            manifest["package_roots"] = roots
            with self.subTest(roots=roots), self.assertRaises(core.Refused):
                target._validate_manifest_packages(manifest)

    def test_live_external_relative_unmanifested_and_wrong_target_refuse(self):
        cases = (
            "live",
            "external",
            "relative",
            "unmanifested",
            "alias_escape",
            "target",
        )
        for case in cases:
            with self.subTest(case=case):
                self.fixture.close()
                self.fixture = SyntheticSource()
                session = self.fixture.begin()
                binary, dep_info = self._outputs(session)
                target_path, dependencies = core._parse_dep_info(dep_info.read_bytes())
                if case == "live":
                    dependencies[0] = str(
                        session.source_root
                        / sorted(target.REQUIRED_DEPENDENCY_RELATIVES)[0]
                    )
                elif case == "external":
                    dependencies[0] = "/etc/passwd"
                elif case == "relative":
                    dependencies[0] = "relative.rs"
                elif case == "unmanifested":
                    dependencies[0] = str(session.snapshot_root / "not-manifested.rs")
                elif case == "alias_escape":
                    dependencies[0] = str(
                        session.snapshot_root
                        / os.path.relpath("/etc/passwd", session.snapshot_root)
                    )
                else:
                    target_path = str(session.target_root / "wrong-binary")
                dep_info.write_text(f"{target_path}: {' '.join(dependencies)}\n")
                with self.assertRaises(core.Refused):
                    self._derive(session, binary, dep_info)

    def test_missing_required_and_duplicate_dependencies_refuse(self):
        session = self.fixture.begin()
        members = sorted(target.REQUIRED_DEPENDENCY_RELATIVES)
        binary, dep_info = self._outputs(session, members[:-1])
        with self.assertRaises(core.Refused):
            self._derive(session, binary, dep_info)

        dep_info.write_text(
            f"{binary}: "
            + " ".join(
                str(session.snapshot_root / value)
                for value in members + [members[-1]]
            )
            + "\n"
        )
        with self.assertRaises(core.Refused):
            self._derive(session, binary, dep_info)

    def test_prover_only_sources_explicitly_refuse_assignment_dep_info(self):
        cases = (
            (
                target.FORBIDDEN_ASSIGNMENT_DEPENDENCY_RELATIVE,
                "dep-info-offline-w1-prover-source",
            ),
            (
                target.FORBIDDEN_LOW_MEMORY_PREFIX + "src/main.rs",
                "dep-info-low-memory-prover-source",
            ),
        )
        for forbidden, reason in cases:
            with self.subTest(forbidden=forbidden):
                self.fixture.close()
                self.fixture = SyntheticSource()
                session = self.fixture.begin()
                members = sorted(target.REQUIRED_DEPENDENCY_RELATIVES) + [forbidden]
                binary, dep_info = self._outputs(session, members)
                with self.assertRaisesRegex(core.Refused, reason):
                    self._derive(session, binary, dep_info)

    def test_lexical_alias_is_inode_bound_and_duplicate_is_recorded(self):
        session = self.fixture.begin()
        members = sorted(target.REQUIRED_DEPENDENCY_RELATIVES)
        alias = (
            "poc/local-private-payment/private_batch_trial/auth_exit/src/"
            "../../../native-authority/native-core/src/lib.rs"
        )
        binary, dep_info = self._outputs(session, members + [alias])
        relatives = self._derive(session, binary, dep_info)
        self.assertEqual(len(relatives), len(members))
        evidence = self.dep_evidence
        self.assertEqual(evidence["raw_dependency_count"], len(members) + 1)
        self.assertEqual(evidence["canonical_unique_dependency_count"], len(members))
        self.assertEqual(evidence["lexical_alias_count"], 1)
        self.assertEqual(evidence["duplicate_canonical_member_count"], 1)
        mapping = evidence["mappings"][-1]
        self.assertTrue(mapping["lexical_alias"])
        self.assertTrue(mapping["duplicate_canonical_member"])
        self.assertIsNotNone(mapping["duplicate_of_raw_index"])

        detached = session.target_root / "admission" / "binary"
        normalized, normalization = target._normalize_dep_info(
            dep_info.read_bytes(),
            original_target=binary,
            detached_target=detached,
            target_root=session.target_root,
            canonical_dependency_absolutes=evidence[
                "canonical_dependency_absolutes"
            ],
        )
        normalized_target, normalized_dependencies = core._parse_dep_info(normalized)
        self.assertEqual(normalized_target, str(detached))
        self.assertEqual(len(normalized_dependencies), len(members))
        self.assertEqual(normalization["canonical_duplicate_count"], 1)

    def test_hardlink_alias_normalization_freezes_via_core(self):
        session = self.fixture.begin()
        members = sorted(target.REQUIRED_DEPENDENCY_RELATIVES)
        alias = (
            "poc/local-private-payment/private_batch_trial/auth_exit/src/"
            "../../../native-authority/native-core/src/lib.rs"
        )
        cargo_binary, cargo_dep_info = self._outputs(session, members + [alias])
        os.chmod(cargo_binary, 0o700)
        os.link(cargo_binary, cargo_binary.with_name("cargo-hashed-example"))
        binary_raw, binary_reference = target._stable_cargo_hardlinked_binary(
            cargo_binary
        )
        relatives = self._derive(session, cargo_binary, cargo_dep_info)
        evidence = self.dep_evidence
        admission = session.target_root / "admission"
        admission.mkdir(mode=0o700)
        detached = admission / "binary"
        detached_reference = core._write_new(detached, binary_raw, 0o500)
        normalized, _ = target._normalize_dep_info(
            cargo_dep_info.read_bytes(),
            original_target=cargo_binary,
            detached_target=detached,
            target_root=session.target_root,
            canonical_dependency_absolutes=evidence[
                "canonical_dependency_absolutes"
            ],
        )
        normalized_dep_info = admission / "binary.d"
        core._write_new(normalized_dep_info, normalized, 0o400)
        result = core._test_only_finalize_candidate(
            session,
            binary=detached,
            dep_info=normalized_dep_info,
            expected_target=detached,
            expected_dependency_relatives=relatives,
        )
        frozen = Path(result["root"])
        self.assertEqual(
            core._stable_file_identity(
                frozen / "artifacts/candidate-binary", 0o500
            )["sha256"],
            binary_reference["sha256"],
        )
        receipt = json.loads((frozen / "BUILD-RECEIPT.json").read_bytes())
        self.assertEqual(receipt["dep_info"]["dependency_count"], len(members))
        self.assertEqual(detached_reference["sha256"], binary_reference["sha256"])


class CargoOutputControls(unittest.TestCase):
    def test_cargo_hardlink_is_stably_read_then_detached_create_new(self):
        with tempfile.TemporaryDirectory(
            prefix="kpb-assignment-cargo-hardlink-control-"
        ) as temporary:
            root = Path(temporary)
            binary = root / "example"
            alias = root / "example-hash"
            binary.write_bytes(b"synthetic cargo binary; never executed\n")
            os.chmod(binary, 0o700)
            os.link(binary, alias)
            raw, reference = target._stable_cargo_hardlinked_binary(binary)
            self.assertEqual(reference["link_count"], 2)
            self.assertEqual(reference["sha256"], core.sha256_bytes(raw))
            detached = root / "detached"
            detached_reference = core._write_new(detached, raw, 0o500)
            self.assertEqual(detached_reference["sha256"], reference["sha256"])
            self.assertEqual(os.lstat(detached).st_nlink, 1)

            os.link(binary, root / "third-link")
            with self.assertRaisesRegex(core.Refused, "cargo-binary-hardlink-shape"):
                target._stable_cargo_hardlinked_binary(binary)


class ExecutedSourceControls(unittest.TestCase):
    def test_mid_build_core_source_change_refuses(self):
        with tempfile.TemporaryDirectory(
            prefix="kpb-assignment-core-source-change-control-"
        ) as temporary:
            source = Path(temporary) / "freeze_current_w1_source_build.py"
            source.write_bytes(b"executed core source version one\n")
            initial_raw, initial_reference = target._capture_python_source(source)
            self.assertEqual(
                target._require_python_source_unchanged(
                    source, initial_raw, initial_reference
                ),
                initial_reference,
            )
            source.write_bytes(b"hostile core source version two!!\n")
            with self.assertRaisesRegex(
                core.Refused, "python-source-changed-during-build"
            ):
                target._require_python_source_unchanged(
                    source, initial_raw, initial_reference
                )

class OuterEvidenceControls(unittest.TestCase):
    DEP_RAW = b"/tmp/cargo-binary: /tmp/snapshot/source.rs\n"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-assignment-build-outer-evidence-controls-"
        )
        self.parent = Path(self.temporary.name) / "parent"
        self.parent.mkdir(mode=0o700)

    def tearDown(self):
        SyntheticSource._unseal(Path(self.temporary.name))
        self.temporary.cleanup()

    @staticmethod
    def receipt():
        return target._receipt_identity(
            {
                "schema": target.RECEIPT_SCHEMA,
                "classification": target.CLASSIFICATION,
                "actions": target._fixed_actions(),
                "dep_info": {
                    "cargo_original": {
                        "frozen_original": {
                            "name": "CARGO-ORIGINAL-DEP-INFO.d",
                            "bytes": len(OuterEvidenceControls.DEP_RAW),
                            "sha256": core.sha256_bytes(
                                OuterEvidenceControls.DEP_RAW
                            ),
                            "mode_octal": "0400",
                            "link_count": 1,
                        }
                    }
                },
                "privacy_acceptance": False,
                "financial_acceptance": False,
                "authorization": False,
            }
        )

    def test_outer_source_and_receipt_publish_create_new_and_sealed(self):
        receipt = self.receipt()
        result = target._publish_outer_evidence(
            self.parent,
            b"synthetic fixed freezer source\n",
            self.DEP_RAW,
            receipt,
        )
        root = Path(result["root"])
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o500)
        self.assertEqual(
            set(os.listdir(root)),
            {
                "FREEZER-SOURCE.py",
                "CARGO-ORIGINAL-DEP-INFO.d",
                "MEASUREMENT-BUILD-RECEIPT.json",
            },
        )
        for name in os.listdir(root):
            self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o400)
        observed = json.loads((root / "MEASUREMENT-BUILD-RECEIPT.json").read_bytes())
        target._validate_outer_receipt(observed)
        with self.assertRaises(core.Refused):
            target._publish_outer_evidence(
                self.parent, b"replacement refused\n", self.DEP_RAW, receipt
            )

    def test_authority_privacy_proof_or_network_claims_refuse(self):
        for field, value in (
            ("authorization", True),
            ("privacy_acceptance", True),
            ("financial_acceptance", True),
        ):
            receipt = self.receipt()
            receipt[field] = value
            unsigned = dict(receipt)
            unsigned.pop("receipt_identity_sha256")
            receipt["receipt_identity_sha256"] = core.sha256_bytes(
                core.canonical(unsigned)
            )
            with self.subTest(field=field), self.assertRaises(core.Refused):
                target._validate_outer_receipt(receipt)

        for action in ("proof", "network_communication", "pk_decode"):
            receipt = self.receipt()
            receipt["actions"] = dict(receipt["actions"])
            receipt["actions"][action] = True
            unsigned = dict(receipt)
            unsigned.pop("receipt_identity_sha256")
            receipt["receipt_identity_sha256"] = core.sha256_bytes(
                core.canonical(unsigned)
            )
            with self.subTest(action=action), self.assertRaises(core.Refused):
                target._validate_outer_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
