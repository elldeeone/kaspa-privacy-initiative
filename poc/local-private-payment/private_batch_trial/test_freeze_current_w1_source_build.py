#!/usr/bin/env python3
"""Hostile controls for the inert current-source W1 build freezer."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import freeze_current_w1_source_build as target


class Fixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-current-w1-source-freezer-controls-"
        )
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.output = self.root / "output"
        self.source.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        self._write(
            "app/Cargo.toml",
            b'''[package]\nname = "app"\nversion = "0.1.0"\nedition = "2024"\n\n[dependencies]\ndep = { path = "../dep" }\n''',
        )
        self._write("app/src/lib.rs", b"pub fn app() -> u8 { dep::value() }\n")
        self._write("app/README.md", b"current source candidate\n")
        self._write(
            "dep/Cargo.toml",
            b'''[package]\nname = "dep"\nversion = "0.1.0"\nedition = "2024"\n''',
        )
        self._write("dep/src/lib.rs", b"pub fn value() -> u8 { 7 }\n")
        # Generated state must never enter the source snapshot.
        self._write("app/target/release/stale", b"not source\n")

    def _write(self, relative: str, raw: bytes) -> Path:
        path = self.source / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def begin(self, name: str = "candidate"):
        return target._test_only_begin_candidate(
            self.source, ("app",), self.output, name
        )

    def build_outputs(self, session, dependencies=None):
        release = session.target_root / "release"
        release.mkdir(mode=0o700)
        binary = release / "app-bin"
        binary.write_bytes(b"synthetic-build-output-not-executable\n")
        dependencies = dependencies or ("app/src/lib.rs", "dep/src/lib.rs")
        absolute = [str(session.snapshot_root / value) for value in dependencies]
        dep_info = release / "app-bin.d"
        dep_info.write_text(f"{binary}: {' '.join(absolute)}\n")
        return binary, dep_info

    def close(self):
        self.temporary.cleanup()


class FreezerCase(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.close()


class StatusControls(unittest.TestCase):
    def test_status_is_inert_and_cli_has_no_build_or_freeze_command(self):
        status = target.status()
        self.assertFalse(status["go"])
        self.assertFalse(status["authorization"])
        self.assertFalse(any(status["actions_performed"].values()))
        self.assertEqual(
            status["pending_bindings"],
            {
                "source_manifest_sha256": None,
                "freezer_source_sha256": None,
                "assignment_preparer_sha256": None,
                "low_memory_runner_sha256": None,
                "build_commands": None,
            },
        )
        for key in (
            "locked_offline_cargo_metadata_graph_bound",
            "workspace_inherited_dependencies_resolved",
            "workspace_patch_replace_resolved",
            "cargo_config_path_sources_and_wrappers_resolved",
            "all_ancestor_manifest_and_cargo_config_semantics_resolved",
            "build_script_proc_macro_ambient_reads_sandboxed",
            "production_expected_dependency_set_derived",
            "production_filesystem_sandbox_present",
            "production_source_manifest_bound",
            "production_freezer_source_bound",
            "production_assignment_preparer_bound",
            "production_low_memory_runner_bound",
            "production_build_commands_bound",
            "production_build_execution_present",
            "production_binary_acceptance_present",
            "production_launch_enabled",
            "authorization",
        ):
            self.assertFalse(status["source_status"][key], key)
        self.assertTrue(
            status["source_status"]["recursive_direct_path_package_snapshot_core"]
        )
        self.assertTrue(
            status["source_status"]["selected_unresolved_package_features_refuse_core"]
        )
        self.assertNotIn(
            "complete_transitive_local_source_deriver_present",
            status["source_status"],
        )
        result = subprocess.run(
            [sys.executable, str(Path(target.__file__)), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("{status}", result.stdout)
        for forbidden in ("build", "freeze", "execute", "publish", "prove"):
            self.assertNotIn("{" + forbidden, result.stdout)


class ManifestControls(FreezerCase):
    def test_derives_recursive_direct_path_package_set_and_excludes_target(self):
        manifest = target.derive_recursive_direct_path_package_manifest(
            self.fixture.source, ("app",)
        )
        target._validate_manifest(manifest)
        paths = [item["relative_path"] for item in manifest["members"]]
        self.assertEqual(
            paths,
            [
                "app/Cargo.toml",
                "app/README.md",
                "app/src/lib.rs",
                "dep/Cargo.toml",
                "dep/src/lib.rs",
            ],
        )
        self.assertEqual(manifest["package_roots"], ["app", "dep"])
        self.assertNotIn("app/target/release/stale", paths)
        self.assertFalse(manifest["authorization"])

    def test_symlink_missing_package_and_outside_path_dependency_refuse(self):
        link = self.fixture.source / "app/src/alias.rs"
        link.symlink_to("lib.rs")
        with self.assertRaises(target.Refused):
            target.derive_recursive_direct_path_package_manifest(
                self.fixture.source, ("app",)
            )
        link.unlink()

        with self.assertRaises(target.Refused):
            target.derive_recursive_direct_path_package_manifest(
                self.fixture.source, ("missing",)
            )

        outside = self.fixture.root / "outside"
        outside.mkdir(mode=0o700)
        (outside / "Cargo.toml").write_text(
            '[package]\nname="outside"\nversion="0.1.0"\n'
        )
        manifest = self.fixture.source / "app/Cargo.toml"
        manifest.write_text(
            '[package]\nname="app"\nversion="0.1.0"\n'
            '[dependencies]\noutside={path="../../outside"}\n'
        )
        with self.assertRaises(target.Refused):
            target.derive_recursive_direct_path_package_manifest(
                self.fixture.source, ("app",)
            )

    def test_extra_or_missing_live_member_during_snapshot_refuses(self):
        original = target._snapshot_members

        def add_extra(source_root, snapshot_root, manifest):
            refs = original(source_root, snapshot_root, manifest)
            self.fixture._write("app/src/late.rs", b"pub fn late() {}\n")
            return refs

        with mock.patch.object(target, "_snapshot_members", side_effect=add_extra):
            with self.assertRaises(target.Refused):
                self.fixture.begin("extra-race")

        self.fixture.close()
        self.fixture = Fixture()

        def remove_member(source_root, snapshot_root, manifest):
            refs = original(source_root, snapshot_root, manifest)
            (self.fixture.source / "app/README.md").unlink()
            return refs

        with mock.patch.object(target, "_snapshot_members", side_effect=remove_member):
            with self.assertRaises(target.Refused):
                self.fixture.begin("missing-race")

    def test_unresolved_cargo_graph_and_ambient_reader_features_refuse(self):
        cases = ("workspace", "patch", "config", "build-script", "proc-macro")
        for case in cases:
            with self.subTest(case=case):
                self.fixture.close()
                self.fixture = Fixture()
                manifest = self.fixture.source / "app/Cargo.toml"
                if case == "workspace":
                    manifest.write_text(
                        '[package]\nname="app"\nversion="0.1.0"\n'
                        '[dependencies]\ndep={workspace=true}\n'
                    )
                elif case == "patch":
                    manifest.write_text(
                        manifest.read_text()
                        + '\n[patch.crates-io]\ndep={path="../dep"}\n'
                    )
                elif case == "config":
                    self.fixture._write(
                        ".cargo/config.toml",
                        b'[source.vendor]\ndirectory="vendor"\n',
                    )
                elif case == "build-script":
                    self.fixture._write("app/build.rs", b"fn main() {}\n")
                else:
                    manifest.write_text(
                        manifest.read_text() + "\n[lib]\nproc-macro=true\n"
                    )
                with self.assertRaises(target.Refused):
                    target.derive_recursive_direct_path_package_manifest(
                        self.fixture.source, ("app",)
                    )


class SnapshotControls(FreezerCase):
    def test_source_path_swap_during_copy_refuses(self):
        source = self.fixture.source / "app/src/lib.rs"
        raw = source.read_bytes()
        identity = target._stable_file_identity(source)
        expected = {
            "relative_path": "app/src/lib.rs",
            "bytes": identity["bytes"],
            "sha256": identity["sha256"],
        }
        destination = self.fixture.output / "copy.rs"
        real_read = os.read
        swapped = False

        def race(fd, size):
            nonlocal swapped
            block = real_read(fd, size)
            if not swapped:
                swapped = True
                old = source.with_suffix(".old")
                source.rename(old)
                source.write_bytes(raw)
            return block

        with mock.patch.object(target.os, "read", side_effect=race):
            with self.assertRaises(target.Refused):
                target._copy_exact_source(source, destination, expected)

    def test_snapshot_content_or_inode_substitution_refuses(self):
        session = self.fixture.begin()
        selected = session.snapshot_root / "app/src/lib.rs"
        os.chmod(selected, 0o600)
        selected.write_bytes(b"mutated snapshot\n")
        os.chmod(selected, 0o400)
        with self.assertRaises(target.Refused):
            target._verify_snapshot(session.snapshot_root, session.snapshot_refs)

        other = self.fixture.begin("inode-substitution")
        selected = other.snapshot_root / "app/src/lib.rs"
        parent = selected.parent
        os.chmod(parent, 0o700)
        selected.rename(selected.with_name("lib-original.rs"))
        selected.write_bytes(b"pub fn app() -> u8 { dep::value() }\n")
        os.chmod(selected, 0o400)
        os.chmod(parent, 0o500)
        with self.assertRaises(target.Refused):
            target._verify_snapshot(other.snapshot_root, other.snapshot_refs)

    def test_extra_empty_directory_and_directory_state_drift_refuse(self):
        session = self.fixture.begin("extra-empty-dir")
        os.chmod(session.snapshot_root, 0o700)
        extra = session.snapshot_root / "unmanifested-empty"
        extra.mkdir(mode=0o500)
        os.chmod(session.snapshot_root, 0o500)
        with self.assertRaises(target.Refused):
            target._verify_snapshot(session.snapshot_root, session.snapshot_refs)

        reference = target._directory_ref(self.fixture.output, 0o700)
        self.assertEqual(
            set(reference),
            {
                "device",
                "inode",
                "link_count",
                "bytes",
                "owner_uid",
                "mode_octal",
                "mtime_ns",
                "ctime_ns",
            },
        )
        (self.fixture.output / "state-drift").mkdir(mode=0o700)
        with self.assertRaises(target.Refused):
            target._require_same_directory(self.fixture.output, reference, 0o700)


class DepInfoControls(FreezerCase):
    def setUp(self):
        super().setUp()
        self.session = self.fixture.begin()
        self.binary, self.dep_info = self.fixture.build_outputs(self.session)
        self.expected = ("app/src/lib.rs", "dep/src/lib.rs")

    def validate(self, raw):
        return target._validate_test_only_snapshot_dep_info(
            raw,
            snapshot_root=self.session.snapshot_root,
            target_root=self.session.target_root,
            expected_target=self.binary,
            snapshot_refs=self.session.snapshot_refs,
            caller_expected_dependency_relatives=self.expected,
            original_source_root=self.fixture.source,
        )

    def test_exact_snapshot_only_dep_info_passes(self):
        value = self.validate(self.dep_info.read_bytes())
        self.assertTrue(value["snapshot_only"])
        self.assertFalse(value["live_path_provenance"])
        self.assertEqual(value["dependency_count"], 2)
        self.assertEqual(
            value["expected_dependency_authority"],
            "CALLER_SUPPLIED_TEST_FIXTURE_ONLY",
        )
        self.assertFalse(value["production_expected_dependency_set_derived"])

    def test_live_extra_missing_reordered_and_wrong_target_dep_info_refuse(self):
        healthy = self.dep_info.read_text()
        rules = [
            f"{self.binary}: {self.fixture.source / 'app/src/lib.rs'}\n",
            healthy.rstrip() + f" {self.session.snapshot_root / 'app/README.md'}\n",
            f"{self.binary}: {self.session.snapshot_root / 'app/src/lib.rs'}\n",
            (
                f"{self.binary}: {self.session.snapshot_root / 'dep/src/lib.rs'} "
                f"{self.session.snapshot_root / 'app/src/lib.rs'}\n"
            ),
            healthy.replace(str(self.binary), str(self.session.target_root / "other"), 1),
        ]
        for raw in rules:
            with self.subTest(raw=raw), self.assertRaises(target.Refused):
                self.validate(raw.encode())

    def test_dep_info_symlink_refuses_before_freeze(self):
        alias = self.dep_info.with_name("alias.d")
        alias.symlink_to(self.dep_info.name)
        with self.assertRaises(target.Refused):
            target._stable_file_bytes(alias)


class PublicationControls(FreezerCase):
    def test_success_is_atomic_read_only_and_explicitly_test_only(self):
        session = self.fixture.begin()
        binary, dep_info = self.fixture.build_outputs(session)
        with mock.patch.object(
            target, "_rename_no_replace_at", wraps=target._rename_no_replace_at
        ) as rename:
            value = target._test_only_finalize_candidate(
                session,
                binary=binary,
                dep_info=dep_info,
                expected_target=binary,
                expected_dependency_relatives=("app/src/lib.rs", "dep/src/lib.rs"),
            )
        rename.assert_called_once()
        parent_fd, source_name, destination_name = rename.call_args.args
        self.assertIsInstance(parent_fd, int)
        self.assertNotIn("/", source_name)
        self.assertEqual(destination_name, "candidate")
        self.assertEqual(
            value["status"], "TEST_ONLY_CURRENT_SOURCE_FREEZE_CONTRACT_COMPLETE"
        )
        self.assertFalse(value["production_build"])
        self.assertFalse(value["authorization"])
        root = Path(value["root"])
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o500)
        for directory in (root / "sources", root / "artifacts"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o500)
        for relative in (
            "sources/app/Cargo.toml",
            "sources/app/src/lib.rs",
            "SOURCE-MANIFEST.json",
            "FREEZER-SOURCE.py",
            "BUILD-RECEIPT.json",
            "artifacts/candidate-binary.d",
        ):
            self.assertEqual(stat.S_IMODE((root / relative).stat().st_mode), 0o400)
        self.assertEqual(
            stat.S_IMODE((root / "artifacts/candidate-binary").stat().st_mode),
            0o500,
        )
        receipt = json.loads((root / "BUILD-RECEIPT.json").read_bytes())
        self.assertEqual(
            receipt["freezer_source"]["sha256"],
            target.sha256_bytes((root / "FREEZER-SOURCE.py").read_bytes()),
        )
        self.assertFalse(receipt["actual_subprocess_build_executed_by_contract"])
        self.assertFalse(receipt["production_source_manifest_bound"])
        self.assertFalse(receipt["production_binary_accepted"])
        for key in (
            "setup",
            "pk_decode",
            "synthesis",
            "proof",
            "network",
            "funds",
            "authorization",
        ):
            self.assertFalse(receipt[key], key)
        self.assertTrue(receipt["snapshot_same_inodes_before_after"])
        self.assertTrue(receipt["dep_info"]["snapshot_only"])
        with self.assertRaises(target.Refused):
            target._test_only_finalize_candidate(
                session,
                binary=binary,
                dep_info=dep_info,
                expected_target=binary,
                expected_dependency_relatives=("app/src/lib.rs", "dep/src/lib.rs"),
            )
        with self.assertRaises(target.Refused):
            self.fixture.begin()

    def test_publish_collision_never_replaces_existing_final(self):
        session = self.fixture.begin("collision")
        binary, dep_info = self.fixture.build_outputs(session)
        final = self.fixture.output / "collision"
        final.mkdir(mode=0o700)
        marker = final / "sentinel"
        marker.write_bytes(b"keep\n")
        with self.assertRaises((FileExistsError, target.Refused)):
            target._test_only_finalize_candidate(
                session,
                binary=binary,
                dep_info=dep_info,
                expected_target=binary,
                expected_dependency_relatives=("app/src/lib.rs", "dep/src/lib.rs"),
            )
        self.assertEqual(marker.read_bytes(), b"keep\n")

    def test_build_output_must_be_regular_target_member(self):
        session = self.fixture.begin("bad-output")
        binary, dep_info = self.fixture.build_outputs(session)
        outside = self.fixture.root / "outside-binary"
        outside.write_bytes(binary.read_bytes())
        with self.assertRaises(target.Refused):
            target._test_only_finalize_candidate(
                session,
                binary=outside,
                dep_info=dep_info,
                expected_target=binary,
                expected_dependency_relatives=("app/src/lib.rs", "dep/src/lib.rs"),
            )

    def test_extra_bundle_leaf_and_target_directory_substitution_refuse(self):
        session = self.fixture.begin("extra-leaf")
        binary, dep_info = self.fixture.build_outputs(session)
        (session.staging_root / "unreviewed").write_bytes(b"extra\n")
        with self.assertRaises(target.Refused):
            target._test_only_finalize_candidate(
                session,
                binary=binary,
                dep_info=dep_info,
                expected_target=binary,
                expected_dependency_relatives=("app/src/lib.rs", "dep/src/lib.rs"),
            )

        other = self.fixture.begin("target-swap")
        binary, dep_info = self.fixture.build_outputs(other)
        original = other.target_root.with_name(other.target_root.name + "-original")
        other.target_root.rename(original)
        other.target_root.mkdir(mode=0o700)
        with self.assertRaises(target.Refused):
            target._test_only_finalize_candidate(
                other,
                binary=other.target_root / "release/app-bin",
                dep_info=other.target_root / "release/app-bin.d",
                expected_target=other.target_root / "release/app-bin",
                expected_dependency_relatives=("app/src/lib.rs", "dep/src/lib.rs"),
            )


if __name__ == "__main__":
    unittest.main()
