#!/usr/bin/env python3
"""Hostile controls for the historical W1 source-closure sealer."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("reconstruct_historical_w1_source_closure.py")
SPEC = importlib.util.spec_from_file_location("historical_w1_sealer", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SEALER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEALER)
SOURCE_SEALER_PATH = Path(__file__).with_name("seal_reviewed_historical_w1_generator.py")
SOURCE_SEALER_SPEC = importlib.util.spec_from_file_location("historical_w1_source_sealer", SOURCE_SEALER_PATH)
assert SOURCE_SEALER_SPEC is not None and SOURCE_SEALER_SPEC.loader is not None
SOURCE_SEALER = importlib.util.module_from_spec(SOURCE_SEALER_SPEC)
SOURCE_SEALER_SPEC.loader.exec_module(SOURCE_SEALER)


class HistoricalW1SealerControls(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="w1-historical-sealer-control-"))
        self.parent = os.open(
            self.temporary,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | SEALER.O_CLOEXEC,
        )
        self.stage_name, self.root = SEALER.create_staging(self.parent, ".stage-")
        os.mkdir("members", 0o700, dir_fd=self.root)
        self.members, _ = SEALER._open_directory_at(self.root, "members")
        self.member_name = "000-" + ("a" * 64)
        self.expected = {
            "CONTROL.json": SEALER.write_bytes_at(self.root, "CONTROL.json", b"{}\n"),
            f"members/{self.member_name}": SEALER.write_bytes_at(
                self.members, self.member_name, b"historical-member\n"
            ),
        }
        os.fchmod(self.members, 0o500)
        os.fsync(self.members)
        self.member_state = SEALER._directory_state(os.fstat(self.members))
        os.fchmod(self.root, 0o500)
        os.fsync(self.root)
        self.root_state = SEALER._directory_state(os.fstat(self.root))
        self.validate()

    def tearDown(self) -> None:
        for descriptor in (getattr(self, "members", None), getattr(self, "root", None)):
            if descriptor is not None:
                try:
                    os.fchmod(descriptor, 0o700)
                except OSError:
                    pass
        for descriptor in (getattr(self, "members", None), getattr(self, "root", None), getattr(self, "parent", None)):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if getattr(self, "temporary", None) is not None:
            for directory, directories, files in os.walk(self.temporary):
                for name in directories:
                    try:
                        os.chmod(Path(directory) / name, 0o700, follow_symlinks=False)
                    except (OSError, NotImplementedError):
                        pass
                for name in files:
                    try:
                        os.chmod(Path(directory) / name, 0o600, follow_symlinks=False)
                    except (OSError, NotImplementedError):
                        pass
            shutil.rmtree(self.temporary)

    def validate(self) -> None:
        SEALER.validate_tree(
            self.parent,
            self.stage_name,
            self.root,
            self.root_state,
            self.member_state,
            self.expected,
            [self.member_name],
        )

    def refresh_member_state(self) -> None:
        self.member_state = SEALER._directory_state(os.fstat(self.members))

    def test_crash_retains_private_staging_and_final_name_is_absent(self) -> None:
        self.assertFalse(SEALER._missing_at(self.parent, self.stage_name))
        self.assertTrue(SEALER._missing_at(self.parent, "final"))

    def test_reviewed_generator_hash_is_pinned_by_source_sealer(self) -> None:
        raw = MODULE_PATH.read_bytes()
        self.assertEqual(SEALER.digest(raw), SOURCE_SEALER.EXPECTED_GENERATOR_SHA256)

    def test_extra_member_is_rejected(self) -> None:
        os.fchmod(self.members, 0o700)
        SEALER.write_bytes_at(self.members, "extra", b"extra\n")
        os.fchmod(self.members, 0o500)
        self.refresh_member_state()
        with self.assertRaisesRegex(SEALER.Refused, "sealed-member-set-order"):
            self.validate()

    def test_missing_member_is_rejected(self) -> None:
        os.fchmod(self.members, 0o700)
        os.unlink(self.member_name, dir_fd=self.members)
        os.fchmod(self.members, 0o500)
        self.refresh_member_state()
        with self.assertRaisesRegex(SEALER.Refused, "sealed-member-set-order"):
            self.validate()

    def test_add_delete_churn_is_rejected_by_directory_times(self) -> None:
        os.fchmod(self.members, 0o700)
        SEALER.write_bytes_at(self.members, "transient", b"transient\n")
        os.unlink("transient", dir_fd=self.members)
        os.fchmod(self.members, 0o500)
        with self.assertRaisesRegex(SEALER.Refused, "sealed-member-directory"):
            self.validate()

    def test_same_bytes_member_substitution_is_rejected_by_inode(self) -> None:
        os.fchmod(self.members, 0o700)
        os.unlink(self.member_name, dir_fd=self.members)
        SEALER.write_bytes_at(self.members, self.member_name, b"historical-member\n")
        os.fchmod(self.members, 0o500)
        self.refresh_member_state()
        with self.assertRaisesRegex(SEALER.Refused, "sealed-file-substitution"):
            self.validate()

    def test_symlink_member_substitution_is_rejected(self) -> None:
        os.fchmod(self.members, 0o700)
        os.unlink(self.member_name, dir_fd=self.members)
        os.symlink("../CONTROL.json", self.member_name, dir_fd=self.members)
        os.fchmod(self.members, 0o500)
        self.refresh_member_state()
        with self.assertRaisesRegex(SEALER.Refused, "sealed-file-substitution"):
            self.validate()

    def test_same_size_in_place_change_is_rejected_by_times(self) -> None:
        os.chmod(self.member_name, 0o600, dir_fd=self.members, follow_symlinks=False)
        descriptor = os.open(
            self.member_name,
            os.O_WRONLY | os.O_NOFOLLOW | SEALER.O_CLOEXEC,
            dir_fd=self.members,
        )
        try:
            os.pwrite(descriptor, b"H", 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(self.member_name, 0o400, dir_fd=self.members, follow_symlinks=False)
        with self.assertRaisesRegex(SEALER.Refused, "sealed-file-substitution"):
            self.validate()

    def test_source_path_swap_after_open_is_rejected(self) -> None:
        source = self.temporary / "source"
        source.write_bytes(b"same\n")
        descriptor, opened = SEALER.stable_open(source, 5)
        try:
            displaced = self.temporary / "source-displaced"
            source.rename(displaced)
            source.write_bytes(b"same\n")
            with self.assertRaisesRegex(SEALER.Refused, "source-read-race"):
                SEALER._verify_source_after(source, opened, descriptor)
        finally:
            os.close(descriptor)

    def test_source_symlink_is_rejected(self) -> None:
        source = self.temporary / "source"
        source.write_bytes(b"source\n")
        link = self.temporary / "source-link"
        link.symlink_to(source)
        with self.assertRaisesRegex(SEALER.Refused, "source-not-regular"):
            SEALER.read_stable(link)

    def test_rename_noreplace_rejects_existing_final(self) -> None:
        os.mkdir("final", 0o700, dir_fd=self.parent)
        with self.assertRaisesRegex(SEALER.Refused, "rename-target-exists"):
            SEALER._rename_noreplace(self.parent, self.stage_name, "final")
        self.assertFalse(SEALER._missing_at(self.parent, self.stage_name))
        self.assertFalse(SEALER._missing_at(self.parent, "final"))

    def test_atomic_publication_preserves_inode_and_exact_tree(self) -> None:
        SEALER._rename_noreplace(self.parent, self.stage_name, "final")
        self.stage_name = "final"
        os.fsync(self.parent)
        final_descriptor, final_opened = SEALER._open_directory_at(self.parent, "final")
        try:
            self.assertEqual(SEALER._directory_identity(final_opened), self.root_state[:6])
            self.root_state = SEALER._directory_state(final_opened)
            SEALER.validate_tree(
                self.parent,
                "final",
                final_descriptor,
                self.root_state,
                self.member_state,
                self.expected,
                [self.member_name],
            )
        finally:
            os.close(final_descriptor)

    def test_retry_uses_a_new_staging_name_without_touching_failure(self) -> None:
        retry_name, retry = SEALER.create_staging(self.parent, ".stage-")
        try:
            self.assertNotEqual(retry_name, self.stage_name)
            self.assertFalse(SEALER._missing_at(self.parent, self.stage_name))
            self.assertFalse(SEALER._missing_at(self.parent, retry_name))
        finally:
            os.close(retry)

    def test_executed_source_wrong_proc_path_is_rejected(self) -> None:
        source = self.temporary / "executed-source"
        source.write_bytes(b"source\n")
        source.chmod(0o400)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | SEALER.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(SEALER.Refused, "executed-source-path"):
                SEALER.capture_executed_source(
                    descriptor,
                    Path(f"/proc/self/fd/{descriptor + 1}"),
                    source,
                )
        finally:
            os.close(descriptor)

    def test_executed_source_closed_fd_is_rejected(self) -> None:
        source = self.temporary / "executed-source"
        source.write_bytes(b"source\n")
        source.chmod(0o400)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | SEALER.O_CLOEXEC)
        os.close(descriptor)
        with self.assertRaisesRegex(SEALER.Refused, "executed-source-open"):
            SEALER.capture_executed_source(
                descriptor,
                Path(f"/proc/self/fd/{descriptor}"),
                source,
            )

    def test_executed_source_wrong_mode_is_rejected(self) -> None:
        source = self.temporary / "executed-source"
        source.write_bytes(b"source\n")
        source.chmod(0o600)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | SEALER.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(SEALER.Refused, "executed-source-mode-owner-link"):
                SEALER.capture_executed_source(
                    descriptor,
                    Path(f"/proc/self/fd/{descriptor}"),
                    source,
                )
        finally:
            os.close(descriptor)

    def test_executed_source_change_after_capture_is_rejected(self) -> None:
        source = self.temporary / "executed-source"
        source.write_bytes(b"source\n")
        source.chmod(0o400)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | SEALER.O_CLOEXEC)
        try:
            binding = SEALER.capture_executed_source(
                descriptor,
                Path(f"/proc/self/fd/{descriptor}"),
                source,
            )
            source.chmod(0o600)
            source.write_bytes(b"SOURCE\n")
            source.chmod(0o400)
            with self.assertRaisesRegex(SEALER.Refused, "executed-source-changed"):
                SEALER.reverify_executed_source(binding)
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
