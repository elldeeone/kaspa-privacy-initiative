#!/usr/bin/env python3
"""Public synthetic calibrations of host reads before namespace staging."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import closure
from run_restore import PublicPolicy


class MetadataExclusionControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='public-recovery-policy-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.private = self.base / 'synthetic-private'
        self.private.mkdir(mode=0o700)
        self.marker = self.private / 'PUBLIC-SYNTHETIC-NOT-A-WALLET'
        self.marker.write_bytes(b'PUBLIC SYNTHETIC EXCLUSION MARKER\n')
        self.policy = PublicPolicy([self.private])

    def refused_without_open(self, path):
        with patch('run_restore.os.open', side_effect=AssertionError('opened-before-refusal')) as opened:
            with self.assertRaises(closure.Refused):
                self.policy.read(path)
        self.assertEqual(opened.call_count, 0)

    def test_private_path_refuses_before_open(self):
        self.refused_without_open(self.marker)

    def test_hardlink_alias_refuses_before_open(self):
        alias = self.base / 'looks-public'
        alias.hardlink_to(self.marker)
        self.refused_without_open(alias)

    def test_known_private_inode_moved_outside_stays_excluded(self):
        alias = self.base / 'moved-looks-public'
        self.marker.rename(alias)
        self.assertEqual(alias.stat().st_nlink, 1)
        self.refused_without_open(alias)

    def test_new_private_inode_is_added_by_metadata_refresh(self):
        new = self.private / 'NEW-PUBLIC-SYNTHETIC-MARKER'
        new.write_bytes(b'NEW PUBLIC SYNTHETIC EXCLUSION MARKER\n')
        self.policy.refresh()
        alias = self.base / 'new-moved-looks-public'
        new.rename(alias)
        self.refused_without_open(alias)

    def test_symlink_alias_refuses_before_open(self):
        alias = self.base / 'symlink-looks-public'
        alias.symlink_to(self.marker)
        self.refused_without_open(alias)

    def test_selected_unrelated_public_bytes_read_normally(self):
        path = self.base / 'PUBLIC-SELECTED-SOURCE'
        raw = b'PUBLIC SYNTHETIC BOOTSTRAP BYTES\n'
        path.write_bytes(raw)
        self.assertEqual(self.policy.read(path, closure.digest(raw)), raw)


if __name__ == '__main__':
    unittest.main()
