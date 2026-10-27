"""Known-public-only write-boundary and stale-inode controls; no real private input."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

import campaign_writer_fix as writer


class WriterControls(unittest.TestCase):
    def test_known_public_marker_survives_stale_private_inode_without_clearing_guard(self):
        with tempfile.TemporaryDirectory(prefix='known-public-writer-control-') as directory:
            root = Path(directory)
            dummy = root / 'KNOWN-PUBLIC-DUMMY-NOT-A-SEED'
            with dummy.open('xb') as f:
                f.write(b'KNOWN PUBLIC DUMMY: no actual private content')
            s = dummy.stat()
            identity = (s.st_dev, s.st_ino)
            h = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
            h['m'].GUARD.inodes.add(identity)  # Exact metadata-only historical-set model.
            dummy.unlink()
            reused = None
            value = {'schema': 'KNOWN-PUBLIC-CONFIRMATION', 'action': 'action-0003'}
            for i in range(4096):
                path = root / ('PUBLIC-' + str(i) + '.json')
                row = writer.publish_known_json(path, value)
                s = path.stat()
                if (s.st_dev, s.st_ino) == identity:
                    reused = path
                    break
                path.unlink()
            self.assertIsNotNone(reused, 'filesystem control must demonstrate real inode reuse')
            self.assertIn(identity, h['m'].GUARD.inodes)
            with self.assertRaisesRegex(Exception, 'aliases-original-backup'):
                h['read'](str(reused), row['sha256'])
            raw = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](str(reused), row['sha256'])
            self.assertEqual(json.loads(raw), value)
            self.assertEqual(set(row), {'path', 'sha256'})

    def test_existing_path_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='known-public-writer-control-') as directory:
            path = Path(directory) / 'marker.json'
            old = writer.publish_known_json(path, {'known_public': 'original'})
            with self.assertRaises(FileExistsError):
                writer.publish_known_json(path, {'known_public': 'replacement'})
            raw = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](str(path), old['sha256'])
            self.assertEqual(json.loads(raw), {'known_public': 'original'})

    def test_symlink_and_symlink_parent_are_rejected_before_write(self):
        with tempfile.TemporaryDirectory(prefix='known-public-writer-control-') as directory:
            root = Path(directory)
            target = root / 'target.json'
            old = writer.publish_known_json(target, {'known_public': 'unchanged'})
            alias = root / 'alias.json'
            alias.symlink_to(target)
            parent = root / 'parent-alias'
            parent.symlink_to(root, target_is_directory=True)
            for path in (alias, parent / 'new.json'):
                with self.assertRaisesRegex(ValueError, 'canonical-path'):
                    writer.publish_known_json(path, {'known_public': 'never-written'})
            raw = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](str(target), old['sha256'])
            self.assertEqual(json.loads(raw), {'known_public': 'unchanged'})

    def test_zero_write_fails_without_returning_success(self):
        with tempfile.TemporaryDirectory(prefix='known-public-writer-control-') as directory:
            path = Path(directory) / 'zero.json'
            with patch.object(writer.os, 'write', return_value=0):
                with self.assertRaisesRegex(ValueError, 'made-no-progress'):
                    writer.publish_known_json(path, {'known_public': True})
            self.assertEqual(path.stat().st_size, 0)

    def test_partial_writes_complete_but_dishonest_short_write_is_rejected(self):
        original = os.write
        with tempfile.TemporaryDirectory(prefix='known-public-writer-control-') as directory:
            path = Path(directory) / 'partial.json'
            with patch.object(writer.os, 'write', side_effect=lambda fd, data: original(fd, data[:1])):
                row = writer.publish_known_json(path, {'known_public': 'complete'})
            raw = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](str(path), row['sha256'])
            self.assertEqual(json.loads(raw), {'known_public': 'complete'})
            bad = Path(directory) / 'dishonest.json'

            def short(fd, data):
                original(fd, data[:1])
                return len(data)

            with patch.object(writer.os, 'write', side_effect=short):
                with self.assertRaisesRegex(ValueError, 'complete-known-public-write'):
                    writer.publish_known_json(bad, {'known_public': 'must-fail'})

    def test_fsync_failure_never_returns_a_row(self):
        with tempfile.TemporaryDirectory(prefix='known-public-writer-control-') as directory:
            with patch.object(writer.os, 'fsync', side_effect=OSError('KNOWN-PUBLIC-TEST-IO-FAILURE')):
                with self.assertRaises(OSError):
                    writer.publish_known_json(Path(directory) / 'io-failure.json', {'known_public': True})


if __name__ == '__main__':
    unittest.main()
