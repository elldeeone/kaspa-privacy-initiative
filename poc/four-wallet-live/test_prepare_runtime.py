"""Public sentinel-only tests for all-eight staging ingress exclusions."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from prepare_runtime import Exclusions
from public import digest


class PublicStagingExclusionControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kpx6-public-eight-exclusions-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.roots = [self.root / 'trial-one', self.root / 'trial-two']
        self.files = []
        for number, root in enumerate(self.roots):
            for role in ('A', 'B', 'C', 'D'):
                path = root / 'owners' / role / 'backup.json'
                path.parent.mkdir(parents=True)
                path.write_bytes(('PUBLIC_SYNTHETIC_SENTINEL_' + str(number) + role).encode())
                self.files.append(path)
        self.excluded = Exclusions(self.roots)

    def test_all_eight_aliases_refuse_before_any_public_open(self):
        for number, original in enumerate(self.files):
            candidate = self.root / ('public-alias-' + str(number))
            candidate.hardlink_to(original)
            with patch('prepare_runtime.os.open', side_effect=AssertionError('no public open')):
                with self.assertRaises(ValueError):
                    self.excluded.read(candidate, '11' * 32)

    def test_eighth_backup_swap_at_open_refuses_before_first_byte(self):
        candidate = self.root / 'public.json'; candidate.write_bytes(b'{}')
        original_open = os.open
        def swap(path, *args):
            if path == candidate:
                candidate.unlink(); candidate.hardlink_to(self.files[-1])
            return original_open(path, *args)
        with patch('prepare_runtime.os.open', side_effect=swap), \
             patch('prepare_runtime.os.fdopen', side_effect=AssertionError('no first byte')):
            with self.assertRaises(ValueError):
                self.excluded.read(candidate, digest(b'{}'))


if __name__ == '__main__':
    unittest.main()
