"""Cheap controls for the new private-trial boundary; no proving or network."""
import os
from pathlib import Path
import stat
import tempfile
import unittest

from core import Core, MAX_SOMPI, save, sompi
from orchestrate import child


class Boundaries(unittest.TestCase):
    def test_canonical_amounts(self):
        for value in (0, 60_000_000, MAX_SOMPI):
            self.assertEqual(sompi(value), value)
        for value in (True, False, -1, MAX_SOMPI + 1, 1.0, '100000000'):
            with self.assertRaises(ValueError):
                sompi(value)

    def test_output_containment(self):
        root = Path('/tmp/kpx2-containment-control')
        for name in ('../escape', '/absolute', 'a/../../escape'):
            with self.assertRaises(ValueError):
                child(root, name)
        self.assertEqual(child(root, 'stage/file.json'), root / 'stage/file.json')

    def test_symlink_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'link').symlink_to('/tmp', target_is_directory=True)
            with self.assertRaises(ValueError):
                child(root, 'link/escaped.json')

    def test_private_create_only(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / 'private.json'
            save(target, {'amount_sompi': 1})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                save(target, {'amount_sompi': 2})

    def test_domain_encoding(self):
        self.assertNotEqual(Core('01' * 32, 'a').domain, Core('02' * 32, 'b').domain)
        for encoded in ('01' * 31, 'AA' * 32, 'nothex'):
            with self.assertRaises(ValueError):
                Core(encoded, 'a')


if __name__ == '__main__':
    unittest.main()
