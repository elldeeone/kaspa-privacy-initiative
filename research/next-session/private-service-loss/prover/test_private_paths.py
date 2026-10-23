import os
from pathlib import Path
import tempfile
import unittest
import subprocess
from private_paths import private_file, private_directory, new_private_directory, PrivatePathError


class Paths(unittest.TestCase):
    def setUp(self):
        # Use a metadata-only synthetic tree outside the source checkout.
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[5])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.file = self.root/'public-test-placeholder'
        self.file.write_bytes(b'public synthetic metadata test')
        self.file.chmod(0o600)

    def test_private_file_and_new_directory(self):
        self.assertEqual(private_file(self.file),self.file)
        self.assertEqual(new_private_directory(self.root/'new'),self.root/'new')

    def test_public_file_permissions_reject(self):
        self.file.chmod(0o644)
        with self.assertRaises(PrivatePathError):private_file(self.file)

    def test_symlink_leaf_rejects(self):
        alias=self.root/'alias';alias.symlink_to(self.file)
        with self.assertRaises(PrivatePathError):private_file(alias)

    def test_symlink_ancestor_rejects(self):
        alias=self.root/'directory-alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(PrivatePathError):private_file(alias/self.file.name)

    def test_git_ancestry_rejects(self):
        subprocess.run(['/usr/bin/git','init','-q',str(self.root)],check=True)
        with self.assertRaises(PrivatePathError):private_file(self.file)

    def test_empty_placeholder_is_not_a_repository(self):
        (self.root/'.git').mkdir()
        self.assertEqual(private_file(self.file),self.file)

    def test_invalid_marker_does_not_hide_real_higher_repository(self):
        subprocess.run(['/usr/bin/git','init','-q',str(self.root)],check=True)
        nested=self.root/'nested';nested.mkdir(mode=0o700)
        (nested/'.git').mkdir()
        item=nested/'public-test-placeholder';item.write_bytes(b'public');item.chmod(0o600)
        with self.assertRaises(PrivatePathError):private_file(item)

    def test_existing_new_directory_rejects(self):
        with self.assertRaises(PrivatePathError):new_private_directory(self.root)

    def test_public_parent_directory_rejects(self):
        self.root.chmod(0o755)
        with self.assertRaises(PrivatePathError):private_file(self.file)

    def test_non_directory_rejects(self):
        with self.assertRaises(PrivatePathError):private_directory(self.file)


if __name__=='__main__':unittest.main()
