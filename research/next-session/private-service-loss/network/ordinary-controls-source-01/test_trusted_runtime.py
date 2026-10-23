"""ADR0054 ordinary public executable controls; no key or proof workload."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from trusted_runtime import TrustedExecutable


class TrustedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "public-true"
        raw = Path("/usr/bin/true").read_bytes(); self.path.write_bytes(raw); self.path.chmod(0o500)
        self.sha256 = hashlib.sha256(raw).hexdigest()

    def tearDown(self):
        self.directory.cleanup()

    def test_ordinary_selected_file_runs_with_explicit_host_premise(self):
        with TrustedExecutable(self.path, self.sha256) as executable:
            self.assertEqual(executable.run([]).returncode, 0)
            self.assertTrue(executable.receipt()["host_and_release_immutability_assumed"])
            self.assertFalse(executable.receipt()["same_inode_host_writer_protection"])

    def test_changed_file_is_rejected_at_next_launch(self):
        with TrustedExecutable(self.path, self.sha256) as executable:
            self.path.chmod(0o700); self.path.write_bytes(b"changed"); self.path.chmod(0o500)
            with self.assertRaisesRegex(ValueError, "software-identity"):
                executable.run([])

    def test_wrong_file_mode_is_rejected(self):
        self.path.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "mode0500"):
            TrustedExecutable(self.path, self.sha256)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "software-identity"):
            TrustedExecutable(self.path, "00" * 32)

    def test_child_environment_is_fixed_and_clean(self):
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "host-value-must-not-enter-child"}):
            with TrustedExecutable(self.path, self.sha256) as executable:
                result = executable.run([])
                self.assertEqual(result.returncode, 0); self.assertEqual(result.stderr, "")

    def test_stdin_passes_in_memory_without_receipt_contents(self):
        raw = Path("/usr/bin/cat").read_bytes(); self.path.chmod(0o700); self.path.write_bytes(raw); self.path.chmod(0o500)
        with TrustedExecutable(self.path, hashlib.sha256(raw).hexdigest()) as executable:
            self.assertEqual(executable.run([], input_text="public-control-input").stdout, "public-control-input")
            self.assertNotIn("public-control-input", str(executable.receipt()))


if __name__ == "__main__":
    unittest.main()
