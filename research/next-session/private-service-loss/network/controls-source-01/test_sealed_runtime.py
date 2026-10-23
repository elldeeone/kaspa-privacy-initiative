"""Public runtime controls only; no SDK, RPC, native verifier or proof run."""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from sealed_runtime import SEALS, SealedExecutable


class SealedRuntimeTests(unittest.TestCase):
    def test_exact_copied_elf_is_sealed_and_runs_after_source_replacement(self):
        raw = Path("/usr/bin/true").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "selected-public-elf"
            source.write_bytes(raw)
            with SealedExecutable(source, hashlib.sha256(raw).hexdigest()) as selected:
                self.assertEqual(fcntl.fcntl(selected.fd, fcntl.F_GET_SEALS), SEALS)
                with self.assertRaises(OSError) as caught:
                    os.pwrite(selected.fd, b"changed", 0)
                self.assertEqual(caught.exception.errno, errno.EPERM)
                source.write_bytes(b"replacement-is-not-an-ELF")
                self.assertEqual(selected.run([]).returncode, 0)
                self.assertEqual(selected.receipt()["execution"], "SAME_HASHED_SEALED_MEMFD_VIA_PINNED_SYSTEM_LOADER")
            self.assertIsNone(selected.fd)

    def test_changed_digest_rejects_before_execution(self):
        with self.assertRaisesRegex(ValueError, "software-identity"):
            SealedExecutable("/usr/bin/true", "00" * 32)

    def test_script_with_matching_digest_is_not_an_elf(self):
        raw = b"#!/bin/sh\nexit 0\n"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "script"
            source.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "elf-required"):
                SealedExecutable(source, hashlib.sha256(raw).hexdigest())

    def test_closed_copy_cannot_be_reused(self):
        digest = hashlib.sha256(Path("/usr/bin/true").read_bytes()).hexdigest()
        selected = SealedExecutable("/usr/bin/true", digest)
        selected.close()
        selected.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            selected.run([])


if __name__ == "__main__":
    unittest.main()
