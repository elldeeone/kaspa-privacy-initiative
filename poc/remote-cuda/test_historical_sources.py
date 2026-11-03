"""Actual package/source selection and tamper controls; no proving or network."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import historical_sources
import lifecycle_package
import recovery_package
from common import sha


class HistoricalSources(unittest.TestCase):
    def test_default_current_source_still_refuses_both_old_packages(self):
        for package in (lifecycle_package, recovery_package):
            with self.subTest(package=package.__name__), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / 'package'
                with self.assertRaisesRegex(AssertionError, 'source/binary drift'):
                    package.restore(out)
                self.assertFalse(out.exists())

    def test_complete_historical_closures_restore_original_binary_and_policy(self):
        for profile, package in (('lifecycle', lifecycle_package), ('recovery', recovery_package)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                with historical_sources.source_closure(profile) as source:
                    out = Path(directory) / 'package'
                    policy = package.restore(out, source_root=source)
                    package.check(out)
                    identity = json.loads((historical_sources.ROOT / historical_sources.PROFILES[profile][0]).read_text())
                    name = 'lifecycle-workload.json' if profile == 'lifecycle' else 'recovery-workload.json'
                    self.assertEqual(sha((out / name).read_bytes()), identity['policySha256'])
                    self.assertEqual(policy['expectedProgramImage'], package.IMAGE)
                    for relative, digest in identity['sourceFiles'].items():
                        self.assertEqual(sha((source / relative).read_bytes()), digest)
                    for binary, metadata in policy['binaries'].items():
                        self.assertEqual(sha((out / 'bin' / binary).read_bytes()), metadata['sha256'])

    def test_changed_selected_source_rejects_before_restoration(self):
        with historical_sources.source_closure('lifecycle') as source, tempfile.TemporaryDirectory() as directory:
            file = source / 'poc/private-note-wallet/src/wallet.rs'
            file.write_bytes(file.read_bytes() + b'changed')
            out = Path(directory) / 'package'
            with self.assertRaisesRegex(AssertionError, 'source/binary drift'):
                lifecycle_package.restore(out, source_root=source)
            self.assertFalse(out.exists())

    def test_changed_identity_and_archive_are_rejected(self):
        profile = 'lifecycle'
        identity_path = historical_sources.PROFILES[profile][0]
        archive_path = 'poc/remote-cuda/historical-sources/lifecycle.tar.gz'
        original = historical_sources.ROOT
        for changed in (identity_path, archive_path):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in (identity_path, archive_path):
                    file = root / name
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_bytes((original / name).read_bytes() + (b'changed' if name == changed else b''))
                with patch.object(historical_sources, 'ROOT', root):
                    with self.assertRaisesRegex(AssertionError, 'historical identity changed|archive hash mismatch'):
                        with historical_sources.source_closure(profile):
                            self.fail('changed source authority accepted')


if __name__ == '__main__':
    unittest.main()
