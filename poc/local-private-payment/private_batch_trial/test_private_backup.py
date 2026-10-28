"""Only explicit public fixture bytes; never locates any actual Original."""
import json
import os
from pathlib import Path
import tempfile
import unittest

import private_worker as worker
import wallet_profile as wallet


class BackupBoundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='kpb-public-backup-codec-test-')
        self.path = Path(self.directory.name) / 'PUBLIC-FIXTURE.json'
        self.profile = wallet.Profile(bytes([1]) * 32, bytes([2]) * 32)
        self.value = {'schema': worker.BACKUP_SCHEMA, 'domain_hex32': self.profile.domain.hex(),
            'profile_id_hex32': self.profile.profile_id.hex(), 'kdf_tag_ascii8': worker.KDF_TAG,
            'seed_hex32': bytes(range(32)).hex()}

    def tearDown(self):
        self.directory.cleanup()

    def put(self, value=None, raw=None):
        worker.write(self.path, self.value if value is None and raw is None else (value if raw is None else raw))

    def test_exact_new_profile_is_required(self):
        self.put()
        self.assertEqual(worker.load_backup(self.path, self.profile), bytes(range(32)))

    def test_legacy_backup_is_rejected(self):
        self.put({'schema': 'kpxa-original-seed-backup/v1', 'domain_hex32': self.profile.domain.hex(),
                  'seed_hex32': self.value['seed_hex32']})
        with self.assertRaises(wallet.Invalid):
            worker.load_backup(self.path, self.profile)

    def test_profile_domain_version_and_fields_fail_closed(self):
        cases = [('profile_id_hex32', bytes([3]).hex() * 32), ('domain_hex32', bytes([3]).hex() * 32),
                 ('schema', 'kpb-ak-bound-original-seed-backup/v2'), ('kdf_tag_ascii8', 'KPX1DRV\0'),
                 ('signing_scalar', '1')]
        for key, value in cases:
            with self.subTest(key=key):
                self.path.unlink(missing_ok=True)
                self.put({**self.value, key: value})
                with self.assertRaises(wallet.Invalid):
                    worker.load_backup(self.path, self.profile)

    def test_duplicate_key_is_rejected(self):
        raw = json.dumps(self.value)[:-1] + ',"seed_hex32":"' + bytes([9]).hex() * 32 + '"}'
        self.put(raw=raw.encode())
        with self.assertRaises(wallet.Invalid):
            worker.load_backup(self.path, self.profile)

    def test_noncanonical_or_short_seed_is_rejected(self):
        for seed in (self.value['seed_hex32'].upper(), '00'):
            with self.subTest(seed=seed):
                self.path.unlink(missing_ok=True)
                self.put({**self.value, 'seed_hex32': seed})
                with self.assertRaises(wallet.Invalid):
                    worker.load_backup(self.path, self.profile)

    def test_group_readable_and_hardlink_are_rejected(self):
        self.put(); self.path.chmod(0o640)
        with self.assertRaises(wallet.Invalid):
            worker.load_backup(self.path, self.profile)
        self.path.chmod(0o600)
        os.link(self.path, self.path.with_name('PUBLIC-ALIAS.json'))
        with self.assertRaises(wallet.Invalid):
            worker.load_backup(self.path, self.profile)

    def test_symlink_is_rejected(self):
        target = self.path.with_name('PUBLIC-TARGET.json')
        worker.write(target, self.value)
        self.path.symlink_to(target)
        with self.assertRaises(wallet.Invalid):
            worker.load_backup(self.path, self.profile)


if __name__ == '__main__':
    unittest.main()
