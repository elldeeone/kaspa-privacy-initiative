"""Calibrated backup-hardlink controls; known public bytes, zero secret reads."""
from pathlib import Path
import os
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from gn2_common import write_new
from gn2_owner import sign_entry


class AliasGuards(unittest.TestCase):
    def test_all_caller_public_aliases_refuse_before_profile_or_bytes(self):
        targets = ('profile', 'case', 'record', 'crypto', 'node', 'native', 'kaspa.js',
                   'kaspa_bg.wasm', 'package.json')
        for target in targets:
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix='kpi-GN2-public-alias-', dir='/var/tmp') as folder:
                root = Path(folder); owner = root / 'owner'; owner.mkdir(mode=0o700)
                backup = owner / 'backup.json'; write_new(backup, b'PUBLIC_CONTROL_NOT_A_REAL_BACKUP', 0o600)
                public = root / 'public'; public.mkdir()
                paths = {}
                for name in ('profile', 'case', 'crypto', 'node', 'native', 'kaspa.js', 'kaspa_bg.wasm', 'package.json'):
                    path = public / name
                    if name == target:
                        os.link(backup, path)
                    else:
                        write_new(path, b'{}', 0o400)
                    paths[name] = path
                original = owner / 'owner-init.json'
                if target == 'record':os.link(backup, original)
                else:write_new(original, b'{}', 0o400)
                args = SimpleNamespace(owner=owner, profile=paths['profile'], case=paths['case'],
                    crypto=paths['crypto'], node=paths['node'], native=paths['native'], sdk_dir=public,
                    profile_sha256='11' * 32, trial_id='2bf79d53-a37a-4780-b6b2-1264edf15b87',
                    output=root / 'out', fee_rate=100)
                with patch('gn2_owner.load_profile') as loader, patch('gn2_owner.public_bytes') as reader:
                    with self.assertRaises(ValueError):
                        sign_entry(args)
                    loader.assert_not_called(); reader.assert_not_called()
                self.assertFalse((root / 'out').exists())


if __name__ == '__main__':
    unittest.main()
