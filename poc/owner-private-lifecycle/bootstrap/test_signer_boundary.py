"""Known-public synthetic canaries; no original owner files are opened."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_signer


class SignerBoundary(unittest.TestCase):
    def test_omitted_whole_private_parent_rejects_before_any_public_read(self):
        with TemporaryDirectory(prefix='kpx8-public-metadata-fixture-') as directory:
            root=Path(directory)
            old=[]
            for name in ('local','live'):
                trial=root/name;old.append(trial)
                for role in ('A','B','C','D'):
                    owner=trial/'owners'/role;owner.mkdir(parents=True,mode=0o700)
                    backup=owner/'backup.json';backup.write_bytes(b'PUBLIC_SYNTHETIC_UNREAD_CANARY')
                    backup.chmod(0o600)
            unrelated=root/'unrelated';unrelated.mkdir(mode=0o700)
            args=SimpleNamespace(exclude_old_trial=old,exclude_private_directory=[unrelated])
            with patch.object(run_signer.HostPolicy,'read',side_effect=AssertionError('public read occurred')):
                with self.assertRaisesRegex(ValueError,'whole-selected-private-parent-must-be-excluded'):
                    run_signer.run(args)


if __name__=='__main__': unittest.main()
