"""Public synthetic pre-read/whole-object controls for the closed owner runner."""
import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import closure
import cold_owner
from run_restore import PublicPolicy


class ColdPreflightControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='public-cold-owner-controls-')
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.private=self.base/'private'
        self.private.mkdir(mode=0o700)

    def args(self):
        return argparse.Namespace(operation='restore',exclude_private_directory=[self.private],
            owner_directory=self.private/'new-owner',mpc_directory=self.private/'new-mpc',
            backup=self.base/'outside-private-backup',software_inventory=self.base/'unread-inventory')

    def test_omitted_own_backup_parent_refuses_before_any_public_read(self):
        a=self.args();a.backup.write_bytes(b'PUBLIC SYNTHETIC BACKUP MARKER\n');a.backup.chmod(0o600)
        with patch.object(cold_owner,'retained_private_roots',return_value=()),\
             patch.object(PublicPolicy,'read',side_effect=AssertionError('content opened')) as opened:
            with self.assertRaisesRegex(closure.Refused,'cold-own-backup-metadata-only'):
                cold_owner.run(a)
        self.assertEqual(opened.call_count,0)

    def test_omitted_own_runtime_parent_refuses_before_any_public_read(self):
        a=self.args();a.owner_directory=self.base/'outside-private-owner'
        with patch.object(cold_owner,'retained_private_roots',return_value=()),\
             patch.object(PublicPolicy,'read',side_effect=AssertionError('content opened')) as opened:
            with self.assertRaisesRegex(closure.Refused,'cold-own-private-directories'):
                cold_owner.run(a)
        self.assertEqual(opened.call_count,0)

    def test_known_private_alias_never_enters_public_stream(self):
        p=self.private/'PUBLIC-SYNTHETIC-MARKER';p.write_bytes(b'PUBLIC MARKER\n')
        policy=PublicPolicy([self.private]);alias=self.base/'moved-marker';p.rename(alias)
        with patch.object(cold_owner.os,'open',side_effect=AssertionError('content opened')) as opened:
            with self.assertRaisesRegex(closure.Refused,'cold-public-private-alias'):
                cold_owner.stream(policy,alias,closure.digest(b'PUBLIC MARKER\n'))
        self.assertEqual(opened.call_count,0)

    def test_whole_public_key_stream_checks_last_byte(self):
        raw=b'A'*(1024*1024)+b'Z';p=self.base/'PUBLIC-NOT-A-PROVING-KEY';p.write_bytes(raw)
        policy=PublicPolicy([self.private]);cold_owner.stream(policy,p,closure.digest(raw),len(raw))
        with p.open('r+b') as target:target.seek(-1,2);target.write(b'X')
        with self.assertRaisesRegex(closure.Refused,'cold-whole-public-object-pin'):
            cold_owner.stream(policy,p,closure.digest(raw),len(raw))

    def test_authenticated_executable_staging_has_required_readonly_mode(self):
        p=self.base/'staged-public-ELF';raw=b'\x7fELFPUBLIC SYNTHETIC NOT EXECUTABLE'
        cold_owner.write(p,raw,0o500)
        self.assertEqual(p.stat().st_mode & 0o777,0o500)
        self.assertEqual(p.read_bytes(),raw)


if __name__=='__main__':unittest.main()
