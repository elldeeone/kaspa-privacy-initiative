"""Public sentinels only: no original keys, signer, SDK, Native or network run."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_closed_signer as signer
import run_closed_entry as entry

TRIAL = 'e65791dc-50d4-4d2c-af70-260fd74fdce7'


class Fixture:
    def __init__(self, root):
        self.root = root
        self.trials = [root / 'LOCAL', root / 'LIVE']
        for index, trial in enumerate(self.trials):
            for role in ('A', 'B', 'C', 'D'):
                owner = trial / 'owners' / role; owner.mkdir(parents=True)
                sentinel = owner / 'backup.json'
                sentinel.write_bytes(('PUBLIC_SENTINEL_NOT_A_KEY_' + str(index) + role).encode())
                sentinel.chmod(0o600)
                (owner / 'owner-init.json').write_bytes(b'PUBLIC_EXCLUDED_DIRECTORY_SENTINEL')
        self.software = root / 'public-software'; self.software.mkdir()
        self.sources, self.runtimes, self.sdk = {}, {}, {}
        for name in signer.SOURCES:
            raw = ('PUBLIC_NONEXECUTABLE_SOURCE_SENTINEL_' + name).encode()
            self.put('runtime-source/' + name, raw); self.sources[name] = signer.digest(raw)
        for name in signer.RUNTIMES:
            raw = b'\x7fELF' + ('PUBLIC_NONEXECUTABLE_ELF_SENTINEL_' + name).encode()
            self.put('runtime/' + name, raw); self.runtimes[name] = signer.digest(raw)
        for name in signer.SDK:
            raw = ('PUBLIC_NONEXECUTABLE_SDK_SENTINEL_' + name).encode()
            self.put('runtime-sdk/' + name, raw); self.sdk[name] = signer.digest(raw)
        raw = b'PUBLIC_NONEXECUTABLE_ENTRY_SOURCE_SENTINEL'
        self.put('runtime-source/' + entry.ENTRY, raw); self.entry_sha = signer.digest(raw)
        self.inputs = []
        for name in ('profile', 'case', 'ownerA', 'ownerC', 'sources', 'approvalA', 'approvalC'):
            path = root / (name + '.json'); path.write_bytes(b'{"public_sentinel":"' + name.encode() + b'"}\n')
            self.inputs.append(path)
        self.pin = {path.stem: signer.digest(path.read_bytes()) for path in self.inputs}
        self.args = SimpleNamespace(software_root=self.software,
            backup=self.trials[1] / 'owners/A/backup.json', role='A',
            owner_public=root / 'ownerA.json', owner_public_sha256=self.pin['ownerA'],
            profile=root / 'profile.json', profile_sha256=self.pin['profile'],
            case=root / 'case.json', case_sha256=self.pin['case'], trial_id=TRIAL,
            output=root / 'fresh-controller', exclude_trial_directory=self.trials, execute=False)

    def put(self, relative, raw):
        path = self.software / relative; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def selected(self):
        return patch.multiple(signer, SOURCES=self.sources, RUNTIMES=self.runtimes, SDK=self.sdk)

    def public_args(self, operation):
        a = copy.copy(self.args); a.operation = operation
        a.owners = [self.root / 'ownerA.json', self.root / 'ownerC.json']
        a.owners_sha256 = [self.pin['ownerA'], self.pin['ownerC']]
        a.sources = self.root / 'sources.json'; a.sources_sha256 = self.pin['sources']
        a.approvals = [self.root / 'approvalA.json', self.root / 'approvalC.json']
        a.approvals_sha256 = [self.pin['approvalA'], self.pin['approvalC']]
        return a


class ClosedIngressControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kpi-public-ingress-controls-', dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))

    def test_signer_prepare_mounts_only_designated_original_and_copied_record(self):
        a = self.f.args
        with self.f.selected():
            result = signer.run(a)
        self.assertFalse(result['executed']); self.assertFalse(result['approval_exported'])
        command = json.loads((a.output / 'PRIVATE-PLAN.json').read_bytes())['command']
        private = [str(trial / 'owners' / role / 'backup.json')
                   for trial in self.f.trials for role in ('A', 'B', 'C', 'D')]
        self.assertEqual([word for word in command if word in private], [str(a.backup)])
        self.assertEqual(command[command.index(str(a.backup)) + 1], '/owner/backup.json')
        for trial in self.f.trials:
            for role in ('A', 'B', 'C', 'D'):
                self.assertNotIn(str(trial / 'owners' / role), command)
        public_record = a.output / 'public-inputs/owner-init.json'
        self.assertEqual(public_record.stat().st_mode & 0o777, 0o400)
        self.assertEqual(signer.digest(public_record.read_bytes()), a.owner_public_sha256)
        self.assertFalse((a.output / 'client/run').exists())

    def test_prepare_and_combine_have_no_backup_mount_and_mask_fixed_sdk_path(self):
        for operation in ('prepare', 'combine'):
            a = self.f.public_args(operation); a.output = self.f.root / operation
            with self.f.selected(), patch.object(entry, 'ENTRY_SHA', self.f.entry_sha):
                result = entry.run(a)
            self.assertFalse(result['executed']); self.assertFalse(result['SDK_or_Native_executed'])
            command = json.loads((a.output / 'PLAN.json').read_bytes())['command']
            self.assertEqual(result['backup_mount_count'], 0)
            for trial in self.f.trials:
                self.assertFalse(any(str(trial / 'owners') in word for word in command))
            for name in signer.SDK:
                self.assertIn(entry.SDK_FIXED + name, command)
            self.assertNotIn('--ro-bind / /', ' '.join(command))

    def test_all_eight_original_owner_directories_rejected_before_public_read(self):
        for trial in self.f.trials:
            for role in ('A', 'B', 'C', 'D'):
                a = copy.copy(self.f.args); a.owner_public = trial / 'owners' / role / 'owner-init.json'
                with self.f.selected(), patch.object(signer.Exclusions, 'read') as read:
                    with self.assertRaises(ValueError): signer.run(a)
                    read.assert_not_called()
                self.assertFalse(a.output.exists())

    def test_all_eight_backup_aliases_rejected_without_opening_first_public_input(self):
        excluded = signer.Exclusions(self.f.trials)
        for index, backup in enumerate(excluded.backups):
            alias = self.f.root / ('public-alias-' + str(index))
            os.link(backup, alias)
            with patch.object(signer.os, 'open', side_effect=AssertionError('NO_BYTE_ACCESS')):
                with self.assertRaises(ValueError): excluded.read(alias, '0' * 64)
            alias.unlink()

    def test_last_sdk_member_alias_rejects_before_first_source_hash_or_copy(self):
        target = self.f.software / 'runtime-sdk/package.json'
        target.unlink(); os.link(self.f.trials[-1] / 'owners/D/backup.json', target)
        with self.f.selected(), patch.object(signer.Exclusions, 'read') as read:
            with self.assertRaises(ValueError): signer.run(self.f.args)
            read.assert_not_called()
        self.assertFalse(self.f.args.output.exists())

    def test_hardlink_swap_after_guard_refuses_before_fdopen_or_read(self):
        excluded = signer.Exclusions(self.f.trials)
        path = self.f.args.case; original_open = os.open
        backup = self.f.trials[-1] / 'owners/D/backup.json'
        def swapped(value, flags, *args, **kwargs):
            if Path(value) == path:
                path.unlink(); os.link(backup, path)
            return original_open(value, flags, *args, **kwargs)
        with patch.object(signer.os, 'open', side_effect=swapped), \
                patch.object(signer.os, 'fdopen', side_effect=AssertionError('NO_BYTE_ACCESS')):
            with self.assertRaises(ValueError): excluded.read(path, self.f.args.case_sha256)

    def test_public_entry_owner_record_alias_rejected_before_any_selected_read(self):
        for operation in ('prepare', 'combine'):
            a = self.f.public_args(operation)
            if operation == 'prepare':
                a.owners[1] = self.f.trials[-1] / 'owners/D/owner-init.json'
            else:
                a.approvals[1] = self.f.trials[-1] / 'owners/D/owner-init.json'
            with self.f.selected(), patch.object(entry, 'ENTRY_SHA', self.f.entry_sha), \
                    patch.object(signer.Exclusions, 'read') as read:
                with self.assertRaises(ValueError): entry.run(a)
                read.assert_not_called()

    def test_context_backup_and_fresh_output_guards(self):
        a = self.f.args
        for field, value in (('trial_id', TRIAL.upper()), ('role', 'B'),
                ('backup', self.f.trials[1] / 'owners/C/backup.json'),
                ('output', self.f.software / 'new-output')):
            b = copy.copy(a); setattr(b, field, value)
            with self.f.selected(), patch.object(signer.Exclusions, 'read') as read:
                with self.assertRaises(ValueError): signer.run(b)
                read.assert_not_called()
        excluded = signer.Exclusions(self.f.trials)
        a.backup.touch()
        with self.assertRaises(ValueError): excluded.original(a.backup, 'A')

    def test_frozen_worker_and_entry_preimages_match_current_selected_source(self):
        for relative, expected in signer.SOURCES.items():
            self.assertEqual(signer.digest((signer.ROOT / relative).read_bytes()), expected)
        self.assertEqual(signer.digest((signer.ROOT / entry.ENTRY).read_bytes()), entry.ENTRY_SHA)


if __name__ == '__main__':
    unittest.main(verbosity=2)
