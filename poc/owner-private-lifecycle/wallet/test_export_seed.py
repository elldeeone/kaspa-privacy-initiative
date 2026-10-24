"""PUBLIC UNSAFE seed sentinels only. No real wallet material is accessed."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import export_seed_worker as worker
import paths
import run_export_seed as launcher

PUBLIC_UNSAFE_SEED = bytes.fromhex('0123456789abcdef' * 4)


class SeedExportControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kpx8-public-unsafe-canary-controls-')
        self.root = Path(self.temp.name); self.private = self.root / 'private'; self.private.mkdir(mode=0o700)
        self.old = [self.root / ('old-' + str(i)) for i in range(2)]
        for parent in self.old:
            for role in 'ABCD':
                folder = parent / 'owners' / role; folder.mkdir(parents=True)
                paths.write_new(folder / 'backup.json', b'PUBLIC UNSAFE OLD SENTINEL')
        self.record = {'schema': 'kpx8-owner-seed-backup/v1', 'domain_hex32': worker.DOMAIN,
                       'participant_id_hex32': '41' * 32, 'seed_hex32': PUBLIC_UNSAFE_SEED.hex()}
        self.labels = ['local-01', 'live-01']
        for label in self.labels:
            for i in range(3):
                folder = self.private / label / ('party-' + str(i)) / 'owner'; folder.mkdir(parents=True, mode=0o700)
                paths.write_new(folder / 'BACKUP.json', paths.encoded(self.record))
        self.owner = self.private / 'local-01/party-0/owner/BACKUP.json'

    def tearDown(self):
        self.temp.cleanup()

    def selection(self, payloads):
        public = self.root / 'public'; public.mkdir(mode=0o700)
        copied = self.root / 'copies'; copied.mkdir(mode=0o700)
        rows = []
        for i, raw in enumerate(payloads):
            name = 'candidate-' + str(i) + '.bin'
            paths.write_new(public / name, raw, 0o400); paths.write_new(copied / (str(i) + '.bin'), raw, 0o400)
            rows.append({'path': name, 'bytes': len(raw), 'sha256': paths.digest(raw)})
        raw = paths.encoded({'schema': 'kpx8-new-owner-seed-export-allowlist/v1', 'files': rows}) + b'\n'
        manifest = self.root / 'ALLOWLIST.json'; paths.write_new(manifest, raw, 0o400)
        return public, copied, manifest, raw

    def args(self, public, manifest, raw, execute=False):
        return SimpleNamespace(owner_leaf=self.owner, public_root=public, allowlist=manifest,
            allowlist_sha256=paths.digest(raw), registered_trial=self.labels,
            exclude_old_trial=self.old, exclude_new_private_parent=[self.private],
            private_output=self.private / 'controller/canary-000001', output=self.root / 'result', execute=execute)

    def run_launcher(self, a):
        with patch.object(launcher, 'PRIVATE_PARENT', self.private):
            return launcher.run(a)

    def test_literal_variants_and_chunk_overlap_without_key_export(self):
        seed = PUBLIC_UNSAFE_SEED
        payloads = [b'KNOWN CLEAN', b'prefix' + seed + b'suffix', seed.hex().encode(),
                    b'x' * (worker.CHUNK - 11) + seed.hex().upper().encode() + b'end']
        _, copied, _, raw = self.selection(payloads)
        result = worker.scan(self.owner, raw, paths.digest(raw), copied)
        self.assertEqual((result['status'], result['candidate_count'], result['matched_candidate_count']), ('FAIL', 5, 3))
        self.assertEqual(result['candidate_bytes'], sum(map(len, payloads)) + len(raw))
        self.assertEqual(set(result), {'schema', 'status', 'candidate_count', 'candidate_bytes', 'matched_candidate_count', 'scope'})
        self.assertNotIn(seed.hex(), paths.encoded(result).decode())

    def test_all_public_authentication_precedes_one_original_read(self):
        _, copied, _, raw = self.selection([b'PUBLIC CLEAN A', b'PUBLIC CLEAN B'])
        with patch.object(worker, 'read_owner', wraps=worker.read_owner) as read:
            result = worker.scan(self.owner, raw, paths.digest(raw), copied)
        self.assertEqual(result['status'], 'PASS'); self.assertEqual(read.call_count, 1)
        (copied / '1.bin').unlink(); paths.write_new(copied / '1.bin', b'TAMPERED', 0o400)
        with patch.object(worker, 'read_owner', side_effect=AssertionError('private read before complete public authentication')):
            with self.assertRaises(ValueError):
                worker.scan(self.owner, raw, paths.digest(raw), copied)

    def test_exact_backup_schema_domain_encoding_and_manifest_paths(self):
        for changed in (dict(self.record, schema='kpx7-unfunded-owner-state/v1'),
                        dict(self.record, seed_hex32=PUBLIC_UNSAFE_SEED.hex().upper()),
                        dict(self.record, domain_hex32='00' * 32), dict(self.record, initial_position=0),
                        dict(self.record, participant_id_hex32='00' * 32)):
            self.owner.unlink(); paths.write_new(self.owner, paths.encoded(changed))
            with self.assertRaises(ValueError):
                worker.read_owner(self.owner)
        for name in ('../escape', '/absolute', '.', 'a//b', 'a\\b', 'nul\0name'):
            raw = paths.encoded({'schema': 'kpx8-new-owner-seed-export-allowlist/v1',
                'files': [{'path': name, 'bytes': 0, 'sha256': paths.digest(b'')}]})
            with self.assertRaises(ValueError):
                worker.allowlist(raw, paths.digest(raw))
        raw = b'{"schema":"a","schema":"b","files":[]}'
        with self.assertRaises(ValueError):
            worker.allowlist(raw, paths.digest(raw))

    def test_decoded_filename_metadata_is_a_scanned_candidate(self):
        _, copied, _, raw = self.selection([b'PUBLIC CLEAN CONTENT'])
        value = paths.parse(raw); value['files'][0]['path'] = PUBLIC_UNSAFE_SEED.hex() + '.bin'
        raw = paths.encoded(value).replace(b'abcdef', b'\\u0061bcdef')
        result = worker.scan(self.owner, raw, paths.digest(raw), copied)
        self.assertEqual((result['status'], result['matched_candidate_count']), ('FAIL', 1))

    def test_staging_is_metadata_only_single_leaf_and_rejects_nested_substitute(self):
        public, _, manifest, raw = self.selection([b'KNOWN PUBLIC CLEAN'])
        a = self.args(public, manifest, raw)
        original = paths.stable_read
        def public_only(path, *args, **kwargs):
            self.assertNotEqual(Path(path), self.owner, 'supervisor read original backup')
            return original(path, *args, **kwargs)
        with patch.object(paths, 'stable_read', side_effect=public_only):
            result = self.run_launcher(a)
        self.assertFalse(result['executed'])
        command = paths.parse((a.private_output / 'PRIVATE-PLAN.json').read_bytes())['command']
        at = command.index(str(self.owner))
        self.assertEqual(command[at - 1:at + 2], ['--ro-bind', str(self.owner), '/BACKUP.json'])
        self.assertIn('--unshare-all', command)
        self.assertNotIn(str(self.owner.parent), command)
        self.assertFalse(any('/attempts' in x or '/mpc' in x or '/runtime/' in x for x in command))
        self.assertEqual(list(a.output.iterdir()), [])
        nested = self.private / 'local-01/party-0/nested/owner/BACKUP.json'; nested.parent.mkdir(parents=True, mode=0o700)
        paths.write_new(nested, paths.encoded(self.record)); a.owner_leaf = nested
        with patch.object(paths, 'stable_read', side_effect=AssertionError('read before original registration')):
            with self.assertRaisesRegex(ValueError, 'exact-registered-original'):
                self.run_launcher(a)

    def test_closed_namespace_executes_only_synthetic_seed_canary(self):
        public, _, manifest, raw = self.selection([b'PUBLIC UNSAFE LEAK ' + PUBLIC_UNSAFE_SEED])
        result = self.run_launcher(self.args(public, manifest, raw, execute=True))
        self.assertEqual((result['status'], result['matched_candidate_count']), ('FAIL', 1))
        self.assertEqual(result['candidate_count'], 2)
        self.assertNotIn(PUBLIC_UNSAFE_SEED.hex(), paths.encoded(result).decode())


if __name__ == '__main__':
    unittest.main(verbosity=2)
