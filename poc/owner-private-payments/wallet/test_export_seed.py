"""PUBLIC UNSAFE SEED sentinels only; never any actual new/old owner material."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import export_seed_worker as worker
import paths
import run_export_seed as launcher
import test_boundary as boundary

PUBLIC_UNSAFE_SEED = bytes.fromhex('0123456789abcdef' * 4)


class ExportSeed(boundary.Boundary):
    def setUp(self):
        super().setUp()
        self.owner = self.new[0] / 'owner' / 'OWNER.json'
        self.record = {'schema': 'kpx7-unfunded-owner-state/v1', 'domain_hex32': worker.DOMAIN,
            'participant_id_hex32': '12' * 32, 'seed_hex32': PUBLIC_UNSAFE_SEED.hex(),
            'initial_position': 0, 'input_receipt_hex216': '34' * 216}
        paths.write_new(self.owner, paths.encoded(self.record) + b'\n')

    def selection(self, payloads):
        public = self.root / 'selected-public'; public.mkdir(mode=0o700)
        copied = self.root / 'worker-candidates'; copied.mkdir(mode=0o700)
        rows = []
        for index, raw in enumerate(payloads):
            name = 'public-' + str(index) + '.bin'
            paths.write_new(public / name, raw, 0o400)
            paths.write_new(copied / (str(index) + '.bin'), raw, 0o400)
            rows.append({'path': name, 'bytes': len(raw), 'sha256': paths.digest(raw)})
        raw = paths.encoded({'schema': 'kpx7-new-owner-seed-export-allowlist/v1', 'files': rows}) + b'\n'
        manifest = self.root / 'ALLOWLIST.json'; paths.write_new(manifest, raw, 0o400)
        return public, copied, manifest, raw

    def args(self, public, manifest, raw, output, execute=False):
        return SimpleNamespace(owner_leaf=self.owner, public_root=public, allowlist=manifest,
            allowlist_sha256=paths.digest(raw), output=output, exclude_old_trial=self.old,
            exclude_new_private_parent=self.new, execute=execute)

    def test_literal_raw_lower_upper_and_chunk_boundary_hits_no_key_output(self):
        seed = PUBLIC_UNSAFE_SEED
        payloads = [b'PUBLIC CLEAN', b'prefix' + seed + b'suffix', seed.hex().encode(),
            b'x' * (worker.CHUNK - 11) + seed.hex().upper().encode() + b'end']
        _, copied, _, raw = self.selection(payloads)
        result = worker.scan(self.owner, raw, paths.digest(raw), copied)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual((result['candidate_count'], result['matched_candidate_count']), (5, 3))
        self.assertEqual(result['candidate_bytes'], sum(map(len, payloads)) + len(raw))
        self.assertEqual(set(result), {'schema', 'status', 'candidate_count', 'candidate_bytes',
                                      'matched_candidate_count', 'scope'})
        self.assertNotIn(seed.hex(), paths.encoded(result).decode())

    def test_all_public_authentication_precedes_single_owner_read(self):
        _, copied, _, raw = self.selection([b'PUBLIC ONLY', b'MORE PUBLIC'])
        original = worker.read_owner
        with patch.object(worker, 'read_owner', wraps=original) as read:
            result = worker.scan(self.owner, raw, paths.digest(raw), copied)
        self.assertEqual(result['status'], 'PASS'); self.assertEqual(read.call_count, 1)
        (copied / '1.bin').unlink(); paths.write_new(copied / '1.bin', b'CHANGED', 0o400)
        with patch.object(worker, 'read_owner', side_effect=AssertionError('private read before public auth')):
            with self.assertRaises(ValueError):
                worker.scan(self.owner, raw, paths.digest(raw), copied)

    def test_public_allowlist_and_decoded_filename_are_also_scanned(self):
        _, copied, _, original = self.selection([b'PUBLIC CLEAN CONTENT'])
        rows = paths.parse(original)
        rows['files'][0]['path'] = PUBLIC_UNSAFE_SEED.hex() + '.bin'
        # JSON unicode escaping cannot hide the actual published filename.
        raw = paths.encoded(rows).replace(b'abcdef', b'\\u0061bcdef')
        result = worker.scan(self.owner, raw, paths.digest(raw), copied)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual((result['candidate_count'], result['matched_candidate_count']), (2, 1))

    def test_exact_schema_and_manifest_reject_malformed_inputs(self):
        for key, replacement in (('seed_hex32', PUBLIC_UNSAFE_SEED.hex().upper()),
                                  ('initial_position', True), ('domain_hex32', '00' * 32)):
            value = copy.deepcopy(self.record); value[key] = replacement
            self.owner.unlink(); paths.write_new(self.owner, paths.encoded(value))
            with self.assertRaises(ValueError):
                worker.read_owner(self.owner)
        for name in ('../escape', '/absolute', '.', 'a//b', 'a\\b', 'nul\0name'):
            raw = paths.encoded({'schema': 'kpx7-new-owner-seed-export-allowlist/v1',
                'files': [{'path': name, 'bytes': 0, 'sha256': paths.digest(b'')}]})
            with self.assertRaises(ValueError):
                worker.allowlist(raw, paths.digest(raw))
        duplicate = b'{"schema":"x","schema":"y","files":[]}'
        with self.assertRaises(ValueError):
            worker.allowlist(duplicate, paths.digest(duplicate))

    def test_all_extra_private_parents_are_metadata_guarded_before_reads(self):
        extra = self.root / 'another-world-controller-private'; extra.mkdir(mode=0o700)
        secret = extra / 'GENERIC.bin'; paths.write_new(secret, b'PUBLIC UNSAFE PRIVATE SENTINEL')
        with patch.object(paths.os, 'open', side_effect=AssertionError('metadata opened bytes')):
            policy = launcher.ExportPolicy(self.old, [*self.new, extra])
        with self.assertRaisesRegex(ValueError, 'inside-private-tree'):
            policy.read(secret)
        alias = self.root / 'alias-public'; alias.hardlink_to(secret)
        with patch.object(paths.os, 'open', side_effect=AssertionError('alias opened bytes')):
            with self.assertRaisesRegex(ValueError, 'private-alias'):
                policy.read(alias)
        with self.assertRaisesRegex(ValueError, 'private-leaf-type-or-link'):
            launcher.ExportPolicy(self.old, [*self.new, extra])

    def test_staging_never_reads_owner_and_mounts_only_that_private_leaf(self):
        public, _, manifest, raw = self.selection([b'PUBLIC ONLY'])
        a = self.args(public, manifest, raw, self.root / 'staged')
        original = paths.stable_read
        def public_only(path, *args, **kwargs):
            self.assertNotEqual(Path(path), self.owner)
            return original(path, *args, **kwargs)
        with patch.object(paths, 'stable_read', side_effect=public_only):
            self.assertFalse(launcher.run(a)['executed'])
        command = paths.parse((a.output / 'PRIVATE-PLAN.json').read_bytes())['command']
        self.assertEqual(command.count(str(self.owner)), 1)
        self.assertIn('--unshare-all', command)
        for root in self.new:
            self.assertNotIn(str(root), command)
            self.assertNotIn(str(root / 'owner'), command)
            self.assertNotIn(str(root / 'mpc'), command)
        self.assertFalse(any('/attempts' in value or '/runtime/' in value or '/parameters/' in value for value in command))

    def test_nested_dummy_owner_cannot_replace_original_leaf(self):
        public, _, manifest, raw = self.selection([b'PUBLIC ONLY'])
        nested = self.new[0] / 'nested' / 'owner'; nested.mkdir(parents=True, mode=0o700)
        dummy = nested / 'OWNER.json'; paths.write_new(dummy, paths.encoded(self.record))
        a = self.args(public, manifest, raw, self.root / 'refused-dummy'); a.owner_leaf = dummy
        with patch.object(paths, 'stable_read', side_effect=AssertionError('read before exact owner selection')):
            with self.assertRaisesRegex(ValueError, 'one-original-new-owner-leaf'):
                launcher.run(a)

    def test_closed_synthetic_namespace_executes_canary_without_actual_owner(self):
        public, _, manifest, raw = self.selection([b'KNOWN PUBLIC UNSAFE ' + PUBLIC_UNSAFE_SEED])
        result = launcher.run(self.args(public, manifest, raw, self.root / 'closed-synthetic', execute=True))
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['matched_candidate_count'], 1)
        self.assertEqual(set(result), {'schema', 'status', 'candidate_count', 'candidate_bytes',
                                      'matched_candidate_count', 'scope'})


for inherited in tuple(name for name in dir(boundary.Boundary) if name.startswith('test_')):
    setattr(ExportSeed, inherited, None)

if __name__ == '__main__':
    unittest.main(verbosity=2)
