"""Public synthetic transport controls; no parameters/private inputs/native use."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import capsule as c
import chunk_public as ch


class OpenWatch:
    def __init__(self, path):
        libc = ctypes.CDLL(None, use_errno=True)
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'inotify_init1')
        if libc.inotify_add_watch(self.fd, os.fsencode(path), 0x20) < 0:
            os.close(self.fd)
            raise OSError(ctypes.get_errno(), 'inotify_add_watch')

    def events(self):
        try:
            return os.read(self.fd, 65536)
        except BlockingIOError:
            return b''

    def close(self):
        os.close(self.fd)


class ChunkControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # CLI always uses 1 GiB. This imported tiny fixture uses 16-byte chunks
        # to exercise boundaries/fallback/ordering without large test objects.
        self.size = patch.object(ch, 'CHUNK_BYTES', 16)
        self.size.start()
        self.data = bytes(range(73))
        self.source = self.root / 'source'
        self.source.write_bytes(self.data)
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.pack = self.root / 'pack'
        ch.pack(self.source, len(self.data), self.digest, self.pack)
        self.manifest = self.pack / 'manifest.json'
        self.index = json.loads(self.manifest.read_bytes())
        self.output = self.root / 'restored'

    def tearDown(self):
        self.size.stop()
        self.tmp.cleanup()

    def write_index(self, index):
        path = self.root / 'edited-index'
        path.write_bytes(c.encoded(index))
        return path

    def restore(self, **kwargs):
        args = dict(manifest=self.manifest, length=len(self.data),
                    digest=self.digest, mirrors=[self.pack], output=self.output)
        args.update(kwargs)
        return ch.restore(**args)

    def incomplete(self, **kwargs):
        with self.assertRaises(c.Invalid):
            self.restore(**kwargs)
        self.assertFalse(self.output.exists())
        self.assertFalse(any(p.name.startswith('.partial-')
                             for p in self.root.iterdir()))

    def test_roundtrip_after_original_source_removed(self):
        original_inode = self.source.stat().st_ino
        self.source.unlink()
        result = self.restore(must_be_absent=[self.source])
        self.assertEqual(self.output.read_bytes(), self.data)
        self.assertNotEqual(self.output.stat().st_ino, original_inode)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o444)
        self.assertTrue(result['whole_verified'])
        self.assertEqual(result['original_path_absence_probe_count'], 1)

    def test_actual_production_cli_single_chunk_source_loss(self):
        script = Path(ch.__file__).absolute()
        packed = self.root / 'cli-pack'
        output = self.root / 'cli-output'
        common = ['--expected-bytes', str(len(self.data)),
                  '--expected-sha256', self.digest]
        packed_result = subprocess.run([sys.executable, '-B', str(script),
            'pack', '--source', str(self.source), '--output-dir', str(packed),
            *common], capture_output=True, check=True)
        self.assertEqual(json.loads(packed_result.stdout)['chunk_bytes'],
                         1_073_741_824)
        self.source.unlink()
        restored = subprocess.run([sys.executable, '-B', str(script), 'restore',
            '--manifest', str(packed / 'manifest.json'), '--mirror', str(packed),
            '--output', str(output), '--must-be-absent', str(self.source),
            *common], capture_output=True, check=True)
        self.assertTrue(json.loads(restored.stdout)['whole_verified'])
        self.assertEqual(output.read_bytes(), self.data)

    def test_corrupt_preferred_falls_back_same_chunk(self):
        preferred = self.root / 'bad-first'
        preferred.mkdir()
        chunk = self.index['chunks'][1]
        (preferred / chunk['basename']).write_bytes(b'X' * chunk['bytes'])
        result = self.restore(mirrors=[preferred, self.pack])
        self.assertEqual(self.output.read_bytes(), self.data)
        self.assertEqual(result['selected_mirror_ordinals'], [1] * 5)
        self.assertIn('chunk-content-sha256-mismatch',
                      [x['reason'] for x in result['rejected_candidates']])

    def test_all_corrupt_fail_without_publishing(self):
        p = self.pack / self.index['chunks'][2]['basename']
        p.chmod(0o600)
        p.write_bytes(b'Q' * p.stat().st_size)
        self.incomplete()

    def test_missing_final_chunk_fails_without_publishing(self):
        (self.pack / self.index['chunks'][-1]['basename']).unlink()
        self.incomplete()

    def test_truncation_and_trailing_rejected(self):
        p = self.pack / self.index['chunks'][0]['basename']
        original = p.read_bytes()
        p.chmod(0o600)
        for mutated in (original[:-1], original + b'X'):
            with self.subTest(length=len(mutated)):
                p.write_bytes(mutated)
                self.incomplete()

    def test_external_anchor_checked_before_chunk_open(self):
        with patch.object(c, '_open_public', wraps=c._open_public) as opened:
            self.incomplete(digest='0' * 64)
        self.assertEqual(opened.call_count, 1)  # index only

    def test_reordered_manifest_positions_rejected(self):
        self.index['chunks'].reverse()
        self.incomplete(manifest=self.write_index(self.index))

    def test_self_consistent_substitution_fails_whole_anchor(self):
        replacement = self.root / 'replacement'
        replacement.mkdir()
        for chunk in self.index['chunks']:
            raw = b'R' * chunk['bytes']
            chunk['sha256'] = hashlib.sha256(raw).hexdigest()
            chunk['basename'] = ch._basename(chunk['index'], chunk['sha256'])
            (replacement / chunk['basename']).write_bytes(raw)
        self.incomplete(manifest=self.write_index(self.index),
                        mirrors=[replacement])

    def test_repeated_chunk_hashes_are_legal(self):
        repeated = b'A' * 32
        source = self.root / 'repeated'
        source.write_bytes(repeated)
        digest = hashlib.sha256(repeated).hexdigest()
        packed = self.root / 'repeated-pack'
        ch.pack(source, 32, digest, packed)
        index = json.loads((packed / 'manifest.json').read_bytes())
        self.assertEqual(index['chunks'][0]['sha256'],
                         index['chunks'][1]['sha256'])
        result = self.restore(manifest=packed / 'manifest.json', length=32,
                              digest=digest, mirrors=[packed])
        self.assertTrue(result['whole_verified'])
        self.assertEqual(self.output.read_bytes(), repeated)

    def test_unsafe_basename_and_duplicate_field_rejected(self):
        self.index['chunks'][0]['basename'] = '../source'
        self.incomplete(manifest=self.write_index(self.index))
        duplicate = self.root / 'duplicate'
        raw = self.manifest.read_bytes()
        duplicate.write_bytes(raw[:-1] + b',"schema":"duplicate"}')
        self.incomplete(manifest=duplicate)

    def test_symlink_manifest_chunk_and_output_parent_rejected(self):
        link = self.root / 'index-link'
        link.symlink_to(self.manifest)
        self.incomplete(manifest=link)
        chunk = self.index['chunks'][0]
        p = self.pack / chunk['basename']
        moved = self.root / 'moved'
        p.rename(moved)
        p.symlink_to(moved)
        self.incomplete()
        p.unlink()
        moved.rename(p)
        parent = self.root / 'parent-link'
        parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.restore(output=parent / 'unexpected')
        self.assertFalse((self.root / 'unexpected').exists())

    def test_alias_guards_before_content_open_kernel_calibrated(self):
        sentinel = self.root / 'synthetic-forbidden'
        sentinel.write_bytes(b'synthetic not a seed')
        watch = OpenWatch(sentinel)
        try:
            with sentinel.open('rb'):
                pass
            self.assertTrue(watch.events())  # positive IN_OPEN calibration
            alias = self.root / 'sentinel-alias'
            os.link(sentinel, alias)
            with self.assertRaises(c.Invalid):
                ch.pack(alias, sentinel.stat().st_size, '0' * 64,
                        self.root / 'bad-pack', [sentinel])
            self.assertEqual(watch.events(), b'')
            self.incomplete(manifest=alias, forbidden_paths=[sentinel])
            self.assertEqual(watch.events(), b'')
            chunk = self.index['chunks'][0]
            chunk['bytes'] = 16  # original fixed chunk size
            chunk['sha256'] = hashlib.sha256(b'synthetic not a seed').hexdigest()
            chunk['basename'] = ch._basename(0, chunk['sha256'])
            os.link(sentinel, self.pack / chunk['basename'])
            self.incomplete(manifest=self.write_index(self.index),
                            forbidden_paths=[sentinel])
            self.assertEqual(watch.events(), b'')
        finally:
            watch.close()

    def test_existing_destination_never_replaced(self):
        self.output.write_bytes(b'keep')
        with self.assertRaises(c.Invalid):
            self.restore()
        self.assertEqual(self.output.read_bytes(), b'keep')

    def test_failed_pack_whole_hash_removes_owned_output(self):
        output = self.root / 'failed-pack'
        with self.assertRaises(c.Invalid):
            ch.pack(self.source, len(self.data), '0' * 64, output)
        self.assertFalse(output.exists())

    def test_visible_original_rejected_before_public_content(self):
        with patch.object(c, '_open_public', wraps=c._open_public) as opened:
            self.incomplete(must_be_absent=[self.source])
        self.assertEqual(opened.call_count, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
