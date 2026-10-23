"""Independent public-only regression for a one-shot forbidden-path iterator.

The sentinel is canonical public JSON, never a seed, backup or real parameter.
The Linux IN_OPEN watch is positively calibrated on the same hardlink inode.
"""
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CODE = Path(os.environ.get('CHUNK_PUBLIC_CODE', '/work'))
c = load('capsule', CODE / 'capsule.py')
ch = load('chunk_public', CODE / 'chunk_public.py')


class IteratorGuard(unittest.TestCase):
    def test_manifest_alias_iterator_rejects_before_content_open(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            payload = b'public fixture bytes'
            digest = hashlib.sha256(payload).hexdigest()
            chunks = root / 'chunks'
            chunks.mkdir()
            basename = f'chunk-00000000-{digest}.bin'
            (chunks / basename).write_bytes(payload)
            manifest = {'schema': 'kpx4-public-object-chunks/v1',
                'object_bytes': len(payload), 'object_sha256': digest,
                'chunk_bytes': 1_073_741_824, 'chunks': [{'index': 0,
                    'offset': 0, 'bytes': len(payload), 'sha256': digest,
                    'basename': basename}]}
            sentinel = root / 'synthetic-public-sentinel-not-a-seed'
            sentinel.write_bytes(c.encoded(manifest))
            alias = root / 'manifest-alias'
            os.link(sentinel, alias)
            libc = ctypes.CDLL(None, use_errno=True)
            watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            self.assertGreaterEqual(watch, 0)
            try:
                self.assertGreaterEqual(libc.inotify_add_watch(watch,
                    os.fsencode(sentinel), 0x20), 0)
                with alias.open('rb'):
                    pass
                self.assertTrue(os.read(watch, 65536), 'positive IN_OPEN calibration')
                output = root / 'must-not-be-published'
                rejected = False
                try:
                    ch.restore(alias, len(payload), digest, [chunks], output,
                        forbidden_paths=(p for p in [sentinel]))
                except c.Invalid:
                    rejected = True
                try:
                    events = os.read(watch, 65536)
                except BlockingIOError:
                    events = b''
                self.assertEqual(events, b'', 'forbidden iterator alias was content-opened')
                self.assertTrue(rejected, 'forbidden iterator alias was accepted')
                self.assertFalse(output.exists())
            finally:
                os.close(watch)


if __name__ == '__main__':
    unittest.main(verbosity=2)
