"""Independent public-only one-shot exclusion guards at three outer APIs.

No actual parameters, backups, witnesses, financial fixtures or network. The
HTTPS case mocks byte transport and semantic staging to inspect propagation;
it is not a TLS, semantic-history or native-acceptance test.
"""
import ctypes
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CODE = Path(os.environ.get('CAPSULE_CODE_PATH', '/work'))
c = load('capsule', CODE / 'capsule.py')
p = load('pack_local', CODE / 'pack_local.py')
h = load('https_mirror', CODE / 'https_mirror.py')


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


class OuterIteratorGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.sentinel = self.root / 'synthetic-public-json-not-a-seed'
        self.sentinel.write_bytes(b'{}')
        self.alias = self.root / 'public-json-alias'
        os.link(self.sentinel, self.alias)
        self.watch = OpenWatch(self.sentinel)
        with self.alias.open('rb'):
            pass
        self.assertTrue(self.watch.events(), 'positive same-inode IN_OPEN calibration')
        digest = hashlib.sha256(b'{}').hexdigest()
        self.pk = b'opaque public fixture, not Ark parameters'
        self.selection = c.TrustedSelection(network_id='testnet-10',
            genesis_hash_hex=c.GENESIS, domain_hex32='01' * 32,
            program_label='AUTH528_COMPACT_BATCH/v1', role='compact2',
            auth_magic_hex8=b'KPX4AU01'.hex(), descriptor_sha256=digest,
            parameters_manifest_sha256=digest,
            public_parameters_sha256=hashlib.sha256(self.pk).hexdigest(),
            public_parameters_bytes=len(self.pk), vk_sha256='02' * 32,
            software_inventory_sha256=digest)

    def tearDown(self):
        os.close(self.watch.fd)
        self.temp.cleanup()

    def excluded(self):
        return (path for path in [self.sentinel])

    def test_stage_generator_manifest_alias_rejected_without_open(self):
        try:
            with self.assertRaises(c.Invalid):
                c.stage_capsule(self.alias, hashlib.sha256(b'{}').hexdigest(),
                    self.selection, [self.root], self.root / 'never-stage',
                    self.excluded(), mode='recognition')
        finally:
            self.assertEqual(self.watch.events(), b'', 'stage content-opened forbidden alias')
        self.assertFalse((self.root / 'never-stage').exists())

    def test_pack_generator_source_alias_rejected_without_open(self):
        sources = {kind: self.alias for kind in c.SMALL_KINDS}
        try:
            with self.assertRaises(c.Invalid):
                p.pack_local(self.selection, sources, self.root / 'never-pack',
                    self.excluded(), mode='recognition')
        finally:
            self.assertEqual(self.watch.events(), b'', 'pack content-opened forbidden alias')
        self.assertFalse((self.root / 'never-pack').exists())

    def test_https_retains_exclusions_across_both_staging_delegations(self):
        small = b'{}'
        small_digest = hashlib.sha256(small).hexdigest()
        pk_digest = hashlib.sha256(self.pk).hexdigest()
        refs = [{'kind': kind, 'sha256': pk_digest if kind == 'public_parameters'
            else small_digest, 'bytes': len(self.pk) if kind == 'public_parameters'
            else len(small)} for kind in sorted(c.KINDS)]
        index = c.encoded({'schema': 'kpx4-public-recovery-capsule/v1',
            'network_id': self.selection.network_id,
            'genesis_hash_hex': self.selection.genesis_hash_hex,
            'domain_hex32': self.selection.domain_hex32,
            'program_label': self.selection.program_label, 'role': 'compact2',
            'objects': refs})
        root_sha = hashlib.sha256(index).hexdigest()
        objects = {root_sha: index, small_digest: small, pk_digest: self.pk}

        class Response(io.BytesIO):
            status = 200

            def __init__(self, url, data):
                super().__init__(data)
                self.url = url
                self.headers = {'Content-Length': str(len(data))}

            def geturl(self):
                return self.url

        class Opener:
            def open(self, request, timeout):
                digest = request.full_url.rsplit('/', 1)[-1]
                return Response(request.full_url, objects[digest])

        seen = []

        def staged(manifest, digest, selection, mirrors, output, exclusions,
                   *, mode):
            self.assertIs(type(exclusions), tuple)
            self.assertEqual(exclusions, (self.sentinel,))
            seen.append(mode)
            return object()  # This test asserts propagation, never semantic success.

        with patch.object(h, 'build_opener', return_value=Opener()), \
             patch.object(c, 'stage_capsule', side_effect=staged):
            h.retrieve_capsule(root_sha, self.selection, ['http://127.0.0.1:1'],
                self.root / 'retrieval', self.excluded(),
                mode='spend_material', allow_loopback_http=True)
        self.assertEqual(seen, ['recognition', 'spend_material'])
        self.assertEqual(self.watch.events(), b'')


if __name__ == '__main__':
    unittest.main(verbosity=2)
