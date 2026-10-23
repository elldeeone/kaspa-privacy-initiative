"""Public unsafe-canary transport controls; no PK/backup/proof reads.

The fixture is explicit public GN material supplied by root, never main history.
TLS uses the same ephemeral test CA as public_fetch controls.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import retrieve as rt
import test_public_fetch as tls_fixture


class PipelineControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tls_fixture.HTTPSControls.setUpClass.__func__(cls)
        fixture = Path(os.environ.get('PUBLIC_CANARY_FIXTURES', '/fixtures'))
        cls.owned = {name: (fixture / name).read_bytes() for name in
            ['PUBLICATION.json', 'EXTERNAL-SELECTION.json', 'descriptor.json',
             'history.json', 'parameters_manifest.json', 'software_inventory.json',
             'capsule.json', 'compact2-chunks.json']}

    @classmethod
    def tearDownClass(cls):
        tls_fixture.HTTPSControls.tearDownClass.__func__(cls)

    setUp = tls_fixture.HTTPSControls.setUp
    tearDown = tls_fixture.HTTPSControls.tearDown

    def prepare(self):
        self.selection = rt.c.TrustedSelection.from_dict(
            rt.c.parse(self.owned['EXTERNAL-SELECTION.json']))
        self.publication = self.root / 'PUBLICATION.json'
        self.publication.write_bytes(self.owned['PUBLICATION.json'])
        self.pin = hashlib.sha256(self.owned['PUBLICATION.json']).hexdigest()
        self.server.objects = {'/' + name: raw for name, raw in self.owned.items()
                               if name not in ('PUBLICATION.json', 'EXTERNAL-SELECTION.json')}

    def restore(self, mode='recognition'):
        return rt.retrieve(self.publication, self.pin, self.selection,
            [{'kind': 'release', 'base': self.base}], self.output,
            ['localhost'], mode=mode)

    def test_recognition_actual_TLS_without_PK_requests_or_current_claim(self):
        self.prepare()
        result = self.restore()
        self.assertFalse(result['current_state_verified'])
        self.assertFalse(result['spend_authorized'])
        self.assertFalse(any('chunk' in path for path in self.server.requests))
        self.assertTrue((self.output / 'recognition/descriptor').exists())

    def test_wrong_publication_root_fails_before_any_network(self):
        self.prepare()
        self.pin = '0' * 64
        with patch.object(rt, 'fetch_object', side_effect=AssertionError('network reached')):
            with self.assertRaises(rt.c.Invalid):
                self.restore()
        self.assertEqual(self.server.requests, [])

    def test_self_consistent_index_cannot_replace_external_whole_key(self):
        self.prepare()
        value = rt.c.parse(self.owned['PUBLICATION.json'])
        value['whole_parameters']['sha256'] = '0' * 64
        raw = rt.c.encoded(value)
        self.publication.write_bytes(raw)
        self.pin = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(rt.c.Invalid):
            self.restore()
        self.assertEqual(self.server.requests, [])

    def test_corrupt_small_object_fails_before_PK_download(self):
        self.prepare()
        raw = self.server.objects['/descriptor.json']
        self.server.objects['/descriptor.json'] = b'X' * len(raw)
        with self.assertRaises(rt.c.Incomplete):
            self.restore(mode='spend_material')
        self.assertFalse(any('chunk' in path for path in self.server.requests))
        self.assertFalse((self.output / 'PUBLIC-RESULT.json').exists())

    def test_missing_required_PK_chunk_is_incomplete_never_zero(self):
        self.prepare()
        with self.assertRaises(rt.c.Incomplete):
            self.restore(mode='spend_material')
        self.assertTrue(any(path.startswith('/chunk-') for path in self.server.requests))
        self.assertFalse((self.output / 'PUBLIC-RESULT.json').exists())
        self.assertFalse((self.output / 'spend-material').exists())

    def test_reordered_chunk_index_rejected_before_chunk_requests(self):
        self.prepare()
        index = rt.c.parse(self.owned['compact2-chunks.json'])
        index['chunks'].reverse()
        raw = rt.c.encoded(index)
        self.server.objects['/compact2-chunks.json'] = raw
        publication = rt.c.parse(self.owned['PUBLICATION.json'])
        row = next(r for r in publication['assets'] if r['kind'] == 'chunk_index')
        row.update({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        raw = rt.c.encoded(publication)
        self.publication.write_bytes(raw)
        self.pin = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(rt.c.Invalid):
            self.restore(mode='spend_material')
        self.assertFalse(any(path.startswith('/chunk-') for path in self.server.requests))

    def test_generator_publication_alias_rejected_before_content_open(self):
        self.prepare()
        alias = self.root / 'public-sentinel-alias'
        os.link(self.publication, alias)
        libc = ctypes.CDLL(None, use_errno=True)
        watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        self.assertGreaterEqual(watch, 0)
        try:
            self.assertGreaterEqual(libc.inotify_add_watch(watch, os.fsencode(alias), 0x20), 0)
            with alias.open('rb'):
                pass
            self.assertTrue(os.read(watch, 65536))
            with self.assertRaises(rt.c.Invalid):
                rt.retrieve(alias, self.pin, self.selection, [], self.output,
                    ['localhost'], forbidden_paths=(p for p in [self.publication]))
            try:
                events = os.read(watch, 65536)
            except BlockingIOError:
                events = b''
            self.assertEqual(events, b'')
        finally:
            os.close(watch)


if __name__ == '__main__':
    unittest.main(verbosity=2)
