"""Real loopback TLS controls with ephemeral synthetic CA, never real secrets.

External system-CA HTTPS observation is a separately retained experiment.
"""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
from urllib.request import Request

import public_fetch as pf

ORIGINAL_CONTEXT = ssl.create_default_context
PAYLOAD = b'public transport fixture: no key, seed or financial witness\n'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urlsplit(self.path).path
        self.server.requests.append(route)
        if route == '/redirect':
            self.send_response(302)
            self.send_header('Location', self.server.base + '/good?token=UNLOGGED_TEST_TOKEN')
            self.end_headers()
            return
        if route == '/missing' or (route not in self.server.objects
                and route not in ('/good', '/bad', '/short', '/appended')):
            self.send_response(404)
            self.end_headers()
            return
        body = self.server.objects.get(route,
            PAYLOAD if route != '/bad' else b'X' * len(PAYLOAD))
        declared = len(body)
        if route == '/short':
            body = body[:-1]
        if route == '/appended':
            body += b'X'
            declared += 1
        self.send_response(200)
        self.send_header('Content-Length', str(declared))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *args):
        pass


class HTTPSControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.cert = root / 'synthetic-test-cert.pem'
        config = root / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nprompt=no\n'
            '[dn]\nCN=localhost\n[x509]\nsubjectAltName=DNS:localhost\n'
            'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-nodes', '-days', '1', '-config', str(config), '-extensions', 'x509',
            '-keyout', str(root / 'ephemeral-TLS-test-key.pem'), '-out', str(cls.cert)],
            check=True, capture_output=True)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, root / 'ephemeral-TLS-test-key.pem')
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.base = 'https://localhost:' + str(cls.server.server_port)
        cls.server.base = cls.base
        cls.server.objects = {}
        cls.server.requests = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def setUp(self):
        self.tmpout = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpout.name)
        self.output = self.root / 'verified-public-object'
        self.server.requests.clear()
        self.trust = patch.object(pf.ssl, 'create_default_context',
            side_effect=lambda: ORIGINAL_CONTEXT(cafile=str(self.cert)))
        self.trust.start()

    def tearDown(self):
        self.trust.stop()
        self.tmpout.cleanup()

    def fetch(self, paths, **kwargs):
        return pf.fetch_object([self.base + p for p in paths], len(PAYLOAD),
            hashlib.sha256(PAYLOAD).hexdigest(), self.output,
            ['localhost', '127.0.0.1'], **kwargs)

    def absent(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(any(p.name.startswith('.partial-') for p in self.root.iterdir()))

    def test_actual_TLS_exact_bytes(self):
        receipt = self.fetch(['/good'])
        self.assertEqual(self.output.read_bytes(), PAYLOAD)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o444)
        self.assertFalse(receipt['spend_authorized'])

    def test_corrupt_preferred_falls_back_without_splice(self):
        receipt = self.fetch(['/bad', '/good'])
        self.assertEqual(self.output.read_bytes(), PAYLOAD)
        self.assertEqual(receipt['selected_source_ordinal'], 1)
        self.assertEqual(len(receipt['rejected_sources']), 1)

    def test_missing_issuer_falls_back(self):
        receipt = self.fetch(['/missing', '/good'])
        self.assertEqual(receipt['selected_source_ordinal'], 1)
        self.assertEqual(self.output.read_bytes(), PAYLOAD)

    def test_all_missing_is_incomplete_without_output(self):
        with self.assertRaises(pf.c.Incomplete):
            self.fetch(['/missing'])
        self.absent()

    def test_truncation_and_declared_overflow_never_publish(self):
        for path in ['/short', '/appended']:
            with self.subTest(path=path), self.assertRaises(pf.c.Incomplete):
                self.fetch([path])
            self.absent()

    def test_real_signed_redirect_query_never_enters_receipt(self):
        receipt = self.fetch(['/redirect'])
        self.assertEqual(len(receipt['redirects']), 1)
        self.assertNotIn('UNLOGGED_TEST_TOKEN', json.dumps(receipt))
        self.assertNotIn('?token', json.dumps(receipt))
        self.assertEqual(self.output.read_bytes(), PAYLOAD)

    def test_untrusted_certificate_rejected(self):
        with patch.object(pf.ssl, 'create_default_context', side_effect=ORIGINAL_CONTEXT):
            with self.assertRaises(pf.c.Incomplete):
                self.fetch(['/good'])
        self.absent()

    def test_hostname_mismatch_rejected(self):
        url = self.base.replace('localhost', '127.0.0.1') + '/good'
        with self.assertRaises(pf.c.Incomplete):
            pf.fetch_object([url], len(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest(),
                self.output, ['127.0.0.1'])
        self.absent()

    def test_redirect_every_hop_policy_and_limit(self):
        request = Request('https://localhost/start')
        for bad in ['http://localhost/plain', 'https://outside.invalid/other',
                    'https://user:password@localhost/other']:
            handler = pf.StrictRedirect(['localhost'])
            with self.subTest(bad=bad), self.assertRaises(pf.c.Invalid):
                handler.redirect_request(request, None, 302, '', {}, bad)
        handler = pf.StrictRedirect(['localhost'])
        for i in range(5):
            handler.redirect_request(request, None, 302, '', {},
                                     'https://localhost/step' + str(i))
        with self.assertRaises(pf.c.Invalid):
            handler.redirect_request(request, None, 302, '', {}, 'https://localhost/sixth')

    def test_initial_credential_query_and_wrong_pin_rejected(self):
        for url in ['https://user:secret@localhost/x', self.base + '/good?token=private']:
            with self.subTest(url=url), self.assertRaises(pf.c.Invalid):
                pf.fetch_object([url], len(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest(),
                    self.output, ['localhost'])
        with self.assertRaises(pf.c.Incomplete):
            pf.fetch_object([self.base + '/good'], len(PAYLOAD), '0' * 64,
                self.output, ['localhost'])
        self.absent()

    def test_existing_destination_and_symlink_parent_never_clobbered(self):
        self.output.write_bytes(b'keep')
        with patch.object(pf, 'opener', side_effect=AssertionError('network must not start')):
            with self.assertRaises(pf.c.Invalid):
                self.fetch(['/good'])
        self.assertEqual(self.output.read_bytes(), b'keep')
        alias = self.root / 'parent-link'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            pf.fetch_object([self.base + '/good'], len(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest(),
                alias / 'unexpected', ['localhost'])
        self.assertFalse((self.root / 'unexpected').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
