"""Real literal-loopback HTTP controls; all keys/bodies are public fake fixtures."""
from contextlib import contextmanager
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import Request

import capsule as c
import https_mirror as h
from test_capsule import PublicFixture


@contextmanager
def server(directory, *, corrupt=False, truncate=None, redirect=None):
    seen = []
    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            seen.append(self.path)
            if redirect is not None:
                self.send_response(302)
                self.send_header('Location', redirect + self.path + '?public_marker=DO_NOT_FUND')
                self.end_headers()
                return
            if corrupt or truncate is not None:
                point = Path(directory) / self.path.split('?', 1)[0].lstrip('/')
                if point.is_file():
                    raw = point.read_bytes()
                    if corrupt and len(raw) > 65536:
                        raw = b'X' * len(raw)
                    elif corrupt and not raw.startswith(b'{"domain_hex32":'):
                        # All typed objects are corrupted; the root index is
                        # kept exact so object-level fallback is exercised.
                        raw = b'X' * len(raw)
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    if truncate and point.name == truncate:
                        self.wfile.write(raw[:-1])
                        self.close_connection = True
                    else:
                        self.wfile.write(raw)
                    return
            super().do_GET()
    handler = functools.partial(Handler, directory=str(directory))
    instance = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(instance.server_address[1]), seen
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join()


class HTTPControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.f = PublicFixture(self.temporary.name)
        self.publish_index()

    def publish_index(self):
        f = self.f
        (f.objects / f.root_sha).write_bytes(f.index_path.read_bytes())

    def retrieve(self, bases, **kwargs):
        return h.retrieve_capsule(self.f.root_sha, self.f.selection, bases,
            self.f.parent / kwargs.pop('out', 'retrieval'),
            allow_loopback_http=True, **kwargs)

    def test_preferred_source_stopped_then_real_mirror_restore(self):
        with server(self.f.root) as (live, _):
            with server(self.f.root) as (gone, _):
                pass
            result = self.retrieve([gone, live])
        report = result.public_receipt()
        self.assertEqual(len(report['transport']['objects_downloaded']), 6)
        self.assertTrue(all(row['mirror_ordinal'] == 1
                            for row in report['transport']['objects_downloaded']))
        self.assertEqual(result.staged.staged_paths['public_parameters'].read_bytes(), self.f.pk)
        self.assertFalse(report['capsule']['current_state_verified'])
        self.assertFalse(report['transport']['independent_provider_or_retention_qualification'])

    def test_corrupted_primary_objects_use_exact_mirror(self):
        with server(self.f.root, corrupt=True) as (bad, _), server(self.f.root) as (good, _):
            result = self.retrieve([bad, good])
        rejected = result.public_receipt()['transport']['rejected_mirror_candidates']
        self.assertTrue(any(row['kind'] != 'capsule_index' for row in rejected))
        self.assertEqual(result.staged.owned_json['history'], self.f.raw['history'])

    def test_recognition_performs_no_PK_HTTP_request(self):
        f = self.f
        (f.objects / c.sha(f.pk)).unlink()
        with server(f.root) as (base, seen):
            result = self.retrieve([base], mode='recognition')
        self.assertFalse(result.staged.public_receipt()['public_PK_staged'])
        self.assertFalse(any(c.sha(f.pk) in path for path in seen))
        self.assertEqual(len(result.public_receipt()['transport']['objects_downloaded']), 5)

    def test_all_sources_missing_returns_incomplete(self):
        empty = self.f.parent / 'empty'
        empty.mkdir()
        with server(empty) as (base, _):
            with self.assertRaisesRegex(c.Incomplete, '^matching-public-object-unavailable$'):
                self.retrieve([base])

    def test_URL_policy_and_HTTPS_redirect_safety(self):
        for value in ('http://example.com/base', 'http://localhost/base',
                      'https://user:secret@example.com/base', 'https://example.com/base?token=x',
                      'https://example.com/base#fragment', 'https://example.com:99999/base'):
            with self.subTest(value=value):
                with self.assertRaises(c.Invalid):
                    h._url(value, True)
        with self.assertRaises(c.Invalid):
            h._url('http://127.0.0.1/base', False)
        redirects = h.SafeRedirect(True)
        request = Request('https://example.com/object')
        with self.assertRaisesRegex(c.Invalid, '^mirror-HTTPS-downgrade$'):
            redirects.redirect_request(request, None, 302, '', {}, 'http://127.0.0.1/object')
        redirected = redirects.redirect_request(request, None, 302, '', {},
            'https://another.example/object?public_signature=DO_NOT_FUND')
        self.assertEqual(redirected.full_url,
            'https://another.example/object?public_signature=DO_NOT_FUND')

    def test_wrong_role_rejected_before_PK_network_request(self):
        f = self.f
        f.parameter['role'], f.parameter['output_arity'] = 'wide32', 32
        f.rebuild()
        self.publish_index()
        with server(f.root) as (base, seen):
            with self.assertRaisesRegex(c.Invalid, '^parameter-manifest-role$'):
                self.retrieve([base])
        self.assertFalse(any(c.sha(f.pk) in path for path in seen))

    def test_actual_loopback_redirect_queries_not_reported(self):
        with server(self.f.root) as (target, _):
            with server(self.f.root, redirect=target) as (front, _):
                result = self.retrieve([front])
        report = str(result.public_receipt())
        self.assertNotIn('DO_NOT_FUND', report)
        self.assertNotIn('http://', report)
        self.assertNotIn('public_marker', report)

    def test_truncated_response_falls_back_without_splicing(self):
        f = self.f
        with server(f.root, truncate=c.sha(f.raw['history'])) as (bad, _):
            with server(f.root) as (good, _):
                result = self.retrieve([bad, good])
        self.assertEqual(result.staged.owned_json['history'], f.raw['history'])
        self.assertTrue(any(row['kind'] == 'history' for row in
            result.public_receipt()['transport']['rejected_mirror_candidates']))


if __name__ == '__main__':
    unittest.main()
