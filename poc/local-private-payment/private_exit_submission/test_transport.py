"""Public framing/socket controls only; no Tor, wallet, proof or anonymity test."""
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import packet
import receiver
import transport


def untrusted_projection(width=1844, marker=0):
    return b'KPBXFX01' + bytes([marker]) + bytes(width - 9)


class Framing(unittest.TestCase):
    def test_terminal_and_continuing_roundtrip(self):
        for width in (1796, 1844):
            projection, proof = untrusted_projection(width), bytes(128)
            frame = packet.encode(projection, proof)
            self.assertEqual(len(frame), 4096)
            self.assertEqual(packet.decode(frame), packet.CandidateBytes(projection, proof))

    def test_invalid_exact_frame(self):
        frame = packet.encode(untrusted_projection(), bytes(128))
        for changed in (frame[:-1], frame + b'\0', b'BADXNET1' + frame[8:],
                        frame[:8] + (1843).to_bytes(2, 'little') + frame[10:]):
            with self.assertRaises(packet.InvalidFrame):
                packet.decode(changed)

    def test_invalid_payload_width(self):
        for width in (0, 1795, 1797, 1843, 1845):
            with self.assertRaises(packet.InvalidFrame):
                packet.encode(bytes(width), bytes(128))
        with self.assertRaises(packet.InvalidFrame):
            packet.encode(untrusted_projection(), bytes(127))

    def test_namespace_only_onion_endpoint(self):
        valid = 'http://' + 'a' * 56 + '.onion/exit'
        self.assertEqual(transport.endpoint(valid), valid)
        for value in ('http://127.0.0.1/exit', valid + '?owner=0',
                      valid.replace('http:', 'https:'), valid.replace('/exit', '/owner-0'),
                      valid.replace('http://', 'http://owner@')):
            with self.assertRaises(ValueError):
                transport.endpoint(value)

    def test_first_memfd_closed_if_second_allocation_fails(self):
        fd = os.memfd_create('public-cleanup-control')
        with mock.patch.object(transport, 'sealed', side_effect=[fd, OSError('control')]):
            with self.assertRaises(OSError):
                transport.submit(packet.encode(untrusted_projection(), bytes(128)),
                    'http://' + 'a' * 56 + '.onion/exit', '127.0.0.1:9050', '/not-executed')
        with self.assertRaises(OSError):
            os.fstat(fd)


class ActualPublicSocket(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kpb-public-frame-', dir='/run/user/1000')
        self.path = Path(self.temporary.name) / 'observations'
        self.server = receiver.ObservedHTTPServer(('127.0.0.1', 0),
            receiver.Observer(self.path), 'common-endpoint')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def headers(self, headers=(), path='/exit'):
        return ('POST ' + path + ' HTTP/1.0\r\nHost: common-endpoint\r\n'
                   'User-Agent: kpb-exit-transport/1\r\nAccept: application/octet-stream\r\n' +
                   '\r\n'.join(headers) + '\r\n\r\n').encode()

    def request(self, headers, body, path='/exit'):
        request = self.headers(headers, path) + body
        with socket.create_connection(self.server.server_address) as stream:
            stream.sendall(request)
            stream.shutdown(socket.SHUT_WR)
            response = bytearray()
            while data := stream.recv(16384):
                response.extend(data)
        return bytes(response)

    def test_actual_arrival_record_and_fixed_ack(self):
        projections = [untrusted_projection(marker=9), untrusted_projection(marker=1)]
        for projection in projections:
            frame = packet.encode(projection, bytes(128))
            response = self.request(['Content-Length: 4096', 'Content-Type: application/octet-stream'], frame)
            self.assertTrue(response.startswith(b'HTTP/1.0 202'))
            self.assertEqual(response.split(b'\r\n\r\n', 1)[1], receiver.ACK)
        rows = [json.loads(p.read_bytes()) for p in sorted(self.path.glob('arrival-*'))]
        self.assertEqual([r['arrival_sequence'] for r in rows], [1, 2])
        self.assertEqual([r['exit_id'] for r in rows], [hashlib.sha256(p).hexdigest() for p in projections])
        self.assertTrue(all(r['financial_validation'] == 'NOT_RUN' and r['broadcast'] is False for r in rows))
        self.assertTrue(all('owner_component' not in r and r['peer'][0] == '127.0.0.1' for r in rows))

    def test_accept_order_survives_reverse_body_completion(self):
        frames = [packet.encode(untrusted_projection(marker=i), bytes(128)) for i in (3, 4)]
        with socket.create_connection(self.server.server_address) as slow:
            slow.settimeout(3)
            slow.sendall(self.headers(['Content-Length: 4096', 'Content-Type: application/octet-stream']))
            deadline = time.monotonic() + 3
            while self.server.observer.sequence != 1 and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(self.server.observer.sequence, 1)
            self.assertTrue(self.request(['Content-Length: 4096', 'Content-Type: application/octet-stream'],
                                        frames[1]).startswith(b'HTTP/1.0 202'))
            slow.sendall(frames[0])
            slow.shutdown(socket.SHUT_WR)
            while slow.recv(16384):
                pass
        rows = [json.loads(p.read_bytes()) for p in sorted(self.path.glob('arrival-*'))]
        self.assertEqual([r['arrival_sequence'] for r in rows], [1, 2])
        self.assertEqual([r['exit_id'] for r in rows],
            [hashlib.sha256(packet.decode(f).projection).hexdigest() for f in frames])
        self.assertLess(rows[0]['accepted_monotonic_ns'], rows[1]['accepted_monotonic_ns'])
        self.assertGreater(rows[0]['recorded_monotonic_ns'], rows[1]['recorded_monotonic_ns'])

    def test_ambiguous_lengths_and_owner_headers_refuse(self):
        frame = packet.encode(untrusted_projection(), bytes(128))
        variants = (
            ['Content-Length: 4096', 'Content-Length: 4096', 'Content-Type: application/octet-stream'],
            ['Content-Length: 4096', 'Transfer-Encoding: chunked', 'Content-Type: application/octet-stream'],
            ['Content-Length: 04096', 'Content-Type: application/octet-stream'],
            ['Content-Length: 4096', 'Content-Type: application/octet-stream', 'X-Owner: 0'],
            ['Content-Length: 4096', 'Content-Type: application/octet-stream', 'Host: other'],
            ['Content-Length: 4096', 'Content-Type: application/octet-stream', 'User-Agent: owner-0'],
            ['Content-Length: 4096', 'Content-Type: application/octet-stream', 'Accept: owner-0'],
            ['Content-Length: 4096', 'Content-Type: application/octet-stream',
             'Content-Type: application/octet-stream'],
        )
        for headers in variants:
            response = self.request(headers, frame)
            self.assertTrue(response.startswith(b'HTTP/1.0 400'))
            self.assertEqual(response.split(b'\r\n\r\n', 1)[1], receiver.ACK)
        rows = [json.loads(p.read_bytes()) for p in self.path.glob('arrival-*')]
        self.assertEqual(len(rows), len(variants))
        self.assertTrue(all(r['framing'] == 'REFUSED' and r['broadcast'] is False for r in rows))

    def test_noncanonical_singleton_and_other_parser_outcomes_retained(self):
        frame = packet.encode(untrusted_projection(), bytes(128))
        requests = [
            self.headers(['Content-Length: 4096', 'Content-Type: application/octet-stream']).replace(
                b'User-Agent: kpb-exit-transport/1', b'User-Agent: owner-0') + frame,
            self.headers(['Content-Length: 4096', 'Content-Type: application/octet-stream']).replace(
                b'Host: common-endpoint', b'Host: owner-0') + frame,
            b'GET /exit HTTP/1.0\r\nHost: common-endpoint\r\n\r\n',
            b'POST /exit HTTP/9.9\r\nHost: common-endpoint\r\n\r\n',
        ]
        for request in requests:
            with socket.create_connection(self.server.server_address) as stream:
                stream.sendall(request)
                stream.shutdown(socket.SHUT_WR)
                response = bytearray()
                while data := stream.recv(16384):
                    response.extend(data)
                self.assertNotIn(b'202 Accepted', response)
        rows = [json.loads(p.read_bytes()) for p in sorted(self.path.glob('arrival-*'))]
        self.assertEqual(len(rows), len(requests))
        self.assertEqual([r['http_status'] for r in rows], [400, 400, 501, 505])
        self.assertTrue(all(r['framing'] == 'REFUSED' for r in rows))


if __name__ == '__main__':
    unittest.main()
