"""Isolated public transport observer. NO validation, submit or broadcast API.

This receives untrusted bytes and preserves actual application observations.
Its records are not accepted-head, proof, owner or financial capabilities.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import packet

ACK = b'KPB_EXIT_TRANSPORT_RECEIVED_ONLY\n'.ljust(256, b' ')
CANONICAL_HEADERS = {'user-agent': 'kpb-exit-transport/1',
    'accept': 'application/octet-stream', 'content-type': 'application/octet-stream',
    'content-length': str(packet.FRAME_BYTES)}


class Observer:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.lock = threading.Lock()
        self.sequence = 0

    def reserve(self):
        with self.lock:
            self.sequence += 1
            return {'schema': 'kpb-exit-transport-arrival/v1',
                'scope': 'UNTRUSTED_PUBLIC_TRANSPORT_ONLY',
                'arrival_sequence': self.sequence,
                'accepted_monotonic_ns': time.monotonic_ns(),
                'accepted_unix_ns': time.time_ns(),
                'financial_validation': 'NOT_RUN', 'broadcast': False}

    def append(self, record):
        with self.lock:
            raw = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
            path = self.directory / ('arrival-%08d.json' % record['arrival_sequence'])
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(fd, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())


class ObservedHTTPServer(ThreadingHTTPServer):
    """Reserve order in the listening accept loop, before worker scheduling."""
    def __init__(self, address, observer, common_host):
        self.observer, self.common_host = observer, common_host
        self.pending, self.pending_lock = {}, threading.Lock()
        super().__init__(address, Handler)

    def get_request(self):
        stream, address = super().get_request()
        record = self.observer.reserve()
        record['peer'] = list(address)
        with self.pending_lock:
            self.pending[stream] = record
        return stream, address


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    server_version = 'KPB-transport-observer/1'
    sys_version = ''

    def log_message(self, *args):
        # The structured record below retains real headers, peer and timings.
        # No second diagnostic log can accidentally create an owner callback.
        pass

    def handle(self):
        with self.server.pending_lock:
            self.record = self.server.pending.pop(self.request)
        self.record['handler_monotonic_ns'] = time.monotonic_ns()
        self.record['framing'] = 'REFUSED'
        try:
            super().handle()
        finally:
            # Include malformed requests and unsupported methods, which do not
            # reach do_POST. Preserve raw parser-visible metadata as observed.
            self.record['request_line'] = getattr(self, 'requestline', '')
            self.record['headers'] = list(self.headers.raw_items()) if hasattr(self, 'headers') else []
            self.record['recorded_monotonic_ns'] = time.monotonic_ns()
            self.server.observer.append(self.record)

    def send_response_only(self, code, message=None):
        self.record['http_status'] = code
        super().send_response_only(code, message)

    def do_POST(self):
        record = self.record
        record['post_handler_monotonic_ns'] = time.monotonic_ns()
        record['path'] = self.path
        status = 400
        try:
            expected = dict(CANONICAL_HEADERS, host=self.server.common_host)
            headers = list(self.headers.raw_items())
            if (self.path != '/exit' or self.request_version != 'HTTP/1.0'
                or len(headers) != len(expected)
                or any(self.headers.get_all(name, []) != [value] for name, value in expected.items())):
                raise packet.InvalidFrame('HTTP shape')
            raw = self.rfile.read(packet.FRAME_BYTES)
            record['received_body_bytes'] = len(raw)
            record['frame_sha256'] = hashlib.sha256(raw).hexdigest()
            candidate = packet.decode(raw)
            record.update(framing='PASS', projection_hex=candidate.projection.hex(),
                          proof_hex128=candidate.proof.hex(),
                          exit_id=hashlib.sha256(candidate.projection).hexdigest())
            status = 202
        except packet.InvalidFrame:
            record['framing'] = 'REFUSED'
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(ACK)))
        self.end_headers()
        self.wfile.write(ACK)


def serve(port, directory, common_host):
    server = ObservedHTTPServer(('127.0.0.1', port), Observer(directory), common_host)
    # Only the public listening endpoint is emitted. No owner, candidate ID,
    # authorization status or transaction acceptance is returned to a caller.
    print(json.dumps({'schema': 'kpb-transport-observer-listener/v1',
                      'scope': 'NO_FINANCIAL_VALIDATION_OR_BROADCAST',
                      'listen': list(server.server_address)}), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--fresh-public-observations', required=True)
    parser.add_argument('--common-host', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    serve(args.port, args.fresh_public_observations, args.common_host)
