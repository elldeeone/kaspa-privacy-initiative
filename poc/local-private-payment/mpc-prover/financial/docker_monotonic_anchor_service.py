#!/usr/bin/env python3
"""Non-networked Docker anchor service for bounded local Testnet research.

The Docker operator remains able to replace or roll back the named volume. This
service separates anchor state from party namespaces; it is not a production
monotonic-security claim.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import stat
import struct
import threading


SCHEMA = 'kpb-docker-monotonic-anchor/v1'
PROTOCOL = 'KPBANCHOR1'
HEADER_SCHEMA = 'kpb-docker-monotonic-anchor-header/v1'
EVENT_SCHEMA = 'kpb-docker-monotonic-anchor-event/v1'
SOCKET_PATH = Path('/run/kpb-anchor/anchor.sock')
STATE_DIRECTORY = Path('/state')
STATE_PATH = STATE_DIRECTORY / 'anchor.log'
MAX_REQUEST = 16 * 1024
MAX_CONNECTIONS = 8
IDLE_FRAME_SECONDS = 30


class Refused(Exception):
    pass


def need(value):
    if not value:
        raise Refused()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True) + '\n').encode('ascii')


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def write_all(fd, raw):
    view = memoryview(raw)
    written = 0
    while written < len(view):
        count = os.write(fd, view[written:])
        need(count > 0)
        written += count


def hex32(value):
    need(isinstance(value, str) and len(value) == 64 and
         all(character in '0123456789abcdef' for character in value) and
         value != '0' * 64)
    return value


def natural(value):
    need(isinstance(value, int) and not isinstance(value, bool) and
         0 <= value < 2**64)
    return value


def exact(value, keys):
    need(isinstance(value, dict) and set(value) == set(keys))


def checked_directory(path, mode):
    information = os.lstat(path)
    need(stat.S_ISDIR(information.st_mode) and
         information.st_uid == os.geteuid() and
         stat.S_IMODE(information.st_mode) == mode)


def checked_state_fd(fd):
    information = os.fstat(fd)
    need(stat.S_ISREG(information.st_mode) and
         information.st_uid == os.geteuid() and
         information.st_nlink == 1 and
         stat.S_IMODE(information.st_mode) == 0o600)


class DurableState:
    def __init__(self):
        checked_directory(STATE_DIRECTORY, 0o700)
        self.authority = hex32(os.environ['KPB_ANCHOR_AUTHORITY'])
        self.initial_checkpoint = hex32(
            os.environ['KPB_ANCHOR_INITIAL_CHECKPOINT'])
        self.image_id = os.environ['KPB_ANCHOR_IMAGE_ID']
        need(self.image_id.startswith('sha256:') and
             len(self.image_id) == len('sha256:') + 64)
        self.source_sha256 = hex32(
            os.environ['KPB_ANCHOR_SOURCE_SHA256'])
        self.supervisor_uid = natural(int(
            os.environ['KPB_ANCHOR_SUPERVISOR_UID']))
        self.supervisor_capability_sha256 = hex32(
            os.environ['KPB_ANCHOR_SUPERVISOR_CAPABILITY_SHA256'])
        actual_source = sha256(Path(__file__).read_bytes())
        need(actual_source == self.source_sha256)
        config = {
            'schema': 'kpb-docker-monotonic-anchor-config/v1',
            'authority': self.authority,
            'initial_checkpoint': self.initial_checkpoint,
            'image_id': self.image_id,
            'source_sha256': self.source_sha256,
            'runtime_uid': os.geteuid(),
        }
        self.configuration_identity = sha256(canonical(config))
        self.sequence = 0
        self.checkpoint = self.initial_checkpoint
        self.transition_ids = set()
        self.record_sha256 = '0' * 64
        self.instance_identity = ''
        self.poisoned = False
        self._load_or_initialize()

    def _load_or_initialize(self):
        expected_instance = os.environ.get('KPB_ANCHOR_EXPECTED_INSTANCE', '')
        if not STATE_PATH.exists():
            need(not expected_instance)
            self.instance_identity = secrets.token_hex(32)
            header = {
                'schema': HEADER_SCHEMA,
                'configuration_identity': self.configuration_identity,
                'instance_identity': self.instance_identity,
                'authority': self.authority,
                'initial_checkpoint': self.initial_checkpoint,
                'image_id': self.image_id,
                'source_sha256': self.source_sha256,
                'runtime_uid': os.geteuid(),
            }
            header['record_sha256'] = sha256(canonical(header))
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                     getattr(os, 'O_NOFOLLOW', 0))
            fd = os.open(STATE_PATH, flags, 0o600)
            try:
                checked_state_fd(fd)
                write_all(fd, canonical(header))
                os.fsync(fd)
            finally:
                os.close(fd)
            directory_fd = os.open(STATE_DIRECTORY,
                                   os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.record_sha256 = header['record_sha256']
            return

        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(STATE_PATH, flags)
        try:
            checked_state_fd(fd)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                rows = stream.readlines()
        finally:
            os.close(fd)
        need(rows and len(rows) <= 1_000_000)
        parsed = []
        for raw in rows:
            need(len(raw) <= MAX_REQUEST and raw.endswith(b'\n'))
            parsed.append(json.loads(raw.decode('ascii')))
        header = parsed[0]
        exact(header, {'schema', 'configuration_identity', 'instance_identity',
                       'authority', 'initial_checkpoint', 'image_id',
                       'source_sha256', 'runtime_uid', 'record_sha256'})
        claimed = header.pop('record_sha256')
        need(claimed == sha256(canonical(header)))
        header['record_sha256'] = claimed
        need(header['schema'] == HEADER_SCHEMA and
             header['configuration_identity'] == self.configuration_identity and
             header['authority'] == self.authority and
             header['initial_checkpoint'] == self.initial_checkpoint and
             header['image_id'] == self.image_id and
             header['source_sha256'] == self.source_sha256 and
             header['runtime_uid'] == os.geteuid())
        self.instance_identity = hex32(header['instance_identity'])
        need(not expected_instance or expected_instance == self.instance_identity)
        self.record_sha256 = claimed
        for event in parsed[1:]:
            self._admit_loaded_event(event)

    def _admit_loaded_event(self, event):
        exact(event, {'schema', 'configuration_identity', 'instance_identity',
                      'sequence', 'previous_checkpoint', 'checkpoint',
                      'transition_identity', 'previous_record_sha256',
                      'record_sha256'})
        claimed = event.pop('record_sha256')
        need(claimed == sha256(canonical(event)))
        event['record_sha256'] = claimed
        sequence = natural(event['sequence'])
        transition = hex32(event['transition_identity'])
        need(event['schema'] == EVENT_SCHEMA and
             event['configuration_identity'] == self.configuration_identity and
             event['instance_identity'] == self.instance_identity and
             sequence == self.sequence + 1 and
             event['previous_checkpoint'] == self.checkpoint and
             hex32(event['checkpoint']) == event['checkpoint'] and
             event['previous_record_sha256'] == self.record_sha256 and
             transition not in self.transition_ids)
        self.sequence = sequence
        self.checkpoint = event['checkpoint']
        self.transition_ids.add(transition)
        self.record_sha256 = claimed

    def public(self):
        need(not self.poisoned)
        return {
            'schema': SCHEMA,
            'status': 'READY',
            'authority': self.authority,
            'configuration_identity': self.configuration_identity,
            'instance_identity': self.instance_identity,
            'sequence': self.sequence,
            'checkpoint': self.checkpoint,
            'record_sha256': self.record_sha256,
            'runtime_uid': os.geteuid(),
            'network_mode': 'none',
            'configured': False,
            'launch_authorized': False,
            'docker_operator_can_rollback': True,
        }

    def advance(self, request):
        need(not self.poisoned)
        exact(request, {'schema', 'operation', 'authority',
                        'configuration_identity', 'instance_identity',
                        'expected_sequence', 'expected_checkpoint',
                        'next_sequence', 'next_checkpoint',
                        'transition_identity'})
        expected_sequence = natural(request['expected_sequence'])
        next_sequence = natural(request['next_sequence'])
        transition = hex32(request['transition_identity'])
        next_checkpoint = hex32(request['next_checkpoint'])
        need(request['schema'] == SCHEMA and request['operation'] == 'advance' and
             request['authority'] == self.authority and
             request['configuration_identity'] == self.configuration_identity and
             request['instance_identity'] == self.instance_identity and
             expected_sequence == self.sequence and
             request['expected_checkpoint'] == self.checkpoint and
             next_sequence == self.sequence + 1 and
             transition not in self.transition_ids)
        event = {
            'schema': EVENT_SCHEMA,
            'configuration_identity': self.configuration_identity,
            'instance_identity': self.instance_identity,
            'sequence': next_sequence,
            'previous_checkpoint': self.checkpoint,
            'checkpoint': next_checkpoint,
            'transition_identity': transition,
            'previous_record_sha256': self.record_sha256,
        }
        event['record_sha256'] = sha256(canonical(event))
        flags = (os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC |
                 getattr(os, 'O_NOFOLLOW', 0))
        try:
            fd = os.open(STATE_PATH, flags)
            try:
                checked_state_fd(fd)
                write_all(fd, canonical(event))
                os.fsync(fd)
            finally:
                os.close(fd)
        except Exception:
            self.poisoned = True
            raise
        self.sequence = next_sequence
        self.checkpoint = next_checkpoint
        self.transition_ids.add(transition)
        self.record_sha256 = event['record_sha256']
        return self.public()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(IDLE_FRAME_SECONDS)
            credentials = self.request.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _, peer_uid, _ = struct.unpack('3i', credentials)
            need(peer_uid == self.server.state.supervisor_uid)
            raw = self.rfile.readline(MAX_REQUEST + 1)
            need(raw.endswith(b'\n') and len(raw) <= MAX_REQUEST)
            tokens = raw.decode('ascii').strip().split(' ')
            need(tokens and tokens[0] == PROTOCOL)
            need(len(tokens) >= 3 and len(tokens[2]) == 64 and
                 hmac.compare_digest(
                     sha256(tokens[2].encode('ascii')),
                     self.server.state.supervisor_capability_sha256))
            with self.server.state_lock:
                if len(tokens) == 3 and tokens[1] == 'STATUS':
                    result = self.server.state.public()
                elif len(tokens) == 11 and tokens[1] == 'ADVANCE':
                    request = {
                        'schema': SCHEMA,
                        'operation': 'advance',
                        'authority': tokens[3],
                        'configuration_identity': tokens[4],
                        'instance_identity': tokens[5],
                        'expected_sequence': int(tokens[6]),
                        'expected_checkpoint': tokens[7],
                        'next_sequence': int(tokens[8]),
                        'next_checkpoint': tokens[9],
                        'transition_identity': tokens[10],
                    }
                    result = self.server.state.advance(request)
                elif (len(tokens) == 4 and tokens[1] == 'SHUTDOWN' and
                      tokens[3] == self.server.state.instance_identity):
                    result = self.server.state.public()
                    result['status'] = 'SHUTTING_DOWN'
                    threading.Thread(target=self.server.shutdown,
                                     daemon=True).start()
                else:
                    raise Refused()
            response = ' '.join([
                PROTOCOL, 'OK', result['status'], result['authority'],
                result['configuration_identity'], result['instance_identity'],
                str(result['sequence']), result['checkpoint'],
                result['record_sha256'], str(result['runtime_uid']), 'NONE',
                '1' if result['configured'] else '0',
                '1' if result['launch_authorized'] else '0',
                '1' if result['docker_operator_can_rollback'] else '0',
            ]) + '\n'
        except Exception:
            response = f'{PROTOCOL} REFUSED\n'
        self.wfile.write(response.encode('ascii'))
        self.wfile.flush()


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, *arguments, **keywords):
        self.connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*arguments, **keywords)

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()


def main():
    need(os.geteuid() == 65532)
    checked_directory(SOCKET_PATH.parent, 0o750)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        information = os.lstat(SOCKET_PATH)
        need(stat.S_ISSOCK(information.st_mode) and
             information.st_uid == os.geteuid())
        os.unlink(SOCKET_PATH)
    state = DurableState()
    with Server(str(SOCKET_PATH), Handler) as server:
        server.state = state
        server.state_lock = threading.Lock()
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever(poll_interval=0.05)
    if SOCKET_PATH.exists():
        os.unlink(SOCKET_PATH)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(1)
