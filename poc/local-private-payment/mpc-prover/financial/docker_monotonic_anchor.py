#!/usr/bin/env python3
"""Rootful-Docker anchor launcher for bounded local Testnet research.

This creates real UID/namespace separation from party containers. The rootful
Docker operator remains trusted and can replace or roll back volumes; this
module never authorizes CONFIGURED=1 or launch.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import time


PROTOCOL = 'KPBANCHOR1'
PINNED_IMAGE_ID = 'sha256:d10a08c52cb2bd14ca0d261c2aad3ab1984f2ce73e68f75f34c803013a5a0613'
DOCKER = '/usr/bin/docker'
SERVICE_UID = 65532
SERVICE_SOURCE = Path(__file__).with_name('docker_monotonic_anchor_service.py')
SAFE_NAME = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')


class AnchorRefused(RuntimeError):
    pass


def need(value, message='docker anchor refused'):
    if not value:
        raise AnchorRefused(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True) + '\n').encode('ascii')


def hex32(value):
    need(isinstance(value, str) and len(value) == 64 and
         all(character in '0123456789abcdef' for character in value) and
         value != '0' * 64)
    return value


def source_status():
    return {
        'schema': 'kpb-docker-monotonic-anchor-source-status/v1',
        'status': 'BOUNDED_DOCKER_RESEARCH_ONLY',
        'rootful_docker_operator_can_rollback': True,
        'party_no_mount_control_available': True,
        'selected_party_namespace_integration': False,
        'supervisor_capability_authenticated': True,
        'production_monotonic_security': False,
        'registered_driver_configured': False,
        'launch_authorized': False,
    }


class DockerMonotonicAnchor:
    def __init__(self, root, authority, initial_checkpoint, token):
        self.root = Path(root)
        self.authority = hex32(authority)
        self.initial_checkpoint = hex32(initial_checkpoint)
        need(SAFE_NAME.fullmatch(token))
        self.token = token
        self.container_name = f'kpb-anchor-{token}'
        self.volume_name = f'kpb-anchor-{token}'
        self.socket_directory = self.root / 'socket'
        self.socket_path = self.socket_directory / 'anchor.sock'
        self.snapshot_directory = self.root / 'snapshot'
        self.snapshot_source = self.snapshot_directory / 'service.py'
        self.instance_file = self.root / 'INSTANCE.json'
        self.capability_file = self.root / 'SUPERVISOR-CAPABILITY'
        self._volumes = {self.volume_name}
        self._validate_root()
        self._provision()

    @classmethod
    def create_for_test(cls, root, authority, initial_checkpoint):
        return cls(root, authority, initial_checkpoint,
                   f'test-{secrets.token_hex(8)}')

    def _validate_root(self):
        need(self.root.is_absolute() and self.root == self.root.resolve())
        information = os.lstat(self.root)
        need(stat.S_ISDIR(information.st_mode) and
             information.st_uid == os.geteuid() and
             stat.S_IMODE(information.st_mode) == 0o700)
        for current in (self.root, *self.root.parents):
            need(not stat.S_ISLNK(os.lstat(current).st_mode))
            if current == current.parent:
                break

    @staticmethod
    def _environment():
        return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8'}

    def _docker(self, arguments, check=True, timeout=30):
        result = subprocess.run(
            [DOCKER, *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self._environment(), timeout=timeout, check=False,
        )
        if check and result.returncode:
            raise AnchorRefused(
                (result.stdout + result.stderr).decode('utf-8', 'replace')[-4000:])
        return result

    def _provision(self):
        image = self._docker(['image', 'inspect', PINNED_IMAGE_ID,
                              '--format', '{{.Id}}']).stdout.decode().strip()
        need(image == PINNED_IMAGE_ID, 'pinned local image unavailable')
        self.snapshot_directory.mkdir(mode=0o700)
        self.socket_directory.mkdir(mode=0o700)
        shutil.copyfile(SERVICE_SOURCE, self.snapshot_source)
        os.chmod(self.snapshot_source, 0o440)
        self.source_sha256 = hashlib.sha256(
            self.snapshot_source.read_bytes()).hexdigest()
        self._create_supervisor_capability()
        self._create_volume(self.volume_name)
        try:
            self._prepare_volume(self.volume_name)
        except Exception:
            self._remove_volume(self.volume_name)
            raise

    def _create_volume(self, name):
        self._docker(['volume', 'create', '--label',
                      'kpb.anchor.test-resource=true', '--label',
                      f'kpb.anchor.instance={self.token}', name])
        raw = self._docker(['volume', 'inspect', name]).stdout
        value = json.loads(raw)[0]
        labels = value.get('Labels') or {}
        need(labels.get('kpb.anchor.test-resource') == 'true' and
             labels.get('kpb.anchor.instance') == self.token)

    def _remove_volume(self, name):
        inspected = self._docker(['volume', 'inspect', name], check=False)
        if inspected.returncode:
            return
        value = json.loads(inspected.stdout)[0]
        labels = value.get('Labels') or {}
        need(labels.get('kpb.anchor.test-resource') == 'true' and
             labels.get('kpb.anchor.instance') == self.token)
        self._docker(['volume', 'rm', name])

    def _create_supervisor_capability(self):
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                 getattr(os, 'O_NOFOLLOW', 0))
        fd = os.open(self.capability_file, flags, 0o600)
        try:
            self._write_all(fd, (secrets.token_hex(32) + '\n').encode('ascii'))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _capability(self):
        information = os.lstat(self.capability_file)
        need(stat.S_ISREG(information.st_mode) and
             information.st_uid == os.geteuid() and
             information.st_nlink == 1 and
             stat.S_IMODE(information.st_mode) == 0o600)
        raw = self.capability_file.read_text('ascii')
        need(raw.endswith('\n') and raw.count('\n') == 1)
        return hex32(raw[:-1])

    @staticmethod
    def _write_all(fd, raw):
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            need(count > 0)
            written += count

    def _prepare_volume(self, volume):
        group = os.getegid()
        script = (
            'import os\n'
            f'uid={SERVICE_UID}; gid={group}\n'
            'assert os.geteuid()==0\n'
            'os.chown("/state",uid,gid); os.chmod("/state",0o700)\n'
            'os.chown("/socket",uid,gid); os.chmod("/socket",0o750)\n'
        )
        self._docker([
            'run', '--rm', '--pull', 'never', '--network', 'none',
            '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN',
            '--cap-add', 'FOWNER',
            '--security-opt', 'no-new-privileges=true', '--pids-limit', '16',
            '--mount', f'type=volume,src={volume},dst=/state,volume-nocopy',
            '--mount', f'type=bind,src={self.socket_directory},dst=/socket',
            PINNED_IMAGE_ID, '/usr/local/bin/python3', '-I', '-c', script,
        ])
        information = os.lstat(self.socket_directory)
        need(information.st_uid == SERVICE_UID and
             information.st_gid == group and
             stat.S_IMODE(information.st_mode) == 0o750)

    def _expected_instance(self):
        if not self.instance_file.exists():
            return ''
        information = os.lstat(self.instance_file)
        need(stat.S_ISREG(information.st_mode) and
             information.st_uid == os.geteuid() and
             information.st_nlink == 1 and
             stat.S_IMODE(information.st_mode) == 0o600)
        value = json.loads(self.instance_file.read_text('ascii'))
        need(set(value) == {'schema', 'instance_identity'} and
             value['schema'] == 'kpb-docker-anchor-instance/v1')
        return hex32(value['instance_identity'])

    def _record_instance(self, identity):
        identity = hex32(identity)
        if self.instance_file.exists():
            need(self._expected_instance() == identity)
            return
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                 getattr(os, 'O_NOFOLLOW', 0))
        fd = os.open(self.instance_file, flags, 0o600)
        try:
            self._write_all(fd, canonical({
                'schema': 'kpb-docker-anchor-instance/v1',
                'instance_identity': identity,
            }))
            os.fsync(fd)
        finally:
            os.close(fd)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)

    def _remove_container(self):
        inspected = self._docker(
            ['container', 'inspect', self.container_name], check=False)
        if inspected.returncode:
            return
        value = json.loads(inspected.stdout)[0]
        labels = value.get('Config', {}).get('Labels') or {}
        need(labels.get('kpb.anchor.test-resource') == 'true' and
             labels.get('kpb.anchor.instance') == self.token)
        self._docker(['container', 'rm', '-f', self.container_name])

    def start(self, volume_override=None):
        self._remove_container()
        volume = volume_override or self.volume_name
        need(volume in self._volumes)
        expected_instance = self._expected_instance()
        command = [
            'run', '-d', '--pull', 'never', '--name', self.container_name,
            '--label', 'kpb.anchor.test-resource=true', '--label',
            f'kpb.anchor.instance={self.token}',
            '--hostname', 'kpb-anchor', '--network', 'none', '--read-only',
            '--user', f'{SERVICE_UID}:{os.getegid()}', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--pids-limit', '64',
            '--memory', '128m', '--cpus', '0.50', '--stop-timeout', '5',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777',
            '--mount', f'type=volume,src={volume},dst=/state,volume-nocopy',
            '--mount', (f'type=bind,src={self.socket_directory},'
                        'dst=/run/kpb-anchor'),
            '--mount', (f'type=bind,src={self.snapshot_source},'
                        'dst=/app/service.py,readonly'),
            '--env', f'KPB_ANCHOR_AUTHORITY={self.authority}',
            '--env', f'KPB_ANCHOR_INITIAL_CHECKPOINT={self.initial_checkpoint}',
            '--env', f'KPB_ANCHOR_IMAGE_ID={PINNED_IMAGE_ID}',
            '--env', f'KPB_ANCHOR_SOURCE_SHA256={self.source_sha256}',
            '--env', f'KPB_ANCHOR_SUPERVISOR_UID={os.geteuid()}',
            '--env', ('KPB_ANCHOR_SUPERVISOR_CAPABILITY_SHA256=' +
                      hashlib.sha256(self._capability().encode('ascii')).hexdigest()),
        ]
        if expected_instance:
            command.extend(['--env',
                            f'KPB_ANCHOR_EXPECTED_INSTANCE={expected_instance}'])
        command.extend([PINNED_IMAGE_ID, '/usr/local/bin/python3', '-B', '-I',
                        '/app/service.py'])
        self._docker(command)
        deadline = time.monotonic() + 10
        last_error = None
        while time.monotonic() < deadline:
            try:
                result = self.status()
                if expected_instance:
                    need(result['instance_identity'] == expected_instance)
                self._record_instance(result['instance_identity'])
                return result
            except (AnchorRefused, FileNotFoundError, ConnectionError,
                    OSError) as error:
                last_error = error
                inspection = self._docker(
                    ['inspect', self.container_name, '--format',
                     '{{.State.Running}} {{.State.ExitCode}}'], check=False)
                if inspection.returncode == 0:
                    state = inspection.stdout.decode().strip().split()
                    if state and state[0] == 'false':
                        break
                time.sleep(0.05)
        logs = self._docker(['logs', self.container_name], check=False)
        self._remove_container()
        diagnostics = (logs.stdout + logs.stderr).decode('utf-8', 'replace')[-2000:]
        raise AnchorRefused(f'anchor did not start: {last_error}; {diagnostics}')

    def _exchange_raw(self, line):
        need(isinstance(line, str) and '\n' not in line and len(line) <= 4096)
        try:
            information = os.lstat(self.socket_path)
            need(stat.S_ISSOCK(information.st_mode) and
                 information.st_uid == SERVICE_UID and
                 information.st_nlink == 1 and
                 stat.S_IMODE(information.st_mode) == 0o660,
                 'anchor service socket identity refused')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(str(self.socket_path))
                credentials = client.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED,
                    struct.calcsize('3i'))
                _, peer_uid, _ = struct.unpack('3i', credentials)
                need(peer_uid == SERVICE_UID,
                     'anchor service peer UID refused')
                client.sendall((line + '\n').encode('ascii'))
                raw = client.makefile('rb').readline(8193)
        except OSError as error:
            raise AnchorRefused(str(error)) from error
        need(raw.endswith(b'\n') and len(raw) <= 8192)
        return raw.decode('ascii').strip()

    def _request(self, line):
        tokens = self._exchange_raw(line).split(' ')
        need(tokens[:2] != [PROTOCOL, 'REFUSED'])
        need(len(tokens) == 14 and tokens[0:2] == [PROTOCOL, 'OK'])
        result = {
            'status': tokens[2], 'authority': hex32(tokens[3]),
            'configuration_identity': hex32(tokens[4]),
            'instance_identity': hex32(tokens[5]),
            'sequence': int(tokens[6]), 'checkpoint': hex32(tokens[7]),
            'record_sha256': hex32(tokens[8]), 'runtime_uid': int(tokens[9]),
            'network_mode': tokens[10].lower(),
            'configured': tokens[11] == '1',
            'launch_authorized': tokens[12] == '1',
            'docker_operator_can_rollback': tokens[13] == '1',
        }
        need(result['authority'] == self.authority and
             result['runtime_uid'] == SERVICE_UID and
             result['network_mode'] == 'none' and
             result['configured'] is False and
             result['launch_authorized'] is False and
             result['docker_operator_can_rollback'] is True)
        expected = self._expected_instance()
        if expected:
            need(result['instance_identity'] == expected)
        return result

    def status(self):
        return self._request(f'{PROTOCOL} STATUS {self._capability()}')

    def advance(self, expected_sequence, expected_checkpoint, next_sequence,
                next_checkpoint, transition_identity):
        current = self.status()
        fields = [PROTOCOL, 'ADVANCE', self._capability(), self.authority,
                  current['configuration_identity'], current['instance_identity'],
                  str(expected_sequence), hex32(expected_checkpoint),
                  str(next_sequence), hex32(next_checkpoint),
                  hex32(transition_identity)]
        return self._request(' '.join(fields))

    def shutdown_cleanly(self):
        current = self.status()
        result = self._request(
            f'{PROTOCOL} SHUTDOWN {self._capability()} '
            f'{current["instance_identity"]}')
        need(result['status'] == 'SHUTTING_DOWN')
        waited = self._docker(['wait', self.container_name], timeout=10)
        need(waited.stdout.decode().strip() == '0')
        self._docker(['rm', self.container_name])
        return True

    def assert_runtime_isolation(self):
        value = json.loads(self._docker(
            ['inspect', self.container_name]).stdout)[0]
        need(value['Image'] == PINNED_IMAGE_ID)
        need(value['Config']['User'] == f'{SERVICE_UID}:{os.getegid()}')
        host = value['HostConfig']
        need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and
             'ALL' in host['CapDrop'] and
             'no-new-privileges=true' in host['SecurityOpt'])
        mounts = value['Mounts']
        need(len(mounts) == 3)
        need({item['Destination'] for item in mounts} ==
             {'/state', '/run/kpb-anchor', '/app/service.py'})
        serialized = json.dumps(value, sort_keys=True)
        need('/var/run/docker.sock' not in serialized and
             '/run/docker.sock' not in serialized)
        return True

    def assert_party_without_mounts_cannot_reach_anchor(self):
        script = (
            'import os\nassert os.geteuid()==1000\n'
            'for path in ("/state","/run/kpb-anchor",'
            '"/var/run/docker.sock","/run/docker.sock"):\n'
            ' assert not os.path.exists(path), path\n'
        )
        result = self._docker([
            'run', '--rm', '--pull', 'never', '--network', 'none',
            '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--pids-limit', '16',
            PINNED_IMAGE_ID, '/usr/local/bin/python3', '-I', '-c', script,
        ], check=False)
        need(result.returncode == 0,
             (result.stdout + result.stderr).decode('utf-8', 'replace'))
        return True

    def assert_unauthorized_and_malformed_requests_refuse(self):
        before = self.status()
        wrong = 'f' * 64
        if wrong == self._capability():
            wrong = 'e' * 64
        attempts = [
            f'{PROTOCOL} STATUS {wrong}',
            (f'{PROTOCOL} ADVANCE {wrong} {self.authority} '
             f'{before["configuration_identity"]} {before["instance_identity"]} '
             f'{before["sequence"]} {before["checkpoint"]} '
             f'{before["sequence"] + 1} {"a" * 64} {"b" * 64}'),
            f'{PROTOCOL} SHUTDOWN {wrong} {before["instance_identity"]}',
            f'{PROTOCOL} ADVANCE',
            '{"operation":"status"}',
        ]
        for line in attempts:
            need(self._exchange_raw(line) == f'{PROTOCOL} REFUSED')
        after = self.status()
        need(after['sequence'] == before['sequence'] and
             after['checkpoint'] == before['checkpoint'])
        return True

    def assert_bounded_idle_connections(self, idle_frame_seconds=30):
        need(isinstance(idle_frame_seconds, int) and
             1 <= idle_frame_seconds <= 60)
        before = self.status()
        held = []
        after = None
        try:
            for _ in range(8):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(2)
                client.connect(str(self.socket_path))
                held.append(client)
            time.sleep(0.1)
            try:
                self.status()
            except AnchorRefused:
                pass
            else:
                raise AnchorRefused('unbounded anchor connection admission')
            deadline = time.monotonic() + idle_frame_seconds + 10
            while True:
                try:
                    after = self.status()
                    break
                except AnchorRefused:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
        finally:
            for client in held:
                client.close()
        need(after is not None)
        need(after['sequence'] == before['sequence'] and
             after['checkpoint'] == before['checkpoint'])
        return True

    def create_empty_replacement_volume(self):
        replacement = f'{self.volume_name}-replacement'
        need(SAFE_NAME.fullmatch(replacement))
        self._create_volume(replacement)
        self._volumes.add(replacement)
        self._prepare_volume(replacement)
        return replacement

    def _reclaim_test_socket_directory(self):
        information = os.lstat(self.socket_directory)
        need(stat.S_ISDIR(information.st_mode) and
             not stat.S_ISLNK(information.st_mode))
        script = (
            'import os,stat\n'
            'path="/socket/anchor.sock"\n'
            'try: info=os.lstat(path)\n'
            'except FileNotFoundError: pass\n'
            'else:\n'
            ' assert stat.S_ISSOCK(info.st_mode)\n'
            ' os.unlink(path)\n'
            f'os.chown("/socket",{os.geteuid()},{os.getegid()})\n'
            'os.chmod("/socket",0o700)\n'
        )
        self._docker([
            'run', '--rm', '--pull', 'never', '--network', 'none',
            '--read-only', '--user', '0:0', '--cap-drop', 'ALL',
            '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE',
            '--cap-add', 'FOWNER', '--security-opt',
            'no-new-privileges=true', '--pids-limit', '16',
            '--mount', (f'type=bind,src={self.socket_directory},'
                        'dst=/socket'),
            PINNED_IMAGE_ID, '/usr/local/bin/python3', '-I', '-c', script,
        ])
        information = os.lstat(self.socket_directory)
        need(information.st_uid == os.geteuid() and
             information.st_gid == os.getegid() and
             stat.S_IMODE(information.st_mode) == 0o700)

    def destroy_test_resources(self, replacement_volume=None):
        self._remove_container()
        self._reclaim_test_socket_directory()
        volumes = set(self._volumes)
        if replacement_volume:
            volumes.add(replacement_volume)
        for volume in sorted(volumes):
            if volume.startswith('kpb-anchor-test-'):
                self._remove_volume(volume)

