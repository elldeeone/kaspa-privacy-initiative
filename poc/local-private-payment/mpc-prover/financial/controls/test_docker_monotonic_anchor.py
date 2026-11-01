#!/usr/bin/env python3
"""Real rootful-Docker controls for the research monotonic-anchor boundary."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


FINANCIAL = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(FINANCIAL))

from docker_monotonic_anchor import (  # noqa: E402
    AnchorRefused,
    DOCKER,
    DockerMonotonicAnchor,
    PINNED_IMAGE_ID,
    source_status,
)
import docker_monotonic_anchor_service as service  # noqa: E402


def digest(value):
    return f'{value:064x}'


class DockerMonotonicAnchorControls(unittest.TestCase):
    def test_real_isolated_restart_replay_concurrency_and_replacement(self):
        with tempfile.TemporaryDirectory(prefix='kpb-docker-anchor-') as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            anchor = DockerMonotonicAnchor.create_for_test(
                root=root,
                authority=digest(1),
                initial_checkpoint=digest(2),
            )
            replacement_volume = None
            try:
                anchor.start()
                initial = anchor.status()
                self.assertEqual(initial['sequence'], 0)
                self.assertEqual(initial['checkpoint'], digest(2))
                self.assertEqual(initial['runtime_uid'], 65532)
                self.assertEqual(initial['network_mode'], 'none')
                self.assertFalse(initial['configured'])
                self.assertFalse(initial['launch_authorized'])
                self.assertEqual(
                    stat.S_IMODE(os.lstat(anchor.socket_directory).st_mode),
                    0o750)
                anchor.assert_runtime_isolation()
                anchor.assert_party_without_mounts_cannot_reach_anchor()
                anchor.assert_unauthorized_and_malformed_requests_refuse()
                anchor.assert_bounded_idle_connections(
                    service.IDLE_FRAME_SECONDS)

                first = anchor.advance(0, digest(2), 1, digest(3), digest(11))
                self.assertEqual(first['sequence'], 1)
                with self.assertRaises(AnchorRefused):
                    anchor.advance(0, digest(2), 1, digest(3), digest(11))
                with self.assertRaises(AnchorRefused):
                    anchor.advance(0, digest(2), 1, digest(4), digest(12))

                def race(value):
                    try:
                        return anchor.advance(1, digest(3), 2,
                                              digest(value), digest(value + 100))
                    except AnchorRefused:
                        return None

                with ThreadPoolExecutor(max_workers=2) as executor:
                    raced = list(executor.map(race, (21, 22)))
                self.assertEqual(sum(item is not None for item in raced), 1)
                after_race = anchor.status()
                self.assertEqual(after_race['sequence'], 2)
                stable_instance = after_race['instance_identity']

                self.assertTrue(anchor.shutdown_cleanly())
                anchor.start()
                restarted = anchor.status()
                self.assertEqual(restarted['sequence'], 2)
                self.assertEqual(restarted['checkpoint'],
                                 after_race['checkpoint'])
                self.assertEqual(restarted['instance_identity'], stable_instance)

                self.assertTrue(anchor.shutdown_cleanly())
                replacement_volume = anchor.create_empty_replacement_volume()
                with self.assertRaises(AnchorRefused):
                    anchor.start(volume_override=replacement_volume)
                anchor.start()
                self.assertEqual(anchor.status()['instance_identity'],
                                 stable_instance)
                self.assertTrue(anchor.shutdown_cleanly())
            finally:
                anchor.destroy_test_resources(replacement_volume)

    def test_source_boundary_remains_unconfigured(self):
        status = source_status()
        self.assertEqual(status['status'], 'BOUNDED_DOCKER_RESEARCH_ONLY')
        self.assertTrue(status['rootful_docker_operator_can_rollback'])
        self.assertTrue(status['party_no_mount_control_available'])
        self.assertFalse(status['selected_party_namespace_integration'])
        self.assertTrue(status['supervisor_capability_authenticated'])
        self.assertFalse(status['production_monotonic_security'])
        self.assertFalse(status['registered_driver_configured'])
        self.assertFalse(status['launch_authorized'])

    def test_client_authenticates_service_before_sending_capability(self):
        with tempfile.TemporaryDirectory(prefix='kpb-anchor-fake-peer-') as directory:
            socket_path = Path(directory) / 'fake.sock'
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(socket_path))
            os.chmod(socket_path, 0o660)
            server.listen(1)
            changed_owner = subprocess.run([
                DOCKER, 'run', '--rm', '--pull', 'never', '--network', 'none',
                '--read-only', '--user', '0:0', '--cap-drop', 'ALL',
                '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE',
                '--cap-add', 'FOWNER', '--security-opt',
                'no-new-privileges=true', '--pids-limit', '16', '--mount',
                f'type=bind,src={directory},dst=/attack', PINNED_IMAGE_ID,
                '/usr/local/bin/python3', '-I', '-c',
                ('import os; os.chown("/attack/fake.sock",65532,'
                 f'{os.getegid()})'),
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False)
            self.assertEqual(
                changed_owner.returncode, 0,
                (changed_owner.stdout + changed_owner.stderr).decode(
                    'utf-8', 'replace'))
            captured = []

            def serve():
                connection, _ = server.accept()
                with connection:
                    captured.append(connection.recv(8192))
                    if captured[-1]:
                        connection.sendall(b'KPBANCHOR1 REFUSED\n')

            thread = threading.Thread(target=serve)
            thread.start()
            fake_client = object.__new__(DockerMonotonicAnchor)
            fake_client.socket_path = socket_path
            try:
                with self.assertRaises(AnchorRefused):
                    fake_client._exchange_raw(
                        'KPBANCHOR1 STATUS ' + 'a' * 64)
            finally:
                thread.join(timeout=5)
                server.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(captured, [b''])

    def test_durable_write_all_handles_short_write_and_refuses_zero(self):
        with tempfile.TemporaryDirectory(prefix='kpb-anchor-short-write-') as directory:
            path = Path(directory) / 'row'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            raw = b'bounded durable anchor row\n'
            original_write = os.write

            def short_write(target_fd, remaining):
                count = max(1, len(remaining) // 2)
                return original_write(target_fd, remaining[:count])

            try:
                with mock.patch.object(service.os, 'write', short_write):
                    service.write_all(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            self.assertEqual(path.read_bytes(), raw)

            fd = os.open(path, os.O_WRONLY | os.O_APPEND)
            try:
                with mock.patch.object(service.os, 'write', return_value=0):
                    with self.assertRaises(service.Refused):
                        service.write_all(fd, b'x')
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
