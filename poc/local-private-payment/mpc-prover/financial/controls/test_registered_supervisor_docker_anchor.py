#!/usr/bin/env python3
"""Real-container controls for Supervisor plus the Docker anchor adapter."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
sys.path.insert(0, str(FINANCIAL))

from docker_monotonic_anchor import DockerMonotonicAnchor  # noqa: E402


def digest(value):
    return f'{value:064x}'


class RegisteredSupervisorDockerAnchorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-supervisor-anchor-build-')
        cls.binary = Path(cls.temporary.name) / 'supervisor-anchor-control'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
            '-DKPI_DOCKER_ANCHOR_CLIENT_TEST_SETUP',
            str(HERE / 'registered_supervisor_docker_anchor_test.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            '-I', str(FINANCIAL), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(
            prefix='kpb-supervisor-anchor-real-')
        root = Path(temporary.name)
        os.chmod(root, 0o700)
        journal = root / 'journal'
        trusted = root / 'trusted'
        journal.mkdir(mode=0o700)
        trusted.mkdir(mode=0o700)
        pins = [digest(value) for value in range(1, 5)]
        initialized = subprocess.run([
            str(self.binary), 'initialize', str(journal), str(trusted), *pins,
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False)
        self.assertEqual(initialized.returncode, 0,
                         initialized.stdout + initialized.stderr)
        public = initialized.stdout.strip().split()
        self.assertEqual(len(public), 2)
        docker_root = root / 'docker-anchor'
        docker_root.mkdir(mode=0o700)
        anchor = DockerMonotonicAnchor.create_for_test(
            docker_root, public[0], public[1])
        anchor.start()
        return temporary, journal, trusted, pins, anchor

    def invoke(self, operation, journal, trusted, pins, anchor):
        status = anchor.status()
        return subprocess.run([
            str(self.binary), operation, str(journal), str(trusted), *pins,
            str(anchor.socket_path), status['configuration_identity'],
            status['instance_identity'],
        ], input=(anchor._capability() + '\n').encode('ascii'),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                 'LC_ALL': 'C.UTF-8'}, check=False)

    def test_supervisor_consumes_registry_and_anchor_once_across_restart(self):
        temporary, journal, trusted, pins, anchor = self.fixture()
        try:
            first = self.invoke('supervise', journal, trusted, pins, anchor)
            self.assertEqual(first.returncode, 0,
                             first.stdout + first.stderr)
            self.assertEqual(anchor.status()['sequence'], 1)

            self.assertTrue(anchor.shutdown_cleanly())
            anchor.start()
            replay = self.invoke('supervise', journal, trusted, pins, anchor)
            self.assertEqual(replay.returncode, 1)
            self.assertEqual(anchor.status()['sequence'], 1)
            self.assertTrue(anchor.shutdown_cleanly())
        finally:
            anchor.destroy_test_resources()
            temporary.cleanup()

    def test_ambiguous_external_cas_poison_is_not_reusable_after_restart(self):
        temporary, journal, trusted, pins, anchor = self.fixture()
        try:
            ambiguous = self.invoke(
                'ambiguous', journal, trusted, pins, anchor)
            self.assertEqual(ambiguous.returncode, 0,
                             ambiguous.stdout + ambiguous.stderr)
            self.assertEqual(anchor.status()['sequence'], 1)

            self.assertTrue(anchor.shutdown_cleanly())
            anchor.start()
            replay = self.invoke('supervise', journal, trusted, pins, anchor)
            self.assertEqual(replay.returncode, 1)
            self.assertEqual(anchor.status()['sequence'], 1)
            self.assertTrue(anchor.shutdown_cleanly())
        finally:
            anchor.destroy_test_resources()
            temporary.cleanup()


if __name__ == '__main__':
    unittest.main()
