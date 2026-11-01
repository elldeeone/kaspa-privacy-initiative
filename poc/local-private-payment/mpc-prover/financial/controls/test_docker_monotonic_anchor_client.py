#!/usr/bin/env python3
"""Real-container controls for the parent-only C++ anchor adapter."""

from concurrent.futures import ThreadPoolExecutor
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


class DockerMonotonicAnchorClientControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-anchor-client-build-')
        cls.binary = Path(cls.temporary.name) / 'anchor-client-control'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_DOCKER_ANCHOR_CLIENT_TEST_SETUP',
            str(HERE / 'docker_monotonic_anchor_client_test.cpp'),
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

    def invoke(self, anchor, operation, *values):
        status = anchor.status()
        command = [
            str(self.binary), operation, str(anchor.socket_path),
            anchor.authority, status['configuration_identity'],
            status['instance_identity'], *[str(value) for value in values],
        ]
        return subprocess.run(
            command, input=(anchor._capability() + '\n').encode('ascii'),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                 'LC_ALL': 'C.UTF-8'}, check=False,
        )

    def test_real_service_status_advance_replay_race_and_restart(self):
        with tempfile.TemporaryDirectory(prefix='kpb-anchor-client-real-') as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            anchor = DockerMonotonicAnchor.create_for_test(
                root, digest(1), digest(2))
            try:
                anchor.start()
                result = self.invoke(anchor, 'status', 0, digest(2))
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                result = self.invoke(
                    anchor, 'advance', 0, digest(2), 1, digest(3))
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertEqual(anchor.status()['sequence'], 1)

                replay = self.invoke(
                    anchor, 'advance', 0, digest(2), 1, digest(3))
                self.assertEqual(replay.returncode, 1)

                def race(value):
                    return self.invoke(
                        anchor, 'advance', 1, digest(3), 2, digest(value))

                with ThreadPoolExecutor(max_workers=2) as executor:
                    raced = list(executor.map(race, (4, 5)))
                self.assertEqual(sum(item.returncode == 0 for item in raced), 1)
                after = anchor.status()
                self.assertEqual(after['sequence'], 2)
                self.assertTrue(anchor.shutdown_cleanly())
                anchor.start()
                restarted = self.invoke(
                    anchor, 'status', 2, after['checkpoint'])
                self.assertEqual(restarted.returncode, 0,
                                 restarted.stdout + restarted.stderr)

                wrong_instance = subprocess.run([
                    str(self.binary), 'status', str(anchor.socket_path),
                    anchor.authority, after['configuration_identity'],
                    digest(99), '2', after['checkpoint'],
                ], input=(anchor._capability() + '\n').encode('ascii'),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False)
                self.assertEqual(wrong_instance.returncode, 1)
                self.assertTrue(anchor.shutdown_cleanly())
            finally:
                anchor.destroy_test_resources()

    def test_registered_proposal_bridge_cannot_forge_client_capability(self):
        source = Path(self.temporary.name) / 'hostile-anchor-bridge.cpp'
        source.write_text(r'''
#include "docker_monotonic_anchor_client.hpp"
#include <utility>
namespace kpi::mpc::financial::attempt_supervisor {
class RegisteredProposalBridge final {
public:
    static docker_anchor::SupervisorCapability capability() {
        return docker_anchor::SupervisorCapability({});
    }
    static docker_anchor::Client client(
            docker_anchor::PublicConfiguration value,
            docker_anchor::SupervisorCapability&& capability) {
        return docker_anchor::Client(
            std::move(value), std::move(capability));
    }
};
}
''', encoding='utf-8')
        result = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-fsyntax-only', str(source), '-I', str(FINANCIAL),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('redefinition', result.stderr)


if __name__ == '__main__':
    unittest.main()
