#!/usr/bin/env python3
"""Runtime controls for the private role-to-parent baseline handoff."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
TRIAL = FINANCIAL.parent.parent / 'private_batch_trial'


class BaselineOwnerScoringParentTransportControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-baseline-owner-parent-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        sources = [
            HERE / 'baseline_owner_scoring_parent_transport_test.cpp',
            FINANCIAL / 'baseline_owner_scoring_parent_transport.cpp',
            FINANCIAL / 'authenticated_baseline_owner_receiver.cpp',
            FINANCIAL / 'registered_parent_role_fork.cpp',
            FINANCIAL / 'registered_projection_route.cpp',
            FINANCIAL / 'registered_parent_role_delivery_bridge.cpp',
            FINANCIAL / 'registered_driver_bridge.cpp',
            FINANCIAL / 'registered_capture_session.cpp',
            FINANCIAL / 'baseline_public_effects_collector.cpp',
            FINANCIAL / 'registered_attempt_supervisor.cpp',
            FINANCIAL / 'registered_identity_registry.cpp',
            FINANCIAL / 'docker_monotonic_anchor_client.cpp',
            TRIAL / 'privacy_capture_hook.cpp',
        ]
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            *map(str, sources), '-I', str(FINANCIAL), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario], capture_output=True, text=True,
            timeout=20, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_exact_three_roles_two_rounds_reach_private_owner_authorities(self):
        self.run_scenario('happy')

    def test_child_endpoint_and_party_authority_replay_refuse(self):
        self.run_scenario('replay')

    def test_round_mixup_refuses_and_poisons_parent_handoff(self):
        self.run_scenario('wrong-round')

    def test_duplicate_round_refuses_and_poisons_parent_handoff(self):
        self.run_scenario('duplicate-round')

    def test_packet_is_fixed_and_no_raw_transport_surface_exists(self):
        header = (FINANCIAL /
                  'baseline_owner_scoring_parent_transport.hpp').read_text(
                      encoding='utf-8')
        self.assertIn('PACKET_BYTES = 1524', header)
        for forbidden in ('int fd', 'std::vector<unsigned char>',
                          'nlohmann', 'std::filesystem', 'from_fd'):
            self.assertNotIn(forbidden, header.lower())


if __name__ == '__main__':
    unittest.main()
