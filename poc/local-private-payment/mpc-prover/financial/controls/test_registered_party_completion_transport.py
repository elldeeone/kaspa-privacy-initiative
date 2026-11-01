#!/usr/bin/env python3
"""Compiled controls for the single registered party terminal packet."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
TRIAL = FINANCIAL.parent.parent / 'private_batch_trial'


class RegisteredPartyCompletionTransportControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-party-completion-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        sources = [
            HERE / 'registered_party_completion_transport_test.cpp',
            FINANCIAL / 'registered_party_completion_transport.cpp',
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
            '-DKPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP',
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

    def test_hidden_uses_fixed_packet_with_zero_baseline_section(self):
        self.run_scenario('hidden')

    def test_baseline_joins_completion_and_private_effects_once(self):
        self.run_scenario('baseline')

    def test_cross_classification_refuses(self):
        self.run_scenario('wrong-class')

    def test_cross_run_refuses(self):
        self.run_scenario('wrong-run')

    def test_cross_trial_refuses(self):
        self.run_scenario('wrong-trial')

    def test_cross_attempt_refuses(self):
        self.run_scenario('wrong-attempt')

    def test_cross_cohort_refuses(self):
        self.run_scenario('wrong-cohort')

    def test_cross_authority_refuses(self):
        self.run_scenario('wrong-authority')

    def test_cross_driver_selection_refuses(self):
        self.run_scenario('wrong-driver')

    def test_cross_capture_source_refuses(self):
        self.run_scenario('wrong-source')

    def test_cross_build_refuses(self):
        self.run_scenario('wrong-build')

    def test_cross_capture_launcher_refuses(self):
        self.run_scenario('wrong-launcher')

    def test_cross_capture_plan_refuses(self):
        self.run_scenario('wrong-plan')

    def test_invalid_tag_is_not_canonicalized(self):
        self.run_scenario('invalid-tag')

    def test_duplicate_terminal_record_is_not_eof(self):
        self.run_scenario('duplicate-terminal')

    def test_baseline_cannot_omit_effects(self):
        self.run_scenario('missing-baseline')

    def test_hidden_cannot_smuggle_effects(self):
        self.run_scenario('hidden-baseline')

    def test_production_surface_has_no_raw_packet_or_public_constructor(self):
        header = (FINANCIAL /
                  'registered_party_completion_transport.hpp').read_text(
                      encoding='utf-8')
        self.assertIn('PACKET_BYTES = 2584', header)
        for forbidden in ('int fd', 'std::vector<unsigned char>', 'nlohmann',
                          'std::filesystem', 'from_fd', 'from_json'):
            self.assertNotIn(forbidden, header.lower())


if __name__ == '__main__':
    unittest.main()
