#!/usr/bin/env python3

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


class AuthenticatedBaselineOwnerReceiverControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-baseline-owner-receiver-')
        cls.binary = Path(cls.temporary.name) / 'receiver-controls'
        result = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            str(HERE / 'authenticated_baseline_owner_receiver_test.cpp'),
            str(FINANCIAL / 'authenticated_baseline_owner_receiver.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            '-I', str(FINANCIAL), '-pthread', '-lcrypto',
            '-o', str(cls.binary),
        ], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_mode(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_exact_six_party_two_round_join_routes_three_private_owner_inputs(self):
        self.run_mode('happy')

    def test_replay_role_round_mapping_nonce_and_session_mixups_refuse(self):
        self.run_mode('mutations')
        self.run_mode('race')

    def test_fixed_challenge_ack_replay_and_projection_mixup_refuse(self):
        self.run_mode('protocol')

    def test_observer_leaf_is_baseline_only_one_shot_and_lineage_bound(self):
        self.run_mode('observer')

    def test_hidden_candidate_has_no_receiver_or_scoring_factory(self):
        self.run_mode('hidden')

    def test_production_surface_has_no_payload_digest_or_json_mint(self):
        self.run_mode('surface')


if __name__ == '__main__':
    unittest.main()
