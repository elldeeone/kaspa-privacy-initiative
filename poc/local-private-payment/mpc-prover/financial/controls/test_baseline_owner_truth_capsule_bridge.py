#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
TRIAL = MPC.parent / 'private_batch_trial'


class BaselineOwnerTruthCapsuleBridgeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temp.name) / 'truth-capsule-control'
        compiler = os.environ.get('CXX', 'g++')
        command = [
            compiler, '-std=c++20', '-O1', '-g0', '-pthread',
            '-Wall', '-Wextra', '-Werror', '-Wno-missing-field-initializers',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            '-DKPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP',
            '-I', str(MPC),
            str(HERE / 'baseline_owner_truth_capsule_bridge_test.cpp'),
            str(FINANCIAL / 'authenticated_baseline_owner_receiver.cpp'),
            str(FINANCIAL / 'baseline_owner_truth_capsule_bridge.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(TRIAL / 'privacy_measurement_authority.cpp'),
            str(TRIAL / 'privacy_measurement_worker_capsule.cpp'),
            '-lcrypto', '-o', str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_mode(self, mode):
        result = subprocess.run([self.binary, mode], capture_output=True,
                                text=True, check=False, timeout=20)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def test_exact_ordered_lineage_and_reaped_feeder(self):
        self.run_mode('happy')

    def test_endpoint_identity_is_random_not_truth_digest(self):
        self.run_mode('random-identity')

    def test_truth_and_endpoint_are_one_shot(self):
        self.run_mode('replay')

    def test_production_surface_has_no_raw_truth_or_descriptor_arguments(self):
        self.run_mode('surface')
        header = (FINANCIAL /
                  'baseline_owner_truth_capsule_bridge.hpp').read_text(
                      encoding='utf-8')
        production = header[header.index(
            'class BaselineOwnerTruthCapsuleBridge final'):]
        production = production[:production.index('\n};')]
        self.assertIn('OwnerScoreTruthAuthority&&', production)
        for forbidden in ('Digest', 'span<', 'vector<', 'int source_fd',
                          'path', 'json', 'bool'):
            self.assertNotIn(forbidden, production)


if __name__ == '__main__':
    unittest.main()
