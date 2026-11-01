#!/usr/bin/env python3
"""Sealed common baseline/candidate owner-truth handoff controls."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
TRIAL = MPC.parent / 'private_batch_trial'
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class OwnerTruthScoreHandoffControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-owner-truth-score-handoff-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        command = [
            'g++', '-std=c++20', '-O1', '-g0', '-pthread',
            '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-Wno-missing-field-initializers', '-Wno-overloaded-virtual',
            '-Wno-psabi', '-march=native',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
            '-DKPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP',
            '-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP',
            '-DKPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP',
            '-DKPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP',
            str(HERE / 'owner_truth_score_handoff_test.cpp'),
            str(FINANCIAL / 'owner_truth_score_handoff.cpp'),
            str(FINANCIAL / 'baseline_owner_truth_capsule_bridge.cpp'),
            str(FINANCIAL / 'authenticated_baseline_owner_receiver.cpp'),
            str(FINANCIAL / 'fresh_owner_process_adapter.cpp'),
            str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(TRIAL / 'privacy_measurement_authority.cpp'),
            str(TRIAL / 'privacy_measurement_worker_capsule.cpp'),
            '-I', str(MPC), '-I', str(VENDOR), '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'),
            '-Wl,-rpath,' + str(VENDOR), '-lcrypto',
            '-o', str(cls.binary),
        ]
        compiled = subprocess.run(command, capture_output=True, text=True,
                                  check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_mode(self, mode):
        result = subprocess.run([self.binary, mode], capture_output=True,
                                text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_baseline_truth_joins_exact_post_barrier_permit(self):
        self.run_mode('baseline')

    def test_candidate_truth_joins_same_opaque_813_byte_endpoint(self):
        self.run_mode('candidate')

    def test_cross_arm_owner_barrier_and_capture_plan_substitution_refuse(self):
        self.run_mode('substitution')

    def test_endpoint_and_result_are_one_shot(self):
        self.run_mode('replay')

    def test_surface_has_no_fd_packet_body_or_body_hash_getter(self):
        self.run_mode('surface')
        header = (FINANCIAL / 'owner_truth_score_handoff.hpp').read_text(
            encoding='utf-8')
        for forbidden in ('int source_fd', 'span<', 'vector<',
                          'body_sha256', 'packet_sha256', 'json',
                          'bool success'):
            self.assertNotIn(forbidden, header)


if __name__ == '__main__':
    unittest.main()
