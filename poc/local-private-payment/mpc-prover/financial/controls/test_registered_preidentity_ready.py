#!/usr/bin/env python3
"""Controls for the causal pre-identity topology/process join."""

from pathlib import Path
import os
import subprocess
import tempfile
import textwrap
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
LOCAL_PAYMENT = MPC.parent
TRIAL = LOCAL_PAYMENT / 'private_batch_trial'
REPO = LOCAL_PAYMENT.parents[1]
VENDOR = REPO / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'
SANITIZE = os.environ.get('KPI_SANITIZE') == '1'


class RegisteredPreidentityReadyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-preidentity-ready-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        sanitizer_flags = (
            ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            if SANITIZE else [])
        cls.compile_prefix = [
            'g++', '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra',
            '-Werror', '-pedantic', '-Wno-overloaded-virtual',
            '-Wno-psabi', '-march=native', *sanitizer_flags,
            '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            '-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP',
            '-DKPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP',
        ]
        compiled = subprocess.run([
            *cls.compile_prefix,
            str(HERE / 'registered_preidentity_ready_test.cpp'),
            str(FINANCIAL / 'registered_preidentity_ready.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_parent_role_delivery_bridge.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_permit.cpp'),
            str(TRIAL / 'privacy_capture_hook.cpp'),
            '-I', str(MPC), '-I', str(TRIAL), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'),
            '-Wl,-rpath,' + str(VENDOR), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False, timeout=120)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario], capture_output=True, text=True,
            timeout=30, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_exact_join_is_move_only_and_resource_clean(self):
        self.run_scenario('exact')

    def test_invalid_topology_refusal_preserves_both_callers(self):
        self.run_scenario('invalid-topology')

    def test_invalid_process_refusal_preserves_both_callers(self):
        self.run_scenario('invalid-process')

    def test_owner_permits_and_ready_residual_are_one_shot(self):
        self.run_scenario('owner-permits')

    def test_wrong_process_epoch_refuses_without_claiming(self):
        self.run_scenario('wrong-epoch')

    def test_stale_process_permit_opens_no_topology_resources(self):
        self.run_scenario('stale-permit')

    def test_source_status_remains_unconfigured(self):
        self.run_scenario('status')

    def test_complete_bridge_cannot_be_hostile_redefined(self):
        hostile = Path(self.temporary.name) / 'hostile.cpp'
        hostile.write_text(textwrap.dedent('''
            #include "financial/registered_preidentity_ready.hpp"
            namespace kpi::mpc::financial::registered_driver {
            class RegisteredPreidentityReadyBridge final {
            public:
                static RegisteredPreidentityReadyAuthority steal();
            };
            }
            int main() { return 0; }
        '''))
        result = subprocess.run([
            *self.compile_prefix, '-fsyntax-only', str(hostile),
            '-I', str(MPC), '-I', str(TRIAL), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
        ], capture_output=True, text=True, check=False, timeout=30)
        self.assertNotEqual(result.returncode, 0,
                            result.stdout + result.stderr)
        self.assertIn('redefinition', result.stderr.lower())

    def test_authority_has_no_public_default_or_copy_factory(self):
        hostile = Path(self.temporary.name) / 'construct.cpp'
        hostile.write_text(textwrap.dedent('''
            #include "financial/registered_preidentity_ready.hpp"
            using namespace kpi::mpc::financial::registered_driver;
            int main() {
                RegisteredPreidentityReadyAuthority value;
                RegisteredPreidentityReadyAuthority copy(value);
                (void)copy;
            }
        '''))
        result = subprocess.run([
            *self.compile_prefix, '-fsyntax-only', str(hostile),
            '-I', str(MPC), '-I', str(TRIAL), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
        ], capture_output=True, text=True, check=False, timeout=30)
        self.assertNotEqual(result.returncode, 0,
                            result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
