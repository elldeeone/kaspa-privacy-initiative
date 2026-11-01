#!/usr/bin/env python3
"""OS-derived, linear registered-trial attempt-history controls."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
PRIVATE_BATCH = MPC.parent / 'private_batch_trial'
VENDOR = ROOT / '.local' / 'mpc-prover-softspoken-vendor'
MP_SPDZ = VENDOR / 'MP-SPDZ'
PREFIX = VENDOR / 'prefix' / 'usr'
MCL = VENDOR / 'mcl'


def compile_flags():
    compiler = shutil.which('x86_64-linux-gnu-g++-15') or shutil.which('g++')
    if compiler is None:
        raise unittest.SkipTest('C++ compiler unavailable')
    result = [
        compiler, '-std=c++20', '-march=native', '-Wall', '-Wextra',
        '-Werror', '-Wno-overloaded-virtual', '-pedantic',
        '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
        '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
        '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
    ]
    for include in (MPC, MP_SPDZ, MP_SPDZ / 'deps',
                    MP_SPDZ / 'local' / 'include', PREFIX / 'include',
                    PREFIX / 'include' / 'x86_64-linux-gnu',
                    MCL / 'include'):
        result += ['-I', str(include)]
    return result


class RegisteredTrialAttemptHistoryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-attempt-history-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        command = [
            *compile_flags(), '-DKPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP',
            str(HERE / 'registered_trial_attempt_history_test.cpp'),
            str(FINANCIAL / 'registered_trial_attempt_history.cpp'),
            str(FINANCIAL /
                'registered_persistent_role_exit_history.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_party_completion_transport.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'registered_fresh_trial_history_ledger.cpp'),
            str(PRIVATE_BATCH /
                'privacy_capture_producer_runtime.cpp'),
            str(PRIVATE_BATCH /
                'privacy_capture_producer_archive.cpp'),
            str(PRIVATE_BATCH /
                'privacy_measurement_authority.cpp'),
            str(PRIVATE_BATCH /
                'privacy_measurement_child_output_authority.cpp'),
            str(PRIVATE_BATCH /
                'privacy_measurement_output_abi.cpp'),
            '-lcrypto', '-pthread', '-o', str(cls.binary),
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, check=False)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_every_attempt_is_os_observed_and_history_is_linear(self):
        result = subprocess.run(
            [str(self.binary)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_no_public_factory_or_forward_friend_forgery(self):
        source = Path(self.temporary.name) / 'hostile.cpp'
        source.write_text(r'''
#include "financial/registered_trial_attempt_history.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver::attempt_history;
static_assert(!std::default_initializable<RegisteredTrialAttemptHistoryAuthority>);
static_assert(!std::copy_constructible<RegisteredTrialAttemptHistoryAuthority>);
static_assert(std::move_constructible<RegisteredTrialAttemptHistoryAuthority>);
static_assert(!std::default_initializable<RegisteredTrialAttemptHistoryRecorder>);
static_assert(!std::default_initializable<RegisteredFreshTrialHistoryLedgerRecorder>);
static_assert(!std::default_initializable<RegisteredFreshTrialHistoryLedgerAuthority>);
template<class T> concept JsonFactory = requires(const char* value) {
    T::from_json(value);
};
template<class T> concept DigestFactory = requires(Digest value) {
    T::from_digest(value);
};
static_assert(!JsonFactory<RegisteredTrialAttemptHistoryAuthority>);
static_assert(!DigestFactory<RegisteredTrialAttemptHistoryAuthority>);
namespace kpi::mpc::financial::registered_driver::attempt_history {
class RegisteredTrialAttemptHistoryTerminalBridge final {};
class RegisteredFreshTrialHistoryLedgerBridge final {};
}
int main() { return 0; }
''', encoding='utf-8')
        result = subprocess.run(
            [*compile_flags(), '-fsyntax-only', str(source)],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0,
                            'exact-name terminal bridge redefinition compiled')

    def test_source_status_keeps_production_unselected(self):
        source = (FINANCIAL / 'registered_trial_attempt_history.hpp').read_text(
            encoding='utf-8')
        for needle in (
                '.os_derived_monotonic_and_wait = true',
                '.exact_sealed_c03_per_attempt = true',
                '.immutable_linear_failures = true',
                '.two_independent_round_chains = true',
                '.global_parent_sequence = true',
                '.unique_terminal_complete_attempt = true',
                '.producer_atomic_append_bridge = true',
                '.recorder_factory = false',
                '.failed_fresh_trial_authority = true',
                '.outer_fresh_trial_ledger = true',
                '.outer_fresh_trial_ledger_factory = false',
                '.fresh_attempt_authority_bridge = false',
                '.selected_parent_callsite = false',
                '.terminal_capture_consumer = false',
                '.configured = false'):
            self.assertIn(needle, source)


if __name__ == '__main__':
    unittest.main()
