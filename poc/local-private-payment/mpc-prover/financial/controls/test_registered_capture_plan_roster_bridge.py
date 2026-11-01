#!/usr/bin/env python3
"""Typed raw-trial UUID to registered capture-plan controls."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
VENDOR = ROOT / '.local' / 'mpc-prover-softspoken-vendor'
MP_SPDZ = VENDOR / 'MP-SPDZ'
PREFIX = VENDOR / 'prefix' / 'usr'
MCL = VENDOR / 'mcl'
TRIAL = FINANCIAL.parent.parent / 'private_batch_trial'


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


class RegisteredCapturePlanRosterBridgeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-capture-plan-roster-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        sources = [
            HERE / 'registered_capture_plan_roster_bridge_test.cpp',
            FINANCIAL / 'registered_capture_plan_roster_bridge.cpp',
            FINANCIAL / 'registered_roster_crypto_player.cpp',
            FINANCIAL / 'registered_driver_bridge.cpp',
            FINANCIAL / 'registered_capture_session.cpp',
            FINANCIAL / 'baseline_public_effects_collector.cpp',
            FINANCIAL / 'registered_attempt_supervisor.cpp',
            FINANCIAL / 'registered_identity_registry.cpp',
            FINANCIAL / 'docker_monotonic_anchor_client.cpp',
            TRIAL / 'privacy_capture_hook.cpp',
            MPC / 'history' / 'epoch_journal.cpp',
        ]
        command = [
            *compile_flags(),
            '-DKPI_REGISTERED_ROSTER_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            *map(str, sources),
            '-L', str(MP_SPDZ), '-Wl,-rpath,' + str(MP_SPDZ),
            '-L', str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-Wl,-rpath,' + str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-L', str(MCL / 'lib'), '-lSPDZ', '-lmcl', '-lssl', '-lcrypto',
            '-lgmpxx', '-lgmp', '-pthread', '-o', str(cls.binary),
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, check=False)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_live_roster_authority_binds_raw_trial_uuid_once(self):
        result = subprocess.run(
            [str(self.binary)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_complete_friend_and_no_caller_string_authority_factory(self):
        source = Path(self.temporary.name) / 'hostile.cpp'
        source.write_text(r'''
#include "financial/registered_capture_plan_roster_bridge.hpp"
#include <concepts>
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
template<class T> concept StringFactory = requires(std::string value) {
    T::from_trial_id(value);
};
static_assert(!std::default_initializable<CapturePlanAuthority>);
static_assert(!std::constructible_from<CapturePlanAuthority,
                                       PublicCapturePlan>);
static_assert(!StringFactory<CapturePlanAuthority>);
namespace kpi::mpc::financial::registered_driver {
class RegisteredCapturePlanRosterBridge final {};
}
int main() { return 0; }
''', encoding='utf-8')
        result = subprocess.run(
            [*compile_flags(), '-fsyntax-only', str(source)],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0,
                            'exact-name bridge redefinition compiled')


if __name__ == '__main__':
    unittest.main()
