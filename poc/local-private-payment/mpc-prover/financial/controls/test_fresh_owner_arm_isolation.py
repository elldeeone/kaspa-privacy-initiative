#!/usr/bin/env python3
"""Fail-closed controls for private baseline/candidate arm isolation."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class FreshOwnerArmIsolationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-fresh-owner-arm-isolation-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP',
            '-DKPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP',
            '-DKPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP',
            str(HERE / 'fresh_owner_arm_isolation_test.cpp'),
            str(FINANCIAL / 'fresh_owner_arm_isolation.cpp'),
            str(FINANCIAL / 'fresh_owner_process_adapter.cpp'),
            str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            '-I', str(FINANCIAL), '-I', str(MPC), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'),
            '-Wl,-rpath,' + str(VENDOR), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([str(self.binary), scenario],
                                capture_output=True, text=True,
                                timeout=30, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_exact_private_pair_yields_only_opaque_capability(self):
        self.run_scenario('happy')

    def test_both_inputs_burn_on_replay_or_alias(self):
        self.run_scenario('replay')

    def test_role_permutation_cannot_hide_logical_owner_collision(self):
        self.run_scenario('logical-owner')

    def test_process_root_pid_or_session_substitution_refuses(self):
        self.run_scenario('process-root-pid')

    def test_contract_and_all_tls_collision_classes_refuse(self):
        self.run_scenario('tls-contract')

    def test_wrong_arm_classification_refuses(self):
        self.run_scenario('classification')

    def test_source_status_keeps_pair_callsite_and_launch_closed(self):
        self.run_scenario('status')

    def test_production_surface_has_no_raw_or_receipt_factory(self):
        source = Path(self.temporary.name) / 'production-surface.cpp'
        source.write_text(r'''
#include "fresh_owner_arm_isolation.hpp"
#include <concepts>
#include <utility>
using namespace kpi::mpc::financial::fresh_owner_issuance;
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasIdentity = requires(const T& value) {
    value.identity();
};
template<class T> concept TestMintVisible = requires {
    T::test_only_mint(0);
};
template<class T> concept RawJoin = requires(T&& left, T&& right) {
    FreshOwnerArmIsolationBridge::join(
        std::forward<T>(left), std::forward<T>(right));
};
static_assert(!std::default_initializable<
              FreshOwnerPrivateArmLaunchAuthority>);
static_assert(!std::copy_constructible<
              FreshOwnerPrivateArmLaunchAuthority>);
static_assert(!std::default_initializable<
              FreshOwnerArmIsolationAuthority>);
static_assert(!std::copy_constructible<
              FreshOwnerArmIsolationAuthority>);
static_assert(!HasReceipt<FreshOwnerPrivateArmLaunchAuthority>);
static_assert(!HasReceipt<FreshOwnerArmIsolationAuthority>);
static_assert(!HasIdentity<FreshOwnerArmIsolationAuthority>);
static_assert(!TestMintVisible<FreshOwnerPrivateArmLaunchAuthority>);
static_assert(!RawJoin<int>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-c', str(source), '-I', str(FINANCIAL),
            '-I', str(MPC), '-I', str(VENDOR), '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            '-o', str(Path(self.temporary.name) / 'production-surface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

        hostile = Path(self.temporary.name) / 'hostile.cpp'
        hostile.write_text(r'''
#include "fresh_owner_arm_isolation.hpp"
namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerArmIsolationBridge final {};
}
''', encoding='utf-8')
        forged = subprocess.run([
            'g++', '-std=c++20', '-fsyntax-only', str(hostile),
            '-I', str(FINANCIAL), '-I', str(MPC), '-I', str(VENDOR),
            '-I', str(PREFIX), '-I', str(PREFIX / 'x86_64-linux-gnu'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(forged.returncode, 0)


if __name__ == '__main__':
    unittest.main()
