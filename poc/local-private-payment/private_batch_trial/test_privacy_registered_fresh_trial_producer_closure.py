#!/usr/bin/env python3
"""Controls for the per-fresh-trial ten-stream producer closure."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent / 'mpc-prover' / 'financial'
MPC = FINANCIAL.parent
ROOT = HERE.parents[2]
VENDOR = ROOT / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class FreshTrialProducerClosureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-fresh-trial-producer-closure-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        command = [
            'g++', '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra',
            '-Werror', '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-pthread', '-ffunction-sections',
            '-fdata-sections', '-Wl,--gc-sections',
            '-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP',
            '-DKPB_CAPTURE_PRODUCER_RUNTIME_TEST_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP',
            '-DKPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP',
            '-DKPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP',
            str(HERE /
                'privacy_registered_fresh_trial_producer_closure_control.cpp'),
            str(HERE /
                'privacy_registered_fresh_trial_producer_closure.cpp'),
            str(HERE /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp'),
            str(HERE / 'privacy_capture_producer_runtime.cpp'),
            str(HERE / 'privacy_capture_producer_archive.cpp'),
            str(HERE / 'privacy_measurement_authority.cpp'),
            str(HERE / 'privacy_measurement_child_output_authority.cpp'),
            str(HERE / 'privacy_measurement_output_abi.cpp'),
            str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'registered_persistent_role_exit_history.cpp'),
            str(FINANCIAL / 'registered_trial_attempt_history.cpp'),
            str(FINANCIAL / 'registered_fresh_trial_history_ledger.cpp'),
            '-I', str(HERE), '-I', str(FINANCIAL), '-I', str(MPC),
            '-I', str(VENDOR), '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'),
            '-Wl,-rpath,' + str(VENDOR), '-lcrypto',
            '-o', str(cls.binary),
        ]
        compiled = subprocess.run(command, capture_output=True, text=True,
                                  check=False, timeout=180)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([str(self.binary), scenario],
                                capture_output=True, text=True,
                                check=False, timeout=30)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def compile_only(self, name, source):
        path = Path(self.temporary.name) / f'{name}.cpp'
        path.write_text(source, encoding='utf-8')
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-pthread', '-c', str(path),
            '-I', str(HERE), '-I', str(FINANCIAL), '-I', str(MPC),
            '-I', str(VENDOR), '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            '-o', str(Path(self.temporary.name) / f'{name}.o'),
        ], capture_output=True, text=True, check=False, timeout=60)

    def test_dedicated_fresh_trial_child_is_consumed_linearly(self):
        self.run_scenario('happy')

    def test_cross_trial_refusal_burns_both_authorities(self):
        self.run_scenario('cross-trial')

    def test_exact_ten_read_end_topology_changes_identity(self):
        self.run_scenario('topology')

    def test_source_bound_runtime_start_is_one_shot(self):
        self.run_scenario('start')

    def test_preidentity_runtime_uses_exact_same_ten_archive_inodes(self):
        self.run_scenario('reserved-start')

    def test_corrupt_archive_fingerprint_burns_same_ten_fds(self):
        self.run_scenario('reserved-corrupt')

    def test_source_status_remains_configured_zero(self):
        self.run_scenario('status')

    def test_production_surface_has_no_digest_fd_or_test_mint(self):
        compiled = self.compile_only('production-surface', r'''
#include "privacy_registered_fresh_trial_producer_closure.hpp"
#include <concepts>
#include <type_traits>
using namespace kpi::mpc::financial::registered_driver;
using kpi::mpc::financial::identity_registry::Digest;
template<class T> concept HasIdentity = requires(const T& value) {
    value.closure_identity();
};
template<class T> concept HasFd = requires(const T& value) { value.fd(); };
template<class T> concept HasTestMint = requires { T::test_only_mint(); };
template<class T> concept HasPreboundTestBind = requires(
    kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerProducerClosureAuthority&& fresh,
    kpb::measurement::producer_runtime::
        ParentTenReadEndsAuthority&& topology) {
    T::test_only_bind_prebound(
        static_cast<decltype(fresh)>(fresh),
        static_cast<decltype(topology)>(topology));
};
template<class T> concept HasReservedTestBind = requires(
    FreshTrialCaptureProducerTopologyResidual&& topology,
    kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerProducerClosureAuthority&& fresh,
    kpb::measurement::producer_runtime::PublicProducerLaunchPlan plan) {
    T::test_only_bind_reserved(
        static_cast<decltype(topology)>(topology),
        static_cast<decltype(fresh)>(fresh), plan);
};
static_assert(!std::default_initializable<
    RegisteredFreshTrialProducerClosureAuthority>);
static_assert(!std::copy_constructible<
    RegisteredFreshTrialProducerClosureAuthority>);
static_assert(!std::constructible_from<
    RegisteredFreshTrialProducerClosureAuthority, Digest>);
static_assert(!std::constructible_from<
    RegisteredFreshTrialProducerClosureAuthority, int>);
static_assert(!HasIdentity<RegisteredFreshTrialProducerClosureAuthority>);
static_assert(!HasFd<RegisteredFreshTrialProducerClosureAuthority>);
static_assert(!HasTestMint<RegisteredFreshTrialProducerClosureAuthority>);
static_assert(!HasPreboundTestBind<
    RegisteredFreshTrialProducerClosureBridge>);
static_assert(!HasReservedTestBind<
    RegisteredFreshTrialProducerClosureBridge>);
static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus.configured);
static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
    .selected_parent_callsite);
static_assert(!kRegisteredFreshTrialProducerClosureSourceStatus
    .production_topology_factory);
int main() { return 0; }
''')
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

    def test_complete_contract_blocks_exact_name_friend_forgery(self):
        attacks = {
            'fresh-owner': r'''
#include "fresh_owner_trial_issuance.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredFreshTrialProducerClosureBridge final {
public:
    static bool steal(fresh_owner_issuance::
                      FreshOwnerProducerClosureAuthority& value) {
        return value.live_.load();
    }
};
}
int main() { return 0; }
''',
            'ten-read-ends': r'''
#include "privacy_capture_producer_runtime.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredFreshTrialProducerClosureBridge final {
public:
    static auto steal(kpb::measurement::producer_runtime::
                      ParentTenReadEndsAuthority& value) {
        return value.plan_;
    }
};
}
int main() { return 0; }
''',
        }
        for name, source in attacks.items():
            with self.subTest(name=name):
                compiled = self.compile_only(name, source)
                self.assertNotEqual(
                    compiled.returncode, 0,
                    f'hostile exact-name bridge {name} compiled')
                self.assertIn('redefinition', compiled.stderr)

    def test_source_derivation_is_explicit_and_no_callsite_is_claimed(self):
        source = (HERE /
                  'privacy_registered_fresh_trial_producer_closure.cpp'
                  ).read_text(encoding='utf-8')
        header = (HERE /
                  'privacy_registered_fresh_trial_producer_closure.hpp'
                  ).read_text(encoding='utf-8')
        contract = (HERE /
                    'privacy_registered_fresh_trial_producer_closure_contract.hpp'
                    ).read_text(encoding='utf-8')
        for required in (
                'KPB_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_V1',
                'KPB_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_V2',
                'canonical_run_binding_bytes',
                'CORRUPT_SERVER_SOURCE_SLOTS{3, 8}',
                'CORRUPT_SERVER_FIXED_FDS{23, 28}',
                'opaque_closure_authority_identity = identity',
                'require_exact_topology'):
            self.assertIn(required, source)
        self.assertIn('.production_topology_factory = false', header)
        self.assertIn(
            '.dedicated_fresh_owner_closure_child_contract = true',
            header)
        self.assertIn(
            '.dedicated_fresh_owner_closure_child_consumed = false',
            header)
        production_bind = contract.split(
            'static RegisteredFreshTrialProducerClosureAuthority bind(',
            1)[1].split(
                '#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP',
                1)[0]
        self.assertIn('FreshOwnerProducerClosureAuthority&&',
                      production_bind)
        self.assertNotIn('FreshOwnerTrialIssuanceAuthority&&',
                         production_bind)
        self.assertIn('.preissuance_topology_reservation = false', header)
        self.assertIn(
            '.all_three_pidfds_bound_before_issuance = false', header)
        self.assertIn('.registered_build_closure = false', header)
        self.assertIn('.same_ten_archive_runtime_start = true', header)
        self.assertIn('.selected_parent_callsite = false', header)
        self.assertIn('.configured = false', header)
        self.assertIn('.launch_enabled = false', header)


if __name__ == '__main__':
    unittest.main()
