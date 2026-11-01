#!/usr/bin/env python3
"""Compiled controls for the source-only registered driver bridge."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


class RegisteredDriverBridgeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-driver-bridge-controls-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            str(HERE / 'registered_driver_bridge_test.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL.parent.parent / 'private_batch_trial' /
                'privacy_capture_hook.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            '-I', str(FINANCIAL), '-lcrypto', '-pthread', '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_complete_authority_chain_binds_one_completion(self):
        result = subprocess.run(
            [str(self.binary), 'complete-authority-chain'],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_authority_mismatch_stale_head_and_replay_refuse(self):
        result = subprocess.run(
            [str(self.binary), 'authority-bypass-replay'],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_capture_projection_and_duplicate_completion_gate(self):
        result = subprocess.run(
            [str(self.binary), 'capture-completion-gate'],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_production_surface_has_no_runtime_configuration_or_authority_mint(self):
        result = subprocess.run(
            [str(self.binary), 'source-boundary'],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

        source = Path(self.temporary.name) / 'production-interface.cpp'
        source.write_text(r'''
#include "registered_driver_bridge.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver;
template<class T> concept RuntimeAdmit = requires(int argc, char** argv) {
    T::admit(argc, argv);
};
static_assert(!std::default_initializable<CompiledDriverSelection>);
static_assert(!std::constructible_from<CompiledDriverSelection,
                                       PublicDriverSelection>);
static_assert(!std::default_initializable<CompiledFreshAttemptAuthority>);
static_assert(!std::constructible_from<CompiledFreshAttemptAuthority,
                                       PublicCompiledFreshAttempt>);
static_assert(!std::default_initializable<AuthenticatedPartyDeliveryAuthority>);
static_assert(!std::constructible_from<AuthenticatedPartyDeliveryAuthority,
                                       PublicAuthenticatedPartyDelivery>);
static_assert(!std::default_initializable<CapturePlanAuthority>);
static_assert(!std::constructible_from<CapturePlanAuthority,
                                       PublicCapturePlan>);
static_assert(!std::default_initializable<PartyDriverCompletionAuthority>);
static_assert(!std::constructible_from<PartyDriverCompletionAuthority,
                                       PublicPartyDriverCompletion>);
static_assert(!std::copy_constructible<PartyDriverCompletionAuthority>);
static_assert(!std::constructible_from<VerifiedEgressAuthority,
                                       PublicVerifiedEgress>);
static_assert(!std::default_initializable<CompiledOuterSupervisorSelection>);
static_assert(!std::constructible_from<CompiledOuterSupervisorSelection,
                                       PublicOuterSupervisorSelection>);
static_assert(!std::default_initializable<OuterSupervisorAuthority>);
static_assert(!RuntimeAdmit<DriverAttempt>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-c', str(source), '-I', str(FINANCIAL),
            '-o', str(Path(self.temporary.name) / 'production-interface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

        # Regression for forward-declared friend forgery. These exact class
        # names used to acquire private authority construction/access merely
        # by being defined in an external translation unit.
        adversary = Path(self.temporary.name) / 'friend-forgery.cpp'
        adversary.write_text(r'''
#include "registered_driver_bridge.hpp"
#include <utility>
namespace kpi::mpc::financial {
class FinancialHistoryAccess {
public:
    static registered_driver::VerifiedEgressAuthority forge(
            registered_driver::PublicVerifiedEgress value) {
        return registered_driver::VerifiedEgressAuthority(std::move(value));
    }
};
class FinancialConstruction {
public:
    static const registered_driver::PublicDriverSelection& inspect(
            const registered_driver::DriverAttempt& value) {
        return value.selected_driver();
    }
};
}
namespace kpi::mpc::financial::registered_driver {
class RegisteredCaptureSession {
public:
    static CapturePlanAuthority forge(PublicCapturePlan value) {
        return CapturePlanAuthority(std::move(value));
    }
};
}
''', encoding='utf-8')
        forged = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-c', str(adversary), '-I', str(FINANCIAL),
            '-o', str(Path(self.temporary.name) / 'friend-forgery.o'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(forged.returncode, 0,
                            'forward-declared friends forged driver authority')
        self.assertIn('private', forged.stderr)


if __name__ == '__main__':
    unittest.main()
