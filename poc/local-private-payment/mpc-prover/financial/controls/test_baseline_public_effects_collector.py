#!/usr/bin/env python3

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


class BaselinePublicEffectsCollectorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-baseline-public-effects-')
        cls.binary = Path(cls.temporary.name) / 'baseline-public-effects'
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            str(HERE / 'baseline_public_effects_collector_test.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL.parent.parent / 'private_batch_trial' /
                'privacy_capture_hook.cpp'),
            '-I', str(FINANCIAL), '-pthread', '-lcrypto', '-o', str(cls.binary),
        ]
        compiled = subprocess.run(
            command, capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_mode(self, mode):
        result = subprocess.run(
            [str(self.binary), mode], capture_output=True, text=True,
            check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_exact_grouped_public_partition(self):
        self.run_mode('happy')

    def test_hidden_mixed_and_duplicate_disclosures_refuse(self):
        self.run_mode('mixed')

    def test_replay_and_plan_substitution_refuse(self):
        self.run_mode('replay')

    def test_production_surface_is_nonforgeable_and_unconfigured(self):
        self.run_mode('source')
        source = Path(self.temporary.name) / 'production-interface.cpp'
        source.write_text(r'''
#include "baseline_public_effects_collector.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;
template<class T, class V> concept HasTestMint = requires(V value) {
    T::test_only_mint(value);
};
static_assert(!std::default_initializable<BaselineEffectsPlanAuthority>);
static_assert(!std::constructible_from<BaselineEffectsPlanAuthority,
                                       PublicBaselineEffectsPlan>);
static_assert(!HasTestMint<BaselineEffectsPlanAuthority,
                           PublicBaselineEffectsPlan>);
static_assert(!std::default_initializable<
    VerifiedBaselinePublicEffectsAuthority>);
static_assert(!std::constructible_from<
    VerifiedBaselinePublicEffectsAuthority, PublicBaselineEffectsPlan>);
static_assert(!HasTestMint<VerifiedBaselinePublicEffectsAuthority,
                           PublicBaselineEffectsPlan>);
static_assert(!std::default_initializable<
    AuthenticatedOwnerEffectsDisclosureAuthority>);
static_assert(!std::constructible_from<
    AuthenticatedOwnerEffectsDisclosureAuthority,
    OwnerEffectsDisclosureInput>);
static_assert(!HasTestMint<AuthenticatedOwnerEffectsDisclosureAuthority,
                           OwnerEffectsDisclosureInput>);
static_assert(!std::constructible_from<
    ExplicitOwnerPublicEffectsAuthority, PublicExplicitOwnerEffects>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-c', str(source), '-I', str(FINANCIAL),
            '-o', str(Path(self.temporary.name) / 'production-interface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

        # Regression for the former undefined-friend hole: an external TU
        # may define these old names, but it must not gain constructor access.
        adversary = Path(self.temporary.name) / 'friend-forgery.cpp'
        adversary.write_text(r'''
#include "baseline_public_effects_collector.hpp"
#include <utility>
namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
class ParentVerifiedBaselineEffectsBridge {
public:
    static BaselineEffectsPlanAuthority forge(PublicBaselineEffectsPlan value) {
        return BaselineEffectsPlanAuthority(std::move(value));
    }
};
class AuthenticatedBaselineOwnerReceiver {
public:
    static AuthenticatedOwnerEffectsDisclosureAuthority forge(
            OwnerEffectsDisclosureInput value) {
        return AuthenticatedOwnerEffectsDisclosureAuthority(std::move(value));
    }
};
}
namespace kpi::mpc::financial {
class FinancialHistoryAccess {
public:
    static registered_driver::baseline_disclosure::
    VerifiedBaselinePublicEffectsAuthority forge(
            registered_driver::baseline_disclosure::
                PublicBaselineEffectsPlan value) {
        return registered_driver::baseline_disclosure::
            VerifiedBaselinePublicEffectsAuthority(std::move(value));
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
                            'undefined friend names forged private authority')
        self.assertIn('private', forged.stderr)


if __name__ == '__main__':
    unittest.main()
