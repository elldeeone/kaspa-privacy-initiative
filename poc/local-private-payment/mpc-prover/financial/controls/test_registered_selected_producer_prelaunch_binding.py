#!/usr/bin/env python3
"""Chronology and authority-surface controls for producer prelaunch binding."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
TRIAL = MPC.parent / 'private_batch_trial'


def compile_command(source):
    return [
        'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
        '-I', str(MPC), '-I', str(FINANCIAL), '-I', str(TRIAL),
        '-fsyntax-only', str(source),
    ]


class RegisteredSelectedProducerPrelaunchBindingControls(unittest.TestCase):
    def test_production_translation_unit_is_strict_compile_clean(self):
        result = subprocess.run(
            compile_command(
                FINANCIAL / 'registered_selected_producer_run_binding.cpp'),
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_surface_has_no_caller_or_postrun_minter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-selected-producer-prelaunch-') as directory:
            source = Path(directory) / 'surface.cpp'
            source.write_text(r'''
#include "financial/registered_selected_producer_run_binding.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver;
static_assert(!std::default_initializable<
    RegisteredSelectedProducerPrelaunchInputAuthority>);
static_assert(!std::default_initializable<
    RegisteredSelectedProducerPrelaunchBindingAuthority>);
static_assert(!std::copy_constructible<
    RegisteredSelectedProducerPrelaunchBindingAuthority>);
static_assert(std::move_constructible<
    RegisteredSelectedProducerPrelaunchBindingAuthority>);
static_assert(!std::constructible_from<
    RegisteredSelectedProducerPrelaunchBindingAuthority,
    RegisteredSelectedProducerPrelaunchPlan,
    kpi::mpc::financial::identity_registry::Digest>);
static_assert(!std::default_initializable<
    RegisteredSelectedProducerPostrunResidualAuthority>);
static_assert(!std::default_initializable<
    RegisteredSelectedProducerRunBindingAuthority>);
int main() { return 0; }
''', encoding='utf-8')
            result = subprocess.run(
                compile_command(source), capture_output=True, text=True,
                check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)

    def test_selected_activation_surface_is_opaque_and_conjunctive(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-selected-producer-activation-') as directory:
            source = Path(directory) / 'surface.cpp'
            source.write_text(r'''
#include "financial/registered_selected_parent_orchestrator.hpp"
#include "financial/registered_selected_producer_activation_contract.hpp"
#include "privacy_owner_score_lineage_source_authority.hpp"
#include "privacy_prelaunch_policy_domain_authority.hpp"
#include <concepts>
#include <type_traits>
using namespace kpi::mpc::financial::registered_driver;
using Activation = kpi::mpc::financial::fresh_owner_issuance::
    FreshOwnerPersistentActivationAuthority;
using Policy = kpb::measurement::prelaunch_policy_domain::
    RegisteredPrelaunchPolicyDomainAuthority;
using Source = kpb::measurement::score_output_lineage_source::
    SelectedOwnerScoreLineagePrelaunchSourceAuthority;
using Result = RegisteredSelectedProducerActivationResult;
using Signature = Result (*)(Activation&&, Policy&&, Source&&);
static_assert(std::same_as<
    decltype(&RegisteredSelectedParentOrchestrator::
        activate_selected_prelaunch), Signature>);
static_assert(!std::default_initializable<Source>);
static_assert(!std::copy_constructible<Source>);
static_assert(std::move_constructible<Source>);
static_assert(!std::default_initializable<
    RegisteredSelectedProducerActivationAuthority>);
static_assert(!std::copy_constructible<
    RegisteredSelectedProducerActivationAuthority>);
static_assert(std::move_constructible<
    RegisteredSelectedProducerActivationAuthority>);
template<class T> concept HasPlan = requires(T& value) { value.plan(); };
template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasDigest = requires(T& value) { value.digest(); };
template<class T> concept HasBytes = requires(T& value) { value.bytes(); };
static_assert(!HasPlan<Source> && !HasFd<Source> && !HasDigest<Source> &&
              !HasBytes<Source>);
static_assert(!HasPlan<RegisteredSelectedProducerActivationAuthority> &&
              !HasFd<RegisteredSelectedProducerActivationAuthority> &&
              !HasDigest<RegisteredSelectedProducerActivationAuthority> &&
              !HasBytes<RegisteredSelectedProducerActivationAuthority>);
int main() { return 0; }
''', encoding='utf-8')
            result = subprocess.run(
                compile_command(source), capture_output=True, text=True,
                check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)

    def test_prelaunch_source_requires_two_unique_sealed_read_only_files(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-selected-prelaunch-source-') as directory:
            root = Path(directory)
            source = root / 'source.cpp'
            source.write_text(r'''
#include "financial/registered_selected_producer_run_binding.hpp"
#include "privacy_owner_score_lineage_source_authority.hpp"
#include <array>
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <openssl/sha.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
using namespace kpi::mpc::financial::registered_driver;
using namespace kpb::measurement::score_output_lineage_source;
using Digest = kpi::mpc::financial::identity_registry::Digest;
Digest digest(const std::string& value) {
    Digest result{};
    assert(SHA256(reinterpret_cast<const unsigned char*>(value.data()),
                  value.size(), result.data()) != nullptr);
    return result;
}
int sealed(const std::string& value, bool executable, bool seal = true) {
    int writer = ::memfd_create("kpb-selected-source",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writer >= 0 && ::write(writer, value.data(), value.size()) ==
           static_cast<ssize_t>(value.size()));
    assert(::fchmod(writer, executable ? 0500 : 0400) == 0);
    if (seal) assert(::fcntl(writer, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
    const auto path = std::string("/proc/self/fd/") +
        std::to_string(writer);
    const int reader = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    assert(reader >= 0);
    ::close(writer);
    return reader;
}
int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string mode(argv[1]);
    RegisteredSelectedProducerPrelaunchPlan plan;
    plan.comparison_selection = digest("selection");
    int selection = sealed("selection", false, mode != "unsealed");
    int worker = mode == "duplicate" ? ::fcntl(selection, F_DUPFD_CLOEXEC, 64)
                                      : sealed("worker", true);
    assert(worker >= 0);
    if (mode == "wrong-hash") plan.comparison_selection[0] ^= 0x80;
    if (mode == "writable") {
        ::close(selection);
        selection = ::memfd_create("kpb-writable-source", MFD_CLOEXEC);
        assert(selection >= 0 && ::write(selection, "selection", 9) == 9);
    }
    bool refused = false;
    try {
        auto authority =
            SelectedOwnerScoreLineagePrelaunchSourceTestBridge::mint(
                std::move(plan), selection, worker);
        (void)authority;
    } catch (...) { refused = true; }
    assert(refused == (mode != "valid"));
}
''', encoding='utf-8')
            binary = root / 'source'
            command = [
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-DKPB_SELECTED_PRODUCER_ACTIVATION_TEST_SETUP',
                '-I', str(MPC), '-I', str(FINANCIAL), '-I', str(TRIAL),
                str(source),
                str(TRIAL /
                    'privacy_owner_score_lineage_prelaunch_source.cpp'),
                '-lcrypto', '-o', str(binary),
            ]
            built = subprocess.run(command, capture_output=True, text=True,
                                   check=False)
            self.assertEqual(built.returncode, 0,
                             built.stdout + built.stderr)
            for mode in ('valid', 'wrong-hash', 'writable', 'unsealed',
                         'duplicate'):
                with self.subTest(mode=mode):
                    run = subprocess.run([str(binary), mode],
                                         capture_output=True, text=True,
                                         check=False)
                    self.assertEqual(run.returncode, 0,
                                     run.stdout + run.stderr)

    def test_complete_bridge_names_cannot_be_hostile_redefined(self):
        attacks = (
            'RegisteredPersistentFreshTrialActivationBridge',
            'RegisteredFreshTrialProducerClosureBridge',
        )
        with tempfile.TemporaryDirectory(
                prefix='kpb-selected-prelaunch-friends-') as directory:
            for index, name in enumerate(attacks):
                source = Path(directory) / f'hostile-{index}.cpp'
                source.write_text(f'''
#include "financial/registered_selected_producer_run_binding.hpp"
namespace kpi::mpc::financial::registered_driver {{
class {name} final {{}};
}}
int main() {{ return 0; }}
''', encoding='utf-8')
                result = subprocess.run(
                    compile_command(source), capture_output=True, text=True,
                    check=False)
                self.assertNotEqual(
                    result.returncode, 0,
                    f'hostile exact-name {name} redefinition compiled')

    def test_postrun_facts_and_selection_remain_disabled(self):
        header = (FINANCIAL /
                  'registered_selected_producer_run_binding.hpp').read_text(
                      encoding='utf-8')
        implementation = (FINANCIAL /
                          'registered_selected_producer_run_binding.cpp').read_text(
                              encoding='utf-8')
        self.assertNotIn('projection_identity', header)
        self.assertNotIn('child_exit_identity', header)
        for needle in (
                '.accepted_head_and_selected_main_plan_authorities = false',
                '.source_owned_outer_attempt_domain = false',
                '.producer_plus_two_capsule_prelaunch_split = false',
                '.round_capsule_prelaunch_children = false',
                '.post_reservation_activation_minter = true',
                '.postrun_projection_residual = false',
                '.postrun_pidfd_exit_residual = false',
                '.observer_v5_preidentity_recorder = false',
                '.persistent_two_round_capsule_owner = false',
                '.observer_v5_state_capsule_residual = false',
                '.final_run_binding_join = false',
                '.selected_parent_callsite = false',
                '.configured = false',
                '.launch_authorized = false'):
            self.assertIn(needle, implementation)


if __name__ == '__main__':
    unittest.main()
