#!/usr/bin/env python3
"""Surface and pinned-implementation controls for the outer owner."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class AllBranchFreshTrialOwnerAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, extra=()):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-I', str(HERE), *extra,
        ]
        command.extend(str(source) for source in sources)
        command.extend(['-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_production_surface_is_opaque_stop_only_and_configured_false(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-all-branch-owner-surface-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_all_branch_fresh_trial_owner_authority.hpp"
#include <concepts>
using namespace kpb::measurement::fresh_trial_owner;
template<class T> concept HasTestBegin = requires { T::test_only_begin(); };
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasFd = requires(const T& value) { value.fd(); };
template<class T> concept HasDigest = requires(const T& value) {
    value.digest();
};
template<class T> concept HasRetry = requires(T&& value) {
    static_cast<T&&>(value).take_retry();
};
template<class T> concept HasSuccess = requires(T&& value) {
    static_cast<T&&>(value).take_success();
};
static_assert(!std::copy_constructible<AllBranchFreshTrialOwnerAuthority>);
static_assert(std::move_constructible<AllBranchFreshTrialOwnerAuthority>);
static_assert(!std::copy_constructible<AllBranchFreshTrialStepAuthority>);
static_assert(std::move_constructible<AllBranchFreshTrialStepAuthority>);
static_assert(!std::copy_constructible<
    AllBranchFreshTrialUnavailableStopAuthority>);
static_assert(std::move_constructible<
    AllBranchFreshTrialUnavailableStopAuthority>);
static_assert(!HasTestBegin<AllBranchFreshTrialOwnerAuthority>);
static_assert(!HasReceipt<AllBranchFreshTrialStepAuthority>);
static_assert(!HasFd<AllBranchFreshTrialStepAuthority>);
static_assert(!HasDigest<AllBranchFreshTrialStepAuthority>);
static_assert(!HasRetry<AllBranchFreshTrialStepAuthority>);
static_assert(!HasSuccess<AllBranchFreshTrialStepAuthority>);
static_assert(kAllBranchFreshTrialOwnerSourceStatus
    .atomic_outcome_and_ledger_claim);
static_assert(kAllBranchFreshTrialOwnerSourceStatus
    .unavailable_is_run_invalidating_stop);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus
    .postissuance_activation_failure_stop);
static_assert(kAllBranchFreshTrialOwnerSourceStatus
    .live_process_linear_quarantine_owner);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus
    .allocation_failure_no_drop);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus.process_crash_durable);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus.power_loss_durable);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus
    .ledger_acquired_before_trial_identity);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus
    .observer_v5_p1_state_capsule);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus
    .complete_failed_view_continuation);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus
    .final_success_terminal);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus.mandatory_abort_sink);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus.selected_factory);
static_assert(!kAllBranchFreshTrialOwnerSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'surface', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_pinned_bridge_definition_blocks_alternate_member_definition(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-all-branch-owner-link-') as raw:
            root = Path(raw)
            official = root / 'official.o'
            activation_official = root / 'activation-official.o'
            hostile = root / 'hostile.o'
            official_compile = self.compile(
                official,
                HERE / 'privacy_all_branch_fresh_trial_owner_authority.cpp',
                extra=('-c',))
            self.assertEqual(
                official_compile.returncode, 0,
                official_compile.stdout + official_compile.stderr)
            activation_official_compile = self.compile(
                activation_official,
                HERE / 'privacy_all_branch_activation_failure_stop_bridge.cpp',
                extra=('-c',))
            self.assertEqual(
                activation_official_compile.returncode, 0,
                activation_official_compile.stdout +
                activation_official_compile.stderr)

            source = root / 'hostile.cpp'
            source.write_text(r'''
#include "privacy_all_branch_fresh_trial_owner_authority.hpp"
namespace kpb::measurement::fresh_trial_owner {
AllBranchFreshTrialStepAuthority AllBranchFreshTrialOwnerBridge::append(
        AllBranchFreshTrialOwnerAuthority&&,
        registered_history::RegisteredAttemptHistoryAppendOutcomeAuthority&&) {
    throw 1;
}
AllBranchFreshTrialStepAuthority
AllBranchFreshTrialOwnerBridge::stop_after_activation_failure(
        AllBranchFreshTrialOwnerAuthority&&,
        kpi::mpc::financial::registered_driver::
            RegisteredPersistentRoleActivationFailureResidual&&) {
    throw 1;
}
}
''', encoding='utf-8')
            hostile_compile = self.compile(
                hostile, source, extra=('-c',))
            self.assertEqual(
                hostile_compile.returncode, 0,
                hostile_compile.stdout + hostile_compile.stderr)
            linked = subprocess.run([
                'g++', '-r', str(official), str(activation_official),
                str(hostile),
                '-o', str(root / 'combined.o'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn('multiple definition', linked.stderr)


if __name__ == '__main__':
    unittest.main()
