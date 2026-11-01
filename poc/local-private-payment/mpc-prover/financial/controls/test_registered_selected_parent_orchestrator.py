#!/usr/bin/env python3
"""Controls for the one-round selected parent orchestration composite."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
VENDOR = ROOT / '.local/mpc-prover-softspoken-vendor'
TRIAL = FINANCIAL.parent.parent / 'private_batch_trial'


def flags():
    compiler = shutil.which('x86_64-linux-gnu-g++-15') or shutil.which('g++')
    if compiler is None:
        raise unittest.SkipTest('C++ compiler unavailable')
    result = [
        compiler, '-std=c++20', '-O1', '-g0', '-march=native', '-pthread',
        '-Wall', '-Wextra', '-Werror', '-Wno-overloaded-virtual',
        '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
        '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK', '-DMCL_FP_BIT=384',
        '-DMCL_FR_BIT=256', '-DMCL_MSM=0', '-fsyntax-only',
    ]
    for include in [
        MPC, VENDOR / 'MP-SPDZ', VENDOR / 'MP-SPDZ/deps',
        VENDOR / 'MP-SPDZ/local/include', VENDOR / 'mcl/include',
        VENDOR / 'prefix/usr/include',
        VENDOR / 'prefix/usr/include/x86_64-linux-gnu',
    ]:
        result.extend(['-I', str(include)])
    return result


class RegisteredSelectedParentOrchestratorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-parent-round-completion-')
        cls.binary = Path(cls.temporary.name) / 'round-controls'
        sources = [
            HERE / 'registered_parent_round_completion_test.cpp',
            FINANCIAL / 'registered_parent_round_completion.cpp',
            FINANCIAL / 'registered_producer_route_bridge.cpp',
            FINANCIAL / 'registered_persistent_role_exit_history.cpp',
            FINANCIAL / 'registered_full_cohort_release_barrier.cpp',
            FINANCIAL / 'registered_party_completion_transport.cpp',
            FINANCIAL / 'authenticated_baseline_owner_receiver.cpp',
            FINANCIAL / 'registered_parent_role_fork.cpp',
            FINANCIAL / 'registered_projection_route.cpp',
            FINANCIAL / 'registered_parent_role_delivery_bridge.cpp',
            FINANCIAL / 'registered_driver_bridge.cpp',
            FINANCIAL / 'registered_capture_session.cpp',
            FINANCIAL / 'baseline_public_effects_collector.cpp',
            FINANCIAL / 'registered_attempt_supervisor.cpp',
            FINANCIAL / 'registered_identity_registry.cpp',
            FINANCIAL / 'docker_monotonic_anchor_client.cpp',
            TRIAL / 'privacy_capture_hook.cpp',
            TRIAL / 'privacy_capture_producer_archive.cpp',
            TRIAL / 'privacy_capture_producer_runtime.cpp',
            TRIAL / 'privacy_measurement_authority.cpp',
            TRIAL / 'privacy_measurement_child_output_authority.cpp',
            TRIAL / 'privacy_measurement_output_abi.cpp',
            FINANCIAL / 'registered_trial_attempt_history.cpp',
            FINANCIAL / 'registered_fresh_trial_history_ledger.cpp',
        ]
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            '-DKPI_REGISTERED_FULL_COHORT_RELEASE_BARRIER_TEST_SETUP',
            '-DKPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP',
            '-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_HISTORY_TEST_SETUP',
            *map(str, sources), '-I', str(FINANCIAL), '-lcrypto', '-pthread',
            '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_round(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario], capture_output=True, text=True,
            timeout=20, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_production_translation_unit_compiles(self):
        result = subprocess.run(
            [*flags(),
             str(FINANCIAL / 'registered_parent_round_completion.cpp'),
             str(FINANCIAL / 'registered_selected_parent_orchestrator.cpp')],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_parent_order_closes_route_before_terminal_join(self):
        source = (FINANCIAL /
                  'registered_selected_parent_orchestrator.cpp').read_text()
        source = source[source.index(
            'RegisteredSelectedParentOrchestrator::execute_round('):]
        ordered = [
            'consume_writer_for_parent_fork(',
            'RegisteredParentRoleFork::launch(',
            'bind_parent_after_fork(',
            'RegisteredParentBootstrapTransport::prepare(',
            'RegisteredParentBootstrapTransport::deliver(',
            'RegisteredSupervisorParentTransport::approve(',
            'RegisteredFullCohortReleaseBarrier::authorize(',
            'RegisteredProjectionRoute::\n        receive_and_retain(',
            'RegisteredPartyCompletionTransport::receive(',
            'RegisteredParentRoundCompletionBridge::join(',
        ]
        positions = [source.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_selected_trial_uses_one_persistent_three_child_session(self):
        source = (FINANCIAL /
                  'registered_selected_parent_orchestrator.cpp').read_text()
        source = source[source.index(
            'RegisteredSelectedParentOrchestrator::execute_trial('):]
        ordered = [
            'consume_writer_for_parent_fork(',
            'RegisteredParentPersistentRoleFork::launch(',
            'RegisteredParentPersistentRoleFork::round1(',
            'RegisteredParentRoundCompletionBridge::defer(',
            'RegisteredParentPersistentRoleFork::activate_round2(',
            'RegisteredParentRoundCompletionBridge::defer(',
            'RegisteredParentTrialCompletionBridge::join(',
        ]
        positions = []
        at = 0
        for needle in ordered:
            at = source.index(needle, at)
            positions.append(at)
            at += len(needle)
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(source.count(
            'RegisteredParentPersistentRoleFork::launch('), 1)
        self.assertEqual(source.count(
            'RegisteredParentTrialCompletionBridge::join('), 1)

    def test_round1_outcome_is_immediately_claimed_by_outer_owner(self):
        header = (FINANCIAL /
                  'registered_selected_parent_orchestrator.hpp').read_text()
        source = (FINANCIAL /
                  'registered_selected_parent_orchestrator.cpp').read_text()
        declaration = header[header.index('issue_round1_attempt('):]
        declaration = declaration[:declaration.index(';')]
        for required in (
                'AllBranchFreshTrialOwnerAuthority&&',
                'FreshOwnerProcessSupervisor&',
                'AcceptedRound1InputHistoryAuthority&&',
                'RegisteredPreidentityReadyAuthority&&',
                'SelectedOwnerReplayRegistryAuthority&&',
                'FreshOwnerArmIsolationResidualAuthority&&'):
            self.assertIn(required, declaration)
        for forbidden in ('Digest', 'string', 'bool'):
            self.assertNotIn(forbidden, declaration)
        selected = source[source.index(
            'RegisteredSelectedParentOrchestrator::issue_round1_attempt('):]
        self.assertLess(
            selected.index('supervisor.issue_round1('),
            selected.index('FreshOwnerRound1AttemptConsumerBridge::append('))
        self.assertIn('.round1_attempt_outcome_claimed = true', source)
        self.assertIn('.all_branch_producer_history_owner = false', source)
        self.assertIn('.registered_driver_configured = false', source)

    def test_round_composite_retains_all_authorities_and_waits_itself(self):
        header = (FINANCIAL /
                  'registered_selected_parent_orchestrator.hpp').read_text()
        source = (FINANCIAL /
                  'registered_parent_round_completion.cpp').read_text()
        self.assertIn('ParentRetainedProjectionAuthority retained_projection',
                      source)
        self.assertIn('ParentObservedPartyCompletionAuthority', source)
        self.assertIn('PartyBaselineOwnerEffectsAuthority', source)
        self.assertIn('children.wait()', source)
        self.assertNotIn('take_native_terminal', header)
        self.assertNotIn('public_party_completion()', header)

    def test_join_checks_exact_route_and_three_party_lineage(self):
        source = (FINANCIAL /
                  'registered_parent_round_completion.cpp').read_text()
        for required in (
            'route.plan_.classification', 'route.plan_.round',
            'route.plan_.trial', 'route.plan_.financial_run',
            'route.plan_.attempt', 'route.plan_.cohort',
            'route.plan_.capture_plan_identity',
            'route.projection_identity_', 'party.role == role',
            'completion_identity', 'observation_identity',
            'all_children_exited_zero'):
            self.assertIn(required, source)

    def test_no_public_receipt_or_legacy_terminal_substitution(self):
        header = (FINANCIAL /
                  'registered_selected_parent_orchestrator.hpp').read_text()
        source = (FINANCIAL /
                  'registered_selected_parent_orchestrator.cpp').read_text()
        self.assertNotIn('PublicRegisteredParentRoundCompletion', header)
        self.assertNotIn('PublicRegisteredParentTrialCompletion', header)
        self.assertNotIn('BaselineOwnerScoringParentTransport', source)
        self.assertNotIn('NativeTerminalRetainedProjectionAuthority', source)
        self.assertIn('.production_plan_factory = false', source)
        self.assertIn('.two_round_global_capture_join = false', source)
        self.assertIn('.persistent_same_child_two_round_join = true', source)
        self.assertIn('.six_party_completion_retained = true', source)
        self.assertIn('.registered_driver_configured = false', source)
        self.assertIn('.launch_authorized = false', source)

    def test_round_authority_cannot_be_rebuilt_from_public_receipts_or_digests(
            self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-parent-round-public-forge-') as directory:
            source = Path(directory) / 'surface.cpp'
            source.write_text(r'''
#include "financial/registered_selected_parent_orchestrator.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::projection_route;
template<class T> concept ReceiptFactory = requires(
        PublicRetainedProjectionReceipt route,
        PublicParentRoleForkCompletion children) {
    T::from_receipts(route, children);
};
template<class T> concept DigestFactory = requires(Digest digest) {
    T::from_digest(digest);
};
static_assert(!std::default_initializable<
              RegisteredParentRoundCompletionAuthority>);
static_assert(!std::copy_constructible<
              RegisteredParentRoundCompletionAuthority>);
static_assert(!std::constructible_from<
              RegisteredParentRoundCompletionAuthority,
              PublicRetainedProjectionReceipt,
              PublicParentRoleForkCompletion>);
static_assert(!ReceiptFactory<RegisteredParentRoundCompletionAuthority>);
static_assert(!DigestFactory<RegisteredParentRoundCompletionAuthority>);
int main() { return 0; }
''', encoding='utf-8')
            result = subprocess.run(
                [*flags(), str(source)], capture_output=True, text=True,
                check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_route_and_pidfd_history_bridges_cannot_be_hostile_redefined(self):
        attacks = {
            'route.cpp': r'''
#include "financial/registered_producer_route_bridge_contract.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredProducerRouteBridge final {};
}
''',
            'history.cpp': r'''
#include "financial/registered_persistent_role_exit_history.hpp"
namespace kpi::mpc::financial::registered_driver::attempt_history {
class RegisteredParentTrialHistoryBridge final {};
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-registered-route-history-friends-') as directory:
            directory = Path(directory)
            for name, body in attacks.items():
                source = directory / name
                source.write_text(body, encoding='utf-8')
                result = subprocess.run(
                    [*flags(), str(source)], capture_output=True, text=True,
                    check=False)
                self.assertNotEqual(result.returncode, 0, name)

    def test_hidden_round_retains_route_and_three_completions_once(self):
        self.run_round('hidden')

    def test_baseline_round_retains_three_private_effect_authorities(self):
        self.run_round('baseline')

    def test_wrong_projection_binding_refuses_round_join(self):
        self.run_round('wrong-projection')

    def test_wrong_party_selection_binding_refuses_round_join(self):
        self.run_round('wrong-selection')

    def test_wrong_full_cohort_barrier_binding_refuses_round_join(self):
        self.run_round('wrong-barrier')

    def test_cross_role_release_ready_mismatch_refuses_before_route(self):
        self.run_round('wrong-release-ready')

    def test_missing_release_ready_refuses_before_route(self):
        self.run_round('missing-release-ready')

    def test_route_ack_without_all_terminal_completions_refuses(self):
        self.run_round('partial')

    def test_nonzero_child_exit_refuses_round_join(self):
        self.run_round('dirty-exit')

    def test_persistent_hidden_trial_uses_same_three_children(self):
        self.run_round('persistent-hidden')

    def test_persistent_baseline_trial_retains_both_round_effects(self):
        self.run_round('persistent-baseline')

    def test_persistent_cross_trial_plan_refuses_before_fork(self):
        self.run_round('persistent-cross-trial')

    def test_persistent_changed_logical_roster_refuses_before_fork(self):
        self.run_round('persistent-changed-roster')

    def test_persistent_swapped_round_order_refuses_before_fork(self):
        self.run_round('persistent-swapped-rounds')

    def test_persistent_wrong_route_lineage_refuses_before_fork(self):
        self.run_round('persistent-wrong-route-lineage')

    def test_round2_cannot_activate_before_round1_deferred_close(self):
        self.run_round('persistent-early-round2')

    def test_persistent_dirty_final_child_exit_refuses_trial_join(self):
        self.run_round('persistent-dirty-final-exit')

    def test_persistent_signaled_child_exit_refuses_trial_join(self):
        self.run_round('persistent-signaled-final-exit')

    def test_external_reap_is_explicitly_unavailable_and_refuses_join(self):
        self.run_round('persistent-echild')

    def test_stale_raw_pid_never_signals_live_sentinel(self):
        self.run_round('persistent-stale-pid-sentinel')

    def test_persistent_poison_then_moved_session_destroy_is_idempotent(self):
        self.run_round('persistent-poison-destroy')

    def test_registered_trial_exports_exact_producer_routes_once(self):
        self.run_round('persistent-export-producer-routes')

    def test_pidfd_exit_residual_attaches_once_and_replay_refuses(self):
        self.run_round('persistent-attach-exit-history')

    def test_pending_round_from_another_persistent_session_refuses(self):
        self.run_round('persistent-cross-session')

    def test_stale_round1_still_burns_fresh_round2(self):
        self.run_round('persistent-stale-first-burns-second')


if __name__ == '__main__':
    unittest.main()
