#!/usr/bin/env python3
"""Real-process controls for staged private-lifecycle owner issuance."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
TRIAL = MPC.parent / 'private_batch_trial'
VENDOR = MPC.parents[2] / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = VENDOR.parent / 'prefix' / 'usr' / 'include'


class FreshOwnerProcessAdapterControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-fresh-owner-process-adapter-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-DKPI_FRESH_OWNER_ISSUANCE_TEST_SETUP',
            '-DKPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP',
            '-DKPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP',
            '-DKPB_FRESH_OWNER_TRANSACTIONAL_REPLAY_TEST_SETUP',
            '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
            str(HERE / 'fresh_owner_process_adapter_test.cpp'),
            str(FINANCIAL / 'fresh_owner_arm_isolation.cpp'),
            str(FINANCIAL / 'candidate_owner_truth_post_barrier_bridge.cpp'),
            str(FINANCIAL / 'fresh_owner_process_adapter.cpp'),
            str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
            str(FINANCIAL / 'registered_preidentity_ready.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_parent_role_delivery_bridge.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_permit.cpp'),
            str(TRIAL / 'privacy_capture_hook.cpp'),
            str(TRIAL /
                'privacy_fresh_owner_transactional_replay_authority.cpp'),
            str(TRIAL / 'privacy_measurement_authority.cpp'),
            str(TRIAL / 'privacy_measurement_child_output_authority.cpp'),
            str(TRIAL / 'privacy_measurement_output_abi.cpp'),
            '-I', str(MPC), '-I', str(VENDOR), '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
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

    def test_exact_three_children_stay_alive_for_causally_gated_round2(self):
        self.run_scenario('happy')

    def test_transactional_round1_returns_indivisible_success(self):
        self.run_scenario('transactional-round1')

    def test_transactional_round2_returns_indivisible_success(self):
        self.run_scenario('transactional-round2')

    def test_every_post_claim_round2_fault_returns_typed_stop(self):
        self.run_scenario('transactional-round2-faults')

    def test_unconsumed_round2_outcome_is_fail_stop(self):
        result = subprocess.run(
            [str(self.binary), 'transactional-round2-drop'],
            capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 87,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_transactional_registry_failure_returns_typed_stop(self):
        self.run_scenario('transactional-stop')

    def test_unconsumed_round1_outcome_is_fail_stop(self):
        result = subprocess.run([str(self.binary), 'transactional-drop'],
                                capture_output=True, text=True,
                                timeout=30, check=False)
        self.assertEqual(result.returncode, 86,
                         result.stdout + result.stderr)
        self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_every_post_join_round1_fault_returns_typed_stop(self):
        self.run_scenario('transactional-faults')

    def test_round1_stop_uses_pidfd_and_retains_unsettled_children(self):
        self.run_scenario('transactional-pidfd')

    def test_unsafe_sigchld_environment_refuses_before_owner_claim(self):
        self.run_scenario('unsafe-sigchld')

    def test_hidden_candidate_truth_is_owner_local_and_post_barrier_only(self):
        self.run_scenario('candidate-truth')

    def test_unread_candidate_endpoints_close_without_parent_decode(self):
        self.run_scenario('candidate-unread')

    def test_candidate_truth_wrong_lineage_missing_truth_and_exit_refuse(self):
        self.run_scenario('candidate-refuse')

    def test_two_arm_private_isolation_join_is_mandatory_before_r1(self):
        self.run_scenario('arm-gate')

    def test_real_paired_private_join_residuals_gate_both_round1_arms(self):
        self.run_scenario('paired-arm')

    def test_wrong_input_or_successor_history_refuses(self):
        self.run_scenario('wrong-history')

    def test_wrong_slot_duplicate_inode_and_wrong_root_refuse(self):
        self.run_scenario('wrong-root')

    def test_eof_credential_substitution_and_nonzero_exit_refuse(self):
        self.run_scenario('child-failure')

    def test_ambiguous_child_failure_burns_trial_before_any_reuse(self):
        self.run_scenario('failure-burn')

    def test_child_identity_must_equal_admitted_long_lived_verifier(self):
        self.run_scenario('verifier-mismatch')

    def test_private_lineage_roster_round_and_missing_owner_refuse(self):
        self.run_scenario('continuity')

    def test_permission_separated_replay_store_refuses_second_tree(self):
        self.run_scenario('replay')

    def test_typed_history_bootstrap_and_pregate_replay_refuse(self):
        self.run_scenario('gate-replay')

    def test_source_status_keeps_unselected_runtime_and_launch_closed(self):
        self.run_scenario('status')

    def test_production_surface_has_no_root_or_private_body_read_authority(self):
        source = Path(self.temporary.name) / 'production-surface.cpp'
        source.write_text(r'''
#include "fresh_owner_process_adapter.hpp"
#include "privacy_measurement_authority.hpp"
#include <concepts>
#include <utility>
using namespace kpi::mpc::financial::fresh_owner_issuance;
template<class T> concept RootFdAccessor = requires(const T& value) {
    value.fd();
};
template<class T> concept RootPathAccessor = requires(const T& value) {
    value.path();
};
template<class T> concept TestRootMintVisible = requires(
    PublicOwnerPrivateRoot value) { T::test_only_mint(value, 3); };
template<class T> concept TestProgramMintVisible = requires(
    PublicFreshOwnerProcessPlan value) { T::test_only_mint(value, nullptr); };
template<class T> concept UngatedRound2 = requires(
    T& supervisor, FreshOwnerRound1IssuedAuthority round1) {
    supervisor.issue_round2(std::move(round1));
};
template<class T> concept UngatedRound1 = requires(
    T& supervisor, AcceptedRound1InputHistoryAuthority history,
    OwnerIssuanceReplayGuardAuthority replay) {
    supervisor.issue_round1(std::move(history), std::move(replay));
};
template<class T> concept EndpointFdAccessor = requires(T& value) {
    value.fd();
};
template<class T> concept TestTruthReadVisible = requires(T& value) {
    value.test_only_receive_packet();
};
template<class T> concept TestBarrierMintVisible = requires(
    PublicCandidateOwnerTruthPostBarrier value) {
    T::test_only_mint(value);
};
template<class T> concept TestEndpointMintVisible = requires(
    PublicCandidateOwnerTruthEndpoint value) {
    T::test_only_mint(value, 3);
};
template<class T> concept UngatedTruthRelease = requires(
    T& supervisor, CandidateOwnerTruthPendingAuthority pending) {
    supervisor.release_candidate_truth(std::move(pending));
};
template<class T> concept PublicReceiptAccessor = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept PerOwnerPermitCanReleaseGlobal = requires(
    FreshOwnerProcessSupervisor& supervisor, T permit,
    CandidateOwnerTruthPendingAuthority pending) {
    CandidateOwnerTruthPostBarrierBridge::release(
        supervisor, std::move(permit), std::move(pending));
};
template<class T> concept PublicValueCanReleaseGlobal = requires(
    FreshOwnerProcessSupervisor& supervisor, T value,
    CandidateOwnerTruthPendingAuthority pending) {
    CandidateOwnerTruthPostBarrierBridge::release(
        supervisor, std::move(value), std::move(pending));
};
template<class T> concept LeaksLogicalOwner = requires(const T& value) {
    value.logical_owner_identity;
};
template<class T> concept TestV3HistoryCorruptVisible = requires(T value) {
    T::test_only_corrupt_successor_head(std::move(value));
};
template<class T> concept LegacyReadyReplayJoin = requires(
    T& supervisor, AcceptedRound1InputHistoryAuthority history,
    kpi::mpc::financial::registered_driver::
        RegisteredPreidentityReadyAuthority ready,
    OwnerIssuanceReplayGuardAuthority replay,
    FreshOwnerArmIsolationResidualAuthority isolation) {
    supervisor.issue_round1(
        std::move(history), std::move(ready), std::move(replay),
        std::move(isolation));
};
template<class T> concept OutcomeStateAccessor = requires(const T& value) {
    value.state();
};
template<class T> concept ProductionRound2Attempt = requires(
    T& supervisor, FreshOwnerRound1IssuedAuthority round1,
    AcceptedRound1SuccessorHistoryAuthority successor) {
    supervisor.issue_round2_transactional(
        std::move(round1), std::move(successor));
};
static_assert(!std::default_initializable<OwnerPrivateRootAuthority>);
static_assert(!std::copy_constructible<OwnerPrivateRootAuthority>);
static_assert(!RootFdAccessor<OwnerPrivateRootAuthority>);
static_assert(!RootPathAccessor<OwnerPrivateRootAuthority>);
static_assert(!TestRootMintVisible<OwnerPrivateRootAuthority>);
static_assert(!TestProgramMintVisible<
    CompiledPrivateLifecycleOwnerProgramAuthority>);
static_assert(!UngatedRound2<FreshOwnerProcessSupervisor>);
static_assert(!UngatedRound1<FreshOwnerProcessSupervisor>);
static_assert(!LegacyReadyReplayJoin<FreshOwnerProcessSupervisor>);
static_assert(!PublicReceiptAccessor<
    FreshOwnerRound1AttemptOutcomeAuthority>);
static_assert(!OutcomeStateAccessor<
    FreshOwnerRound1AttemptOutcomeAuthority>);
static_assert(!PublicReceiptAccessor<
    FreshOwnerRound2AttemptOutcomeAuthority>);
static_assert(!OutcomeStateAccessor<
    FreshOwnerRound2AttemptOutcomeAuthority>);
static_assert(!ProductionRound2Attempt<FreshOwnerProcessSupervisor>);
static_assert(!EndpointFdAccessor<CandidateOwnerTruthEndpointAuthority>);
static_assert(!TestTruthReadVisible<CandidateOwnerTruthEndpointAuthority>);
static_assert(!TestBarrierMintVisible<
    CandidateOwnerTruthPostBarrierAuthority>);
static_assert(!TestEndpointMintVisible<
    CandidateOwnerTruthEndpointAuthority>);
static_assert(!UngatedTruthRelease<FreshOwnerProcessSupervisor>);
static_assert(!PublicReceiptAccessor<CandidateOwnerTruthPendingAuthority>);
static_assert(!PublicReceiptAccessor<
    CandidateOwnerTruthPostBarrierAuthority>);
static_assert(!PublicReceiptAccessor<
    V3AcceptedRound1HistoryResidualAuthority>);
static_assert(!std::constructible_from<
    V3AcceptedRound1HistoryResidualAuthority>);
static_assert(!std::constructible_from<
    CandidateOwnerTruthPostBarrierAuthority,
    PublicCandidateOwnerTruthPostBarrier>);
static_assert(!PerOwnerPermitCanReleaseGlobal<
    kpb::measurement::OwnerTruthReleasePermitAuthority>);
static_assert(!PublicValueCanReleaseGlobal<
    kpb::measurement::PublicCandidateTruthBarrierRelease>);
static_assert(!LeaksLogicalOwner<PublicCandidateOwnerTruthEndpoint>);
static_assert(!TestV3HistoryCorruptVisible<
    V3AcceptedRound1HistoryResidualAuthority>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native', '-c', str(source), '-I', str(FINANCIAL),
            '-I', str(MPC), '-I', str(TRIAL), '-I', str(VENDOR),
            '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            '-o', str(Path(self.temporary.name) / 'production-surface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)

        # Link every production authority/bridge translation unit without any
        # fixture macro. This catches a hidden test-only dependency in the
        # genuine RunMeasurement -> owner-supervisor path.
        linked = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-Wno-overloaded-virtual', '-Wno-psabi',
            '-march=native',
            str(Path(self.temporary.name) / 'production-surface.o'),
            str(FINANCIAL / 'candidate_owner_truth_post_barrier_bridge.cpp'),
            str(FINANCIAL / 'fresh_owner_process_adapter.cpp'),
            str(FINANCIAL / 'fresh_owner_trial_issuance.cpp'),
            str(FINANCIAL / 'registered_preidentity_ready.cpp'),
            str(FINANCIAL / 'registered_parent_role_fork.cpp'),
            str(FINANCIAL / 'registered_projection_route.cpp'),
            str(FINANCIAL / 'registered_parent_role_delivery_bridge.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_reservation.cpp'),
            str(TRIAL /
                'privacy_registered_fresh_trial_capture_topology_permit.cpp'),
            str(TRIAL / 'privacy_capture_hook.cpp'),
            str(TRIAL /
                'privacy_fresh_owner_transactional_replay_authority.cpp'),
            str(TRIAL / 'privacy_measurement_authority.cpp'),
            str(TRIAL / 'privacy_measurement_child_output_authority.cpp'),
            str(TRIAL / 'privacy_measurement_output_abi.cpp'),
            '-I', str(FINANCIAL), '-I', str(MPC), '-I', str(TRIAL),
            '-I', str(VENDOR), '-I', str(PREFIX),
            '-I', str(PREFIX / 'x86_64-linux-gnu'),
            str(VENDOR / 'libSPDZ.so'),
            '-Wl,-rpath,' + str(VENDOR), '-lcrypto', '-pthread',
            '-o', str(Path(self.temporary.name) / 'production-link'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(linked.returncode, 0,
                         linked.stdout + linked.stderr)
        run = subprocess.run(
            [str(Path(self.temporary.name) / 'production-link')],
            capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual((run.stdout, run.stderr), ('', ''))

        implementation = (
            (FINANCIAL / 'fresh_owner_process_adapter.hpp').read_text() +
            (FINANCIAL / 'fresh_owner_process_adapter.cpp').read_text())
        for forbidden in ('openat', 'std::filesystem', 'std::ifstream',
                          'body_sha256', 'owner_file_path',
                          'private_file_path', 'root_path'):
            self.assertNotIn(forbidden, implementation)


if __name__ == '__main__':
    unittest.main()
