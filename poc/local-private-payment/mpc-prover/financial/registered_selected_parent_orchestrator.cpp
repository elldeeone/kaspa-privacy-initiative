#include "registered_selected_parent_orchestrator.hpp"

#include "fresh_owner_trial_issuance.hpp"
#include "registered_capture_plan_roster_bridge.hpp"
#include "registered_party_completion_transport.hpp"
#include "registered_full_cohort_release_barrier_contract.hpp"
#include "fresh_owner_process_adapter.hpp"
#include "../../private_batch_trial/privacy_fresh_owner_round1_outcome_consumer_authority.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver {

RegisteredSelectedProducerActivationResult
RegisteredSelectedParentOrchestrator::activate_selected_prelaunch(
        fresh_owner_issuance::FreshOwnerPersistentActivationAuthority&&
            activation,
        kpb::measurement::prelaunch_policy_domain::
            RegisteredPrelaunchPolicyDomainAuthority&& policy,
        kpb::measurement::score_output_lineage_source::
            SelectedOwnerScoreLineagePrelaunchSourceAuthority&& source) {
    return RegisteredSelectedProducerActivationBridge::activate(
        std::move(activation), std::move(policy), std::move(source));
}

kpb::measurement::fresh_trial_owner::
FreshOwnerRound1AttemptStepAuthority
RegisteredSelectedParentOrchestrator::issue_round1_attempt(
        kpb::measurement::fresh_trial_owner::
            AllBranchFreshTrialOwnerAuthority&& owner,
        fresh_owner_issuance::FreshOwnerProcessSupervisor& supervisor,
        fresh_owner_issuance::AcceptedRound1InputHistoryAuthority&& history,
        RegisteredPreidentityReadyAuthority&& ready,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&& replay,
        fresh_owner_issuance::FreshOwnerArmIsolationResidualAuthority&&
            isolation) {
    auto outcome = supervisor.issue_round1(
        std::move(history), std::move(ready), std::move(replay),
        std::move(isolation));
    return kpb::measurement::fresh_trial_owner::
        FreshOwnerRound1AttemptConsumerBridge::append(
            std::move(owner), std::move(outcome));
}

RegisteredParentRoundCompletionAuthority
RegisteredSelectedParentOrchestrator::execute_round(
        ParentRoleForkPlanAuthority&& fork_plan,
        projection_route::Role0ProjectionRouteWriterAuthority&& route_writer,
        projection_route::ParentProjectionRouteEndpointAuthority&&
            route_parent,
        RegisteredRoleChildProgram& program,
        fresh_owner_issuance::ConsumedFreshOwnerRoundBootstrap&& fresh,
        RosterBoundCapturePlan&& capture,
        std::span<const CompiledDriverSelection> drivers,
        const InheritedSealedQueryArtifact& inherited_query_artifact,
        OuterSupervisorAuthority& supervisor) {
    projection_route::RegisteredProjectionRouteForkBridge::
        consume_writer_for_parent_fork(
            std::move(route_writer), fork_plan);
    auto children = RegisteredParentRoleFork::launch(
        std::move(fork_plan), program);
    auto bound_route_parent =
        projection_route::RegisteredProjectionRouteForkBridge::
            bind_parent_after_fork(std::move(route_parent), children);
    auto bootstrap = RegisteredParentBootstrapTransport::prepare(
        std::move(fresh), std::move(capture), drivers,
        inherited_query_artifact, children);
    RegisteredParentBootstrapTransport::deliver(
        std::move(bootstrap), children);
    RegisteredSupervisorParentTransport::approve(supervisor, children);
    RegisteredFullCohortReleaseBarrier::authorize(children);
    auto retained = projection_route::RegisteredProjectionRoute::
        receive_and_retain(std::move(bound_route_parent));
    auto role0 = RegisteredPartyCompletionTransport::receive(
        children.take_completion_endpoint(0));
    auto role1 = RegisteredPartyCompletionTransport::receive(
        children.take_completion_endpoint(1));
    auto role2 = RegisteredPartyCompletionTransport::receive(
        children.take_completion_endpoint(2));
    return RegisteredParentRoundCompletionBridge::join(
        std::move(retained), std::move(role0), std::move(role1),
        std::move(role2), children);
}

RegisteredParentTrialCompletionAuthority
RegisteredSelectedParentOrchestrator::execute_trial(
        ParentRoleForkPlanAuthority&& round1_fork_plan,
        projection_route::Role0ProjectionRouteWriterAuthority&&
            round1_route_writer,
        projection_route::ParentProjectionRouteEndpointAuthority&&
            round1_route_parent,
        fresh_owner_issuance::ConsumedFreshOwnerRoundBootstrap&&
            round1_fresh,
        RosterBoundCapturePlan&& round1_capture,
        std::span<const CompiledDriverSelection> round1_drivers,
        ParentRoleForkPlanAuthority&& round2_fork_plan,
        projection_route::Role0ProjectionRouteWriterAuthority&&
            round2_route_writer,
        projection_route::ParentProjectionRouteEndpointAuthority&&
            round2_route_parent,
        fresh_owner_issuance::ConsumedFreshOwnerRoundBootstrap&&
            round2_fresh,
        RosterBoundCapturePlan&& round2_capture,
        std::span<const CompiledDriverSelection> round2_drivers,
        RegisteredPersistentRoleChildProgram& program,
        const InheritedSealedQueryArtifact& inherited_query_artifact,
        OuterSupervisorAuthority& supervisor) {
    projection_route::RegisteredProjectionRouteForkBridge::
        consume_writer_for_parent_fork(
            std::move(round1_route_writer), round1_fork_plan);
    projection_route::RegisteredProjectionRouteForkBridge::
        consume_writer_for_parent_fork(
            std::move(round2_route_writer), round2_fork_plan);

    auto session = RegisteredParentPersistentRoleFork::launch(
        std::move(round1_fork_plan), std::move(round2_fork_plan), program);

    auto& round1_children =
        RegisteredParentPersistentRoleFork::round1(session);
    auto round1_parent =
        projection_route::RegisteredProjectionRouteForkBridge::
            bind_parent_after_fork(
                std::move(round1_route_parent), round1_children);
    auto round1_bootstrap = RegisteredParentBootstrapTransport::prepare(
        std::move(round1_fresh), std::move(round1_capture), round1_drivers,
        inherited_query_artifact, round1_children);
    RegisteredParentBootstrapTransport::deliver(
        std::move(round1_bootstrap), round1_children);
    RegisteredSupervisorParentTransport::approve(
        supervisor, round1_children);
    RegisteredFullCohortReleaseBarrier::authorize(round1_children);
    auto round1_route = projection_route::RegisteredProjectionRoute::
        receive_and_retain(std::move(round1_parent));
    auto round1_role0 = RegisteredPartyCompletionTransport::receive(
        round1_children.take_completion_endpoint(0));
    auto round1_role1 = RegisteredPartyCompletionTransport::receive(
        round1_children.take_completion_endpoint(1));
    auto round1_role2 = RegisteredPartyCompletionTransport::receive(
        round1_children.take_completion_endpoint(2));
    auto round1 = RegisteredParentRoundCompletionBridge::defer(
        std::move(round1_route), std::move(round1_role0),
        std::move(round1_role1), std::move(round1_role2), round1_children);

    auto& round2_children =
        RegisteredParentPersistentRoleFork::activate_round2(session);
    auto round2_parent =
        projection_route::RegisteredProjectionRouteForkBridge::
            bind_parent_after_fork(
                std::move(round2_route_parent), round2_children);
    auto round2_bootstrap = RegisteredParentBootstrapTransport::prepare(
        std::move(round2_fresh), std::move(round2_capture), round2_drivers,
        inherited_query_artifact, round2_children);
    RegisteredParentBootstrapTransport::deliver(
        std::move(round2_bootstrap), round2_children);
    RegisteredSupervisorParentTransport::approve(
        supervisor, round2_children);
    RegisteredFullCohortReleaseBarrier::authorize(round2_children);
    auto round2_route = projection_route::RegisteredProjectionRoute::
        receive_and_retain(std::move(round2_parent));
    auto round2_role0 = RegisteredPartyCompletionTransport::receive(
        round2_children.take_completion_endpoint(0));
    auto round2_role1 = RegisteredPartyCompletionTransport::receive(
        round2_children.take_completion_endpoint(1));
    auto round2_role2 = RegisteredPartyCompletionTransport::receive(
        round2_children.take_completion_endpoint(2));
    auto round2 = RegisteredParentRoundCompletionBridge::defer(
        std::move(round2_route), std::move(round2_role0),
        std::move(round2_role1), std::move(round2_role2), round2_children);
    return RegisteredParentTrialCompletionBridge::join(
        std::move(round1), std::move(round2), session);
}

RegisteredSelectedParentOrchestratorSourceStatus
registered_selected_parent_orchestrator_source_status() {
    return {
        .schema = "kpb-registered-selected-parent-orchestrator-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .exact_three_role_fork = true,
        .typed_bootstrap_and_supervisor = true,
        .round1_attempt_outcome_claimed = true,
        .pre_route_full_cohort_release_barrier = true,
        .route_retained_before_terminal_join = true,
        .three_parent_observed_party_completions = true,
        .conditional_baseline_effects_retained = true,
        .clean_child_exit_join = true,
        .persistent_same_child_two_round_join = true,
        .six_party_completion_retained = true,
        .public_receipt_substitution = false,
        .legacy_baseline_terminal_selected = false,
        .production_plan_factory = false,
        .two_round_global_capture_join = false,
        .producer_closure_join = false,
        .all_branch_producer_history_owner = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver
