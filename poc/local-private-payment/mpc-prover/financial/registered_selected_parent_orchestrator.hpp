#pragma once

// One-round parent orchestration from already genuine typed authorities.  The
// resulting capability is intentionally indivisible: it retains the exact
// projection, all three parent-observed party completions, optional baseline
// effects, and clean child-exit evidence.  It cannot be converted directly to
// a network/terminal authority before the future two-round global capture join.

#include "registered_parent_round_completion_contract.hpp"
#include "registered_measurement_capture_bridge_contract.hpp"
#include "registered_selected_producer_activation_contract.hpp"
#include "registered_producer_route_bridge_contract.hpp"
#include "registered_persistent_role_exit_history.hpp"
#include "registered_projection_route.hpp"
#include "../../private_batch_trial/privacy_fresh_owner_round1_outcome_consumer_contract.hpp"

#include <array>
#include <memory>
#include <span>
#include <string>

namespace kpb::measurement::fresh_owner_transactional_replay {
class SelectedOwnerReplayRegistryAuthority;
}

namespace kpi::mpc::financial::fresh_owner_issuance {
class AcceptedRound1InputHistoryAuthority;
class FreshOwnerArmIsolationResidualAuthority;
class FreshOwnerProcessSupervisor;
}

namespace kpi::mpc::financial::registered_driver {

class RosterBoundCapturePlan;

class RegisteredParentRoundCompletionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredParentRoundCompletionAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredParentRoundCompletionBridge;
public:
    RegisteredParentRoundCompletionAuthority(
        const RegisteredParentRoundCompletionAuthority&) = delete;
    RegisteredParentRoundCompletionAuthority& operator=(
        const RegisteredParentRoundCompletionAuthority&) = delete;
    RegisteredParentRoundCompletionAuthority(
        RegisteredParentRoundCompletionAuthority&&) noexcept;
    RegisteredParentRoundCompletionAuthority& operator=(
        RegisteredParentRoundCompletionAuthority&&) = delete;
    ~RegisteredParentRoundCompletionAuthority();
};

// Same genuine route/party/effects payload as a round completion, but child
// process exit is intentionally deferred. It can only be consumed together
// with the other round and the one persistent process-session capability.
class RegisteredParentPendingRoundCompletionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredParentPendingRoundCompletionAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredParentRoundCompletionBridge;
    friend class RegisteredParentTrialCompletionBridge;
public:
    RegisteredParentPendingRoundCompletionAuthority(
        const RegisteredParentPendingRoundCompletionAuthority&) = delete;
    RegisteredParentPendingRoundCompletionAuthority& operator=(
        const RegisteredParentPendingRoundCompletionAuthority&) = delete;
    RegisteredParentPendingRoundCompletionAuthority(
        RegisteredParentPendingRoundCompletionAuthority&&) noexcept;
    RegisteredParentPendingRoundCompletionAuthority& operator=(
        RegisteredParentPendingRoundCompletionAuthority&&) = delete;
    ~RegisteredParentPendingRoundCompletionAuthority();
};

// Indivisible two-round result. It retains both private routes, all six live
// parent-observed party completions, conditional baseline effects and the
// final same-PID clean-exit evidence. It has no public receipt or split API.
class RegisteredParentTrialCompletionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredParentTrialCompletionAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredParentTrialCompletionBridge;
    friend class RegisteredMeasurementCaptureBridge;
    friend class RegisteredProducerRouteBridge;
    friend class attempt_history::RegisteredParentTrialHistoryBridge;
public:
    RegisteredParentTrialCompletionAuthority(
        const RegisteredParentTrialCompletionAuthority&) = delete;
    RegisteredParentTrialCompletionAuthority& operator=(
        const RegisteredParentTrialCompletionAuthority&) = delete;
    RegisteredParentTrialCompletionAuthority(
        RegisteredParentTrialCompletionAuthority&&) noexcept;
    RegisteredParentTrialCompletionAuthority& operator=(
        RegisteredParentTrialCompletionAuthority&&) = delete;
    ~RegisteredParentTrialCompletionAuthority();
};

class RegisteredSelectedParentOrchestrator final {
    RegisteredSelectedParentOrchestrator() = delete;
public:
    // The sole selected-parent prelaunch seam.  It consumes the causal
    // post-issuance activation child together with the opaque source-policy
    // and sealed privacy-launch source capabilities.  A public plan or raw
    // descriptor cannot reach this call.
    static RegisteredSelectedProducerActivationResult
        activate_selected_prelaunch(
            fresh_owner_issuance::FreshOwnerPersistentActivationAuthority&&,
            kpb::measurement::prelaunch_policy_domain::
                RegisteredPrelaunchPolicyDomainAuthority&&,
            kpb::measurement::score_output_lineage_source::
                SelectedOwnerScoreLineagePrelaunchSourceAuthority&&);

    // The selected parent must acquire its outer ledger owner before the
    // source-owned Round-1 attempt. This call immediately consumes the opaque
    // attempt outcome into the indivisible outer step; no caller can drop the
    // success or STOP arm between issuance and history ownership.
    [[nodiscard]] static
    kpb::measurement::fresh_trial_owner::
        FreshOwnerRound1AttemptStepAuthority issue_round1_attempt(
            kpb::measurement::fresh_trial_owner::
                AllBranchFreshTrialOwnerAuthority&&,
            fresh_owner_issuance::FreshOwnerProcessSupervisor&,
            fresh_owner_issuance::AcceptedRound1InputHistoryAuthority&&,
            RegisteredPreidentityReadyAuthority&&,
            kpb::measurement::fresh_owner_transactional_replay::
                SelectedOwnerReplayRegistryAuthority&&,
            fresh_owner_issuance::
                FreshOwnerArmIsolationResidualAuthority&&);

    static RegisteredParentRoundCompletionAuthority execute_round(
        ParentRoleForkPlanAuthority&&,
        projection_route::Role0ProjectionRouteWriterAuthority&&,
        projection_route::ParentProjectionRouteEndpointAuthority&&,
        RegisteredRoleChildProgram&,
        fresh_owner_issuance::ConsumedFreshOwnerRoundBootstrap&&,
        RosterBoundCapturePlan&&,
        std::span<const CompiledDriverSelection>,
        const InheritedSealedQueryArtifact&,
        OuterSupervisorAuthority&);

    // Forks exactly once, retains the same three authenticated child PIDs for
    // R1 and R2, defers both per-round exits, and joins all six typed party
    // completions only after the final clean wait. The caller must already
    // possess every genuine compiled/bootstrap capability; there is no
    // digest, path, argv, environment or public-receipt overload.
    static RegisteredParentTrialCompletionAuthority execute_trial(
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
        RegisteredPersistentRoleChildProgram&,
        const InheritedSealedQueryArtifact&,
        OuterSupervisorAuthority&);
};

struct RegisteredSelectedParentOrchestratorSourceStatus {
    std::string schema;
    std::string status;
    bool exact_three_role_fork{};
    bool typed_bootstrap_and_supervisor{};
    bool round1_attempt_outcome_claimed{};
    bool pre_route_full_cohort_release_barrier{};
    bool route_retained_before_terminal_join{};
    bool three_parent_observed_party_completions{};
    bool conditional_baseline_effects_retained{};
    bool clean_child_exit_join{};
    bool persistent_same_child_two_round_join{};
    bool six_party_completion_retained{};
    bool public_receipt_substitution{};
    bool legacy_baseline_terminal_selected{};
    bool production_plan_factory{};
    bool two_round_global_capture_join{};
    bool producer_closure_join{};
    bool all_branch_producer_history_owner{};
    bool registered_driver_configured{};
    bool launch_authorized{};
};

RegisteredSelectedParentOrchestratorSourceStatus
registered_selected_parent_orchestrator_source_status();

} // namespace kpi::mpc::financial::registered_driver
