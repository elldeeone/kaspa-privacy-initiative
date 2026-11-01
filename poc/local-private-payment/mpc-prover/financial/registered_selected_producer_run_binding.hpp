#pragma once

// Chronology-correct selected producer binding. The prelaunch authority holds
// only facts fixed after resource/process reservation and before MPC. Emitted
// projections, actual child exits, and observer-v5 state capsules are absent;
// a future post-run residual must carry those facts into the terminal join.

#include "registered_capture_plan_roster_bridge_contract.hpp"
#include "registered_persistent_fresh_trial_activation_contract.hpp"
#include "registered_selected_producer_activation_contract.hpp"
#include "../../private_batch_trial/privacy_capture_producer_runtime.hpp"
#include "../../private_batch_trial/c1_registered_plan_route_bridge_contract.hpp"
#include "../../private_batch_trial/privacy_owner_score_lineage_source_contract.hpp"
#include "../../private_batch_trial/privacy_registered_fresh_trial_producer_closure_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <string>

namespace kpi::mpc::financial::registered_driver {

struct RegisteredSelectedProducerPrelaunchRoutePolicy final {
    unsigned round{};
    identity_registry::Digest route_capability_identity{};
    std::uint64_t projection_bytes{};
    unsigned route_endpoint_count{};
    unsigned owner_ack_count{};
    bool role_blind_required{};
    bool after_full_cohort_barrier_required{};
    bool owner_socket_or_path_derivation_forbidden{};
};

struct RegisteredSelectedProducerPrelaunchStreamPolicy final {
    unsigned round{};
    kpb::measurement::CaptureKind kind{};
    unsigned fixed_fd{};
    identity_registry::Digest process_identity{};
    identity_registry::Digest expected_exit_policy_identity{};
};

// Plain data is not authority. Only the private activation-produced input
// capability can reach the compiler below.
struct RegisteredSelectedProducerPrelaunchPlan final {
    kpb::measurement::Classification classification{};
    identity_registry::Digest comparison_selection{};
    identity_registry::Digest run_selection{};
    std::string capture_trial_id;
    identity_registry::Digest trial{};
    identity_registry::Digest measurement_attempt{};
    identity_registry::Digest measurement_cohort{};
    identity_registry::Digest capture{};
    identity_registry::Digest method{};
    identity_registry::Digest workload{};
    identity_registry::Digest source_closure{};
    identity_registry::Digest runtime{};
    identity_registry::Digest accepted_head_policy_identity{};
    identity_registry::Digest selected_main_policy_identity{};
    identity_registry::Digest prelaunch_policy_manifest_identity{};
    kpb::measurement::FiniteManifestBinding finite_manifest;
    identity_registry::Digest outer_parent_process{};
    identity_registry::Digest outer_parent_executable{};
    identity_registry::Digest capture_source{};
    identity_registry::Digest capture_build{};
    identity_registry::Digest capture_runtime{};
    identity_registry::Digest capture_launcher{};
    kpb::measurement::WorkerBinding observer_worker;
    kpb::measurement::WorkerBinding score_worker;
    kpb::measurement::WorkerBinding aggregate_worker;
    std::array<identity_registry::Digest, 2> financial_runs{};
    std::array<std::string, 2> capture_attempt_ids;
    std::array<identity_registry::Digest, 2> round_attempts{};
    std::array<identity_registry::Digest, 2> round_cohorts{};
    std::array<identity_registry::Digest, 2> round_capture_plans{};
    identity_registry::Digest process_reservation_identity{};
    identity_registry::Digest persistent_process_session_identity{};
    std::array<identity_registry::Digest, 2> fork_plan_identities{};
    identity_registry::Digest producer_process_identity{};
    identity_registry::Digest role_closure_identity{};
    identity_registry::Digest manifest_seal{};
    kpb::measurement::ConstructionPolicy construction_policy{};
    identity_registry::Digest construction_classification_receipt{};
    std::array<RegisteredSelectedProducerPrelaunchRoutePolicy, 2>
        route_policies{};
    std::array<RegisteredSelectedProducerPrelaunchStreamPolicy, 10>
        streams{};
};

class RegisteredSelectedProducerPrelaunchInputAuthority final {
    RegisteredSelectedProducerPrelaunchPlan plan_;
    std::atomic_bool live_{true};
    explicit RegisteredSelectedProducerPrelaunchInputAuthority(
        RegisteredSelectedProducerPrelaunchPlan);
    friend class RegisteredPersistentFreshTrialActivationBridge;
    friend class RegisteredSelectedProducerActivationBridge;
    friend class RegisteredSelectedProducerPrelaunchBindingFactory;
public:
    RegisteredSelectedProducerPrelaunchInputAuthority(
        const RegisteredSelectedProducerPrelaunchInputAuthority&) = delete;
    RegisteredSelectedProducerPrelaunchInputAuthority& operator=(
        const RegisteredSelectedProducerPrelaunchInputAuthority&) = delete;
    RegisteredSelectedProducerPrelaunchInputAuthority(
        RegisteredSelectedProducerPrelaunchInputAuthority&&) noexcept;
    RegisteredSelectedProducerPrelaunchInputAuthority& operator=(
        RegisteredSelectedProducerPrelaunchInputAuthority&&) = delete;
    ~RegisteredSelectedProducerPrelaunchInputAuthority();
};

class RegisteredSelectedProducerPrelaunchBindingAuthority final {
    RegisteredSelectedProducerPrelaunchPlan plan_;
    identity_registry::Digest authority_identity_{};
    std::atomic_bool live_{true};
    std::atomic_bool c1_round_lineage_issued_{false};
    // Reserved one-shot sub-capability for the selected diagnostic lineage
    // worker.  The production compiler leaves it absent until the selected
    // parent owns exact source/runtime artifacts and the outer-attempt domain.
    int lineage_selection_fd_{-1};
    int lineage_worker_fd_{-1};
    identity_registry::Digest lineage_worker_sha256_{};
    std::atomic_bool lineage_receiver_live_{false};
    bool lineage_worker_selected_{};
    RegisteredSelectedProducerPrelaunchBindingAuthority(
        RegisteredSelectedProducerPrelaunchPlan,
        identity_registry::Digest);
    const RegisteredSelectedProducerPrelaunchPlan&
        inspect_for_state_capsule_compiler() const;
    friend class RegisteredSelectedProducerPrelaunchBindingFactory;
    friend class RegisteredSelectedProducerActivationBridge;
    friend class RegisteredFreshTrialProducerClosureBridge;
    friend class ::kpb::measurement::c1_capture::
        RegisteredC1PlanRouteBridge;
    friend class ::kpb::measurement::score_output_lineage_source::
        PrivacyLaunchLineageSourceReceiverBridge;
    friend class ::kpb::measurement::p1_state::
        P1StateCapsulePrelaunchCompilerBridge;
public:
    RegisteredSelectedProducerPrelaunchBindingAuthority(
        const RegisteredSelectedProducerPrelaunchBindingAuthority&) = delete;
    RegisteredSelectedProducerPrelaunchBindingAuthority& operator=(
        const RegisteredSelectedProducerPrelaunchBindingAuthority&) = delete;
    RegisteredSelectedProducerPrelaunchBindingAuthority(
        RegisteredSelectedProducerPrelaunchBindingAuthority&&) noexcept;
    RegisteredSelectedProducerPrelaunchBindingAuthority& operator=(
        RegisteredSelectedProducerPrelaunchBindingAuthority&&) = delete;
    ~RegisteredSelectedProducerPrelaunchBindingAuthority();

};

class RegisteredSelectedProducerPrelaunchBindingFactory final {
    RegisteredSelectedProducerPrelaunchBindingFactory() = delete;
public:
    static RegisteredSelectedProducerPrelaunchBindingAuthority compile(
        RegisteredSelectedProducerPrelaunchInputAuthority&&);
};

// Reserved names for the separate post-run half and final join. They remain
// unconstructible until a complete source-owned bridge consumes actual pidfd
// exits, projections, and observer-v5 capsules.
class RegisteredSelectedProducerPostrunResidualAuthority final {
    RegisteredSelectedProducerPostrunResidualAuthority() = delete;
};
class RegisteredSelectedProducerRunBindingAuthority final {
    RegisteredSelectedProducerRunBindingAuthority() = delete;
};

struct RegisteredSelectedProducerRunBindingSourceStatus final {
    std::string schema;
    std::string status;
    bool structural_prelaunch_factory_core{};
    bool raw_uuid_domain_binding{};
    bool accepted_head_and_selected_main_plan_authorities{};
    bool source_owned_outer_attempt_domain{};
    bool producer_plus_two_capsule_prelaunch_split{};
    bool round_capsule_prelaunch_children{};
    bool exact_two_round_lineage{};
    bool finite_manifest_binding{};
    bool process_reservation_and_session_binding{};
    bool route_capability_policy_binding{};
    bool expected_exit_policy_binding{};
    bool caller_prelaunch_factory{};
    bool post_reservation_activation_minter{};
    bool postrun_projection_residual{};
    bool postrun_pidfd_exit_residual{};
    bool observer_v5_preidentity_recorder{};
    bool persistent_two_round_capsule_owner{};
    bool observer_v5_state_capsule_residual{};
    bool final_run_binding_join{};
    bool selected_parent_callsite{};
    bool configured{};
    bool launch_authorized{};
};

RegisteredSelectedProducerRunBindingSourceStatus
registered_selected_producer_run_binding_source_status();

} // namespace kpi::mpc::financial::registered_driver
