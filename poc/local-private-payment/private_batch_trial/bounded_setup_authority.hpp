#pragma once

// Fail-closed mechanism for the explicitly trusted, bounded-Testnet-only
// A-CRS-LOCAL-BOUNDED-V1 setup assumption.  This file does not select that
// assumption: the source-owned worker/plan selectors and production callsite
// are intentionally absent.

#include "bounded_setup_chronology_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <memory>
#include <string_view>

namespace kpb::bounded_setup {

using Digest = std::array<unsigned char, 32>;

class SetupRefused final : public std::exception {
public:
    const char* what() const noexcept override {
        return "bounded setup authority refused";
    }
};

enum class CircuitRole : std::uint8_t { Output = 1, Aggregate = 2 };

struct CircuitClosureReceipt final {
    // Pre-setup circuit closure only: reviewed source identity, recomputed
    // matrix identity/geometry and exact serialization lengths. Generated
    // PK/VK content identities never appear here; they are outputs below.
    CircuitRole role{};
    Digest source_identity{};
    Digest matrix_identity{};
    std::uint64_t constraints{};
    std::uint64_t variables{};
    std::uint64_t proving_key_bytes{};
    std::uint64_t verifying_key_bytes{};
};

struct SetupArtifactReceipt final {
    // Post-setup output identity, measured only after exact-size EOF, wait0,
    // fsync and hashing. It is never accepted as a setup-plan input.
    CircuitRole role{};
    bool proving_key{};
    std::uint64_t bytes{};
    Digest sha256{};
};

struct FrozenSetupPlanBinding final {
    // Only identities that may be chosen before any setup output, proof,
    // observer output, capture-plan material, or selected-parent artifact
    // exists are admitted here.  Later lifecycle authorities must join their
    // richer bindings to this receipt; they cannot be smuggled into setup.
    // The future source-owned selector chooses this root before setup. Every
    // other lifecycle identity below is a fixed domain-separated child of it,
    // so an arbitrary PK/VK/CRS or later evidence digest cannot be inserted.
    Digest trial{};
    std::array<Digest, 2> financial_runs{};
    // These are the predeclared round attempt nonces carried by
    // PublicFreshOwnerRoundReceipt, never the later attempt-history row
    // identities (which commit outcomes, projection and process evidence).
    std::array<Digest, 2> round_attempts{};
    std::array<Digest, 2> round_cohorts{};
    bool operator==(const FrozenSetupPlanBinding&) const = default;
};

struct BoundedSetupReceipt final {
    FrozenSetupPlanBinding selected_plan{};
    Digest plan_identity{};
    Digest worker_identity{};
    std::array<CircuitClosureReceipt, 2> circuits{};
    std::array<SetupArtifactReceipt, 4> artifacts{};
    std::array<std::int64_t, 2> worker_pids{{-1, -1}};
    bool source_and_matrix_bound{};
    bool exact_two_run_plan{};
    bool pre_setup_only_plan{};
    bool post_setup_artifacts_excluded_from_plan{};
    bool dedicated_one_shot_process_per_circuit{};
    bool single_threaded_controller{};
    bool inherited_private_output_fds{};
    bool exact_allowed_outputs{};
    bool environment_empty{};
    bool unknown_descriptors_closed{};
    bool network_syscalls_denied{};
    bool source_opens_denied{};
    bool descendant_processes_denied{};
    bool debugger_attachment_denied{};
    bool core_dumps_disabled{};
    bool swap_max_zero_before_and_after{};
    bool finite_memory_and_disk_guard_satisfied{};
    bool eof_observed{};
    bool wait_status_zero{};
    bool outputs_fsynced{};
    bool directory_fsynced{};
    bool process_terminated{};
    bool parent_death_kills_worker{};
    bool worker_reported_erasure_attempt{};
    bool best_effort_erasure_only{};
    bool erasure_cryptographically_proven{};
    bool setup_honesty_cryptographically_proven{};
    bool ceremony_claimed{};
    bool s4_selected{};
    bool s12_selected{};
    bool configured{};
};

class FrozenTwoRunPlanAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    std::atomic_bool live_{true};
    explicit FrozenTwoRunPlanAuthority(std::unique_ptr<Storage>);
    friend class BoundedSetupTestFixture;
    friend class BoundedSetupSupervisor;
public:
    FrozenTwoRunPlanAuthority(const FrozenTwoRunPlanAuthority&) = delete;
    FrozenTwoRunPlanAuthority& operator=(const FrozenTwoRunPlanAuthority&) = delete;
    FrozenTwoRunPlanAuthority(FrozenTwoRunPlanAuthority&&) noexcept;
    FrozenTwoRunPlanAuthority& operator=(FrozenTwoRunPlanAuthority&&) = delete;
    ~FrozenTwoRunPlanAuthority();
};

class SetupWorkerSelectionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    std::atomic_bool live_{true};
    explicit SetupWorkerSelectionAuthority(std::unique_ptr<Storage>);
    friend class BoundedSetupTestFixture;
    friend class BoundedSetupSupervisor;
    friend class SourceOwnedBoundedSetupLauncher;
public:
    SetupWorkerSelectionAuthority(const SetupWorkerSelectionAuthority&) = delete;
    SetupWorkerSelectionAuthority& operator=(const SetupWorkerSelectionAuthority&) = delete;
    SetupWorkerSelectionAuthority(SetupWorkerSelectionAuthority&&) noexcept;
    SetupWorkerSelectionAuthority& operator=(SetupWorkerSelectionAuthority&&) = delete;
    ~SetupWorkerSelectionAuthority();
};

class SetupCompletionAuthority final {
    std::unique_ptr<BoundedSetupReceipt> receipt_;
    std::atomic_bool live_{true};
    explicit SetupCompletionAuthority(BoundedSetupReceipt);
    friend class BoundedSetupSupervisor;
public:
    SetupCompletionAuthority(const SetupCompletionAuthority&) = delete;
    SetupCompletionAuthority& operator=(const SetupCompletionAuthority&) = delete;
    SetupCompletionAuthority(SetupCompletionAuthority&&) noexcept;
    SetupCompletionAuthority& operator=(SetupCompletionAuthority&&) = delete;
    ~SetupCompletionAuthority();

    // Non-authorizing inspection.  No S4/S12 selector consumes this type yet.
    const BoundedSetupReceipt& receipt() const;
#ifdef KPB_BOUNDED_SETUP_TEST_SETUP
    BoundedSetupReceipt consume_for_test();
#endif
};

// Future chronology-only capabilities.  They deliberately expose no public
// constructor, receipt, digest, getter or serializer.  Implementations and
// callsites are absent while the production pre-run trial source is absent.
class W1SetupBindingContinuationAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit W1SetupBindingContinuationAuthority(std::unique_ptr<Storage>);
    friend class BoundedSetupChronologyBridge;
    friend class W1PreSetupSplitAuthority;
public:
    W1SetupBindingContinuationAuthority(
        const W1SetupBindingContinuationAuthority&) = delete;
    W1SetupBindingContinuationAuthority& operator=(
        const W1SetupBindingContinuationAuthority&) = delete;
    W1SetupBindingContinuationAuthority(
        W1SetupBindingContinuationAuthority&&) noexcept;
    W1SetupBindingContinuationAuthority& operator=(
        W1SetupBindingContinuationAuthority&&) = delete;
    ~W1SetupBindingContinuationAuthority();
};

class W1PreSetupSplitAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit W1PreSetupSplitAuthority(std::unique_ptr<Storage>);
    friend class BoundedSetupChronologyBridge;
    friend class SourceOwnedBoundedSetupLauncher;
public:
    W1PreSetupSplitAuthority(const W1PreSetupSplitAuthority&) = delete;
    W1PreSetupSplitAuthority& operator=(
        const W1PreSetupSplitAuthority&) = delete;
    W1PreSetupSplitAuthority(W1PreSetupSplitAuthority&&) noexcept;
    W1PreSetupSplitAuthority& operator=(W1PreSetupSplitAuthority&&) = delete;
    ~W1PreSetupSplitAuthority();
};

class W1PostSetupReceiptAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit W1PostSetupReceiptAuthority(std::unique_ptr<Storage>);
    friend class BoundedSetupChronologyBridge;
public:
    W1PostSetupReceiptAuthority(const W1PostSetupReceiptAuthority&) = delete;
    W1PostSetupReceiptAuthority& operator=(
        const W1PostSetupReceiptAuthority&) = delete;
    W1PostSetupReceiptAuthority(W1PostSetupReceiptAuthority&&) noexcept;
    W1PostSetupReceiptAuthority& operator=(
        W1PostSetupReceiptAuthority&&) = delete;
    ~W1PostSetupReceiptAuthority();
};

struct BoundedSetupPlanBlocker final {
    std::string_view schema;
    std::string_view reason;
    std::string_view selected_parent_contract;
    std::string_view selected_parent_missing_report;
    std::uint64_t required_parent_artifacts{};
    std::uint64_t missing_parent_artifacts{};
    bool production_plan_selected{};
    bool source_owned_plan_selector{};
    bool production_trial_root_authority_present{};
    bool typed_post_setup_key_join_present{};
    bool full_setup_ready{};
    bool s4_selected{};
    bool s12_selected{};
    bool configured{};
};

inline constexpr BoundedSetupPlanBlocker kBoundedSetupPlanBlocker{
    .schema = "kpb-bounded-setup-plan-blocker/v1",
    .reason =
        "source-owned-pre-setup-two-run-plan-missing-and-post-setup-fields-excluded",
    .selected_parent_contract =
        "privacy_measurement_selected_parent_artifact_contract.json",
    .selected_parent_missing_report =
        "privacy_measurement_selected_parent_artifact_missing.json",
    .required_parent_artifacts = 60,
    .missing_parent_artifacts = 60,
    .production_plan_selected = false,
    .source_owned_plan_selector = false,
    .production_trial_root_authority_present = false,
    .typed_post_setup_key_join_present = false,
    .full_setup_ready = false,
    .s4_selected = false,
    .s12_selected = false,
    .configured = false,
};

struct BoundedSetupPreflightReceipt final {
    Digest worker_identity{};
    Digest aggregate_context_identity{};
    Digest aggregate_signature_identity{};
    std::uint64_t worker_bytes{};
    std::uint64_t cgroup_memory_limit_bytes{};
    std::uint64_t cgroup_memory_current_bytes{};
    std::uint64_t host_memory_available_bytes{};
    std::uint64_t output_filesystem_available_bytes{};
    bool source_closed_static_worker_exact{};
    bool aggregate_public_inputs_exact{};
    bool cgroup_memory_finite_and_bounded{};
    bool memory_headroom_sufficient{};
    bool swap_max_zero{};
    bool output_filesystem_headroom_sufficient{};
    bool anonymous_private_outputs_supported{};
    bool production_plan_selected{};
    std::uint64_t missing_parent_artifacts{};
    bool full_setup_ready{};
    bool s4_selected{};
    bool s12_selected{};
    bool configured{};
};

class SourceOwnedBoundedSetupLauncher final {
    static SetupWorkerSelectionAuthority select_worker(
        std::string_view workspace_root);
public:
    // Non-launching source/build/resource admission.  It probes anonymous
    // O_TMPFILE support but publishes no output.  There is intentionally no
    // setup API until the source-owned production two-run plan exists.
    static BoundedSetupPreflightReceipt preflight(
        std::string_view workspace_root,
        std::string_view fresh_output_directory);
};

class BoundedSetupSupervisor final {
    static SetupCompletionAuthority execute(
        SetupWorkerSelectionAuthority&&,
        FrozenTwoRunPlanAuthority&&,
        std::string_view fresh_output_directory);
    friend class SourceOwnedBoundedSetupLauncher;
    friend class BoundedSetupTestFixture;
};

struct BoundedSetupSourceStatus final {
    bool exact_output_closure_bound{};
    bool exact_aggregate_closure_bound{};
    bool exact_two_run_plan_abi{};
    bool pre_setup_only_plan_abi{};
    bool post_setup_artifacts_excluded{};
    bool dedicated_process_per_circuit{};
    bool source_closed_static_worker_required{};
    bool aggregate_sources_fd_bound{};
    bool fd_only_parameter_outputs{};
    bool network_core_swap_policy_mechanism{};
    bool finite_memory_and_disk_guard_mechanism{};
    bool source_owned_worker_selector{};
    bool source_owned_plan_selector{};
    bool typed_w1_pre_setup_handoff{};
    bool typed_w1_post_setup_measured_key_join{};
    bool actual_fd_setup_worker{};
    bool full_output_setup_executed{};
    bool full_aggregate_setup_executed{};
    bool setup_honesty_or_erasure_proven{};
    bool s4_selected{};
    bool s12_selected{};
    bool configured{};
};

inline constexpr BoundedSetupSourceStatus kBoundedSetupSourceStatus{
    .exact_output_closure_bound = true,
    .exact_aggregate_closure_bound = true,
    .exact_two_run_plan_abi = true,
    .pre_setup_only_plan_abi = true,
    .post_setup_artifacts_excluded = true,
    .dedicated_process_per_circuit = true,
    .source_closed_static_worker_required = true,
    .aggregate_sources_fd_bound = true,
    .fd_only_parameter_outputs = true,
    .network_core_swap_policy_mechanism = true,
    .finite_memory_and_disk_guard_mechanism = true,
    .source_owned_worker_selector = true,
    .source_owned_plan_selector = false,
    .typed_w1_pre_setup_handoff = false,
    .typed_w1_post_setup_measured_key_join = false,
    .actual_fd_setup_worker = true,
    .full_output_setup_executed = false,
    .full_aggregate_setup_executed = false,
    .setup_honesty_or_erasure_proven = false,
    .s4_selected = false,
    .s12_selected = false,
    .configured = false,
};

#ifdef KPB_BOUNDED_SETUP_TEST_SETUP
class BoundedSetupTestFixture final {
public:
    static Digest digest(std::string_view hex);
    static FrozenSetupPlanBinding pre_setup_plan(Digest trial);
    static CircuitClosureReceipt output_closure();
    static CircuitClosureReceipt aggregate_closure();
    static FrozenTwoRunPlanAuthority freeze_plan(
        FrozenSetupPlanBinding,
        CircuitClosureReceipt output, CircuitClosureReceipt aggregate);
    static SetupWorkerSelectionAuthority select_worker(
        std::string_view executable, Digest expected_identity);
    static SetupCompletionAuthority execute(
        SetupWorkerSelectionAuthority&& worker,
        FrozenTwoRunPlanAuthority&& plan,
        std::string_view fresh_output_directory);
};
#endif

} // namespace kpb::bounded_setup
