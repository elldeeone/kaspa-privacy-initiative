#pragma once

// Chronology-correct registered adapter for C1 contact/value capture.
//
// This module deliberately does not parse lifecycle JSON and does not accept
// operation IDs, contacts, route digests, or terminal claims as prepare()
// arguments.  Those values can enter only through opaque source authorities.
// Source-owned minter cores exist in c1_registered_plan_route_minters.*, but
// the selected controller/launcher callsites are still absent.  The source
// status therefore remains unconfigured and no actual receipt can be emitted.
//
// KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP is a legacy/synthetic control build,
// never a selected production build.  No authority or receipt produced in
// that build is eligible as actual evidence.  Production controls compile the
// bridge/minter objects with the macro absent and verify that no fixture or
// test-mint symbol is present.

#include "c1_contact_value_authority.hpp"
#include "c1_registered_plan_route_bridge_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace kpb::measurement::c1_capture {

enum class C1ControllerStage : std::uint8_t;
class C1ControllerSelectionSourceAuthority;
class C1Fd31OfferParseSourceAuthority;
class C1ControllerTerminalSourceAuthority;
class C1ObservedRouteSourceAuthority;
class C1Fd31CompletionSourceAuthority;
class RegisteredC1RoundLineageAuthority;
class RegisteredC1ControllerSelectionCallsite;
class RegisteredC1SelectedRound;
class RegisteredC1SelectedLaunchCallsite;
class RegisteredC1TerminalCallsite;
class RegisteredC1TerminalAdmissionSplit;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
// The macro is caller-controlled, so this test-only friend must also be a
// complete, non-extensible type in the first header that grants friendship.
// Otherwise a hostile translation unit can define the exact fixture name and
// use that friendship to extract a pending production residual.
class RegisteredC1RouteMinterTestFixture final {
    RegisteredC1RouteMinterTestFixture() = delete;
public:
    static C1ControllerSelectionSourceAuthority selection_source(
        RegisteredC1ControllerSelectionCallsite&,
        C1ControllerStage, std::string operation_id,
        int controller_selection_fd);
    static C1Fd31OfferParseSourceAuthority fd31_parse_source(
        RegisteredC1TerminalCallsite&);
    static C1ControllerTerminalSourceAuthority terminal_source(
        RegisteredC1TerminalCallsite&, C1ControllerStage,
        int controller_result_fd, int normalized_worker_exit_code);
    static C1ObservedRouteSourceAuthority route_source(
        RegisteredC1TerminalCallsite&, unsigned source_owner_component,
        int observed_route_fd, int normalized_worker_exit_code = 0);
    static C1Fd31CompletionSourceAuthority completion_source(
        RegisteredC1TerminalCallsite&,
        int normalized_supervisor_exit_code = 0,
        unsigned observed_retry_count = 0);
};
#endif

// These privileged callsite types must be complete before any authority grants
// friendship to them.  A mere forward declaration lets an unrelated
// translation unit include this header, define the exact friend name, and
// acquire the private authority state.  Their pimpls keep the implementation
// opaque while the complete class definitions make those names non-redefinable.
class RegisteredC1RuntimeCallsiteBridge final {
    RegisteredC1RuntimeCallsiteBridge() = delete;
public:
    static RegisteredC1ControllerSelectionCallsite
    begin_controller_selection(
        RegisteredC1RoundLineageAuthority&&,
        std::string capture_identity);

    static RegisteredC1SelectedLaunchCallsite prepare_selected(
        producer_runtime::ParentTenReadEndsAuthority&,
        RegisteredC1SelectedRound&&);
};

class RegisteredC1ControllerSelectionCallsite final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredC1ControllerSelectionCallsite(
        std::unique_ptr<Storage>);
    friend class RegisteredC1RuntimeCallsiteBridge;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    friend class RegisteredC1RouteMinterTestFixture;
#endif
public:
    RegisteredC1ControllerSelectionCallsite(
        const RegisteredC1ControllerSelectionCallsite&) = delete;
    RegisteredC1ControllerSelectionCallsite& operator=(
        const RegisteredC1ControllerSelectionCallsite&) = delete;
    RegisteredC1ControllerSelectionCallsite(
        RegisteredC1ControllerSelectionCallsite&&) noexcept;
    RegisteredC1ControllerSelectionCallsite& operator=(
        RegisteredC1ControllerSelectionCallsite&&) = delete;
    ~RegisteredC1ControllerSelectionCallsite();

    void observe_selected_stage(C1ControllerSelectionSourceAuthority&&);
    RegisteredC1SelectedRound finish() &&;
};

class RegisteredC1SelectedLaunchCallsite final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredC1SelectedLaunchCallsite(std::unique_ptr<Storage>);
    friend class RegisteredC1RuntimeCallsiteBridge;
public:
    RegisteredC1SelectedLaunchCallsite(
        const RegisteredC1SelectedLaunchCallsite&) = delete;
    RegisteredC1SelectedLaunchCallsite& operator=(
        const RegisteredC1SelectedLaunchCallsite&) = delete;
    RegisteredC1SelectedLaunchCallsite(
        RegisteredC1SelectedLaunchCallsite&&) noexcept;
    RegisteredC1SelectedLaunchCallsite& operator=(
        RegisteredC1SelectedLaunchCallsite&&) = delete;
    ~RegisteredC1SelectedLaunchCallsite();

    C1ContactValueOfferAuthority take_fd31_offer();
    RegisteredC1TerminalCallsite take_terminal_callsite();
};

class RegisteredC1TerminalCallsite final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredC1TerminalCallsite(std::unique_ptr<Storage>);
    friend class RegisteredC1SelectedLaunchCallsite;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    friend class RegisteredC1RouteMinterTestFixture;
#endif
public:
    RegisteredC1TerminalCallsite(
        const RegisteredC1TerminalCallsite&) = delete;
    RegisteredC1TerminalCallsite& operator=(
        const RegisteredC1TerminalCallsite&) = delete;
    RegisteredC1TerminalCallsite(RegisteredC1TerminalCallsite&&) noexcept;
    RegisteredC1TerminalCallsite& operator=(
        RegisteredC1TerminalCallsite&&) = delete;
    ~RegisteredC1TerminalCallsite();

    void observe_fd31_offer_parse(C1Fd31OfferParseSourceAuthority&&);
    void observe_controller_terminal(C1ControllerTerminalSourceAuthority&&);
    void observe_route_artifact(C1ObservedRouteSourceAuthority&&);
    void observe_authenticated_completion(
        C1Fd31CompletionSourceAuthority&&);
    RegisteredC1TerminalAdmissionSplit finish() &&;
};

// Exact registered/P1/public provenance copied into one round-scoped child by
// split_registered_prelaunch().  Plain instances are data, never authority.
struct PublicRegisteredC1RoundLineage final {
    Classification classification{};
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    Digest registered_prelaunch_identity{};
    Digest comparison_selection{};
    Digest run_selection{};
    Digest trial{};
    Digest measurement_attempt{};
    Digest measurement_cohort{};
    Digest capture{};
    Digest method{};
    Digest workload{};
    Digest source_closure{};
    Digest runtime{};
    FiniteManifestBinding finite_manifest;
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest capture_source{};
    Digest capture_build{};
    Digest capture_runtime{};
    Digest capture_launcher{};
    WorkerBinding observer_worker;
    WorkerBinding score_worker;
    WorkerBinding aggregate_worker;
    Digest financial_run{};
    Digest round_attempt{};
    Digest round_cohort{};
    Digest round_capture_plan{};
    Digest process_reservation_identity{};
    Digest persistent_process_session_identity{};
    Digest fork_plan_identity{};
    Digest route_capability_identity{};
    Digest producer_process_identity{};
    Digest role_closure_identity{};
    Digest manifest_seal{};
    ConstructionPolicy construction_policy{};
    Digest construction_classification_receipt{};
    Digest c1_process_identity{};
    Digest c1_expected_exit_policy_identity{};
};

class RegisteredC1RoundLineageAuthority final {
    PublicRegisteredC1RoundLineage value_;
    std::atomic_bool live_{true};
    explicit RegisteredC1RoundLineageAuthority(
        PublicRegisteredC1RoundLineage);
    friend class RegisteredC1PlanRouteBridge;
    friend class RegisteredC1ControllerSelectionCallsite;
    friend class RegisteredC1RuntimeCallsiteBridge;
public:
    RegisteredC1RoundLineageAuthority(
        const RegisteredC1RoundLineageAuthority&) = delete;
    RegisteredC1RoundLineageAuthority& operator=(
        const RegisteredC1RoundLineageAuthority&) = delete;
    RegisteredC1RoundLineageAuthority(
        RegisteredC1RoundLineageAuthority&&) noexcept;
    RegisteredC1RoundLineageAuthority& operator=(
        RegisteredC1RoundLineageAuthority&&) = delete;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    static RegisteredC1RoundLineageAuthority test_only_mint(
        PublicRegisteredC1RoundLineage);
#endif
};

// Pimpl keeps the registered producer authority opaque here and preserves its
// existing selected-parent consumer.  The two C1 children are one-use.
class RegisteredC1PrelaunchSplit final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredC1PrelaunchSplit(std::unique_ptr<Storage>);
    friend class RegisteredC1PlanRouteBridge;
public:
    RegisteredC1PrelaunchSplit(const RegisteredC1PrelaunchSplit&) = delete;
    RegisteredC1PrelaunchSplit& operator=(
        const RegisteredC1PrelaunchSplit&) = delete;
    RegisteredC1PrelaunchSplit(RegisteredC1PrelaunchSplit&&) noexcept;
    RegisteredC1PrelaunchSplit& operator=(
        RegisteredC1PrelaunchSplit&&) = delete;
    ~RegisteredC1PrelaunchSplit();

    kpi::mpc::financial::registered_driver::
        RegisteredSelectedProducerPrelaunchBindingAuthority
        take_registered_prelaunch();
    RegisteredC1RoundLineageAuthority take_round(unsigned round);
};

// Accepted before any owner operation starts.  A future source-owned
// controller adapter must mint this from its accepted selection; there is no
// production constructor, raw-data factory, or JSON/path overload today.
struct PublicC1AcceptedControllerSelection final {
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    std::string capture_identity;
    std::array<std::string, 3> operation_ids{}; // invoice, pay, scan
    std::array<unsigned, 3> contact_owner_components{};
    Digest registered_prelaunch_identity{};
    Digest round_capture_plan_identity{};
    WorkerBinding generator_worker;
    std::array<Digest, 3> accepted_stage_selection_identities{};
    Digest accepted_selection_history_identity{};
};

class C1AcceptedControllerSelectionAuthority final {
    PublicC1AcceptedControllerSelection value_;
    Digest identity_{};
    std::atomic_bool live_{true};
    explicit C1AcceptedControllerSelectionAuthority(
        PublicC1AcceptedControllerSelection);
    friend class RegisteredC1PlanRouteBridge;
    friend class RegisteredC1ControllerSelectionCallsite;
    friend class RegisteredC1RuntimeCallsiteBridge;
public:
    C1AcceptedControllerSelectionAuthority(
        const C1AcceptedControllerSelectionAuthority&) = delete;
    C1AcceptedControllerSelectionAuthority& operator=(
        const C1AcceptedControllerSelectionAuthority&) = delete;
    C1AcceptedControllerSelectionAuthority(
        C1AcceptedControllerSelectionAuthority&&) noexcept;
    C1AcceptedControllerSelectionAuthority& operator=(
        C1AcceptedControllerSelectionAuthority&&) = delete;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    static C1AcceptedControllerSelectionAuthority test_only_mint(
        PublicC1AcceptedControllerSelection);
#endif
};

// The ordinary C1 residual is withheld until terminal controller and observed
// route histories are consumed.  This prevents a prelaunch plan from being
// mistaken for actual execution evidence.
class RegisteredC1PendingTerminalAuthority final {
    std::optional<C1PostcaptureAdmissionAuthority> residual_;
    PublicC1AcceptedControllerSelection selection_;
    Digest selection_identity_{};
    Digest expected_projection_identity_{};
    WorkerBinding expected_validator_worker_;
    Digest expected_contact_value_authority_identity_{};
    Digest expected_offer_file_sha256_{};
    std::uint64_t expected_offer_device_{};
    std::uint64_t expected_offer_inode_{};
    Digest expected_c1_process_identity_{};
    Digest expected_c1_exit_policy_identity_{};
    std::atomic_bool live_{true};
    RegisteredC1PendingTerminalAuthority(
        C1PostcaptureAdmissionAuthority&&,
        PublicC1AcceptedControllerSelection, Digest, Digest,
        WorkerBinding, Digest, Digest, std::uint64_t, std::uint64_t,
        Digest, Digest);
    friend class RegisteredC1PlanRouteBridge;
    friend class RegisteredC1TerminalCallsite;
public:
    RegisteredC1PendingTerminalAuthority(
        const RegisteredC1PendingTerminalAuthority&) = delete;
    RegisteredC1PendingTerminalAuthority& operator=(
        const RegisteredC1PendingTerminalAuthority&) = delete;
    RegisteredC1PendingTerminalAuthority(
        RegisteredC1PendingTerminalAuthority&&) noexcept;
    RegisteredC1PendingTerminalAuthority& operator=(
        RegisteredC1PendingTerminalAuthority&&) = delete;
};

// Source-owned proof that the exact sealed offer coupled to the pending
// residual was actually read from FD31 and completed before EOF/exit.  A
// future selected C1 supervisor/runtime join must mint this authority; there
// is deliberately no production constructor or receipt factory here.
struct PublicC1Fd31QualifiedCompletionAck final {
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    std::string capture_identity;
    std::array<std::string, 3> operation_ids{};
    std::array<unsigned, 3> contact_owner_components{};
    Digest registered_prelaunch_identity{};
    Digest round_capture_plan_identity{};
    Digest accepted_selection_identity{};
    Digest contact_value_authority_identity{};
    Digest offer_file_sha256{};
    std::uint64_t offer_device{};
    std::uint64_t offer_inode{};
    std::uint64_t offer_byte_count{};
    unsigned fixed_fd{};
    Digest c1_process_identity{};
    Digest expected_exit_policy_identity{};
    WorkerBinding supervisor_worker;
    Digest exact_offer_parse_identity{};
    Digest authenticated_completion_identity{};
    Digest writer_close_identity{};
    Digest eof_identity{};
    Digest exit_join_identity{};
    std::uint64_t offer_parse_monotonic_ns{};
    std::uint64_t completion_ack_monotonic_ns{};
    std::uint64_t writer_close_monotonic_ns{};
    std::uint64_t eof_monotonic_ns{};
    std::uint64_t exit_join_monotonic_ns{};
    bool exact_fd31_read{};
    bool fallback_offer_absent{};
    bool authenticated_completion{};
    bool writer_closed{};
    bool eof_observed{};
    bool expected_exit_observed{};
};

class C1Fd31QualifiedCompletionAckAuthority final {
    PublicC1Fd31QualifiedCompletionAck value_;
    std::atomic_bool live_{true};
    explicit C1Fd31QualifiedCompletionAckAuthority(
        PublicC1Fd31QualifiedCompletionAck);
    friend class RegisteredC1PlanRouteBridge;
    friend class RegisteredC1TerminalCallsite;
public:
    C1Fd31QualifiedCompletionAckAuthority(
        const C1Fd31QualifiedCompletionAckAuthority&) = delete;
    C1Fd31QualifiedCompletionAckAuthority& operator=(
        const C1Fd31QualifiedCompletionAckAuthority&) = delete;
    C1Fd31QualifiedCompletionAckAuthority(
        C1Fd31QualifiedCompletionAckAuthority&&) noexcept;
    C1Fd31QualifiedCompletionAckAuthority& operator=(
        C1Fd31QualifiedCompletionAckAuthority&&) = delete;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    static C1Fd31QualifiedCompletionAckAuthority test_only_mint(
        PublicC1Fd31QualifiedCompletionAck);
#endif
};

class RegisteredC1LaunchSplit final {
    std::optional<C1ContactValueOfferAuthority> offer_;
    std::optional<RegisteredC1PendingTerminalAuthority> pending_;
    RegisteredC1LaunchSplit(
        C1ContactValueOfferAuthority&&,
        RegisteredC1PendingTerminalAuthority&&);
    friend class RegisteredC1PlanRouteBridge;
public:
    RegisteredC1LaunchSplit(const RegisteredC1LaunchSplit&) = delete;
    RegisteredC1LaunchSplit& operator=(
        const RegisteredC1LaunchSplit&) = delete;
    RegisteredC1LaunchSplit(RegisteredC1LaunchSplit&&) noexcept = default;
    RegisteredC1LaunchSplit& operator=(
        RegisteredC1LaunchSplit&&) = delete;

    C1ContactValueOfferAuthority take_offer();
    RegisteredC1PendingTerminalAuthority take_pending_terminal();
};

// Actual controller terminal history.  A retry is represented explicitly and
// is refused; absence of all three terminal results is also refused.
struct PublicC1AcceptedControllerResult final {
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    std::string capture_identity;
    std::array<std::string, 3> operation_ids{};
    Digest registered_prelaunch_identity{};
    Digest round_capture_plan_identity{};
    Digest accepted_selection_identity{};
    Digest fd31_authenticated_completion_identity{};
    std::array<Digest, 3> controller_result_identities{};
    Digest retry_history_identity{};
    Digest terminal_history_identity{};
    WorkerBinding generator_worker;
    unsigned completed_stage_count{};
    unsigned retry_count{};
};

class C1AcceptedControllerResultAuthority final {
    PublicC1AcceptedControllerResult value_;
    std::atomic_bool live_{true};
    explicit C1AcceptedControllerResultAuthority(
        PublicC1AcceptedControllerResult);
    friend class RegisteredC1PlanRouteBridge;
    friend class RegisteredC1TerminalCallsite;
public:
    C1AcceptedControllerResultAuthority(
        const C1AcceptedControllerResultAuthority&) = delete;
    C1AcceptedControllerResultAuthority& operator=(
        const C1AcceptedControllerResultAuthority&) = delete;
    C1AcceptedControllerResultAuthority(
        C1AcceptedControllerResultAuthority&&) noexcept;
    C1AcceptedControllerResultAuthority& operator=(
        C1AcceptedControllerResultAuthority&&) = delete;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    static C1AcceptedControllerResultAuthority test_only_mint(
        PublicC1AcceptedControllerResult);
#endif
};

struct PublicC1ObservedRouteArtifact final {
    unsigned source_owner_component{};
    unsigned target_owner_component{};
    std::string source_operation_id;
    std::string target_invoice_operation_id;
    Digest raw_bytes_sha256{};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t byte_count{};
    Digest record_identity{};
};

struct PublicC1ObservedInvoiceRoute final {
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    std::string capture_identity;
    std::array<std::string, 3> operation_ids{};
    std::array<unsigned, 3> contact_owner_components{};
    Digest registered_prelaunch_identity{};
    Digest round_capture_plan_identity{};
    Digest accepted_selection_identity{};
    Digest fd31_authenticated_completion_identity{};
    Digest invoice_result_identity{};
    Digest pay_result_identity{};
    std::array<PublicC1ObservedRouteArtifact, 3> route_artifacts{};
    Digest retry_history_identity{};
    Digest terminal_history_identity{};
    Digest projection_identity{};
    WorkerBinding generator_worker;
    WorkerBinding validator_worker;
    std::array<int, 3> worker_returncodes{};
};

class C1ObservedInvoiceRouteAuthority final {
    PublicC1ObservedInvoiceRoute value_;
    std::atomic_bool live_{true};
    explicit C1ObservedInvoiceRouteAuthority(
        PublicC1ObservedInvoiceRoute);
    friend class RegisteredC1PlanRouteBridge;
    friend class RegisteredC1TerminalCallsite;
public:
    C1ObservedInvoiceRouteAuthority(
        const C1ObservedInvoiceRouteAuthority&) = delete;
    C1ObservedInvoiceRouteAuthority& operator=(
        const C1ObservedInvoiceRouteAuthority&) = delete;
    C1ObservedInvoiceRouteAuthority(
        C1ObservedInvoiceRouteAuthority&&) noexcept;
    C1ObservedInvoiceRouteAuthority& operator=(
        C1ObservedInvoiceRouteAuthority&&) = delete;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    static C1ObservedInvoiceRouteAuthority test_only_mint(
        PublicC1ObservedInvoiceRoute);
#endif
};

struct RegisteredC1PlanRouteSourceStatus final {
    std::string schema;
    std::string status;
    bool registered_prelaunch_split_core{};
    bool exact_p1_c1_public_provenance{};
    bool controller_selection_authority_type{};
    bool fd31_completion_ack_authority_type{};
    bool observed_route_terminal_authority_type{};
    bool distinct_generator_validator_provenance{};
    bool exact_route_artifact_file_binding{};
    bool stage_plan_route_compiler_core{};
    bool parent_round_burns_before_validation{};
    bool sealed_offer_withheld_terminal_residual{};
    bool retry_and_terminal_history_required{};
    bool archive_observer_admission_join_exists{};
    bool caller_event_or_digest_factory{};
    bool immutable_sealed_source_snapshot_core{};
    bool opaque_source_controller_selection_minter_core{};
    bool opaque_source_fd31_completion_ack_minter_core{};
    bool opaque_source_controller_terminal_minter_core{};
    bool opaque_source_observed_route_minter_core{};
    bool production_controller_selection_minter{};
    bool production_fd31_completion_ack_minter{};
    bool production_controller_terminal_minter{};
    bool production_observed_route_minter{};
    bool production_two_round_route_evidence_minter{};
    bool typed_launcher_terminal_callsite_contract_core{};
    bool two_round_route_evidence_join_core{};
    bool exact_launcher_terminal_callsite_contract{};
    bool fail_closed_two_round_route_join{};
    bool selected_launcher_consumes_offer{};
    bool selected_terminal_admission_callsite{};
    bool selected_two_round_route_callsite{};
    bool selected_consumer_uses_same_source_snapshot{};
    bool owner_truth_input{};
    bool actual_receipt_emitted{};
    bool configured{};
    bool actual_launch{};
    bool complete{};
};

RegisteredC1PlanRouteSourceStatus registered_c1_plan_route_source_status();

} // namespace kpb::measurement::c1_capture
