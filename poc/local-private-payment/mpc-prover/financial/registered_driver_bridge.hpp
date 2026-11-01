#pragma once

// Source-only authority bridge for ADR-0083. This module binds the parent
// supervisor's one-shot approval to one fixed driver/capture selection. It is
// not a configured driver and cannot launch MPC or mint an actual capture.

#include "registered_attempt_supervisor.hpp"
#include "registered_capture_plan_roster_bridge_contract.hpp"
#include "docker_monotonic_anchor_client.hpp"
#include "registered_parent_bootstrap_contract.hpp"
#include "registered_party_completion_transport.hpp"
#include "registered_full_cohort_release_barrier_contract.hpp"
#include "financial_history_access_contract.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <filesystem>
#include <memory>
#include <span>
#include <string>

namespace kpi::mpc { class MascotContext; struct OwnerInputContract; }
namespace kpi::mpc::history {
struct AttemptBinding;
class LockedAttempt;
class EgressRelease;
}

namespace kpi::mpc::financial {
class AcceptedFinancialHead;
class FinancialConstruction;
class RegisteredService;

namespace registered_driver {

using Digest = identity_registry::Digest;
class RegisteredCaptureSession;
class CapturePlanAuthorityBridge;
class P1CapturePlanSplit;
class RegisteredConstructionAuthorityBridge;
class VerifiedEgressAuthorityBridge;

struct PublicDriverSelection {
    unsigned role{};
    Digest authority_identity{};
    Digest selection_identity{};
    Digest service_identity{};
    Digest source_identity{};
    Digest build_identity{};
    Digest roster_identity{};
    Digest capture_source_identity{};
    Digest capture_build_identity{};
    Digest capture_launcher_identity{};
    Digest model_preimage_identity{};
    Digest query_store_preimage_identity{};
    Digest scalar_capture_manifest_identity{};
    int owner_port{};
    std::size_t multiplication_batch{};
};

class CompiledDriverSelection final {
    PublicDriverSelection value_;
    Digest identity_;
    explicit CompiledDriverSelection(PublicDriverSelection);
    friend class attempt_supervisor::RegisteredProposalBridge;
    friend class DriverAttempt;
    friend class CapturePlanAuthorityBridge;
    friend class RegisteredParentBootstrapTransport;
public:
    const PublicDriverSelection& public_selection() const { return value_; }
    const Digest& identity() const { return identity_; }
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static CompiledDriverSelection test_only_mint(PublicDriverSelection);
#endif
};

struct PublicCompiledFreshAttempt {
    unsigned role{};
    Digest authority_identity{};
    Digest run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest service_identity{};
    Digest source_identity{};
    Digest build_identity{};
    Digest driver_selection_identity{};
};

// Emitted only by the fixed selected configuration after compiling a fresh
// lineage. A receipt cannot reconstruct this one-shot capability.
class CompiledFreshAttemptAuthority final {
    PublicCompiledFreshAttempt value_;
    std::atomic_bool live_{true};
    explicit CompiledFreshAttemptAuthority(PublicCompiledFreshAttempt);
    friend class attempt_supervisor::RegisteredProposalBridge;
    friend class RegisteredParentBootstrapTransport;
public:
    CompiledFreshAttemptAuthority(const CompiledFreshAttemptAuthority&) = delete;
    CompiledFreshAttemptAuthority& operator=(
        const CompiledFreshAttemptAuthority&) = delete;
    CompiledFreshAttemptAuthority(CompiledFreshAttemptAuthority&&) noexcept;
    CompiledFreshAttemptAuthority& operator=(
        CompiledFreshAttemptAuthority&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static CompiledFreshAttemptAuthority test_only_mint(
        PublicCompiledFreshAttempt);
#endif
};

struct PublicAuthenticatedPartyDelivery {
    unsigned role{};
    Digest authority_identity{};
    Digest supervisor_session{};
    Digest party_session{};
    Digest service_identity{};
    Digest driver_selection_identity{};
};

// The sealed parent-fork bridge converts a kernel-authenticated child delivery.
// The selected production plan factory/callsite remains deliberately absent.
class AuthenticatedPartyDeliveryAuthority final {
    PublicAuthenticatedPartyDelivery value_;
    std::atomic_bool live_{true};
    explicit AuthenticatedPartyDeliveryAuthority(
        PublicAuthenticatedPartyDelivery);
    friend class attempt_supervisor::RegisteredProposalBridge;
public:
    AuthenticatedPartyDeliveryAuthority(
        const AuthenticatedPartyDeliveryAuthority&) = delete;
    AuthenticatedPartyDeliveryAuthority& operator=(
        const AuthenticatedPartyDeliveryAuthority&) = delete;
    AuthenticatedPartyDeliveryAuthority(
        AuthenticatedPartyDeliveryAuthority&&) noexcept;
    AuthenticatedPartyDeliveryAuthority& operator=(
        AuthenticatedPartyDeliveryAuthority&&) = delete;
    const PublicAuthenticatedPartyDelivery& public_receipt() const {
        return value_;
    }
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static AuthenticatedPartyDeliveryAuthority test_only_mint(
        PublicAuthenticatedPartyDelivery);
#endif
};

struct PublicOuterSupervisorSelection {
    std::filesystem::path registry_journal_directory;
    std::filesystem::path registry_anchor_directory;
    identity_registry::Authority registry_authority;
    docker_anchor::PublicConfiguration docker_anchor;
    Digest anchor_policy_identity{};
    Digest supervisor_session{};
};

class CompiledOuterSupervisorSelection final {
    PublicOuterSupervisorSelection value_;
    std::atomic_bool live_{true};
    explicit CompiledOuterSupervisorSelection(PublicOuterSupervisorSelection);
    friend class attempt_supervisor::RegisteredProposalBridge;
public:
    CompiledOuterSupervisorSelection(
        const CompiledOuterSupervisorSelection&) = delete;
    CompiledOuterSupervisorSelection& operator=(
        const CompiledOuterSupervisorSelection&) = delete;
    CompiledOuterSupervisorSelection(
        CompiledOuterSupervisorSelection&&) noexcept;
    CompiledOuterSupervisorSelection& operator=(
        CompiledOuterSupervisorSelection&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static CompiledOuterSupervisorSelection test_only_mint(
        PublicOuterSupervisorSelection);
#endif
};

// Member order is the lifetime proof: registry, then anchor, then supervisor.
// Destruction runs in reverse, so Supervisor can never outlive Registry.
class OuterSupervisorAuthority final {
    std::unique_ptr<identity_registry::Registry> registry_;
    std::shared_ptr<docker_anchor::Client> anchor_;
    std::unique_ptr<attempt_supervisor::Supervisor> supervisor_;
    OuterSupervisorAuthority(
        std::unique_ptr<identity_registry::Registry>,
        std::shared_ptr<docker_anchor::Client>,
        std::unique_ptr<attempt_supervisor::Supervisor>);
    friend class attempt_supervisor::RegisteredProposalBridge;
    friend class RegisteredSupervisorParentTransport;
public:
    OuterSupervisorAuthority(const OuterSupervisorAuthority&) = delete;
    OuterSupervisorAuthority& operator=(const OuterSupervisorAuthority&) = delete;
    OuterSupervisorAuthority(OuterSupervisorAuthority&&) = delete;
    OuterSupervisorAuthority& operator=(OuterSupervisorAuthority&&) = delete;
    void submit(const attempt_supervisor::Proposal&);
    bool ready() const;
    attempt_supervisor::ApprovalBatch approve(
        identity_registry::FailureOnlyHook = {},
        attempt_supervisor::Supervisor::SupervisorFailureOnlyHook = {});
};

enum class CaptureClassification : std::uint8_t {
    HiddenCandidate = 1,
    ExplicitOwnerPublicEffectsBaseline = 2,
};

struct PublicCapturePlan {
    CaptureClassification classification{};
    unsigned round{};
    std::string capture_trial_id;
    std::string capture_attempt_id;
    std::string capture_identity;
    Digest run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest source_identity{};
    Digest build_identity{};
    Digest launcher_identity{};
    Digest model_preimage_identity{};
    Digest query_store_preimage_identity{};
    Digest scalar_capture_manifest_identity{};
    std::array<int, 10> fixed_fds{};
};

class CapturePlanAuthority final {
    enum class Scope : std::uint8_t { Parent = 1, SessionResidual = 2 };
    PublicCapturePlan value_;
    Digest identity_;
    Scope scope_{Scope::Parent};
    unsigned computing_role_{3};
    std::atomic_bool live_{true};
    explicit CapturePlanAuthority(PublicCapturePlan);
    CapturePlanAuthority(PublicCapturePlan, Scope, unsigned computing_role);
    friend class DriverAttempt;
    friend class CapturePlanAuthorityBridge;
    friend class RegisteredCapturePlanRosterBridge;
    friend class RegisteredParentBootstrapTransport;
public:
    CapturePlanAuthority(const CapturePlanAuthority&) = delete;
    CapturePlanAuthority& operator=(const CapturePlanAuthority&) = delete;
    CapturePlanAuthority(CapturePlanAuthority&&) noexcept;
    CapturePlanAuthority& operator=(CapturePlanAuthority&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static CapturePlanAuthority test_only_mint(PublicCapturePlan);
    static CapturePlanAuthority test_only_session_residual(
        PublicCapturePlan, unsigned computing_role);
#endif
};

// A session burns a genuine plan through this concrete definition. External
// code cannot gain private access by defining a forward-declared friend name.
struct ConsumedCapturePlan {
    PublicCapturePlan value;
    Digest identity;
};

class CapturePlanAuthorityBridge final {
    static void require_valid(const CapturePlanAuthority&);
    static void require_valid(const CompiledDriverSelection&);
    friend class RegisteredCapturePlanRosterBridge;
public:
    static P1CapturePlanSplit split_for_driver(
        CapturePlanAuthority&&, const CompiledDriverSelection&);
    static ConsumedCapturePlan consume_session(
        CapturePlanAuthority&&, unsigned computing_role);
};

struct PublicAuthorizedAttempt {
    unsigned role{};
    unsigned round{};
    CaptureClassification classification{};
    std::string capture_trial_id;
    Digest authority_identity{};
    Digest driver_selection_identity{};
    Digest selection_identity{};
    Digest run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest accepted_head{};
    Digest postlock_accepted_head{};
    Digest attempt_identity{};
    Digest proposal_identity{};
    Digest durable_lock{};
    std::array<Digest, 3> owner_contracts{};
    Digest capture_plan_identity{};
    Digest capture_source_identity{};
    Digest capture_build_identity{};
    Digest capture_launcher_identity{};
    Digest authorization_identity{};
};

struct PublicVerifiedEgress {
    Digest binding_identity{};
    Digest effects_identity{};
    Digest core_identity{};
    Digest proof_identity{};
    Digest projection_identity{};
};

class VerifiedEgressAuthority final {
    PublicVerifiedEgress value_;
    std::atomic_bool live_{true};
    explicit VerifiedEgressAuthority(PublicVerifiedEgress);
    friend class AuthorizedDriverAttempt;
    friend class VerifiedEgressAuthorityBridge;
public:
    VerifiedEgressAuthority(const VerifiedEgressAuthority&) = delete;
    VerifiedEgressAuthority& operator=(const VerifiedEgressAuthority&) = delete;
    VerifiedEgressAuthority(VerifiedEgressAuthority&&) noexcept;
    VerifiedEgressAuthority& operator=(VerifiedEgressAuthority&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static VerifiedEgressAuthority test_only_mint(PublicVerifiedEgress);
#endif
};

// The only production mint accepts a genuine durable EgressRelease object.
// There is no digest/JSON overload and this friend is fully defined here.
class VerifiedEgressAuthorityBridge final {
public:
    static VerifiedEgressAuthority from_release(
        const history::EgressRelease&);
};

struct PublicPartyReleaseReady {
    PublicAuthorizedAttempt attempt;
    PublicVerifiedEgress egress;
    Digest readiness_identity{};
};

struct PublicPartyDriverCompletion;

// Minted exactly once from the live authorized attempt plus its genuine
// durable EGRESS authority. It is transported only over the retained
// authenticated role channel; there is no digest or receipt constructor.
class PartyReleaseReadyAuthority final {
    PublicPartyReleaseReady value_;
    std::atomic_bool live_{true};
    explicit PartyReleaseReadyAuthority(PublicPartyReleaseReady);
    friend class AuthorizedDriverAttempt;
    friend class RegisteredFullCohortReleaseBarrier;
public:
    PartyReleaseReadyAuthority(const PartyReleaseReadyAuthority&) = delete;
    PartyReleaseReadyAuthority& operator=(
        const PartyReleaseReadyAuthority&) = delete;
    PartyReleaseReadyAuthority(PartyReleaseReadyAuthority&&) noexcept;
    PartyReleaseReadyAuthority& operator=(
        PartyReleaseReadyAuthority&&) = delete;
#ifdef KPI_REGISTERED_FULL_COHORT_RELEASE_BARRIER_TEST_SETUP
    static PartyReleaseReadyAuthority test_only_mint(
        PublicAuthorizedAttempt, PublicVerifiedEgress);
#endif
};

class PartyReleaseAuthorizationAuthority final {
    PublicAuthorizedAttempt attempt_;
    PublicVerifiedEgress egress_;
    Digest readiness_identity_{};
    Digest barrier_identity_{};
    std::uint64_t barrier_monotonic_ns_{};
    std::atomic_bool live_{true};
    PartyReleaseAuthorizationAuthority(
        PublicAuthorizedAttempt, PublicVerifiedEgress, Digest, Digest,
        std::uint64_t);
    friend class AuthorizedDriverAttempt;
    friend class RegisteredFullCohortReleaseBarrier;
public:
    PartyReleaseAuthorizationAuthority(
        const PartyReleaseAuthorizationAuthority&) = delete;
    PartyReleaseAuthorizationAuthority& operator=(
        const PartyReleaseAuthorizationAuthority&) = delete;
    PartyReleaseAuthorizationAuthority(
        PartyReleaseAuthorizationAuthority&&) noexcept;
    PartyReleaseAuthorizationAuthority& operator=(
        PartyReleaseAuthorizationAuthority&&) = delete;
#ifdef KPI_REGISTERED_FULL_COHORT_RELEASE_BARRIER_TEST_SETUP
    void test_only_bind_completion(PublicPartyDriverCompletion&);
#endif
};

struct PublicPartyDriverCompletion {
    unsigned role{};
    unsigned round{};
    CaptureClassification classification{};
    std::string capture_trial_id;
    Digest authority_identity{};
    Digest driver_selection_identity{};
    Digest selection_identity{};
    Digest run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest accepted_head{};
    Digest postlock_accepted_head{};
    Digest attempt_identity{};
    Digest proposal_identity{};
    Digest durable_lock{};
    std::array<Digest, 3> owner_contracts{};
    Digest capture_plan_identity{};
    Digest capture_source_identity{};
    Digest capture_build_identity{};
    Digest capture_launcher_identity{};
    Digest authorization_identity{};
    Digest egress_binding_identity{};
    Digest effects_identity{};
    Digest core_identity{};
    Digest proof_identity{};
    Digest projection_identity{};
    Digest full_cohort_barrier_identity{};
    std::uint64_t full_cohort_barrier_observed_monotonic_ns{};
    Digest completion_identity{};
};

// This is party-local durable-EGRESS authority only. It makes no claim about
// global capture stream closure. The outer capture supervisor must join all
// six party capabilities with the genuine ten-stream producer closure.
class PartyDriverCompletionAuthority final {
    PublicPartyDriverCompletion receipt_;
    std::atomic_bool live_{true};
    explicit PartyDriverCompletionAuthority(PublicPartyDriverCompletion);
    friend class AuthorizedDriverAttempt;
    friend class RegisteredPartyCompletionTransport;
#ifdef KPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP
    friend class RegisteredPartyCompletionTransportTestBridge;
#endif
public:
    PartyDriverCompletionAuthority(
        const PartyDriverCompletionAuthority&) = delete;
    PartyDriverCompletionAuthority& operator=(
        const PartyDriverCompletionAuthority&) = delete;
    PartyDriverCompletionAuthority(PartyDriverCompletionAuthority&&) noexcept;
    PartyDriverCompletionAuthority& operator=(
        PartyDriverCompletionAuthority&&) = delete;
    const PublicPartyDriverCompletion& public_receipt() const {
        return receipt_;
    }
};

class AuthorizedDriverAttempt final {
    enum class State {
        AwaitingIntake,
        IntakeConsumed,
        ReleaseReady,
        ReleaseAuthorized,
        Completed,
        Poisoned,
    };
    PublicAuthorizedAttempt receipt_;
    attempt_supervisor::OwnerIntakePermit permit_;
    std::unique_ptr<RegisteredCaptureSession> capture_session_;
    std::optional<attempt_supervisor::PublicIntakePermit> intake_;
    std::optional<PublicVerifiedEgress> verified_egress_;
    Digest full_cohort_barrier_identity_{};
    std::uint64_t full_cohort_barrier_monotonic_ns_{};
    std::mutex mutex_;
    State state_{State::AwaitingIntake};
    bool baseline_effects_claimed_{false};
    AuthorizedDriverAttempt(PublicAuthorizedAttempt,
                            attempt_supervisor::OwnerIntakePermit&&,
                            std::unique_ptr<RegisteredCaptureSession>);
    attempt_supervisor::PublicIntakePermit consume_owner_intake(unsigned);
    void claim_owner_intake(MascotContext&, history::LockedAttempt&,
                            const history::AttemptBinding&);
    PartyReleaseReadyAuthority begin_release_ready(
        VerifiedEgressAuthority&&);
    void authorize_release(PartyReleaseAuthorizationAuthority&&);
    void require_release_authorized();
    RegisteredCaptureSession& capture_session();
    friend class DriverAttempt;
    friend class RegisteredConstructionAuthorityBridge;
    friend class ::kpi::mpc::financial::FinancialHistoryAccess;
public:
    // A move-only proof that this exact registered attempt has reached party
    // durable EGRESS and selected the explicit baseline classification.
    class BaselineEffectsClaim final {
        PublicAuthorizedAttempt receipt_;
        std::atomic_bool live_{true};
        explicit BaselineEffectsClaim(PublicAuthorizedAttempt);
        friend class AuthorizedDriverAttempt;
    public:
        BaselineEffectsClaim(const BaselineEffectsClaim&) = delete;
        BaselineEffectsClaim& operator=(const BaselineEffectsClaim&) = delete;
        BaselineEffectsClaim(BaselineEffectsClaim&&) noexcept;
        BaselineEffectsClaim& operator=(BaselineEffectsClaim&&) = delete;
        PublicAuthorizedAttempt consume();
    };

    ~AuthorizedDriverAttempt();
    AuthorizedDriverAttempt(const AuthorizedDriverAttempt&) = delete;
    AuthorizedDriverAttempt& operator=(const AuthorizedDriverAttempt&) = delete;
    AuthorizedDriverAttempt(AuthorizedDriverAttempt&&) = delete;
    AuthorizedDriverAttempt& operator=(AuthorizedDriverAttempt&&) = delete;
    const PublicAuthorizedAttempt& public_receipt() const { return receipt_; }
    PartyDriverCompletionAuthority complete_egress();
    BaselineEffectsClaim claim_baseline_effects();
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    attempt_supervisor::PublicIntakePermit
    test_only_consume_owner_intake(unsigned role) {
        return consume_owner_intake(role);
    }
    void test_only_capture_lifecycle(
        std::span<const unsigned char> projection,
        std::size_t fixed_frame_bytes);
    void test_only_authorize_release(
        VerifiedEgressAuthority&&, Digest barrier_identity,
        std::uint64_t barrier_monotonic_ns);
#endif
};

class DriverAttempt final {
    enum class State { Admitted, HeadRechecked, Authorized, Poisoned };
    CompiledDriverSelection driver_;
    Digest capture_identity_;
    PublicCapturePlan capture_plan_;
    std::unique_ptr<RegisteredCaptureSession> capture_session_;
    attempt_supervisor::Proposal proposal_;
    std::optional<attempt_supervisor::PartyApproval> approval_;
    std::optional<attempt_supervisor::RegisteredFreshAttempt> fresh_;
    std::mutex mutex_;
    State state_{State::Admitted};
    DriverAttempt(CompiledDriverSelection, Digest, PublicCapturePlan,
                  std::unique_ptr<RegisteredCaptureSession>,
                  attempt_supervisor::Proposal,
                  attempt_supervisor::PartyApproval&&);
    static DriverAttempt admit_authority(
        CompiledDriverSelection, CapturePlanAuthority&&,
        attempt_supervisor::PartyApproval&&,
        const attempt_supervisor::Proposal&);
    void recheck_before_lock(
        attempt_supervisor::DirectAcceptedHeadCommitment&&);
    std::unique_ptr<AuthorizedDriverAttempt> after_durable_lock(
        attempt_supervisor::DirectAcceptedHeadCommitment&&,
        attempt_supervisor::DurableLockCommitment&&);
    const PublicDriverSelection& selected_driver() const;
    const attempt_supervisor::Proposal& proposal() const;
    friend class RegisteredConstructionAuthorityBridge;
public:
    ~DriverAttempt();
    DriverAttempt(const DriverAttempt&) = delete;
    DriverAttempt& operator=(const DriverAttempt&) = delete;
    DriverAttempt(DriverAttempt&&) = delete;
    DriverAttempt& operator=(DriverAttempt&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static DriverAttempt test_only_admit(
        CompiledDriverSelection selected, CapturePlanAuthority&& capture,
        attempt_supervisor::PartyApproval&& approval,
        const attempt_supervisor::Proposal& local) {
        return admit_authority(std::move(selected), std::move(capture),
                               std::move(approval), local);
    }
    void test_only_recheck_before_lock(
        attempt_supervisor::DirectAcceptedHeadCommitment&& head) {
        recheck_before_lock(std::move(head));
    }
    std::unique_ptr<AuthorizedDriverAttempt> test_only_after_durable_lock(
        attempt_supervisor::DirectAcceptedHeadCommitment&& head,
        attempt_supervisor::DurableLockCommitment&& lock) {
        return after_durable_lock(std::move(head), std::move(lock));
    }
#endif
};

// Sole private transition surface used by registered construction. The class
// is complete in this header, so a lookalike external definition cannot gain
// friendship.
class RegisteredConstructionAuthorityBridge final {
public:
    static DriverAttempt admit(
        CompiledDriverSelection, CapturePlanAuthority&&,
        attempt_supervisor::PartyApproval&&,
        const attempt_supervisor::Proposal&);
    static const PublicDriverSelection& selected_driver(
        const DriverAttempt&);
    static const attempt_supervisor::Proposal& proposal(
        const DriverAttempt&);
    static void recheck_before_lock(
        DriverAttempt&,
        attempt_supervisor::DirectAcceptedHeadCommitment&&);
    static std::unique_ptr<AuthorizedDriverAttempt> after_durable_lock(
        DriverAttempt&,
        attempt_supervisor::DirectAcceptedHeadCommitment&&,
        attempt_supervisor::DurableLockCommitment&&);
    static void claim_owner_intake(
        AuthorizedDriverAttempt&, MascotContext&, history::LockedAttempt&,
        const history::AttemptBinding&);
    static RegisteredCaptureSession& capture_session(
        AuthorizedDriverAttempt&);
};

struct SourceStatus {
    std::string schema;
    std::string status;
    bool accepts_argv_or_environment;
    bool registry_lifetime_owned_by_driver;
    bool docker_anchor_client_bridge;
    bool party_can_access_registry_anchor_path_or_fd;
    bool capture_classification_bound;
    bool raw_trial_uuid_roster_bridge;
    bool production_capture_plan_minter;
    bool p1_capture_plan_split_authority;
    bool p1_capturing_player_callsite_integration;
    bool parent_role_fork_topology;
    bool parent_role_completion_transport;
    bool parent_role_fork_selected_callsite_integration;
    bool authenticated_per_role_ipc_delivery;
    bool durable_lock_minted_from_locked_attempt;
    bool genuine_head_and_owner_factory_integrated;
    bool construct_registered_integration;
    bool proof_verification_integration;
    bool verified_release_integration;
    bool verified_egress_pre_route_barrier;
    bool party_egress_completion_authority;
    bool actual_capture_completion_integration;
    bool global_capture_supervisor_integration;
    bool parent_durable_completion_integration;
    bool downstream_completion_authority;
    bool downstream_completion_integration;
    bool registered_driver_configured;
    bool launch_authorized;
};

SourceStatus source_status();

} // namespace registered_driver

} // namespace kpi::mpc::financial
