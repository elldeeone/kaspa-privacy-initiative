#pragma once

// Source-only architecture-A authority. A single outer supervisor owns the
// durable identity registry; party-facing objects contain public hashes only.

#include "registered_identity_registry.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>

namespace kpi::mpc {
struct OwnerInputContract;
namespace history { class LockedAttempt; }
namespace financial {
class AcceptedFinancialHead;
class RegisteredService;
namespace docker_anchor { class SupervisorCapability; }
namespace attempt_supervisor {
class Proposal;
class PartyApproval;
class Supervisor;
}
namespace registered_driver {
class OuterSupervisorAuthority;
class CompiledOuterSupervisorSelection;
class CompiledFreshAttemptAuthority;
class AuthenticatedPartyDeliveryAuthority;
class ParentAuthenticatedPartyDeliveryAuthority;
class CompiledDriverSelection;
class ChildRoleCompletionEndpointAuthority;
class ParentRoleChildren;

#ifdef KPI_REGISTERED_SUPERVISOR_TRANSPORT_TEST_SETUP
enum class SupervisorTransportTestFault : std::uint8_t {
    None = 0,
    WrongApprovalAck = 1,
    DuplicateProposal = 2,
    DuplicateApprovalAck = 3,
};
#endif

// Complete, sealed cross-process bridge for the parent-owned supervisor. It
// has no descriptor, packet, receipt or metadata constructor. The child side
// must start from a genuine Proposal and the retained role endpoint; the
// parent side owns the only Supervisor capable of committing all three.
class RegisteredSupervisorParentTransport final {
    RegisteredSupervisorParentTransport() = delete;
    static attempt_supervisor::PartyApproval submit_impl(
        const attempt_supervisor::Proposal&,
        ChildRoleCompletionEndpointAuthority&, std::uint8_t fault,
        std::uint8_t base_phase);
    static void approve_impl(
        attempt_supervisor::Supervisor&, ParentRoleChildren&,
        std::uint8_t base_phase);
public:
    static attempt_supervisor::PartyApproval submit_and_wait(
        const attempt_supervisor::Proposal&,
        ChildRoleCompletionEndpointAuthority&);
    static void approve(OuterSupervisorAuthority&, ParentRoleChildren&);
#ifdef KPI_REGISTERED_SUPERVISOR_TRANSPORT_TEST_SETUP
    static attempt_supervisor::PartyApproval test_only_submit_and_wait(
        const attempt_supervisor::Proposal&,
        ChildRoleCompletionEndpointAuthority&,
        SupervisorTransportTestFault);
    static void test_only_approve(
        attempt_supervisor::Supervisor&, ParentRoleChildren&);
#endif
};
}
}
}

namespace kpi::mpc::financial::attempt_supervisor {

using Digest = identity_registry::Digest;
using Selection = identity_registry::Selection;
using FailureOnlyHook = identity_registry::FailureOnlyHook;

class RegisteredProposalBridge;
class Proposal;

class AttemptLineageCommitment final {
    Digest run_, trial_, attempt_, cohort_;
    std::atomic_bool live_{true};
    AttemptLineageCommitment(Digest, Digest, Digest, Digest);
    friend class RegisteredProposalBridge;
    friend class Proposal;
public:
    AttemptLineageCommitment(const AttemptLineageCommitment&) = delete;
    AttemptLineageCommitment& operator=(const AttemptLineageCommitment&) = delete;
    AttemptLineageCommitment(AttemptLineageCommitment&&) noexcept;
    AttemptLineageCommitment& operator=(AttemptLineageCommitment&&) = delete;
#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
    static AttemptLineageCommitment test_only_mint(
        Digest run, Digest trial, Digest attempt, Digest cohort);
#endif
};

class DirectAcceptedHeadCommitment final {
    Digest identity_;
    std::atomic_bool live_{true};
    explicit DirectAcceptedHeadCommitment(Digest);
    friend class RegisteredProposalBridge;
    friend class Proposal;
    friend class PartyApproval;
    friend class RegisteredFreshAttempt;
public:
    DirectAcceptedHeadCommitment(const DirectAcceptedHeadCommitment&) = delete;
    DirectAcceptedHeadCommitment& operator=(const DirectAcceptedHeadCommitment&) = delete;
    DirectAcceptedHeadCommitment(DirectAcceptedHeadCommitment&&) noexcept;
    DirectAcceptedHeadCommitment& operator=(DirectAcceptedHeadCommitment&&) = delete;
#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
    static DirectAcceptedHeadCommitment test_only_mint(Digest);
#endif
};

class CanonicalOwnerContractsCommitment final {
    std::array<Digest, 3> identities_;
    std::atomic_bool live_{true};
    explicit CanonicalOwnerContractsCommitment(std::array<Digest, 3>);
    friend class RegisteredProposalBridge;
    friend class Proposal;
public:
    CanonicalOwnerContractsCommitment(
        const CanonicalOwnerContractsCommitment&) = delete;
    CanonicalOwnerContractsCommitment& operator=(
        const CanonicalOwnerContractsCommitment&) = delete;
    CanonicalOwnerContractsCommitment(
        CanonicalOwnerContractsCommitment&&) noexcept;
    CanonicalOwnerContractsCommitment& operator=(
        CanonicalOwnerContractsCommitment&&) = delete;
#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
    static CanonicalOwnerContractsCommitment test_only_mint(
        std::array<Digest, 3>);
#endif
};

struct PublicAnchorPolicy {
    Digest policy_identity;
    bool permission_separated;
    bool monotonic;
    bool child_path_exposed;
    bool child_fd_exposed;
};

struct ExternalAnchorSnapshot {
    Digest authority_identity;
    std::uint64_t sequence;
    Digest checkpoint;
    bool operator==(const ExternalAnchorSnapshot&) const = default;
};

// Implemented by a permission-separated compare-and-advance service. The
// source-only module defines the narrow contract, not a production backend.
class ExternalMonotonicAnchor {
public:
    virtual ~ExternalMonotonicAnchor() = default;
    virtual ExternalAnchorSnapshot snapshot() = 0;
    virtual void compare_and_advance(const ExternalAnchorSnapshot& expected,
                                     const ExternalAnchorSnapshot& next) = 0;
};

class SupervisorAnchorPolicy final {
    PublicAnchorPolicy policy_;
    std::shared_ptr<ExternalMonotonicAnchor> anchor_;
    std::atomic_bool live_{true};
    SupervisorAnchorPolicy(PublicAnchorPolicy,
                           std::shared_ptr<ExternalMonotonicAnchor>);
    friend class RegisteredProposalBridge;
    friend class Supervisor;
public:
    SupervisorAnchorPolicy(const SupervisorAnchorPolicy&) = delete;
    SupervisorAnchorPolicy& operator=(const SupervisorAnchorPolicy&) = delete;
    SupervisorAnchorPolicy(SupervisorAnchorPolicy&&) noexcept;
    SupervisorAnchorPolicy& operator=(SupervisorAnchorPolicy&&) = delete;
#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
    static SupervisorAnchorPolicy test_only_mint(
        PublicAnchorPolicy, std::shared_ptr<ExternalMonotonicAnchor>);
#endif
};

class Proposal final {
    unsigned role_;
    Digest authority_identity_;
    Digest supervisor_session_;
    Digest party_session_;
    Selection selection_;
    Proposal(unsigned, Digest, Digest, Digest,
             AttemptLineageCommitment&&,
             DirectAcceptedHeadCommitment&&,
             CanonicalOwnerContractsCommitment&&);
    Proposal(unsigned, Digest, Digest, Digest, Selection);
    friend class RegisteredProposalBridge;
    friend class registered_driver::RegisteredSupervisorParentTransport;
public:
    Proposal(const Proposal&) = default;
    Proposal& operator=(const Proposal&) = default;
    unsigned role() const { return role_; }
    const Digest& authority_identity() const { return authority_identity_; }
    const Digest& supervisor_session() const { return supervisor_session_; }
    const Digest& party_session() const { return party_session_; }
    const Selection& public_selection_hashes() const { return selection_; }
    bool operator==(const Proposal&) const = default;
#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
    static Proposal test_only_mint(
        unsigned role, Digest authority_identity, Digest supervisor_session,
        Digest party_session, AttemptLineageCommitment&&,
        DirectAcceptedHeadCommitment&&,
        CanonicalOwnerContractsCommitment&&);
#endif
};

struct PublicApproval {
    unsigned role;
    Digest authority_identity;
    Digest selection_identity;
    Digest supervisor_session;
    Digest party_session;
    Digest anchor_policy_identity;
    std::uint64_t registry_sequence;
    Digest registry_checkpoint;
    Digest approval_identity;
};

struct PublicFreshAttempt {
    unsigned role;
    Digest authority_identity;
    Digest selection_identity;
    Digest accepted_head;
    Digest attempt_identity;
};

struct PublicIntakePermit {
    unsigned role;
    Digest authority_identity;
    Digest selection_identity;
    Digest accepted_head;
    Digest durable_lock;
    Digest permit_identity;
};

class DurableLockCommitment final {
    unsigned role_;
    Digest selection_identity_, accepted_head_, lock_identity_;
    std::atomic_bool live_{true};
    DurableLockCommitment(unsigned, Digest, Digest, Digest);
    friend class RegisteredProposalBridge;
    friend class RegisteredFreshAttempt;
public:
    DurableLockCommitment(const DurableLockCommitment&) = delete;
    DurableLockCommitment& operator=(const DurableLockCommitment&) = delete;
    DurableLockCommitment(DurableLockCommitment&&) noexcept;
    DurableLockCommitment& operator=(DurableLockCommitment&&) = delete;
#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
    static DurableLockCommitment test_only_mint(
        unsigned role, Digest selection_identity,
        Digest accepted_head, Digest lock_identity);
#endif
};

class OwnerIntakePermit final {
    PublicIntakePermit receipt_;
    std::atomic_bool live_{true};
    explicit OwnerIntakePermit(PublicIntakePermit);
    friend class RegisteredFreshAttempt;
public:
    OwnerIntakePermit(const OwnerIntakePermit&) = delete;
    OwnerIntakePermit& operator=(const OwnerIntakePermit&) = delete;
    OwnerIntakePermit(OwnerIntakePermit&&) noexcept;
    OwnerIntakePermit& operator=(OwnerIntakePermit&&) = delete;

    // Future claim_owner_intake integration must accept this capability by
    // rvalue and invoke this exactly once at its entry point.
    PublicIntakePermit consume_for_claim(unsigned role);
    const PublicIntakePermit& public_receipt() const { return receipt_; }
};

class RegisteredFreshAttempt final {
    Proposal proposal_;
    PublicFreshAttempt receipt_;
    std::atomic_bool live_{true};
    RegisteredFreshAttempt(Proposal, PublicFreshAttempt);
    friend class PartyApproval;
public:
    RegisteredFreshAttempt(const RegisteredFreshAttempt&) = delete;
    RegisteredFreshAttempt& operator=(const RegisteredFreshAttempt&) = delete;
    RegisteredFreshAttempt(RegisteredFreshAttempt&&) noexcept;
    RegisteredFreshAttempt& operator=(RegisteredFreshAttempt&&) = delete;

    // Called only after the actual durable LOCK and immediately before the
    // owner-intake claim. A second direct-head observation closes the stale
    // head window between approval and private intake.
    OwnerIntakePermit burn_immediately_before_owner_intake(
        unsigned role, DirectAcceptedHeadCommitment&& direct_accepted_head,
        DurableLockCommitment&& durable_lock);
    const PublicFreshAttempt& public_receipt() const { return receipt_; }
};

class PartyApproval final {
    Proposal proposal_;
    PublicApproval receipt_;
    std::atomic_bool live_{true};
    PartyApproval(Proposal, PublicApproval);
    friend class ApprovalBatch;
    friend class registered_driver::RegisteredSupervisorParentTransport;
public:
    PartyApproval(const PartyApproval&) = delete;
    PartyApproval& operator=(const PartyApproval&) = delete;
    PartyApproval(PartyApproval&&) noexcept;
    PartyApproval& operator=(PartyApproval&&) = delete;

    // Each party must compare its direct C++ AcceptedFinancialHead observation
    // immediately before LOCK. Failure burns this approval.
    RegisteredFreshAttempt recheck_before_lock(
        const Proposal& locally_derived,
        DirectAcceptedHeadCommitment&& direct_accepted_head);
    const PublicApproval& public_receipt() const { return receipt_; }
};

class ApprovalBatch final {
    std::array<std::optional<PartyApproval>, 3> approvals_;
    std::array<bool, 3> acknowledged_{};
    std::mutex mutex_;
    bool live_ = true;
    ApprovalBatch(const std::array<Proposal, 3>&,
                  const identity_registry::PublicReceipt&,
                  const PublicAnchorPolicy&);
    friend class Supervisor;
public:
    ApprovalBatch(const ApprovalBatch&) = delete;
    ApprovalBatch(ApprovalBatch&&) = delete;
    ApprovalBatch& operator=(const ApprovalBatch&) = delete;
    ApprovalBatch& operator=(ApprovalBatch&&) = delete;

    // PREPARE is public hash-only metadata. It cannot mint a party capability.
    PublicApproval preview(unsigned role, const Digest& party_session);
    // COMMIT remains closed until all three exact previews are acknowledged.
    void acknowledge(unsigned role, const Digest& party_session,
                     const Digest& approval_identity);
    bool activated();
    PartyApproval take(unsigned role, const Digest& party_session);
};

class Supervisor final {
    identity_registry::Registry& registry_;
    Digest authority_identity_;
    Digest supervisor_session_;
    std::array<std::optional<Proposal>, 3> proposals_;
    mutable std::mutex mutex_;
    bool poisoned_ = false;
    bool committed_ = false;
    PublicAnchorPolicy anchor_policy_;
    std::shared_ptr<ExternalMonotonicAnchor> external_anchor_;
public:
    Supervisor(identity_registry::Registry&, const Digest& supervisor_session,
               SupervisorAnchorPolicy&&);
    Supervisor(const Supervisor&) = delete;
    Supervisor(Supervisor&&) = delete;
    Supervisor& operator=(const Supervisor&) = delete;
    Supervisor& operator=(Supervisor&&) = delete;

    void submit(const Proposal&);
    bool ready() const;
    enum class Boundary { ExternalAnchorAdvanced };
    using SupervisorFailureOnlyHook = std::function<void(Boundary)>;
    ApprovalBatch approve(FailureOnlyHook = {}, SupervisorFailureOnlyHook = {});
};

// Sole production mint for supervisor capabilities derived from genuine C++
// authorities. This complete definition lives beside every private friend, so
// another translation unit cannot define a lookalike friend class.
class RegisteredProposalBridge final {
public:
    static registered_driver::OuterSupervisorAuthority open_outer(
        registered_driver::CompiledOuterSupervisorSelection&&,
        docker_anchor::SupervisorCapability&&);
    static Proposal proposal(
        registered_driver::CompiledFreshAttemptAuthority&&,
        registered_driver::AuthenticatedPartyDeliveryAuthority&&,
        const registered_driver::CompiledDriverSelection&,
        const RegisteredService&, const AcceptedFinancialHead&,
        std::span<const OwnerInputContract>);
    static registered_driver::AuthenticatedPartyDeliveryAuthority
    authenticated_party_delivery(
        registered_driver::ParentAuthenticatedPartyDeliveryAuthority&&,
        const registered_driver::CompiledDriverSelection&);
    static DirectAcceptedHeadCommitment direct_head(
        const AcceptedFinancialHead&);
    static CanonicalOwnerContractsCommitment owner_contracts(
        std::span<const OwnerInputContract>);
    static DurableLockCommitment durable_lock(
        const Proposal&, const history::LockedAttempt&,
        std::span<const OwnerInputContract>);
};

struct SourceStatus {
    std::string schema;
    std::string status;
    bool registry_mounted_to_children;
    bool supervisor_anchor_path_or_fd_exposed_to_children;
    bool permission_separated_monotonic_anchor_backend;
    bool external_monotonic_anchor_interface;
    bool coordinated_same_inode_rollback_detected;
    bool actual_process_ipc_integration;
    bool typed_registered_bridge_integration;
    bool direct_accepted_head_type_integration;
    bool canonical_owner_contract_type_integration;
    bool claim_owner_intake_integration;
    bool registered_driver_configured;
    bool launch_authorized;
};

Digest proposal_identity(const Proposal&);
SourceStatus source_status();

} // namespace kpi::mpc::financial::attempt_supervisor
