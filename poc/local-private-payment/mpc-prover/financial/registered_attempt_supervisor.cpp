#include "registered_attempt_supervisor.hpp"

#include <algorithm>
#include <set>
#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::attempt_supervisor {
namespace {
using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void valid(const Proposal& value) {
    need(value.role() < 3 && nonzero(value.authority_identity()) &&
         nonzero(value.supervisor_session()) && nonzero(value.party_session()));
    const auto selected = identity_registry::selection_identity(
        value.public_selection_hashes());
    need(nonzero(selected) && value.party_session() != value.authority_identity() &&
         value.party_session() != value.supervisor_session());
}

bool same_common_commitment(const Proposal& left, const Proposal& right) {
    return left.authority_identity() == right.authority_identity() &&
           left.supervisor_session() == right.supervisor_session() &&
           left.public_selection_hashes() == right.public_selection_hashes();
}

Digest approval_identity(const Proposal& proposal,
                         const identity_registry::PublicReceipt& registry,
                         const PublicAnchorPolicy& anchor_policy) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_PARENT_APPROVAL_V1\n");
    add(bytes, proposal_identity(proposal));
    add(bytes, registry.authority_identity);
    add(bytes, registry.selection_identity);
    integer(bytes, registry.sequence);
    add(bytes, registry.checkpoint);
    add(bytes, registry.consumed_set_identity);
    add(bytes, anchor_policy.policy_identity);
    return identity_registry::digest(bytes);
}

Digest fresh_attempt_identity(const Proposal& proposal,
                              const PublicApproval& approval) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_FRESH_ATTEMPT_V1\n");
    add(bytes, proposal_identity(proposal));
    add(bytes, approval.approval_identity);
    add(bytes, proposal.public_selection_hashes().accepted_head);
    return identity_registry::digest(bytes);
}

Digest intake_permit_identity(const PublicFreshAttempt& attempt,
                              const Digest& durable_lock) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_OWNER_INTAKE_PERMIT_V1\n");
    integer(bytes, attempt.role);
    add(bytes, attempt.authority_identity);
    add(bytes, attempt.selection_identity);
    add(bytes, attempt.accepted_head);
    add(bytes, attempt.attempt_identity);
    add(bytes, durable_lock);
    return identity_registry::digest(bytes);
}
} // namespace

AttemptLineageCommitment::AttemptLineageCommitment(
    Digest run, Digest trial, Digest attempt, Digest cohort)
    : run_(run), trial_(trial), attempt_(attempt), cohort_(cohort) {}

AttemptLineageCommitment::AttemptLineageCommitment(
    AttemptLineageCommitment&& other) noexcept
    : run_(other.run_), trial_(other.trial_), attempt_(other.attempt_),
      cohort_(other.cohort_), live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
AttemptLineageCommitment AttemptLineageCommitment::test_only_mint(
    Digest run, Digest trial, Digest attempt, Digest cohort) {
    return AttemptLineageCommitment(run, trial, attempt, cohort);
}
#endif

DirectAcceptedHeadCommitment::DirectAcceptedHeadCommitment(Digest identity)
    : identity_(identity) {}

DirectAcceptedHeadCommitment::DirectAcceptedHeadCommitment(
    DirectAcceptedHeadCommitment&& other) noexcept
    : identity_(other.identity_), live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
DirectAcceptedHeadCommitment DirectAcceptedHeadCommitment::test_only_mint(
    Digest identity) {
    return DirectAcceptedHeadCommitment(identity);
}
#endif

CanonicalOwnerContractsCommitment::CanonicalOwnerContractsCommitment(
    std::array<Digest, 3> identities)
    : identities_(identities) {}

CanonicalOwnerContractsCommitment::CanonicalOwnerContractsCommitment(
    CanonicalOwnerContractsCommitment&& other) noexcept
    : identities_(other.identities_), live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
CanonicalOwnerContractsCommitment
CanonicalOwnerContractsCommitment::test_only_mint(
    std::array<Digest, 3> identities) {
    return CanonicalOwnerContractsCommitment(identities);
}
#endif

SupervisorAnchorPolicy::SupervisorAnchorPolicy(
    PublicAnchorPolicy policy,
    std::shared_ptr<ExternalMonotonicAnchor> anchor)
    : policy_(policy), anchor_(std::move(anchor)) {}

SupervisorAnchorPolicy::SupervisorAnchorPolicy(
    SupervisorAnchorPolicy&& other) noexcept
    : policy_(other.policy_), anchor_(std::move(other.anchor_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
SupervisorAnchorPolicy SupervisorAnchorPolicy::test_only_mint(
    PublicAnchorPolicy policy,
    std::shared_ptr<ExternalMonotonicAnchor> anchor) {
    return SupervisorAnchorPolicy(policy, std::move(anchor));
}
#endif

Proposal::Proposal(
    unsigned role, Digest authority_identity, Digest supervisor_session,
    Digest party_session, AttemptLineageCommitment&& lineage,
    DirectAcceptedHeadCommitment&& head,
    CanonicalOwnerContractsCommitment&& owners)
    : role_(role), authority_identity_(authority_identity),
      supervisor_session_(supervisor_session), party_session_(party_session),
      selection_{
          .run = lineage.run_, .trial = lineage.trial_,
          .attempt = lineage.attempt_, .cohort = lineage.cohort_,
          .accepted_head = head.identity_, .owner_contracts = owners.identities_} {
    const bool lineage_live = lineage.live_.exchange(false);
    const bool head_live = head.live_.exchange(false);
    const bool owners_live = owners.live_.exchange(false);
    need(lineage_live && head_live && owners_live);
    valid(*this);
}

Proposal::Proposal(
    unsigned role, Digest authority_identity, Digest supervisor_session,
    Digest party_session, Selection selection)
    : role_(role), authority_identity_(authority_identity),
      supervisor_session_(supervisor_session), party_session_(party_session),
      selection_(std::move(selection)) {
    valid(*this);
}

#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
Proposal Proposal::test_only_mint(
    unsigned role, Digest authority_identity, Digest supervisor_session,
    Digest party_session, AttemptLineageCommitment&& lineage,
    DirectAcceptedHeadCommitment&& head,
    CanonicalOwnerContractsCommitment&& owners) {
    return Proposal(role, authority_identity, supervisor_session, party_session,
                    std::move(lineage), std::move(head), std::move(owners));
}
#endif

DurableLockCommitment::DurableLockCommitment(
    unsigned role, Digest selection_identity, Digest accepted_head,
    Digest lock_identity)
    : role_(role), selection_identity_(selection_identity),
      accepted_head_(accepted_head), lock_identity_(lock_identity) {}

DurableLockCommitment::DurableLockCommitment(
    DurableLockCommitment&& other) noexcept
    : role_(other.role_), selection_identity_(other.selection_identity_),
      accepted_head_(other.accepted_head_), lock_identity_(other.lock_identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_ATTEMPT_TEST_SETUP
DurableLockCommitment DurableLockCommitment::test_only_mint(
    unsigned role, Digest selection_identity, Digest accepted_head,
    Digest lock_identity) {
    return DurableLockCommitment(
        role, selection_identity, accepted_head, lock_identity);
}
#endif

Digest proposal_identity(const Proposal& proposal) {
    valid(proposal);
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_PARENT_PROPOSAL_V1\n");
    integer(bytes, proposal.role());
    add(bytes, proposal.authority_identity());
    add(bytes, proposal.supervisor_session());
    add(bytes, proposal.party_session());
    add(bytes, identity_registry::selection_identity(
        proposal.public_selection_hashes()));
    return identity_registry::digest(bytes);
}

OwnerIntakePermit::OwnerIntakePermit(PublicIntakePermit receipt)
    : receipt_(std::move(receipt)) {}

OwnerIntakePermit::OwnerIntakePermit(OwnerIntakePermit&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

PublicIntakePermit OwnerIntakePermit::consume_for_claim(unsigned role) {
    const bool was_live = live_.exchange(false);
    need(was_live && role < 3 && role == receipt_.role);
    return receipt_;
}

RegisteredFreshAttempt::RegisteredFreshAttempt(
    Proposal proposal, PublicFreshAttempt receipt)
    : proposal_(std::move(proposal)), receipt_(std::move(receipt)) {}

RegisteredFreshAttempt::RegisteredFreshAttempt(
    RegisteredFreshAttempt&& other) noexcept
    : proposal_(other.proposal_), receipt_(other.receipt_),
      live_(other.live_.exchange(false)) {}

OwnerIntakePermit RegisteredFreshAttempt::burn_immediately_before_owner_intake(
    unsigned role, DirectAcceptedHeadCommitment&& direct_accepted_head,
    DurableLockCommitment&& durable_lock) {
    const bool was_live = live_.exchange(false);
    const bool head_live = direct_accepted_head.live_.exchange(false);
    const bool lock_live = durable_lock.live_.exchange(false);
    need(was_live && head_live && lock_live && role < 3 &&
         role == proposal_.role() && role == receipt_.role &&
         nonzero(direct_accepted_head.identity_) &&
         direct_accepted_head.identity_ ==
             proposal_.public_selection_hashes().accepted_head &&
         direct_accepted_head.identity_ == receipt_.accepted_head &&
         durable_lock.role_ == role &&
         durable_lock.selection_identity_ == receipt_.selection_identity &&
         durable_lock.accepted_head_ == direct_accepted_head.identity_ &&
         nonzero(durable_lock.lock_identity_));
    PublicIntakePermit permit{
        .role = role,
        .authority_identity = receipt_.authority_identity,
        .selection_identity = receipt_.selection_identity,
        .accepted_head = receipt_.accepted_head,
        .durable_lock = durable_lock.lock_identity_,
        .permit_identity = intake_permit_identity(
            receipt_, durable_lock.lock_identity_),
    };
    return OwnerIntakePermit(std::move(permit));
}

PartyApproval::PartyApproval(Proposal proposal, PublicApproval receipt)
    : proposal_(std::move(proposal)), receipt_(std::move(receipt)) {}

PartyApproval::PartyApproval(PartyApproval&& other) noexcept
    : proposal_(other.proposal_), receipt_(other.receipt_),
      live_(other.live_.exchange(false)) {}

RegisteredFreshAttempt PartyApproval::recheck_before_lock(
    const Proposal& locally_derived,
    DirectAcceptedHeadCommitment&& direct_accepted_head) {
    const bool was_live = live_.exchange(false);
    const bool head_live = direct_accepted_head.live_.exchange(false);
    need(was_live && head_live);
    valid(locally_derived);
    need(locally_derived == proposal_ &&
         direct_accepted_head.identity_ ==
             proposal_.public_selection_hashes().accepted_head &&
         nonzero(direct_accepted_head.identity_) &&
         receipt_.role == proposal_.role() &&
         receipt_.authority_identity == proposal_.authority_identity() &&
         receipt_.selection_identity ==
             identity_registry::selection_identity(
                 proposal_.public_selection_hashes()) &&
         receipt_.supervisor_session == proposal_.supervisor_session() &&
         receipt_.party_session == proposal_.party_session());
    PublicFreshAttempt fresh{
        .role = proposal_.role(),
        .authority_identity = proposal_.authority_identity(),
        .selection_identity = receipt_.selection_identity,
        .accepted_head = direct_accepted_head.identity_,
        .attempt_identity = fresh_attempt_identity(proposal_, receipt_),
    };
    return RegisteredFreshAttempt(proposal_, std::move(fresh));
}

ApprovalBatch::ApprovalBatch(
    const std::array<Proposal, 3>& proposals,
    const identity_registry::PublicReceipt& registry,
    const PublicAnchorPolicy& anchor_policy) {
    for (unsigned role = 0; role < proposals.size(); ++role) {
        const auto& proposal = proposals[role];
        need(proposal.role() == role &&
             registry.authority_identity == proposal.authority_identity() &&
             registry.selection_identity ==
                 identity_registry::selection_identity(
                     proposal.public_selection_hashes()));
        PublicApproval approval{
            .role = role,
            .authority_identity = registry.authority_identity,
            .selection_identity = registry.selection_identity,
            .supervisor_session = proposal.supervisor_session(),
            .party_session = proposal.party_session(),
            .anchor_policy_identity = anchor_policy.policy_identity,
            .registry_sequence = registry.sequence,
            .registry_checkpoint = registry.checkpoint,
            .approval_identity = attempt_supervisor::approval_identity(
                proposal, registry, anchor_policy),
        };
        PartyApproval value(proposal, std::move(approval));
        approvals_[role].emplace(std::move(value));
    }
}

PublicApproval ApprovalBatch::preview(unsigned role,
                                      const Digest& party_session) {
    std::lock_guard guard(mutex_);
    const bool valid_preview = live_ && role < approvals_.size() &&
        approvals_[role].has_value() && nonzero(party_session) &&
        approvals_[role]->public_receipt().party_session == party_session;
    if (!valid_preview) {
        live_ = false;
        for (auto& approval : approvals_) approval.reset();
        refuse();
    }
    return approvals_[role]->public_receipt();
}

void ApprovalBatch::acknowledge(unsigned role, const Digest& party_session,
                                const Digest& approval_identity) {
    std::lock_guard guard(mutex_);
    const bool valid_ack = live_ && role < approvals_.size() &&
        approvals_[role].has_value() && !acknowledged_[role] &&
        nonzero(party_session) && nonzero(approval_identity) &&
        approvals_[role]->public_receipt().party_session == party_session &&
        approvals_[role]->public_receipt().approval_identity == approval_identity;
    if (!valid_ack) {
        live_ = false;
        for (auto& approval : approvals_) approval.reset();
        refuse();
    }
    acknowledged_[role] = true;
}

bool ApprovalBatch::activated() {
    std::lock_guard guard(mutex_);
    return live_ && std::all_of(acknowledged_.begin(), acknowledged_.end(),
                                [](bool value) { return value; });
}

PartyApproval ApprovalBatch::take(unsigned role, const Digest& party_session) {
    std::lock_guard guard(mutex_);
    const bool all_acknowledged =
        std::all_of(acknowledged_.begin(), acknowledged_.end(),
                    [](bool value) { return value; });
    const bool valid_take = live_ && all_acknowledged &&
        role < approvals_.size() &&
        approvals_[role].has_value() && nonzero(party_session) &&
        approvals_[role]->public_receipt().party_session == party_session;
    if (!valid_take) {
        live_ = false;
        for (auto& approval : approvals_) approval.reset();
        refuse();
    }
    PartyApproval result(std::move(*approvals_[role]));
    approvals_[role].reset();
    return result;
}

Supervisor::Supervisor(identity_registry::Registry& registry,
                       const Digest& supervisor_session,
                       SupervisorAnchorPolicy&& anchor_policy)
    : registry_(registry),
      authority_identity_(registry.snapshot().authority_identity),
      supervisor_session_(supervisor_session),
      anchor_policy_(anchor_policy.policy_),
      external_anchor_(std::move(anchor_policy.anchor_)) {
    const bool policy_live = anchor_policy.live_.exchange(false);
    need(nonzero(authority_identity_) && nonzero(supervisor_session_) &&
         authority_identity_ != supervisor_session_ &&
         policy_live &&
         bool(external_anchor_) &&
         nonzero(anchor_policy_.policy_identity) &&
         anchor_policy_.permission_separated && anchor_policy_.monotonic &&
         !anchor_policy_.child_path_exposed &&
         !anchor_policy_.child_fd_exposed);
}

void Supervisor::submit(const Proposal& proposal) {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && !committed_);
        valid(proposal);
        need(proposal.authority_identity() == authority_identity_ &&
             proposal.supervisor_session() == supervisor_session_ &&
             !proposals_[proposal.role()].has_value());
        for (const auto& existing : proposals_) {
            if (!existing) continue;
            need(same_common_commitment(*existing, proposal) &&
                 existing->party_session() != proposal.party_session());
        }
        proposals_[proposal.role()] = proposal;
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

bool Supervisor::ready() const {
    std::lock_guard guard(mutex_);
    need(!poisoned_ && !committed_);
    return std::all_of(proposals_.begin(), proposals_.end(),
                       [](const auto& proposal) { return proposal.has_value(); });
}

ApprovalBatch Supervisor::approve(
    FailureOnlyHook hook, SupervisorFailureOnlyHook supervisor_hook) {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && !committed_ &&
             std::all_of(proposals_.begin(), proposals_.end(),
                         [](const auto& proposal) { return proposal.has_value(); }));
        committed_ = true;
        std::array<Proposal, 3> proposals{
            *proposals_[0], *proposals_[1], *proposals_[2]};
        const auto before = registry_.snapshot();
        const ExternalAnchorSnapshot expected_anchor{
            .authority_identity = before.authority_identity,
            .sequence = before.sequence,
            .checkpoint = before.checkpoint,
        };
        need(external_anchor_->snapshot() == expected_anchor);
        auto consumed = registry_.consume(
            proposals[0].public_selection_hashes(), std::move(hook));
        const auto receipt = consumed.public_receipt();
        need(receipt.authority_identity == authority_identity_ &&
             receipt.selection_identity ==
                 identity_registry::selection_identity(
                     proposals[0].public_selection_hashes()));
        const ExternalAnchorSnapshot next_anchor{
            .authority_identity = receipt.authority_identity,
            .sequence = receipt.sequence,
            .checkpoint = receipt.checkpoint,
        };
        external_anchor_->compare_and_advance(expected_anchor, next_anchor);
        need(external_anchor_->snapshot() == next_anchor);
        if (supervisor_hook)
            supervisor_hook(Boundary::ExternalAnchorAdvanced);
        return ApprovalBatch(proposals, receipt, anchor_policy_);
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

SourceStatus source_status() {
    return SourceStatus{
        .schema = "kpb-registered-attempt-supervisor-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .registry_mounted_to_children = false,
        .supervisor_anchor_path_or_fd_exposed_to_children = false,
        .permission_separated_monotonic_anchor_backend = false,
        .external_monotonic_anchor_interface = true,
        .coordinated_same_inode_rollback_detected = false,
        .actual_process_ipc_integration = false,
        .typed_registered_bridge_integration = false,
        .direct_accepted_head_type_integration = false,
        .canonical_owner_contract_type_integration = false,
        .claim_owner_intake_integration = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::attempt_supervisor
