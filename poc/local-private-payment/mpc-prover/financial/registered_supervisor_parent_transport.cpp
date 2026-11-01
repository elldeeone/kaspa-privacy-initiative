#include "registered_parent_role_fork.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

using attempt_supervisor::PartyApproval;
using attempt_supervisor::Proposal;
using attempt_supervisor::PublicApproval;
using attempt_supervisor::Supervisor;
using identity_registry::Selection;
using Bytes = std::vector<unsigned char>;

constexpr std::uint8_t PHASE_PROPOSAL = 1;
constexpr std::uint8_t PHASE_PREVIEW = 2;
constexpr std::uint8_t PHASE_PREVIEW_ACK = 3;
constexpr std::uint8_t PHASE_GRANT = 4;
constexpr std::uint8_t PHASE_GRANT_ACK = 5;

constexpr std::size_t PROPOSAL_BYTES = 564;
constexpr std::size_t APPROVAL_BYTES = 412;
constexpr std::size_t ACK_BYTES = 244;

constexpr std::array<unsigned char, 8> PROPOSAL_MAGIC{
    'K', 'P', 'B', 'S', 'P', 'P', '0', '1'};
constexpr std::array<unsigned char, 8> APPROVAL_MAGIC{
    'K', 'P', 'B', 'S', 'P', 'A', '0', '1'};
constexpr std::array<unsigned char, 8> ACK_MAGIC{
    'K', 'P', 'B', 'S', 'P', 'K', '0', '1'};

enum class Fault : std::uint8_t {
    None = 0,
    WrongApprovalAck = 1,
    DuplicateProposal = 2,
    DuplicateApprovalAck = 3,
};

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void byte(Bytes& out, unsigned value) {
    need(value <= std::numeric_limits<unsigned char>::max());
    out.push_back(static_cast<unsigned char>(value));
}

void u32(Bytes& out, std::int64_t value) {
    need(value > 1 &&
         value <= static_cast<std::int64_t>(
             std::numeric_limits<std::uint32_t>::max()));
    const auto encoded = static_cast<std::uint32_t>(value);
    for (unsigned shift = 0; shift < 32; shift += 8)
        out.push_back(static_cast<unsigned char>(encoded >> shift));
}

void u64(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void digest(Bytes& out, const Digest& value) {
    need(nonzero(value));
    out.insert(out.end(), value.begin(), value.end());
}

void common_header(
        Bytes& out, const std::array<unsigned char, 8>& magic,
        const detail::RoleCompletionBinding& binding, unsigned stage) {
    need(binding.role < 3 &&
         (binding.round == 1 || binding.round == 2) &&
         binding.parent_pid != binding.child_pid);
    out.insert(out.end(), magic.begin(), magic.end());
    byte(out, 1);
    byte(out, binding.role);
    byte(out, binding.round);
    byte(out, stage);
    u32(out, binding.parent_pid);
    u32(out, binding.child_pid);
    for (const auto* value : {
             &binding.fork_plan_identity, &binding.offer_identity,
             &binding.ack_identity, &binding.channel_nonce})
        digest(out, *value);
}

void finish(Bytes& out, std::size_t expected) {
    need(out.size() + Digest{}.size() == expected);
    digest(out, identity_registry::digest(out));
    need(out.size() == expected);
}

unsigned take_byte(std::span<const unsigned char> in, std::size_t& at) {
    need(at < in.size());
    return in[at++];
}

std::uint32_t take_u32(
        std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 4 <= in.size() - at);
    std::uint32_t result = 0;
    for (unsigned shift = 0; shift < 32; shift += 8)
        result |= std::uint32_t(in[at++]) << shift;
    return result;
}

std::uint64_t take_u64(
        std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 8 <= in.size() - at);
    std::uint64_t result = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
        result |= std::uint64_t(in[at++]) << shift;
    return result;
}

Digest take_digest(
        std::span<const unsigned char> in, std::size_t& at) {
    Digest result{};
    need(at <= in.size() && result.size() <= in.size() - at);
    std::copy_n(in.begin() + at, result.size(), result.begin());
    at += result.size();
    need(nonzero(result));
    return result;
}

void require_header(
        std::span<const unsigned char> in,
        const std::array<unsigned char, 8>& magic,
        const detail::RoleCompletionBinding& binding, unsigned stage,
        std::size_t& at) {
    need(in.size() >= 8 + 4 + 8 + 4 * Digest{}.size() + Digest{}.size() &&
         std::equal(magic.begin(), magic.end(), in.begin()));
    at = magic.size();
    need(take_byte(in, at) == 1 &&
         take_byte(in, at) == binding.role &&
         take_byte(in, at) == binding.round &&
         take_byte(in, at) == stage &&
         take_u32(in, at) == binding.parent_pid &&
         take_u32(in, at) == binding.child_pid &&
         take_digest(in, at) == binding.fork_plan_identity &&
         take_digest(in, at) == binding.offer_identity &&
         take_digest(in, at) == binding.ack_identity &&
         take_digest(in, at) == binding.channel_nonce);
}

Digest packet_identity(std::span<const unsigned char> packet) {
    need(packet.size() >= Digest{}.size());
    Digest result{};
    std::copy_n(packet.end() - result.size(), result.size(), result.begin());
    need(nonzero(result) &&
         result == identity_registry::digest(
             packet.first(packet.size() - result.size())));
    return result;
}

void require_selection(const Selection& selected) {
    for (const auto* value : {
             &selected.run, &selected.trial, &selected.attempt,
             &selected.cohort, &selected.accepted_head,
             &selected.owner_contracts[0], &selected.owner_contracts[1],
             &selected.owner_contracts[2]})
        need(nonzero(*value));
    need(nonzero(identity_registry::selection_identity(selected)));
}

Bytes proposal_packet(
        const Proposal& proposal,
        const detail::RoleCompletionBinding& binding, unsigned stage) {
    const auto& selected = proposal.public_selection_hashes();
    require_selection(selected);
    need(proposal.role() == binding.role &&
         proposal.authority_identity() == binding.authority_identity &&
         proposal.supervisor_session() == binding.supervisor_session &&
         proposal.party_session() == binding.party_session);
    Bytes out;
    out.reserve(PROPOSAL_BYTES);
    common_header(out, PROPOSAL_MAGIC, binding, stage);
    digest(out, proposal.authority_identity());
    digest(out, proposal.supervisor_session());
    digest(out, proposal.party_session());
    for (const auto* value : {
             &selected.run, &selected.trial, &selected.attempt,
             &selected.cohort, &selected.accepted_head,
             &selected.owner_contracts[0], &selected.owner_contracts[1],
             &selected.owner_contracts[2]})
        digest(out, *value);
    digest(out, attempt_supervisor::proposal_identity(proposal));
    finish(out, PROPOSAL_BYTES);
    return out;
}

struct DecodedProposal final {
    unsigned role{};
    Digest authority{};
    Digest supervisor{};
    Digest party{};
    Selection selection{};
    Digest proposal_identity{};
};

DecodedProposal parse_proposal(
        std::span<const unsigned char> packet,
        const detail::RoleCompletionBinding& binding, unsigned stage) {
    need(packet.size() == PROPOSAL_BYTES);
    std::size_t at = 0;
    require_header(
        packet, PROPOSAL_MAGIC, binding, stage, at);
    const auto authority = take_digest(packet, at);
    const auto supervisor = take_digest(packet, at);
    const auto party = take_digest(packet, at);
    Selection selected{
        .run = take_digest(packet, at),
        .trial = take_digest(packet, at),
        .attempt = take_digest(packet, at),
        .cohort = take_digest(packet, at),
        .accepted_head = take_digest(packet, at),
        .owner_contracts = {
            take_digest(packet, at), take_digest(packet, at),
            take_digest(packet, at)},
    };
    const auto supplied_proposal_identity = take_digest(packet, at);
    need(at + Digest{}.size() == packet.size() &&
         authority == binding.authority_identity &&
         supervisor == binding.supervisor_session &&
         party == binding.party_session);
    (void)packet_identity(packet);
    return {
        .role = binding.role,
        .authority = authority,
        .supervisor = supervisor,
        .party = party,
        .selection = std::move(selected),
        .proposal_identity = supplied_proposal_identity,
    };
}

void require_approval(
        const PublicApproval& approval, const Proposal& proposal,
        const detail::RoleCompletionBinding& binding) {
    need(approval.role == binding.role &&
         approval.role == proposal.role() &&
         approval.authority_identity == binding.authority_identity &&
         approval.authority_identity == proposal.authority_identity() &&
         approval.selection_identity ==
             identity_registry::selection_identity(
                 proposal.public_selection_hashes()) &&
         approval.supervisor_session == binding.supervisor_session &&
         approval.supervisor_session == proposal.supervisor_session() &&
         approval.party_session == binding.party_session &&
         approval.party_session == proposal.party_session() &&
         nonzero(approval.anchor_policy_identity) &&
         approval.registry_sequence > 0 &&
         nonzero(approval.registry_checkpoint) &&
         nonzero(approval.approval_identity));
}

Bytes approval_packet(
        const PublicApproval& approval, const Proposal& proposal,
        const detail::RoleCompletionBinding& binding, unsigned stage) {
    need(stage > 0 && stage <= std::numeric_limits<std::uint8_t>::max());
    require_approval(approval, proposal, binding);
    Bytes out;
    out.reserve(APPROVAL_BYTES);
    common_header(out, APPROVAL_MAGIC, binding, stage);
    digest(out, approval.authority_identity);
    digest(out, approval.selection_identity);
    digest(out, approval.supervisor_session);
    digest(out, approval.party_session);
    digest(out, approval.anchor_policy_identity);
    u64(out, approval.registry_sequence);
    digest(out, approval.registry_checkpoint);
    digest(out, approval.approval_identity);
    finish(out, APPROVAL_BYTES);
    return out;
}

struct ParsedApproval final {
    PublicApproval value;
    Digest packet_identity;
};

ParsedApproval parse_approval(
        std::span<const unsigned char> packet,
        const detail::RoleCompletionBinding& binding, const Proposal& proposal,
        unsigned stage) {
    need(packet.size() == APPROVAL_BYTES && stage > 0 &&
         stage <= std::numeric_limits<std::uint8_t>::max());
    std::size_t at = 0;
    require_header(packet, APPROVAL_MAGIC, binding, stage, at);
    PublicApproval result{
        .role = binding.role,
        .authority_identity = take_digest(packet, at),
        .selection_identity = take_digest(packet, at),
        .supervisor_session = take_digest(packet, at),
        .party_session = take_digest(packet, at),
        .anchor_policy_identity = take_digest(packet, at),
        .registry_sequence = take_u64(packet, at),
        .registry_checkpoint = take_digest(packet, at),
        .approval_identity = take_digest(packet, at),
    };
    need(at + Digest{}.size() == packet.size());
    const auto identity = packet_identity(packet);
    require_approval(result, proposal, binding);
    return {std::move(result), identity};
}

Bytes acknowledgment_packet(
        const detail::RoleCompletionBinding& binding,
        const Digest& approval_identity, const Digest& referenced_packet,
        unsigned stage) {
    need(stage > 0 && stage <= std::numeric_limits<std::uint8_t>::max());
    Bytes out;
    out.reserve(ACK_BYTES);
    common_header(out, ACK_MAGIC, binding, stage);
    digest(out, approval_identity);
    digest(out, referenced_packet);
    finish(out, ACK_BYTES);
    return out;
}

void require_acknowledgment(
        std::span<const unsigned char> packet,
        const detail::RoleCompletionBinding& binding,
        const Digest& approval_identity, const Digest& referenced_packet,
        unsigned stage) {
    need(packet.size() == ACK_BYTES && stage > 0 &&
         stage <= std::numeric_limits<std::uint8_t>::max());
    std::size_t at = 0;
    require_header(packet, ACK_MAGIC, binding, stage, at);
    need(take_digest(packet, at) == approval_identity &&
         take_digest(packet, at) == referenced_packet &&
         at + Digest{}.size() == packet.size());
    (void)packet_identity(packet);
}

} // namespace

attempt_supervisor::PartyApproval
RegisteredSupervisorParentTransport::submit_impl(
        const Proposal& local,
        ChildRoleCompletionEndpointAuthority& endpoint,
        std::uint8_t raw_fault, std::uint8_t base_phase) {
    try {
        const auto fault = static_cast<Fault>(raw_fault);
        need(fault == Fault::None || fault == Fault::WrongApprovalAck ||
             fault == Fault::DuplicateProposal ||
             fault == Fault::DuplicateApprovalAck);
        need(base_phase <= std::numeric_limits<std::uint8_t>::max() -
                 PHASE_GRANT_ACK);
        const auto proposal_phase = base_phase + PHASE_PROPOSAL;
        const auto preview_phase = base_phase + PHASE_PREVIEW;
        const auto preview_ack_phase = base_phase + PHASE_PREVIEW_ACK;
        const auto grant_phase = base_phase + PHASE_GRANT;
        const auto grant_ack_phase = base_phase + PHASE_GRANT_ACK;
        const auto proposal = proposal_packet(
            local, endpoint.binding_, proposal_phase);
        endpoint.send_role_packet(
            base_phase, proposal_phase, proposal);
        if (fault == Fault::DuplicateProposal)
            endpoint.send_role_packet(
                proposal_phase, proposal_phase, proposal);

        const auto preview_packet = endpoint.receive_role_packet(
            proposal_phase, preview_phase, APPROVAL_BYTES);
        const auto preview = parse_approval(
            preview_packet, endpoint.binding_, local, preview_phase);
        auto ack_approval = preview.value.approval_identity;
        if (fault == Fault::WrongApprovalAck) ack_approval[0] ^= 0xffU;
        const auto preview_ack = acknowledgment_packet(
            endpoint.binding_, ack_approval, preview.packet_identity,
            preview_ack_phase);
        endpoint.send_role_packet(
            preview_phase, preview_ack_phase, preview_ack);
        if (fault == Fault::DuplicateApprovalAck)
            endpoint.send_role_packet(
                preview_ack_phase, preview_ack_phase, preview_ack);

        const auto grant_packet = endpoint.receive_role_packet(
            preview_ack_phase, grant_phase, APPROVAL_BYTES);
        const auto grant = parse_approval(
            grant_packet, endpoint.binding_, local, grant_phase);
        need(grant.value.role == preview.value.role &&
             grant.value.authority_identity ==
                 preview.value.authority_identity &&
             grant.value.selection_identity ==
                 preview.value.selection_identity &&
             grant.value.supervisor_session ==
                 preview.value.supervisor_session &&
             grant.value.party_session == preview.value.party_session &&
             grant.value.anchor_policy_identity ==
                 preview.value.anchor_policy_identity &&
             grant.value.registry_sequence ==
                 preview.value.registry_sequence &&
             grant.value.registry_checkpoint ==
                 preview.value.registry_checkpoint &&
             grant.value.approval_identity ==
                 preview.value.approval_identity);
        const auto grant_ack = acknowledgment_packet(
            endpoint.binding_, grant.value.approval_identity,
            grant.packet_identity, grant_ack_phase);
        endpoint.send_role_packet(
            grant_phase, grant_ack_phase, grant_ack);
        return PartyApproval(local, grant.value);
    } catch (...) {
        endpoint.poison_role_channel();
        refuse();
    }
}

void RegisteredSupervisorParentTransport::approve_impl(
        Supervisor& supervisor, ParentRoleChildren& children,
        std::uint8_t base_phase) {
    try {
        need(base_phase <= std::numeric_limits<std::uint8_t>::max() -
                 PHASE_GRANT_ACK);
        const auto proposal_phase = base_phase + PHASE_PROPOSAL;
        const auto preview_phase = base_phase + PHASE_PREVIEW;
        const auto preview_ack_phase = base_phase + PHASE_PREVIEW_ACK;
        const auto grant_phase = base_phase + PHASE_GRANT;
        const auto grant_ack_phase = base_phase + PHASE_GRANT_ACK;
        std::array<std::optional<Proposal>, 3> proposals;
        for (unsigned role = 0; role < proposals.size(); ++role) {
            const auto packet = children.receive_role_packet(
                role, base_phase, proposal_phase, PROPOSAL_BYTES);
            auto decoded = parse_proposal(
                packet, children.completion_bindings_[role],
                proposal_phase);
            Proposal reconstructed(
                decoded.role, decoded.authority, decoded.supervisor,
                decoded.party, std::move(decoded.selection));
            proposals[role].emplace(reconstructed);
            need(attempt_supervisor::proposal_identity(*proposals[role]) ==
                 decoded.proposal_identity);
            supervisor.submit(*proposals[role]);
        }
        need(supervisor.ready());
        auto approvals = supervisor.approve();

        std::array<PublicApproval, 3> previews{};
        std::array<Digest, 3> preview_packets{};
        for (unsigned role = 0; role < previews.size(); ++role) {
            const auto party = proposals[role]->party_session();
            previews[role] = approvals.preview(role, party);
            const auto packet = approval_packet(
                previews[role], *proposals[role],
                children.completion_bindings_[role], preview_phase);
            preview_packets[role] = packet_identity(packet);
            children.send_role_packet(
                role, proposal_phase, preview_phase, packet);
        }

        for (unsigned role = 0; role < previews.size(); ++role) {
            const auto packet = children.receive_role_packet(
                role, preview_phase, preview_ack_phase, ACK_BYTES);
            require_acknowledgment(
                packet, children.completion_bindings_[role],
                previews[role].approval_identity, preview_packets[role],
                preview_ack_phase);
            approvals.acknowledge(
                role, proposals[role]->party_session(),
                previews[role].approval_identity);
        }
        need(approvals.activated());

        std::array<Digest, 3> grant_packets{};
        for (unsigned role = 0; role < previews.size(); ++role) {
            auto approval = approvals.take(
                role, proposals[role]->party_session());
            need(approval.live_.exchange(false) &&
                 approval.proposal_ == *proposals[role] &&
                 approval.receipt_.approval_identity ==
                     previews[role].approval_identity);
            const auto packet = approval_packet(
                approval.receipt_, approval.proposal_,
                children.completion_bindings_[role], grant_phase);
            grant_packets[role] = packet_identity(packet);
            children.send_role_packet(
                role, preview_ack_phase, grant_phase, packet);
        }

        for (unsigned role = 0; role < previews.size(); ++role) {
            const auto packet = children.receive_role_packet(
                role, grant_phase, grant_ack_phase, ACK_BYTES);
            require_acknowledgment(
                packet, children.completion_bindings_[role],
                previews[role].approval_identity, grant_packets[role],
                grant_ack_phase);
        }
    } catch (...) {
        children.poison_role_channels();
        refuse();
    }
}

attempt_supervisor::PartyApproval
RegisteredSupervisorParentTransport::submit_and_wait(
        const attempt_supervisor::Proposal& proposal,
        ChildRoleCompletionEndpointAuthority& endpoint) {
    return submit_impl(
        proposal, endpoint, static_cast<std::uint8_t>(Fault::None), 2);
}

void RegisteredSupervisorParentTransport::approve(
        OuterSupervisorAuthority& outer, ParentRoleChildren& children) {
    try {
        need(outer.supervisor_ != nullptr);
        approve_impl(*outer.supervisor_, children, 2);
    } catch (...) {
        children.poison_role_channels();
        refuse();
    }
}

#ifdef KPI_REGISTERED_SUPERVISOR_TRANSPORT_TEST_SETUP
attempt_supervisor::PartyApproval
RegisteredSupervisorParentTransport::test_only_submit_and_wait(
        const attempt_supervisor::Proposal& proposal,
        ChildRoleCompletionEndpointAuthority& endpoint,
        SupervisorTransportTestFault fault) {
    return submit_impl(
        proposal, endpoint, static_cast<std::uint8_t>(fault), 0);
}

void RegisteredSupervisorParentTransport::test_only_approve(
        attempt_supervisor::Supervisor& supervisor,
        ParentRoleChildren& children) {
    approve_impl(supervisor, children, 0);
}
#endif

} // namespace kpi::mpc::financial::registered_driver
