#include "baseline_owner_scoring_parent_transport.hpp"

#include "authenticated_baseline_owner_receiver.hpp"
#include "registered_parent_role_fork.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;
constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'B', 'O', 'E', 'P', '1'};

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

Digest payload_type() {
    static constexpr char domain[] =
        "KPB_BASELINE_OWNER_EFFECTS_COMPLETION_PACKET_V1\n";
    return identity_registry::digest(std::span(
        reinterpret_cast<const unsigned char*>(domain), sizeof(domain) - 1));
}

void put_byte(Bytes& out, std::size_t& at, unsigned value) {
    need(value <= 255 && at < out.size());
    out[at++] = static_cast<unsigned char>(value);
}

void put_u32(Bytes& out, std::size_t& at, std::int64_t value) {
    need(value > 1 &&
         value <= static_cast<std::int64_t>(
             std::numeric_limits<std::uint32_t>::max()) &&
         at <= out.size() && 4 <= out.size() - at);
    const auto encoded = static_cast<std::uint32_t>(value);
    for (unsigned index = 0; index < 4; ++index)
        out[at++] = static_cast<unsigned char>(encoded >> (8 * index));
}

void put_digest(Bytes& out, std::size_t& at, const Digest& value) {
    need(nonzero(value) && at <= out.size() &&
         value.size() <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() + at);
    at += value.size();
}

unsigned get_byte(std::span<const unsigned char> in, std::size_t& at) {
    need(at < in.size());
    return in[at++];
}

std::int64_t get_u32(std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 4 <= in.size() - at);
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index)
        value |= std::uint32_t(in[at++]) << (8 * index);
    need(value > 1);
    return value;
}

Digest get_digest(std::span<const unsigned char> in, std::size_t& at) {
    Digest result{};
    need(at <= in.size() && result.size() <= in.size() - at);
    std::copy_n(in.begin() + at, result.size(), result.begin());
    at += result.size();
    need(nonzero(result));
    return result;
}

Bytes encode(const PrivatePartyBaselineOwnerEffects& value,
             const Digest& party_identity,
             const detail::RoleCompletionBinding& binding) {
    need(value.role == binding.role && value.round == binding.round &&
         binding.parent_pid != binding.child_pid);
    Bytes out(BaselineOwnerScoringParentTransport::PACKET_BYTES);
    std::copy(MAGIC.begin(), MAGIC.end(), out.begin());
    std::size_t at = MAGIC.size();
    put_byte(out, at, 1);
    put_byte(out, at, static_cast<unsigned>(value.classification));
    put_byte(out, at, value.round);
    put_byte(out, at, value.role);
    put_u32(out, at, binding.parent_pid);
    put_u32(out, at, binding.child_pid);
    put_digest(out, at, binding.fork_plan_identity);
    put_digest(out, at, binding.offer_identity);
    put_digest(out, at, binding.ack_identity);
    put_digest(out, at, party_identity);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.relation_source_identity,
             &value.owner_effects_recipe_identity,
             &value.baseline_plan_identity, &value.verified_egress_identity,
             &value.policy_identity, &value.roster_authority_identity,
             &value.roster_root_identity, &value.consent_nonce})
        put_digest(out, at, *field);
    for (const auto& field : value.owner_contracts)
        put_digest(out, at, field);
    for (const auto& field : value.logical_owner_identities)
        put_digest(out, at, field);
    for (const auto& field : value.pre_disclosure_challenge_identities)
        put_digest(out, at, field);
    for (const auto& field : value.owner_sessions)
        put_digest(out, at, field);
    for (const auto& truth : value.owner_truth) {
        put_digest(out, at, truth.public_nullifier);
        put_digest(out, at, truth.public_tuple_hashes[0]);
        put_digest(out, at, truth.public_tuple_hashes[1]);
        put_digest(out, at, truth.public_tuple_commitments[0]);
        put_digest(out, at, truth.public_tuple_commitments[1]);
    }
    need(at + Digest{}.size() == out.size());
    const auto packet_identity = identity_registry::digest(
        std::span<const unsigned char>(out.data(), at));
    put_digest(out, at, packet_identity);
    need(at == out.size());
    return out;
}

struct Decoded {
    PrivatePartyBaselineOwnerEffects value;
    Digest party_identity;
};

Decoded decode(
        std::span<const unsigned char> in,
        const detail::RoleCompletionBinding& binding) {
    need(in.size() == BaselineOwnerScoringParentTransport::PACKET_BYTES &&
         std::equal(MAGIC.begin(), MAGIC.end(), in.begin()));
    std::size_t at = MAGIC.size();
    need(get_byte(in, at) == 1);
    PrivatePartyBaselineOwnerEffects value{};
    value.classification = static_cast<CaptureClassification>(
        get_byte(in, at));
    value.round = get_byte(in, at);
    value.role = get_byte(in, at);
    need(value.role == binding.role && value.round == binding.round &&
         get_u32(in, at) == binding.parent_pid &&
         get_u32(in, at) == binding.child_pid &&
         get_digest(in, at) == binding.fork_plan_identity &&
         get_digest(in, at) == binding.offer_identity &&
         get_digest(in, at) == binding.ack_identity);
    const auto party_identity = get_digest(in, at);
    value.run = get_digest(in, at);
    value.trial = get_digest(in, at);
    value.attempt = get_digest(in, at);
    value.cohort = get_digest(in, at);
    value.capture_plan_identity = get_digest(in, at);
    value.projection_identity = get_digest(in, at);
    value.context_identity = get_digest(in, at);
    value.relation_source_identity = get_digest(in, at);
    value.owner_effects_recipe_identity = get_digest(in, at);
    value.baseline_plan_identity = get_digest(in, at);
    value.verified_egress_identity = get_digest(in, at);
    value.policy_identity = get_digest(in, at);
    value.roster_authority_identity = get_digest(in, at);
    value.roster_root_identity = get_digest(in, at);
    value.consent_nonce = get_digest(in, at);
    for (auto& field : value.owner_contracts) field = get_digest(in, at);
    for (auto& field : value.logical_owner_identities)
        field = get_digest(in, at);
    for (auto& field : value.pre_disclosure_challenge_identities)
        field = get_digest(in, at);
    for (auto& field : value.owner_sessions) field = get_digest(in, at);
    for (unsigned owner = 0; owner < value.owner_truth.size(); ++owner) {
        auto& truth = value.owner_truth[owner];
        truth.owner = owner;
        truth.round = value.round;
        truth.run = value.run;
        truth.trial = value.trial;
        truth.attempt = value.attempt;
        truth.cohort = value.cohort;
        truth.capture_plan_identity = value.capture_plan_identity;
        truth.projection_identity = value.projection_identity;
        truth.context_identity = value.context_identity;
        truth.owner_contract_identity = value.owner_contracts[owner];
        truth.logical_owner_identity = value.logical_owner_identities[owner];
        truth.roster_authority_identity = value.roster_authority_identity;
        truth.roster_root_identity = value.roster_root_identity;
        truth.pre_disclosure_challenge_identity =
            value.pre_disclosure_challenge_identities[owner];
        truth.public_nullifier = get_digest(in, at);
        truth.public_tuple_hashes[0] = get_digest(in, at);
        truth.public_tuple_hashes[1] = get_digest(in, at);
        truth.public_tuple_commitments[0] = get_digest(in, at);
        truth.public_tuple_commitments[1] = get_digest(in, at);
    }
    need(at + Digest{}.size() == in.size());
    const auto supplied_packet_identity = get_digest(in, at);
    need(at == in.size() && supplied_packet_identity ==
         identity_registry::digest(in.first(in.size() - Digest{}.size())));
    return {std::move(value), party_identity};
}
} // namespace

void BaselineOwnerScoringParentTransport::submit(
        PartyBaselineOwnerEffectsAuthority&& supplied,
        ChildRoleCompletionEndpointAuthority&& endpoint) {
    try {
        need(supplied.live_.exchange(false));
        const auto packet = encode(
            supplied.value_, supplied.identity_, endpoint.binding_);
        endpoint.send_fixed(payload_type(), packet);
    } catch (...) { refuse(); }
}

PartyBaselineOwnerEffectsAuthority
BaselineOwnerScoringParentTransport::receive(
        ParentRoleCompletionEndpointAuthority&& endpoint) {
    try {
        const auto packet = endpoint.receive_fixed(
            payload_type(), PACKET_BYTES);
        auto decoded = decode(packet, endpoint.binding_);
        PartyBaselineOwnerEffectsAuthority result(
            std::move(decoded.value));
        need(result.identity_ == decoded.party_identity);
        return result;
    } catch (...) { refuse(); }
}

void BaselineOwnerScoringParentHandoff::accept_round(
        registered_driver::ParentRoleChildren&& supplied) {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && !finished_);
        auto children = std::move(supplied);
        const auto acknowledgements = children.public_acknowledgements();
        const auto round = acknowledgements[0].round;
        need((round == 1 || round == 2) &&
             !accepted_rounds_[round - 1]);
        for (unsigned role = 0; role < acknowledgements.size(); ++role)
            need(acknowledgements[role].role == role &&
                 acknowledgements[role].round == round &&
                 acknowledgements[role].fork_plan_identity ==
                     acknowledgements[0].fork_plan_identity);

        std::array<std::optional<PartyBaselineOwnerEffectsAuthority>, 3>
            parties;
        for (unsigned role = 0; role < parties.size(); ++role)
            parties[role].emplace(
                BaselineOwnerScoringParentTransport::receive(
                    children.take_completion_endpoint(role)));
        const auto completion = children.wait();
        need(completion.all_children_exited_zero &&
             completion.fork_plan_identity ==
                 acknowledgements[0].fork_plan_identity);
        for (auto& party : parties)
            collector_.submit(std::move(*party));
        accepted_rounds_[round - 1] = true;
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

BaselineOwnerScoringLaunchAuthority
BaselineOwnerScoringParentHandoff::finish() {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && !finished_ && accepted_rounds_[0] &&
             accepted_rounds_[1]);
        auto result = collector_.finish();
        finished_ = true;
        return result;
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
