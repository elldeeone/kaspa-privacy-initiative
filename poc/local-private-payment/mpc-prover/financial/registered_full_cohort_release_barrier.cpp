#include "registered_full_cohort_release_barrier_contract.hpp"

#include "registered_driver_bridge.hpp"
#include "registered_parent_role_fork.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::array<unsigned char, 8> READY_MAGIC{
    'K', 'P', 'B', 'F', 'R', 'R', '0', '1'};
constexpr std::array<unsigned char, 8> GRANT_MAGIC{
    'K', 'P', 'B', 'F', 'R', 'G', '0', '1'};
constexpr std::size_t READY_DIGESTS = 27;
constexpr std::size_t READY_BYTES = 8 + 4 + 36 + READY_DIGESTS * 32;
constexpr std::size_t GRANT_BYTES = 8 + 4 + 36 + 4 * 32 + 8;

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
void add_string(Bytes& out, const std::string& value) {
    integer(out, value.size());
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}
void add_authorized(Bytes& out, const PublicAuthorizedAttempt& value) {
    integer(out, value.role);
    integer(out, value.round);
    integer(out, static_cast<std::uint8_t>(value.classification));
    add_string(out, value.capture_trial_id);
    for (const auto* field : {
             &value.authority_identity, &value.driver_selection_identity,
             &value.selection_identity, &value.run, &value.trial,
             &value.attempt, &value.cohort, &value.accepted_head,
             &value.postlock_accepted_head, &value.attempt_identity,
             &value.proposal_identity, &value.durable_lock,
             &value.capture_plan_identity, &value.capture_source_identity,
             &value.capture_build_identity, &value.capture_launcher_identity,
             &value.authorization_identity})
        add(out, *field);
    for (const auto& owner : value.owner_contracts) add(out, owner);
}
void add_egress(Bytes& out, const PublicVerifiedEgress& value) {
    for (const auto* field : {
             &value.binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity})
        add(out, *field);
}
Digest readiness_identity(const PublicPartyReleaseReady& value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_PARTY_RELEASE_READY_V1\n");
    add_authorized(bytes, value.attempt);
    add_egress(bytes, value.egress);
    return identity_registry::digest(bytes);
}

void put_byte(Bytes& out, std::size_t& at, unsigned value) {
    need(value <= 255 && at < out.size());
    out[at++] = static_cast<unsigned char>(value);
}
void put_u64(Bytes& out, std::size_t& at, std::uint64_t value) {
    need(at <= out.size() && 8 <= out.size() - at);
    for (unsigned index = 0; index < 8; ++index)
        out[at++] = static_cast<unsigned char>(value >> (8 * index));
}
void put_digest(Bytes& out, std::size_t& at, const Digest& value) {
    need(nonzero(value) && at <= out.size() &&
         value.size() <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() + at);
    at += value.size();
}
void put_text(Bytes& out, std::size_t& at, const std::string& value) {
    need(value.size() == 36 && at <= out.size() &&
         value.size() <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() + at);
    at += value.size();
}
unsigned get_byte(std::span<const unsigned char> in, std::size_t& at) {
    need(at < in.size());
    return in[at++];
}
std::uint64_t get_u64(
        std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 8 <= in.size() - at);
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index)
        value |= std::uint64_t(in[at++]) << (8 * index);
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
std::string get_text(std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 36 <= in.size() - at);
    std::string result(
        reinterpret_cast<const char*>(in.data() + at), 36);
    at += 36;
    return result;
}

void put_attempt(
        Bytes& out, std::size_t& at,
        const PublicAuthorizedAttempt& value) {
    put_text(out, at, value.capture_trial_id);
    for (const auto* field : {
             &value.authority_identity, &value.driver_selection_identity,
             &value.selection_identity, &value.run, &value.trial,
             &value.attempt, &value.cohort, &value.accepted_head,
             &value.postlock_accepted_head, &value.attempt_identity,
             &value.proposal_identity, &value.durable_lock,
             &value.owner_contracts[0], &value.owner_contracts[1],
             &value.owner_contracts[2], &value.capture_plan_identity,
             &value.capture_source_identity, &value.capture_build_identity,
             &value.capture_launcher_identity,
             &value.authorization_identity})
        put_digest(out, at, *field);
}
PublicAuthorizedAttempt get_attempt(
        std::span<const unsigned char> in, std::size_t& at,
        unsigned role, unsigned round, CaptureClassification classification) {
    return PublicAuthorizedAttempt{
        .role = role,
        .round = round,
        .classification = classification,
        .capture_trial_id = get_text(in, at),
        .authority_identity = get_digest(in, at),
        .driver_selection_identity = get_digest(in, at),
        .selection_identity = get_digest(in, at),
        .run = get_digest(in, at),
        .trial = get_digest(in, at),
        .attempt = get_digest(in, at),
        .cohort = get_digest(in, at),
        .accepted_head = get_digest(in, at),
        .postlock_accepted_head = get_digest(in, at),
        .attempt_identity = get_digest(in, at),
        .proposal_identity = get_digest(in, at),
        .durable_lock = get_digest(in, at),
        .owner_contracts = {
            get_digest(in, at), get_digest(in, at), get_digest(in, at)},
        .capture_plan_identity = get_digest(in, at),
        .capture_source_identity = get_digest(in, at),
        .capture_build_identity = get_digest(in, at),
        .capture_launcher_identity = get_digest(in, at),
        .authorization_identity = get_digest(in, at),
    };
}
void put_egress(
        Bytes& out, std::size_t& at, const PublicVerifiedEgress& value) {
    for (const auto* field : {
             &value.binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity})
        put_digest(out, at, *field);
}
PublicVerifiedEgress get_egress(
        std::span<const unsigned char> in, std::size_t& at) {
    return PublicVerifiedEgress{
        .binding_identity = get_digest(in, at),
        .effects_identity = get_digest(in, at),
        .core_identity = get_digest(in, at),
        .proof_identity = get_digest(in, at),
        .projection_identity = get_digest(in, at),
    };
}

struct DecodedReady final {
    PublicPartyReleaseReady ready;
    Digest packet_identity{};
};

Bytes encode_ready(const PublicPartyReleaseReady& value) {
    need(value.attempt.role < 3 &&
         (value.attempt.round == 1 || value.attempt.round == 2) &&
         (value.attempt.classification == CaptureClassification::HiddenCandidate ||
          value.attempt.classification == CaptureClassification::
              ExplicitOwnerPublicEffectsBaseline) &&
         value.readiness_identity == readiness_identity(value));
    Bytes packet(READY_BYTES);
    std::size_t at = 0;
    std::copy(READY_MAGIC.begin(), READY_MAGIC.end(), packet.begin());
    at += READY_MAGIC.size();
    put_byte(packet, at, value.attempt.role);
    put_byte(packet, at, value.attempt.round);
    put_byte(packet, at, static_cast<unsigned>(value.attempt.classification));
    put_byte(packet, at, 0);
    put_attempt(packet, at, value.attempt);
    put_egress(packet, at, value.egress);
    put_digest(packet, at, value.readiness_identity);
    need(at + Digest{}.size() == packet.size());
    const auto packet_id = identity_registry::digest(
        std::span<const unsigned char>(packet.data(), at));
    put_digest(packet, at, packet_id);
    need(at == packet.size());
    return packet;
}

DecodedReady decode_ready(
        std::span<const unsigned char> packet,
        const detail::RoleCompletionBinding& binding) {
    need(packet.size() == READY_BYTES &&
         std::equal(READY_MAGIC.begin(), READY_MAGIC.end(), packet.begin()));
    std::size_t at = READY_MAGIC.size();
    const auto role = get_byte(packet, at);
    const auto round = get_byte(packet, at);
    const auto raw_classification = get_byte(packet, at);
    need(get_byte(packet, at) == 0 &&
         (raw_classification == static_cast<unsigned>(
              CaptureClassification::HiddenCandidate) ||
          raw_classification == static_cast<unsigned>(
              CaptureClassification::ExplicitOwnerPublicEffectsBaseline)));
    const auto classification =
        static_cast<CaptureClassification>(raw_classification);
    auto attempt = get_attempt(packet, at, role, round, classification);
    auto egress = get_egress(packet, at);
    const auto ready_identity = get_digest(packet, at);
    const auto expected_packet_identity = identity_registry::digest(
        packet.first(at));
    const auto packet_identity = get_digest(packet, at);
    need(at == packet.size() &&
         packet_identity == expected_packet_identity &&
         role == binding.role && round == binding.round &&
         classification == binding.classification &&
         attempt.capture_trial_id == binding.capture_trial_id &&
         attempt.authority_identity == binding.authority_identity &&
         attempt.driver_selection_identity ==
             binding.driver_selection_identity &&
         attempt.run == binding.run && attempt.trial == binding.trial &&
         attempt.attempt == binding.attempt &&
         attempt.cohort == binding.cohort &&
         attempt.capture_plan_identity == binding.capture_plan_identity &&
         attempt.capture_source_identity == binding.capture_source_identity &&
         attempt.capture_build_identity == binding.capture_build_identity &&
         attempt.capture_launcher_identity ==
             binding.capture_launcher_identity);
    PublicPartyReleaseReady ready{
        .attempt = std::move(attempt),
        .egress = std::move(egress),
        .readiness_identity = ready_identity,
    };
    need(ready.readiness_identity == readiness_identity(ready));
    return {std::move(ready), packet_identity};
}

bool same_common(
        const PublicPartyReleaseReady& first,
        const PublicPartyReleaseReady& value) {
    return value.attempt.round == first.attempt.round &&
           value.attempt.classification == first.attempt.classification &&
           value.attempt.capture_trial_id == first.attempt.capture_trial_id &&
           value.attempt.authority_identity ==
               first.attempt.authority_identity &&
           value.attempt.selection_identity ==
               first.attempt.selection_identity &&
           value.attempt.run == first.attempt.run &&
           value.attempt.trial == first.attempt.trial &&
           value.attempt.attempt == first.attempt.attempt &&
           value.attempt.cohort == first.attempt.cohort &&
           value.attempt.accepted_head == first.attempt.accepted_head &&
           value.attempt.postlock_accepted_head ==
               first.attempt.postlock_accepted_head &&
           value.attempt.owner_contracts == first.attempt.owner_contracts &&
           value.attempt.capture_plan_identity ==
               first.attempt.capture_plan_identity &&
           value.attempt.capture_source_identity ==
               first.attempt.capture_source_identity &&
           value.attempt.capture_build_identity ==
               first.attempt.capture_build_identity &&
           value.attempt.capture_launcher_identity ==
               first.attempt.capture_launcher_identity &&
           value.egress.effects_identity == first.egress.effects_identity &&
           value.egress.core_identity == first.egress.core_identity &&
           value.egress.proof_identity == first.egress.proof_identity &&
           value.egress.projection_identity ==
               first.egress.projection_identity;
}

std::uint64_t monotonic_ns() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const auto count = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now).count();
    need(count > 0);
    return static_cast<std::uint64_t>(count);
}

Digest bind_barrier(
        const std::array<DecodedReady, 3>& ready,
        const std::array<detail::RoleCompletionBinding, 3>& bindings,
        std::uint64_t observed_ns) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_FULL_COHORT_RELEASE_BARRIER_V1\n");
    integer(bytes, ready[0].ready.attempt.round);
    integer(bytes, static_cast<std::uint8_t>(
        ready[0].ready.attempt.classification));
    add_string(bytes, ready[0].ready.attempt.capture_trial_id);
    for (unsigned role = 0; role < ready.size(); ++role) {
        add(bytes, ready[role].packet_identity);
        const auto& binding = bindings[role];
        add(bytes, binding.fork_plan_identity);
        add(bytes, binding.offer_identity);
        add(bytes, binding.ack_identity);
        add(bytes, binding.channel_nonce);
        integer(bytes, static_cast<std::uint64_t>(binding.parent_pid));
        integer(bytes, static_cast<std::uint64_t>(binding.child_pid));
    }
    integer(bytes, observed_ns);
    return identity_registry::digest(bytes);
}

Bytes encode_grant(
        const DecodedReady& ready, const Digest& barrier,
        std::uint64_t observed_ns) {
    Bytes packet(GRANT_BYTES);
    std::size_t at = 0;
    std::copy(GRANT_MAGIC.begin(), GRANT_MAGIC.end(), packet.begin());
    at += GRANT_MAGIC.size();
    put_byte(packet, at, ready.ready.attempt.role);
    put_byte(packet, at, ready.ready.attempt.round);
    put_byte(packet, at,
             static_cast<unsigned>(ready.ready.attempt.classification));
    put_byte(packet, at, 0);
    put_text(packet, at, ready.ready.attempt.capture_trial_id);
    put_digest(packet, at, ready.ready.readiness_identity);
    put_digest(packet, at, ready.packet_identity);
    put_digest(packet, at, barrier);
    put_u64(packet, at, observed_ns);
    need(at + Digest{}.size() == packet.size());
    const auto identity = identity_registry::digest(
        std::span<const unsigned char>(packet.data(), at));
    put_digest(packet, at, identity);
    need(at == packet.size());
    return packet;
}

struct DecodedGrant final {
    Digest barrier_identity{};
    std::uint64_t observed_ns{};
};

DecodedGrant decode_grant(
        std::span<const unsigned char> packet,
        const PublicPartyReleaseReady& ready,
        const Digest& ready_packet_identity) {
    need(packet.size() == GRANT_BYTES &&
         std::equal(GRANT_MAGIC.begin(), GRANT_MAGIC.end(), packet.begin()));
    std::size_t at = GRANT_MAGIC.size();
    const auto role = get_byte(packet, at);
    const auto round = get_byte(packet, at);
    const auto classification = get_byte(packet, at);
    need(get_byte(packet, at) == 0 &&
         role == ready.attempt.role && round == ready.attempt.round &&
         classification == static_cast<unsigned>(
             ready.attempt.classification) &&
         get_text(packet, at) == ready.attempt.capture_trial_id &&
         get_digest(packet, at) == ready.readiness_identity &&
         get_digest(packet, at) == ready_packet_identity);
    const auto barrier = get_digest(packet, at);
    const auto observed_ns = get_u64(packet, at);
    const auto expected_identity = identity_registry::digest(packet.first(at));
    need(get_digest(packet, at) == expected_identity &&
         at == packet.size() && observed_ns > 0);
    return {barrier, observed_ns};
}

} // namespace

PartyReleaseAuthorizationAuthority
RegisteredFullCohortReleaseBarrier::arrive_and_wait(
        PartyReleaseReadyAuthority&& supplied,
        ChildRoleCompletionEndpointAuthority& endpoint) {
    try {
        need(supplied.live_.exchange(false));
        const auto packet = encode_ready(supplied.value_);
        Digest ready_packet_identity{};
        std::copy_n(packet.end() - ready_packet_identity.size(),
                    ready_packet_identity.size(),
                    ready_packet_identity.begin());
        need(nonzero(ready_packet_identity));
        const auto& binding = endpoint.binding_;
        need(supplied.value_.attempt.role == binding.role &&
             supplied.value_.attempt.round == binding.round &&
             supplied.value_.attempt.classification ==
                 binding.classification &&
             supplied.value_.attempt.capture_trial_id ==
                 binding.capture_trial_id &&
             supplied.value_.attempt.authority_identity ==
                 binding.authority_identity &&
             supplied.value_.attempt.driver_selection_identity ==
                 binding.driver_selection_identity &&
             supplied.value_.attempt.run == binding.run &&
             supplied.value_.attempt.trial == binding.trial &&
             supplied.value_.attempt.attempt == binding.attempt &&
             supplied.value_.attempt.cohort == binding.cohort &&
             supplied.value_.attempt.capture_plan_identity ==
                 binding.capture_plan_identity &&
             supplied.value_.attempt.capture_source_identity ==
                 binding.capture_source_identity &&
             supplied.value_.attempt.capture_build_identity ==
                 binding.capture_build_identity &&
             supplied.value_.attempt.capture_launcher_identity ==
                 binding.capture_launcher_identity);
        std::uint8_t base_phase = 7;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        base_phase = endpoint.supervisor_phase_;
#endif
        need(base_phase <= std::numeric_limits<std::uint8_t>::max() - 2);
        endpoint.send_role_packet(
            base_phase, static_cast<std::uint8_t>(base_phase + 1), packet);
        const auto grant = endpoint.receive_role_packet(
            static_cast<std::uint8_t>(base_phase + 1),
            static_cast<std::uint8_t>(base_phase + 2), GRANT_BYTES);
        const auto decoded = decode_grant(
            grant, supplied.value_, ready_packet_identity);
        return PartyReleaseAuthorizationAuthority(
            supplied.value_.attempt, supplied.value_.egress,
            supplied.value_.readiness_identity,
            decoded.barrier_identity, decoded.observed_ns);
    } catch (...) {
        endpoint.poison_role_channel();
        refuse();
    }
}

void RegisteredFullCohortReleaseBarrier::authorize(
        ParentRoleChildren& children) {
    try {
        std::uint8_t base_phase = 7;
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
        {
            std::lock_guard guard(children.mutex_);
            need(children.supervisor_phases_[0] ==
                     children.supervisor_phases_[1] &&
                 children.supervisor_phases_[0] ==
                     children.supervisor_phases_[2]);
            base_phase = children.supervisor_phases_[0];
        }
#endif
        need(base_phase <= std::numeric_limits<std::uint8_t>::max() - 2);
        std::array<DecodedReady, 3> ready;
        for (unsigned role = 0; role < ready.size(); ++role) {
            const auto packet = children.receive_role_packet(
                role, base_phase,
                static_cast<std::uint8_t>(base_phase + 1), READY_BYTES);
            ready[role] = decode_ready(
                packet, children.completion_bindings_[role]);
            need(ready[role].ready.attempt.role == role &&
                 (role == 0 || same_common(
                     ready[0].ready, ready[role].ready)));
        }
        need(ready[0].ready.readiness_identity !=
                 ready[1].ready.readiness_identity &&
             ready[0].ready.readiness_identity !=
                 ready[2].ready.readiness_identity &&
             ready[1].ready.readiness_identity !=
                 ready[2].ready.readiness_identity);
        const auto observed_ns = monotonic_ns();
        const auto barrier = bind_barrier(
            ready, children.completion_bindings_, observed_ns);
        need(nonzero(barrier));
        for (unsigned role = 0; role < ready.size(); ++role) {
            const auto grant = encode_grant(
                ready[role], barrier, observed_ns);
            children.send_role_packet(
                role, static_cast<std::uint8_t>(base_phase + 1),
                static_cast<std::uint8_t>(base_phase + 2), grant);
        }
        {
            std::lock_guard guard(children.mutex_);
            need(children.live_ && !children.full_cohort_release_authorized_);
            for (unsigned role = 0; role < ready.size(); ++role)
                children.release_ready_identities_[role] =
                    ready[role].ready.readiness_identity;
            children.full_cohort_barrier_identity_ = barrier;
            children.full_cohort_barrier_monotonic_ns_ = observed_ns;
            children.full_cohort_release_authorized_ = true;
        }
    } catch (...) {
        children.poison_role_channels();
        refuse();
    }
}

} // namespace kpi::mpc::financial::registered_driver


