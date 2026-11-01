#include "registered_party_completion_transport.hpp"

#include "authenticated_baseline_owner_receiver.hpp"
#include "registered_driver_bridge.hpp"
#include "registered_parent_role_fork.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {
using Bytes = std::vector<unsigned char>;
using baseline_disclosure::PartyBaselineOwnerEffectsAuthority;
using baseline_disclosure::PrivatePartyBaselineOwnerEffects;

constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'R', 'P', 'C', '0', '3'};
constexpr std::array<unsigned char, 8> BASELINE_MAGIC{
    'K', 'P', 'B', 'B', 'O', 'E', 'P', '1'};
constexpr std::size_t PARTY_DIGESTS = 27;
constexpr std::size_t PARTY_PREFIX_BYTES = 120;
constexpr std::size_t BASELINE_OFFSET =
    PARTY_PREFIX_BYTES + 36 + PARTY_DIGESTS * Digest{}.size() + 8;
constexpr std::size_t PACKET_IDENTITY_OFFSET =
    RegisteredPartyCompletionTransport::PACKET_BYTES - Digest{}.size();
static_assert(BASELINE_OFFSET == 1028);
static_assert(BASELINE_OFFSET +
                  RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES ==
              PACKET_IDENTITY_OFFSET);

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

Digest payload_type() {
    static constexpr char domain[] =
        "KPB_REGISTERED_PARTY_COMPLETION_PACKET_V2\n";
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

void put_u64(Bytes& out, std::size_t& at, std::uint64_t value) {
    need(value > 0 && at <= out.size() && 8 <= out.size() - at);
    for (unsigned index = 0; index < 8; ++index)
        out[at++] = static_cast<unsigned char>(value >> (8 * index));
}

void put_digest(Bytes& out, std::size_t& at, const Digest& value) {
    need(nonzero(value) && at <= out.size() &&
         value.size() <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() + at);
    at += value.size();
}

void put_fixed_text(
        Bytes& out, std::size_t& at, const std::string& value,
        std::size_t exact_bytes) {
    need(value.size() == exact_bytes && at <= out.size() &&
         exact_bytes <= out.size() - at);
    std::copy(value.begin(), value.end(), out.begin() + at);
    at += exact_bytes;
}

unsigned get_byte(std::span<const unsigned char> in, std::size_t& at) {
    need(at < in.size());
    return in[at++];
}

std::int64_t get_u32(
        std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 4 <= in.size() - at);
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result |= std::uint32_t(in[at++]) << (8 * index);
    need(result > 1);
    return result;
}

std::uint64_t get_u64(
        std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 8 <= in.size() - at);
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result |= std::uint64_t(in[at++]) << (8 * index);
    need(result > 0);
    return result;
}

Digest get_digest(
        std::span<const unsigned char> in, std::size_t& at,
        bool allow_zero = false) {
    Digest result{};
    need(at <= in.size() && result.size() <= in.size() - at);
    std::copy_n(in.begin() + at, result.size(), result.begin());
    at += result.size();
    need(allow_zero || nonzero(result));
    return result;
}

std::string get_fixed_text(
        std::span<const unsigned char> in, std::size_t& at,
        std::size_t exact_bytes) {
    need(at <= in.size() && exact_bytes <= in.size() - at);
    std::string result(
        reinterpret_cast<const char*>(in.data() + at), exact_bytes);
    at += exact_bytes;
    return result;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest completion_identity(const PublicPartyDriverCompletion& value) {
    Bytes bytes;
    static constexpr char domain[] =
        "KPB_REGISTERED_PARTY_DRIVER_COMPLETION_V3\n";
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(domain), sizeof(domain) - 1));
    integer(bytes, value.role);
    integer(bytes, value.round);
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    integer(bytes, value.capture_trial_id.size());
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(
            value.capture_trial_id.data()),
        value.capture_trial_id.size()));
    for (const auto* field : {
             &value.authority_identity, &value.driver_selection_identity,
             &value.selection_identity, &value.run, &value.trial,
             &value.attempt, &value.cohort, &value.accepted_head,
             &value.postlock_accepted_head, &value.attempt_identity,
             &value.proposal_identity, &value.durable_lock,
             &value.capture_plan_identity, &value.capture_source_identity,
             &value.capture_build_identity,
             &value.capture_launcher_identity,
             &value.authorization_identity,
             &value.egress_binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity,
             &value.full_cohort_barrier_identity})
        add(bytes, *field);
    for (const auto& owner : value.owner_contracts) add(bytes, owner);
    integer(bytes, value.full_cohort_barrier_observed_monotonic_ns);
    return identity_registry::digest(bytes);
}

void require_party(
        const PublicPartyDriverCompletion& value,
        const detail::RoleCompletionBinding& binding) {
    need(value.role == binding.role && value.round == binding.round &&
         value.classification == binding.classification &&
         value.capture_trial_id == binding.capture_trial_id &&
         value.trial == RegisteredCapturePlanRosterBridge::trial_identity(
             value.capture_trial_id) &&
         value.run == binding.run && value.trial == binding.trial &&
         value.attempt == binding.attempt && value.cohort == binding.cohort &&
         value.authority_identity == binding.authority_identity &&
         value.driver_selection_identity ==
             binding.driver_selection_identity &&
         value.capture_plan_identity == binding.capture_plan_identity &&
         value.capture_source_identity == binding.capture_source_identity &&
         value.capture_build_identity == binding.capture_build_identity &&
         value.capture_launcher_identity ==
             binding.capture_launcher_identity &&
         (value.classification == CaptureClassification::HiddenCandidate ||
          value.classification == CaptureClassification::
              ExplicitOwnerPublicEffectsBaseline));
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
             &value.authorization_identity,
             &value.egress_binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity,
             &value.full_cohort_barrier_identity,
             &value.completion_identity})
        need(nonzero(*field));
    need(value.full_cohort_barrier_observed_monotonic_ns > 0);
    need(value.completion_identity == completion_identity(value));
}

void put_party(
        Bytes& out, std::size_t& at,
        const PublicPartyDriverCompletion& value) {
    put_fixed_text(out, at, value.capture_trial_id, 36);
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
             &value.authorization_identity,
             &value.egress_binding_identity, &value.effects_identity,
             &value.core_identity, &value.proof_identity,
             &value.projection_identity,
             &value.full_cohort_barrier_identity})
        put_digest(out, at, *field);
    put_u64(out, at, value.full_cohort_barrier_observed_monotonic_ns);
    put_digest(out, at, value.completion_identity);
}

PublicPartyDriverCompletion get_party(
        std::span<const unsigned char> in, std::size_t& at,
        CaptureClassification classification, unsigned round,
        unsigned role) {
    PublicPartyDriverCompletion value{
        .role = role,
        .round = round,
        .classification = classification,
        .capture_trial_id = get_fixed_text(in, at, 36),
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
        .egress_binding_identity = get_digest(in, at),
        .effects_identity = get_digest(in, at),
        .core_identity = get_digest(in, at),
        .proof_identity = get_digest(in, at),
        .projection_identity = get_digest(in, at),
        .full_cohort_barrier_identity = get_digest(in, at),
        .full_cohort_barrier_observed_monotonic_ns = get_u64(in, at),
        .completion_identity = get_digest(in, at),
    };
    return value;
}

void put_baseline(
        Bytes& out, std::size_t& at,
        const PrivatePartyBaselineOwnerEffects& value,
        const Digest& party_identity,
        const detail::RoleCompletionBinding& binding) {
    const auto begin = at;
    need(begin == BASELINE_OFFSET);
    std::copy(BASELINE_MAGIC.begin(), BASELINE_MAGIC.end(), out.begin() + at);
    at += BASELINE_MAGIC.size();
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
             &value.baseline_plan_identity,
             &value.verified_egress_identity, &value.policy_identity,
             &value.roster_authority_identity,
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
    need(at + Digest{}.size() ==
         begin + RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES);
    const auto section_identity = identity_registry::digest(std::span(
        out.data() + begin, at - begin));
    put_digest(out, at, section_identity);
    need(at == begin +
                   RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES);
}

struct DecodedBaseline {
    PrivatePartyBaselineOwnerEffects value;
    Digest identity;
};

DecodedBaseline get_baseline(
        std::span<const unsigned char> in, std::size_t& at,
        const detail::RoleCompletionBinding& binding) {
    const auto begin = at;
    need(begin == BASELINE_OFFSET &&
         in.size() >= begin +
             RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES &&
         std::equal(BASELINE_MAGIC.begin(), BASELINE_MAGIC.end(),
                    in.begin() + begin));
    at += BASELINE_MAGIC.size();
    need(get_byte(in, at) == 1);
    PrivatePartyBaselineOwnerEffects value{};
    value.classification =
        static_cast<CaptureClassification>(get_byte(in, at));
    value.round = get_byte(in, at);
    value.role = get_byte(in, at);
    need(value.role == binding.role && value.round == binding.round &&
         get_u32(in, at) == binding.parent_pid &&
         get_u32(in, at) == binding.child_pid &&
         get_digest(in, at) == binding.fork_plan_identity &&
         get_digest(in, at) == binding.offer_identity &&
         get_digest(in, at) == binding.ack_identity);
    const auto supplied_identity = get_digest(in, at);
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
    need(at + Digest{}.size() ==
         begin + RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES);
    const auto supplied_section = get_digest(in, at);
    need(supplied_section == identity_registry::digest(
        in.subspan(begin, at - begin - Digest{}.size())));
    return {std::move(value), supplied_identity};
}

Digest observation_identity(
        const PublicPartyDriverCompletion& party,
        const detail::RoleCompletionBinding& binding,
        const Digest& baseline_identity) {
    Bytes bytes;
    static constexpr char domain[] =
        "KPB_PARENT_OBSERVED_REGISTERED_PARTY_COMPLETION_V1\n";
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(domain), sizeof(domain) - 1));
    integer(bytes, party.role);
    integer(bytes, party.round);
    integer(bytes, static_cast<unsigned>(party.classification));
    integer(bytes, static_cast<std::uint64_t>(binding.parent_pid));
    integer(bytes, static_cast<std::uint64_t>(binding.child_pid));
    for (const auto* value : {
             &binding.fork_plan_identity, &binding.offer_identity,
             &binding.ack_identity,
             &binding.fresh_owner_issuance_identity,
             &party.completion_identity})
        add(bytes, *value);
    integer(bytes, nonzero(baseline_identity) ? 1 : 0);
    if (nonzero(baseline_identity)) add(bytes, baseline_identity);
    return identity_registry::digest(bytes);
}

Bytes encode(
        const PublicPartyDriverCompletion& party,
        const PrivatePartyBaselineOwnerEffects* baseline,
        const Digest& baseline_identity,
        const detail::RoleCompletionBinding& binding) {
    require_party(party, binding);
    const bool has_baseline = baseline != nullptr;
    need(has_baseline ==
         (party.classification == CaptureClassification::
             ExplicitOwnerPublicEffectsBaseline));
    Bytes out(RegisteredPartyCompletionTransport::PACKET_BYTES);
    std::copy(MAGIC.begin(), MAGIC.end(), out.begin());
    std::size_t at = MAGIC.size();
    put_byte(out, at, 1);
    put_byte(out, at, static_cast<unsigned>(party.classification));
    put_byte(out, at, party.round);
    put_byte(out, at, party.role);
    put_byte(out, at, has_baseline ? 1 : 0);
    put_byte(out, at, 0);
    put_byte(out, at, 0);
    put_byte(out, at, 0);
    put_u32(out, at, binding.parent_pid);
    put_u32(out, at, binding.child_pid);
    put_digest(out, at, binding.fork_plan_identity);
    put_digest(out, at, binding.offer_identity);
    put_digest(out, at, binding.ack_identity);
    put_party(out, at, party);
    need(at == BASELINE_OFFSET);
    if (baseline) {
        const auto& value = *baseline;
        need(value.classification == party.classification &&
             value.round == party.round && value.role == party.role &&
             value.run == party.run && value.trial == party.trial &&
             value.attempt == party.attempt && value.cohort == party.cohort &&
             value.capture_plan_identity == party.capture_plan_identity &&
             value.projection_identity == party.projection_identity &&
             value.owner_contracts == party.owner_contracts &&
             nonzero(baseline_identity));
        put_baseline(out, at, value, baseline_identity, binding);
    } else {
        at += RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES;
    }
    need(at == PACKET_IDENTITY_OFFSET);
    const auto packet_identity = identity_registry::digest(
        std::span<const unsigned char>(out.data(), at));
    put_digest(out, at, packet_identity);
    need(at == out.size());
    return out;
}

struct Decoded {
    PublicPartyDriverCompletion party;
    std::optional<DecodedBaseline> baseline;
};

Decoded decode(
        std::span<const unsigned char> in,
        const detail::RoleCompletionBinding& binding) {
    need(in.size() == RegisteredPartyCompletionTransport::PACKET_BYTES &&
         std::equal(MAGIC.begin(), MAGIC.end(), in.begin()));
    std::size_t at = MAGIC.size();
    need(get_byte(in, at) == 1);
    const auto classification =
        static_cast<CaptureClassification>(get_byte(in, at));
    const auto round = get_byte(in, at);
    const auto role = get_byte(in, at);
    const auto baseline_tag = get_byte(in, at);
    need(baseline_tag <= 1);
    const bool has_baseline = baseline_tag == 1;
    need(get_byte(in, at) == 0 && get_byte(in, at) == 0 &&
         get_byte(in, at) == 0 && role == binding.role &&
         round == binding.round && get_u32(in, at) == binding.parent_pid &&
         get_u32(in, at) == binding.child_pid &&
         get_digest(in, at) == binding.fork_plan_identity &&
         get_digest(in, at) == binding.offer_identity &&
         get_digest(in, at) == binding.ack_identity);
    auto party = get_party(in, at, classification, round, role);
    require_party(party, binding);
    need(at == BASELINE_OFFSET &&
         has_baseline ==
             (classification == CaptureClassification::
                 ExplicitOwnerPublicEffectsBaseline));
    std::optional<DecodedBaseline> baseline;
    if (has_baseline) {
        baseline.emplace(get_baseline(in, at, binding));
        const auto& value = baseline->value;
        need(value.classification == party.classification &&
             value.round == party.round && value.role == party.role &&
             value.run == party.run && value.trial == party.trial &&
             value.attempt == party.attempt && value.cohort == party.cohort &&
             value.capture_plan_identity == party.capture_plan_identity &&
             value.projection_identity == party.projection_identity &&
             value.owner_contracts == party.owner_contracts);
    } else {
        need(std::all_of(
            in.begin() + at,
            in.begin() + at +
                RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES,
            [](unsigned char value) { return value == 0; }));
        at += RegisteredPartyCompletionTransport::BASELINE_SECTION_BYTES;
    }
    need(at == PACKET_IDENTITY_OFFSET);
    const auto supplied_packet_identity = get_digest(in, at);
    need(at == in.size() && supplied_packet_identity ==
         identity_registry::digest(in.first(PACKET_IDENTITY_OFFSET)));
    return {std::move(party), std::move(baseline)};
}
} // namespace

struct ParentObservedPartyCompletionAuthority::Storage {
    PublicParentObservedPartyCompletion observation;
    PublicPartyDriverCompletion party;
    Storage(PublicParentObservedPartyCompletion selected,
            PublicPartyDriverCompletion completion)
        : observation(std::move(selected)), party(std::move(completion)) {}
};

ParentObservedPartyCompletionAuthority::
ParentObservedPartyCompletionAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
ParentObservedPartyCompletionAuthority::
ParentObservedPartyCompletionAuthority(
        ParentObservedPartyCompletionAuthority&&) noexcept = default;
ParentObservedPartyCompletionAuthority::~
ParentObservedPartyCompletionAuthority() = default;
const PublicParentObservedPartyCompletion&
ParentObservedPartyCompletionAuthority::public_observation() const {
    need(storage_ != nullptr);
    return storage_->observation;
}
const PublicPartyDriverCompletion&
ParentObservedPartyCompletionAuthority::public_party_completion() const {
    need(storage_ != nullptr);
    return storage_->party;
}

struct ParentObservedRegisteredPartyResult::Storage {
    std::optional<ParentObservedPartyCompletionAuthority> completion;
    std::optional<PartyBaselineOwnerEffectsAuthority> baseline;
    Storage(ParentObservedPartyCompletionAuthority&& selected,
            std::optional<PartyBaselineOwnerEffectsAuthority>&& effects)
        : completion(std::move(selected)), baseline(std::move(effects)) {}
};

ParentObservedRegisteredPartyResult::ParentObservedRegisteredPartyResult(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}
ParentObservedRegisteredPartyResult::ParentObservedRegisteredPartyResult(
        ParentObservedRegisteredPartyResult&&) noexcept = default;
ParentObservedRegisteredPartyResult::~ParentObservedRegisteredPartyResult() =
    default;
bool ParentObservedRegisteredPartyResult::has_baseline_effects() const {
    need(storage_ != nullptr);
    return storage_->baseline.has_value();
}
ParentObservedPartyCompletionAuthority
ParentObservedRegisteredPartyResult::take_party_completion() {
    need(storage_ != nullptr && storage_->completion.has_value());
    auto result = std::move(*storage_->completion);
    storage_->completion.reset();
    return result;
}
PartyBaselineOwnerEffectsAuthority
ParentObservedRegisteredPartyResult::take_baseline_effects() {
    need(storage_ != nullptr && storage_->baseline.has_value());
    auto result = std::move(*storage_->baseline);
    storage_->baseline.reset();
    return result;
}

void RegisteredPartyCompletionTransport::submit_hidden(
        PartyDriverCompletionAuthority&& supplied,
        ChildRoleCompletionEndpointAuthority&& endpoint) {
    try {
        need(supplied.live_.exchange(false) &&
             supplied.receipt_.classification ==
                 CaptureClassification::HiddenCandidate);
        const auto packet = encode(supplied.receipt_, nullptr, Digest{},
                                   endpoint.binding_);
        endpoint.send_fixed(payload_type(), packet);
    } catch (...) { refuse(); }
}

void RegisteredPartyCompletionTransport::submit_baseline(
        PartyDriverCompletionAuthority&& supplied,
        PartyBaselineOwnerEffectsAuthority&& effects,
        ChildRoleCompletionEndpointAuthority&& endpoint) {
    try {
        const bool completion_live = supplied.live_.exchange(false);
        const bool effects_live = effects.live_.exchange(false);
        need(completion_live && effects_live &&
             supplied.receipt_.classification ==
                 CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
        const auto packet = encode(supplied.receipt_, &effects.value_,
                                   effects.identity_,
                                   endpoint.binding_);
        endpoint.send_fixed(payload_type(), packet);
    } catch (...) { refuse(); }
}

ParentObservedRegisteredPartyResult
RegisteredPartyCompletionTransport::receive(
        ParentRoleCompletionEndpointAuthority&& endpoint) {
    try {
        const auto packet = endpoint.receive_fixed(
            payload_type(), PACKET_BYTES);
        auto decoded = decode(packet, endpoint.binding_);
        std::optional<PartyBaselineOwnerEffectsAuthority> baseline;
        Digest baseline_identity{};
        if (decoded.baseline) {
            baseline_identity = decoded.baseline->identity;
            PartyBaselineOwnerEffectsAuthority selected(
                std::move(decoded.baseline->value));
            baseline.emplace(std::move(selected));
            need(baseline->identity_ == baseline_identity);
        }
        const auto observed_identity = observation_identity(
            decoded.party, endpoint.binding_, baseline_identity);
        need(nonzero(observed_identity));
        PublicParentObservedPartyCompletion observation{
            .role = decoded.party.role,
            .round = decoded.party.round,
            .parent_pid = endpoint.binding_.parent_pid,
            .child_pid = endpoint.binding_.child_pid,
            .fork_plan_identity = endpoint.binding_.fork_plan_identity,
            .offer_identity = endpoint.binding_.offer_identity,
            .acknowledgement_identity = endpoint.binding_.ack_identity,
            .fresh_owner_issuance_identity =
                endpoint.binding_.fresh_owner_issuance_identity,
            .party_completion_identity =
                decoded.party.completion_identity,
            .observation_identity = observed_identity,
        };
        auto observed = ParentObservedPartyCompletionAuthority(
            std::make_unique<ParentObservedPartyCompletionAuthority::Storage>(
                std::move(observation), std::move(decoded.party)));
        return ParentObservedRegisteredPartyResult(
            std::make_unique<ParentObservedRegisteredPartyResult::Storage>(
                std::move(observed), std::move(baseline)));
    } catch (...) { refuse(); }
}

#ifdef KPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP
void RegisteredPartyCompletionTransport::
test_only_submit_hidden_invalid_baseline_tag(
        PartyDriverCompletionAuthority&& supplied,
        ChildRoleCompletionEndpointAuthority&& endpoint) {
    try {
        need(supplied.live_.exchange(false) &&
             supplied.receipt_.classification ==
                 CaptureClassification::HiddenCandidate);
        auto packet = encode(
            supplied.receipt_, nullptr, Digest{}, endpoint.binding_);
        packet[12] = 2;
        const auto identity = identity_registry::digest(
            std::span<const unsigned char>(
                packet.data(), PACKET_IDENTITY_OFFSET));
        std::copy(identity.begin(), identity.end(),
                  packet.begin() + PACKET_IDENTITY_OFFSET);
        endpoint.send_fixed(payload_type(), packet);
    } catch (...) { refuse(); }
}

void RegisteredPartyCompletionTransport::
test_only_submit_hidden_duplicate_terminal(
        PartyDriverCompletionAuthority&& supplied,
        ChildRoleCompletionEndpointAuthority&& endpoint) {
    try {
        need(supplied.live_.exchange(false) &&
             supplied.receipt_.classification ==
                 CaptureClassification::HiddenCandidate);
        const auto packet = encode(
            supplied.receipt_, nullptr, Digest{}, endpoint.binding_);
        endpoint.test_only_send_fixed_duplicate(payload_type(), packet);
    } catch (...) { refuse(); }
}
#endif

#ifdef KPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP
PartyDriverCompletionAuthority
RegisteredPartyCompletionTransportTestBridge::mint_party(
        PublicPartyDriverCompletion value) {
    need(!nonzero(value.completion_identity));
    value.completion_identity = completion_identity(value);
    return PartyDriverCompletionAuthority(std::move(value));
}
#endif

} // namespace kpi::mpc::financial::registered_driver
