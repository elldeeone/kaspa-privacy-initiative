#include "authenticated_baseline_owner_receiver.hpp"

#include <algorithm>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <span>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}

template<std::size_t N>
void distinct(const std::array<Digest, N>& values) {
    for (std::size_t index = 0; index < values.size(); ++index) {
        need(nonzero(values[index]));
        for (std::size_t prior = 0; prior < index; ++prior)
            need(values[index] != values[prior]);
    }
}

Digest pre_disclosure_nonce(
        const BaselineOwnerPreDisclosureBinding& value) {
    need(value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         (value.round == 1 || value.round == 2) && value.owner < 3);
    Bytes bytes;
    text(bytes, "KPB_BASELINE_OWNER_PRE_DISCLOSURE_NONCE_V1\n");
    bytes.push_back(static_cast<unsigned char>(value.classification));
    bytes.push_back(static_cast<unsigned char>(value.round));
    bytes.push_back(static_cast<unsigned char>(value.owner));
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.owner_contract_identity,
             &value.relation_source_identity,
             &value.owner_effects_recipe_identity, &value.policy_identity,
             &value.roster_authority_identity, &value.roster_root_identity}) {
        need(nonzero(*field));
        add(bytes, *field);
    }
    return hash(bytes);
}

Digest pre_disclosure_consent_identity(
        const BaselineOwnerPreDisclosureConsentReceipt& value) {
    Bytes bytes;
    text(bytes, "KPB_BASELINE_OWNER_PRE_DISCLOSURE_CONSENT_V1\n");
    integer(bytes, static_cast<unsigned char>(value.classification));
    integer(bytes, value.round); integer(bytes, value.role);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.relation_source_identity,
             &value.owner_effects_recipe_identity,
             &value.baseline_plan_identity, &value.verified_egress_identity,
             &value.policy_identity, &value.roster_authority_identity,
             &value.roster_root_identity})
        add(bytes, *field);
    for (const auto& field : value.pre_challenge_identities) add(bytes, field);
    for (const auto& field : value.owner_contracts) add(bytes, field);
    for (const auto& field : value.logical_owner_identities) add(bytes, field);
    for (const auto& field : value.owner_proof_sessions) add(bytes, field);
    return hash(bytes);
}

void valid(const BaselineOwnerPreDisclosureConsentReceipt& value) {
    need(value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         (value.round == 1 || value.round == 2) && value.role < 3);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.relation_source_identity,
             &value.owner_effects_recipe_identity,
             &value.baseline_plan_identity, &value.verified_egress_identity,
             &value.policy_identity, &value.roster_authority_identity,
             &value.roster_root_identity,
             &value.consent_identity})
        need(nonzero(*field));
    distinct(value.pre_challenge_identities);
    distinct(value.owner_contracts);
    distinct(value.logical_owner_identities);
    distinct(value.owner_proof_sessions);
    need(value.consent_identity == pre_disclosure_consent_identity(value));
}

void valid(const PrivateOwnerScoringTruth& value) {
    need(value.owner < 3 && (value.round == 1 || value.round == 2) &&
         value.public_tuple_hashes[0] < value.public_tuple_hashes[1] &&
         value.public_tuple_commitments[0] !=
             value.public_tuple_commitments[1]);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.owner_contract_identity,
             &value.logical_owner_identity,
             &value.roster_authority_identity,
             &value.roster_root_identity,
             &value.pre_disclosure_challenge_identity,
             &value.public_nullifier, &value.public_tuple_hashes[0],
             &value.public_tuple_hashes[1],
             &value.public_tuple_commitments[0],
             &value.public_tuple_commitments[1]})
        need(nonzero(*field));
}

void valid(const PrivatePartyBaselineOwnerEffects& value) {
    need(value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         (value.round == 1 || value.round == 2) && value.role < 3);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.relation_source_identity,
             &value.owner_effects_recipe_identity,
             &value.baseline_plan_identity, &value.verified_egress_identity,
             &value.policy_identity, &value.roster_authority_identity,
             &value.roster_root_identity, &value.consent_nonce})
        need(nonzero(*field));
    distinct(value.owner_contracts);
    distinct(value.logical_owner_identities);
    distinct(value.pre_disclosure_challenge_identities);
    distinct(value.owner_sessions);
    for (unsigned owner = 0; owner < value.owner_truth.size(); ++owner) {
        const auto& truth = value.owner_truth[owner];
        valid(truth);
        need(truth.owner == owner && truth.round == value.round &&
             truth.run == value.run && truth.trial == value.trial &&
             truth.attempt == value.attempt &&
             truth.cohort == value.cohort &&
             truth.capture_plan_identity == value.capture_plan_identity &&
             truth.projection_identity == value.projection_identity &&
             truth.context_identity == value.context_identity &&
             truth.owner_contract_identity == value.owner_contracts[owner] &&
             truth.logical_owner_identity ==
                 value.logical_owner_identities[owner] &&
             truth.roster_authority_identity ==
                 value.roster_authority_identity &&
             truth.roster_root_identity == value.roster_root_identity &&
             truth.pre_disclosure_challenge_identity ==
                 value.pre_disclosure_challenge_identities[owner]);
    }
}

Digest party_identity(const PrivatePartyBaselineOwnerEffects& value) {
    Bytes bytes;
    text(bytes, "KPB_PARTY_BASELINE_OWNER_EFFECTS_V1\n");
    integer(bytes, static_cast<unsigned char>(value.classification));
    integer(bytes, value.round); integer(bytes, value.role);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.relation_source_identity,
             &value.owner_effects_recipe_identity,
             &value.baseline_plan_identity, &value.verified_egress_identity,
             &value.policy_identity, &value.roster_authority_identity,
             &value.roster_root_identity, &value.consent_nonce})
        add(bytes, *field);
    for (const auto& field : value.owner_contracts) add(bytes, field);
    for (const auto& field : value.logical_owner_identities) add(bytes, field);
    for (const auto& field : value.pre_disclosure_challenge_identities)
        add(bytes, field);
    for (const auto& field : value.owner_sessions) add(bytes, field);
    for (const auto& truth : value.owner_truth) {
        integer(bytes, truth.owner); integer(bytes, truth.round);
        for (const auto* field : {
                 &truth.public_nullifier, &truth.public_tuple_hashes[0],
                 &truth.public_tuple_hashes[1],
                 &truth.public_tuple_commitments[0],
                 &truth.public_tuple_commitments[1]}) add(bytes, *field);
    }
    return hash(bytes);
}

bool shared_round_equal(const PrivatePartyBaselineOwnerEffects& left,
                        const PrivatePartyBaselineOwnerEffects& right) {
    return left.classification == right.classification &&
        left.round == right.round && left.run == right.run &&
        left.trial == right.trial &&
        left.attempt == right.attempt && left.cohort == right.cohort &&
        left.capture_plan_identity == right.capture_plan_identity &&
        left.projection_identity == right.projection_identity &&
        left.context_identity == right.context_identity &&
        left.relation_source_identity == right.relation_source_identity &&
        left.owner_effects_recipe_identity ==
            right.owner_effects_recipe_identity &&
        left.policy_identity == right.policy_identity &&
        left.roster_authority_identity == right.roster_authority_identity &&
        left.roster_root_identity == right.roster_root_identity &&
        left.consent_nonce == right.consent_nonce &&
        left.owner_contracts == right.owner_contracts &&
        left.logical_owner_identities == right.logical_owner_identities &&
        left.pre_disclosure_challenge_identities ==
            right.pre_disclosure_challenge_identities &&
        left.owner_truth == right.owner_truth;
}
} // namespace

BaselineOwnerPreDisclosureProtocol::Challenge
BaselineOwnerPreDisclosureProtocol::challenge(
        BaselineOwnerPreDisclosureBinding value) {
    static constexpr std::array<unsigned char, 8> magic{
        'K','P','B','B','O','E','P','1'};
    value.nonce = pre_disclosure_nonce(value);
    Bytes bytes(magic.begin(), magic.end());
    bytes.push_back(static_cast<unsigned char>(value.classification));
    bytes.push_back(static_cast<unsigned char>(value.round));
    bytes.push_back(static_cast<unsigned char>(value.owner));
    add(bytes, value.nonce);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.owner_contract_identity,
             &value.relation_source_identity,
             &value.owner_effects_recipe_identity, &value.policy_identity,
             &value.roster_authority_identity, &value.roster_root_identity})
        add(bytes, *field);
    need(bytes.size() == CHALLENGE_BYTES);
    Challenge result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

BaselineOwnerPreDisclosureBinding
BaselineOwnerPreDisclosureProtocol::parse(
        std::span<const unsigned char> bytes) {
    static constexpr std::array<unsigned char, 8> magic{
        'K','P','B','B','O','E','P','1'};
    need(bytes.size() == CHALLENGE_BYTES &&
         std::equal(magic.begin(), magic.end(), bytes.begin()));
    std::size_t at = magic.size();
    BaselineOwnerPreDisclosureBinding result{};
    result.classification = static_cast<CaptureClassification>(bytes[at++]);
    result.round = bytes[at++]; result.owner = bytes[at++];
    auto take = [&](Digest& field) {
        need(at <= bytes.size() && field.size() <= bytes.size() - at);
        std::copy_n(bytes.begin() + at, field.size(), field.begin());
        at += field.size();
    };
    take(result.nonce); take(result.run); take(result.trial);
    take(result.attempt); take(result.cohort);
    take(result.capture_plan_identity); take(result.projection_identity);
    take(result.context_identity); take(result.owner_contract_identity);
    take(result.relation_source_identity);
    take(result.owner_effects_recipe_identity); take(result.policy_identity);
    take(result.roster_authority_identity); take(result.roster_root_identity);
    need(at == bytes.size() && result.nonce == pre_disclosure_nonce(result));
    return result;
}

BaselineOwnerPreDisclosureConsentAuthority::
BaselineOwnerPreDisclosureConsentAuthority(
        BaselineOwnerPreDisclosureConsentReceipt receipt)
    : receipt_(std::move(receipt)) {
    need(receipt_.consent_identity == Digest{});
    receipt_.consent_identity = pre_disclosure_consent_identity(receipt_);
    valid(receipt_);
}

BaselineOwnerPreDisclosureConsentAuthority::
BaselineOwnerPreDisclosureConsentAuthority(
        BaselineOwnerPreDisclosureConsentAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

BaselineOwnerPreDisclosureConsentReceipt
BaselineOwnerPreDisclosureConsentAuthority::consume_for_recipe() {
    need(live_.exchange(false));
    valid(receipt_);
    return receipt_;
}

Digest BaselineOwnerConsentProtocol::consent_nonce(
        CaptureClassification classification,
        const PrivateOwnerScoringTruth& truth,
        const Digest& relation_source_identity,
        const Digest& owner_effects_recipe_identity,
        const Digest& policy_identity) {
    valid(truth);
    need(classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         nonzero(relation_source_identity) &&
         nonzero(owner_effects_recipe_identity) && nonzero(policy_identity));
    Bytes bytes;
    text(bytes, "KPB_BASELINE_OWNER_CONSENT_NONCE_V1\n");
    bytes.push_back(static_cast<unsigned char>(classification));
    bytes.push_back(static_cast<unsigned char>(truth.round));
    for (const auto* field : {
             &truth.run, &truth.trial, &truth.attempt, &truth.cohort,
             &truth.capture_plan_identity, &truth.projection_identity,
             &truth.context_identity, &truth.roster_authority_identity,
             &truth.roster_root_identity, &relation_source_identity,
             &owner_effects_recipe_identity, &policy_identity}) add(bytes, *field);
    return hash(bytes);
}

BaselineOwnerConsentProtocol::Challenge
BaselineOwnerConsentProtocol::challenge(
        CaptureClassification classification,
        const PrivateOwnerScoringTruth& truth,
        const Digest& relation_source_identity,
        const Digest& owner_effects_recipe_identity,
        const Digest& policy_identity,
        const Digest& pre_disclosure_challenge_identity,
        const Digest& nonce) {
    static constexpr std::array<unsigned char, 8> magic{
        'K','P','B','B','O','E','R','1'};
    need(nonce == consent_nonce(classification, truth,
                                relation_source_identity,
                                owner_effects_recipe_identity,
                                policy_identity) &&
         pre_disclosure_challenge_identity ==
             truth.pre_disclosure_challenge_identity);
    Bytes bytes(magic.begin(), magic.end());
    bytes.push_back(static_cast<unsigned char>(classification));
    bytes.push_back(static_cast<unsigned char>(truth.round));
    bytes.push_back(static_cast<unsigned char>(truth.owner));
    add(bytes, nonce);
    for (const auto* field : {
             &truth.run, &truth.trial, &truth.attempt, &truth.cohort,
             &truth.capture_plan_identity, &truth.projection_identity,
             &truth.context_identity, &truth.owner_contract_identity,
             &truth.logical_owner_identity,
             &truth.roster_authority_identity,
             &truth.roster_root_identity,
             &pre_disclosure_challenge_identity,
             &truth.public_nullifier, &truth.public_tuple_hashes[0],
             &truth.public_tuple_hashes[1],
             &truth.public_tuple_commitments[0],
             &truth.public_tuple_commitments[1], &relation_source_identity,
             &owner_effects_recipe_identity, &policy_identity}) add(bytes, *field);
    need(bytes.size() == CHALLENGE_BYTES);
    Challenge result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

BaselineOwnerConsentProtocol::Acknowledgment
BaselineOwnerConsentProtocol::acknowledge(const Challenge& challenge) {
    static constexpr std::array<unsigned char, 8> magic{
        'K','P','B','B','O','E','A','1'};
    Acknowledgment result{};
    std::copy(magic.begin(), magic.end(), result.begin());
    const auto identity = hash(challenge);
    std::copy(identity.begin(), identity.end(), result.begin() + magic.size());
    return result;
}

void BaselineOwnerConsentProtocol::require_acknowledgment(
        const Challenge& challenge, const Acknowledgment& supplied) {
    const auto expected = acknowledge(challenge);
    need(CRYPTO_memcmp(expected.data(), supplied.data(), expected.size()) == 0);
}

PartyBaselineOwnerEffectsAuthority::PartyBaselineOwnerEffectsAuthority(
        PrivatePartyBaselineOwnerEffects value) : value_(std::move(value)) {
    valid(value_);
    identity_ = party_identity(value_);
}

PartyBaselineOwnerEffectsAuthority::PartyBaselineOwnerEffectsAuthority(
        PartyBaselineOwnerEffectsAuthority&& other) noexcept
    : value_(other.value_), identity_(other.identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
PartyBaselineOwnerEffectsAuthority
PartyBaselineOwnerEffectsAuthority::test_only_mint(
        PrivatePartyBaselineOwnerEffects value) {
    return PartyBaselineOwnerEffectsAuthority(std::move(value));
}
#endif

OwnerScoreTruthAuthority::OwnerScoreTruthAuthority(
        std::array<PrivateOwnerScoringTruth, 2> rounds,
        std::array<std::array<Digest, 3>, 2> sessions)
    : rounds_(std::move(rounds)), party_sessions_(std::move(sessions)) {
    need(rounds_[0].owner == rounds_[1].owner &&
         rounds_[0].round == 1 && rounds_[1].round == 2 &&
         rounds_[0].run != rounds_[1].run &&
         rounds_[0].trial == rounds_[1].trial &&
         rounds_[0].attempt != rounds_[1].attempt &&
         rounds_[0].cohort != rounds_[1].cohort &&
         rounds_[0].capture_plan_identity !=
             rounds_[1].capture_plan_identity &&
         rounds_[0].projection_identity != rounds_[1].projection_identity);
    need(rounds_[0].logical_owner_identity ==
             rounds_[1].logical_owner_identity &&
         rounds_[0].roster_authority_identity ==
             rounds_[1].roster_authority_identity &&
         rounds_[0].roster_root_identity ==
             rounds_[1].roster_root_identity &&
         rounds_[0].pre_disclosure_challenge_identity !=
             rounds_[1].pre_disclosure_challenge_identity);
    valid(rounds_[0]); valid(rounds_[1]);
    std::array<Digest, 6> flattened{};
    std::size_t at = 0;
    for (const auto& round : party_sessions_)
        for (const auto& session : round) flattened[at++] = session;
    distinct(flattened);
}

OwnerScoreTruthAuthority::OwnerScoreTruthAuthority(
        OwnerScoreTruthAuthority&& other) noexcept
    : rounds_(other.rounds_), party_sessions_(other.party_sessions_),
      live_(other.live_.exchange(false)) {}

struct BaselineOwnerScoringLaunchAuthority::Storage {
    std::array<std::optional<OwnerScoreTruthAuthority>, 3> owners;
    std::mutex mutex;
    explicit Storage(std::array<OwnerScoreTruthAuthority, 3>&& values)
        : owners{std::move(values[0]), std::move(values[1]),
                 std::move(values[2])} {}
};

BaselineOwnerScoringLaunchAuthority::BaselineOwnerScoringLaunchAuthority(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
BaselineOwnerScoringLaunchAuthority::BaselineOwnerScoringLaunchAuthority(
        BaselineOwnerScoringLaunchAuthority&&) noexcept = default;
BaselineOwnerScoringLaunchAuthority::~BaselineOwnerScoringLaunchAuthority() =
    default;

OwnerScoreTruthAuthority BaselineOwnerScoringLaunchAuthority::take_owner(
        unsigned owner) {
    if (!storage_) refuse();
    std::lock_guard guard(storage_->mutex);
    if (owner >= storage_->owners.size() ||
        !storage_->owners[owner]) refuse();
    auto result = std::move(*storage_->owners[owner]);
    storage_->owners[owner].reset();
    return result;
}

void BaselineOwnerScoringParentCollector::submit(
        PartyBaselineOwnerEffectsAuthority&& supplied) {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && !finished_ && supplied.live_.exchange(false));
        valid(supplied.value_);
        const auto round = supplied.value_.round - 1;
        const auto role = supplied.value_.role;
        need(!parties_[round][role].has_value());
        for (unsigned other = 0; other < parties_[round].size(); ++other) {
            if (!parties_[round][other]) continue;
            need(shared_round_equal(*parties_[round][other], supplied.value_) &&
                 parties_[round][other]->baseline_plan_identity !=
                     supplied.value_.baseline_plan_identity &&
                 parties_[round][other]->verified_egress_identity !=
                     supplied.value_.verified_egress_identity);
            for (const auto& prior : parties_[round][other]->owner_sessions)
                for (const auto& current : supplied.value_.owner_sessions)
                    need(prior != current);
        }
        parties_[round][role] = supplied.value_;
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

BaselineOwnerScoringLaunchAuthority
BaselineOwnerScoringParentCollector::finish() {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && !finished_);
        for (const auto& round : parties_)
            for (const auto& party : round) need(party.has_value());
        const auto& first = *parties_[0][0];
        const auto& second = *parties_[1][0];
        need(first.run != second.run && first.trial == second.trial &&
             first.round == 1 &&
             second.round == 2 && first.attempt != second.attempt &&
             first.cohort != second.cohort &&
             first.capture_plan_identity != second.capture_plan_identity &&
             first.projection_identity != second.projection_identity &&
             first.context_identity != second.context_identity &&
             first.consent_nonce != second.consent_nonce &&
             first.relation_source_identity ==
                 second.relation_source_identity &&
             first.owner_effects_recipe_identity ==
                 second.owner_effects_recipe_identity &&
             first.logical_owner_identities ==
                 second.logical_owner_identities &&
             first.roster_authority_identity ==
                 second.roster_authority_identity &&
             first.roster_root_identity == second.roster_root_identity &&
             first.pre_disclosure_challenge_identities !=
                 second.pre_disclosure_challenge_identities &&
             first.policy_identity == second.policy_identity);

        std::array<Digest, 6> plan_identities{}, egress_identities{};
        std::array<Digest, 18> session_identities{};
        std::size_t at = 0, session_at = 0;
        for (const auto& round : parties_)
            for (const auto& party : round) {
                plan_identities[at] = party->baseline_plan_identity;
                egress_identities[at] = party->verified_egress_identity;
                ++at;
                for (const auto& session : party->owner_sessions)
                    session_identities[session_at++] = session;
            }
        distinct(plan_identities); distinct(egress_identities);
        distinct(session_identities);

        const auto make_owner = [&](unsigned owner) {
            std::array<std::array<Digest, 3>, 2> sessions{};
            for (unsigned round = 0; round < 2; ++round)
                for (unsigned role = 0; role < 3; ++role)
                    sessions[round][role] =
                        parties_[round][role]->owner_sessions[owner];
            return OwnerScoreTruthAuthority(
                {first.owner_truth[owner], second.owner_truth[owner]},
                sessions);
        };
        std::array<OwnerScoreTruthAuthority, 3> owners{
            make_owner(0), make_owner(1), make_owner(2)};
        finished_ = true;
        return BaselineOwnerScoringLaunchAuthority(
            std::make_unique<BaselineOwnerScoringLaunchAuthority::Storage>(
                std::move(owners)));
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

AuthenticatedBaselineOwnerReceiverSourceStatus
authenticated_baseline_owner_receiver_source_status() {
    return {
        .schema = "kpb-authenticated-baseline-owner-receiver-source-only/v1",
        .status = "CONFIGURED0_UNQUALIFIED",
        .exact_three_party_two_round_join = true,
        .owner_effect_source_consumed = true,
        .mutual_tls_owner_reauthentication = true,
        .challenge_ack_bound_to_nonce_and_projection = true,
        .hidden_candidate_receiver_factory_absent = true,
        .owner_truth_routed_only_to_private_scorer = true,
        .private_role_completion_transport_integrated = true,
        .parent_three_by_two_join_integrated = true,
        .observer_capture_export = true,
        .parent_worker_process_launch_integrated = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
