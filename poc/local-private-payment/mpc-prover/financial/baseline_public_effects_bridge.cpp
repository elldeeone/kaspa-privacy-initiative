#include "baseline_public_effects_collector.hpp"
#include "construction.hpp"

#include "../history/epoch_ticket.hpp"

#include <algorithm>
#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}

Digest verified_egress_identity(
        const PublicAuthorizedAttempt& attempt,
        const history::EgressRelease& release) {
    const auto& packet = release.packet();
    Bytes bytes;
    text(bytes, "KPB_BASELINE_VERIFIED_REGISTERED_EGRESS_V1\n");
    for (const auto* field : {
             &attempt.authorization_identity, &attempt.durable_lock,
             &attempt.capture_plan_identity, &release.binding_identity(),
             &packet.effects, &packet.core, &packet.aggregate_proof,
             &packet.projection})
        add(bytes, *field);
    return identity_registry::digest(bytes);
}
} // namespace

VerifiedBaselinePublicEffectsAuthority
BaselineDisclosureAuthorityBridge::from_registered_egress(
        const FinancialConstruction& construction,
        const history::EgressRelease& release) {
    try {
        auto claim = RegisteredBaselineConstructionBridge::
            claim_baseline_effects(construction);
        const auto attempt = claim.consume();
        const auto& packet = release.packet();
        const auto core = release.core();
        const auto proof = release.aggregate_proof();
        const auto projection = release.projection();
        need(attempt.classification ==
                 CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
             (attempt.round == 1 || attempt.round == 2) &&
             attempt.durable_lock == release.binding_identity() &&
             core.size() == FinancialConstruction::CORE_BYTES &&
             proof.size() == 128 && projection.size() == 10685 &&
             std::equal(core.begin(), core.end(), projection.begin() + 193) &&
             std::equal(proof.begin(), proof.end(),
                        projection.begin() + 193 + core.size()) &&
             identity_registry::digest(core) == packet.core &&
             identity_registry::digest(core) == packet.effects &&
             identity_registry::digest(proof) == packet.aggregate_proof &&
             identity_registry::digest(projection) == packet.projection &&
             history::canonical_history_nullifiers(core) ==
                 packet.nullifiers);

        constexpr std::size_t first_output = 692;
        constexpr std::size_t output_bytes = 520;
        std::array<Digest, 6> tuples{};
        for (std::size_t index = 0; index < tuples.size(); ++index) {
            const auto at = first_output + output_bytes * index;
            need(at <= core.size() && output_bytes <= core.size() - at);
            tuples[index] = identity_registry::digest(
                core.subspan(at, output_bytes));
        }
        std::sort(tuples.begin(), tuples.end());

        PublicBaselineEffectsPlan value{
            .classification = attempt.classification,
            .round = attempt.round,
            .run = attempt.run,
            .trial = attempt.trial,
            .attempt = attempt.attempt,
            .cohort = attempt.cohort,
            .capture_plan_identity = attempt.capture_plan_identity,
            .projection_identity = packet.projection,
            .context_identity = identity_registry::digest(
                core.subspan(8, 276)),
            .verified_egress_identity =
                verified_egress_identity(attempt, release),
            .owner_contracts = attempt.owner_contracts,
            .public_nullifiers = packet.nullifiers,
            .public_tuple_hashes = tuples,
            .policy_identity = policy_identity(),
        };
        return VerifiedBaselinePublicEffectsAuthority(std::move(value));
    } catch (...) { refuse(); }
}

ExplicitOwnerPublicEffectsAuthority
ExplicitOwnerPublicEffectsAuthority::from_acknowledged_registered_egress(
        PartyBaselineOwnerEffectsAuthority& supplied,
        const FinancialConstruction& construction,
        const history::EgressRelease& release) {
    try {
        const auto& value = supplied.value_;
        const auto& attempt =
            construction.registered_authority().public_receipt();
        const auto& packet = release.packet();
        const auto core = release.core();
        const auto projection = release.projection();
        need(core.size() == FinancialConstruction::CORE_BYTES &&
             projection.size() == 10685 &&
             release.binding_identity() ==
                 construction.locked_attempt().binding_identity() &&
             packet.projection == value.projection_identity &&
             identity_registry::digest(projection) ==
                 value.projection_identity);

        std::array<Digest, 3> nullifiers{};
        std::array<Digest, 6> mapped_tuples{};
        std::size_t at = 0;
        for (unsigned owner = 0; owner < value.owner_truth.size(); ++owner) {
            nullifiers[owner] = value.owner_truth[owner].public_nullifier;
            for (const auto& tuple : value.owner_truth[owner].public_tuple_hashes)
                mapped_tuples[at++] = tuple;
        }
        std::sort(nullifiers.begin(), nullifiers.end());
        std::sort(mapped_tuples.begin(), mapped_tuples.end());
        need(std::adjacent_find(nullifiers.begin(), nullifiers.end()) ==
                 nullifiers.end() &&
             std::adjacent_find(mapped_tuples.begin(), mapped_tuples.end()) ==
                 mapped_tuples.end() &&
             nullifiers == packet.nullifiers);

        constexpr std::size_t first_output = 692;
        constexpr std::size_t output_bytes = 520;
        std::array<Digest, 6> released_tuples{};
        std::array<Digest, 6> released_commitments{};
        for (std::size_t index = 0; index < released_tuples.size(); ++index) {
            const auto offset = first_output + index * output_bytes;
            need(offset <= core.size() && output_bytes <= core.size() - offset);
            released_tuples[index] = identity_registry::digest(
                core.subspan(offset, output_bytes));
            std::copy_n(core.begin() + offset, 32,
                        released_commitments[index].begin());
        }
        for (const auto& truth : value.owner_truth)
            for (unsigned row = 0; row < truth.public_tuple_hashes.size(); ++row) {
                const auto found = std::find(
                    released_tuples.begin(), released_tuples.end(),
                    truth.public_tuple_hashes[row]);
                need(found != released_tuples.end() &&
                     truth.public_tuple_commitments[row] ==
                         released_commitments[static_cast<std::size_t>(
                             found - released_tuples.begin())]);
            }
        std::sort(released_tuples.begin(), released_tuples.end());
        need(std::adjacent_find(released_tuples.begin(),
                                released_tuples.end()) ==
                 released_tuples.end() && mapped_tuples == released_tuples);

        const auto context_identity = identity_registry::digest(
            core.subspan(8, 276));
        return from_bound_party(
            supplied, attempt, release.binding_identity(), packet.projection,
            context_identity);
    } catch (...) { refuse(); }
}

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
