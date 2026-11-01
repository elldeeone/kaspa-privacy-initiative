#include "baseline_owner_effects_recipe.hpp"
#include "authenticated_baseline_owner_receiver.hpp"
#include "baseline_public_effects_collector.hpp"
#include "construction_storage.hpp"

#include "../history/epoch_ticket.hpp"

#include <algorithm>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest bits_to_digest(std::span<const Fr> bits) {
    need(bits.size() == 256);
    Digest result{};
    for (std::size_t index = 0; index < bits.size(); ++index) {
        need(bits[index] == Fr(0) || bits[index] == Fr(1));
        if (bits[index] == Fr(1))
            result[index / 8] |= static_cast<unsigned char>(1u << (index % 8));
    }
    need(result != Digest{});
    return result;
}
} // namespace

PreparedBaselineOwnerEffects BaselineOwnerEffectsRecipeBridge::derive(
        MascotContext& context, const FinancialConstruction& construction,
        const history::EgressRelease& release,
        BaselineEffectsPlanAuthority&& selected,
        BaselineOwnerPreDisclosureConsentAuthority&& supplied_consent) {
    try {
        // Burn the plan before any private opening. A replay/racing caller
        // cannot perform a second disclosure even if it later loses minting.
        auto retained = claim_plan(std::move(selected));
        context.require_healthy();
        construction.require_live(context, construction.attempt_);
        const auto& plan = retained.value_;
        const auto& attempt = construction.registered_authority().public_receipt();
        const auto& packet = release.packet();
        const auto recipe = construction.storage_->owner_effects_recipe;
        const auto core = release.core();
        need(core.size() >= 284);
        const auto expected_context_identity = identity_registry::digest(
            core.subspan(8, 276));
        need(recipe != nullptr &&
             plan.classification ==
                 CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
             attempt.classification == plan.classification &&
             attempt.round == plan.round && attempt.run == plan.run &&
             attempt.attempt == plan.attempt && attempt.cohort == plan.cohort &&
             attempt.capture_plan_identity == plan.capture_plan_identity &&
             attempt.owner_contracts == plan.owner_contracts &&
             release.binding_identity() ==
                 construction.locked_attempt().binding_identity() &&
             packet.projection == plan.projection_identity &&
             identity_registry::digest(release.projection()) ==
                 plan.projection_identity &&
             recipe->source_identity() == history::hex(construction.attempt_.source) &&
             recipe->layout_identity() == history::hex(construction.attempt_.layout) &&
             recipe->model_variables() == construction.assignment().size() &&
             recipe->instances() == 3);

        // This one-shot verification must occur before selecting or opening a
        // single owner-mapping wire. Its constructor is reachable only after
        // all three long-lived owner authorization proofs were verified.
        const auto consent = supplied_consent.consume_for_recipe();
        need(consent.classification == plan.classification &&
             consent.round == plan.round && consent.role == attempt.role &&
             consent.run == plan.run && consent.trial == attempt.trial &&
             consent.attempt == plan.attempt &&
             consent.cohort == plan.cohort &&
             consent.capture_plan_identity == plan.capture_plan_identity &&
             consent.projection_identity == plan.projection_identity &&
             consent.context_identity == expected_context_identity &&
             consent.relation_source_identity == construction.attempt_.source &&
             consent.owner_effects_recipe_identity ==
                 history::unhex(recipe->identity()) &&
             consent.baseline_plan_identity == retained.identity_ &&
             consent.verified_egress_identity ==
                 plan.verified_egress_identity &&
             consent.policy_identity == plan.policy_identity &&
             consent.owner_contracts == plan.owner_contracts);

        std::vector<AuthScalar> selected_wires;
        selected_wires.reserve(3 * 256 + 36);
        for (const auto& owner : recipe->owners())
            for (const auto column : owner.input_nf_bits) {
                need(column < construction.assignment().size());
                selected_wires.push_back(construction.assignment()[column]);
            }
        for (const auto& owner : recipe->owners())
            for (const auto& row : owner.output_permutation)
                for (const auto column : row) {
                    need(column < construction.assignment().size());
                    selected_wires.push_back(construction.assignment()[column]);
                }
        need(selected_wires.size() == 804);

        const auto before = context.check_counter();
        const auto opened = context.open_public_checked(selected_wires);
        need(opened.size() == selected_wires.size() &&
             context.check_counter() == before + 2);

        OpenedOwnerEffects effects{};
        std::size_t at = 0;
        for (auto& nullifier : effects.nullifiers) {
            nullifier = bits_to_digest(
                std::span(opened).subspan(at, 256));
            at += 256;
        }
        for (auto& row : effects.output_permutation)
            for (auto& bit : row) {
                need(opened[at] == Fr(0) || opened[at] == Fr(1));
                bit = opened[at] == Fr(1) ? 1u : 0u;
                ++at;
            }
        need(at == opened.size());

        constexpr std::size_t first_output = 692;
        constexpr std::size_t output_bytes = 520;
        effects.context_identity = expected_context_identity;
        for (std::size_t destination = 0;
             destination < effects.egress_tuple_hashes.size();
             ++destination) {
            const auto offset = first_output + destination * output_bytes;
            need(offset <= core.size() && output_bytes <= core.size() - offset);
            effects.egress_tuple_hashes[destination] =
                identity_registry::digest(core.subspan(offset, output_bytes));
            std::copy_n(core.begin() + offset, 32,
                        effects.egress_tuple_commitments[destination].begin());
        }
        effects.relation_source_identity = construction.attempt_.source;
        effects.owner_effects_recipe_identity =
            history::unhex(recipe->identity());

        Bytes agreement;
        constexpr char label[] = "KPB_BASELINE_OWNER_EFFECTS_OPENED_V1\n";
        agreement.insert(agreement.end(), label, label + sizeof(label) - 1);
        add(agreement, retained.identity_);
        add(agreement, effects.relation_source_identity);
        add(agreement, effects.owner_effects_recipe_identity);
        add(agreement, effects.context_identity);
        add(agreement, plan.projection_identity);
        for (const auto& identity : consent.pre_challenge_identities)
            add(agreement, identity);
        for (const auto& nullifier : effects.nullifiers)
            add(agreement, nullifier);
        for (const auto& row : effects.output_permutation)
            for (const auto bit : row) integer(agreement, bit);
        for (const auto& commitment : effects.egress_tuple_commitments)
            add(agreement, commitment);
        context.agree_public_bytes(
            "baseline-owner-effects-after-durable-egress", agreement);
        return derive_claimed(std::move(retained), std::move(effects));
    } catch (...) {
        context.poison();
        throw;
    }
}

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
