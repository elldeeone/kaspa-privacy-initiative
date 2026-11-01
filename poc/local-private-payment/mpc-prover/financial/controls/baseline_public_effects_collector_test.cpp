#include "../baseline_public_effects_collector.hpp"

#include <array>
#include <cassert>
#include <concepts>
#include <string>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;

namespace {
Digest id(unsigned long long value) {
    Digest result{};
    for (unsigned i = 0; i < 8; ++i)
        result[i] = static_cast<unsigned char>(value >> (8 * i));
    return result;
}

template<class Callable> void refuse(Callable&& callable) {
    bool failed = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { failed = true; }
    assert(failed);
}

PublicBaselineEffectsPlan plan_value(
    CaptureClassification classification =
        CaptureClassification::ExplicitOwnerPublicEffectsBaseline) {
    return PublicBaselineEffectsPlan{
        .classification = classification,
        .round = 1,
        .run = id(0x13), .trial = id(0x16),
        .attempt = id(0x14), .cohort = id(0x15),
        .capture_plan_identity = id(0x10),
        .projection_identity = id(0x11),
        .context_identity = id(0x17),
        .verified_egress_identity = id(0x12),
        .owner_contracts = {id(0x20), id(0x21), id(0x22)},
        .public_nullifiers = {id(0x30), id(0x31), id(0x32)},
        .public_tuple_hashes = {
            id(0x40), id(0x41), id(0x42),
            id(0x43), id(0x44), id(0x45)},
        .policy_identity = id(0x50),
    };
}

OwnerEffectsDisclosureInput owner_value(unsigned owner) {
    return OwnerEffectsDisclosureInput{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = 1,
        .owner = owner,
        .run = id(0x13), .trial = id(0x16),
        .attempt = id(0x14), .cohort = id(0x15),
        .capture_plan_identity = id(0x10),
        .projection_identity = id(0x11),
        .context_identity = id(0x17),
        .owner_contract_identity = id(0x20 + owner),
        .public_nullifier = id(0x30 + owner),
        .public_tuple_hashes = {
            id(0x40 + 2 * owner), id(0x41 + 2 * owner)},
        .authenticated_session_identity = id(0x60 + owner),
    };
}

BaselineEffectsPlanAuthority plan(
    CaptureClassification classification =
        CaptureClassification::ExplicitOwnerPublicEffectsBaseline) {
    return BaselineEffectsPlanAuthority::test_only_mint(
        plan_value(classification));
}

BaselineEffectsPlanAuthority verified_plan() {
    auto value = plan_value();
    value.policy_identity = BaselineDisclosureAuthorityBridge::policy_identity();
    auto verified = VerifiedBaselinePublicEffectsAuthority::test_only_mint(
        value);
    return BaselineDisclosureAuthorityBridge::from_verified_egress(
        std::move(verified));
}

AuthenticatedOwnerEffectsDisclosureAuthority owner(unsigned role) {
    return AuthenticatedOwnerEffectsDisclosureAuthority::test_only_mint(
        owner_value(role));
}

void happy_exact_partition() {
    auto selected = verified_plan();
    std::array disclosures{owner(2), owner(0), owner(1)};
    const auto completed = BaselinePublicEffectsCollector::collect(
        std::move(selected), std::move(disclosures));
    const auto& receipt = completed.public_receipt();
    assert(receipt.status == "EXPLICIT_OWNER_PUBLIC_EFFECTS");
    assert(receipt.classification ==
           CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    assert(receipt.round == 1 && receipt.run == id(0x13) &&
           receipt.trial == id(0x16) &&
           receipt.attempt == id(0x14) && receipt.cohort == id(0x15));
    assert(receipt.capture_plan_identity == id(0x10));
    assert(receipt.projection_identity == id(0x11));
    assert(receipt.context_identity == id(0x17));
    for (unsigned role = 0; role < 3; ++role) {
        const auto& effect = receipt.owner_effects[role];
        assert(effect.owner == role);
        assert(effect.owner_contract_identity == id(0x20 + role));
        assert(effect.public_nullifier == id(0x30 + role));
        assert(effect.public_tuple_hashes[0] == id(0x40 + 2 * role));
        assert(effect.public_tuple_hashes[1] == id(0x41 + 2 * role));
    }
    assert(receipt.receipt_identity != Digest{});
}

void hidden_and_mixed_authority_refuse() {
    refuse([] {
        (void)plan(CaptureClassification::HiddenCandidate);
    });

    for (unsigned mutation = 0; mutation < 9; ++mutation) {
        auto selected = plan();
        auto first = owner_value(0);
        auto second = owner_value(1);
        auto third = owner_value(2);
        if (mutation == 0) second.owner = 0;
        if (mutation == 1) second.owner_contract_identity = id(0xbad1);
        if (mutation == 2) second.projection_identity = id(0xbad2);
        if (mutation == 3) second.public_nullifier = id(0xbad3);
        if (mutation == 4) second.public_tuple_hashes[1] = id(0xbad4);
        if (mutation == 5) second.authenticated_session_identity =
            first.authenticated_session_identity;
        if (mutation == 6) second.classification =
            CaptureClassification::HiddenCandidate;
        if (mutation == 7) second.attempt = id(0xbad7);
        if (mutation == 8)
            second.public_tuple_hashes[1] = first.public_tuple_hashes[0];
        refuse([&] {
            std::array disclosures{
                AuthenticatedOwnerEffectsDisclosureAuthority::test_only_mint(first),
                AuthenticatedOwnerEffectsDisclosureAuthority::test_only_mint(second),
                AuthenticatedOwnerEffectsDisclosureAuthority::test_only_mint(third),
            };
            (void)BaselinePublicEffectsCollector::collect(
                std::move(selected), std::move(disclosures));
        });
    }
}

void replay_and_plan_substitution_refuse() {
    auto verified_value = plan_value();
    verified_value.policy_identity =
        BaselineDisclosureAuthorityBridge::policy_identity();
    auto verified = VerifiedBaselinePublicEffectsAuthority::test_only_mint(
        verified_value);
    (void)BaselineDisclosureAuthorityBridge::from_verified_egress(
        std::move(verified));
    refuse([&] {
        (void)BaselineDisclosureAuthorityBridge::from_verified_egress(
            std::move(verified));
    });

    auto selected = plan();
    std::array disclosures{owner(0), owner(1), owner(2)};
    (void)BaselinePublicEffectsCollector::collect(
        std::move(selected), std::move(disclosures));
    refuse([&] {
        (void)BaselinePublicEffectsCollector::collect(
            std::move(selected), std::move(disclosures));
    });

    auto changed = plan_value();
    changed.public_tuple_hashes[5] = id(0xcafe);
    auto changed_plan = BaselineEffectsPlanAuthority::test_only_mint(changed);
    std::array exact{owner(0), owner(1), owner(2)};
    refuse([&] {
        (void)BaselinePublicEffectsCollector::collect(
            std::move(changed_plan), std::move(exact));
    });

    // Each owner's pair has one canonical representation even if its
    // authenticated source authority supplies the two public rows reversed.
    auto canonical = plan();
    auto reversed = owner_value(1);
    std::swap(reversed.public_tuple_hashes[0],
              reversed.public_tuple_hashes[1]);
    std::array reversed_disclosures{
        owner(0),
        AuthenticatedOwnerEffectsDisclosureAuthority::test_only_mint(
            reversed),
        owner(2),
    };
    const auto normalized = BaselinePublicEffectsCollector::collect(
        std::move(canonical), std::move(reversed_disclosures));
    const std::array<Digest, 2> expected_pair{id(0x42), id(0x43)};
    assert(normalized.public_receipt().owner_effects[1].public_tuple_hashes ==
           expected_pair);
}

void source_boundary() {
    static_assert(!std::default_initializable<
        VerifiedBaselinePublicEffectsAuthority>);
    static_assert(!std::constructible_from<
        VerifiedBaselinePublicEffectsAuthority,
        PublicBaselineEffectsPlan>);
    static_assert(!std::copy_constructible<
        VerifiedBaselinePublicEffectsAuthority>);
    static_assert(!std::default_initializable<BaselineEffectsPlanAuthority>);
    static_assert(!std::constructible_from<BaselineEffectsPlanAuthority,
                                           PublicBaselineEffectsPlan>);
    static_assert(!std::copy_constructible<BaselineEffectsPlanAuthority>);
    static_assert(!std::default_initializable<
        AuthenticatedOwnerEffectsDisclosureAuthority>);
    static_assert(!std::constructible_from<
        AuthenticatedOwnerEffectsDisclosureAuthority,
        OwnerEffectsDisclosureInput>);
    static_assert(!std::copy_constructible<
        AuthenticatedOwnerEffectsDisclosureAuthority>);
    static_assert(!std::constructible_from<
        ExplicitOwnerPublicEffectsAuthority, PublicExplicitOwnerEffects>);
    const auto status = baseline_disclosure::source_status();
    assert(status.classification_bound_to_capture_plan);
    assert(status.exact_three_owner_partition);
    assert(status.grouped_owner_mapping_preserved);
    assert(status.hidden_candidate_disclosure_factory_absent);
    assert(status.verified_egress_authority_integration);
    assert(status.authenticated_owner_ipc_integration);
    assert(status.parent_dispatcher_integration);
    assert(!status.actual_capture_completion);
    assert(!status.registered_driver_configured);
    assert(!status.launch_authorized);
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string mode(argv[1]);
    if (mode == "happy") happy_exact_partition();
    else if (mode == "mixed") hidden_and_mixed_authority_refuse();
    else if (mode == "replay") replay_and_plan_substitution_refuse();
    else if (mode == "source") source_boundary();
    else return 2;
}
