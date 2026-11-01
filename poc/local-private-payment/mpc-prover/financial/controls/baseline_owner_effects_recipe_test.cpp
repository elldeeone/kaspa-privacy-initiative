#include "../baseline_owner_effects_recipe.hpp"
#include "../baseline_public_effects_collector.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <concepts>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;

namespace {
Digest id(unsigned long long value) {
    Digest result{};
    for (unsigned i = 0; i < 8; ++i)
        result[i] = static_cast<unsigned char>(value >> (8 * i));
    return result;
}

template<class Callable> void refused(Callable&& callable) {
    bool failed = false;
    try { callable(); }
    catch (const kpi::mpc::financial::identity_registry::Refused&) {
        failed = true;
    }
    catch (const std::exception&) { failed = true; }
    assert(failed);
}

PublicBaselineEffectsPlan plan_value() {
    return PublicBaselineEffectsPlan{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = 1,
        .run = id(0x10), .trial = id(0x16),
        .attempt = id(0x11), .cohort = id(0x12),
        .capture_plan_identity = id(0x13),
        .projection_identity = id(0x14),
        .context_identity = id(0x70),
        .verified_egress_identity = id(0x15),
        .owner_contracts = {id(0x20), id(0x21), id(0x22)},
        .public_nullifiers = {id(0x30), id(0x31), id(0x32)},
        .public_tuple_hashes = {
            id(0x40), id(0x41), id(0x42),
            id(0x43), id(0x44), id(0x45)},
        .policy_identity = BaselineDisclosureAuthorityBridge::policy_identity(),
    };
}

BaselineEffectsPlanAuthority plan() {
    return BaselineEffectsPlanAuthority::test_only_mint(plan_value());
}

BaselineOwnerEffectsRecipeBridge::TestOpenedOwnerEffects opened() {
    BaselineOwnerEffectsRecipeBridge::TestOpenedOwnerEffects result{
        .nullifiers = {id(0x30), id(0x31), id(0x32)},
        .egress_tuple_hashes = {
            id(0x40), id(0x41), id(0x42),
            id(0x43), id(0x44), id(0x45)},
        .egress_tuple_commitments = {
            id(0x60), id(0x61), id(0x62),
            id(0x63), id(0x64), id(0x65)},
        .context_identity = id(0x70),
        .relation_source_identity = id(0x50),
        .owner_effects_recipe_identity = id(0x51),
    };
    constexpr std::array<unsigned, 6> destinations{4, 1, 0, 5, 3, 2};
    for (unsigned source = 0; source < 6; ++source)
        result.output_permutation[source][destinations[source]] = 1;
    return result;
}

void authority_happy() {
    auto prepared = BaselineOwnerEffectsRecipeBridge::test_only_derive_opened(
        plan(), opened());
    const std::array<std::array<Digest, 2>, 3> expected{{
        {id(0x41), id(0x44)},
        {id(0x40), id(0x45)},
        {id(0x42), id(0x43)},
    }};
    const std::array<std::array<Digest, 2>, 3> expected_commitments{{
        {id(0x61), id(0x64)},
        {id(0x60), id(0x65)},
        {id(0x62), id(0x63)},
    }};
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto& value = prepared.test_only_owner(owner);
        assert(value.owner == owner &&
               value.owner_contract_identity == id(0x20 + owner) &&
               value.public_nullifier == id(0x30 + owner) &&
               value.public_tuple_hashes == expected[owner] &&
               value.public_tuple_commitments ==
                   expected_commitments[owner] &&
               value.context_identity == id(0x70) &&
               value.relation_source_identity == id(0x50) &&
               value.owner_effects_recipe_identity == id(0x51) &&
               value.baseline_plan_identity != Digest{} &&
               value.verified_egress_identity == id(0x15) &&
               value.policy_identity ==
                   BaselineDisclosureAuthorityBridge::policy_identity() &&
               value.authority_identity != Digest{});
    }
    auto owner_two = prepared.take_owner(2);
    (void)OwnerPrivateEffectsReceiverBridge::consume(
        std::move(owner_two));
    refused([&] {
        (void)OwnerPrivateEffectsReceiverBridge::consume(
            std::move(owner_two));
    });
    (void)prepared.take_owner(0);
    (void)prepared.take_owner(1);
    (void)prepared.take_plan();
    refused([&] { (void)prepared.take_owner(1); });
    refused([&] { (void)prepared.take_plan(); });
}

void authority_race() {
    auto selected = plan();
    std::atomic<unsigned> ready{}, succeeded{}, refused_count{};
    const auto run = [&] {
        ready.fetch_add(1);
        while (ready.load() != 2) std::this_thread::yield();
        try {
            auto result = BaselineOwnerEffectsRecipeBridge::
                test_only_derive_opened(std::move(selected), opened());
            (void)result.take_owner(0);
            succeeded.fetch_add(1);
        } catch (const kpi::mpc::financial::identity_registry::Refused&) {
            refused_count.fetch_add(1);
        }
    };
    std::thread first(run), second(run);
    first.join(); second.join();
    assert(succeeded.load() == 1 && refused_count.load() == 1);

    auto prepared = BaselineOwnerEffectsRecipeBridge::test_only_derive_opened(
        plan(), opened());
    ready = 0; succeeded = 0; refused_count = 0;
    const auto take = [&] {
        ready.fetch_add(1);
        while (ready.load() != 2) std::this_thread::yield();
        try {
            (void)prepared.take_plan();
            (void)prepared.take_owner(0);
            (void)prepared.take_owner(1);
            (void)prepared.take_owner(2);
            succeeded.fetch_add(1);
        } catch (const kpi::mpc::financial::identity_registry::Refused&) {
            refused_count.fetch_add(1);
        }
    };
    std::thread third(take), fourth(take);
    third.join(); fourth.join();
    assert(succeeded.load() == 1 && refused_count.load() == 1);
}

void authority_mutations() {
    for (unsigned mutation = 0; mutation < 11; ++mutation) {
        auto value = opened();
        if (mutation == 0) {
            value.output_permutation[1] = {};
            value.output_permutation[1][4] = 1;
        }
        if (mutation == 1) value.output_permutation[2][0] = 2;
        if (mutation == 2) value.nullifiers[1] = id(0xbad2);
        if (mutation == 3) value.egress_tuple_hashes[4] = id(0xbad3);
        if (mutation == 4) value.relation_source_identity = {};
        if (mutation == 5) value.owner_effects_recipe_identity = {};
        if (mutation == 6) value.nullifiers[2] = value.nullifiers[0];
        if (mutation == 7)
            value.egress_tuple_hashes[5] = value.egress_tuple_hashes[0];
        if (mutation == 8) value.context_identity = {};
        if (mutation == 9) value.egress_tuple_commitments[0] = {};
        if (mutation == 10)
            value.egress_tuple_commitments[5] =
                value.egress_tuple_commitments[0];
        refused([&] {
            (void)BaselineOwnerEffectsRecipeBridge::test_only_derive_opened(
                plan(), value);
        });
    }
}

std::array<std::vector<std::size_t>, 3> fixture_layout() {
    std::array<std::vector<std::size_t>, 3> result;
    for (std::size_t column = 10; column <= 265; ++column)
        result[0].push_back(column);
    for (std::size_t column = 500; column <= 755; ++column)
        result[1].push_back(column);
    for (std::size_t column = 1000; column <= 1255; ++column)
        result[2].push_back(column);
    return result;
}

void load_recipe(int argc, char** argv) {
    assert(argc == 7);
    const auto layout = fixture_layout();
    const std::array<std::span<const std::size_t>, 3> views{
        layout[0], layout[1], layout[2]};
    const auto recipe = BaselineOwnerEffectsRecipe::load(
        argv[2], argv[3], argv[4], argv[5], 2000, 3, views);
    assert(recipe->identity() == argv[3] &&
           recipe->source_identity() == argv[4] &&
           recipe->layout_identity() == argv[5] &&
           recipe->model_variables() == 2000 && recipe->instances() == 3);
    assert(recipe->owners()[0].input_nf_bits.front() == 10);
    assert(recipe->owners()[2].input_nf_bits.back() == 1255);
    assert(recipe->owners()[1].output_permutation[0][0] == 800);
    assert(std::string(argv[6]) == "accept");
}

void source_boundary() {
    static_assert(!std::default_initializable<OwnerPrivateEffectsAuthority>);
    static_assert(!std::copy_constructible<OwnerPrivateEffectsAuthority>);
    static_assert(!std::default_initializable<PreparedBaselineOwnerEffects>);
    static_assert(!std::copy_constructible<PreparedBaselineOwnerEffects>);
    const auto status = baseline_owner_effects_source_status();
    assert(status.exact_selected_owner_nf_columns);
    assert(status.authenticated_output_permutation_columns);
    assert(!status.raw_pre_shuffle_tuples_opened);
    assert(status.post_egress_mac_checked_opening);
    assert(status.exact_egress_set_join);
    assert(status.hidden_candidate_factory_absent);
    assert(status.registered_recipe_selected);
    assert(!status.registered_driver_configured);
    assert(!status.launch_authorized);
}
} // namespace

int main(int argc, char** argv) {
    assert(argc >= 2);
    const std::string mode(argv[1]);
    if (mode == "authority-happy") authority_happy();
    else if (mode == "authority-mutations") authority_mutations();
    else if (mode == "authority-race") authority_race();
    else if (mode == "load") load_recipe(argc, argv);
    else if (mode == "source") source_boundary();
    else return 2;
}
