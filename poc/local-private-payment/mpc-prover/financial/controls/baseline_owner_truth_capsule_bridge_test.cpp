#include "../authenticated_baseline_owner_receiver.hpp"
#include "../../../private_batch_trial/privacy_measurement_worker_capsule.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <concepts>
#include <string_view>
#include <sys/wait.h>

using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;
using namespace kpb::measurement::runtime_bridge;

namespace {
Digest id(unsigned long long value) {
    Digest result{};
    for (unsigned index = 0; index < 8; ++index)
        result[index] = static_cast<unsigned char>(value >> (8 * index));
    result[31] = static_cast<unsigned char>(value ^ 0x6dU);
    return result;
}

template<class Callable> void refused(Callable&& callable) {
    bool rejected = false;
    try { callable(); }
    catch (const kpi::mpc::financial::identity_registry::Refused&) {
        rejected = true;
    }
    assert(rejected);
}

PrivatePartyBaselineOwnerEffects value(unsigned round, unsigned role) {
    PrivatePartyBaselineOwnerEffects result{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = round,
        .role = role,
        .run = id(0x10 + round),
        .trial = id(0x20),
        .attempt = id(0x30 + round),
        .cohort = id(0x40 + round),
        .capture_plan_identity = id(0x50 + round),
        .projection_identity = id(0x60 + round),
        .context_identity = id(0x70 + round),
        .relation_source_identity = id(0x80),
        .owner_effects_recipe_identity = id(0x81),
        .baseline_plan_identity = id(0x90 + 3 * round + role),
        .verified_egress_identity = id(0xa0 + 3 * round + role),
        .policy_identity = id(0xb0),
        .roster_authority_identity = id(0xb1),
        .roster_root_identity = id(0xb2),
        .consent_nonce = id(0xc0 + round),
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        result.owner_contracts[owner] = id(0x100 + 8 * round + owner);
        result.logical_owner_identities[owner] = id(0x180 + owner);
        result.pre_disclosure_challenge_identities[owner] =
            id(0x1c0 + 8 * round + owner);
        result.owner_sessions[owner] =
            id(0x200 + 32 * round + 4 * role + owner);
        auto& truth = result.owner_truth[owner];
        truth.owner = owner;
        truth.round = round;
        truth.run = result.run;
        truth.trial = result.trial;
        truth.attempt = result.attempt;
        truth.cohort = result.cohort;
        truth.capture_plan_identity = result.capture_plan_identity;
        truth.projection_identity = result.projection_identity;
        truth.context_identity = result.context_identity;
        truth.owner_contract_identity = result.owner_contracts[owner];
        truth.logical_owner_identity = result.logical_owner_identities[owner];
        truth.roster_authority_identity = result.roster_authority_identity;
        truth.roster_root_identity = result.roster_root_identity;
        truth.pre_disclosure_challenge_identity =
            result.pre_disclosure_challenge_identities[owner];
        truth.public_nullifier = id(0x300 + 8 * round + owner);
        truth.public_tuple_hashes = {
            id(0x400 + 16 * round + 2 * owner),
            id(0x401 + 16 * round + 2 * owner)};
        truth.public_tuple_commitments = {
            id(0x500 + 16 * round + 2 * owner),
            id(0x501 + 16 * round + 2 * owner)};
    }
    return result;
}

BaselineOwnerScoringLaunchAuthority complete() {
    BaselineOwnerScoringParentCollector parent;
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            parent.submit(PartyBaselineOwnerEffectsAuthority::test_only_mint(
                value(round, role)));
    return parent.finish();
}

kpb::measurement::PublicOwnerTruthReleasePermit release() {
    kpb::measurement::PublicOwnerTruthReleasePermit result{};
    result.barrier = id(0x900);
    return result;
}

void no_unreaped_child() {
    int status = 0;
    errno = 0;
    assert(::waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
}

void happy() {
    auto launch = complete();
    auto endpoint = BaselineOwnerTruthCapsuleBridge::test_only_prepare(
        launch.take_owner(1), release());
    const auto& receipt = endpoint.public_receipt();
    assert((receipt.kind == MeasurementInputKind::OwnerTruth &&
           receipt.owner == 1 &&
           receipt.fixed_fd == MEASUREMENT_SCORE_OWNER_TRUTH_FD &&
           receipt.identity != Digest{} &&
           receipt.lineage.classification ==
               kpb::measurement::Classification::TransparentBaseline &&
           receipt.lineage.trial == id(0x20) &&
           receipt.lineage.barrier == id(0x900) &&
           receipt.lineage.capture_plan_identities ==
               std::array<Digest, 2>{id(0x51), id(0x52)} &&
           receipt.lineage.financial_runs ==
               std::array<Digest, 2>{id(0x11), id(0x12)} &&
           receipt.lineage.round_attempts ==
               std::array<Digest, 2>{id(0x31), id(0x32)} &&
           receipt.lineage.round_cohorts ==
               std::array<Digest, 2>{id(0x41), id(0x42)} &&
           receipt.lineage.projections ==
               std::array<Digest, 2>{id(0x61), id(0x62)}));
    no_unreaped_child();
}

void random_identity() {
    auto first_launch = complete();
    auto second_launch = complete();
    auto first = BaselineOwnerTruthCapsuleBridge::test_only_prepare(
        first_launch.take_owner(0), release());
    auto second = BaselineOwnerTruthCapsuleBridge::test_only_prepare(
        second_launch.take_owner(0), release());
    assert(first.public_receipt().identity !=
           second.public_receipt().identity);
    no_unreaped_child();
}

void replay() {
    auto launch = complete();
    auto truth = launch.take_owner(2);
    auto endpoint = BaselineOwnerTruthCapsuleBridge::test_only_prepare(
        std::move(truth), release());
    (void)endpoint;
    refused([&] {
        (void)BaselineOwnerTruthCapsuleBridge::test_only_prepare(
            std::move(truth), release());
    });
    no_unreaped_child();
}

void surface() {
    static_assert(!std::default_initializable<OwnerScoreTruthAuthority>);
    static_assert(!std::copy_constructible<OwnerScoreTruthAuthority>);
    static_assert(!std::default_initializable<MeasurementInputEndpointAuthority>);
    static_assert(!std::copy_constructible<MeasurementInputEndpointAuthority>);
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view mode(argv[1]);
    if (mode == "happy") happy();
    else if (mode == "random-identity") random_identity();
    else if (mode == "replay") replay();
    else if (mode == "surface") surface();
    else return 2;
}
