#include "../authenticated_baseline_owner_receiver.hpp"
#include "../registered_parent_role_fork.hpp"

#include <array>
#include <cassert>
#include <fcntl.h>
#include <string_view>
#include <unistd.h>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;

namespace {
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest id(unsigned long long value) {
    Digest result{};
    for (unsigned index = 0; index < 8; ++index)
        result[index] = static_cast<unsigned char>(value >> (8 * index));
    result[31] = static_cast<unsigned char>(value ^ 0xa7U);
    return result;
}

template<class Callable> void refused(Callable&& callable) {
    bool rejected = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { rejected = true; }
    assert(rejected);
}

PublicParentRoleForkPlan plan(unsigned round) {
    PublicParentRoleForkPlan result{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = round,
        .capture_trial_id = std::string(TRIAL_UUID),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .financial_run = id(0x110 + round),
        .attempt = id(0x120 + round),
        .cohort = id(0x130 + round),
        .fresh_owner_issuance_identity = id(0x140),
        .authority_identity = id(1),
        .supervisor_session = id(2),
        .capture_plan_identity = id(0x40 + round),
        .capture_source_identity = id(4),
        .capture_build_identity = id(5),
        .capture_launcher_identity = id(6),
    };
    for (unsigned role = 0; role < 3; ++role)
        result.roles[role] = PublicParentRoleBinding{
            .role = role,
            .party_session = id(0x10 + 8 * round + role),
            .service_identity = id(0x20),
            .driver_selection_identity = id(0x30 + role),
        };
    return result;
}

struct Pipes {
    std::array<std::array<int, 2>, 3> value{};
    Pipes() {
        for (auto& pair : value) assert(::pipe2(pair.data(), O_CLOEXEC) == 0);
    }
    Pipes(const Pipes&) = delete;
    ~Pipes() {
        for (const auto& pair : value)
            for (const int fd : pair) if (fd >= 0) ::close(fd);
    }
    void close_writes() {
        for (auto& pair : value) {
            assert(::close(pair[1]) == 0);
            pair[1] = -1;
        }
    }
};

std::array<InheritedCaptureEndpointAuthority, 3> endpoints(
        const PublicParentRoleForkPlan& selected, const Pipes& pipes) {
    const int offset = selected.round == 1 ? 0 : 5;
    return {
        InheritedCaptureEndpointAuthority::test_only_mint(
            PublicInheritedCaptureEndpoint{
                .kind = InheritedCaptureKind::Projection, .role = 0,
                .round = selected.round, .fixed_fd = 20 + offset,
                .authority_identity = id(0x50),
                .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[0][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            PublicInheritedCaptureEndpoint{
                .kind = InheritedCaptureKind::Dispatcher, .role = 0,
                .round = selected.round, .fixed_fd = 22 + offset,
                .authority_identity = id(0x51),
                .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[1][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            PublicInheritedCaptureEndpoint{
                .kind = InheritedCaptureKind::CorruptServer, .role = 1,
                .round = selected.round, .fixed_fd = 23 + offset,
                .authority_identity = id(0x52),
                .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[2][1]),
    };
}

PrivatePartyBaselineOwnerEffects value(unsigned round, unsigned role) {
    PrivatePartyBaselineOwnerEffects result{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = round, .role = role, .run = id(0x10 + round),
        .trial = id(0x11),
        .attempt = id(0x20 + round), .cohort = id(0x30 + round),
        .capture_plan_identity = id(0x40 + round),
        .projection_identity = id(0x50 + round),
        .context_identity = id(0x60 + round),
        .relation_source_identity = id(0x70),
        .owner_effects_recipe_identity = id(0x71),
        .baseline_plan_identity = id(0x80 + 3 * round + role),
        .verified_egress_identity = id(0x90 + 3 * round + role),
        .policy_identity = id(0xa0),
        .roster_authority_identity = id(0xa1),
        .roster_root_identity = id(0xa2),
        .consent_nonce = id(0xb0 + round),
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        result.owner_contracts[owner] = id(0x100 + 8 * round + owner);
        result.logical_owner_identities[owner] = id(0x180 + owner);
        result.pre_disclosure_challenge_identities[owner] =
            id(0x1c0 + 8 * round + owner);
        result.owner_sessions[owner] =
            id(0x200 + 32 * round + 4 * role + owner);
        auto& truth = result.owner_truth[owner];
        truth.owner = owner; truth.round = round;
        truth.run = result.run; truth.attempt = result.attempt;
        truth.trial = result.trial;
        truth.cohort = result.cohort;
        truth.capture_plan_identity = result.capture_plan_identity;
        truth.projection_identity = result.projection_identity;
        truth.context_identity = result.context_identity;
        truth.owner_contract_identity = result.owner_contracts[owner];
        truth.logical_owner_identity =
            result.logical_owner_identities[owner];
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

class Program final : public RegisteredRoleChildProgram {
    unsigned round_;
    bool wrong_round_;
    bool replay_;
public:
    Program(unsigned round, bool wrong_round = false, bool replay = false)
        : round_(round), wrong_round_(wrong_round), replay_(replay) {}
    int run(ParentAuthenticatedPartyDeliveryAuthority&& delivered,
            ChildRoleCompletionEndpointAuthority&& endpoint) override {
        const auto receipt = delivered.public_receipt();
        if (receipt.round != round_ || receipt.role >= 3) return 10;
        try {
            auto first = PartyBaselineOwnerEffectsAuthority::test_only_mint(
                value(wrong_round_ ? 3 - round_ : round_, receipt.role));
            BaselineOwnerScoringParentTransport::submit(
                std::move(first), std::move(endpoint));
            if (replay_) {
                auto second =
                    PartyBaselineOwnerEffectsAuthority::test_only_mint(
                        value(round_, receipt.role));
                try {
                    BaselineOwnerScoringParentTransport::submit(
                        std::move(second), std::move(endpoint));
                    return 11;
                } catch (const identity_registry::Refused&) {}
            }
            return 0;
        } catch (const identity_registry::Refused&) { return 12; }
    }
};

ParentRoleChildren launch(unsigned round, Program& program, Pipes& pipes) {
    const auto selected = plan(round);
    auto authority = ParentRoleForkPlanAuthority::test_only_mint(
        selected, endpoints(selected, pipes));
    pipes.close_writes();
    return RegisteredParentRoleFork::launch(std::move(authority), program);
}

void happy(bool replay) {
    BaselineOwnerScoringParentHandoff parent;
    for (unsigned round = 1; round <= 2; ++round) {
        Pipes pipes;
        Program program(round, false, replay);
        parent.accept_round(launch(round, program, pipes));
    }
    auto launch_authority = parent.finish();
    for (unsigned owner = 0; owner < 3; ++owner) {
        auto truth = launch_authority.take_owner(owner);
        const auto& rounds = truth.test_only_rounds();
        assert(rounds[0].owner == owner && rounds[0].round == 1 &&
               rounds[1].owner == owner && rounds[1].round == 2 &&
               rounds[0].run == id(0x11) &&
               rounds[1].run == id(0x12) &&
               rounds[0].run != rounds[1].run);
    }
}

void wrong_round() {
    BaselineOwnerScoringParentHandoff parent;
    Pipes pipes;
    Program program(1, true);
    refused([&] { parent.accept_round(launch(1, program, pipes)); });
    refused([&] { (void)parent.finish(); });
}

void duplicate_round() {
    BaselineOwnerScoringParentHandoff parent;
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        Pipes pipes;
        Program program(1);
        auto children = launch(1, program, pipes);
        if (attempt == 0) parent.accept_round(std::move(children));
        else refused([&] { parent.accept_round(std::move(children)); });
    }
    refused([&] { (void)parent.finish(); });
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view mode(argv[1]);
    if (mode == "happy") happy(false);
    else if (mode == "replay") happy(true);
    else if (mode == "wrong-round") wrong_round();
    else if (mode == "duplicate-round") duplicate_round();
    else return 2;
}
