#include "../registered_p1_capture_bridge.hpp"

#include <cassert>
#include <string>
#include <string_view>
#include <utility>

using namespace kpi::mpc::financial::registered_driver;

namespace {
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xa5U);
    return result;
}

Digest scalar_manifest() {
    return kpi::mpc::financial::identity_registry::unhex(
        "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b");
}

PublicDriverSelection driver_value(unsigned role) {
    return {
        .role = role,
        .authority_identity = id(1),
        .selection_identity = id(2),
        .service_identity = id(3),
        .source_identity = id(4),
        .build_identity = id(5),
        .roster_identity = id(6),
        .capture_source_identity = id(7),
        .capture_build_identity = id(8),
        .capture_launcher_identity = id(9),
        .model_preimage_identity = id(13),
        .query_store_preimage_identity = id(14),
        .scalar_capture_manifest_identity = scalar_manifest(),
        .owner_port = 32100,
        .multiplication_batch = 4096,
    };
}

PublicCapturePlan plan_value() {
    return {
        .classification = CaptureClassification::HiddenCandidate,
        .round = 1,
        .capture_trial_id = std::string(TRIAL_UUID),
        .capture_attempt_id = "123e4567-e89b-42d3-a456-426614174000",
        .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
        .run = id(10),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .attempt = RegisteredCapturePlanRosterBridge::attempt_identity(
            "123e4567-e89b-42d3-a456-426614174000"),
        .cohort = id(12),
        .source_identity = id(7),
        .build_identity = id(8),
        .launcher_identity = id(9),
        .model_preimage_identity = id(13),
        .query_store_preimage_identity = id(14),
        .scalar_capture_manifest_identity = scalar_manifest(),
        .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
    };
}

template<class Callable>
void refuses(Callable&& callable) {
    bool refused = false;
    try {
        callable();
    } catch (const kpi::mpc::financial::identity_registry::Refused&) {
        refused = true;
    }
    assert(refused);
}

void role_one_split_is_linear() {
    auto driver = CompiledDriverSelection::test_only_mint(driver_value(1));
    auto parent = CapturePlanAuthority::test_only_mint(plan_value());
    auto split = CapturePlanAuthorityBridge::split_for_driver(
        std::move(parent), driver);
    assert(split.has_p1_player_capture());

    auto p1 = split.take_p1_player_capture();
    (void)p1;
    assert(!split.has_p1_player_capture());
    refuses([&] { (void)split.take_p1_player_capture(); });

    auto session = split.take_session();
    const auto consumed = CapturePlanAuthorityBridge::consume_session(
        std::move(session), 1);
    assert(consumed.value.round == 1);
    assert(consumed.value.source_identity == id(7));
    refuses([&] { (void)split.take_session(); });
    refuses([&] {
        (void)CapturePlanAuthorityBridge::consume_session(
            std::move(session), 1);
    });

    refuses([&] {
        (void)CapturePlanAuthorityBridge::split_for_driver(
            std::move(parent), driver);
    });
}

void non_p1_roles_never_receive_p1_authority() {
    for (const unsigned role : {0U, 2U}) {
        auto driver = CompiledDriverSelection::test_only_mint(
            driver_value(role));
        auto parent = CapturePlanAuthority::test_only_mint(plan_value());
        auto split = CapturePlanAuthorityBridge::split_for_driver(
            std::move(parent), driver);
        assert(!split.has_p1_player_capture());
        refuses([&] { (void)split.take_p1_player_capture(); });
        auto session = split.take_session();
        const auto consumed = CapturePlanAuthorityBridge::consume_session(
            std::move(session), role);
        assert(consumed.value.round == 1);
    }
}

void wrong_role_burns_residual() {
    auto driver = CompiledDriverSelection::test_only_mint(driver_value(1));
    auto parent = CapturePlanAuthority::test_only_mint(plan_value());
    auto split = CapturePlanAuthorityBridge::split_for_driver(
        std::move(parent), driver);
    auto session = split.take_session();
    refuses([&] {
        (void)CapturePlanAuthorityBridge::consume_session(
            std::move(session), 0);
    });
    refuses([&] {
        (void)CapturePlanAuthorityBridge::consume_session(
            std::move(session), 1);
    });
}

void wrong_plan_burns_parent() {
    for (unsigned mutation = 0; mutation < 5; ++mutation) {
        auto driver = CompiledDriverSelection::test_only_mint(driver_value(1));
        auto wrong = plan_value();
        if (mutation == 0) wrong.source_identity = id(99);
        if (mutation == 1) wrong.model_preimage_identity = id(99);
        if (mutation == 2) wrong.query_store_preimage_identity = id(99);
        if (mutation == 3)
            wrong.scalar_capture_manifest_identity = id(99);
        if (mutation == 4) wrong.trial = {};
        auto parent = CapturePlanAuthority::test_only_mint(std::move(wrong));
        refuses([&] {
            (void)CapturePlanAuthorityBridge::split_for_driver(
                std::move(parent), driver);
        });
        refuses([&] {
            (void)CapturePlanAuthorityBridge::split_for_driver(
                std::move(parent), driver);
        });
    }
}

} // namespace

int main() {
    role_one_split_is_linear();
    non_p1_roles_never_receive_p1_authority();
    wrong_role_burns_residual();
    wrong_plan_burns_parent();
}
