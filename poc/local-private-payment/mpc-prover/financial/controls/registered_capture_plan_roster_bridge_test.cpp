#include "../registered_capture_plan_roster_bridge.hpp"

#include <array>
#include <cassert>
#include <string>
#include <string_view>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;

namespace {

constexpr std::string_view TRIAL_A =
    "11111111-1111-4111-8111-111111111111";
constexpr std::string_view TRIAL_B =
    "22222222-2222-4222-8222-222222222222";

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xb7U);
    return result;
}

template<class Callable> void refuses(Callable&& callable) {
    bool rejected = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { rejected = true; }
    assert(rejected);
}

RegisteredRosterBinding roster_binding(std::string trial_id) {
    return {
        .trial_id = std::move(trial_id),
        .selection_candidate = id(1),
        .registration = id(2),
        .trial_authority = id(3),
        .ready_checkpoint = id(4),
        .certificate_authority = id(5),
        .server_certificates = {id(6), id(7), id(8)},
        .accepted_head_source_closure = id(9),
        .accepted_head_build = id(10),
        .exporter_adapter = id(11),
        .exporter_source_closure = id(12),
        .exporter_build = id(13),
        .qualifier_source_closure = id(14),
        .qualifier_build = id(15),
        .qualifier_authority_build = id(16),
        .qualifier_build_contract = id(17),
        .qualifier_configuration_selection = id(18),
        .native_parameters = id(19),
        .immutable_tail = id(20),
        .component_profile = id(21),
        .outer_image = id(22),
        .native_program = id(23),
        .native_codec = id(24),
    };
}

PublicImmutableRosterSelection roster(std::string trial_id) {
    auto binding = roster_binding(std::move(trial_id));
    return {
        .role = 0,
        .hosts = {"127.0.0.1", "127.0.0.1", "127.0.0.1"},
        .port_base = 32100,
        .server_certificates = binding.server_certificates,
        .registered_binding = std::move(binding),
        .transport_source_identity = id(30),
        .transport_build_identity = id(31),
        .transport_launcher_identity = id(32),
    };
}

PublicCapturePlan plan(std::string trial_id) {
    PublicCapturePlan result{
        .classification = CaptureClassification::HiddenCandidate,
        .round = 1,
        .capture_trial_id = std::move(trial_id),
        .capture_attempt_id = "33333333-3333-4333-8333-333333333333",
        .capture_identity = "44444444-4444-4444-8444-444444444444",
        .run = id(40),
        .attempt = RegisteredCapturePlanRosterBridge::attempt_identity(
            "33333333-3333-4333-8333-333333333333"),
        .cohort = id(42),
        .source_identity = id(43),
        .build_identity = id(44),
        .launcher_identity = id(45),
        .model_preimage_identity = id(46),
        .query_store_preimage_identity = id(47),
        .scalar_capture_manifest_identity = identity_registry::unhex(
            "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b"),
        .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
    };
    result.trial = RegisteredCapturePlanRosterBridge::trial_identity(
        result.capture_trial_id);
    return result;
}

void positive_and_replay() {
    auto capture = CapturePlanAuthority::test_only_mint(
        plan(std::string(TRIAL_A)));
    auto roster_authority = ImmutableRegisteredRosterAuthority::test_only_mint(
        roster(std::string(TRIAL_A)));
    auto bound = RegisteredCapturePlanRosterBridge::bind(
        std::move(capture), std::move(roster_authority));
    auto capture_residual = bound.take_capture_plan();
    auto roster_residual = bound.take_roster();
    refuses([&] { (void)bound.take_capture_plan(); });
    refuses([&] { (void)bound.take_roster(); });
    refuses([&] {
        (void)RegisteredCapturePlanRosterBridge::bind(
            std::move(capture), std::move(roster_authority));
    });

    // The residuals remain genuine and linear; a second bind transfers rather
    // than duplicates them.
    auto rebound = RegisteredCapturePlanRosterBridge::bind(
        std::move(capture_residual), std::move(roster_residual));
    (void)rebound.take_capture_plan();
    (void)rebound.take_roster();
}

void cross_uuid_refuses() {
    auto capture = CapturePlanAuthority::test_only_mint(
        plan(std::string(TRIAL_B)));
    auto roster_authority = ImmutableRegisteredRosterAuthority::test_only_mint(
        roster(std::string(TRIAL_A)));
    refuses([&] {
        (void)RegisteredCapturePlanRosterBridge::bind(
            std::move(capture), std::move(roster_authority));
    });
}

void stale_capture_burns_fresh_roster() {
    auto stale_capture = CapturePlanAuthority::test_only_mint(
        plan(std::string(TRIAL_A)));
    auto initial_roster = ImmutableRegisteredRosterAuthority::test_only_mint(
        roster(std::string(TRIAL_A)));
    (void)RegisteredCapturePlanRosterBridge::bind(
        std::move(stale_capture), std::move(initial_roster));

    auto fresh_roster = ImmutableRegisteredRosterAuthority::test_only_mint(
        roster(std::string(TRIAL_A)));
    refuses([&] {
        (void)RegisteredCapturePlanRosterBridge::bind(
            std::move(stale_capture), std::move(fresh_roster));
    });

    // A failed join burns both inputs.  The second input must not remain
    // reusable merely because the first input was already stale.
    auto fresh_capture = CapturePlanAuthority::test_only_mint(
        plan(std::string(TRIAL_A)));
    refuses([&] {
        (void)RegisteredCapturePlanRosterBridge::bind(
            std::move(fresh_capture), std::move(fresh_roster));
    });
}

void caller_string_and_digest_refuse() {
    {
        auto bad = plan(std::string(TRIAL_A));
        bad.capture_trial_id =
            "11111111-1111-4111-8111-111111111112";
        auto capture = CapturePlanAuthority::test_only_mint(std::move(bad));
        auto roster_authority =
            ImmutableRegisteredRosterAuthority::test_only_mint(
                roster(std::string(TRIAL_A)));
        refuses([&] {
            (void)RegisteredCapturePlanRosterBridge::bind(
                std::move(capture), std::move(roster_authority));
        });
    }
    {
        auto bad = plan(std::string(TRIAL_A));
        bad.trial = id(99);
        auto capture = CapturePlanAuthority::test_only_mint(std::move(bad));
        auto roster_authority =
            ImmutableRegisteredRosterAuthority::test_only_mint(
                roster(std::string(TRIAL_A)));
        refuses([&] {
            (void)RegisteredCapturePlanRosterBridge::bind(
                std::move(capture), std::move(roster_authority));
        });
    }
    {
        auto bad = plan(std::string(TRIAL_A));
        bad.capture_trial_id =
            "11111111-1111-4111-8111-11111111111A";
        auto capture = CapturePlanAuthority::test_only_mint(std::move(bad));
        auto roster_authority =
            ImmutableRegisteredRosterAuthority::test_only_mint(
                roster(std::string(TRIAL_A)));
        refuses([&] {
            (void)RegisteredCapturePlanRosterBridge::bind(
                std::move(capture), std::move(roster_authority));
        });
    }
}

} // namespace

int main() {
    positive_and_replay();
    cross_uuid_refuses();
    stale_capture_burns_fresh_roster();
    caller_string_and_digest_refuse();
    return 0;
}
