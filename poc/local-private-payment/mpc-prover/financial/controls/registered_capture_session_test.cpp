#include "../registered_capture_session.hpp"
#include "../baseline_public_effects_collector.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <concepts>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace kpi::mpc::financial::registered_driver;

template<class T> concept HasPublicReceipt = requires(const T& value) {
    value.public_receipt();
};

static_assert(!std::default_initializable<
              baseline_disclosure::BaselineTerminalOwnerMappingAuthority>);
static_assert(!std::copy_constructible<
              baseline_disclosure::BaselineTerminalOwnerMappingAuthority>);
static_assert(!HasPublicReceipt<
              baseline_disclosure::BaselineTerminalOwnerMappingAuthority>);

namespace {
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest digest(unsigned char value) {
    Digest result{}; result.fill(value); return result;
}

PublicCapturePlan plan_value(
        unsigned round = 1,
        CaptureClassification classification =
            CaptureClassification::HiddenCandidate) {
    return PublicCapturePlan{
        .classification = classification,
        .round = round,
        .capture_trial_id = std::string(TRIAL_UUID),
        .capture_attempt_id = "123e4567-e89b-42d3-a456-426614174000",
        .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
        .run = digest(0x11),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .attempt = RegisteredCapturePlanRosterBridge::attempt_identity(
            "123e4567-e89b-42d3-a456-426614174000"),
        .cohort = digest(0x13), .source_identity = digest(0x14),
        .build_identity = digest(0x15), .launcher_identity = digest(0x16),
        .model_preimage_identity = digest(0x17),
        .query_store_preimage_identity = digest(0x18),
        .scalar_capture_manifest_identity =
            kpi::mpc::financial::identity_registry::unhex(
            "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b"),
        .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
    };
}

CapturePlanAuthority plan(
        unsigned round = 1, unsigned role = 0,
        CaptureClassification classification =
            CaptureClassification::HiddenCandidate) {
    return CapturePlanAuthority::test_only_session_residual(
        plan_value(round, classification), role);
}

baseline_disclosure::PublicExplicitOwnerEffects explicit_value(
        const PublicCapturePlan& plan, const Digest& plan_identity,
        const Digest& projection_identity) {
    baseline_disclosure::PublicExplicitOwnerEffects result{
        .status = "EXPLICIT_OWNER_PUBLIC_EFFECTS",
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = plan.round,
        .run = plan.run,
        .trial = plan.trial,
        .attempt = plan.attempt,
        .cohort = plan.cohort,
        .capture_plan_identity = plan_identity,
        .projection_identity = projection_identity,
        .context_identity = digest(0x22),
    };
    for (unsigned owner = 0; owner < result.owner_effects.size(); ++owner) {
        result.owner_effects[owner] = baseline_disclosure::PublicOwnerEffect{
            .owner = owner,
            .owner_contract_identity = digest(0x30 + owner),
            .public_nullifier = digest(0x40 + owner),
            .public_tuple_hashes = {
                digest(0x50 + 2 * owner), digest(0x51 + 2 * owner)},
        };
    }
    return result;
}

struct Pipe {
    int read{-1};
    explicit Pipe(int target) {
        std::array<int, 2> descriptors{};
        assert(::pipe2(descriptors.data(), O_CLOEXEC) == 0);
        read = descriptors[0];
        assert(::dup2(descriptors[1], target) == target);
        if (descriptors[1] != target) assert(::close(descriptors[1]) == 0);
    }
    Pipe(const Pipe&) = delete;
    ~Pipe() { if (read >= 0) (void)::close(read); }
    std::vector<unsigned char> drain() {
        std::vector<unsigned char> result;
        std::array<unsigned char, 4096> buffer{};
        for (;;) {
            const auto count = ::read(read, buffer.data(), buffer.size());
            if (count == 0) break;
            assert(count > 0);
            result.insert(result.end(), buffer.begin(),
                          buffer.begin() + count);
        }
        assert(::close(read) == 0); read = -1; return result;
    }
};

std::vector<unsigned char> tags(const std::vector<unsigned char>& raw) {
    std::vector<unsigned char> result;
    std::size_t at = 0;
    while (at < raw.size()) {
        assert(raw.size() - at >= 17);
        assert(std::string(raw.begin() + at, raw.begin() + at + 8) ==
               "KPBCEV01");
        result.push_back(raw[at + 8]);
        std::uint64_t size = 0;
        for (unsigned index = 0; index < 8; ++index)
            size = (size << 8) | raw[at + 9 + index];
        at += 17 + static_cast<std::size_t>(size);
        assert(at <= raw.size());
    }
    return result;
}

std::size_t occurrences(const std::vector<unsigned char>& raw,
                        const std::string& value) {
    return std::count(raw.begin(), raw.end(),
                      static_cast<unsigned char>(value.front())) == 0
        ? 0
        : [&] {
            const std::string text(raw.begin(), raw.end());
            std::size_t count = 0, at = 0;
            while ((at = text.find(value, at)) != std::string::npos) {
                ++count; at += value.size();
            }
            return count;
        }();
}

void exact_single_writer_and_no_synthetic_route() {
    Pipe projection(20); Pipe dispatcher(22);
    std::vector<unsigned char> projection_raw, dispatcher_raw;
    std::thread projection_reader(
        [&] { projection_raw = projection.drain(); });
    std::thread dispatcher_reader(
        [&] { dispatcher_raw = dispatcher.drain(); });
    auto session = RegisteredCaptureSession::test_only_begin(plan(), 0);
    session->test_only_listeners_ready();
    for (const auto owner : {2U, 0U, 1U})
        session->owner_authenticated(owner);
    for (unsigned owner = 0; owner < 3; ++owner)
        session->owner_upload_complete(owner, 64);
    std::vector<unsigned char> released(10685, 0x41);
    session->test_only_released_projection(released);
    assert(session->test_only_projection_identity() ==
           kpi::mpc::financial::identity_registry::digest(released));
    session.reset();
    projection_reader.join(); dispatcher_reader.join();
    assert(tags(projection_raw) == std::vector<unsigned char>({1, 4, 5}));
    const auto dispatcher_tags = tags(dispatcher_raw);
    assert(dispatcher_tags.front() == 1);
    assert(std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 2) == 1);
    assert(std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 3) == 9);
    assert(std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 5) == 0);
    assert(occurrences(dispatcher_raw, "aggregate-release") == 1);
    assert(occurrences(dispatcher_raw, "release-policy-bound") == 1);
    assert(occurrences(dispatcher_raw, "outbound-route") == 0);
}

void non_owner_roles_never_touch_capture_fds() {
    (void)::close(20); (void)::close(22);
    for (unsigned role : {1U, 2U}) {
        auto session = RegisteredCaptureSession::test_only_begin(
            plan(1, role), role);
        session->test_only_listeners_ready();
        for (unsigned owner = 0; owner < 3; ++owner)
            session->owner_authenticated(owner);
        for (unsigned owner = 0; owner < 3; ++owner)
            session->owner_upload_complete(owner, 64);
        std::vector<unsigned char> released(10685,
                                            static_cast<unsigned char>(role));
        session->test_only_released_projection(released);
        assert(session->test_only_projection_identity() ==
               kpi::mpc::financial::identity_registry::digest(released));
    }
}

void baseline_emits_exact_public_mapping_after_release() {
    Pipe projection(20); Pipe dispatcher(22);
    std::vector<unsigned char> projection_raw, dispatcher_raw;
    std::thread projection_reader(
        [&] { projection_raw = projection.drain(); });
    std::thread dispatcher_reader(
        [&] { dispatcher_raw = dispatcher.drain(); });
    const auto public_plan = plan_value(
        1, CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    auto session = RegisteredCaptureSession::test_only_begin(
        CapturePlanAuthority::test_only_session_residual(public_plan, 0), 0);
    session->test_only_listeners_ready();
    for (unsigned owner = 0; owner < 3; ++owner) {
        session->owner_authenticated(owner);
        session->owner_upload_complete(owner, 64);
    }
    std::vector<unsigned char> released(10685, 0x61);
    session->test_only_released_projection(released);
    auto wrong_trial_value = explicit_value(
        public_plan, session->test_only_plan_identity(),
        session->test_only_projection_identity());
    wrong_trial_value.trial = digest(0xfe);
    auto wrong_trial = baseline_disclosure::
        ExplicitOwnerPublicEffectsAuthority::test_only_mint(
            std::move(wrong_trial_value));
    bool wrong_trial_refused = false;
    try {
        auto impossible = RegisteredBaselineObserverCaptureBridge::
            explicit_owner_public_effects(*session, std::move(wrong_trial));
        (void)impossible;
    } catch (...) { wrong_trial_refused = true; }
    assert(wrong_trial_refused);
    auto authority = baseline_disclosure::ExplicitOwnerPublicEffectsAuthority::
        test_only_mint(explicit_value(
            public_plan, session->test_only_plan_identity(),
            session->test_only_projection_identity()));
    auto terminal_mapping =
        RegisteredBaselineObserverCaptureBridge::explicit_owner_public_effects(
        *session, std::move(authority));
    (void)terminal_mapping;
    bool replay_refused = false;
    try {
        RegisteredBaselineObserverCaptureBridge::explicit_owner_public_effects(
            *session, std::move(authority));
    } catch (...) { replay_refused = true; }
    assert(replay_refused);
    session.reset();
    projection_reader.join(); dispatcher_reader.join();
    assert(tags(projection_raw) == std::vector<unsigned char>({1, 4, 5}));
    const auto dispatcher_tags = tags(dispatcher_raw);
    assert(dispatcher_tags.front() == 1);
    assert(std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 2) == 1);
    assert(std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 3) == 10);
    assert(std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 5) == 0);
    assert(occurrences(dispatcher_raw, "EXPLICIT_OWNER_PUBLIC_EFFECTS") == 1);
    assert(occurrences(dispatcher_raw,
                       "explicit-owner-public-effects") == 1);
    assert(occurrences(dispatcher_raw, "release-policy-bound") == 1);
    assert(occurrences(dispatcher_raw, "outbound-route") == 0);
    for (const auto forbidden : {"logical_owner", "certificate", "body_sha256"})
        assert(occurrences(dispatcher_raw, forbidden) == 0);
}

void missing_designated_dispatcher_refuses_before_lock() {
    (void)::close(22);
    bool refused = false;
    try {
        auto session = RegisteredCaptureSession::test_only_begin(plan(), 0);
        (void)session;
    } catch (...) { refused = true; }
    assert(refused);
}

void unsplit_and_wrong_role_residual_refuse() {
    bool unsplit_refused = false;
    try {
        auto session = RegisteredCaptureSession::test_only_begin(
            CapturePlanAuthority::test_only_mint(plan_value()), 2);
        (void)session;
    } catch (...) { unsplit_refused = true; }
    assert(unsplit_refused);

    bool role_refused = false;
    try {
        auto session = RegisteredCaptureSession::test_only_begin(
            plan(1, 1), 2);
        (void)session;
    } catch (...) { role_refused = true; }
    assert(role_refused);
}

} // namespace

int main() {
    exact_single_writer_and_no_synthetic_route();
    non_owner_roles_never_touch_capture_fds();
    baseline_emits_exact_public_mapping_after_release();
    missing_designated_dispatcher_refuses_before_lock();
    unsplit_and_wrong_role_residual_refuse();
}
