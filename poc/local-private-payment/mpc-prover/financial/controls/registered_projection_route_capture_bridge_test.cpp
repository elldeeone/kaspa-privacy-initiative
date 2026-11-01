#include "../registered_projection_route_capture_bridge.hpp"
#include "../registered_projection_route.hpp"
#include "../registered_capture_session.hpp"
#include "../baseline_public_effects_collector.hpp"
#include "../registered_identity_registry.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::projection_route;

namespace {
using Bytes = std::vector<unsigned char>;
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest id(unsigned char value) {
    Digest result{}; result.fill(value); return result;
}
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_string(Bytes& out, const std::string& value) {
    integer(out, value.size());
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

Digest capture_plan_identity(const PublicCapturePlan& value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_CAPTURE_PLAN_V4\n");
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    integer(bytes, value.round);
    add_string(bytes, value.capture_trial_id);
    add_string(bytes, value.capture_attempt_id);
    add_string(bytes, value.capture_identity);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.source_identity, &value.build_identity,
             &value.launcher_identity, &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity})
        add(bytes, *field);
    for (const auto fd : value.fixed_fds)
        integer(bytes, static_cast<std::uint64_t>(fd));
    return kpi::mpc::financial::identity_registry::digest(bytes);
}

PublicCapturePlan capture_plan(CaptureClassification classification) {
    return PublicCapturePlan{
        .classification = classification,
        .round = 1,
        .capture_trial_id = std::string(TRIAL_UUID),
        .capture_attempt_id = "123e4567-e89b-42d3-a456-426614174000",
        .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
        .run = id(0x11),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .attempt = RegisteredCapturePlanRosterBridge::attempt_identity(
            "123e4567-e89b-42d3-a456-426614174000"),
        .cohort = id(0x13), .source_identity = id(0x14),
        .build_identity = id(0x15), .launcher_identity = id(0x16),
        .model_preimage_identity = id(0x17),
        .query_store_preimage_identity = id(0x18),
        .scalar_capture_manifest_identity =
            kpi::mpc::financial::identity_registry::unhex(
            "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b"),
        .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
    };
}

PublicProjectionRoutePlan route_plan(const PublicCapturePlan& capture) {
    return PublicProjectionRoutePlan{
        .classification = capture.classification,
        .round = capture.round,
        .computing_role = 0,
        .trial = capture.trial,
        .attempt = capture.attempt,
        .cohort = capture.cohort,
        .financial_run = capture.run,
        .capture_plan_identity = capture_plan_identity(capture),
        .producer_process_authority = id(0x30),
        .producer_exit_authority = id(0x31),
        .dispatcher_process_authority = id(0x32),
        .dispatcher_exit_authority = id(0x33),
    };
}

std::vector<unsigned char> projection(unsigned char seed) {
    std::vector<unsigned char> result(PUBLIC_PROJECTION_BYTES);
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(seed + index % 251);
    return result;
}

baseline_disclosure::PublicExplicitOwnerEffects explicit_effects(
        const PublicCapturePlan& plan, const Digest& plan_identity,
        const Digest& projection_identity) {
    baseline_disclosure::PublicExplicitOwnerEffects result{
        .status = "EXPLICIT_OWNER_PUBLIC_EFFECTS",
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = plan.round,
        .run = plan.run, .trial = plan.trial, .attempt = plan.attempt,
        .cohort = plan.cohort,
        .capture_plan_identity = plan_identity,
        .projection_identity = projection_identity,
        .context_identity = id(0x40),
    };
    for (unsigned owner = 0; owner < 3; ++owner)
        result.owner_effects[owner] = baseline_disclosure::PublicOwnerEffect{
            .owner = owner,
            .owner_contract_identity = id(0x50 + owner),
            .public_nullifier = id(0x60 + owner),
            .public_tuple_hashes = {
                id(0x70 + 2 * owner), id(0x71 + 2 * owner)},
        };
    return result;
}

struct CapturePipes {
    int projection_read{-1};
    int dispatcher_read{-1};
    CapturePipes() {
        std::array<int, 2> projection_pipe{}, dispatcher_pipe{};
        assert(::pipe2(projection_pipe.data(), O_CLOEXEC) == 0);
        assert(::pipe2(dispatcher_pipe.data(), O_CLOEXEC) == 0);
        projection_read = projection_pipe[0];
        dispatcher_read = dispatcher_pipe[0];
        assert(::dup2(projection_pipe[1], 20) == 20);
        assert(::dup2(dispatcher_pipe[1], 22) == 22);
        if (projection_pipe[1] != 20) assert(::close(projection_pipe[1]) == 0);
        if (dispatcher_pipe[1] != 22) assert(::close(dispatcher_pipe[1]) == 0);
    }
    void child_close_reads() {
        (void)::close(projection_read); projection_read = -1;
        (void)::close(dispatcher_read); dispatcher_read = -1;
    }
    void parent_close_writes() {
        (void)::close(20); (void)::close(22);
    }
    static Bytes drain(int& fd) {
        Bytes result; std::array<unsigned char, 4096> buffer{};
        for (;;) {
            const auto count = ::read(fd, buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR) continue;
            assert(count >= 0);
            if (count == 0) break;
            result.insert(result.end(), buffer.begin(),
                          buffer.begin() + count);
        }
        (void)::close(fd); fd = -1; return result;
    }
    ~CapturePipes() {
        if (projection_read >= 0) (void)::close(projection_read);
        if (dispatcher_read >= 0) (void)::close(dispatcher_read);
    }
};

void bind_parent(ParentProjectionRouteEndpointAuthority& endpoint,
                 const PublicProjectionRoutePlan& selected,
                 std::int64_t child) {
    endpoint.test_only_bind_role0_process(
        0, selected.round, child, id(0xd1), id(0xd2), id(0xd3), id(0xd4));
}
void bind_writer(Role0ProjectionRouteWriterAuthority& writer,
                 const PublicProjectionRoutePlan& selected) {
    writer.test_only_bind_role0_process(
        0, selected.round, ::getpid(), id(0xd1), id(0xd2), id(0xd3), id(0xd4));
}

std::vector<unsigned char> tags(const Bytes& raw) {
    std::vector<unsigned char> result;
    std::size_t at = 0;
    while (at < raw.size()) {
        assert(raw.size() - at >= 17 &&
               std::string(raw.begin() + at, raw.begin() + at + 8) ==
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
std::size_t occurrences(const Bytes& raw, const std::string& needle) {
    const std::string text(raw.begin(), raw.end());
    std::size_t result = 0, at = 0;
    while ((at = text.find(needle, at)) != std::string::npos) {
        ++result; at += needle.size();
    }
    return result;
}

enum class Mutation {
    None, Body, Projection, Round, Classification, Trial, Run, Attempt,
    Cohort, Plan,
};
enum class ParentFault { None, CloseWriter, OversizedAck, ZeroBeforeEof };

struct Result {
    bool child_success{};
    bool parent_success{};
    bool retained_exact{};
    Bytes projection_capture;
    Bytes dispatcher_capture;
};

Result execute(CaptureClassification classification, Mutation mutation,
               ParentFault fault = ParentFault::None,
               bool replay = false) {
    auto capture = capture_plan(classification);
    auto selected_route = route_plan(capture);
    switch (mutation) {
    case Mutation::Round: selected_route.round = 2; break;
    case Mutation::Classification:
        selected_route.classification =
            classification == CaptureClassification::HiddenCandidate
            ? CaptureClassification::ExplicitOwnerPublicEffectsBaseline
            : CaptureClassification::HiddenCandidate;
        break;
    case Mutation::Trial: selected_route.trial = id(0xe1); break;
    case Mutation::Run: selected_route.financial_run = id(0xe2); break;
    case Mutation::Attempt: selected_route.attempt = id(0xe3); break;
    case Mutation::Cohort: selected_route.cohort = id(0xe4); break;
    case Mutation::Plan: selected_route.capture_plan_identity = id(0xe5); break;
    default: break;
    }
    auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    CapturePipes capture_pipes;
    const auto body = projection(0x81);
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        capture_pipes.child_close_reads();
        auto unused_parent = endpoints.take_parent();
        std::move(unused_parent).discard();
        auto writer = endpoints.take_role0_writer();
        bind_writer(writer, selected_route);
        bool success = false;
        try {
            auto session = RegisteredCaptureSession::test_only_begin(
                CapturePlanAuthority::test_only_session_residual(capture, 0),
                0);
            session->test_only_listeners_ready();
            for (unsigned owner = 0; owner < 3; ++owner) {
                session->owner_authenticated(owner);
                session->owner_upload_complete(owner, 64);
            }
            session->test_only_released_projection(body);
            if (classification ==
                    CaptureClassification::ExplicitOwnerPublicEffectsBaseline) {
                auto authority = baseline_disclosure::
                    ExplicitOwnerPublicEffectsAuthority::test_only_mint(
                        explicit_effects(
                            capture, session->test_only_plan_identity(),
                            session->test_only_projection_identity()));
                auto terminal = RegisteredBaselineObserverCaptureBridge::
                    explicit_owner_public_effects(
                        *session, std::move(authority));
                (void)terminal;
            }
            if (mutation == Mutation::Body)
                session->test_only_corrupt_retained_projection();
            if (mutation == Mutation::Projection)
                session->test_only_corrupt_projection_identity();
            RegisteredProjectionRouteCaptureBridge::consume(
                *session, std::move(writer));
            success = session->test_only_route_complete();
            if (replay) {
                bool refused = false;
                try {
                    RegisteredProjectionRouteCaptureBridge::consume(
                        *session, std::move(writer));
                } catch (...) { refused = true; }
                success = success && refused;
            }
        } catch (...) { success = false; }
        _exit(success ? 0 : 77);
    }

    capture_pipes.parent_close_writes();
    auto parent = endpoints.take_parent();
    auto unused_writer = endpoints.take_role0_writer();
    std::move(unused_writer).discard();
    bind_parent(parent, selected_route, child);
    bool parent_success = false, retained_exact = false;
    try {
        if (fault == ParentFault::CloseWriter) {
            std::move(parent).discard();
        } else {
            auto retained =
                fault == ParentFault::OversizedAck
                ? RegisteredProjectionRoute::test_only_receive_and_retain(
                    std::move(parent),
                    ProjectionRouteTestFault::OversizedAcknowledgement)
                : fault == ParentFault::ZeroBeforeEof
                ? RegisteredProjectionRoute::test_only_receive_and_retain(
                    std::move(parent),
                    ProjectionRouteTestFault::ZeroLengthRecordBeforeParentEof)
                : RegisteredProjectionRoute::receive_and_retain(
                    std::move(parent));
            parent_success = true;
            const auto retained_bytes = retained.test_only_projection();
            retained_exact = retained_bytes.size() == body.size() &&
                std::equal(retained_bytes.begin(), retained_bytes.end(),
                    body.begin(), [](std::byte left, unsigned char right) {
                        return left == static_cast<std::byte>(right);
                    });
        }
    } catch (...) { parent_success = false; }
    int status{}; pid_t waited;
    do { waited = ::waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    assert(waited == child && WIFEXITED(status));
    Result result{
        .child_success = WEXITSTATUS(status) == 0,
        .parent_success = parent_success,
        .retained_exact = retained_exact,
        .projection_capture = CapturePipes::drain(
            capture_pipes.projection_read),
        .dispatcher_capture = CapturePipes::drain(
            capture_pipes.dispatcher_read),
    };
    return result;
}

void positive_exact_sequence() {
    for (const auto classification : {
             CaptureClassification::HiddenCandidate,
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline}) {
        const auto result = execute(
            classification, Mutation::None, ParentFault::None, true);
        assert(result.child_success && result.parent_success &&
               result.retained_exact);
        assert(tags(result.projection_capture) ==
               std::vector<unsigned char>({1, 4, 5}));
        const auto dispatcher_tags = tags(result.dispatcher_capture);
        assert(dispatcher_tags.front() == 1 && dispatcher_tags.back() == 5 &&
               std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 5) ==
                   1 &&
               occurrences(result.dispatcher_capture, "aggregate-release") ==
                   1 &&
               occurrences(result.dispatcher_capture,
                           "release-policy-bound") == 1 &&
               occurrences(result.dispatcher_capture, "outbound-route") ==
                   1 &&
               occurrences(result.dispatcher_capture,
                           "explicit-owner-public-effects") ==
                   (classification == CaptureClassification::HiddenCandidate
                    ? 0 : 1));
    }
}

void lineage_and_body_refuse() {
    for (const auto mutation : {
             Mutation::Body, Mutation::Projection, Mutation::Round,
             Mutation::Classification, Mutation::Trial, Mutation::Run,
             Mutation::Attempt, Mutation::Cohort, Mutation::Plan}) {
        const auto result = execute(
            CaptureClassification::HiddenCandidate, mutation);
        assert(!result.child_success);
        assert(occurrences(result.dispatcher_capture, "outbound-route") == 0);
        const auto dispatcher_tags = tags(result.dispatcher_capture);
        assert(std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 5) ==
               0);
    }
}

void writer_ack_eof_failures_refuse() {
    for (const auto fault : {
             ParentFault::CloseWriter, ParentFault::OversizedAck,
             ParentFault::ZeroBeforeEof}) {
        const auto result = execute(
            CaptureClassification::HiddenCandidate,
            Mutation::None, fault);
        const auto dispatcher_tags = tags(result.dispatcher_capture);
        assert(!result.child_success &&
               occurrences(result.dispatcher_capture, "outbound-route") == 0 &&
               std::count(dispatcher_tags.begin(), dispatcher_tags.end(), 5) ==
                   0);
    }
}
} // namespace

int main() {
    positive_exact_sequence();
    lineage_and_body_refuse();
    writer_ack_eof_failures_refuse();
}
