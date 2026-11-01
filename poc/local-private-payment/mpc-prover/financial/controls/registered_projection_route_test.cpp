#include "../registered_projection_route.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <span>
#include <stdexcept>
#include <sys/wait.h>
#include <tuple>
#include <unistd.h>
#include <utility>

using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::projection_route;

namespace {

Digest id(unsigned char value) {
    Digest result{}; result.fill(value); return result;
}

PublicProjectionRoutePlan plan(
        CaptureClassification classification, unsigned round,
        unsigned char base) {
    return PublicProjectionRoutePlan{
        .classification = classification,
        .round = round,
        .computing_role = 0,
        .trial = id(base),
        .attempt = id(base + 1),
        .cohort = id(base + 2),
        .financial_run = id(base + 3),
        .capture_plan_identity = id(base + 4),
        .producer_process_authority = id(base + 5),
        .producer_exit_authority = id(base + 6),
        .dispatcher_process_authority = id(base + 7),
        .dispatcher_exit_authority = id(base + 8),
    };
}

std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection(
        unsigned char seed) {
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<std::byte>(seed + index % 251);
    return result;
}

bool same_projection(
        std::span<const std::byte> left,
        const std::array<std::byte, PUBLIC_PROJECTION_BYTES>& right) {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

void bind_parent(ParentProjectionRouteEndpointAuthority& endpoint,
                 const PublicProjectionRoutePlan& selected,
                 std::int64_t role0_pid) {
    endpoint.test_only_bind_role0_process(
        0, selected.round, role0_pid, id(0xd1), id(0xd2), id(0xd3),
        id(0xd4));
}

void bind_writer(Role0ProjectionRouteWriterAuthority& writer,
                 const PublicProjectionRoutePlan& selected) {
    writer.test_only_bind_role0_process(
        0, selected.round, ::getpid(), id(0xd1), id(0xd2), id(0xd3),
        id(0xd4));
}

void write_exact(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0); at += static_cast<std::size_t>(count);
    }
}
void read_exact(int fd, std::span<unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::read(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0); at += static_cast<std::size_t>(count);
    }
}

void require_clean_child(pid_t child) {
    int status{};
    pid_t waited;
    do { waited = ::waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    assert(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

struct RunResult {
    ParentRetainedProjectionAuthority retained;
    Digest route;
};

RunResult positive(PublicProjectionRoutePlan selected,
                   std::array<std::byte, PUBLIC_PROJECTION_BYTES> bytes,
                   bool delay_reader) {
    auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    std::array<int, 2> observation{-1, -1};
    assert(::pipe2(observation.data(), O_CLOEXEC) == 0);
    const auto child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        (void)::close(observation[0]);
        try {
            auto unused_parent = endpoints.take_parent();
            std::move(unused_parent).discard();
            auto writer = endpoints.take_role0_writer();
            bind_writer(writer, selected);
            auto delivery = ProjectionDeliveryAuthority::test_only_mint(
                selected, bytes);
            const auto completion =
                RegisteredProjectionRoute::deliver_after_release(
                    std::move(writer), std::move(delivery));
            assert(completion.public_receipt().parent_read_complete &&
                   completion.public_receipt().parent_kernel_eof &&
                   completion.public_receipt().parent_acknowledged &&
                   completion.public_receipt().parent_writer_closed);
            const auto identity = completion.test_only_route_identity();
            write_exact(observation[1], identity);
            (void)::close(observation[1]);
            _exit(0);
        } catch (...) { _exit(91); }
    }
    (void)::close(observation[1]);
    auto parent = endpoints.take_parent();
    auto unused_writer = endpoints.take_role0_writer();
    std::move(unused_writer).discard();
    bind_parent(parent, selected, child);
    if (delay_reader) ::usleep(50'000);
    auto retained = RegisteredProjectionRoute::receive_and_retain(
        std::move(parent));
    Digest route{}; read_exact(observation[0], route);
    (void)::close(observation[0]);
    require_clean_child(child);
    return RunResult{std::move(retained), route};
}

template<class T>
concept HasProjectionMember = requires(T value) { value.projection; };
template<class T>
concept HasRouteIdentityMember = requires(T value) { value.route_identity; };
template<class T>
concept HasPidMember = requires(T value) { value.pid; };

void positive_both_arms_and_private_retention() {
    auto candidate = positive(
        plan(CaptureClassification::HiddenCandidate, 1, 0x10),
        projection(0x31), true);
    const auto& candidate_receipt = candidate.retained.public_receipt();
    assert(candidate_receipt.round == 1 &&
           candidate_receipt.exact_size && candidate_receipt.read_complete &&
           candidate_receipt.kernel_eof && candidate_receipt.clean &&
           same_projection(candidate.retained.test_only_projection(),
                           projection(0x31)));

    auto baseline = positive(
        plan(CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
             2, 0x40), projection(0x52), false);
    const auto& baseline_receipt = baseline.retained.public_receipt();
    assert(baseline_receipt.round == 2 &&
           baseline_receipt.exact_size && baseline_receipt.read_complete &&
           baseline_receipt.kernel_eof && baseline_receipt.clean &&
           same_projection(baseline.retained.test_only_projection(),
                           projection(0x52)));
    assert(candidate.route != baseline.route);

    auto native = RegisteredProjectionRoute::
        test_only_transfer_for_native_terminal(
            std::move(candidate.retained));
    assert(same_projection(native.test_only_projection(), projection(0x31)));
    bool refused = false;
    try {
        (void)RegisteredProjectionRoute::
            test_only_transfer_for_native_terminal(
                std::move(candidate.retained));
    } catch (const std::runtime_error&) { refused = true; }
    assert(refused);
}

void wrong_lineage_refuses_both_halves() {
    auto selected = plan(CaptureClassification::HiddenCandidate, 1, 0x60);
    auto changed = selected; changed.trial = id(0xee);
    auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    const auto child = ::fork(); assert(child >= 0);
    if (child == 0) {
        try {
            auto unused_parent = endpoints.take_parent();
            std::move(unused_parent).discard();
            auto writer = endpoints.take_role0_writer();
            bind_writer(writer, selected);
            auto delivery = ProjectionDeliveryAuthority::test_only_mint(
                changed, projection(0x71));
            (void)RegisteredProjectionRoute::deliver_after_release(
                std::move(writer), std::move(delivery));
            _exit(92);
        } catch (...) { _exit(0); }
    }
    auto parent = endpoints.take_parent();
    auto unused_writer = endpoints.take_role0_writer();
    std::move(unused_writer).discard();
    bind_parent(parent, selected, child);
    bool refused = false;
    try {
        (void)RegisteredProjectionRoute::receive_and_retain(
            std::move(parent));
    } catch (const std::runtime_error&) { refused = true; }
    assert(refused); require_clean_child(child);
}

void closed_parent_poisons_writer() {
    auto selected = plan(CaptureClassification::HiddenCandidate, 1, 0x80);
    auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    const auto child = ::fork(); assert(child >= 0);
    if (child == 0) {
        try {
            auto unused_parent = endpoints.take_parent();
            std::move(unused_parent).discard();
            auto writer = endpoints.take_role0_writer();
            bind_writer(writer, selected);
            ::usleep(50'000);
            auto delivery = ProjectionDeliveryAuthority::test_only_mint(
                selected, projection(0x91));
            (void)RegisteredProjectionRoute::deliver_after_release(
                std::move(writer), std::move(delivery));
            _exit(93);
        } catch (...) { _exit(0); }
    }
    {
        auto parent = endpoints.take_parent();
        auto unused_writer = endpoints.take_role0_writer();
        std::move(unused_writer).discard();
        bind_parent(parent, selected, child);
        (void)parent;
    }
    require_clean_child(child);
}

void malformed_frame_controls() {
    for (const auto [child_fault, parent_fault, parent_refuses,
                     child_refuses] : {
             std::tuple{ProjectionRouteTestFault::ExtraFrameBeforeEof,
                        ProjectionRouteTestFault::None, true, true},
             std::tuple{ProjectionRouteTestFault::None,
                        ProjectionRouteTestFault::OversizedAcknowledgement,
                        false, true},
             std::tuple{
                 ProjectionRouteTestFault::ZeroLengthRecordBeforeChildEof,
                 ProjectionRouteTestFault::None, true, true},
             std::tuple{
                 ProjectionRouteTestFault::None,
                 ProjectionRouteTestFault::ZeroLengthRecordBeforeParentEof,
                 false, true},
             std::tuple{
                 ProjectionRouteTestFault::ZeroLengthChildRecordWhileOpen,
                 ProjectionRouteTestFault::None, true, true},
         }) {
        auto selected = plan(CaptureClassification::HiddenCandidate,
                             1, child_fault ==
                                    ProjectionRouteTestFault::None
                                    ? 0xc0 : 0xd0);
        auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
            ProjectionRoutePlanAuthority::test_only_mint(selected));
        const auto child = ::fork(); assert(child >= 0);
        if (child == 0) {
            auto unused_parent = endpoints.take_parent();
            std::move(unused_parent).discard();
            auto writer = endpoints.take_role0_writer();
            bind_writer(writer, selected);
            bool refused = false;
            try {
                auto delivery = ProjectionDeliveryAuthority::test_only_mint(
                    selected, projection(0xa7));
                (void)RegisteredProjectionRoute::
                    test_only_deliver_after_release(
                        std::move(writer), std::move(delivery), child_fault);
            } catch (const std::runtime_error&) { refused = true; }
            _exit(refused == child_refuses ? 0 : 94);
        }
        auto parent = endpoints.take_parent();
        auto unused_writer = endpoints.take_role0_writer();
        std::move(unused_writer).discard();
        bind_parent(parent, selected, child);
        bool refused = false;
        try {
            (void)RegisteredProjectionRoute::test_only_receive_and_retain(
                std::move(parent), parent_fault);
        } catch (const std::runtime_error&) { refused = true; }
        assert(refused == parent_refuses);
        require_clean_child(child);
    }
}

void sibling_writer_is_not_role_zero() {
    auto selected = plan(CaptureClassification::HiddenCandidate, 1, 0xe0);
    auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    const auto role0 = ::fork(); assert(role0 >= 0);
    if (role0 == 0) {
        auto parent = endpoints.take_parent();
        auto writer = endpoints.take_role0_writer();
        std::move(parent).discard();
        std::move(writer).discard();
        ::usleep(100'000);
        _exit(0);
    }
    const auto sibling = ::fork(); assert(sibling >= 0);
    if (sibling == 0) {
        auto parent = endpoints.take_parent();
        std::move(parent).discard();
        auto writer = endpoints.take_role0_writer();
        bind_writer(writer, selected);
        bool refused = false;
        try {
            auto delivery = ProjectionDeliveryAuthority::test_only_mint(
                selected, projection(0xe7));
            (void)RegisteredProjectionRoute::deliver_after_release(
                std::move(writer), std::move(delivery));
        } catch (const std::runtime_error&) { refused = true; }
        _exit(refused ? 0 : 95);
    }
    auto parent = endpoints.take_parent();
    auto writer = endpoints.take_role0_writer();
    std::move(writer).discard();
    bind_parent(parent, selected, role0);
    bool refused = false;
    try {
        (void)RegisteredProjectionRoute::receive_and_retain(
            std::move(parent));
    } catch (const std::runtime_error&) { refused = true; }
    assert(refused);
    require_clean_child(sibling);
    require_clean_child(role0);
}

void stale_round_and_wrong_role_poison_binding() {
    for (const auto [role, round] : {
             std::pair{1U, 1U}, std::pair{0U, 2U}}) {
        auto selected = plan(CaptureClassification::HiddenCandidate, 1, 0xf0);
        auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
            ProjectionRoutePlanAuthority::test_only_mint(selected));
        auto parent = endpoints.take_parent();
        auto writer = endpoints.take_role0_writer();
        bool refused = false;
        try {
            parent.test_only_bind_role0_process(
                role, round, ::getpid() + 1000, id(0xd1), id(0xd2),
                id(0xd3), id(0xd4));
        } catch (const std::runtime_error&) { refused = true; }
        assert(refused);
        refused = false;
        try {
            parent.test_only_bind_role0_process(
                0, selected.round, ::getpid() + 1001, id(0xd1), id(0xd2),
                id(0xd3), id(0xd4));
        } catch (const std::runtime_error&) { refused = true; }
        assert(refused);
        std::move(parent).discard();
        std::move(writer).discard();
    }
}

void wrong_role_and_double_take_refuse() {
    auto wrong = plan(CaptureClassification::HiddenCandidate, 1, 0xa0);
    wrong.computing_role = 1;
    bool refused = false;
    try {
        (void)ProjectionRoutePlanAuthority::test_only_mint(wrong);
    } catch (const std::runtime_error&) { refused = true; }
    assert(refused);

    auto selected = plan(CaptureClassification::HiddenCandidate, 1, 0xb0);
    auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    auto parent = endpoints.take_parent();
    auto writer = endpoints.take_role0_writer();
    refused = false;
    try { (void)endpoints.take_parent(); }
    catch (const std::runtime_error&) { refused = true; }
    assert(refused);
    refused = false;
    try { (void)endpoints.take_role0_writer(); }
    catch (const std::runtime_error&) { refused = true; }
    assert(refused);
    std::move(parent).discard();
    std::move(writer).discard();
}

void failed_join_burns_writer_and_delivery_independently() {
    auto selected = plan(CaptureClassification::HiddenCandidate, 1, 0xb8);
    auto stale_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    auto stale_parent = stale_endpoints.take_parent();
    auto stale_writer = stale_endpoints.take_role0_writer();
    std::move(stale_parent).discard();
    std::move(stale_writer).discard();
    auto delivery = ProjectionDeliveryAuthority::test_only_mint(
        selected, projection(0xb9));

    bool refused = false;
    try {
        (void)RegisteredProjectionRoute::deliver_after_release(
            std::move(stale_writer), std::move(delivery));
    } catch (const std::runtime_error&) { refused = true; }
    assert(refused);

    auto fresh_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    auto fresh_parent = fresh_endpoints.take_parent();
    auto fresh_writer = fresh_endpoints.take_role0_writer();
    std::move(fresh_parent).discard();
    refused = false;
    try {
        (void)RegisteredProjectionRoute::deliver_after_release(
            std::move(fresh_writer), std::move(delivery));
    } catch (const std::runtime_error&) { refused = true; }
    assert(refused);
}

void inherited_parent_peer_alias_is_exact_and_one_shot() {
    auto selected = plan(CaptureClassification::HiddenCandidate, 1, 0x24);
    auto endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    auto parent = endpoints.take_parent();
    auto writer = endpoints.take_role0_writer();
    assert(writer.test_only_parent_peer_alias_open());
    auto moved = Role0ProjectionRouteWriterAuthority(std::move(writer));
    assert(moved.test_only_parent_peer_alias_open());
    moved.test_only_close_inherited_parent_peer_alias();
    assert(!moved.test_only_parent_peer_alias_open());
    bool refused = false;
    try { moved.test_only_close_inherited_parent_peer_alias(); }
    catch (const std::runtime_error&) { refused = true; }
    assert(refused);
    std::move(parent).discard();
    std::move(moved).discard();

    auto already_closed = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected));
    auto closed_parent = already_closed.take_parent();
    auto blocked_writer = already_closed.take_role0_writer();
    std::move(closed_parent).discard();
    assert(!blocked_writer.test_only_parent_peer_alias_open());
    refused = false;
    try { blocked_writer.test_only_close_inherited_parent_peer_alias(); }
    catch (const std::runtime_error&) { refused = true; }
    assert(refused);
    std::move(blocked_writer).discard();
}

} // namespace

int main() {
    static_assert(!HasProjectionMember<PublicRetainedProjectionReceipt>);
    static_assert(!HasRouteIdentityMember<PublicRetainedProjectionReceipt>);
    static_assert(!HasPidMember<PublicRetainedProjectionReceipt>);
    static_assert(!std::copy_constructible<ProjectionRoutePlanAuthority>);
    static_assert(!std::copy_constructible<ProjectionDeliveryAuthority>);
    static_assert(!std::copy_constructible<ParentRetainedProjectionAuthority>);
    static_assert(!std::copy_constructible<
                  NativeTerminalRetainedProjectionAuthority>);

    positive_both_arms_and_private_retention();
    wrong_lineage_refuses_both_halves();
    closed_parent_poisons_writer();
    malformed_frame_controls();
    sibling_writer_is_not_role_zero();
    stale_round_and_wrong_role_poison_binding();
    wrong_role_and_double_take_refuse();
    failed_join_burns_writer_and_delivery_independently();
    inherited_parent_peer_alias_is_exact_and_one_shot();

    const auto status = projection_route_source_status();
    assert(status.parent_minted_pre_intake_pair &&
           status.role0_only_writer && status.exact_projection_bytes &&
           status.kernel_eof_before_ack && status.retained_body_private &&
           status.route_identity_body_independent &&
           !status.candidate_egress_callsite &&
           !status.baseline_post_disclosure_callsite &&
           !status.parent_bootstrap_mint_integration &&
           !status.dispatcher_close_integration &&
           !status.native_terminal_retention_integration &&
           !status.registered_driver_configured && !status.launch_authorized);
}
