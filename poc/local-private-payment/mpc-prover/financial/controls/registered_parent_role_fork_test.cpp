#include "../registered_parent_role_fork.hpp"
#include "../registered_projection_route.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::projection_route;

namespace {
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0x9dU);
    return result;
}

PublicDriverSelection driver_value(
    const PublicParentRoleForkPlan&, unsigned);

PublicProjectionRoutePlan route_plan(
        const PublicParentRoleForkPlan& plan) {
    return {
        .classification = CaptureClassification::HiddenCandidate,
        .round = plan.round,
        .computing_role = 0,
        .trial = plan.trial,
        .attempt = plan.attempt,
        .cohort = plan.cohort,
        .financial_run = plan.financial_run,
        .capture_plan_identity = plan.capture_plan_identity,
        .producer_process_authority = id(105),
        .producer_exit_authority = id(106),
        .dispatcher_process_authority = id(107),
        .dispatcher_exit_authority = id(108),
    };
}

std::array<std::byte, PUBLIC_PROJECTION_BYTES> route_projection() {
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<std::byte>(index % 251);
    return result;
}

PublicParentRoleForkPlan plan_value(unsigned round = 1) {
    PublicParentRoleForkPlan value{
        .classification = CaptureClassification::HiddenCandidate,
        .round = round,
        .capture_trial_id = std::string(TRIAL_UUID),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .financial_run = id(104),
        .attempt = id(102),
        .cohort = id(103),
        .fresh_owner_issuance_identity = id(105),
        .authority_identity = id(1),
        .supervisor_session = id(2),
        .capture_plan_identity = id(3),
        .capture_source_identity = id(4),
        .capture_build_identity = id(5),
        .capture_launcher_identity = id(6),
    };
    for (unsigned role = 0; role < 3; ++role) {
        value.roles[role] = PublicParentRoleBinding{
            .role = role,
            .party_session = id(10 + role),
            .service_identity = id(20),
            .driver_selection_identity = id(30 + role),
        };
    }
    for (unsigned role = 0; role < 3; ++role) {
        auto driver = CompiledDriverSelection::test_only_mint(
            driver_value(value, role));
        value.roles[role].driver_selection_identity = driver.identity();
    }
    return value;
}

PublicDriverSelection driver_value(
        const PublicParentRoleForkPlan& plan, unsigned role) {
    return {
        .role = role,
        .authority_identity = plan.authority_identity,
        .selection_identity = id(40),
        .service_identity = plan.roles[role].service_identity,
        .source_identity = id(41),
        .build_identity = id(42),
        .roster_identity = id(43),
        .capture_source_identity = plan.capture_source_identity,
        .capture_build_identity = plan.capture_build_identity,
        .capture_launcher_identity = plan.capture_launcher_identity,
        .model_preimage_identity = id(44),
        .query_store_preimage_identity = id(45),
        .scalar_capture_manifest_identity = identity_registry::unhex(
            "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b"),
        .owner_port = 32100,
        .multiplication_batch = 4096,
    };
}

struct Pipes {
    std::array<std::array<int, 2>, 3> values{};
    Pipes() {
        for (auto& pipe : values)
            assert(::pipe2(pipe.data(), O_CLOEXEC) == 0);
    }
    Pipes(const Pipes&) = delete;
    ~Pipes() {
        for (const auto& pipe : values)
            for (const int fd : pipe)
                if (fd >= 0) ::close(fd);
    }
    void close_writes() {
        for (auto& pipe : values) {
            assert(::close(pipe[1]) == 0);
            pipe[1] = -1;
        }
    }
};

std::array<InheritedCaptureEndpointAuthority, 3> endpoints(
        const PublicParentRoleForkPlan& plan, const Pipes& pipes) {
    const int offset = plan.round == 1 ? 0 : 5;
    return {
        InheritedCaptureEndpointAuthority::test_only_mint(
            PublicInheritedCaptureEndpoint{
                .kind = InheritedCaptureKind::Projection,
                .role = 0,
                .round = plan.round,
                .fixed_fd = 20 + offset,
                .authority_identity = id(50),
                .capture_plan_identity = plan.capture_plan_identity,
            }, pipes.values[0][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            PublicInheritedCaptureEndpoint{
                .kind = InheritedCaptureKind::Dispatcher,
                .role = 0,
                .round = plan.round,
                .fixed_fd = 22 + offset,
                .authority_identity = id(51),
                .capture_plan_identity = plan.capture_plan_identity,
            }, pipes.values[1][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            PublicInheritedCaptureEndpoint{
                .kind = InheritedCaptureKind::CorruptServer,
                .role = 1,
                .round = plan.round,
                .fixed_fd = 23 + offset,
                .authority_identity = id(52),
                .capture_plan_identity = plan.capture_plan_identity,
            }, pipes.values[2][1]),
    };
}

ParentRoleForkPlanAuthority authority(
        const PublicParentRoleForkPlan& plan, const Pipes& pipes) {
    return ParentRoleForkPlanAuthority::test_only_mint(
        plan, endpoints(plan, pipes));
}

template<class Callable>
void refuses(Callable&& callable) {
    bool did_refuse = false;
    try {
        callable();
    } catch (const identity_registry::Refused&) {
        did_refuse = true;
    }
    assert(did_refuse);
}

bool descriptor_open(int fd) {
    errno = 0;
    const int result = ::fcntl(fd, F_GETFD);
    return result >= 0 || errno != EBADF;
}

bool inherited_pidfd_open() {
    for (int fd = 0; fd < 1024; ++fd) {
        const std::string path = "/proc/self/fd/" + std::to_string(fd);
        std::array<char, 128> target{};
        const auto length = ::readlink(
            path.c_str(), target.data(), target.size());
        if (length > 0 && std::string_view(
                target.data(), static_cast<std::size_t>(length)).find(
                    "pidfd") != std::string_view::npos)
            return true;
    }
    return false;
}

class CheckingProgram final : public RegisteredRoleChildProgram {
    PublicParentRoleForkPlan plan_;
    bool spoof_completion_eof_{};
    bool require_projection_route_{};
    bool discard_projection_route_{};
    PublicProjectionRoutePlan route_plan_{};
public:
    explicit CheckingProgram(
            PublicParentRoleForkPlan plan,
            bool spoof_completion_eof = false)
        : plan_(std::move(plan)),
          spoof_completion_eof_(spoof_completion_eof) {}

    CheckingProgram(
            PublicParentRoleForkPlan plan,
            PublicProjectionRoutePlan selected_route,
            bool discard_projection_route = false)
        : plan_(std::move(plan)), require_projection_route_(true),
          discard_projection_route_(discard_projection_route),
          route_plan_(std::move(selected_route)) {}

    int run(
            ParentAuthenticatedPartyDeliveryAuthority&& delivered,
            ChildRoleCompletionEndpointAuthority&& completion) override {
        if (inherited_pidfd_open()) return 22;
        const auto expected_role = delivered.public_receipt().role;
        auto dispatched = std::move(delivered).dispatch_role();
        if (dispatched.index() != expected_role) return 23;
        auto role_delivery = std::visit(
            [](auto&& selected) {
                return std::move(selected).take_delivery();
            }, std::move(dispatched));
        bool dispatch_replay_refused = false;
        try { (void)std::move(delivered).dispatch_role(); }
        catch (const identity_registry::Refused&) {
            dispatch_replay_refused = true;
        }
        if (!dispatch_replay_refused) return 24;
        const auto receipt = role_delivery.public_receipt();
        if (receipt.role >= 3 || receipt.round != plan_.round ||
            receipt.parent_pid <= 1 || receipt.child_pid <= 1 ||
            receipt.parent_pid == receipt.child_pid ||
            receipt.capture_plan_identity != plan_.capture_plan_identity ||
            receipt.fork_plan_identity == Digest{} ||
            receipt.offer_identity == Digest{} ||
            receipt.ack_identity == Digest{}) return 10;
        if (receipt.projection_route_parent_peer_alias_closed !=
            require_projection_route_) return 21;

        const int offset = plan_.round == 1 ? 0 : 5;
        const std::array<int, 3> selected{20 + offset, 22 + offset,
                                          23 + offset};
        for (int fd = 20; fd <= 29; ++fd) {
            const bool expected =
                (receipt.role == 0 &&
                 (fd == selected[0] || fd == selected[1])) ||
                (receipt.role == 1 && fd == selected[2]);
            if (descriptor_open(fd) != expected) return 11;
        }
        if (descriptor_open(ROLE0_PROJECTION_ROUTE_FIXED_FD)) return 17;

        if (require_projection_route_) {
            if (receipt.role == 0) {
                auto writer = RegisteredProjectionRouteForkBridge::
                    take_role0_writer(role_delivery);
                if (!descriptor_open(ROLE0_PROJECTION_ROUTE_FIXED_FD) ||
                    writer.test_only_public_writer().role != 0 ||
                    writer.test_only_public_writer().round != plan_.round ||
                    writer.test_only_public_writer().fixed_fd !=
                        ROLE0_PROJECTION_ROUTE_FIXED_FD ||
                    writer.test_only_parent_peer_alias_open())
                    return 18;
                if (discard_projection_route_) {
                    std::move(writer).discard();
                } else {
                    auto delivery =
                        ProjectionDeliveryAuthority::test_only_mint(
                            route_plan_, route_projection());
                    (void)RegisteredProjectionRoute::deliver_after_release(
                        std::move(writer), std::move(delivery));
                }
                if (descriptor_open(ROLE0_PROJECTION_ROUTE_FIXED_FD))
                    return 19;
            } else {
                bool refused = false;
                try {
                    (void)RegisteredProjectionRouteForkBridge::
                        take_role0_writer(role_delivery);
                } catch (const identity_registry::Refused&) {
                    refused = true;
                }
                if (!refused ||
                    descriptor_open(ROLE0_PROJECTION_ROUTE_FIXED_FD))
                    return 20;
            }
        }

        if (receipt.role == 0) {
            if (::write(selected[0], "P", 1) != 1 ||
                ::write(selected[1], "D", 1) != 1) return 12;
        } else if (receipt.role == 1) {
            if (::write(selected[2], "S", 1) != 1) return 13;
        }

        auto driver = CompiledDriverSelection::test_only_mint(
            driver_value(plan_, receipt.role));
        auto proposal_delivery =
            attempt_supervisor::RegisteredProposalBridge::
                authenticated_party_delivery(
                    std::move(role_delivery), driver);
        const auto& public_delivery = proposal_delivery.public_receipt();
        if (public_delivery.role != receipt.role ||
            public_delivery.authority_identity != plan_.authority_identity ||
            public_delivery.supervisor_session != plan_.supervisor_session ||
            public_delivery.party_session !=
                plan_.roles[receipt.role].party_session ||
            public_delivery.service_identity !=
                plan_.roles[receipt.role].service_identity ||
            public_delivery.driver_selection_identity !=
                plan_.roles[receipt.role].driver_selection_identity)
            return 14;
        try {
            (void)attempt_supervisor::RegisteredProposalBridge::
                authenticated_party_delivery(std::move(delivered), driver);
            return 15;
        } catch (const identity_registry::Refused&) {
        }
        const std::array<unsigned char, 1> payload{
            static_cast<unsigned char>(receipt.role)};
        if (spoof_completion_eof_ && receipt.role == 0) {
            ParentRoleForkTestCompletionBridge::
                submit_zero_record_then_hold(
                    std::move(completion), id(90), payload);
            return 0;
        }
        ParentRoleForkTestCompletionBridge::submit(
            std::move(completion), id(90), payload);
        try {
            ParentRoleForkTestCompletionBridge::submit(
                std::move(completion), id(90), payload);
            return 16;
        } catch (const identity_registry::Refused&) {
        }
        return 0;
    }
};

class UnreachableReservedRoundProgram final
        : public RegisteredRoleChildProgram {
public:
    int run(
            ParentAuthenticatedPartyDeliveryAuthority&&,
            ChildRoleCompletionEndpointAuthority&&) override {
        return 99;
    }
};

class GenericPreIdentityProgram final
        : public RegisteredPreIdentityPersistentRoleChildProgram {
    std::array<UnreachableReservedRoundProgram, 2> rounds_;
public:
    RegisteredRoleChildProgram& round_program(unsigned round) override {
        assert(round == 1 || round == 2);
        return rounds_[round - 1];
    }
};

char read_marker(int fd) {
    char result = 0;
    assert(::read(fd, &result, 1) == 1);
    char extra = 0;
    assert(::read(fd, &extra, 1) == 0);
    return result;
}

void valid_three_role_fork() {
    Pipes pipes;
    const auto plan = plan_value();
    auto selected = authority(plan, pipes);
    pipes.close_writes();
    CheckingProgram program(plan);
    auto launched = RegisteredParentRoleFork::launch(
        std::move(selected), program);
    ParentRoleChildren children(std::move(launched));
    const auto& acknowledgements = children.public_acknowledgements();
    for (unsigned role = 0; role < 3; ++role) {
        assert(acknowledgements[role].role == role);
        assert(acknowledgements[role].round == 1);
        assert(acknowledgements[role].child_pid > 1);
        assert(acknowledgements[role].offer_identity != Digest{});
        assert(acknowledgements[role].ack_identity != Digest{});
    }
    assert(acknowledgements[0].child_pid != acknowledgements[1].child_pid);
    assert(acknowledgements[0].child_pid != acknowledgements[2].child_pid);
    assert(acknowledgements[1].child_pid != acknowledgements[2].child_pid);
    for (unsigned role = 0; role < 3; ++role) {
        auto endpoint = children.take_completion_endpoint(role);
        const auto payload = ParentRoleForkTestCompletionBridge::receive(
            std::move(endpoint), id(90), 1);
        assert(payload.size() == 1 && payload[0] == role);
        refuses([&] {
            (void)children.take_completion_endpoint(role);
        });
    }
    const auto completion = children.wait();
    assert(completion.fork_plan_identity != Digest{});
    assert(completion.all_children_exited_zero);
    assert(read_marker(pipes.values[0][0]) == 'P');
    assert(read_marker(pipes.values[1][0]) == 'D');
    assert(read_marker(pipes.values[2][0]) == 'S');
    refuses([&] { (void)children.wait(); });
}

void role_zero_projection_route_is_fork_bound() {
    Pipes pipes;
    const auto plan = plan_value();
    const auto selected_route = route_plan(plan);
    auto route_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    auto parent_route = route_endpoints.take_parent();
    auto writer = route_endpoints.take_role0_writer();
    auto selected = authority(plan, pipes);
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(writer), selected);
    pipes.close_writes();
    CheckingProgram program(plan, selected_route);
    auto children = RegisteredParentRoleFork::launch(
        std::move(selected), program);
    auto bound_parent =
        RegisteredProjectionRouteForkBridge::bind_parent_after_fork(
            std::move(parent_route), children);
    auto retained = RegisteredProjectionRoute::receive_and_retain(
        std::move(bound_parent));
    const auto retained_bytes = retained.test_only_projection();
    const auto expected = route_projection();
    assert(retained_bytes.size() == expected.size() &&
           std::equal(retained_bytes.begin(), retained_bytes.end(),
                      expected.begin()));
    for (unsigned role = 0; role < 3; ++role) {
        auto endpoint = children.take_completion_endpoint(role);
        const auto payload = ParentRoleForkTestCompletionBridge::receive(
            std::move(endpoint), id(90), 1);
        assert(payload.size() == 1 && payload[0] == role);
    }
    assert(children.wait().all_children_exited_zero);
    assert(read_marker(pipes.values[0][0]) == 'P');
    assert(read_marker(pipes.values[1][0]) == 'D');
    assert(read_marker(pipes.values[2][0]) == 'S');
}

void projection_route_writer_replay_burns_fork_plan() {
    Pipes pipes;
    const auto plan = plan_value();
    const auto selected_route = route_plan(plan);
    auto first = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    auto second = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    auto first_parent = first.take_parent();
    auto first_writer = first.take_role0_writer();
    auto second_parent = second.take_parent();
    auto second_writer = second.take_role0_writer();
    auto selected = authority(plan, pipes);
    const auto before = selected.identity();
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(first_writer), selected);
    assert(selected.identity() != before);
    refuses([&] {
        RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
            std::move(second_writer), selected);
    });
    CheckingProgram program(plan);
    refuses([&] {
        (void)RegisteredParentRoleFork::launch(
            std::move(selected), program);
    });
    std::move(first_parent).discard();
    std::move(second_parent).discard();
}

void stale_projection_route_round_burns_fork_plan() {
    Pipes pipes;
    const auto plan = plan_value(1);
    auto stale = route_plan(plan);
    stale.round = 2;
    auto route = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(stale));
    auto parent = route.take_parent();
    auto writer = route.take_role0_writer();
    auto selected = authority(plan, pipes);
    refuses([&] {
        RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
            std::move(writer), selected);
    });
    CheckingProgram program(plan);
    refuses([&] {
        (void)RegisteredParentRoleFork::launch(
            std::move(selected), program);
    });
    std::move(parent).discard();
}

void baseline_candidate_route_substitution_refuses() {
    Pipes pipes;
    const auto plan = plan_value(1);
    auto substituted = route_plan(plan);
    substituted.classification =
        CaptureClassification::ExplicitOwnerPublicEffectsBaseline;
    // The hostile test mint keeps the same round, lineage and claimed capture
    // plan identity.  The fork must still reject the cross-arm authority.
    auto route = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(substituted));
    auto parent = route.take_parent();
    auto writer = route.take_role0_writer();
    auto selected = authority(plan, pipes);
    refuses([&] {
        RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
            std::move(writer), selected);
    });
    CheckingProgram program(plan);
    refuses([&] {
        (void)RegisteredParentRoleFork::launch(
            std::move(selected), program);
    });
    std::move(parent).discard();
}

void wrong_parent_route_mixup_poisoned() {
    Pipes pipes;
    const auto plan = plan_value();
    const auto selected_route = route_plan(plan);
    auto selected_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    auto wrong_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    auto selected_parent = selected_endpoints.take_parent();
    auto selected_writer = selected_endpoints.take_role0_writer();
    auto wrong_parent = wrong_endpoints.take_parent();
    auto wrong_writer = wrong_endpoints.take_role0_writer();
    std::move(wrong_writer).discard();
    auto selected = authority(plan, pipes);
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(selected_writer), selected);
    pipes.close_writes();
    CheckingProgram program(plan, selected_route);
    auto children = RegisteredParentRoleFork::launch(
        std::move(selected), program);
    refuses([&] {
        (void)RegisteredProjectionRouteForkBridge::bind_parent_after_fork(
            std::move(wrong_parent), children);
    });
    refuses([&] {
        (void)RegisteredProjectionRouteForkBridge::bind_parent_after_fork(
            std::move(selected_parent), children);
    });
}

void missing_parent_route_binding_refuses_join() {
    Pipes pipes;
    const auto plan = plan_value();
    const auto selected_route = route_plan(plan);
    auto route = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    auto parent = route.take_parent();
    auto writer = route.take_role0_writer();
    auto selected = authority(plan, pipes);
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(writer), selected);
    pipes.close_writes();
    CheckingProgram program(plan, selected_route, true);
    auto children = RegisteredParentRoleFork::launch(
        std::move(selected), program);
    std::move(parent).discard();
    for (unsigned role = 0; role < 3; ++role) {
        auto endpoint = children.take_completion_endpoint(role);
        const auto payload = ParentRoleForkTestCompletionBridge::receive(
            std::move(endpoint), id(90), 1);
        assert(payload.size() == 1 && payload[0] == role);
    }
    refuses([&] { (void)children.wait(); });
}

void inherited_parent_route_alias_fault_refuses(
        ParentRoleForkTestFault fault) {
    Pipes pipes;
    const auto plan = plan_value();
    const auto selected_route = route_plan(plan);
    auto route = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(selected_route));
    auto parent = route.take_parent();
    auto writer = route.take_role0_writer();
    auto selected = authority(plan, pipes);
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(writer), selected);
    pipes.close_writes();
    CheckingProgram program(plan, selected_route);
    refuses([&] {
        (void)RegisteredParentRoleFork::test_only_launch(
            std::move(selected), program, fault);
    });
    std::move(parent).discard();
}

void completion_replay_poisons_parent_join() {
    Pipes pipes;
    const auto plan = plan_value();
    auto selected = authority(plan, pipes);
    pipes.close_writes();
    CheckingProgram program(plan);
    auto children = RegisteredParentRoleFork::launch(
        std::move(selected), program);
    auto first_endpoint = children.take_completion_endpoint(0);
    auto first_payload = ParentRoleForkTestCompletionBridge::receive(
        std::move(first_endpoint), id(90), 1);
    assert(first_payload.size() == 1 && first_payload[0] == 0);
    for (unsigned role = 1; role < 3; ++role) {
        auto endpoint = children.take_completion_endpoint(role);
        const auto payload = ParentRoleForkTestCompletionBridge::receive(
            std::move(endpoint), id(90), 1);
        assert(payload.size() == 1 && payload[0] == role);
    }
    refuses([&] {
        (void)ParentRoleForkTestCompletionBridge::receive(
            std::move(first_endpoint), id(90), 1);
    });
    refuses([&] { (void)children.wait(); });
}

void zero_length_record_is_not_completion_eof() {
    Pipes pipes;
    const auto plan = plan_value();
    auto selected = authority(plan, pipes);
    pipes.close_writes();
    CheckingProgram program(plan, true);
    auto children = RegisteredParentRoleFork::launch(
        std::move(selected), program);
    auto endpoint = children.take_completion_endpoint(0);
    refuses([&] {
        (void)ParentRoleForkTestCompletionBridge::receive(
            std::move(endpoint), id(90), 1);
    });
    refuses([&] { (void)children.wait(); });
}

void wrong_role_refuses_and_burns() {
    Pipes pipes;
    const auto plan = plan_value();
    auto selected = authority(plan, pipes);
    pipes.close_writes();
    CheckingProgram program(plan);
    refuses([&] {
        (void)RegisteredParentRoleFork::test_only_launch(
            std::move(selected), program,
            ParentRoleForkTestFault::SwapRoleZeroAndOneOffers);
    });
    refuses([&] {
        (void)RegisteredParentRoleFork::launch(
            std::move(selected), program);
    });
}

void fd_mixup_refuses_and_burns() {
    Pipes pipes;
    const auto plan = plan_value(2);
    auto selected = authority(plan, pipes);
    pipes.close_writes();
    CheckingProgram program(plan);
    refuses([&] {
        (void)RegisteredParentRoleFork::test_only_launch(
            std::move(selected), program,
            ParentRoleForkTestFault::SwapProjectionAndCorruptServerSources);
    });
    refuses([&] {
        (void)RegisteredParentRoleFork::launch(
            std::move(selected), program);
    });
}

void parent_self_ack_refuses() {
    Pipes pipes;
    const auto plan = plan_value();
    auto selected = authority(plan, pipes);
    pipes.close_writes();
    CheckingProgram program(plan);
    refuses([&] {
        (void)RegisteredParentRoleFork::test_only_launch(
            std::move(selected), program,
            ParentRoleForkTestFault::ParentSelfAcknowledgement);
    });
}

void malformed_endpoint_role_refuses() {
    Pipes pipes;
    const auto plan = plan_value();
    auto selected_endpoints = endpoints(plan, pipes);
    auto wrong = selected_endpoints[2].test_only_public_receipt();
    wrong.role = 2;
    std::array<InheritedCaptureEndpointAuthority, 3> malformed{
        std::move(selected_endpoints[0]),
        std::move(selected_endpoints[1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            wrong, pipes.values[2][1]),
    };
    refuses([&] {
        (void)ParentRoleForkPlanAuthority::test_only_mint(
            plan, std::move(malformed));
    });
    refuses([&] {
        (void)ParentRoleForkPlanAuthority::test_only_mint(
            plan, std::move(malformed));
    });
}

void source_status_remains_unconfigured() {
    const auto status = parent_role_fork_source_status();
    assert(status.exact_three_internal_roles);
    assert(status.inherited_seqpacket_capability_channels);
    assert(status.kernel_sender_credentials_each_packet);
    assert(status.parent_self_ack_refused);
    assert(status.fixed_capture_fd_role_partition);
    assert(status.role0_projection_route_fixed_fd30);
    assert(status.projection_route_exact_fork_binding);
    assert(status.projection_route_parent_alias_closed_before_offer);
    assert(status.parent_supervisor_proposal_approval_transport);
    assert(status.pidfd_exact_process_identity);
    assert(status.pidfd_only_child_signaling);
    assert(status.unavailable_wait_status_refused);
    assert(status.persistent_same_pid_two_round_exit_evidence);
    assert(!status.p1_two_round_observer_v5_capsule_residual);
    assert(status.pre_identity_process_reservation);
    assert(status.preidentity_child_descriptor_allowlist);
    assert(status.process_first_topology_reservation_permit);
    assert(!status.post_reservation_trial_activation);
    assert(status.process_settled_abort_noalloc);
    assert(!status.typed_complete_activation_abort);
    assert(!status.selected_plan_factory_integration);
    assert(!status.selected_gate_callsite_integration);
    assert(!status.registered_driver_configured);
    assert(!status.launch_authorized);
}

void pre_identity_reservation_aborts_with_complete_evidence() {
    GenericPreIdentityProgram program;
    auto reserved = RegisteredParentPersistentRoleFork::reserve(program);
    RegisteredPersistentRoleProcessReservation moved(std::move(reserved));
    auto evidence = RegisteredParentPersistentRoleFork::abort(
        std::move(moved));
    assert(evidence.all_children_settled_value());
    assert(!evidence.pidfd_signal_used_value());
    const auto& pids = evidence.child_pids_value();
    const auto& exits = evidence.exit_codes_value();
    const auto& signals = evidence.term_signals_value();
    for (unsigned role = 0; role < 3; ++role) {
        assert(pids[role] > 1);
        assert(exits[role] == 121);
        assert(signals[role] == 0);
    }
    assert(pids[0] != pids[1] && pids[0] != pids[2] &&
           pids[1] != pids[2]);

    detail::PersistentRoleReservationAbortEvidence retained(
        std::move(evidence));
    assert(!evidence.all_children_settled_value());
    assert(retained.all_children_settled_value());
    refuses([&] {
        (void)RegisteredParentPersistentRoleFork::abort(
            std::move(reserved));
    });
}

void topology_permit_is_process_first_and_one_shot() {
    GenericPreIdentityProgram program;
    auto reserved = RegisteredParentPersistentRoleFork::reserve(program);
    auto permit = reserved.issue_topology_reservation_permit();
    RegisteredTopologyReservationPermit moved(std::move(permit));
    refuses([&] {
        (void)reserved.issue_topology_reservation_permit();
    });
    auto evidence = RegisteredParentPersistentRoleFork::abort(
        std::move(reserved));
    assert(evidence.all_children_settled_value());
    assert(!evidence.pidfd_signal_used_value());
    for (unsigned role = 0; role < 3; ++role) {
        assert(evidence.exit_codes_value()[role] == 121);
        assert(evidence.term_signals_value()[role] == 0);
    }
    (void)moved;
}

void pre_identity_children_close_unrelated_inherited_descriptors() {
    std::array<std::array<int, 2>, 8> sentinels{};
    for (auto& sentinel : sentinels)
        assert(::pipe2(sentinel.data(), O_CLOEXEC) == 0);
    const int unrelated = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(unrelated >= 0);

    GenericPreIdentityProgram program;
    auto reserved = RegisteredParentPersistentRoleFork::reserve(program);
    auto evidence = RegisteredParentPersistentRoleFork::abort(
        std::move(reserved));
    assert(evidence.all_children_settled_value());
    assert(!evidence.pidfd_signal_used_value());
    // Exit 121 is emitted only after the child has enumerated /proc/self/fd
    // and proved that only stdio plus its two reserved channels remain.
    for (unsigned role = 0; role < 3; ++role) {
        assert(evidence.exit_codes_value()[role] == 121);
        assert(evidence.term_signals_value()[role] == 0);
    }

    assert(::close(unrelated) == 0);
    for (auto& sentinel : sentinels) {
        assert(::close(sentinel[0]) == 0);
        assert(::close(sentinel[1]) == 0);
    }
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view selected = argv[1];
    if (selected == "valid") valid_three_role_fork();
    else if (selected == "projection-route")
        role_zero_projection_route_is_fork_bound();
    else if (selected == "projection-route-replay")
        projection_route_writer_replay_burns_fork_plan();
    else if (selected == "projection-route-stale-round")
        stale_projection_route_round_burns_fork_plan();
    else if (selected == "projection-route-arm-substitution")
        baseline_candidate_route_substitution_refuses();
    else if (selected == "projection-route-mixup")
        wrong_parent_route_mixup_poisoned();
    else if (selected == "projection-route-missing-parent")
        missing_parent_route_binding_refuses_join();
    else if (selected == "projection-route-wrong-peer-fingerprint")
        inherited_parent_route_alias_fault_refuses(
            ParentRoleForkTestFault::
                WrongProjectionRouteParentPeerFingerprintRole0);
    else if (selected == "projection-route-peer-already-closed")
        inherited_parent_route_alias_fault_refuses(
            ParentRoleForkTestFault::ClosedProjectionRouteParentPeerRole1);
    else if (selected == "projection-route-peer-fd-reused")
        inherited_parent_route_alias_fault_refuses(
            ParentRoleForkTestFault::ReusedProjectionRouteParentPeerFdRole2);
    else if (selected == "partial-fork")
        inherited_parent_route_alias_fault_refuses(
            ParentRoleForkTestFault::FailBeforeRole2Fork);
    else if (selected == "partial-pidfd-open")
        inherited_parent_route_alias_fault_refuses(
            ParentRoleForkTestFault::FailPidfdOpenRole1);
    else if (selected == "completion-replay")
        completion_replay_poisons_parent_join();
    else if (selected == "zero-record-eof")
        zero_length_record_is_not_completion_eof();
    else if (selected == "wrong-role") wrong_role_refuses_and_burns();
    else if (selected == "fd-mixup") fd_mixup_refuses_and_burns();
    else if (selected == "parent-self-ack") parent_self_ack_refuses();
    else if (selected == "malformed-endpoint") malformed_endpoint_role_refuses();
    else if (selected == "status") source_status_remains_unconfigured();
    else if (selected == "pre-identity-reservation-abort")
        pre_identity_reservation_aborts_with_complete_evidence();
    else if (selected == "process-first-topology-permit")
        topology_permit_is_process_first_and_one_shot();
    else if (selected == "pre-identity-child-fd-allowlist")
        pre_identity_children_close_unrelated_inherited_descriptors();
    else return 2;
    return 0;
}
