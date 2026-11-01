#define main embedded_party_completion_transport_main
#include "registered_party_completion_transport_test.cpp"
#undef main

#include "../registered_selected_parent_orchestrator.hpp"
#include "../registered_trial_attempt_history.hpp"
#include "../../private_batch_trial/privacy_capture_producer_runtime.hpp"

#include <csignal>
#include <optional>
#include <sys/wait.h>
#include <unistd.h>

using namespace kpi::mpc::financial::registered_driver::projection_route;

namespace {

template<class Callable> void history_refuses(Callable&& callable) {
    bool rejected = false;
    try { callable(); }
    catch (const attempt_history::AttemptHistoryRefused&) {
        rejected = true;
    }
    assert(rejected);
}

std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection(
        unsigned seed = 9) {
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = std::byte((index * 17 + seed) & 0xffU);
    return result;
}

Digest projection_identity(
        const std::array<std::byte, PUBLIC_PROJECTION_BYTES>& value) {
    return identity_registry::digest(std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

PublicProjectionRoutePlan route_plan(
        const PublicParentRoleForkPlan& selected) {
    return {
        .classification = selected.classification,
        .round = selected.round,
        .computing_role = 0,
        .trial = selected.trial,
        .attempt = selected.attempt,
        .cohort = selected.cohort,
        .financial_run = selected.financial_run,
        .capture_plan_identity = selected.capture_plan_identity,
        .producer_process_authority = id(0xa01),
        .producer_exit_authority = id(0xa02),
        .dispatcher_process_authority = id(0xa03),
        .dispatcher_exit_authority = id(0xa04),
    };
}

enum class RoundFault {
    None,
    WrongProjection,
    WrongSelection,
    WrongBarrier,
    WrongReleaseReady,
    MissingReleaseReady,
    PartialCompletion,
    DirtyChildExit,
    SignaledChildExit,
};

PartyReleaseReadyAuthority ready_from_party(
        const PublicPartyDriverCompletion& value) {
    return PartyReleaseReadyAuthority::test_only_mint(
        PublicAuthorizedAttempt{
            .role = value.role,
            .round = value.round,
            .classification = value.classification,
            .capture_trial_id = value.capture_trial_id,
            .authority_identity = value.authority_identity,
            .driver_selection_identity = value.driver_selection_identity,
            .selection_identity = value.selection_identity,
            .run = value.run,
            .trial = value.trial,
            .attempt = value.attempt,
            .cohort = value.cohort,
            .accepted_head = value.accepted_head,
            .postlock_accepted_head = value.postlock_accepted_head,
            .attempt_identity = value.attempt_identity,
            .proposal_identity = value.proposal_identity,
            .durable_lock = value.durable_lock,
            .owner_contracts = value.owner_contracts,
            .capture_plan_identity = value.capture_plan_identity,
            .capture_source_identity = value.capture_source_identity,
            .capture_build_identity = value.capture_build_identity,
            .capture_launcher_identity = value.capture_launcher_identity,
            .authorization_identity = value.authorization_identity,
        },
        PublicVerifiedEgress{
            .binding_identity = value.egress_binding_identity,
            .effects_identity = value.effects_identity,
            .core_identity = value.core_identity,
            .proof_identity = value.proof_identity,
            .projection_identity = value.projection_identity,
        });
}

class RoundProgram final : public RegisteredRoleChildProgram {
    PublicParentRoleForkPlan selected_;
    PublicProjectionRoutePlan route_;
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> projection_;
    RoundFault fault_;
public:
    RoundProgram(
            PublicParentRoleForkPlan selected,
            PublicProjectionRoutePlan route,
            std::array<std::byte, PUBLIC_PROJECTION_BYTES> body,
            RoundFault fault)
        : selected_(std::move(selected)), route_(std::move(route)),
          projection_(std::move(body)), fault_(fault) {}

    int run(
            ParentAuthenticatedPartyDeliveryAuthority&& delivered,
            ChildRoleCompletionEndpointAuthority&& endpoint) override {
        const unsigned role = delivered.public_receipt().role;
        auto value = party(selected_, role);
        if (selected_.round == 2) {
            value.accepted_head = id(0xc21);
            value.postlock_accepted_head = value.accepted_head;
            value.owner_contracts = {id(0xc60), id(0xc61), id(0xc62)};
            value.effects_identity = id(0xc80);
            value.core_identity = id(0xc81);
            value.proof_identity = id(0xc82);
        }
        value.projection_identity = projection_identity(projection_);
        if (fault_ == RoundFault::MissingReleaseReady && role == 2)
            return 0;
        if (fault_ == RoundFault::WrongReleaseReady && role == 1)
            value.effects_identity = id(0xbadd);
        auto release_authorization =
            RegisteredFullCohortReleaseBarrier::arrive_and_wait(
                ready_from_party(value), endpoint);
        release_authorization.test_only_bind_completion(value);
        if (role == 0) {
            auto writer = delivered.take_projection_route_writer();
            auto body = ProjectionDeliveryAuthority::test_only_mint(
                route_, projection_);
            (void)RegisteredProjectionRoute::deliver_after_release(
                std::move(writer), std::move(body));
        }
        if (fault_ == RoundFault::PartialCompletion && role == 2)
            return 0;
        if (fault_ == RoundFault::WrongProjection && role == 1)
            value.projection_identity = id(0xbad);
        if (fault_ == RoundFault::WrongSelection && role == 1)
            value.selection_identity = id(0xbad);
        if (fault_ == RoundFault::WrongBarrier && role == 1)
            value.full_cohort_barrier_identity = id(0xbabe);
        auto completion = RegisteredPartyCompletionTransportTestBridge::
            mint_party(value);
        if (selected_.classification ==
                CaptureClassification::ExplicitOwnerPublicEffectsBaseline) {
            auto baseline = PartyBaselineOwnerEffectsAuthority::test_only_mint(
                effects(value));
            RegisteredPartyCompletionTransport::submit_baseline(
                std::move(completion), std::move(baseline),
                std::move(endpoint));
        } else {
            RegisteredPartyCompletionTransport::submit_hidden(
                std::move(completion), std::move(endpoint));
        }
        if (fault_ == RoundFault::DirtyChildExit && role == 2)
            return 7;
        if (fault_ == RoundFault::SignaledChildExit && role == 2) {
            (void)::raise(SIGABRT);
            return 8;
        }
        return 0;
    }
};

PublicParentRoleForkPlan round_plan(
        CaptureClassification classification, unsigned round) {
    auto result = plan(classification);
    if (round == 1) return result;
    assert(round == 2);
    result.round = 2;
    result.financial_run = id(0xd02);
    result.attempt = id(0xd03);
    result.cohort = id(0xd04);
    result.authority_identity = id(0xd05);
    result.capture_plan_identity = id(0xd07);
    for (unsigned role = 0; role < 3; ++role) {
        result.roles[role].party_session = id(0xd20 + role);
        result.roles[role].driver_selection_identity = id(0xd40 + role);
    }
    return result;
}

std::array<InheritedCaptureEndpointAuthority, 3> round_endpoints(
        const PublicParentRoleForkPlan& selected, const Pipes& pipes) {
    const int offset = selected.round == 1 ? 0 : 5;
    return {
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::Projection, .role = 0,
             .round = selected.round, .fixed_fd = 20 + offset,
             .authority_identity = id(0xe01 + 16 * selected.round),
             .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[0][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::Dispatcher, .role = 0,
             .round = selected.round, .fixed_fd = 22 + offset,
             .authority_identity = id(0xe02 + 16 * selected.round),
             .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[1][1]),
        InheritedCaptureEndpointAuthority::test_only_mint(
            {.kind = InheritedCaptureKind::CorruptServer, .role = 1,
             .round = selected.round, .fixed_fd = 23 + offset,
             .authority_identity = id(0xe03 + 16 * selected.round),
             .capture_plan_identity = selected.capture_plan_identity},
            pipes.value[2][1]),
    };
}

class PersistentProgram final : public RegisteredPersistentRoleChildProgram {
    RoundProgram round1_, round2_;
public:
    PersistentProgram(
            PublicParentRoleForkPlan first,
            PublicParentRoleForkPlan second,
            PublicProjectionRoutePlan route1,
            PublicProjectionRoutePlan route2,
            std::array<std::byte, PUBLIC_PROJECTION_BYTES> body1,
            std::array<std::byte, PUBLIC_PROJECTION_BYTES> body2,
            RoundFault round2_fault = RoundFault::None)
        : round1_(std::move(first), std::move(route1), std::move(body1),
                  RoundFault::None),
          round2_(std::move(second), std::move(route2), std::move(body2),
                  round2_fault) {}

    RegisteredRoleChildProgram& round_program(unsigned round) override {
        if (round == 1) return round1_;
        assert(round == 2);
        return round2_;
    }
};

enum class PersistentFault {
    None,
    CrossTrial,
    ChangedRoster,
    SwapRounds,
    WrongRouteLineage,
    ActivateRound2Early,
    DirtyFinalChildExit,
    SignaledFinalChildExit,
    ExternallyReapedBeforeJoin,
    StalePidSentinelCleanup,
    PoisonThenDestroy,
    ExportProducerRoutes,
    AttachExitHistory,
};

struct PreparedPersistentTrial final {
    RegisteredParentPendingRoundCompletionAuthority round1;
    RegisteredParentPendingRoundCompletionAuthority round2;
    RegisteredPersistentRoleSession session;

    PreparedPersistentTrial(
            RegisteredParentPendingRoundCompletionAuthority&& first,
            RegisteredParentPendingRoundCompletionAuthority&& second,
            RegisteredPersistentRoleSession&& selected)
        : round1(std::move(first)), round2(std::move(second)),
          session(std::move(selected)) {}
};

PreparedPersistentTrial prepare_persistent_trial() {
    Pipes first_pipes, second_pipes;
    const auto first = round_plan(CaptureClassification::HiddenCandidate, 1);
    const auto second = round_plan(CaptureClassification::HiddenCandidate, 2);
    const auto first_route = route_plan(first);
    const auto second_route = route_plan(second);
    const auto first_body = projection(0x61);
    const auto second_body = projection(0x72);
    auto first_route_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(first_route));
    auto second_route_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(second_route));
    auto first_parent = first_route_endpoints.take_parent();
    auto second_parent = second_route_endpoints.take_parent();
    auto first_writer = first_route_endpoints.take_role0_writer();
    auto second_writer = second_route_endpoints.take_role0_writer();
    auto first_fork = ParentRoleForkPlanAuthority::test_only_mint(
        first, round_endpoints(first, first_pipes));
    auto second_fork = ParentRoleForkPlanAuthority::test_only_mint(
        second, round_endpoints(second, second_pipes));
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(first_writer), first_fork);
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(second_writer), second_fork);
    first_pipes.close_writes();
    second_pipes.close_writes();
    PersistentProgram program(
        first, second, first_route, second_route, first_body, second_body);
    auto session = RegisteredParentPersistentRoleFork::launch(
        std::move(first_fork), std::move(second_fork), program);

    auto& first_children = RegisteredParentPersistentRoleFork::round1(
        session);
    auto first_bound = RegisteredProjectionRouteForkBridge::
        bind_parent_after_fork(std::move(first_parent), first_children);
    RegisteredFullCohortReleaseBarrier::authorize(first_children);
    auto first_retained = RegisteredProjectionRoute::receive_and_retain(
        std::move(first_bound));
    auto first_role0 = RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(0));
    auto first_role1 = RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(1));
    auto first_role2 = RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(2));
    auto pending1 = RegisteredParentRoundCompletionBridge::defer(
        std::move(first_retained), std::move(first_role0),
        std::move(first_role1), std::move(first_role2), first_children);

    auto& second_children =
        RegisteredParentPersistentRoleFork::activate_round2(session);
    auto second_bound = RegisteredProjectionRouteForkBridge::
        bind_parent_after_fork(std::move(second_parent), second_children);
    RegisteredFullCohortReleaseBarrier::authorize(second_children);
    auto second_retained = RegisteredProjectionRoute::receive_and_retain(
        std::move(second_bound));
    auto second_role0 = RegisteredPartyCompletionTransport::receive(
        second_children.take_completion_endpoint(0));
    auto second_role1 = RegisteredPartyCompletionTransport::receive(
        second_children.take_completion_endpoint(1));
    auto second_role2 = RegisteredPartyCompletionTransport::receive(
        second_children.take_completion_endpoint(2));
    auto pending2 = RegisteredParentRoundCompletionBridge::defer(
        std::move(second_retained), std::move(second_role0),
        std::move(second_role1), std::move(second_role2), second_children);
    return PreparedPersistentTrial(
        std::move(pending1), std::move(pending2), std::move(session));
}

void persistent_stale_round1_burns_fresh_round2() {
    const auto first = round_plan(
        CaptureClassification::HiddenCandidate, 1);
    const auto second = round_plan(
        CaptureClassification::HiddenCandidate, 2);
    const auto first_route = route_plan(first);
    const auto second_route = route_plan(second);
    PersistentProgram program(
        first, second, first_route, second_route,
        projection(0x41), projection(0x42));

    Pipes stale_first_pipes, sacrificial_second_pipes;
    auto stale_first = ParentRoleForkPlanAuthority::test_only_mint(
        first, round_endpoints(first, stale_first_pipes));
    auto sacrificial_second = ParentRoleForkPlanAuthority::test_only_mint(
        second, round_endpoints(second, sacrificial_second_pipes));
    refuses([&] {
        (void)RegisteredParentPersistentRoleFork::launch(
            std::move(stale_first), std::move(sacrificial_second), program);
    });

    Pipes fresh_second_pipes;
    auto fresh_second = ParentRoleForkPlanAuthority::test_only_mint(
        second, round_endpoints(second, fresh_second_pipes));
    refuses([&] {
        (void)RegisteredParentPersistentRoleFork::launch(
            std::move(stale_first), std::move(fresh_second), program);
    });

    // Even though the first input was stale, the failed two-input join must
    // have burned the second.  A route writer cannot be attached afterward.
    auto route_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(second_route));
    auto writer = route_endpoints.take_role0_writer();
    refuses([&] {
        RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
            std::move(writer), fresh_second);
    });
}

void execute_cross_session_pending_mix() {
    auto first = prepare_persistent_trial();
    auto second = prepare_persistent_trial();
    refuses([&] {
        (void)RegisteredParentTrialCompletionBridge::join(
            std::move(first.round1), std::move(second.round2),
            first.session);
    });
}

void execute_persistent(
        CaptureClassification classification,
        PersistentFault fault = PersistentFault::None) {
    Pipes first_pipes, second_pipes;
    const auto first = round_plan(classification, 1);
    auto second = round_plan(classification, 2);
    if (fault == PersistentFault::CrossTrial) {
        second.capture_trial_id =
            "22222222-2222-4222-8222-222222222222";
        second.trial = RegisteredCapturePlanRosterBridge::trial_identity(
            second.capture_trial_id);
    }
    if (fault == PersistentFault::ChangedRoster)
        second.fresh_owner_issuance_identity = id(0xbad);
    const auto first_route = route_plan(first);
    auto second_route = route_plan(second);
    if (fault == PersistentFault::WrongRouteLineage)
        second_route.capture_plan_identity = id(0xbad);
    const auto first_body = projection(0x31);
    const auto second_body = projection(0x52);
    auto first_route_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(first_route));
    auto second_route_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(second_route));
    auto first_parent = first_route_endpoints.take_parent();
    auto second_parent = second_route_endpoints.take_parent();
    auto first_writer = first_route_endpoints.take_role0_writer();
    auto second_writer = second_route_endpoints.take_role0_writer();
    auto first_fork = ParentRoleForkPlanAuthority::test_only_mint(
        first, round_endpoints(first, first_pipes));
    auto second_fork = ParentRoleForkPlanAuthority::test_only_mint(
        second, round_endpoints(second, second_pipes));
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(first_writer), first_fork);
    if (fault == PersistentFault::WrongRouteLineage) {
        refuses([&] {
            RegisteredProjectionRouteForkBridge::
                consume_writer_for_parent_fork(
                    std::move(second_writer), second_fork);
        });
        return;
    }
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(second_writer), second_fork);
    first_pipes.close_writes();
    second_pipes.close_writes();
    PersistentProgram program(
        first, second, first_route, second_route, first_body, second_body,
        fault == PersistentFault::DirtyFinalChildExit
            ? RoundFault::DirtyChildExit
            : fault == PersistentFault::SignaledFinalChildExit
                ? RoundFault::SignaledChildExit : RoundFault::None);
    if (fault == PersistentFault::CrossTrial ||
        fault == PersistentFault::ChangedRoster ||
        fault == PersistentFault::SwapRounds) {
        refuses([&] {
            (void)RegisteredParentPersistentRoleFork::launch(
                fault == PersistentFault::SwapRounds
                    ? std::move(second_fork) : std::move(first_fork),
                fault == PersistentFault::SwapRounds
                    ? std::move(first_fork) : std::move(second_fork),
                program);
        });
        return;
    }
    auto session = RegisteredParentPersistentRoleFork::launch(
        std::move(first_fork), std::move(second_fork), program);
    if (fault == PersistentFault::StalePidSentinelCleanup) {
        auto& exact_children =
            RegisteredParentPersistentRoleFork::round1(session);
        std::array<pid_t, 3> exact_child_pids{};
        for (unsigned role = 0; role < exact_child_pids.size(); ++role)
            exact_child_pids[role] = static_cast<pid_t>(
                exact_children.public_acknowledgements()[role].child_pid);
        int sentinel_pipe[2]{-1, -1};
        assert(::pipe2(sentinel_pipe, O_CLOEXEC) == 0);
        const pid_t sentinel = ::fork();
        assert(sentinel >= 0);
        if (sentinel == 0) {
            (void)::close(sentinel_pipe[1]);
            char byte = 0;
            ssize_t count;
            do { count = ::read(sentinel_pipe[0], &byte, 1); }
            while (count < 0 && errno == EINTR);
            ::_exit(count == 0 ? 0 : 90);
        }
        (void)::close(sentinel_pipe[0]);
        ParentRoleForkTestProcessBridge::replace_raw_pid_metadata(
            session, 0, sentinel);
        {
            RegisteredPersistentRoleSession moved(std::move(session));
            ParentRoleForkTestProcessBridge::terminate_and_settle(moved);
            ParentRoleForkTestProcessBridge::terminate_and_settle(moved);
        }
        int status = 0;
        for (const auto exact_pid : exact_child_pids) {
            errno = 0;
            assert(::waitpid(exact_pid, &status, WNOHANG) == -1);
            assert(errno == ECHILD);
        }
        assert(::waitpid(sentinel, &status, WNOHANG) == 0);
        assert(::close(sentinel_pipe[1]) == 0);
        assert(::waitpid(sentinel, &status, 0) == sentinel);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        return;
    }
    if (fault == PersistentFault::PoisonThenDestroy) {
        auto& children = RegisteredParentPersistentRoleFork::round1(session);
        ParentRoleForkTestProcessBridge::poison_role_channels(children);
        RegisteredPersistentRoleSession moved(std::move(session));
        return;
    }
    if (fault == PersistentFault::ActivateRound2Early) {
        refuses([&] {
            (void)RegisteredParentPersistentRoleFork::activate_round2(
                session);
        });
        return;
    }

    auto& first_children = RegisteredParentPersistentRoleFork::round1(
        session);
    std::array<std::int64_t, 3> child_pids{};
    for (unsigned role = 0; role < child_pids.size(); ++role)
        child_pids[role] =
            first_children.public_acknowledgements()[role].child_pid;
    auto first_bound = RegisteredProjectionRouteForkBridge::
        bind_parent_after_fork(std::move(first_parent), first_children);
    RegisteredFullCohortReleaseBarrier::authorize(first_children);
    auto first_retained = RegisteredProjectionRoute::receive_and_retain(
        std::move(first_bound));
    auto first_role0 = RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(0));
    auto first_role1 = RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(1));
    auto first_role2 = RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(2));
    auto pending1 = RegisteredParentRoundCompletionBridge::defer(
        std::move(first_retained), std::move(first_role0),
        std::move(first_role1), std::move(first_role2), first_children);

    auto& second_children =
        RegisteredParentPersistentRoleFork::activate_round2(session);
    auto second_bound = RegisteredProjectionRouteForkBridge::
        bind_parent_after_fork(std::move(second_parent), second_children);
    RegisteredFullCohortReleaseBarrier::authorize(second_children);
    auto second_retained = RegisteredProjectionRoute::receive_and_retain(
        std::move(second_bound));
    auto second_role0 = RegisteredPartyCompletionTransport::receive(
        second_children.take_completion_endpoint(0));
    auto second_role1 = RegisteredPartyCompletionTransport::receive(
        second_children.take_completion_endpoint(1));
    auto second_role2 = RegisteredPartyCompletionTransport::receive(
        second_children.take_completion_endpoint(2));
    auto pending2 = RegisteredParentRoundCompletionBridge::defer(
        std::move(second_retained), std::move(second_role0),
        std::move(second_role1), std::move(second_role2), second_children);
    if (fault == PersistentFault::ExternallyReapedBeforeJoin) {
        for (const auto pid : child_pids) {
            int status = 0;
            assert(::waitpid(static_cast<pid_t>(pid), &status, 0) == pid);
            assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
        refuses([&] {
            (void)RegisteredParentTrialCompletionBridge::join(
                std::move(pending1), std::move(pending2), session);
        });
        return;
    }
    if (fault == PersistentFault::DirtyFinalChildExit ||
        fault == PersistentFault::SignaledFinalChildExit) {
        refuses([&] {
            (void)RegisteredParentTrialCompletionBridge::join(
                std::move(pending1), std::move(pending2), session);
        });
        return;
    }
    auto trial = RegisteredParentTrialCompletionBridge::join(
        std::move(pending1), std::move(pending2), session);
    if (fault == PersistentFault::ExportProducerRoutes) {
        auto producer_routes = RegisteredProducerRouteBridge::take_once(
            trial);
        (void)producer_routes;
        refuses([&] {
            (void)RegisteredProducerRouteBridge::take_once(trial);
        });
    }
    if (fault == PersistentFault::AttachExitHistory) {
        auto history = attempt_history::
            RegisteredTrialAttemptHistoryTestBridge::begin({
                .classification = classification,
                .capture_trial_id = first.capture_trial_id,
                .trial_identity = first.trial,
            });
        attempt_history::RegisteredParentTrialHistoryBridge::
            attach_exit_evidence(trial, history);
        history_refuses([&] {
            attempt_history::RegisteredParentTrialHistoryBridge::
                attach_exit_evidence(trial, history);
        });
        RegisteredParentTrialCompletionAuthority moved(std::move(trial));
        auto second_history = attempt_history::
            RegisteredTrialAttemptHistoryTestBridge::begin({
                .classification = classification,
                .capture_trial_id = first.capture_trial_id,
                .trial_identity = first.trial,
            });
        history_refuses([&] {
            attempt_history::RegisteredParentTrialHistoryBridge::
                attach_exit_evidence(trial, second_history);
        });
        (void)moved;
    }
    (void)trial;
    refuses([&] {
        (void)RegisteredParentTrialCompletionBridge::join(
            std::move(pending1), std::move(pending2), session);
    });
}

void execute(CaptureClassification classification, RoundFault fault) {
    Pipes pipes;
    const auto selected = plan(classification);
    const auto route = route_plan(selected);
    const auto body = projection();
    auto route_endpoints = RegisteredProjectionRoute::mint_pre_intake(
        ProjectionRoutePlanAuthority::test_only_mint(route));
    auto parent = route_endpoints.take_parent();
    auto writer = route_endpoints.take_role0_writer();
    auto fork = ParentRoleForkPlanAuthority::test_only_mint(
        selected, endpoints(selected, pipes));
    RegisteredProjectionRouteForkBridge::consume_writer_for_parent_fork(
        std::move(writer), fork);
    pipes.close_writes();
    RoundProgram program(selected, route, body, fault);
    auto children = RegisteredParentRoleFork::launch(
        std::move(fork), program);
    auto bound = RegisteredProjectionRouteForkBridge::bind_parent_after_fork(
        std::move(parent), children);
    if (fault == RoundFault::MissingReleaseReady ||
        fault == RoundFault::WrongReleaseReady) {
        refuses([&] {
            RegisteredFullCohortReleaseBarrier::authorize(children);
        });
        return;
    }
    RegisteredFullCohortReleaseBarrier::authorize(children);
    auto retained = RegisteredProjectionRoute::receive_and_retain(
        std::move(bound));

    auto role0 = RegisteredPartyCompletionTransport::receive(
        children.take_completion_endpoint(0));
    auto role1 = RegisteredPartyCompletionTransport::receive(
        children.take_completion_endpoint(1));
    if (fault == RoundFault::PartialCompletion) {
        refuses([&] {
            (void)RegisteredPartyCompletionTransport::receive(
                children.take_completion_endpoint(2));
        });
        refuses([&] { (void)children.wait(); });
        return;
    }
    auto role2 = RegisteredPartyCompletionTransport::receive(
        children.take_completion_endpoint(2));

    if (fault == RoundFault::WrongProjection ||
        fault == RoundFault::WrongSelection ||
        fault == RoundFault::WrongBarrier ||
        fault == RoundFault::DirtyChildExit) {
        refuses([&] {
            (void)RegisteredParentRoundCompletionBridge::join(
                std::move(retained), std::move(role0), std::move(role1),
                std::move(role2), children);
        });
        // A refused round join burns the ACKed route at entry. It must not be
        // reusable by the pre-existing standalone terminal-transfer seam.
        bool route_burned = false;
        try {
            (void)RegisteredProjectionRoute::
                test_only_transfer_for_native_terminal(
                    std::move(retained));
        } catch (const std::runtime_error&) { route_burned = true; }
        assert(route_burned);
        return;
    }

    auto joined = RegisteredParentRoundCompletionBridge::join(
        std::move(retained), std::move(role0), std::move(role1),
        std::move(role2), children);
    (void)joined;
    // All inputs and the child wait are linear.  Moved-from values cannot
    // reconstruct a second round authority.
    refuses([&] {
        (void)RegisteredParentRoundCompletionBridge::join(
            std::move(retained), std::move(role0), std::move(role1),
            std::move(role2), children);
    });
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view selected(argv[1]);
    if (selected == "hidden")
        execute(CaptureClassification::HiddenCandidate, RoundFault::None);
    else if (selected == "baseline")
        execute(CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
                RoundFault::None);
    else if (selected == "wrong-projection")
        execute(CaptureClassification::HiddenCandidate,
                RoundFault::WrongProjection);
    else if (selected == "wrong-selection")
        execute(CaptureClassification::HiddenCandidate,
                RoundFault::WrongSelection);
    else if (selected == "wrong-barrier")
        execute(CaptureClassification::HiddenCandidate,
                RoundFault::WrongBarrier);
    else if (selected == "wrong-release-ready")
        execute(CaptureClassification::HiddenCandidate,
                RoundFault::WrongReleaseReady);
    else if (selected == "missing-release-ready")
        execute(CaptureClassification::HiddenCandidate,
                RoundFault::MissingReleaseReady);
    else if (selected == "partial")
        execute(CaptureClassification::HiddenCandidate,
                RoundFault::PartialCompletion);
    else if (selected == "dirty-exit")
        execute(CaptureClassification::HiddenCandidate,
                RoundFault::DirtyChildExit);
    else if (selected == "persistent-hidden")
        execute_persistent(CaptureClassification::HiddenCandidate);
    else if (selected == "persistent-baseline")
        execute_persistent(
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    else if (selected == "persistent-cross-trial")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::CrossTrial);
    else if (selected == "persistent-changed-roster")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::ChangedRoster);
    else if (selected == "persistent-swapped-rounds")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::SwapRounds);
    else if (selected == "persistent-wrong-route-lineage")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::WrongRouteLineage);
    else if (selected == "persistent-early-round2")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::ActivateRound2Early);
    else if (selected == "persistent-dirty-final-exit")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::DirtyFinalChildExit);
    else if (selected == "persistent-signaled-final-exit")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::SignaledFinalChildExit);
    else if (selected == "persistent-echild")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::ExternallyReapedBeforeJoin);
    else if (selected == "persistent-stale-pid-sentinel")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::StalePidSentinelCleanup);
    else if (selected == "persistent-poison-destroy")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::PoisonThenDestroy);
    else if (selected == "persistent-export-producer-routes")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::ExportProducerRoutes);
    else if (selected == "persistent-attach-exit-history")
        execute_persistent(CaptureClassification::HiddenCandidate,
                           PersistentFault::AttachExitHistory);
    else if (selected == "persistent-cross-session")
        execute_cross_session_pending_mix();
    else if (selected == "persistent-stale-first-burns-second")
        persistent_stale_round1_burns_fresh_round2();
    else
        return 2;
    return 0;
}
