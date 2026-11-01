#define main embedded_registered_party_completion_transport_main
#include "../mpc-prover/financial/controls/registered_party_completion_transport_test.cpp"
#undef main

#include "../mpc-prover/financial/registered_projection_route.hpp"
#include "../mpc-prover/financial/registered_selected_parent_orchestrator.hpp"
#include "privacy_measurement_authority.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <functional>
#include <set>
#include <string_view>
#include <utility>

using namespace kpi::mpc::financial::registered_driver::projection_route;

namespace {

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
public:
    RoundProgram(
            PublicParentRoleForkPlan selected,
            PublicProjectionRoutePlan route,
            std::array<std::byte, PUBLIC_PROJECTION_BYTES> body)
        : selected_(std::move(selected)), route_(std::move(route)),
          projection_(std::move(body)) {}

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
    RoundProgram round1_;
    RoundProgram round2_;
public:
    PersistentProgram(
            PublicParentRoleForkPlan first,
            PublicParentRoleForkPlan second,
            PublicProjectionRoutePlan route1,
            PublicProjectionRoutePlan route2,
            std::array<std::byte, PUBLIC_PROJECTION_BYTES> body1,
            std::array<std::byte, PUBLIC_PROJECTION_BYTES> body2)
        : round1_(std::move(first), std::move(route1), std::move(body1)),
          round2_(std::move(second), std::move(route2), std::move(body2)) {}

    RegisteredRoleChildProgram& round_program(unsigned round) override {
        if (round == 1) return round1_;
        assert(round == 2);
        return round2_;
    }
};

namespace measurement = kpb::measurement;
namespace registered = kpi::mpc::financial::registered_driver;

measurement::Digest measurement_digest(unsigned char value) {
    measurement::Digest result{};
    result.fill(value);
    return result;
}

measurement::WorkerBinding measurement_worker(
        const measurement::ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

measurement::FiniteManifestBinding measurement_manifest() {
    std::array<measurement::ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0x90 + 7 * index);
        entries[index] = {
            .component = static_cast<measurement::ManifestComponent>(
                index + 1),
            .source_identity = measurement_digest(seed),
            .build_identity = measurement_digest(seed + 1),
            .runtime_identity = measurement_digest(seed + 2),
            .assets_identity = measurement_digest(seed + 3),
            .pinned_executable_identity = measurement_digest(seed + 4),
            .launcher_identity = measurement_digest(seed + 5),
        };
    }
    return {
        .manifest_identity =
            measurement::recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = measurement_digest(0x8f),
        .entries = entries,
    };
}

measurement::Classification measurement_classification(
        registered::CaptureClassification value) {
    return value == registered::CaptureClassification::HiddenCandidate
        ? measurement::Classification::HiddenCandidate
        : measurement::Classification::TransparentBaseline;
}

measurement::RunBinding measurement_binding(
        registered::CaptureClassification classification) {
    const auto manifest = measurement_manifest();
    const auto first_body = projection(0x31);
    const auto second_body = projection(0x52);
    const auto& capture = manifest.entries.at(1);
    measurement::RunBinding result{
        .classification = measurement_classification(classification),
        .comparison_selection = measurement_digest(0x11),
        .run_selection = measurement_digest(0x12),
        .trial = registered::RegisteredCapturePlanRosterBridge::
            trial_identity(TRIAL_UUID),
        .attempt = measurement_digest(0x14),
        .cohort = measurement_digest(0x15),
        .capture = measurement_digest(0x16),
        .method = measurement_digest(0x17),
        .workload = measurement_digest(0x18),
        .source_closure = measurement_digest(0x19),
        .runtime = measurement_digest(0x1a),
        .finite_manifest = manifest,
        .outer_parent_process = measurement_digest(0x1b),
        .outer_parent_executable = measurement_digest(0x1c),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = measurement_worker(manifest.entries.at(6)),
        .score_worker = measurement_worker(manifest.entries.at(7)),
        .aggregate_worker = measurement_worker(manifest.entries.at(8)),
        .financial_runs = {
            measurement_digest(0x21), measurement_digest(0x22)},
        .round_attempts = {
            measurement_digest(0x23), measurement_digest(0x24)},
        .round_cohorts = {
            measurement_digest(0x25), measurement_digest(0x26)},
        .round_capture_plans = {
            measurement_digest(0x27), measurement_digest(0x28)},
        .projections = {
            projection_identity(first_body),
            projection_identity(second_body)},
    };
    measurement::validate_measurement_run_binding(result);
    return result;
}

measurement::ParentManifestRecomputationAuthority parent_manifest(
        const measurement::RunBinding& selected) {
    return measurement::ParentManifestRecomputationAuthority::test_only_mint({
        .manifest = selected.finite_manifest,
        .parent_process_identity = selected.outer_parent_process,
        .parent_executable_identity = selected.outer_parent_executable,
        .recomputation_receipt =
            selected.finite_manifest.parent_recomputation_identity,
    });
}

registered::PublicParentRoleForkPlan registered_plan(
        const measurement::RunBinding& selected, unsigned round) {
    auto result = round_plan(
        selected.classification == measurement::Classification::HiddenCandidate
            ? registered::CaptureClassification::HiddenCandidate
            : registered::CaptureClassification::
                  ExplicitOwnerPublicEffectsBaseline,
        round);
    const auto index = round - 1;
    result.trial = selected.trial;
    result.financial_run = selected.financial_runs[index];
    result.attempt = selected.round_attempts[index];
    result.cohort = selected.round_cohorts[index];
    result.capture_plan_identity = selected.round_capture_plans[index];
    result.capture_source_identity = selected.capture_source;
    result.capture_build_identity = selected.capture_build;
    result.capture_launcher_identity = selected.capture_launcher;
    return result;
}

registered::RegisteredParentTrialCompletionAuthority registered_trial(
        const measurement::RunBinding& selected) {
    Pipes first_pipes;
    Pipes second_pipes;
    const auto first = registered_plan(selected, 1);
    const auto second = registered_plan(selected, 2);
    const auto first_route = route_plan(first);
    const auto second_route = route_plan(second);
    const auto first_body = projection(0x31);
    const auto second_body = projection(0x52);

    auto first_route_endpoints =
        registered::projection_route::RegisteredProjectionRoute::
            mint_pre_intake(
                registered::projection_route::
                    ProjectionRoutePlanAuthority::test_only_mint(
                        first_route));
    auto second_route_endpoints =
        registered::projection_route::RegisteredProjectionRoute::
            mint_pre_intake(
                registered::projection_route::
                    ProjectionRoutePlanAuthority::test_only_mint(
                        second_route));
    auto first_parent = first_route_endpoints.take_parent();
    auto second_parent = second_route_endpoints.take_parent();
    auto first_writer = first_route_endpoints.take_role0_writer();
    auto second_writer = second_route_endpoints.take_role0_writer();
    auto first_fork = registered::ParentRoleForkPlanAuthority::test_only_mint(
        first, round_endpoints(first, first_pipes));
    auto second_fork = registered::ParentRoleForkPlanAuthority::test_only_mint(
        second, round_endpoints(second, second_pipes));
    registered::projection_route::RegisteredProjectionRouteForkBridge::
        consume_writer_for_parent_fork(
            std::move(first_writer), first_fork);
    registered::projection_route::RegisteredProjectionRouteForkBridge::
        consume_writer_for_parent_fork(
            std::move(second_writer), second_fork);
    first_pipes.close_writes();
    second_pipes.close_writes();

    PersistentProgram program(
        first, second, first_route, second_route, first_body, second_body);
    auto session = registered::RegisteredParentPersistentRoleFork::launch(
        std::move(first_fork), std::move(second_fork), program);

    auto& first_children =
        registered::RegisteredParentPersistentRoleFork::round1(session);
    auto first_bound = registered::projection_route::
        RegisteredProjectionRouteForkBridge::bind_parent_after_fork(
            std::move(first_parent), first_children);
    registered::RegisteredFullCohortReleaseBarrier::authorize(
        first_children);
    auto first_retained = registered::projection_route::
        RegisteredProjectionRoute::receive_and_retain(
            std::move(first_bound));
    auto first_role0 = registered::RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(0));
    auto first_role1 = registered::RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(1));
    auto first_role2 = registered::RegisteredPartyCompletionTransport::receive(
        first_children.take_completion_endpoint(2));
    auto pending1 = registered::RegisteredParentRoundCompletionBridge::defer(
        std::move(first_retained), std::move(first_role0),
        std::move(first_role1), std::move(first_role2), first_children);

    auto& second_children =
        registered::RegisteredParentPersistentRoleFork::activate_round2(
            session);
    auto second_bound = registered::projection_route::
        RegisteredProjectionRouteForkBridge::bind_parent_after_fork(
            std::move(second_parent), second_children);
    registered::RegisteredFullCohortReleaseBarrier::authorize(
        second_children);
    auto second_retained = registered::projection_route::
        RegisteredProjectionRoute::receive_and_retain(
            std::move(second_bound));
    auto second_role0 =
        registered::RegisteredPartyCompletionTransport::receive(
            second_children.take_completion_endpoint(0));
    auto second_role1 =
        registered::RegisteredPartyCompletionTransport::receive(
            second_children.take_completion_endpoint(1));
    auto second_role2 =
        registered::RegisteredPartyCompletionTransport::receive(
            second_children.take_completion_endpoint(2));
    auto pending2 = registered::RegisteredParentRoundCompletionBridge::defer(
        std::move(second_retained), std::move(second_role0),
        std::move(second_role1), std::move(second_role2), second_children);
    return registered::RegisteredParentTrialCompletionBridge::join(
        std::move(pending1), std::move(pending2), session);
}

enum class ProducerFault {
    None,
    ProjectionProcess,
    ProjectionExit,
    DispatcherProcess,
    DispatcherExit,
};

measurement::ProducerClosureAuthority producer(
        const measurement::RunBinding& selected,
        ProducerFault fault = ProducerFault::None) {
    std::array<measurement::PublicStreamClosure, 10> streams{};
    measurement::ProducerClosureEvidence evidence{
        .opaque_closure_authority_identity = measurement_digest(0x71),
        .producer_child_exit = measurement_digest(0x72),
        .producer_receipt = measurement_digest(0x73),
        .producer_identity = measurement_digest(0x74),
    };
    constexpr std::array<unsigned, 5> manifest_indexes{0, 3, 4, 1, 2};
    for (unsigned index = 0; index < streams.size(); ++index) {
        const unsigned kind = index % 5;
        const auto& entry =
            selected.finite_manifest.entries.at(manifest_indexes[kind]);
        auto process = measurement_digest(
            static_cast<unsigned char>(0xa0 + index));
        auto child_exit = measurement_digest(
            static_cast<unsigned char>(0xb0 + index));
        if (kind == 0) {
            process = id(0xa01);
            child_exit = id(0xa02);
            if (fault == ProducerFault::ProjectionProcess && index == 0)
                process = measurement_digest(0xe1);
            if (fault == ProducerFault::ProjectionExit && index == 0)
                child_exit = measurement_digest(0xe2);
        } else if (kind == 2) {
            process = id(0xa03);
            child_exit = id(0xa04);
            if (fault == ProducerFault::DispatcherProcess && index == 2)
                process = measurement_digest(0xe3);
            if (fault == ProducerFault::DispatcherExit && index == 2)
                child_exit = measurement_digest(0xe4);
        }
        streams[index] = {
            .round = index / 5 + 1,
            .kind = static_cast<measurement::CaptureKind>(kind + 1),
            .fixed_fd = 20 + index,
            .manifest_component = entry.component,
            .source_identity = entry.source_identity,
            .build_identity = entry.build_identity,
            .runtime_identity = entry.runtime_identity,
            .launcher_identity = entry.launcher_identity,
            .process_identity = process,
            .child_exit_identity = child_exit,
            .root_closed = true,
            .end_observed = true,
            .eof_observed = true,
        };
        evidence.streams[index] = {
            .record_root = measurement_digest(
                static_cast<unsigned char>(0xc0 + index)),
            .end_frame_identity = measurement_digest(
                static_cast<unsigned char>(0xd0 + index)),
            .eof_identity = measurement_digest(
                static_cast<unsigned char>(0xe0 + index)),
            .record_count = 1 + index,
            .payload_bytes = 100 + index,
            .raw_wire_bytes = 200 + index,
        };
    }
    return measurement::ProducerClosureAuthority::test_only_mint({
        .binding = selected,
        .opaque_closure_authority_identity = measurement_digest(0x71),
        .producer_worker = measurement_worker(
            selected.finite_manifest.entries.at(5)),
        .producer_process_identity = measurement_digest(0x75),
        .role_closure_identity = measurement_digest(0x76),
        .manifest_seal = measurement_digest(0x77),
        .construction_policy = selected.classification ==
                measurement::Classification::TransparentBaseline
            ? measurement::ConstructionPolicy::ExplicitOwnerPublicEffects
            : measurement::ConstructionPolicy::
                  SecretPermutationIndependent,
        .construction_classification_receipt = measurement_digest(0x78),
        .streams = streams,
        .stream_count = 10,
        .closed_root_count = 10,
        .unknown_record_count = 0,
    }, std::move(evidence));
}

measurement::PartyCompletionAuthority fixture_party(
        const measurement::RunBinding& selected, unsigned round,
        unsigned role) {
    const auto index = round - 1;
    return measurement::PartyCompletionAuthority::test_only_mint({
        .binding = selected,
        .round = round,
        .role = role,
        .financial_run = selected.financial_runs[index],
        .trial = selected.trial,
        .attempt = selected.round_attempts[index],
        .cohort = selected.round_cohorts[index],
        .child_exit = measurement_digest(
            static_cast<unsigned char>(0x31 + 3 * index + role)),
        .driver_completion = measurement_digest(
            static_cast<unsigned char>(0x41 + 3 * index + role)),
        .selection_identity = measurement_digest(
            static_cast<unsigned char>(0x51 + index)),
        .proposal_identity = measurement_digest(
            static_cast<unsigned char>(0x61 + 3 * index + role)),
        .accepted_head = measurement_digest(
            static_cast<unsigned char>(0x71 + index)),
        .postlock_accepted_head = measurement_digest(
            static_cast<unsigned char>(0x71 + index)),
        .durable_lock = measurement_digest(
            static_cast<unsigned char>(0x81 + index)),
        .capture_source = selected.capture_source,
        .capture_build = selected.capture_build,
        .capture_runtime = selected.capture_runtime,
        .capture_launcher = selected.capture_launcher,
        .process_identity = measurement_digest(
            static_cast<unsigned char>(0x91 + 3 * index + role)),
        .egress = measurement_digest(
            static_cast<unsigned char>(0xa1 + index)),
        .proof = measurement_digest(
            static_cast<unsigned char>(0xb1 + index)),
        .projection = selected.projections[index],
    });
}

template<class Function>
void expect_measurement_refused(Function&& function) {
    bool refused = false;
    try {
        function();
    } catch (const measurement::Refused&) {
        refused = true;
    }
    assert(refused);
}

void complete_registered_trial_joins(
        registered::CaptureClassification classification) {
    const auto selected = measurement_binding(classification);
    measurement::TrialCaptureJoiner joiner(
        selected, parent_manifest(selected));
    joiner.test_only_require_registered_trial_for_finish();
    joiner.submit(producer(selected));
    auto trial = registered_trial(selected);
    registered::RegisteredMeasurementCaptureBridge::submit(
        joiner, std::move(trial));
    auto completed = joiner.finish();
    const auto& receipt = completed.public_receipt();
    assert(receipt.binding == selected);
    assert(receipt.projections == selected.projections);
    for (const auto& round : receipt.party_completion)
        for (const auto& party : round)
            assert(party != measurement::Digest{});
    expect_measurement_refused([&] {
        registered::RegisteredMeasurementCaptureBridge::submit(
            joiner, std::move(trial));
    });
    measurement::RunMeasurement run(std::move(completed));
    assert(run.test_only_has_registered_trial_retention());
}

void producer_is_required_and_trial_is_burned() {
    const auto selected = measurement_binding(
        registered::CaptureClassification::HiddenCandidate);
    measurement::TrialCaptureJoiner joiner(
        selected, parent_manifest(selected));
    joiner.test_only_require_registered_trial_for_finish();
    auto trial = registered_trial(selected);
    expect_measurement_refused([&] {
        registered::RegisteredMeasurementCaptureBridge::submit(
            joiner, std::move(trial));
    });
    expect_measurement_refused([&] {
        registered::RegisteredMeasurementCaptureBridge::submit(
            joiner, std::move(trial));
    });
    expect_measurement_refused([&] { (void)joiner.finish(); });
}

void prepopulated_party_slot_refuses() {
    const auto selected = measurement_binding(
        registered::CaptureClassification::HiddenCandidate);
    measurement::TrialCaptureJoiner joiner(
        selected, parent_manifest(selected));
    joiner.test_only_require_registered_trial_for_finish();
    joiner.submit(producer(selected));
    joiner.submit(fixture_party(selected, 1, 0));
    auto trial = registered_trial(selected);
    expect_measurement_refused([&] {
        registered::RegisteredMeasurementCaptureBridge::submit(
            joiner, std::move(trial));
    });
    expect_measurement_refused([&] { (void)joiner.finish(); });
}

void finish_without_registered_retention_refuses() {
    const auto selected = measurement_binding(
        registered::CaptureClassification::HiddenCandidate);
    measurement::TrialCaptureJoiner joiner(
        selected, parent_manifest(selected));
    joiner.test_only_require_registered_trial_for_finish();
    joiner.submit(producer(selected));
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            joiner.submit(fixture_party(selected, round, role));
    expect_measurement_refused([&] { (void)joiner.finish(); });
}

void producer_route_substitution_refuses(ProducerFault fault) {
    const auto selected = measurement_binding(
        registered::CaptureClassification::HiddenCandidate);
    measurement::TrialCaptureJoiner joiner(
        selected, parent_manifest(selected));
    joiner.test_only_require_registered_trial_for_finish();
    joiner.submit(producer(selected, fault));
    auto trial = registered_trial(selected);
    expect_measurement_refused([&] {
        registered::RegisteredMeasurementCaptureBridge::submit(
            joiner, std::move(trial));
    });
    expect_measurement_refused([&] { (void)joiner.finish(); });
}

enum class BindingFault {
    Classification,
    Trial,
    FinancialRun1,
    FinancialRun2,
    Attempt1,
    Attempt2,
    Cohort1,
    Cohort2,
    CapturePlan1,
    CapturePlan2,
    Projection1,
    Projection2,
    CaptureSource,
    CaptureBuild,
    CaptureLauncher,
};

void mutate_binding(measurement::RunBinding& value, BindingFault fault) {
    const auto replacement = measurement_digest(
        static_cast<unsigned char>(0xf0 +
            static_cast<unsigned>(fault)));
    switch (fault) {
    case BindingFault::Classification:
        value.classification = value.classification ==
                measurement::Classification::HiddenCandidate
            ? measurement::Classification::TransparentBaseline
            : measurement::Classification::HiddenCandidate;
        break;
    case BindingFault::Trial: value.trial = replacement; break;
    case BindingFault::FinancialRun1:
        value.financial_runs[0] = replacement; break;
    case BindingFault::FinancialRun2:
        value.financial_runs[1] = replacement; break;
    case BindingFault::Attempt1:
        value.round_attempts[0] = replacement; break;
    case BindingFault::Attempt2:
        value.round_attempts[1] = replacement; break;
    case BindingFault::Cohort1:
        value.round_cohorts[0] = replacement; break;
    case BindingFault::Cohort2:
        value.round_cohorts[1] = replacement; break;
    case BindingFault::CapturePlan1:
        value.round_capture_plans[0] = replacement; break;
    case BindingFault::CapturePlan2:
        value.round_capture_plans[1] = replacement; break;
    case BindingFault::Projection1:
        value.projections[0] = replacement; break;
    case BindingFault::Projection2:
        value.projections[1] = replacement; break;
    case BindingFault::CaptureSource:
        value.capture_source = replacement;
        value.finite_manifest.entries[1].source_identity = replacement;
        value.finite_manifest.manifest_identity =
            measurement::recompute_finite_manifest_identity(
                value.finite_manifest.entries);
        break;
    case BindingFault::CaptureBuild:
        value.capture_build = replacement;
        value.finite_manifest.entries[1].build_identity = replacement;
        value.finite_manifest.manifest_identity =
            measurement::recompute_finite_manifest_identity(
                value.finite_manifest.entries);
        break;
    case BindingFault::CaptureLauncher:
        value.capture_launcher = replacement;
        value.finite_manifest.entries[1].launcher_identity = replacement;
        value.finite_manifest.manifest_identity =
            measurement::recompute_finite_manifest_identity(
                value.finite_manifest.entries);
        break;
    }
    measurement::validate_measurement_run_binding(value);
}

void binding_lineage_substitution_refuses(BindingFault fault) {
    const auto original = measurement_binding(
        registered::CaptureClassification::HiddenCandidate);
    auto changed = original;
    mutate_binding(changed, fault);
    measurement::TrialCaptureJoiner joiner(
        changed, parent_manifest(changed));
    joiner.test_only_require_registered_trial_for_finish();
    joiner.submit(producer(changed));
    auto trial = registered_trial(original);
    expect_measurement_refused([&] {
        registered::RegisteredMeasurementCaptureBridge::submit(
            joiner, std::move(trial));
    });
    expect_measurement_refused([&] { (void)joiner.finish(); });
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view scenario(argv[1]);
    if (scenario == "hidden")
        complete_registered_trial_joins(
            registered::CaptureClassification::HiddenCandidate);
    else if (scenario == "baseline")
        complete_registered_trial_joins(
            registered::CaptureClassification::
                ExplicitOwnerPublicEffectsBaseline);
    else if (scenario == "missing-producer")
        producer_is_required_and_trial_is_burned();
    else if (scenario == "prepopulated")
        prepopulated_party_slot_refuses();
    else if (scenario == "missing-retention")
        finish_without_registered_retention_refuses();
    else if (scenario == "projection-process")
        producer_route_substitution_refuses(
            ProducerFault::ProjectionProcess);
    else if (scenario == "projection-exit")
        producer_route_substitution_refuses(ProducerFault::ProjectionExit);
    else if (scenario == "dispatcher-process")
        producer_route_substitution_refuses(
            ProducerFault::DispatcherProcess);
    else if (scenario == "dispatcher-exit")
        producer_route_substitution_refuses(ProducerFault::DispatcherExit);
    else {
        constexpr std::array<std::pair<std::string_view, BindingFault>, 15>
            faults{{
                {"classification", BindingFault::Classification},
                {"trial", BindingFault::Trial},
                {"financial-run-1", BindingFault::FinancialRun1},
                {"financial-run-2", BindingFault::FinancialRun2},
                {"attempt-1", BindingFault::Attempt1},
                {"attempt-2", BindingFault::Attempt2},
                {"cohort-1", BindingFault::Cohort1},
                {"cohort-2", BindingFault::Cohort2},
                {"capture-plan-1", BindingFault::CapturePlan1},
                {"capture-plan-2", BindingFault::CapturePlan2},
                {"projection-1", BindingFault::Projection1},
                {"projection-2", BindingFault::Projection2},
                {"capture-source", BindingFault::CaptureSource},
                {"capture-build", BindingFault::CaptureBuild},
                {"capture-launcher", BindingFault::CaptureLauncher},
            }};
        const auto found = std::find_if(
            faults.begin(), faults.end(), [&](const auto& value) {
                return value.first == scenario;
            });
        if (found == faults.end()) return 2;
        binding_lineage_substitution_refuses(found->second);
    }
    return 0;
}
