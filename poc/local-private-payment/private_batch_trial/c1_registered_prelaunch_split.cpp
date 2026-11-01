#include "c1_registered_plan_route_bridge.hpp"

#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"

#include <utility>

namespace kpb::measurement::c1_capture {
namespace {

using RegisteredPrelaunch =
    kpi::mpc::financial::registered_driver::
        RegisteredSelectedProducerPrelaunchBindingAuthority;
using RegisteredPlan =
    kpi::mpc::financial::registered_driver::
        RegisteredSelectedProducerPrelaunchPlan;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

PublicRegisteredC1RoundLineage lineage(
        const RegisteredPlan& plan, const Digest& authority_identity,
        unsigned round) {
    need(round == 1 || round == 2);
    const auto index = round - 1;
    const auto stream_index = index * 5 + 4;
    const auto& stream = plan.streams[stream_index];
    need(stream.round == round &&
         stream.kind == CaptureKind::ColluderWallet &&
         stream.fixed_fd == (round == 1 ? 24U : 29U));
    return {
        .classification = plan.classification,
        .round = round,
        .capture_trial_id = plan.capture_trial_id,
        .capture_attempt_id = plan.capture_attempt_ids[index],
        .registered_prelaunch_identity = authority_identity,
        .comparison_selection = plan.comparison_selection,
        .run_selection = plan.run_selection,
        .trial = plan.trial,
        .measurement_attempt = plan.measurement_attempt,
        .measurement_cohort = plan.measurement_cohort,
        .capture = plan.capture,
        .method = plan.method,
        .workload = plan.workload,
        .source_closure = plan.source_closure,
        .runtime = plan.runtime,
        .finite_manifest = plan.finite_manifest,
        .outer_parent_process = plan.outer_parent_process,
        .outer_parent_executable = plan.outer_parent_executable,
        .capture_source = plan.capture_source,
        .capture_build = plan.capture_build,
        .capture_runtime = plan.capture_runtime,
        .capture_launcher = plan.capture_launcher,
        .observer_worker = plan.observer_worker,
        .score_worker = plan.score_worker,
        .aggregate_worker = plan.aggregate_worker,
        .financial_run = plan.financial_runs[index],
        .round_attempt = plan.round_attempts[index],
        .round_cohort = plan.round_cohorts[index],
        .round_capture_plan = plan.round_capture_plans[index],
        .process_reservation_identity = plan.process_reservation_identity,
        .persistent_process_session_identity =
            plan.persistent_process_session_identity,
        .fork_plan_identity = plan.fork_plan_identities[index],
        .route_capability_identity =
            plan.route_policies[index].route_capability_identity,
        .producer_process_identity = plan.producer_process_identity,
        .role_closure_identity = plan.role_closure_identity,
        .manifest_seal = plan.manifest_seal,
        .construction_policy = plan.construction_policy,
        .construction_classification_receipt =
            plan.construction_classification_receipt,
        .c1_process_identity = stream.process_identity,
        .c1_expected_exit_policy_identity =
            stream.expected_exit_policy_identity,
    };
}

} // namespace

struct RegisteredC1PrelaunchSplit::Storage final {
    std::optional<RegisteredPrelaunch> registered_prelaunch;
    std::array<std::optional<RegisteredC1RoundLineageAuthority>, 2> rounds;

    Storage(RegisteredPrelaunch&& source,
            RegisteredC1RoundLineageAuthority&& round1,
            RegisteredC1RoundLineageAuthority&& round2)
        : registered_prelaunch(std::move(source)) {
        rounds[0].emplace(std::move(round1));
        rounds[1].emplace(std::move(round2));
    }
};

RegisteredC1PrelaunchSplit::RegisteredC1PrelaunchSplit(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

RegisteredC1PrelaunchSplit::RegisteredC1PrelaunchSplit(
        RegisteredC1PrelaunchSplit&&) noexcept = default;
RegisteredC1PrelaunchSplit::~RegisteredC1PrelaunchSplit() = default;

RegisteredPrelaunch
RegisteredC1PrelaunchSplit::take_registered_prelaunch() {
    need(storage_ != nullptr &&
         storage_->registered_prelaunch.has_value());
    RegisteredPrelaunch result(
        std::move(*storage_->registered_prelaunch));
    storage_->registered_prelaunch.reset();
    return result;
}

RegisteredC1RoundLineageAuthority
RegisteredC1PrelaunchSplit::take_round(unsigned round) {
    need(storage_ != nullptr && (round == 1 || round == 2));
    auto& selected = storage_->rounds[round - 1];
    need(selected.has_value());
    RegisteredC1RoundLineageAuthority result(std::move(*selected));
    selected.reset();
    return result;
}

RegisteredC1PrelaunchSplit
RegisteredC1PlanRouteBridge::split_registered_prelaunch(
        RegisteredPrelaunch&& supplied) {
    RegisteredPrelaunch claimed(std::move(supplied));
    try {
        need(claimed.live_.load() &&
             !claimed.c1_round_lineage_issued_.exchange(true));
        auto round1 = RegisteredC1RoundLineageAuthority(
            lineage(claimed.plan_, claimed.authority_identity_, 1));
        auto round2 = RegisteredC1RoundLineageAuthority(
            lineage(claimed.plan_, claimed.authority_identity_, 2));
        return RegisteredC1PrelaunchSplit(
            std::make_unique<RegisteredC1PrelaunchSplit::Storage>(
                std::move(claimed), std::move(round1),
                std::move(round2)));
    } catch (...) { refuse(); }
}

} // namespace kpb::measurement::c1_capture
