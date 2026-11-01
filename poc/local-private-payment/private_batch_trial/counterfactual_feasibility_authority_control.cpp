#include "counterfactual_feasibility_authority.hpp"

#include <array>
#include <cassert>
#include <concepts>
#include <utility>

using namespace kpb::measurement;
using namespace kpb::measurement::counterfactual_feasibility;

namespace {

Digest word(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest workload_identity() {
    constexpr char encoded[] =
        "7fedea9560e241b08521ec3d88c29dba4592f017b6e909092f530a97ee210170";
    Digest result{};
    auto nibble = [](char value) -> unsigned char {
        return value <= '9' ? static_cast<unsigned char>(value - '0') :
            static_cast<unsigned char>(10 + value - 'a');
    };
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            (nibble(encoded[index * 2]) << 4U) |
            nibble(encoded[index * 2 + 1]));
    return result;
}

WorkerBinding worker(const ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

RunBinding binding(unsigned char seed = 0x10) {
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = word(seed);
    result.run_selection = word(static_cast<unsigned char>(seed + 1));
    result.trial = word(static_cast<unsigned char>(seed + 2));
    result.attempt = word(static_cast<unsigned char>(seed + 3));
    result.cohort = word(static_cast<unsigned char>(seed + 4));
    result.capture = word(static_cast<unsigned char>(seed + 5));
    result.method = word(static_cast<unsigned char>(seed + 6));
    result.workload = workload_identity();
    result.source_closure = word(static_cast<unsigned char>(seed + 8));
    result.runtime = word(static_cast<unsigned char>(seed + 9));
    result.outer_parent_process = word(
        static_cast<unsigned char>(seed + 10));
    result.outer_parent_executable = word(
        static_cast<unsigned char>(seed + 11));
    result.financial_runs = {word(0x20), word(0x21)};
    result.round_attempts = {word(0x22), word(0x23)};
    result.round_cohorts = {word(0x24), word(0x25)};
    result.round_capture_plans = {word(0x26), word(0x27)};
    result.projections = {word(0x28), word(0x29)};
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto component_seed =
            static_cast<unsigned char>(0x40 + index * 7);
        result.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = word(component_seed),
            .build_identity = word(
                static_cast<unsigned char>(component_seed + 1)),
            .runtime_identity = word(
                static_cast<unsigned char>(component_seed + 2)),
            .assets_identity = word(
                static_cast<unsigned char>(component_seed + 3)),
            .pinned_executable_identity = word(
                static_cast<unsigned char>(component_seed + 4)),
            .launcher_identity = word(
                static_cast<unsigned char>(component_seed + 5)),
        };
    }
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.finite_manifest.parent_recomputation_identity = word(0xfc);
    const auto& p1 = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    result.capture_source = p1.source_identity;
    result.capture_build = p1.build_identity;
    result.capture_runtime = p1.runtime_identity;
    result.capture_launcher = p1.launcher_identity;
    result.observer_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    validate_measurement_run_binding(result);
    return result;
}

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

CounterfactualPrecommitAuthority exact_precommit(const RunBinding& selected) {
    auto plan = CounterfactualFeasibilityBridge::test_only_plan(
        selected, TestOnlyCounterfactualFault::None);
    return CounterfactualFeasibilityBridge::precommit(std::move(plan));
}

CounterfactualArithmeticShapeAuthority exact_shape(
        const RunBinding& selected) {
    auto precommit = exact_precommit(selected);
    auto observed = CounterfactualFeasibilityBridge::test_only_observation(
        selected, TestOnlyCounterfactualFault::None);
    auto truth = CounterfactualFeasibilityBridge::test_only_post_barrier(
        selected, TestOnlyCounterfactualFault::None);
    return CounterfactualFeasibilityBridge::verify_arithmetic_shape(
        std::move(precommit), std::move(observed), std::move(truth));
}

FullW1WithCloseResidualAuthority exact_relation_residual(
        const RunBinding& selected,
        TestOnlyCounterfactualFault fault =
            TestOnlyCounterfactualFault::None) {
    auto source = CounterfactualFeasibilityBridge::test_only_live_source(
        selected, fault);
    return CounterfactualFullW1WitnessBridge::construct_and_verify(
        std::move(source));
}

CounterfactualJointClosureAuthority exact_joint(
        const RunBinding& selected,
        TestOnlyCounterfactualFault fault =
            TestOnlyCounterfactualFault::None) {
    auto residual = exact_relation_residual(selected, fault);
    return CounterfactualRuntimeCloseBridge::close_descendants(
        std::move(residual));
}

void valid_two_round_rewire_mints_one_opaque_authority() {
    const auto selected = binding();
    auto plan = CounterfactualFeasibilityBridge::test_only_plan(
        selected, TestOnlyCounterfactualFault::None);
    auto precommit =
        CounterfactualFeasibilityBridge::precommit(std::move(plan));
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::precommit(std::move(plan));
    });
    auto observed = CounterfactualFeasibilityBridge::test_only_observation(
        selected, TestOnlyCounterfactualFault::None);
    auto truth = CounterfactualFeasibilityBridge::test_only_post_barrier(
        selected, TestOnlyCounterfactualFault::None);
    auto shape = CounterfactualFeasibilityBridge::verify_arithmetic_shape(
        std::move(precommit), std::move(observed), std::move(truth));
    expect_refused([&] {
        auto fresh_observed =
            CounterfactualFeasibilityBridge::test_only_observation(
                selected, TestOnlyCounterfactualFault::None);
        auto fresh_truth =
            CounterfactualFeasibilityBridge::test_only_post_barrier(
                selected, TestOnlyCounterfactualFault::None);
        (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(precommit), std::move(fresh_observed),
            std::move(fresh_truth));
    });
    auto source = CounterfactualFeasibilityBridge::test_only_live_source(
        selected, TestOnlyCounterfactualFault::None);
    auto residual = CounterfactualFullW1WitnessBridge::construct_and_verify(
        std::move(source));
    expect_refused([&] {
        (void)CounterfactualFullW1WitnessBridge::construct_and_verify(
            std::move(source));
    });
    auto joint = CounterfactualRuntimeCloseBridge::close_descendants(
        std::move(residual));
    expect_refused([&] {
        (void)CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(residual));
    });
    auto result = CounterfactualFeasibilityBridge::close_full_witness(
        std::move(shape), std::move(joint));
    auto transfer = acceptance_v4::CounterfactualFeasibilityAcceptanceBridge::
        take(std::move(result));
    (void)transfer;
    expect_refused([&] {
        (void)acceptance_v4::CounterfactualFeasibilityAcceptanceBridge::take(
            std::move(result));
    });
}

void every_invalid_precommit_refuses() {
    constexpr std::array faults{
        TestOnlyCounterfactualFault::PlanAfterObservation,
        TestOnlyCounterfactualFault::WrongWorkloadIdentity,
        TestOnlyCounterfactualFault::WrongRehearsalIdentity,
        TestOnlyCounterfactualFault::WrongRelationIdentity,
        TestOnlyCounterfactualFault::WrongFullW1VerifierIdentity,
        TestOnlyCounterfactualFault::WrongFullW1BridgeIdentity,
        TestOnlyCounterfactualFault::WrongSourceTableIdentity,
        TestOnlyCounterfactualFault::WrongMatrixIdentity,
        TestOnlyCounterfactualFault::WrongMatrixEvidenceIdentity,
        TestOnlyCounterfactualFault::WrongLeakageClosureIdentity,
        TestOnlyCounterfactualFault::InputSwapDisabled,
        TestOnlyCounterfactualFault::ChangeSwapDisabled,
        TestOnlyCounterfactualFault::PaymentSwapEnabled,
        TestOnlyCounterfactualFault::WrongLeakageClass,
        TestOnlyCounterfactualFault::UnequalHonestInput,
        TestOnlyCounterfactualFault::UnequalPayment,
        TestOnlyCounterfactualFault::UnequalFee,
        TestOnlyCounterfactualFault::BadEquation,
        TestOnlyCounterfactualFault::BadValueRange,
        TestOnlyCounterfactualFault::WrongRound2Selection,
    };
    const auto selected = binding();
    for (const auto fault : faults) {
        auto plan = CounterfactualFeasibilityBridge::test_only_plan(
            selected, fault);
        expect_refused([&] {
            (void)CounterfactualFeasibilityBridge::precommit(
                std::move(plan));
        });
    }
    auto wrong_binding = binding();
    wrong_binding.workload = word(0xee);
    auto plan = CounterfactualFeasibilityBridge::test_only_plan(
        wrong_binding, TestOnlyCounterfactualFault::None);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::precommit(std::move(plan));
    });
}

void every_invalid_post_barrier_join_refuses() {
    constexpr std::array observation_faults{
        TestOnlyCounterfactualFault::MissingW1Public,
        TestOnlyCounterfactualFault::MissingW1Dispatcher,
        TestOnlyCounterfactualFault::MissingW1CorruptServerWallet,
        TestOnlyCounterfactualFault::MissingW1Union,
        TestOnlyCounterfactualFault::MalformedCandidate,
        TestOnlyCounterfactualFault::ObservationNotComplete,
    };
    constexpr std::array truth_faults{
        TestOnlyCounterfactualFault::BarrierNotComplete,
        TestOnlyCounterfactualFault::ScoresIncomplete,
        TestOnlyCounterfactualFault::MalformedTruthMapping,
        TestOnlyCounterfactualFault::WrongC1VisibleCreator,
        TestOnlyCounterfactualFault::TruthValueMismatch,
    };
    const auto selected = binding();
    for (const auto fault : observation_faults) {
        auto precommit = exact_precommit(selected);
        auto observed =
            CounterfactualFeasibilityBridge::test_only_observation(
                selected, fault);
        auto truth = CounterfactualFeasibilityBridge::test_only_post_barrier(
            selected, TestOnlyCounterfactualFault::None);
        expect_refused([&] {
            (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
                std::move(precommit), std::move(observed),
                std::move(truth));
        });
    }
    for (const auto fault : truth_faults) {
        auto precommit = exact_precommit(selected);
        auto observed =
            CounterfactualFeasibilityBridge::test_only_observation(
                selected, TestOnlyCounterfactualFault::None);
        auto truth = CounterfactualFeasibilityBridge::test_only_post_barrier(
            selected, fault);
        expect_refused([&] {
            (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
                std::move(precommit), std::move(observed),
                std::move(truth));
        });
    }

    auto precommit = exact_precommit(selected);
    auto observed = CounterfactualFeasibilityBridge::test_only_observation(
        binding(0x11), TestOnlyCounterfactualFault::None);
    auto truth = CounterfactualFeasibilityBridge::test_only_post_barrier(
        selected, TestOnlyCounterfactualFault::None);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(precommit), std::move(observed), std::move(truth));
    });

    auto incomplete = CounterfactualFeasibilityBridge::test_only_live_source(
        selected, TestOnlyCounterfactualFault::FullWitnessIncomplete);
    expect_refused([&] {
        (void)CounterfactualFullW1WitnessBridge::construct_and_verify(
            std::move(incomplete));
    });

    auto mismatched_relation = exact_relation_residual(
        selected, TestOnlyCounterfactualFault::FullWitnessWrongW1);
    expect_refused([&] {
        (void)CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(mismatched_relation));
    });

    auto mismatched_close = exact_relation_residual(
        selected, TestOnlyCounterfactualFault::CloseWrongW1);
    expect_refused([&] {
        (void)CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(mismatched_close));
    });

    auto incomplete_close = exact_relation_residual(
        selected, TestOnlyCounterfactualFault::CloseIncomplete);
    expect_refused([&] {
        (void)CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(incomplete_close));
    });

    auto mismatched_instance = exact_relation_residual(
        selected, TestOnlyCounterfactualFault::CloseWrongInstance);
    expect_refused([&] {
        (void)CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(mismatched_instance));
    });

    // Even mutually consistent relation/Close arms cannot substitute a
    // different graph for the independently established arithmetic shape.
    auto exact_shape_wrong_joint = exact_shape(selected);
    auto wrong_graph_joint = exact_joint(
        selected, TestOnlyCounterfactualFault::JointWrongW1);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::close_full_witness(
            std::move(exact_shape_wrong_joint),
            std::move(wrong_graph_joint));
    });

    auto wrong_shape = exact_shape(selected);
    auto wrong_joint = exact_joint(binding(0x11));
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::close_full_witness(
            std::move(wrong_shape), std::move(wrong_joint));
    });
}

void mixed_replay_burns_every_supplied_capability() {
    const auto selected = binding();

    auto empty_precommit = exact_precommit(selected);
    auto spent_observed =
        CounterfactualFeasibilityBridge::test_only_observation(
            selected, TestOnlyCounterfactualFault::None);
    auto spent_truth =
        CounterfactualFeasibilityBridge::test_only_post_barrier(
            selected, TestOnlyCounterfactualFault::None);
    auto discarded_shape =
        CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(empty_precommit), std::move(spent_observed),
            std::move(spent_truth));
    (void)discarded_shape;

    auto live_observed =
        CounterfactualFeasibilityBridge::test_only_observation(
            selected, TestOnlyCounterfactualFault::None);
    auto live_truth =
        CounterfactualFeasibilityBridge::test_only_post_barrier(
            selected, TestOnlyCounterfactualFault::None);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(empty_precommit), std::move(live_observed),
            std::move(live_truth));
    });
    auto fresh_precommit = exact_precommit(selected);
    auto fresh_truth =
        CounterfactualFeasibilityBridge::test_only_post_barrier(
            selected, TestOnlyCounterfactualFault::None);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(fresh_precommit), std::move(live_observed),
            std::move(fresh_truth));
    });

    auto empty_precommit_2 = exact_precommit(selected);
    auto spent_observed_2 =
        CounterfactualFeasibilityBridge::test_only_observation(
            selected, TestOnlyCounterfactualFault::None);
    auto spent_truth_2 =
        CounterfactualFeasibilityBridge::test_only_post_barrier(
            selected, TestOnlyCounterfactualFault::None);
    auto discarded_shape_2 =
        CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(empty_precommit_2), std::move(spent_observed_2),
            std::move(spent_truth_2));
    (void)discarded_shape_2;

    auto live_observed_2 =
        CounterfactualFeasibilityBridge::test_only_observation(
            selected, TestOnlyCounterfactualFault::None);
    auto live_truth_2 =
        CounterfactualFeasibilityBridge::test_only_post_barrier(
            selected, TestOnlyCounterfactualFault::None);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(empty_precommit_2), std::move(live_observed_2),
            std::move(live_truth_2));
    });
    auto fresh_precommit_2 = exact_precommit(selected);
    auto fresh_observed_2 =
        CounterfactualFeasibilityBridge::test_only_observation(
            selected, TestOnlyCounterfactualFault::None);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(fresh_precommit_2), std::move(fresh_observed_2),
            std::move(live_truth_2));
    });

    // Each linear source stage is one-shot.
    auto empty_source = CounterfactualFeasibilityBridge::test_only_live_source(
        selected, TestOnlyCounterfactualFault::None);
    auto consumed_residual =
        CounterfactualFullW1WitnessBridge::construct_and_verify(
            std::move(empty_source));
    expect_refused([&] {
        (void)CounterfactualFullW1WitnessBridge::construct_and_verify(
            std::move(empty_source));
    });

    auto consumed_joint =
        CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(consumed_residual));
    expect_refused([&] {
        (void)CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(consumed_residual));
    });

    // Empty shape: the otherwise-live joint closure is burned at entry.
    auto empty_shape = exact_shape(selected);
    auto discarded_result =
        CounterfactualFeasibilityBridge::close_full_witness(
            std::move(empty_shape), std::move(consumed_joint));
    (void)discarded_result;
    auto live_joint = exact_joint(selected);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::close_full_witness(
            std::move(empty_shape), std::move(live_joint));
    });
    auto fresh_shape = exact_shape(selected);
    auto fresh_joint = exact_joint(selected);
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::close_full_witness(
            std::move(fresh_shape), std::move(live_joint));
    });
    // The failed mixed replay burned the fresh shape too.
    expect_refused([&] {
        (void)CounterfactualFeasibilityBridge::close_full_witness(
            std::move(fresh_shape), std::move(fresh_joint));
    });
}

} // namespace

int main() {
    static_assert(!std::default_initializable<
                  CounterfactualPlanSelectionAuthority>);
    static_assert(!std::copy_constructible<
                  CounterfactualPlanSelectionAuthority>);
    static_assert(std::move_constructible<
                  CounterfactualPlanSelectionAuthority>);
    static_assert(!std::default_initializable<
                  CounterfactualPrecommitAuthority>);
    static_assert(!std::copy_constructible<
                  CounterfactualPrecommitAuthority>);
    static_assert(std::move_constructible<
                  CounterfactualPrecommitAuthority>);
    static_assert(!std::default_initializable<
                  ObservationCandidateResidualAuthority>);
    static_assert(!std::copy_constructible<
                  ObservationCandidateResidualAuthority>);
    static_assert(std::move_constructible<
                  ObservationCandidateResidualAuthority>);
    static_assert(!std::default_initializable<
                  PostBarrierTruthResidualAuthority>);
    static_assert(!std::copy_constructible<
                  PostBarrierTruthResidualAuthority>);
    static_assert(std::move_constructible<
                  PostBarrierTruthResidualAuthority>);
    static_assert(!std::default_initializable<
                  CounterfactualFeasibilityAuthority>);
    static_assert(!std::copy_constructible<
                  CounterfactualFeasibilityAuthority>);
    static_assert(std::move_constructible<
                  CounterfactualFeasibilityAuthority>);
    static_assert(!std::default_initializable<
                  CounterfactualArithmeticShapeAuthority>);
    static_assert(!std::copy_constructible<
                  CounterfactualArithmeticShapeAuthority>);
    static_assert(std::move_constructible<
                  CounterfactualArithmeticShapeAuthority>);
    static_assert(!std::default_initializable<
                  LiveCounterfactualSourceInstanceAuthority>);
    static_assert(!std::copy_constructible<
                  LiveCounterfactualSourceInstanceAuthority>);
    static_assert(std::move_constructible<
                  LiveCounterfactualSourceInstanceAuthority>);
    static_assert(!std::default_initializable<
                  FullW1WithCloseResidualAuthority>);
    static_assert(!std::copy_constructible<
                  FullW1WithCloseResidualAuthority>);
    static_assert(std::move_constructible<
                  FullW1WithCloseResidualAuthority>);
    static_assert(!std::default_initializable<
                  CounterfactualJointClosureAuthority>);
    static_assert(!std::copy_constructible<
                  CounterfactualJointClosureAuthority>);
    static_assert(std::move_constructible<
                  CounterfactualJointClosureAuthority>);
    static_assert(!std::default_initializable<
                  CounterfactualFeasibilityTransfer>);
    static_assert(!std::copy_constructible<
                  CounterfactualFeasibilityTransfer>);
    static_assert(std::move_constructible<
                  CounterfactualFeasibilityTransfer>);
    static_assert(!kCounterfactualFeasibilityStatus.production_plan_minter);
    static_assert(!kCounterfactualFeasibilityStatus.observation_join_friend);
    static_assert(
        !kCounterfactualFeasibilityStatus.post_barrier_score_join_friend);
    static_assert(
        kCounterfactualFeasibilityStatus.pinned_rust_full_w1_typed_bridge);
    static_assert(
        !kCounterfactualFeasibilityStatus.rust_full_w1_closure_consumer);
    static_assert(
        !kCounterfactualFeasibilityStatus.full_w1_witness_constructor);
    static_assert(
        !kCounterfactualFeasibilityStatus.exact_full_relation_satisfaction_check);
    static_assert(
        !kCounterfactualFeasibilityStatus.complete_close_descendant_check);
    static_assert(!kCounterfactualFeasibilityStatus.selected_runtime_callsite);
    static_assert(!kCounterfactualFeasibilityStatus.configured);
    valid_two_round_rewire_mints_one_opaque_authority();
    every_invalid_precommit_refuses();
    every_invalid_post_barrier_join_refuses();
    mixed_replay_burns_every_supplied_capability();
}
