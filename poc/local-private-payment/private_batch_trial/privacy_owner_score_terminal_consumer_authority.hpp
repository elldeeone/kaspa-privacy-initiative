#pragma once

#include "privacy_owner_score_terminal_consumer_contract.hpp"

namespace kpb::measurement::score_terminal {

// Required future chronology:
//  1. the selected source-owned compact lineage must already have produced the
//     all-three score outcome retained by RunMeasurement;
//  2. a durable STOP sink and an aggregate/comparison success consumer must be
//     acquired and preallocated before that outcome is claimed;
//  3. the sole bridge burns all three capabilities and routes STOP durably;
//     the success arm requires aggregate completion carrying all comparison residuals
//     into the final aggregate-plus-comparison consumer;
//  4. it returns one opaque result and exposes no arm, receipt, digest, fd,
//     bool, optional residual or caller-selected continuation.
//
// None of those source capabilities exists yet. These move-only types reserve
// the exact boundary but intentionally have no production or test mint.

class RunMeasurementOwnerScoreOutcomeTransferAuthority final {
    void* storage_{};
    void (*destroy_storage_)(void*) noexcept{};
    RunMeasurementOwnerScoreOutcomeTransferAuthority(
        void*, void (*)(void*) noexcept) noexcept;
public:
    RunMeasurementOwnerScoreOutcomeTransferAuthority(
        const RunMeasurementOwnerScoreOutcomeTransferAuthority&) = delete;
    RunMeasurementOwnerScoreOutcomeTransferAuthority& operator=(
        const RunMeasurementOwnerScoreOutcomeTransferAuthority&) = delete;
    RunMeasurementOwnerScoreOutcomeTransferAuthority(
        RunMeasurementOwnerScoreOutcomeTransferAuthority&&) noexcept;
    RunMeasurementOwnerScoreOutcomeTransferAuthority& operator=(
        RunMeasurementOwnerScoreOutcomeTransferAuthority&&) = delete;
    ~RunMeasurementOwnerScoreOutcomeTransferAuthority();
};

class OwnerScoreDurableStopSinkAuthority final {
    void* storage_{};
    void (*destroy_storage_)(void*) noexcept{};
    OwnerScoreDurableStopSinkAuthority(
        void*, void (*)(void*) noexcept) noexcept;
public:
    OwnerScoreDurableStopSinkAuthority(
        const OwnerScoreDurableStopSinkAuthority&) = delete;
    OwnerScoreDurableStopSinkAuthority& operator=(
        const OwnerScoreDurableStopSinkAuthority&) = delete;
    OwnerScoreDurableStopSinkAuthority(
        OwnerScoreDurableStopSinkAuthority&&) noexcept;
    OwnerScoreDurableStopSinkAuthority& operator=(
        OwnerScoreDurableStopSinkAuthority&&) = delete;
    ~OwnerScoreDurableStopSinkAuthority();
};

class OwnerScoreAggregateComparisonConsumerAuthority final {
    void* storage_{};
    void (*destroy_storage_)(void*) noexcept{};
    OwnerScoreAggregateComparisonConsumerAuthority(
        void*, void (*)(void*) noexcept) noexcept;
public:
    OwnerScoreAggregateComparisonConsumerAuthority(
        const OwnerScoreAggregateComparisonConsumerAuthority&) = delete;
    OwnerScoreAggregateComparisonConsumerAuthority& operator=(
        const OwnerScoreAggregateComparisonConsumerAuthority&) = delete;
    OwnerScoreAggregateComparisonConsumerAuthority(
        OwnerScoreAggregateComparisonConsumerAuthority&&) noexcept;
    OwnerScoreAggregateComparisonConsumerAuthority& operator=(
        OwnerScoreAggregateComparisonConsumerAuthority&&) = delete;
    ~OwnerScoreAggregateComparisonConsumerAuthority();
};

class OwnerScoreTerminalConsumeResultAuthority final {
    void* storage_{};
    void (*destroy_storage_)(void*) noexcept{};
    OwnerScoreTerminalConsumeResultAuthority(
        void*, void (*)(void*) noexcept) noexcept;
public:
    OwnerScoreTerminalConsumeResultAuthority(
        const OwnerScoreTerminalConsumeResultAuthority&) = delete;
    OwnerScoreTerminalConsumeResultAuthority& operator=(
        const OwnerScoreTerminalConsumeResultAuthority&) = delete;
    OwnerScoreTerminalConsumeResultAuthority(
        OwnerScoreTerminalConsumeResultAuthority&&) noexcept;
    OwnerScoreTerminalConsumeResultAuthority& operator=(
        OwnerScoreTerminalConsumeResultAuthority&&) = delete;
    ~OwnerScoreTerminalConsumeResultAuthority();
};

struct OwnerScoreTerminalConsumerSourceStatus final {
    bool requires_preacquired_stop_and_success_consumers{};
    bool no_public_arm_or_optional_residual{};
    bool run_measurement_transfer{};
    bool durable_stop_sink{};
    bool aggregate_comparison_consumer{};
    bool closed_sum_consumer{};
    bool aggregate_completion_carries_comparison{};
    bool final_privacy_pass{};
    bool selected_callsite{};
    bool configured{};
};

inline constexpr OwnerScoreTerminalConsumerSourceStatus
kOwnerScoreTerminalConsumerSourceStatus{
    .requires_preacquired_stop_and_success_consumers = true,
    .no_public_arm_or_optional_residual = true,
    .run_measurement_transfer = false,
    .durable_stop_sink = false,
    .aggregate_comparison_consumer = false,
    .closed_sum_consumer = false,
    .aggregate_completion_carries_comparison = false,
    .final_privacy_pass = false,
    .selected_callsite = false,
    .configured = false,
};

} // namespace kpb::measurement::score_terminal
