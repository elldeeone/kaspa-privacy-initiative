#pragma once

#include "privacy_measurement_authority.hpp"
#include "privacy_measurement_child_supervisor.hpp"
#include "privacy_measurement_runtime_bridge_contract.hpp"
#include "privacy_measurement_runtime_types.hpp"

#include <atomic>

namespace kpb::measurement::runtime_bridge {

// Move-only proof that the parent observed the exact selected child, offer,
// completion packet, clean exit and EOF. A serialized struct cannot construct
// this type. MeasurementChildSupervisor is the sole production minter.
class ChildCompletionEvidenceAuthority final {
    PublicRuntimeChildCompletion receipt_;
    std::atomic_bool live_{true};
    explicit ChildCompletionEvidenceAuthority(PublicRuntimeChildCompletion);
    friend class RuntimeCompletionBridge;
    friend class MeasurementChildSupervisor;
public:
    ChildCompletionEvidenceAuthority(
        const ChildCompletionEvidenceAuthority&) = delete;
    ChildCompletionEvidenceAuthority& operator=(
        const ChildCompletionEvidenceAuthority&) = delete;
    ChildCompletionEvidenceAuthority(
        ChildCompletionEvidenceAuthority&&) noexcept;
    ChildCompletionEvidenceAuthority& operator=(
        ChildCompletionEvidenceAuthority&&) = delete;
    const PublicRuntimeChildCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_RUNTIME_BRIDGE_TEST_SETUP
    static ChildCompletionEvidenceAuthority test_only_mint(
        PublicRuntimeChildCompletion);
#endif
};

class ObservationRuntimeCompletion final {
    ObservationRuntimeCompletion(
        ObserverExecutionPermitAuthority&&,
        ObservationCompletionAuthority&&);
    friend class RuntimeCompletionBridge;
public:
    ObserverExecutionPermitAuthority permit;
    ObservationCompletionAuthority completion;
    ObservationRuntimeCompletion(const ObservationRuntimeCompletion&) =
        delete;
    ObservationRuntimeCompletion& operator=(
        const ObservationRuntimeCompletion&) = delete;
    ObservationRuntimeCompletion(ObservationRuntimeCompletion&&) noexcept =
        default;
    ObservationRuntimeCompletion& operator=(
        ObservationRuntimeCompletion&&) = delete;
};

class OwnerScoreRuntimeCompletion final {
    OwnerScoreRuntimeCompletion(
        OwnerScoreExecutionPermitAuthority&&,
        OwnerScoreCompletionAuthority&&);
    friend class RuntimeCompletionBridge;
public:
    OwnerScoreExecutionPermitAuthority permit;
    OwnerScoreCompletionAuthority completion;
    OwnerScoreRuntimeCompletion(const OwnerScoreRuntimeCompletion&) = delete;
    OwnerScoreRuntimeCompletion& operator=(
        const OwnerScoreRuntimeCompletion&) = delete;
    OwnerScoreRuntimeCompletion(OwnerScoreRuntimeCompletion&&) noexcept =
        default;
    OwnerScoreRuntimeCompletion& operator=(
        OwnerScoreRuntimeCompletion&&) = delete;
};

class AggregateRuntimeCompletion final {
    AggregateRuntimeCompletion(
        AggregatePermitAuthority&&, AggregateCompletionAuthority&&);
    friend class RuntimeCompletionBridge;
public:
    AggregatePermitAuthority permit;
    AggregateCompletionAuthority completion;
    AggregateRuntimeCompletion(const AggregateRuntimeCompletion&) = delete;
    AggregateRuntimeCompletion& operator=(
        const AggregateRuntimeCompletion&) = delete;
    AggregateRuntimeCompletion(AggregateRuntimeCompletion&&) noexcept =
        default;
    AggregateRuntimeCompletion& operator=(
        AggregateRuntimeCompletion&&) = delete;
};

class OwnerComparisonRuntimeCompletion final {
    OwnerComparisonRuntimeCompletion(
        OwnerComparisonPermitAuthority&&,
        OwnerComparisonCompletionAuthority&&);
    friend class RuntimeCompletionBridge;
public:
    OwnerComparisonPermitAuthority permit;
    OwnerComparisonCompletionAuthority completion;
    OwnerComparisonRuntimeCompletion(
        const OwnerComparisonRuntimeCompletion&) = delete;
    OwnerComparisonRuntimeCompletion& operator=(
        const OwnerComparisonRuntimeCompletion&) = delete;
    OwnerComparisonRuntimeCompletion(
        OwnerComparisonRuntimeCompletion&&) noexcept = default;
    OwnerComparisonRuntimeCompletion& operator=(
        OwnerComparisonRuntimeCompletion&&) = delete;
};

struct RuntimeBridgeSourceStatus {
    bool evidence_authority{};
    bool authenticated_child_supervisor{};
    bool registered_transport_integrated{};
    bool observation_adapter{};
    bool owner_score_adapter{};
    bool aggregate_adapter{};
    bool owner_comparison_adapter{};
    bool configured{};
    bool launch_enabled{};
    bool actual_privacy_pass{};
};

inline constexpr RuntimeBridgeSourceStatus kRuntimeBridgeSourceStatus{
    .evidence_authority = true,
    .authenticated_child_supervisor = true,
    .observation_adapter = true,
    .owner_score_adapter = true,
    .aggregate_adapter = true,
    .owner_comparison_adapter = true,
};

} // namespace kpb::measurement::runtime_bridge
