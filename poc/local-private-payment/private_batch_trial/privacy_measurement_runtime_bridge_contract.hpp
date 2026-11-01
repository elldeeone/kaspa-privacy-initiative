#pragma once

// Complete, dependency-neutral contract for the sole runtime completion
// adapter. Authority headers include this definition before granting
// friendship, so another translation unit cannot define the friend name.

namespace kpb::measurement {
class ObserverExecutionPermitAuthority;
class OwnerScoreExecutionPermitAuthority;
class AggregatePermitAuthority;
class OwnerComparisonPermitAuthority;

namespace empirical_result {
class NativeEmpiricalResultAuthority;
}

namespace runtime_bridge {
class ChildCompletionEvidenceAuthority;
class ObservationRuntimeCompletion;
class OwnerScoreRuntimeCompletion;
class AggregateRuntimeCompletion;
class OwnerComparisonRuntimeCompletion;
class SealedChildOutputAuthority;

class RuntimeCompletionBridge final {
    RuntimeCompletionBridge() = delete;
public:
    static ObservationRuntimeCompletion observation(
        ObserverExecutionPermitAuthority&&,
        ChildCompletionEvidenceAuthority&&,
        SealedChildOutputAuthority&&,
        empirical_result::NativeEmpiricalResultAuthority&&);
    static OwnerScoreRuntimeCompletion owner_score(
        OwnerScoreExecutionPermitAuthority&&,
        ChildCompletionEvidenceAuthority&&,
        SealedChildOutputAuthority&&);
    static AggregateRuntimeCompletion aggregate(
        AggregatePermitAuthority&&, ChildCompletionEvidenceAuthority&&);
    static OwnerComparisonRuntimeCompletion owner_comparison(
        OwnerComparisonPermitAuthority&&,
        ChildCompletionEvidenceAuthority&&);
#ifdef KPB_MEASUREMENT_RUNTIME_BRIDGE_TEST_SETUP
    static void test_only_consume(ChildCompletionEvidenceAuthority&&);
#endif
};
} // namespace runtime_bridge
} // namespace kpb::measurement
