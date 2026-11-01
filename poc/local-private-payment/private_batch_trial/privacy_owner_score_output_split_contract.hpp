#pragma once

// Complete dependency-neutral contract for the all-three OwnerScore output
// join. The bridge accepts only one live source-lineage capability plus the
// three live runtime completions; no receipt, digest, descriptor, or
// caller-authored expectation overload exists.

namespace kpb::measurement::runtime_bridge {
class OwnerScoreRuntimeCompletion;
}

namespace kpb::measurement::score_output_split {

class OwnerScoreOutputSplitBundleAuthority;
class OwnerScoreOutputLineageAuthority;
class OwnerScoreOutputSplitOutcomeAuthority;

#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
enum class TestOnlyOwnerScoreSplitFault : unsigned char {
    None,
    BodyMutation,
    WritableReopen,
    CrossOwnerReopen,
    BeforeClaimAllocation,
    PostClaimAllocation,
};
#endif

class OwnerScoreOutputSplitBridge final {
    OwnerScoreOutputSplitBridge() = delete;
    static OwnerScoreOutputSplitOutcomeAuthority split_impl(
        OwnerScoreOutputLineageAuthority&&,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner0,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner1,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner2,
        unsigned char fault);
public:
    static OwnerScoreOutputSplitOutcomeAuthority split(
        OwnerScoreOutputLineageAuthority&&,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner0,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner1,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner2);
#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
    static OwnerScoreOutputSplitOutcomeAuthority test_only_split(
        OwnerScoreOutputLineageAuthority&&,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner0,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner1,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner2,
        TestOnlyOwnerScoreSplitFault);
#endif
};

} // namespace kpb::measurement::score_output_split
