#pragma once

// Complete neutral contract for the future mandatory failed-view sink.  The
// selected root, exact byte schedule and canonical serializer do not exist in
// this source state, so this declaration has deliberately no implementation
// and grants no friendship to an authority.

namespace kpb::measurement::fresh_trial_owner {
class AllBranchFreshTrialStepAuthority;
}

namespace kpb::measurement::durable_failed_view {

class DurableFailedViewSinkAuthority;
class SelectedDurableFailedViewSinkRootAuthority;
class SelectedDurableFailedViewByteScheduleAuthority;

class DurableFailedViewSinkBridge final {
    DurableFailedViewSinkBridge() = delete;
public:
    static DurableFailedViewSinkAuthority persist_failed_view(
        fresh_trial_owner::AllBranchFreshTrialStepAuthority&&,
        SelectedDurableFailedViewSinkRootAuthority&&,
        SelectedDurableFailedViewByteScheduleAuthority&&);
};

} // namespace kpb::measurement::durable_failed_view
