#include "registered_capture_plan_roster_bridge.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

} // namespace

RosterBoundCapturePlan::RosterBoundCapturePlan(
        CapturePlanAuthority&& capture,
        ImmutableRegisteredRosterAuthority&& roster)
    : capture_(std::move(capture)), roster_(std::move(roster)) {}

CapturePlanAuthority RosterBoundCapturePlan::take_capture_plan() {
    need(capture_.has_value());
    auto result = std::move(*capture_);
    capture_.reset();
    return result;
}

ImmutableRegisteredRosterAuthority RosterBoundCapturePlan::take_roster() {
    need(roster_.has_value());
    auto result = std::move(*roster_);
    roster_.reset();
    return result;
}

RosterBoundCapturePlan RegisteredCapturePlanRosterBridge::bind(
        CapturePlanAuthority&& capture,
        ImmutableRegisteredRosterAuthority&& roster) {
    try {
        const bool capture_was_live = capture.live_.exchange(false);
        const bool roster_was_live = roster.live_.exchange(false);
        need(capture_was_live && roster_was_live);
        CapturePlanAuthorityBridge::require_valid(capture);
        roster.require_valid_for_capture_plan();
        need(capture.scope_ == CapturePlanAuthority::Scope::Parent &&
             capture.computing_role_ == 3 &&
             capture.value_.capture_trial_id ==
                 roster.value_.registered_binding.trial_id &&
             capture.value_.trial == trial_identity(
                 roster.value_.registered_binding.trial_id) &&
             capture.value_.attempt == attempt_identity(
                 capture.value_.capture_attempt_id));

        CapturePlanAuthority capture_residual(capture.value_);
        ImmutableRegisteredRosterAuthority roster_residual(roster.value_);
        return RosterBoundCapturePlan(
            std::move(capture_residual), std::move(roster_residual));
    } catch (...) { refuse(); }
}

} // namespace kpi::mpc::financial::registered_driver
