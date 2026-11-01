#pragma once

#include "registered_capture_plan_roster_bridge_contract.hpp"
#include "registered_driver_bridge.hpp"
#include "registered_parent_bootstrap_contract.hpp"
#include "registered_roster_crypto_player.hpp"

#include <optional>

namespace kpi::mpc::financial::registered_driver {

// Linear result of binding one genuine immutable roster authority to one
// parent capture plan. Both residual capabilities must be taken explicitly;
// neither can be reconstructed from the raw UUID or its public digest.
class RosterBoundCapturePlan final {
    std::optional<CapturePlanAuthority> capture_;
    std::optional<ImmutableRegisteredRosterAuthority> roster_;
    RosterBoundCapturePlan(
        CapturePlanAuthority&&,
        ImmutableRegisteredRosterAuthority&&);
    friend class RegisteredCapturePlanRosterBridge;
    friend class RegisteredParentBootstrapTransport;
public:
    RosterBoundCapturePlan(const RosterBoundCapturePlan&) = delete;
    RosterBoundCapturePlan& operator=(const RosterBoundCapturePlan&) = delete;
    RosterBoundCapturePlan(RosterBoundCapturePlan&&) noexcept = default;
    RosterBoundCapturePlan& operator=(RosterBoundCapturePlan&&) = delete;

    CapturePlanAuthority take_capture_plan();
    ImmutableRegisteredRosterAuthority take_roster();
};

} // namespace kpi::mpc::financial::registered_driver
