#pragma once

// Complete neutral contract shared by the driver and immutable-roster
// authority headers. Defining the bridge here prevents an external
// translation unit from defining a lookalike friend with private access.

#include "registered_identity_registry.hpp"

#include <string_view>

namespace kpi::mpc::financial {

class ImmutableRegisteredRosterAuthority;

namespace registered_driver {

class CapturePlanAuthority;
class RosterBoundCapturePlan;

class RegisteredCapturePlanRosterBridge final {
    RegisteredCapturePlanRosterBridge() = delete;
public:
    // Public formula, not an authority factory. It pins the canonical raw
    // trial UUID to the digest used throughout the registered lineage.
    static identity_registry::Digest trial_identity(std::string_view);
    static identity_registry::Digest attempt_identity(std::string_view);

    // Consumes both live capabilities. There is deliberately no overload
    // accepting a roster receipt, UUID string, digest, JSON, path or fd.
    static RosterBoundCapturePlan bind(
        CapturePlanAuthority&&,
        ImmutableRegisteredRosterAuthority&&);
};

} // namespace registered_driver
} // namespace kpi::mpc::financial
