#pragma once

#include <cstddef>

// Private child-to-parent transport for baseline owner scoring truth.  The
// endpoint authorities are minted only by RegisteredParentRoleFork; this
// complete bridge definition is the only endpoint friend and never exposes a
// descriptor, packet, digest, JSON object, or caller-selected binding.

namespace kpi::mpc::financial::registered_driver {

class ChildRoleCompletionEndpointAuthority;
class ParentRoleCompletionEndpointAuthority;

namespace baseline_disclosure {

class PartyBaselineOwnerEffectsAuthority;

class BaselineOwnerScoringParentTransport final {
public:
    static constexpr std::size_t PACKET_BYTES = 1524;
    static void submit(
        PartyBaselineOwnerEffectsAuthority&&,
        ChildRoleCompletionEndpointAuthority&&);
    static PartyBaselineOwnerEffectsAuthority receive(
        ParentRoleCompletionEndpointAuthority&&);
};

} // namespace baseline_disclosure
} // namespace kpi::mpc::financial::registered_driver
