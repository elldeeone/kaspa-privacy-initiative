#pragma once

// Complete contract for the only parent-authorized pre-route all-party
// release barrier. Keeping this class complete before private friendship is
// granted prevents hostile exact-name friend definitions.

namespace kpi::mpc::financial::registered_driver {

class PartyReleaseReadyAuthority;
class PartyReleaseAuthorizationAuthority;
class ChildRoleCompletionEndpointAuthority;
class ParentRoleChildren;

class RegisteredFullCohortReleaseBarrier final {
    RegisteredFullCohortReleaseBarrier() = delete;
public:
    static PartyReleaseAuthorizationAuthority arrive_and_wait(
        PartyReleaseReadyAuthority&&,
        ChildRoleCompletionEndpointAuthority&);
    static void authorize(ParentRoleChildren&);
};

} // namespace kpi::mpc::financial::registered_driver
