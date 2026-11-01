#pragma once

// Complete, source-owned friendship contract for the C1 prelaunch join.
// Keeping this definition independent of the authority layouts prevents a
// translation unit from defining the formerly forward-declared friend name.

#include "c1_registered_plan_route_bridge_contract.hpp"

namespace kpb::measurement::producer_runtime {
class ParentTenReadEndsAuthority;
}

namespace kpb::measurement::c1_capture {

class C1LifecycleStagePlanAuthority;
class C1InvoiceRouteAuthority;
class C1ContactValueAuthoritySplit;

class C1ContactValueAuthorityBridge final {
    C1ContactValueAuthorityBridge() = delete;
    static C1ContactValueAuthoritySplit prepare_after_registered_claim(
        producer_runtime::ParentTenReadEndsAuthority&,
        C1LifecycleStagePlanAuthority&&,
        C1InvoiceRouteAuthority&&);
    static C1ContactValueAuthoritySplit prepare_impl(
        producer_runtime::ParentTenReadEndsAuthority&,
        C1LifecycleStagePlanAuthority&&,
        C1InvoiceRouteAuthority&&,
        bool parent_round_already_claimed);
    friend class RegisteredC1PlanRouteBridge;
public:
    static C1ContactValueAuthoritySplit prepare(
        producer_runtime::ParentTenReadEndsAuthority&,
        C1LifecycleStagePlanAuthority&&,
        C1InvoiceRouteAuthority&&);
};

} // namespace kpb::measurement::c1_capture
