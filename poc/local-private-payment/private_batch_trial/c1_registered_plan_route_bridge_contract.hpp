#pragma once

// Complete friendship boundary for the registered C1 plan/route bridge.
//
// The bridge has two chronological halves.  Before launch it consumes an
// opaque registered-lineage child plus an opaque controller selection and
// produces a sealed FD31 offer with a pending terminal residual.  After the
// worker has exited it consumes source-owned controller/route terminal
// authorities before releasing the ordinary C1 observer-admission residual.
// No public receipt, digest, JSON, path, or caller-authored event overload is
// part of this surface.

namespace kpi::mpc::financial::registered_driver {
class RegisteredSelectedProducerPrelaunchBindingAuthority;
}

namespace kpb::measurement::producer_runtime {
class ParentTenReadEndsAuthority;
}

namespace kpb::measurement::c1_capture {

class C1LifecycleStagePlanAuthority;
class C1InvoiceRouteAuthority;
class C1PostcaptureAdmissionAuthority;
class RegisteredC1RoundLineageAuthority;
class RegisteredC1PrelaunchSplit;
class C1AcceptedControllerSelectionAuthority;
class RegisteredC1LaunchSplit;
class RegisteredC1PendingTerminalAuthority;
class C1Fd31QualifiedCompletionAckAuthority;
class C1AcceptedControllerResultAuthority;
class C1ObservedInvoiceRouteAuthority;

class RegisteredC1PlanRouteBridge final {
    RegisteredC1PlanRouteBridge() = delete;
public:
    static RegisteredC1PrelaunchSplit split_registered_prelaunch(
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerPrelaunchBindingAuthority&&);

    static RegisteredC1LaunchSplit prepare(
        producer_runtime::ParentTenReadEndsAuthority&,
        RegisteredC1RoundLineageAuthority&&,
        C1AcceptedControllerSelectionAuthority&&);

    static C1PostcaptureAdmissionAuthority admit_terminal(
        RegisteredC1PendingTerminalAuthority&&,
        C1Fd31QualifiedCompletionAckAuthority&&,
        C1AcceptedControllerResultAuthority&&,
        C1ObservedInvoiceRouteAuthority&&);
};

} // namespace kpb::measurement::c1_capture
