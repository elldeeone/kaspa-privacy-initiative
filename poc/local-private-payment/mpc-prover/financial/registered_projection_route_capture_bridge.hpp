#pragma once

// Fully-defined, descriptor-free join between the genuine role-0 projection
// route completion and its retained capture session. The implementation alone
// may inspect the route/projection identities; callers cannot supply strings,
// digests, booleans, descriptors, or JSON as route authority.

namespace kpi::mpc::financial::registered_driver {

class RegisteredCaptureSession;
namespace projection_route { class Role0ProjectionRouteWriterAuthority; }

class RegisteredProjectionRouteCaptureBridge final {
    RegisteredProjectionRouteCaptureBridge() = delete;
public:
    static void consume(
        RegisteredCaptureSession&,
        projection_route::Role0ProjectionRouteWriterAuthority&&);
};

} // namespace kpi::mpc::financial::registered_driver
