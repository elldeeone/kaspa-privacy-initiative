#pragma once

#include "registered_driver_bridge.hpp"
#include "registered_projection_route_capture_bridge.hpp"
#include "../owner_cohort_observer.hpp"

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <utility>

namespace kpi::mpc::financial::registered_driver {

namespace baseline_disclosure {
class ExplicitOwnerPublicEffectsAuthority;
class BaselineTerminalOwnerMappingAuthority;
}

class RegisteredCaptureSession;

// Fully defined call-site bridges replace forward-declared friendship. A
// different translation unit cannot define a lookalike FinancialConstruction,
// FinancialHistoryAccess, or EgressRelease to acquire private session access.
class RegisteredCaptureConstructionBridge final {
    RegisteredCaptureConstructionBridge() = delete;
public:
    static void listeners_ready(RegisteredCaptureSession&);
};

class RegisteredCaptureEgressBridge final {
    RegisteredCaptureEgressBridge() = delete;
public:
    static void released_projection(
        RegisteredCaptureSession&, std::span<const unsigned char>);
};

class RegisteredBaselineObserverCaptureBridge final {
    RegisteredBaselineObserverCaptureBridge() = delete;
public:
    static baseline_disclosure::BaselineTerminalOwnerMappingAuthority
    explicit_owner_public_effects(
        RegisteredCaptureSession&,
        baseline_disclosure::ExplicitOwnerPublicEffectsAuthority&&);
};

// The selected registered build owns exactly one dispatcher/projection stream.
// P1/P2 still validate and execute the same MPC but never touch these FDs.
inline constexpr unsigned CAPTURE_STREAM_OWNER_ROLE = 0;

// One source-owned capture session. The only factory burns an admitted
// CapturePlanAuthority; there is no JSON/digest/bool constructor. The session
// starts the dispatcher channel before head recheck/LOCK, observes the genuine
// owner socket boundary, and captures projection/aggregate release only from
// verified durable EGRESS. The private route bridge can close the dispatcher
// only after the parent reads the exact retained projection, observes kernel
// EOF and ACKs it; the selected role-child call site remains unconfigured.
class RegisteredCaptureSession final : public PrivateOwnerCohortObserver {
    class Impl;
    std::unique_ptr<Impl> impl_;

    explicit RegisteredCaptureSession(CapturePlanAuthority&&,
                                      unsigned computing_role);
    static std::unique_ptr<RegisteredCaptureSession> begin(
        CapturePlanAuthority&&, unsigned computing_role);
    void listeners_ready();
    void released_projection(std::span<const unsigned char> projection);
    baseline_disclosure::BaselineTerminalOwnerMappingAuthority
    explicit_owner_public_effects(
        baseline_disclosure::ExplicitOwnerPublicEffectsAuthority&&);
    const Digest& plan_identity() const;
    const Digest& projection_identity() const;
    void require_baseline_effects_ready() const;
    void require_egress_completion_ready() const;
    const PublicCapturePlan& route_capture_plan() const;
    const std::array<std::byte, 10685>&
        retained_projection_for_route() const;
    void close_after_projection_route(
        const Digest& route_identity, const Digest& projection_identity);

    friend class DriverAttempt;
    friend class AuthorizedDriverAttempt;
    friend class RegisteredCaptureConstructionBridge;
    friend class RegisteredCaptureEgressBridge;
    friend class RegisteredBaselineObserverCaptureBridge;
    friend class RegisteredProjectionRouteCaptureBridge;

public:
    ~RegisteredCaptureSession() override;
    RegisteredCaptureSession(const RegisteredCaptureSession&) = delete;
    RegisteredCaptureSession& operator=(const RegisteredCaptureSession&) = delete;
    RegisteredCaptureSession(RegisteredCaptureSession&&) = delete;
    RegisteredCaptureSession& operator=(RegisteredCaptureSession&&) = delete;

    // These callbacks remain owner-private. The session itself is retained by
    // the registered driver authority and is never returned by a public API.
    void owner_authenticated(unsigned owner) override;
    void owner_upload_complete(unsigned owner,
                               std::size_t fixed_frame_bytes) override;
#ifdef KPI_REGISTERED_CAPTURE_SESSION_TEST_SETUP
    static std::unique_ptr<RegisteredCaptureSession> test_only_begin(
        CapturePlanAuthority&& authority, unsigned computing_role) {
        return begin(std::move(authority), computing_role);
    }
    void test_only_listeners_ready() { listeners_ready(); }
    void test_only_released_projection(
        std::span<const unsigned char> projection) {
        released_projection(projection);
    }
    const Digest& test_only_projection_identity() const {
        return projection_identity();
    }
    const Digest& test_only_plan_identity() const { return plan_identity(); }
    void test_only_corrupt_retained_projection();
    void test_only_corrupt_projection_identity();
    bool test_only_route_complete() const;
#endif
};

} // namespace kpi::mpc::financial::registered_driver
