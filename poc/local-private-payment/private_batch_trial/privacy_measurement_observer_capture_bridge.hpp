#pragma once

// Fully defined friendship boundary for the sole observer-admission consumer.
// A public permit or closure receipt is intentionally insufficient: admit()
// first consumes the live producer spool and C03 launch capabilities.  The
// resulting opaque authority is carried through trial capture and RunMeasurement
// before prepare() snapshots the exact ten sealed raw-stream objects into one
// sealed FD40
// capsule and returns an execution-only permit plus sealed worker capsule.

#include "privacy_measurement_observer_capture_bridge_contract.hpp"

#include <atomic>
#include <memory>
#include <optional>

namespace kpb::measurement {
class ObserverPermitAuthority;
class ObserverExecutionPermitAuthority;
struct PublicObserverPermit;
struct ProducerClosureEvidence;
struct PublicProducerClosure;
struct RunBinding;
namespace producer_supervisor {
class ProducerSpoolAuthority;
class C03RoleLaunchAdmissionAuthority;
}
namespace c1_capture { class C1PostcaptureAdmissionAuthority; }
namespace runtime_bridge {
class MeasurementWorkerCapsuleAuthority;

class ObserverAdmissionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ObserverAdmissionAuthority(std::unique_ptr<Storage>);
    friend class ObserverCaptureCapsuleBridge;
public:
    ObserverAdmissionAuthority(
        const ObserverAdmissionAuthority&) = delete;
    ObserverAdmissionAuthority& operator=(
        const ObserverAdmissionAuthority&) = delete;
    ObserverAdmissionAuthority(ObserverAdmissionAuthority&&) noexcept;
    ObserverAdmissionAuthority& operator=(
        ObserverAdmissionAuthority&&) = delete;
    ~ObserverAdmissionAuthority();
    // Possession of the move-only admission is the capability. This operation
    // can only burn/match it; it cannot mint a replacement or expose storage.
    void require_matches(
        const RunBinding&, const PublicProducerClosure&,
        const ProducerClosureEvidence&);
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    // Explicitly unavailable from production.  This carries no spool and is
    // accepted only by authority-state controls, never by prepare().
    static ObserverAdmissionAuthority test_only_mint(
        const RunBinding&);
#endif
};

// Atomic, opaque handoff from terminal-v2 admission into the existing trial
// capture join. It exposes neither half of the conjunction: only
// TrialCaptureJoiner may consume it.
class ObserverTerminalCaptureJoin final {
    std::optional<ObserverAdmissionAuthority> admission_;
    std::atomic_bool live_{true};
    explicit ObserverTerminalCaptureJoin(ObserverAdmissionAuthority&&);
    friend class ObserverCaptureCapsuleBridge;
public:
    ObserverTerminalCaptureJoin(
        const ObserverTerminalCaptureJoin&) = delete;
    ObserverTerminalCaptureJoin& operator=(
        const ObserverTerminalCaptureJoin&) = delete;
    ObserverTerminalCaptureJoin(
        ObserverTerminalCaptureJoin&&) noexcept;
    ObserverTerminalCaptureJoin& operator=(
        ObserverTerminalCaptureJoin&&) = delete;
};

class ObserverCaptureCapsuleHandoff final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ObserverCaptureCapsuleHandoff(std::unique_ptr<Storage>);
    friend class ObserverCaptureCapsuleBridge;
public:
    ObserverCaptureCapsuleHandoff(
        const ObserverCaptureCapsuleHandoff&) = delete;
    ObserverCaptureCapsuleHandoff& operator=(
        const ObserverCaptureCapsuleHandoff&) = delete;
    ObserverCaptureCapsuleHandoff(
        ObserverCaptureCapsuleHandoff&&) noexcept;
    ObserverCaptureCapsuleHandoff& operator=(
        ObserverCaptureCapsuleHandoff&&) = delete;
    ~ObserverCaptureCapsuleHandoff();

    ObserverExecutionPermitAuthority take_execution_permit();
    MeasurementWorkerCapsuleAuthority take_worker_capsule();
};

} // namespace runtime_bridge
} // namespace kpb::measurement
