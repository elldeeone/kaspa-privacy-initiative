#pragma once

// Complete, dependency-neutral contract for the only consumer that may turn
// a genuine two-round registered-parent trial completion into the six party
// inputs of the private measurement capture join.  Both granting headers
// include this definition before friendship is declared, so a hostile
// translation unit cannot define a same-named friend.

#include <utility>

namespace kpb::measurement { class TrialCaptureJoiner; }

namespace kpi::mpc::financial::registered_driver {

class RegisteredParentTrialCompletionAuthority;

// Opaque lifetime carrier for the two retained projections and conditional
// baseline owner effects after the six public party completions have entered
// TrialCaptureJoiner. It has no receipt, split, or public constructor.
class RegisteredMeasurementCaptureRetention final {
    using Deleter = void (*)(void*) noexcept;
    void* storage_{};
    Deleter deleter_{};
    RegisteredMeasurementCaptureRetention(void* storage, Deleter deleter)
        : storage_(storage), deleter_(deleter) {}
    friend class RegisteredMeasurementCaptureBridge;
public:
    RegisteredMeasurementCaptureRetention(
        const RegisteredMeasurementCaptureRetention&) = delete;
    RegisteredMeasurementCaptureRetention& operator=(
        const RegisteredMeasurementCaptureRetention&) = delete;
    RegisteredMeasurementCaptureRetention(
            RegisteredMeasurementCaptureRetention&& other) noexcept
        : storage_(std::exchange(other.storage_, nullptr)),
          deleter_(std::exchange(other.deleter_, nullptr)) {}
    RegisteredMeasurementCaptureRetention& operator=(
        RegisteredMeasurementCaptureRetention&&) = delete;
    ~RegisteredMeasurementCaptureRetention() {
        if (storage_ != nullptr && deleter_ != nullptr) deleter_(storage_);
    }
};

class RegisteredMeasurementCaptureBridge final {
    RegisteredMeasurementCaptureBridge() = delete;
    static void destroy_retention(void*) noexcept;
public:
    static void submit(
        kpb::measurement::TrialCaptureJoiner&,
        RegisteredParentTrialCompletionAuthority&&);
};

} // namespace kpi::mpc::financial::registered_driver
