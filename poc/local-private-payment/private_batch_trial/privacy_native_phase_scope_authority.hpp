#pragma once

// Linear native Observer-output evidence. The bridge consumes one
// authenticated sealed FD62 completion plus the opaque native empirical
// residual, validates the exact immutable v3 open-inventory and v2 deferred
// Step-3 sections, and retains the sole FD. It deliberately mints no Step-2,
// prediction, phase, barrier, FD41 or Step-3 permit.

#include "privacy_native_phase_scope_bridge_contract.hpp"
#include "privacy_observation_barrier_fanout_contract.hpp"
#include "privacy_measurement_authority.hpp"

#include <cstddef>

namespace kpb::measurement::runtime_bridge {
struct PrivateChildOutputCompletion;
class SealedChildOutputAuthority;
}

namespace kpb::measurement::phase_scope {

class ObservationOutputFanoutTransfer final {
    void* storage_{};
    void (*destroy_)(void*) noexcept{};
    const runtime_bridge::PrivateChildOutputCompletion* completion_{};
    const Digest* sealed_output_identity_{};
    runtime_bridge::SealedChildOutputAuthority* output_{};
    const unsigned char* deferred_step3_{};
    std::size_t deferred_step3_size_{};
    const unsigned char* open_step2_{};
    std::size_t open_step2_size_{};
    ObservationOutputFanoutTransfer(
        void*, void (*)(void*) noexcept,
        const runtime_bridge::PrivateChildOutputCompletion*, const Digest*,
        runtime_bridge::SealedChildOutputAuthority*,
        const unsigned char*, std::size_t,
        const unsigned char*, std::size_t);
    friend class ObservationOutputJoinAuthority;
    friend class kpb::measurement::observation_fanout::
        ObservationBarrierFanoutBridge;
public:
    ObservationOutputFanoutTransfer(
        const ObservationOutputFanoutTransfer&) = delete;
    ObservationOutputFanoutTransfer& operator=(
        const ObservationOutputFanoutTransfer&) = delete;
    ObservationOutputFanoutTransfer(
        ObservationOutputFanoutTransfer&&) noexcept;
    ObservationOutputFanoutTransfer& operator=(
        ObservationOutputFanoutTransfer&&) = delete;
    ~ObservationOutputFanoutTransfer();
};

class ObservationOutputJoinAuthority final {
    struct Storage;
    void* storage_{};
    void (*destroy_)(void*) noexcept{};
    ObservationOutputJoinAuthority(
        Storage*, void (*)(void*) noexcept);
    ObservationOutputFanoutTransfer transfer_for_observation_fanout() &&;
    friend class NativePrivacyPhaseScopeBridge;
    friend class kpb::measurement::observation_fanout::
        ObservationBarrierFanoutBridge;
public:
    ObservationOutputJoinAuthority(
        const ObservationOutputJoinAuthority&) = delete;
    ObservationOutputJoinAuthority& operator=(
        const ObservationOutputJoinAuthority&) = delete;
    ObservationOutputJoinAuthority(
        ObservationOutputJoinAuthority&&) noexcept;
    ObservationOutputJoinAuthority& operator=(
        ObservationOutputJoinAuthority&&) = delete;
    ~ObservationOutputJoinAuthority() {
        if (storage_ != nullptr) destroy_(storage_);
    }
};

struct NativePhaseScopeSourceStatus {
    bool observer_abi_v3_exact_open_inventory{};
    bool exact_deferred_step3_section{};
    bool sealed_observer_output_retained{};
    bool native_empirical_residual_retained{};
    bool observation_output_linear_join{};
    bool standalone_prediction_permit_removed{};
    bool native_prediction_consumer{};
    bool native_step3_consumer{};
    bool selected_runtime_callsite{};
    bool configured{};
};

inline constexpr NativePhaseScopeSourceStatus kNativePhaseScopeStatus{
    .observer_abi_v3_exact_open_inventory = true,
    .exact_deferred_step3_section = true,
    .sealed_observer_output_retained = true,
    .native_empirical_residual_retained = true,
    .observation_output_linear_join = true,
    .standalone_prediction_permit_removed = true,
};

} // namespace kpb::measurement::phase_scope
