#pragma once

#include "privacy_observation_barrier_fanout_contract.hpp"
#include "privacy_measurement_worker_capsule.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

namespace kpb::measurement::observation_fanout {

// Retains the original sealed Observer output, empirical residual, exact open
// v3 inventory, and three independently reopened FD41 endpoints. This is
// deliberately not a BarrierFreezeAuthority or score permit.
class OpenObservationFanoutAuthority final {
    void* retained_join_storage_{};
    void (*destroy_join_storage_)(void*) noexcept{};
    Digest barrier_{};
    std::uint64_t device_{};
    std::uint64_t inode_{};
    std::uint64_t exact_size_{};
    std::array<std::unique_ptr<runtime_bridge::
        MeasurementInputEndpointAuthority>, 3> endpoints_{};
    std::array<std::uint64_t, 3> endpoint_devices_{};
    std::array<std::uint64_t, 3> endpoint_inodes_{};
    std::array<bool, 3> endpoint_read_only_{};
    std::atomic_bool live_{true};
    OpenObservationFanoutAuthority(
        void*, void (*)(void*) noexcept, Digest, std::uint64_t,
        std::uint64_t, std::uint64_t,
        std::array<std::unique_ptr<runtime_bridge::
            MeasurementInputEndpointAuthority>, 3>&&,
        std::array<std::uint64_t, 3>,
        std::array<std::uint64_t, 3>, std::array<bool, 3>);
    friend class ObservationBarrierFanoutBridge;
public:
    OpenObservationFanoutAuthority(
        const OpenObservationFanoutAuthority&) = delete;
    OpenObservationFanoutAuthority& operator=(
        const OpenObservationFanoutAuthority&) = delete;
    OpenObservationFanoutAuthority(
        OpenObservationFanoutAuthority&&) noexcept;
    OpenObservationFanoutAuthority& operator=(
        OpenObservationFanoutAuthority&&) = delete;
    ~OpenObservationFanoutAuthority();
#ifdef KPB_OBSERVATION_BARRIER_FANOUT_TEST_SETUP
    struct TestOnlySummary {
        Digest barrier{};
        std::uint64_t device{};
        std::uint64_t inode{};
        std::uint64_t exact_size{};
        std::array<runtime_bridge::PublicMeasurementInputEndpoint, 3>
            endpoints{};
        std::array<std::uint64_t, 3> endpoint_devices{};
        std::array<std::uint64_t, 3> endpoint_inodes{};
        std::array<bool, 3> endpoint_read_only{};
    };
    TestOnlySummary test_only_summary() const;
#endif
};

struct ObservationFanoutSourceStatus {
    bool sealed_join_consumed{};
    bool salted_barrier_identity{};
    bool independent_fd41_fanout{};
    bool open_v3_nonauthorizing{};
    bool barrier_freeze_authority{};
    bool score_permit_authority{};
    bool selected_runtime_callsite{};
    bool configured{};
};

inline constexpr ObservationFanoutSourceStatus
kObservationFanoutSourceStatus{
    .sealed_join_consumed = true,
    .salted_barrier_identity = true,
    .independent_fd41_fanout = true,
    .open_v3_nonauthorizing = true,
};

} // namespace kpb::measurement::observation_fanout
