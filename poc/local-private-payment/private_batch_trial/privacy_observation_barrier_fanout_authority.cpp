#include "privacy_observation_barrier_fanout_authority.hpp"

#include <utility>

namespace kpb::measurement::observation_fanout {

OpenObservationFanoutAuthority::OpenObservationFanoutAuthority(
        void* retained_join_storage,
        void (*destroy_join_storage)(void*) noexcept,
        Digest barrier, std::uint64_t device, std::uint64_t inode,
        std::uint64_t exact_size,
        std::array<std::unique_ptr<runtime_bridge::
            MeasurementInputEndpointAuthority>, 3>&& endpoints,
        std::array<std::uint64_t, 3> endpoint_devices,
        std::array<std::uint64_t, 3> endpoint_inodes,
        std::array<bool, 3> endpoint_read_only)
    : retained_join_storage_(retained_join_storage),
      destroy_join_storage_(destroy_join_storage), barrier_(barrier),
      device_(device), inode_(inode), exact_size_(exact_size),
      endpoints_(std::move(endpoints)),
      endpoint_devices_(endpoint_devices), endpoint_inodes_(endpoint_inodes),
      endpoint_read_only_(endpoint_read_only) {
    if (retained_join_storage_ == nullptr ||
        destroy_join_storage_ == nullptr)
        throw Refused();
}

OpenObservationFanoutAuthority::OpenObservationFanoutAuthority(
        OpenObservationFanoutAuthority&& other) noexcept
    : retained_join_storage_(
          std::exchange(other.retained_join_storage_, nullptr)),
      destroy_join_storage_(
          std::exchange(other.destroy_join_storage_, nullptr)),
      barrier_(other.barrier_), device_(other.device_), inode_(other.inode_),
      exact_size_(other.exact_size_), endpoints_(std::move(other.endpoints_)),
      endpoint_devices_(other.endpoint_devices_),
      endpoint_inodes_(other.endpoint_inodes_),
      endpoint_read_only_(other.endpoint_read_only_),
      live_(other.live_.exchange(false)) {}

OpenObservationFanoutAuthority::~OpenObservationFanoutAuthority() {
    if (retained_join_storage_ != nullptr)
        destroy_join_storage_(retained_join_storage_);
}

#ifdef KPB_OBSERVATION_BARRIER_FANOUT_TEST_SETUP
OpenObservationFanoutAuthority::TestOnlySummary
OpenObservationFanoutAuthority::test_only_summary() const {
    if (!live_.load() || retained_join_storage_ == nullptr)
        throw Refused();
    TestOnlySummary result{
        .barrier = barrier_,
        .device = device_,
        .inode = inode_,
        .exact_size = exact_size_,
        .endpoint_devices = endpoint_devices_,
        .endpoint_inodes = endpoint_inodes_,
        .endpoint_read_only = endpoint_read_only_,
    };
    for (unsigned owner = 0; owner < endpoints_.size(); ++owner) {
        if (endpoints_[owner] == nullptr) throw Refused();
        result.endpoints[owner] = endpoints_[owner]->public_receipt();
    }
    return result;
}
#endif

} // namespace kpb::measurement::observation_fanout
