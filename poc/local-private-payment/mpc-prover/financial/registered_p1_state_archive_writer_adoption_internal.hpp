#pragma once

// Private shared definition for the SCM bridge and capsule implementation.
// Only the exact friends in the complete public contract may access it.

#include "registered_p1_state_archive_writer_adoption_contract.hpp"
#include "../../private_batch_trial/privacy_measurement_authority.hpp"

#include <cstdint>

namespace kpi::mpc::financial::registered_driver {

struct P1StateArchiveWriterAdoptionAuthority::Storage {
    int writer{-1};
    unsigned round{};
    std::int64_t parent_pid{-1};
    std::int64_t child_pid{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint32_t mode{};
    std::uint64_t nlink{};
    std::uint64_t size{};
    kpb::measurement::Digest reservation_identity{};
    kpb::measurement::Digest activation_identity{};
    bool live{true};
    ~Storage();
};

} // namespace kpi::mpc::financial::registered_driver
