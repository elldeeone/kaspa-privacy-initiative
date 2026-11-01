#pragma once

// Private shared definition for the capsule TU and the authenticated child
// state-channel bridge only. Access remains restricted by the residual's
// private nested type and exact complete friendship in the public contract.

#include "privacy_p1_corrupt_state_capsule_authority.hpp"

#include <array>
#include <cstdint>

namespace kpb::measurement::p1_state_capsule {

struct P1CorruptStateCapsuleChildDispositionResidual::Storage {
    StaticStateCapsulePlan plan;
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    bool manifest_structurally_complete{};
    bool unavailable{};
    bool aborted{};
    bool read_only{};
    bool anonymous_disk_backed{};
    bool writer_closed{};
    bool descriptor_retained{};
    SourcePhase terminal_phase{};
    AbortClass abort_class{};
    std::uint64_t sequence{};
    std::uint64_t archive_bytes{};
    std::uint64_t missing_family_bitmap{};
    std::uint64_t closed_family_bitmap{};
    std::uint64_t not_constructed_bitmap{};
    std::uint64_t abort_prefix_bitmap{};
    Digest abort_terminal_site_identity{};
    std::array<std::uint64_t, STATE_FAMILY_COUNT> event_counts{};
    Digest archive_sha256{};
};

} // namespace kpb::measurement::p1_state_capsule
