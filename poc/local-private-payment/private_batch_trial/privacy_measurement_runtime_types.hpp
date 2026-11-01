#pragma once

#include "privacy_measurement_authority.hpp"

#include <cstdint>
#include <limits>

namespace kpb::measurement::runtime_bridge {

enum class RuntimeChildRole : unsigned char {
    Observer = 1,
    OwnerScore = 2,
    Aggregate = 3,
    OwnerComparison = 4,
};

inline constexpr unsigned NO_OWNER = std::numeric_limits<unsigned>::max();

// Public data is never authority. Only the authenticated parent transport may
// turn this exact receipt into ChildCompletionEvidenceAuthority.
struct PublicRuntimeChildCompletion {
    RuntimeChildRole role{};
    unsigned owner{NO_OWNER};
    Digest permit_identity{};
    WorkerBinding worker{};
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest transport_session{};
    Digest offer_identity{};
    Digest child_exit_identity{};
    // Fresh opaque capabilities, never unsalted body/outcome hashes.
    Digest opaque_completion_authority_identity{};
    Digest opaque_capsule_authority_identity{};
    std::uint64_t authenticated_pid{};
    std::uint64_t waited_pid{};
    int exit_code{-1};
    int term_signal{-1};
    bool credentials_verified{};
    bool offer_acknowledged{};
    bool eof_observed{};
    AggregateOutcome aggregate_outcome{};
    OwnerComparisonOutcome comparison_outcome{};
    Digest process_identity{};
};

Digest recompute_process_identity(const PublicRuntimeChildCompletion&);

} // namespace kpb::measurement::runtime_bridge
