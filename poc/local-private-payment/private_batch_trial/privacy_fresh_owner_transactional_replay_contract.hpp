#pragma once

// Complete dependency-neutral contract for the transactional replay core.
// The eventual FreshOwner join must prepare before claiming Ready/owner
// capabilities and may call commit only after it owns a preallocated STOP
// result.  This contract itself grants no issuance or trial authority.

#include <array>
#include <cstddef>

namespace kpb::measurement::fresh_owner_transactional_replay {

using ReplayIdentity = std::array<unsigned char, 32>;
inline constexpr std::size_t EXACT_OWNER_REPLAY_IDENTITY_COUNT = 56;
using ExactOwnerReplaySet =
    std::array<ReplayIdentity, EXACT_OWNER_REPLAY_IDENTITY_COUNT>;

class SelectedOwnerReplayRegistryAuthority;
class FreshOwnerReplayPrepareAuthority;
class FreshOwnerReplayOutcomeAuthority;

class FreshOwnerTransactionalReplayBridge final {
    FreshOwnerTransactionalReplayBridge() = delete;
public:
    // May allocate and throw. On failure the registry authority remains live
    // and no replay identity has been committed.
    static FreshOwnerReplayPrepareAuthority prepare(
        SelectedOwnerReplayRegistryAuthority&&,
        const ExactOwnerReplaySet&);

    // Claims the prepared operation first. It never allocates or throws and
    // returns an opaque committed-or-unavailable residual.
    static FreshOwnerReplayOutcomeAuthority commit_after_claim(
        FreshOwnerReplayPrepareAuthority&&) noexcept;
};

} // namespace kpb::measurement::fresh_owner_transactional_replay
