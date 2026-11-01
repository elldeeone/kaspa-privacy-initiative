#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"

#include <utility>

namespace kpb::measurement::p1_state {

struct P1HookSerializerManifestAuthority::Storage final {};
struct P1AbortTerminalManifestAuthority::Storage final {};
struct P1StateCapsulePrelaunchSplit::Storage final {};

P1HookSerializerManifestAuthority::P1HookSerializerManifestAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1HookSerializerManifestAuthority::P1HookSerializerManifestAuthority(
        P1HookSerializerManifestAuthority&&) noexcept = default;
P1HookSerializerManifestAuthority::~P1HookSerializerManifestAuthority() =
    default;

P1AbortTerminalManifestAuthority::P1AbortTerminalManifestAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1AbortTerminalManifestAuthority::P1AbortTerminalManifestAuthority(
        P1AbortTerminalManifestAuthority&&) noexcept = default;
P1AbortTerminalManifestAuthority::~P1AbortTerminalManifestAuthority() =
    default;

P1StateCapsulePrelaunchSplit::P1StateCapsulePrelaunchSplit(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
P1StateCapsulePrelaunchSplit::P1StateCapsulePrelaunchSplit(
        P1StateCapsulePrelaunchSplit&&) noexcept = default;
P1StateCapsulePrelaunchSplit::~P1StateCapsulePrelaunchSplit() = default;

P1StateCapsulePrelaunchCompilerStatus
p1_state_capsule_prelaunch_compiler_status() noexcept {
    return {
        .complete_bridge_name_before_friendship = true,
        .exact_future_type_vocabulary = true,
        .selected_prelaunch_required = true,
        .source_policy_domain_required = true,
        .fourteen_family_hook_serializer_manifest_required = true,
        .abort_terminal_manifest_required = true,
        .retained_producer_plus_two_round_plans_required = true,
        .role1_round1_round2_only_required = true,
        .writerless_before_topology_transfer_required = true,
        .stale_swapped_partial_replay_burn_controls_required = true,
        .caller_static_plan_or_event_factory = false,
        .caller_digest_path_bytes_or_fd_input = false,
        .hook_serializer_manifest_source_minter = false,
        .abort_terminal_manifest_source_minter = false,
        .capsule_plan_compiler_implemented = false,
        .atomic_activation_split_implemented = false,
        .stale_lineage_control = false,
        .swapped_round_control = false,
        .partial_manifest_control = false,
        .replay_burn_control = false,
        .selected_parent_callsite = false,
        .configured = false,
        .actual_plan_mint = false,
    };
}

} // namespace kpb::measurement::p1_state
