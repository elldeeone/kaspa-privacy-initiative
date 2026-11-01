#pragma once

// Typed, source-owned prelaunch compiler gate for role-1 P1 state capsules.
// Production accepts only already-authenticated linear authorities. Missing
// epoch sources force an opaque UNAVAILABLE result; no raw plan, digest, path,
// descriptor, byte span, event list, or family array is a minting path.

#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"

#include <memory>

namespace kpi::mpc::financial::registered_driver {
struct RegisteredSelectedProducerPrelaunchPlan;
class RegisteredSelectedProducerPrelaunchBindingAuthority;
}

namespace kpb::measurement::prelaunch_policy_domain {
class RegisteredPrelaunchPolicyDomainAuthority;
}

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateCapsulePlanAuthority;
}

namespace kpb::measurement::p1_state {

class P1MascotFreshPrepDirectoryAuthority;
class P1MascotTwoRoundManifestAuthority;
class P1MascotAbortTerminalManifestAuthority;
class P1HookSerializerManifestAuthority;
class P1AbortTerminalManifestAuthority;
class P1StateCapsulePrelaunchUnavailableAuthority;
class P1StateCapsulePrelaunchSplit;

class P1HookSerializerManifestSourceBridge final {
    P1HookSerializerManifestSourceBridge() = delete;
    static P1HookSerializerManifestAuthority mint(
        P1MascotTwoRoundManifestAuthority&&);
    friend class P1StateCapsulePrelaunchCompilerBridge;
};

class P1HookSerializerManifestAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1HookSerializerManifestAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class P1HookSerializerManifestSourceBridge;
    friend class P1AbortTerminalManifestSourceBridge;
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
    P1HookSerializerManifestAuthority(
        const P1HookSerializerManifestAuthority&) = delete;
    P1HookSerializerManifestAuthority& operator=(
        const P1HookSerializerManifestAuthority&) = delete;
    P1HookSerializerManifestAuthority(
        P1HookSerializerManifestAuthority&&) noexcept;
    P1HookSerializerManifestAuthority& operator=(
        P1HookSerializerManifestAuthority&&) = delete;
    ~P1HookSerializerManifestAuthority();
};

class P1AbortTerminalManifestSourceBridge final {
    P1AbortTerminalManifestSourceBridge() = delete;
    static P1AbortTerminalManifestAuthority mint(
        P1MascotAbortTerminalManifestAuthority&&,
        const P1HookSerializerManifestAuthority&);
    friend class P1StateCapsulePrelaunchCompilerBridge;
};

class P1AbortTerminalManifestAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1AbortTerminalManifestAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class P1AbortTerminalManifestSourceBridge;
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
    P1AbortTerminalManifestAuthority(
        const P1AbortTerminalManifestAuthority&) = delete;
    P1AbortTerminalManifestAuthority& operator=(
        const P1AbortTerminalManifestAuthority&) = delete;
    P1AbortTerminalManifestAuthority(
        P1AbortTerminalManifestAuthority&&) noexcept;
    P1AbortTerminalManifestAuthority& operator=(
        P1AbortTerminalManifestAuthority&&) = delete;
    ~P1AbortTerminalManifestAuthority();
};

// Reserved future success vocabulary. It is mechanically unconstructible
// until typed nonzero epoch authorities and every selected family callsite
// exist.
class P1StateCapsulePrelaunchSplit final {
    P1StateCapsulePrelaunchSplit() = delete;
    P1StateCapsulePrelaunchSplit(
        const P1StateCapsulePrelaunchSplit&) = delete;
    P1StateCapsulePrelaunchSplit(P1StateCapsulePrelaunchSplit&&) = delete;
    ~P1StateCapsulePrelaunchSplit() = delete;
};

struct P1StateCapsulePrelaunchCompilerContract final {
    using ActivationAuthority =
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerActivationAuthority;
    using InputAuthority =
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerActivationResult;
    using SelectedPrelaunchAuthority =
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerPrelaunchBindingAuthority;
    using PolicyDomainAuthority =
        kpb::measurement::prelaunch_policy_domain::
            RegisteredPrelaunchPolicyDomainAuthority;
    using HookSerializerManifestAuthority =
        P1HookSerializerManifestAuthority;
    using AbortTerminalManifestAuthority =
        P1AbortTerminalManifestAuthority;
    using RoundPlanAuthority =
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsulePlanAuthority;
    using OutputAuthority = P1StateCapsulePrelaunchUnavailableAuthority;
    using FutureSuccessAuthority = P1StateCapsulePrelaunchSplit;
};

struct P1StateCapsulePrelaunchCompilerStatus final {
    bool hostile_bridge_substitution_rejected{};
    bool exact_future_type_vocabulary{};
    bool selected_prelaunch_required{};
    bool source_policy_domain_required{};
    bool fourteen_family_hook_serializer_manifest_required{};
    bool abort_terminal_manifest_required{};
    bool retained_producer_plus_two_round_plans_required{};
    bool role1_round1_round2_only_required{};
    bool writerless_before_topology_transfer_required{};
    bool stale_swapped_partial_replay_burn_controls_required{};
    bool macro_free_production_caller_static_plan_or_event_factory{};
    bool caller_defined_test_macro_unforgeability{};
    bool exact_macro_free_build_closure_required{};
    bool caller_digest_path_bytes_or_fd_input{};
    bool hook_serializer_manifest_source_minter{};
    bool abort_terminal_manifest_source_minter{};
    bool capsule_plan_compiler_implemented{};
    bool atomic_activation_split_implemented{};
    bool fail_closed_unavailable_authority_implemented{};
    bool missing_epoch_authorities_recorded{};
    bool stale_lineage_control{};
    bool swapped_round_control{};
    bool partial_manifest_control{};
    bool replay_burn_control{};
    bool selected_parent_callsite{};
    bool configured{};
    bool actual_plan_mint{};
};

P1StateCapsulePrelaunchCompilerStatus
p1_state_capsule_prelaunch_compiler_status() noexcept;

} // namespace kpb::measurement::p1_state
