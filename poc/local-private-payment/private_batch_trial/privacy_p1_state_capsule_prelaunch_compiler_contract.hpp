#pragma once

// Dependency-neutral contract for the missing source-owned P1 state-capsule
// plan compiler.  This file deliberately defines every privileged bridge name
// before any future friendship is granted.  No callable compiler or source
// manifest minter exists in this revision: a translation unit must not be able
// to supply the missing member definition and thereby acquire private state.

#include <memory>

namespace kpi::mpc::financial::registered_driver {
class RegisteredSelectedProducerPrelaunchBindingAuthority;
}

namespace kpb::measurement::prelaunch_policy_domain {
class RegisteredPrelaunchPolicyDomainAuthority;
}

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateCapsulePlanAuthority;
}

namespace kpb::measurement::p1_state {

// Complete before every friendship grant below. It intentionally has no
// compile method while either source manifest authority lacks a genuine
// source minter.
class P1StateCapsulePrelaunchCompilerBridge final {
public:
    P1StateCapsulePrelaunchCompilerBridge() = delete;
};

// Future source-only joins of all fourteen hook inventories and serializer
// identities.  It must be minted from typed source adapters, never from a
// caller-provided raw capsule-plan struct, event list, digest, path, or bytes.
class P1HookSerializerManifestSourceBridge final {
public:
    P1HookSerializerManifestSourceBridge() = delete;
};

class P1HookSerializerManifestAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1HookSerializerManifestAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class P1HookSerializerManifestSourceBridge;
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

// Future source-only join of the exact catch sites, phases, abort classes and
// per-family closed/not-constructed/terminal-prefix inventories.  It exposes
// no terminal-site digest or caller event factory.
class P1AbortTerminalManifestSourceBridge final {
public:
    P1AbortTerminalManifestSourceBridge() = delete;
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

// Future indivisible result: the retained selected-producer prelaunch
// authority plus exact round-1 and round-2 role-1 capsule plans.  It owns no
// descriptor, projection bytes, child-exit identity or terminal result, and it
// exposes no getter that could separate one component before the future atomic
// activation split.
class P1StateCapsulePrelaunchSplit final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1StateCapsulePrelaunchSplit(
        std::unique_ptr<Storage>) noexcept;
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
    P1StateCapsulePrelaunchSplit(
        const P1StateCapsulePrelaunchSplit&) = delete;
    P1StateCapsulePrelaunchSplit& operator=(
        const P1StateCapsulePrelaunchSplit&) = delete;
    P1StateCapsulePrelaunchSplit(
        P1StateCapsulePrelaunchSplit&&) noexcept;
    P1StateCapsulePrelaunchSplit& operator=(
        P1StateCapsulePrelaunchSplit&&) = delete;
    ~P1StateCapsulePrelaunchSplit();
};

// Non-authorizing type vocabulary for the future compiler signature.  Aliases
// describe the only admissible typed inputs and output; they are not values and
// cannot mint an authority.  The implementation must privately reproduce the
// complete P1StateCapsulePrelaunchBinding lineage: classification, selection,
// raw trial/attempt IDs, attempt/cohort/capture/method/workload/source/runtime,
// finite manifest, parent/source/build/launcher workers, both financial runs,
// round attempts/cohorts/capture plans, reservation/session/fork identities,
// producer/role/manifest/construction identities, derived route and stream
// policy identities, and the recomputed binding identity.  Each role-1 round
// plan must additionally bind the selected policy plans, persistent-child and
// context epochs, fourteen hook/serializer families, source dependency pins,
// topology/filesystem policy and exact abort-terminal inventories.
struct P1StateCapsulePrelaunchCompilerContract final {
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
    using OutputAuthority = P1StateCapsulePrelaunchSplit;
};

struct P1StateCapsulePrelaunchCompilerStatus final {
    bool complete_bridge_name_before_friendship{};
    bool exact_future_type_vocabulary{};
    bool selected_prelaunch_required{};
    bool source_policy_domain_required{};
    bool fourteen_family_hook_serializer_manifest_required{};
    bool abort_terminal_manifest_required{};
    bool retained_producer_plus_two_round_plans_required{};
    bool role1_round1_round2_only_required{};
    bool writerless_before_topology_transfer_required{};
    bool stale_swapped_partial_replay_burn_controls_required{};
    bool caller_static_plan_or_event_factory{};
    bool caller_digest_path_bytes_or_fd_input{};
    bool hook_serializer_manifest_source_minter{};
    bool abort_terminal_manifest_source_minter{};
    bool capsule_plan_compiler_implemented{};
    bool atomic_activation_split_implemented{};
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
