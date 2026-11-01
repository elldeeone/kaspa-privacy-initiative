#pragma once

// Complete neutral contract for the sole chronology-correct selected-parent
// prelaunch join.  The implementation consumes the already issued persistent
// activation child, the source-pinned pre-TLS policy authority, and one sealed
// privacy-launch selection/worker source authority.  No public plan, digest,
// path, descriptor, or receipt can substitute for those three capabilities.

#include <memory>

namespace kpb::measurement::prelaunch_policy_domain {
class RegisteredPrelaunchPolicyDomainAuthority;
}

namespace kpb::measurement::score_output_lineage_source {
class SelectedOwnerScoreLineagePrelaunchSourceAuthority;
}

namespace kpb::measurement::p1_state {
class P1MascotFreshPrepDirectoryAuthority;
class P1StateCapsulePrelaunchUnavailableAuthority;
class P1StateCapsulePrelaunchSplit;
class P1StateCapsulePrelaunchCompilerBridge;
}

namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerPersistentActivationAuthority;
}

namespace kpi::mpc::financial::registered_driver {

class RegisteredSelectedProducerPrelaunchBindingAuthority;

class RegisteredSelectedProducerActivationAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredSelectedProducerActivationAuthority(
        std::unique_ptr<Storage>) noexcept;
    const RegisteredSelectedProducerPrelaunchBindingAuthority&
        inspect_for_state_capsule_compiler() const;
    kpb::measurement::p1_state::P1MascotFreshPrepDirectoryAuthority
        claim_mascot_for_state_capsule_compiler();
    friend class RegisteredSelectedProducerActivationBridge;
    friend class ::kpb::measurement::p1_state::
        P1StateCapsulePrelaunchCompilerBridge;
public:
    RegisteredSelectedProducerActivationAuthority(
        const RegisteredSelectedProducerActivationAuthority&) = delete;
    RegisteredSelectedProducerActivationAuthority& operator=(
        const RegisteredSelectedProducerActivationAuthority&) = delete;
    RegisteredSelectedProducerActivationAuthority(
        RegisteredSelectedProducerActivationAuthority&&) noexcept;
    RegisteredSelectedProducerActivationAuthority& operator=(
        RegisteredSelectedProducerActivationAuthority&&) = delete;
    ~RegisteredSelectedProducerActivationAuthority();
};

class RegisteredSelectedProducerActivationFailureAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredSelectedProducerActivationFailureAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class RegisteredSelectedProducerActivationBridge;
public:
    RegisteredSelectedProducerActivationFailureAuthority(
        const RegisteredSelectedProducerActivationFailureAuthority&) = delete;
    RegisteredSelectedProducerActivationFailureAuthority& operator=(
        const RegisteredSelectedProducerActivationFailureAuthority&) = delete;
    RegisteredSelectedProducerActivationFailureAuthority(
        RegisteredSelectedProducerActivationFailureAuthority&&) noexcept;
    RegisteredSelectedProducerActivationFailureAuthority& operator=(
        RegisteredSelectedProducerActivationFailureAuthority&&) = delete;
    ~RegisteredSelectedProducerActivationFailureAuthority();
};

class RegisteredSelectedProducerActivationResult final {
    std::unique_ptr<RegisteredSelectedProducerActivationAuthority> success_;
    std::unique_ptr<RegisteredSelectedProducerActivationFailureAuthority>
        failure_;
    explicit RegisteredSelectedProducerActivationResult(
        std::unique_ptr<RegisteredSelectedProducerActivationAuthority>)
        noexcept;
    explicit RegisteredSelectedProducerActivationResult(
        std::unique_ptr<RegisteredSelectedProducerActivationFailureAuthority>)
        noexcept;
    RegisteredSelectedProducerActivationAuthority
        claim_success_for_state_capsule_compiler() &&;
    friend class RegisteredSelectedProducerActivationBridge;
    friend class ::kpb::measurement::p1_state::
        P1StateCapsulePrelaunchCompilerBridge;
public:
    RegisteredSelectedProducerActivationResult(
        const RegisteredSelectedProducerActivationResult&) = delete;
    RegisteredSelectedProducerActivationResult& operator=(
        const RegisteredSelectedProducerActivationResult&) = delete;
    RegisteredSelectedProducerActivationResult(
        RegisteredSelectedProducerActivationResult&&) noexcept;
    RegisteredSelectedProducerActivationResult& operator=(
        RegisteredSelectedProducerActivationResult&&) = delete;
    ~RegisteredSelectedProducerActivationResult();
};

class RegisteredSelectedProducerActivationBridge final {
    RegisteredSelectedProducerActivationBridge() = delete;
public:
    static RegisteredSelectedProducerActivationResult activate(
        fresh_owner_issuance::FreshOwnerPersistentActivationAuthority&&,
        kpb::measurement::prelaunch_policy_domain::
            RegisteredPrelaunchPolicyDomainAuthority&&,
        kpb::measurement::score_output_lineage_source::
            SelectedOwnerScoreLineagePrelaunchSourceAuthority&&);
};

} // namespace kpi::mpc::financial::registered_driver

namespace kpb::measurement::p1_state {

// Complete before it appears in the public compiler signature. The opaque
// storage retains the selected activation and exact Missing manifests without
// exposing invented epoch values or a capsule-plan authority.
class P1StateCapsulePrelaunchUnavailableAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1StateCapsulePrelaunchUnavailableAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class P1StateCapsulePrelaunchCompilerBridge;
public:
    P1StateCapsulePrelaunchUnavailableAuthority(
        const P1StateCapsulePrelaunchUnavailableAuthority&) = delete;
    P1StateCapsulePrelaunchUnavailableAuthority& operator=(
        const P1StateCapsulePrelaunchUnavailableAuthority&) = delete;
    P1StateCapsulePrelaunchUnavailableAuthority(
        P1StateCapsulePrelaunchUnavailableAuthority&&) noexcept;
    P1StateCapsulePrelaunchUnavailableAuthority& operator=(
        P1StateCapsulePrelaunchUnavailableAuthority&&) = delete;
    ~P1StateCapsulePrelaunchUnavailableAuthority();
};

// Complete only after the production input authority is complete. This keeps
// the public compile signature immune to a hostile replacement definition
// while preserving the narrow friendship declared above.
class P1StateCapsulePrelaunchCompilerBridge final {
    P1StateCapsulePrelaunchCompilerBridge() = delete;
public:
    static P1StateCapsulePrelaunchUnavailableAuthority compile(
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerActivationResult&&);
};

} // namespace kpb::measurement::p1_state
