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

namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerPersistentActivationAuthority;
}

namespace kpi::mpc::financial::registered_driver {

class RegisteredSelectedProducerActivationAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredSelectedProducerActivationAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class RegisteredSelectedProducerActivationBridge;
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
    friend class RegisteredSelectedProducerActivationBridge;
#ifdef KPB_SELECTED_PRODUCER_ACTIVATION_TEST_SETUP
    friend class RegisteredSelectedProducerActivationTestBridge;
#endif
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

#ifdef KPB_SELECTED_PRODUCER_ACTIVATION_TEST_SETUP
class RegisteredSelectedProducerActivationTestBridge final {
    RegisteredSelectedProducerActivationTestBridge() = delete;
public:
    static bool succeeded(
        const RegisteredSelectedProducerActivationResult&) noexcept;
    static bool failed(
        const RegisteredSelectedProducerActivationResult&) noexcept;
};
#endif

} // namespace kpi::mpc::financial::registered_driver
