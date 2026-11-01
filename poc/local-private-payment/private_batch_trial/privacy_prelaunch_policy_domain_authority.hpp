#pragma once

// Pre-CryptoPlayer source-policy authority. These identities name the exact
// reviewed algorithms which will later acquire an accepted head and admit the
// registered main program. They are not the post-TLS selected head/program
// values and must never be relabeled as those runtime authorities.

#include <array>
#include <memory>

#include "../mpc-prover/financial/registered_selected_producer_activation_contract.hpp"

namespace kpb::measurement::prelaunch_policy_domain {

using PolicyDigest = std::array<unsigned char, 32>;

class RegisteredPrelaunchPolicyDomainAuthority;

#ifdef KPB_PRELAUNCH_POLICY_DOMAIN_TEST_SETUP
struct TestOnlyRegisteredPrelaunchPolicyDomainSummary final {
    PolicyDigest accepted_head_policy_identity{};
    PolicyDigest selected_main_policy_identity{};
    PolicyDigest source_manifest_identity{};
};
#endif

// Complete before friendship. It accepts no paths, bytes, digests, context,
// runtime head, or registered selection. The complete state-capsule compiler
// reacquires and consumes this typed source solely to check the selected
// activation's already-authenticated policy lineage.
class RegisteredPrelaunchPolicyDomainSourceBridge final {
public:
    RegisteredPrelaunchPolicyDomainSourceBridge() = delete;
    static RegisteredPrelaunchPolicyDomainAuthority acquire();
#ifdef KPB_PRELAUNCH_POLICY_DOMAIN_TEST_SETUP
    static TestOnlyRegisteredPrelaunchPolicyDomainSummary test_only_consume(
        RegisteredPrelaunchPolicyDomainAuthority&&);
#endif
};

class RegisteredPrelaunchPolicyDomainAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredPrelaunchPolicyDomainAuthority(
        std::unique_ptr<Storage>) noexcept;
    void consume_for_selected_activation(
        PolicyDigest& accepted_head_policy_identity,
        PolicyDigest& selected_main_policy_identity,
        PolicyDigest& source_manifest_identity) &&;
    friend class RegisteredPrelaunchPolicyDomainSourceBridge;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredSelectedProducerActivationBridge;
    friend class ::kpb::measurement::p1_state::
        P1StateCapsulePrelaunchCompilerBridge;
public:
    RegisteredPrelaunchPolicyDomainAuthority(
        const RegisteredPrelaunchPolicyDomainAuthority&) = delete;
    RegisteredPrelaunchPolicyDomainAuthority& operator=(
        const RegisteredPrelaunchPolicyDomainAuthority&) = delete;
    RegisteredPrelaunchPolicyDomainAuthority(
        RegisteredPrelaunchPolicyDomainAuthority&&) noexcept;
    RegisteredPrelaunchPolicyDomainAuthority& operator=(
        RegisteredPrelaunchPolicyDomainAuthority&&) = delete;
    ~RegisteredPrelaunchPolicyDomainAuthority();
};

struct RegisteredPrelaunchPolicyDomainStatus final {
    bool exact_source_pin_constants{};
    bool accepted_head_policy_algorithm_identity{};
    bool selected_main_policy_algorithm_identity{};
    bool caller_digest_or_path_input{};
    bool runtime_accepted_head_authority{};
    bool runtime_selected_main_authority{};
    bool selected_prelaunch_compiler_consumer{};
    bool producer_plus_two_capsule_split{};
    bool configured{};
};

inline constexpr RegisteredPrelaunchPolicyDomainStatus
kRegisteredPrelaunchPolicyDomainStatus{
    .exact_source_pin_constants = true,
    .accepted_head_policy_algorithm_identity = true,
    .selected_main_policy_algorithm_identity = true,
    .caller_digest_or_path_input = false,
    .runtime_accepted_head_authority = false,
    .runtime_selected_main_authority = false,
    .selected_prelaunch_compiler_consumer = true,
    .producer_plus_two_capsule_split = false,
    .configured = false,
};

} // namespace kpb::measurement::prelaunch_policy_domain
