#pragma once

// Private one-comparison gate for the independently launched baseline and
// hidden-candidate owner-process arms. The join consumes both live launch
// authorities, retains no raw arm evidence, and yields two arm-bound residuals
// that are mandatory inputs to R1 issuance.

#include "fresh_owner_process_adapter.hpp"

#include <atomic>
#include <mutex>
#include <optional>
#include <string>

namespace kpi::mpc::financial::fresh_owner_issuance {

class FreshOwnerArmIsolationAuthority final {
    Digest isolation_authority_identity_{};
    std::optional<FreshOwnerArmIsolationResidualAuthority> baseline_;
    std::optional<FreshOwnerArmIsolationResidualAuthority> hidden_candidate_;
    std::atomic_bool live_{true};
    mutable std::mutex mutex_;
    FreshOwnerArmIsolationAuthority(
        Digest isolation_authority_identity,
        FreshOwnerArmIsolationResidualAuthority&& baseline,
        FreshOwnerArmIsolationResidualAuthority&& hidden_candidate);
    friend class FreshOwnerArmIsolationBridge;
public:
    FreshOwnerArmIsolationAuthority(
        const FreshOwnerArmIsolationAuthority&) = delete;
    FreshOwnerArmIsolationAuthority& operator=(
        const FreshOwnerArmIsolationAuthority&) = delete;
    FreshOwnerArmIsolationAuthority(
        FreshOwnerArmIsolationAuthority&&) noexcept;
    FreshOwnerArmIsolationAuthority& operator=(
        FreshOwnerArmIsolationAuthority&&) = delete;
    ~FreshOwnerArmIsolationAuthority();

    FreshOwnerArmIsolationResidualAuthority take_baseline_residual();
    FreshOwnerArmIsolationResidualAuthority
        take_hidden_candidate_residual();
};

struct FreshOwnerArmIsolationSourceStatus {
    std::string schema;
    std::string status;
    bool exact_baseline_hidden_pair;
    bool full_cross_set_private_disjointness;
    bool mandatory_r1_residual_gate;
    bool role_permutation_shortcut;
    bool public_or_durable_raw_identifier_output;
    bool production_paired_trial_callsite;
    bool registered_driver_configured;
    bool launch_authorized;
};

FreshOwnerArmIsolationSourceStatus
fresh_owner_arm_isolation_source_status();

} // namespace kpi::mpc::financial::fresh_owner_issuance
