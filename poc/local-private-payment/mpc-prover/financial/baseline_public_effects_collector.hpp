#pragma once

// Source-only transparent baseline authority for ADR-0085. It reveals only
// each authenticated owner's already-public NF and two public tuple hashes.
// No private body, witness, share, owner input or hidden-candidate route exists.

#include "registered_driver_bridge.hpp"
#include "registered_capture_session.hpp"
#include "baseline_owner_effects_recipe.hpp"
#include "../../private_batch_trial/native_terminal_projection_intake_bridge.hpp"

#include <array>
#include <atomic>
#include <string>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {

class PartyBaselineOwnerEffectsAuthority;

struct PublicBaselineEffectsPlan {
    CaptureClassification classification{};
    unsigned round{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest verified_egress_identity{};
    std::array<Digest, 3> owner_contracts{};
    // Canonical sorted public sets derived from genuine verified EGRESS.
    std::array<Digest, 3> public_nullifiers{};
    std::array<Digest, 6> public_tuple_hashes{};
    Digest policy_identity{};
};

// Minted only by FinancialHistoryAccess from one actual registered
// FinancialConstruction plus its durable EgressRelease. No digest-only
// production constructor or undefined friend seam exists.
class VerifiedBaselinePublicEffectsAuthority final {
    PublicBaselineEffectsPlan value_;
    std::atomic_bool live_{true};
    explicit VerifiedBaselinePublicEffectsAuthority(PublicBaselineEffectsPlan);
    friend class BaselineDisclosureAuthorityBridge;
public:
    VerifiedBaselinePublicEffectsAuthority(
        const VerifiedBaselinePublicEffectsAuthority&) = delete;
    VerifiedBaselinePublicEffectsAuthority& operator=(
        const VerifiedBaselinePublicEffectsAuthority&) = delete;
    VerifiedBaselinePublicEffectsAuthority(
        VerifiedBaselinePublicEffectsAuthority&&) noexcept;
    VerifiedBaselinePublicEffectsAuthority& operator=(
        VerifiedBaselinePublicEffectsAuthority&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static VerifiedBaselinePublicEffectsAuthority test_only_mint(
        PublicBaselineEffectsPlan);
#endif
};

class BaselineEffectsPlanAuthority final {
    struct ClaimedTransfer {};
    PublicBaselineEffectsPlan value_;
    Digest identity_{};
    std::atomic_bool live_{true};
    explicit BaselineEffectsPlanAuthority(PublicBaselineEffectsPlan);
    BaselineEffectsPlanAuthority(
        PublicBaselineEffectsPlan, Digest, ClaimedTransfer);
    friend class BaselinePublicEffectsCollector;
    friend class BaselineDisclosureAuthorityBridge;
    friend class BaselineOwnerEffectsRecipeBridge;
public:
    BaselineEffectsPlanAuthority(const BaselineEffectsPlanAuthority&) = delete;
    BaselineEffectsPlanAuthority& operator=(
        const BaselineEffectsPlanAuthority&) = delete;
    BaselineEffectsPlanAuthority(BaselineEffectsPlanAuthority&&) noexcept;
    BaselineEffectsPlanAuthority& operator=(
        BaselineEffectsPlanAuthority&&) = delete;
    const PublicBaselineEffectsPlan& public_plan() const { return value_; }
    const Digest& identity() const { return identity_; }
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static BaselineEffectsPlanAuthority test_only_mint(
        PublicBaselineEffectsPlan);
#endif
};

struct OwnerEffectsDisclosureInput {
    CaptureClassification classification{};
    unsigned round{};
    unsigned owner{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest owner_contract_identity{};
    Digest public_nullifier{};
    std::array<Digest, 2> public_tuple_hashes{};
    Digest authenticated_session_identity{};
};

class AuthenticatedOwnerEffectsDisclosureAuthority final {
    OwnerEffectsDisclosureInput value_;
    Digest identity_{};
    std::atomic_bool live_{true};
    explicit AuthenticatedOwnerEffectsDisclosureAuthority(
        OwnerEffectsDisclosureInput);
    friend class BaselinePublicEffectsCollector;
public:
    AuthenticatedOwnerEffectsDisclosureAuthority(
        const AuthenticatedOwnerEffectsDisclosureAuthority&) = delete;
    AuthenticatedOwnerEffectsDisclosureAuthority& operator=(
        const AuthenticatedOwnerEffectsDisclosureAuthority&) = delete;
    AuthenticatedOwnerEffectsDisclosureAuthority(
        AuthenticatedOwnerEffectsDisclosureAuthority&&) noexcept;
    AuthenticatedOwnerEffectsDisclosureAuthority& operator=(
        AuthenticatedOwnerEffectsDisclosureAuthority&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static AuthenticatedOwnerEffectsDisclosureAuthority test_only_mint(
        OwnerEffectsDisclosureInput);
#endif
};

struct PublicOwnerEffect {
    unsigned owner{};
    Digest owner_contract_identity{};
    Digest public_nullifier{};
    std::array<Digest, 2> public_tuple_hashes{};
};

struct PublicExplicitOwnerEffects {
    std::string status;
    CaptureClassification classification{};
    unsigned round{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    std::array<PublicOwnerEffect, 3> owner_effects{};
    Digest receipt_identity{};
};

// Minted only after the genuine dispatcher has accepted the exact baseline
// public mapping and its typed release-policy binding. It carries the same
// already-public owner/NF/two-tuple rows privately to the native terminal
// intake; there is no HiddenCandidate constructor or public row getter.
class BaselineTerminalOwnerMappingAuthority final {
    PublicExplicitOwnerEffects value_;
    std::atomic_bool live_{true};
    explicit BaselineTerminalOwnerMappingAuthority(
        PublicExplicitOwnerEffects);
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredCaptureSession;
    friend class ::kpb::native_terminal::NativeTerminalProjectionIntake;
public:
    BaselineTerminalOwnerMappingAuthority(
        const BaselineTerminalOwnerMappingAuthority&) = delete;
    BaselineTerminalOwnerMappingAuthority& operator=(
        const BaselineTerminalOwnerMappingAuthority&) = delete;
    BaselineTerminalOwnerMappingAuthority(
        BaselineTerminalOwnerMappingAuthority&&) noexcept;
    BaselineTerminalOwnerMappingAuthority& operator=(
        BaselineTerminalOwnerMappingAuthority&&) = delete;
};

class ExplicitOwnerPublicEffectsAuthority final {
    PublicExplicitOwnerEffects receipt_;
    std::atomic_bool live_{true};
    static Digest receipt_identity(const PublicExplicitOwnerEffects&);
    static ExplicitOwnerPublicEffectsAuthority from_bound_party(
        PartyBaselineOwnerEffectsAuthority&,
        const PublicAuthorizedAttempt&, const Digest& egress_binding,
        const Digest& projection_identity, const Digest& context_identity);
    explicit ExplicitOwnerPublicEffectsAuthority(PublicExplicitOwnerEffects);
    friend class BaselinePublicEffectsCollector;
public:
    ExplicitOwnerPublicEffectsAuthority(
        const ExplicitOwnerPublicEffectsAuthority&) = delete;
    ExplicitOwnerPublicEffectsAuthority& operator=(
        const ExplicitOwnerPublicEffectsAuthority&) = delete;
    ExplicitOwnerPublicEffectsAuthority(
        ExplicitOwnerPublicEffectsAuthority&&) noexcept;
    ExplicitOwnerPublicEffectsAuthority& operator=(
        ExplicitOwnerPublicEffectsAuthority&&) = delete;
    const PublicExplicitOwnerEffects& public_receipt() const {
        return receipt_;
    }
    PublicExplicitOwnerEffects consume_for_capture() {
        if (!live_.exchange(false)) throw identity_registry::Refused();
        return receipt_;
    }
    static ExplicitOwnerPublicEffectsAuthority
    from_acknowledged_registered_egress(
        PartyBaselineOwnerEffectsAuthority&,
        const ::kpi::mpc::financial::FinancialConstruction&,
        const ::kpi::mpc::history::EgressRelease&);
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static ExplicitOwnerPublicEffectsAuthority test_only_mint(
        PublicExplicitOwnerEffects);
    static ExplicitOwnerPublicEffectsAuthority test_only_from_bound_party(
        PartyBaselineOwnerEffectsAuthority& party,
        const PublicAuthorizedAttempt& attempt,
        const Digest& egress_binding, const Digest& projection_identity,
        const Digest& context_identity) {
        return from_bound_party(party, attempt, egress_binding,
                                projection_identity, context_identity);
    }
#endif
};

class BaselinePublicEffectsCollector final {
public:
    static ExplicitOwnerPublicEffectsAuthority collect(
        BaselineEffectsPlanAuthority&&,
        std::array<AuthenticatedOwnerEffectsDisclosureAuthority, 3>&&);
};

class BaselineDisclosureAuthorityBridge final {
public:
    static Digest policy_identity();
    static VerifiedBaselinePublicEffectsAuthority from_registered_egress(
        const ::kpi::mpc::financial::FinancialConstruction&,
        const ::kpi::mpc::history::EgressRelease&);
    static BaselineEffectsPlanAuthority from_verified_egress(
        VerifiedBaselinePublicEffectsAuthority&&);
};

struct SourceStatus {
    std::string schema;
    std::string status;
    bool classification_bound_to_capture_plan;
    bool exact_three_owner_partition;
    bool grouped_owner_mapping_preserved;
    bool hidden_candidate_disclosure_factory_absent;
    bool verified_egress_authority_integration;
    bool authenticated_owner_ipc_integration;
    bool parent_dispatcher_integration;
    bool actual_capture_completion;
    bool registered_driver_configured;
    bool launch_authorized;
};

SourceStatus source_status();

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
