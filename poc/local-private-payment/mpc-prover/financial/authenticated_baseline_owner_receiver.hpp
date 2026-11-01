#pragma once

// Baseline-only owner truth handoff. Party receivers consume genuine
// post-EGRESS owner-effect sources after mutual-TLS consent. The parent joins
// all three party copies for both rounds and releases one private truth input
// per owner. Separately, role 0 emits one baseline-only observer leaf containing
// only the intentional already-public owner-to-NF/two-tuple mapping.

#include "registered_driver_bridge.hpp"
#include "authenticated_baseline_owner_receiver_contract.hpp"
#include "baseline_owner_scoring_parent_transport.hpp"
#include "registered_party_completion_transport.hpp"
#include "baseline_owner_truth_capsule_bridge.hpp"
#include "baseline_public_effects_collector.hpp"

#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kpi::mpc {
class MascotContext;
struct OwnerInputContract;
namespace history { class EgressRelease; }
namespace financial {
class FinancialConstruction;
namespace fresh_owner_issuance {
class BaselineOwnerRosterReceiverAuthority;
}
namespace registered_driver { class ParentRoleChildren; }
namespace registered_driver::baseline_disclosure {
class BaselineEffectsPlanAuthority;
class PreparedBaselineOwnerEffects;
class PartyBaselineOwnerEffectsAuthority;

struct PrivateOwnerScoringTruth {
    unsigned owner{};
    unsigned round{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest owner_contract_identity{};
    Digest logical_owner_identity{};
    Digest roster_authority_identity{};
    Digest roster_root_identity{};
    Digest pre_disclosure_challenge_identity{};
    Digest public_nullifier{};
    std::array<Digest, 2> public_tuple_hashes{};
    std::array<Digest, 2> public_tuple_commitments{};
    bool operator==(const PrivateOwnerScoringTruth&) const = default;
};

class BaselineOwnerConsentProtocol final {
public:
    static constexpr std::size_t CHALLENGE_BYTES = 683;
    static constexpr std::size_t ACK_BYTES = 40;
    using Challenge = std::array<unsigned char, CHALLENGE_BYTES>;
    using Acknowledgment = std::array<unsigned char, ACK_BYTES>;

    static Digest consent_nonce(
        CaptureClassification, const PrivateOwnerScoringTruth&,
        const Digest& relation_source_identity,
        const Digest& owner_effects_recipe_identity,
        const Digest& policy_identity);
    static Challenge challenge(
        CaptureClassification, const PrivateOwnerScoringTruth&,
        const Digest& relation_source_identity,
        const Digest& owner_effects_recipe_identity,
        const Digest& policy_identity,
        const Digest& pre_disclosure_challenge_identity,
        const Digest& consent_nonce);
    static Acknowledgment acknowledge(const Challenge&);
    static void require_acknowledgment(
        const Challenge&, const Acknowledgment&);
};

struct BaselineOwnerPreDisclosureBinding {
    CaptureClassification classification{};
    unsigned round{};
    unsigned owner{};
    Digest nonce{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest owner_contract_identity{};
    Digest relation_source_identity{};
    Digest owner_effects_recipe_identity{};
    Digest policy_identity{};
    Digest roster_authority_identity{};
    Digest roster_root_identity{};
    bool operator==(const BaselineOwnerPreDisclosureBinding&) const = default;
};

class BaselineOwnerPreDisclosureProtocol final {
public:
    static constexpr std::size_t CHALLENGE_BYTES = 459;
    using Challenge = std::array<unsigned char, CHALLENGE_BYTES>;
    static Challenge challenge(BaselineOwnerPreDisclosureBinding);
    static BaselineOwnerPreDisclosureBinding parse(
        std::span<const unsigned char>);
};

struct BaselineOwnerPreDisclosureConsentReceipt {
    CaptureClassification classification{};
    unsigned round{};
    unsigned role{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest relation_source_identity{};
    Digest owner_effects_recipe_identity{};
    Digest baseline_plan_identity{};
    Digest verified_egress_identity{};
    Digest policy_identity{};
    Digest roster_authority_identity{};
    Digest roster_root_identity{};
    std::array<Digest, 3> pre_challenge_identities{};
    std::array<Digest, 3> owner_contracts{};
    std::array<Digest, 3> logical_owner_identities{};
    std::array<Digest, 3> owner_proof_sessions{};
    Digest consent_identity{};
};

// Minted only after the private roster verifier accepts all three long-lived
// owner-key proofs. The recipe burns it before selecting or MAC-opening any
// owner-mapping wire.
class BaselineOwnerPreDisclosureConsentAuthority final {
    BaselineOwnerPreDisclosureConsentReceipt receipt_;
    std::atomic_bool live_{true};
    explicit BaselineOwnerPreDisclosureConsentAuthority(
        BaselineOwnerPreDisclosureConsentReceipt);
    friend class AuthenticatedBaselineOwnerReceiver;
public:
    BaselineOwnerPreDisclosureConsentAuthority(
        const BaselineOwnerPreDisclosureConsentAuthority&) = delete;
    BaselineOwnerPreDisclosureConsentAuthority& operator=(
        const BaselineOwnerPreDisclosureConsentAuthority&) = delete;
    BaselineOwnerPreDisclosureConsentAuthority(
        BaselineOwnerPreDisclosureConsentAuthority&&) noexcept;
    BaselineOwnerPreDisclosureConsentAuthority& operator=(
        BaselineOwnerPreDisclosureConsentAuthority&&) = delete;
    BaselineOwnerPreDisclosureConsentReceipt consume_for_recipe();
};

// Private despite the structural name: no production accessor or serializer
// exists. Only the receiver can construct it and only the parent can consume
// it. Role-specific EGRESS/plan/session identities prevent one party copy from
// being counted as the required three-party join.
struct PrivatePartyBaselineOwnerEffects {
    CaptureClassification classification{};
    unsigned round{};
    unsigned role{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest relation_source_identity{};
    Digest owner_effects_recipe_identity{};
    Digest baseline_plan_identity{};
    Digest verified_egress_identity{};
    Digest policy_identity{};
    Digest roster_authority_identity{};
    Digest roster_root_identity{};
    Digest consent_nonce{};
    std::array<Digest, 3> owner_contracts{};
    // Parent-issued private roster identities. They remain stable across the
    // two attempts while TLS certificates and session identities stay fresh.
    std::array<Digest, 3> logical_owner_identities{};
    std::array<Digest, 3> pre_disclosure_challenge_identities{};
    std::array<Digest, 3> owner_sessions{};
    std::array<PrivateOwnerScoringTruth, 3> owner_truth{};
};

class PartyBaselineOwnerEffectsAuthority final {
    PrivatePartyBaselineOwnerEffects value_;
    Digest identity_{};
    std::atomic_bool live_{true};
    std::atomic_bool observer_exported_{false};
    explicit PartyBaselineOwnerEffectsAuthority(
        PrivatePartyBaselineOwnerEffects);
    friend class AuthenticatedBaselineOwnerReceiver;
    friend class BaselineOwnerScoringParentCollector;
    friend class BaselineOwnerScoringParentTransport;
    friend class registered_driver::RegisteredPartyCompletionTransport;
    friend class ExplicitOwnerPublicEffectsAuthority;
public:
    PartyBaselineOwnerEffectsAuthority(
        const PartyBaselineOwnerEffectsAuthority&) = delete;
    PartyBaselineOwnerEffectsAuthority& operator=(
        const PartyBaselineOwnerEffectsAuthority&) = delete;
    PartyBaselineOwnerEffectsAuthority(
        PartyBaselineOwnerEffectsAuthority&&) noexcept;
    PartyBaselineOwnerEffectsAuthority& operator=(
        PartyBaselineOwnerEffectsAuthority&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    static PartyBaselineOwnerEffectsAuthority test_only_mint(
        PrivatePartyBaselineOwnerEffects);
#endif
};

class OwnerScoreTruthAuthority final {
    std::array<PrivateOwnerScoringTruth, 2> rounds_;
    std::array<std::array<Digest, 3>, 2> party_sessions_{};
    std::atomic_bool live_{true};
    OwnerScoreTruthAuthority(
        std::array<PrivateOwnerScoringTruth, 2>,
        std::array<std::array<Digest, 3>, 2>);
    friend class BaselineOwnerScoringParentCollector;
    friend class BaselineOwnerScoringLaunchAuthority;
    friend class BaselineOwnerTruthCapsuleBridge;
public:
    OwnerScoreTruthAuthority(const OwnerScoreTruthAuthority&) = delete;
    OwnerScoreTruthAuthority& operator=(const OwnerScoreTruthAuthority&) =
        delete;
    OwnerScoreTruthAuthority(OwnerScoreTruthAuthority&&) noexcept;
    OwnerScoreTruthAuthority& operator=(OwnerScoreTruthAuthority&&) = delete;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    const std::array<PrivateOwnerScoringTruth, 2>& test_only_rounds() const {
        return rounds_;
    }
#endif
};

class BaselineOwnerScoringLaunchAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit BaselineOwnerScoringLaunchAuthority(std::unique_ptr<Storage>);
    friend class BaselineOwnerScoringParentCollector;
public:
    BaselineOwnerScoringLaunchAuthority(
        const BaselineOwnerScoringLaunchAuthority&) = delete;
    BaselineOwnerScoringLaunchAuthority& operator=(
        const BaselineOwnerScoringLaunchAuthority&) = delete;
    BaselineOwnerScoringLaunchAuthority(
        BaselineOwnerScoringLaunchAuthority&&) noexcept;
    BaselineOwnerScoringLaunchAuthority& operator=(
        BaselineOwnerScoringLaunchAuthority&&) = delete;
    ~BaselineOwnerScoringLaunchAuthority();

    OwnerScoreTruthAuthority take_owner(unsigned owner);
};

class BaselineOwnerScoringParentCollector final {
    std::array<std::array<
        std::optional<PrivatePartyBaselineOwnerEffects>, 3>, 2> parties_;
    std::mutex mutex_;
    bool poisoned_{};
    bool finished_{};
public:
    BaselineOwnerScoringParentCollector() = default;
    BaselineOwnerScoringParentCollector(
        const BaselineOwnerScoringParentCollector&) = delete;
    BaselineOwnerScoringParentCollector& operator=(
        const BaselineOwnerScoringParentCollector&) = delete;
    void submit(PartyBaselineOwnerEffectsAuthority&&);
    BaselineOwnerScoringLaunchAuthority finish();
};

// Parent-owned process handoff. Each accepted round consumes all three
// kernel-authenticated child completion endpoints, requires the children to
// exit successfully, and only then commits the three party copies to the
// private 3x2 join. It never exposes an owner mapping or packet bytes.
class BaselineOwnerScoringParentHandoff final {
    BaselineOwnerScoringParentCollector collector_;
    std::array<bool, 2> accepted_rounds_{};
    std::mutex mutex_;
    bool poisoned_{};
    bool finished_{};
public:
    BaselineOwnerScoringParentHandoff() = default;
    BaselineOwnerScoringParentHandoff(
        const BaselineOwnerScoringParentHandoff&) = delete;
    BaselineOwnerScoringParentHandoff& operator=(
        const BaselineOwnerScoringParentHandoff&) = delete;
    void accept_round(registered_driver::ParentRoleChildren&&);
    BaselineOwnerScoringLaunchAuthority finish();
};

// Owner-side selected consent. The owner verifies this exact lineage and its
// own NF/two 520-byte rows before acknowledging the same fixed challenge to all
// three mutually authenticated computing parties.
struct BaselineOwnerConsentSelection {
    CaptureClassification classification{};
    unsigned round{};
    Digest run{}, trial{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest logical_owner_identity{};
    Digest roster_authority_identity{};
    Digest roster_root_identity{};
    Digest relation_source_identity{};
    Digest owner_effects_recipe_identity{};
    Digest policy_identity{};
};

class BaselineOwnerProofSigner {
public:
    virtual ~BaselineOwnerProofSigner() = default;
    virtual std::vector<unsigned char> prove(
        std::span<const unsigned char> challenge) = 0;
};

void confirm_baseline_owner_effects(
    const std::array<std::string, 3>& hostnames, int port_base,
    const OwnerInputContract&, const BaselineOwnerConsentSelection&,
    const Digest& public_nullifier,
    const std::array<std::span<const unsigned char>, 2>& public_rows,
    BaselineOwnerProofSigner&);

struct AuthenticatedBaselineOwnerReceiverSourceStatus {
    std::string schema;
    std::string status;
    bool exact_three_party_two_round_join;
    bool owner_effect_source_consumed;
    bool mutual_tls_owner_reauthentication;
    bool challenge_ack_bound_to_nonce_and_projection;
    bool hidden_candidate_receiver_factory_absent;
    bool owner_truth_routed_only_to_private_scorer;
    bool private_role_completion_transport_integrated;
    bool parent_three_by_two_join_integrated;
    bool observer_capture_export;
    bool parent_worker_process_launch_integrated;
    bool registered_driver_configured;
    bool launch_authorized;
};

AuthenticatedBaselineOwnerReceiverSourceStatus
authenticated_baseline_owner_receiver_source_status();

} // namespace registered_driver::baseline_disclosure
} // namespace financial
} // namespace kpi::mpc
