#pragma once

// Fresh owner-local input issuance for a two-round registered trial.  This
// source boundary carries public metadata and linear capabilities only.  It
// never accepts or exposes an owner file path, owner-file body, body digest,
// wallet authorization key, or stable logical-owner identity.

#include "registered_driver_bridge.hpp"
#include "registered_parent_bootstrap_contract.hpp"
#include "registered_persistent_fresh_trial_activation_contract.hpp"
#include "registered_preidentity_ready.hpp"
#include "../../private_batch_trial/privacy_fresh_owner_transactional_issuance_contract.hpp"
#include "../../private_batch_trial/privacy_registered_fresh_trial_producer_closure_contract.hpp"
#include "../owner_inputs_active.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace kpi::mpc::financial::fresh_owner_issuance {

using Digest = identity_registry::Digest;
using LogicalOwnerIdentity = std::array<unsigned char, 32>;

inline constexpr std::uint64_t OWNER_PRIVATE_INPUT_V2_BYTES = 84'333'120;

class OwnerLocalIssuanceAuthority;
class FreshOwnerRoundAuthority;
class ConsumedFreshOwnerRoundBootstrap;
class AuthenticatedOwnerProcessBundle;
class FreshOwnerRoundContinuityAuthority;
class FreshOwnerProcessSupervisor;
class AcceptedRound1InputHistoryAuthority;
class AcceptedRound1SuccessorHistoryAuthority;
class AcceptedRound1InputHistoryBootstrapAuthority;
class AcceptedRound1SuccessorHistoryBootstrapAuthority;

// Complete production mint bridge.  Plain receipts, paths and digests cannot
// reach either private constructor; only authenticated process capabilities
// created by the exact-three child supervisor can be consumed here.
class FreshOwnerProcessMintBridge final {
public:
    static OwnerLocalIssuanceAuthority mint_owner(
        AuthenticatedOwnerProcessBundle&&,
        registered_driver::RegisteredOwnerIssuancePermit&&);
#if defined(KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP) && \
    defined(KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP)
    static OwnerLocalIssuanceAuthority mint_owner(
        AuthenticatedOwnerProcessBundle&&);
#endif
};

// Complete bootstrap bridge used by the selected parent.  It has no digest or
// receipt overload: a round becomes consumable only with its matching typed
// accepted-history capability.
class FreshOwnerRoundBootstrapBridge final {
public:
    static ConsumedFreshOwnerRoundBootstrap consume(
        FreshOwnerRoundAuthority&&,
        AcceptedRound1InputHistoryBootstrapAuthority&&,
        FreshOwnerRoundContinuityAuthority&&);
    static ConsumedFreshOwnerRoundBootstrap consume(
        FreshOwnerRoundAuthority&&,
        AcceptedRound1SuccessorHistoryBootstrapAuthority&&,
        FreshOwnerRoundContinuityAuthority&&);
};

struct PublicOwnerRoundIssuance {
    unsigned round{};
    Digest attempt{};
    Digest cohort{};
    Digest accepted_input_head_identity{};
    // Round 1 binds the accepted genesis-history authority. Round 2 must be
    // minted only after consuming the accepted Round 1 successor-history
    // authority. A digest alone is metadata, never the production minter.
    Digest history_gate_identity{};
    OwnerInputContract contract{};
    Digest contract_identity{};
    Digest file_identity{};
    Digest file_metadata_identity{};
    std::uint64_t file_bytes{};
    Digest owner_tls_spki_identity{};
    std::array<Digest, 3> server_tls_spki_identities{};
};

// The logical-owner binding is opaque and scoped to this fresh run/trial/root.
// It is not the stable identity and cannot be opened by the controller.
struct PublicOwnerIssuanceReceipt {
    registered_driver::CaptureClassification classification{};
    Digest authority_identity{};
    Digest registration_identity{};
    Digest service_identity{};
    Digest controller_source_identity{};
    Digest controller_build_identity{};
    Digest owner_issuer_source_identity{};
    Digest owner_issuer_build_identity{};
    Digest run{};
    Digest trial{};
    Digest root_identity{};
    Digest baseline_policy_identity{};
    unsigned owner_component{};
    Digest owner_process_identity{};
    std::array<PublicOwnerRoundIssuance, 2> rounds{};
    Digest logical_owner_binding{};
    Digest issuance_identity{};
};

// A concrete selected wallet verifier will retain the expected long-lived
// authorization public key/record.  Proof bytes never supply or replace that
// expected key.  Its identity and verification entry points are private to the
// issuance/receiver boundary.
class LongLivedOwnerProofVerifier {
    virtual LogicalOwnerIdentity logical_identity() const = 0;
    virtual bool verify(
        std::span<const unsigned char> challenge,
        std::span<const unsigned char> proof) const = 0;
    friend class OwnerLocalIssuanceAuthority;
    friend class FreshOwnerTrialIssuanceAuthority;
    friend class BaselineOwnerRosterReceiverSession;
    friend class FreshOwnerTransactionalIssuanceBridge;
public:
    virtual ~LongLivedOwnerProofVerifier() = default;
};

class OwnerLocalIssuanceAuthority final {
    PublicOwnerIssuanceReceipt receipt_;
    std::shared_ptr<const LongLivedOwnerProofVerifier> verifier_;
    LogicalOwnerIdentity logical_owner_identity_{};
    Digest binding_nonce_{};
    std::optional<registered_driver::RegisteredOwnerIssuancePermit>
        preidentity_permit_;
    std::atomic_bool live_{true};
    OwnerLocalIssuanceAuthority(
        PublicOwnerIssuanceReceipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier>, Digest,
        registered_driver::RegisteredOwnerIssuancePermit&&);
    OwnerLocalIssuanceAuthority(
        PublicOwnerIssuanceReceipt&&,
        std::shared_ptr<const LongLivedOwnerProofVerifier>&&,
        LogicalOwnerIdentity, Digest,
        registered_driver::RegisteredOwnerIssuancePermit&&) noexcept;
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    OwnerLocalIssuanceAuthority(
        PublicOwnerIssuanceReceipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier>, Digest);
#endif
    friend class FreshOwnerTrialIssuanceBridge;
    friend class FreshOwnerTransactionalIssuanceBridge;
    friend class FreshOwnerProcessMintBridge;
    friend class registered_driver::RegisteredPreidentityReadyIssuanceBridge;
public:
    OwnerLocalIssuanceAuthority(const OwnerLocalIssuanceAuthority&) = delete;
    OwnerLocalIssuanceAuthority& operator=(
        const OwnerLocalIssuanceAuthority&) = delete;
    OwnerLocalIssuanceAuthority(OwnerLocalIssuanceAuthority&&) noexcept;
    OwnerLocalIssuanceAuthority& operator=(
        OwnerLocalIssuanceAuthority&&) = delete;
    const PublicOwnerIssuanceReceipt& public_receipt() const {
        return receipt_;
    }
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    static OwnerLocalIssuanceAuthority test_only_mint(
        PublicOwnerIssuanceReceipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier>,
        Digest binding_nonce);
    static OwnerLocalIssuanceAuthority test_only_mint(
        PublicOwnerIssuanceReceipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier>,
        Digest binding_nonce,
        registered_driver::RegisteredOwnerIssuancePermit&&);
#endif
};

// Implemented by a future permission-separated, monotonic consumed-identity
// service.  Only its typed capability below can reach the join.
class ExternalOwnerIssuanceReplayRegistry {
public:
    virtual ~ExternalOwnerIssuanceReplayRegistry() = default;
    virtual void consume(std::span<const Digest>) = 0;
};

struct PublicOwnerIssuanceReplayPolicy {
    Digest authority_identity{};
    Digest policy_identity{};
    bool permission_separated{};
    bool monotonic{};
    bool child_path_exposed{};
    bool child_fd_exposed{};
};

class OwnerIssuanceReplayGuardAuthority final {
    PublicOwnerIssuanceReplayPolicy policy_;
    std::shared_ptr<ExternalOwnerIssuanceReplayRegistry> registry_;
    std::atomic_bool live_{true};
    OwnerIssuanceReplayGuardAuthority(
        PublicOwnerIssuanceReplayPolicy,
        std::shared_ptr<ExternalOwnerIssuanceReplayRegistry>);
    friend class FreshOwnerTrialIssuanceBridge;
public:
    OwnerIssuanceReplayGuardAuthority(
        const OwnerIssuanceReplayGuardAuthority&) = delete;
    OwnerIssuanceReplayGuardAuthority& operator=(
        const OwnerIssuanceReplayGuardAuthority&) = delete;
    OwnerIssuanceReplayGuardAuthority(
        OwnerIssuanceReplayGuardAuthority&&) noexcept;
    OwnerIssuanceReplayGuardAuthority& operator=(
        OwnerIssuanceReplayGuardAuthority&&) = delete;
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    static OwnerIssuanceReplayGuardAuthority test_only_mint(
        PublicOwnerIssuanceReplayPolicy,
        std::shared_ptr<ExternalOwnerIssuanceReplayRegistry>);
#endif
};

struct PublicFreshOwnerTrialIssuanceReceipt {
    registered_driver::CaptureClassification classification{};
    Digest authority_identity{};
    Digest registration_identity{};
    Digest service_identity{};
    Digest controller_source_identity{};
    Digest controller_build_identity{};
    Digest owner_issuer_source_identity{};
    Digest owner_issuer_build_identity{};
    Digest run{};
    Digest trial{};
    Digest root_identity{};
    Digest baseline_policy_identity{};
    Digest roster_authority_identity{};
    Digest replay_policy_identity{};
    std::array<PublicOwnerIssuanceReceipt, 3> owners{};
    Digest issuance_identity{};
};

// The sole causal handoff from source-owned owner issuance into persistent
// MPC activation.  It retains the exact pre-identity topology/process pair
// and the issuance lineage; no receipt, PID, FD, digest, or split is public.
class FreshOwnerPersistentActivationAuthority final {
    std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt> receipt_;
    registered_driver::RegisteredPreidentityReadyIssuanceResidual ready_;
    std::atomic_bool live_{true};
    FreshOwnerPersistentActivationAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>,
        registered_driver::RegisteredPreidentityReadyIssuanceResidual&&)
        noexcept;
    friend class FreshOwnerTrialIssuanceAuthority;
    friend class FreshOwnerTrialIssuanceBridge;
    friend class FreshOwnerTrialSplit;
    friend class FreshOwnerTransactionalIssuanceBridge;
    friend class registered_driver::
        RegisteredPersistentFreshTrialActivationBridge;
public:
    FreshOwnerPersistentActivationAuthority(
        const FreshOwnerPersistentActivationAuthority&) = delete;
    FreshOwnerPersistentActivationAuthority& operator=(
        const FreshOwnerPersistentActivationAuthority&) = delete;
    FreshOwnerPersistentActivationAuthority(
        FreshOwnerPersistentActivationAuthority&&) noexcept;
    FreshOwnerPersistentActivationAuthority& operator=(
        FreshOwnerPersistentActivationAuthority&&) = delete;
};

// Independent one-shot child for the ten-stream producer closure.  It is
// minted by the same causal issuance as the persistent activation child so
// binding the producer cannot consume or discard activation authority.
class FreshOwnerProducerClosureAuthority final {
    std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt> receipt_;
    std::atomic_bool live_{true};
    explicit FreshOwnerProducerClosureAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>) noexcept;
    friend class FreshOwnerTrialIssuanceAuthority;
    friend class FreshOwnerTrialIssuanceBridge;
    friend class FreshOwnerTrialSplit;
    friend class registered_driver::RegisteredFreshTrialProducerClosureBridge;
public:
    FreshOwnerProducerClosureAuthority(
        const FreshOwnerProducerClosureAuthority&) = delete;
    FreshOwnerProducerClosureAuthority& operator=(
        const FreshOwnerProducerClosureAuthority&) = delete;
    FreshOwnerProducerClosureAuthority(
        FreshOwnerProducerClosureAuthority&&) noexcept;
    FreshOwnerProducerClosureAuthority& operator=(
        FreshOwnerProducerClosureAuthority&&) = delete;
};

class FreshOwnerTrialIssuanceAuthority final {
    std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt> receipt_;
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids_{};
    std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
        verifiers_{};
    std::optional<FreshOwnerPersistentActivationAuthority>
        persistent_activation_;
    std::optional<FreshOwnerProducerClosureAuthority> producer_closure_;
    std::atomic_bool live_{true};
    FreshOwnerTrialIssuanceAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>,
        std::array<LogicalOwnerIdentity, 3>,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>,
        FreshOwnerPersistentActivationAuthority&&) noexcept;
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    FreshOwnerTrialIssuanceAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>,
        std::array<LogicalOwnerIdentity, 3>,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>);
#endif
    void validate_for_persistent_activation() const;
    friend class FreshOwnerTrialIssuanceBridge;
    friend class FreshOwnerTransactionalIssuanceBridge;
#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
    friend class registered_driver::
        RegisteredFreshTrialProducerClosureBridge;
#endif
    friend class registered_driver::
        RegisteredPersistentFreshTrialActivationBridge;
public:
    FreshOwnerTrialIssuanceAuthority(
        const FreshOwnerTrialIssuanceAuthority&) = delete;
    FreshOwnerTrialIssuanceAuthority& operator=(
        const FreshOwnerTrialIssuanceAuthority&) = delete;
    FreshOwnerTrialIssuanceAuthority(
        FreshOwnerTrialIssuanceAuthority&&) noexcept;
    FreshOwnerTrialIssuanceAuthority& operator=(
        FreshOwnerTrialIssuanceAuthority&&) = delete;
    const PublicFreshOwnerTrialIssuanceReceipt& public_receipt() const {
        return *receipt_;
    }
};

struct FreshOwnerTransactionalIssuanceOutcomeStorage;

// Indivisible committed-or-STOP result of the transactional replay join.
// It exposes no receipt, state, replay set, or authority extractor.
class FreshOwnerTransactionalIssuanceOutcomeAuthority final {
    std::unique_ptr<FreshOwnerTransactionalIssuanceOutcomeStorage> storage_;
    explicit FreshOwnerTransactionalIssuanceOutcomeAuthority(
        std::unique_ptr<FreshOwnerTransactionalIssuanceOutcomeStorage>&&)
        noexcept;
    bool committed_for_round1_process() const noexcept;
    FreshOwnerTrialIssuanceAuthority
        take_committed_for_round1_process() noexcept;
    bool retains_round1_process_lineage() const noexcept;
    friend class FreshOwnerTransactionalIssuanceBridge;
    friend class FreshOwnerProcessSupervisor;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound1AttemptOutcomeTestBridge;
#endif
#ifdef KPI_FRESH_OWNER_TRANSACTIONAL_ISSUANCE_TEST_SETUP
    friend class FreshOwnerTransactionalIssuanceTestBridge;
#endif
public:
    FreshOwnerTransactionalIssuanceOutcomeAuthority(
        const FreshOwnerTransactionalIssuanceOutcomeAuthority&) = delete;
    FreshOwnerTransactionalIssuanceOutcomeAuthority& operator=(
        const FreshOwnerTransactionalIssuanceOutcomeAuthority&) = delete;
    FreshOwnerTransactionalIssuanceOutcomeAuthority(
        FreshOwnerTransactionalIssuanceOutcomeAuthority&&) noexcept;
    FreshOwnerTransactionalIssuanceOutcomeAuthority& operator=(
        FreshOwnerTransactionalIssuanceOutcomeAuthority&&) = delete;
    ~FreshOwnerTransactionalIssuanceOutcomeAuthority();
};

#ifdef KPI_FRESH_OWNER_TRANSACTIONAL_ISSUANCE_TEST_SETUP
enum class TestFreshOwnerTransactionalIssuanceOutcome : unsigned char {
    Committed,
    UnavailableStop,
    Invalid,
};

class FreshOwnerTransactionalIssuanceTestBridge final {
    FreshOwnerTransactionalIssuanceTestBridge() = delete;
public:
    static TestFreshOwnerTransactionalIssuanceOutcome inspect(
        const FreshOwnerTransactionalIssuanceOutcomeAuthority&) noexcept;
};
#endif

struct PublicFreshOwnerRoundReceipt {
    registered_driver::CaptureClassification classification{};
    unsigned round{};
    Digest authority_identity{};
    Digest registration_identity{};
    Digest service_identity{};
    Digest controller_source_identity{};
    Digest controller_build_identity{};
    Digest run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest accepted_input_head_identity{};
    Digest history_gate_identity{};
    Digest root_identity{};
    Digest issuance_identity{};
};

class FreshOwnerRoundAuthority final {
    PublicFreshOwnerRoundReceipt receipt_;
    std::array<OwnerInputContract, 3> contracts_{};
    std::atomic_bool live_{true};
    FreshOwnerRoundAuthority(
        PublicFreshOwnerRoundReceipt,
        std::array<OwnerInputContract, 3>);
    friend class FreshOwnerTrialIssuanceBridge;
    friend class FreshOwnerRoundBootstrapBridge;
    friend class FreshOwnerTrialSplit;
    friend class attempt_supervisor::RegisteredProposalBridge;
public:
    FreshOwnerRoundAuthority(const FreshOwnerRoundAuthority&) = delete;
    FreshOwnerRoundAuthority& operator=(
        const FreshOwnerRoundAuthority&) = delete;
    FreshOwnerRoundAuthority(FreshOwnerRoundAuthority&&) noexcept;
    FreshOwnerRoundAuthority& operator=(FreshOwnerRoundAuthority&&) = delete;
    const PublicFreshOwnerRoundReceipt& public_receipt() const {
        return receipt_;
    }
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    const std::array<OwnerInputContract, 3>& test_only_contracts() const {
        return contracts_;
    }
#endif
};

class ConsumedFreshOwnerRoundBootstrap final {
    PublicFreshOwnerRoundReceipt receipt_;
    std::array<OwnerInputContract, 3> contracts_{};
    std::atomic_bool live_{true};
    ConsumedFreshOwnerRoundBootstrap(
        PublicFreshOwnerRoundReceipt,
        std::array<OwnerInputContract, 3>);
    friend class FreshOwnerRoundBootstrapBridge;
    friend class registered_driver::RegisteredParentBootstrapTransport;
public:
    ConsumedFreshOwnerRoundBootstrap(
        const ConsumedFreshOwnerRoundBootstrap&) = delete;
    ConsumedFreshOwnerRoundBootstrap& operator=(
        const ConsumedFreshOwnerRoundBootstrap&) = delete;
    ConsumedFreshOwnerRoundBootstrap(
        ConsumedFreshOwnerRoundBootstrap&&) noexcept;
    ConsumedFreshOwnerRoundBootstrap& operator=(
        ConsumedFreshOwnerRoundBootstrap&&) = delete;
    const PublicFreshOwnerRoundReceipt& public_receipt() const {
        return receipt_;
    }
    const std::array<OwnerInputContract, 3>& contracts() const {
        return contracts_;
    }
};

struct PublicBaselineOwnerRosterReceipt {
    registered_driver::CaptureClassification classification{};
    Digest run{};
    Digest trial{};
    Digest root_identity{};
    Digest policy_identity{};
    Digest roster_authority_identity{};
    Digest issuance_identity{};
};

class BaselineOwnerRosterAuthority final {
    PublicBaselineOwnerRosterReceipt receipt_;
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids_{};
    std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
        verifiers_{};
    std::atomic_bool live_{true};
    BaselineOwnerRosterAuthority(
        PublicBaselineOwnerRosterReceipt,
        std::array<LogicalOwnerIdentity, 3>,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>);
    friend class FreshOwnerTrialIssuanceBridge;
    friend class FreshOwnerTrialSplit;
    friend class BaselineOwnerRosterBridge;
public:
    BaselineOwnerRosterAuthority(const BaselineOwnerRosterAuthority&) = delete;
    BaselineOwnerRosterAuthority& operator=(
        const BaselineOwnerRosterAuthority&) = delete;
    BaselineOwnerRosterAuthority(BaselineOwnerRosterAuthority&&) noexcept;
    BaselineOwnerRosterAuthority& operator=(
        BaselineOwnerRosterAuthority&&) = delete;
    const PublicBaselineOwnerRosterReceipt& public_receipt() const {
        return receipt_;
    }
};

class FreshOwnerTrialSplit final {
    std::array<std::optional<FreshOwnerRoundAuthority>, 2> rounds_{};
    std::optional<BaselineOwnerRosterAuthority> roster_;
    std::optional<FreshOwnerPersistentActivationAuthority>
        persistent_activation_;
    std::optional<FreshOwnerProducerClosureAuthority> producer_closure_;
    FreshOwnerTrialSplit(
        FreshOwnerRoundAuthority&&, FreshOwnerRoundAuthority&&,
        std::optional<BaselineOwnerRosterAuthority>&&,
        std::optional<FreshOwnerPersistentActivationAuthority>&&,
        std::optional<FreshOwnerProducerClosureAuthority>&&) noexcept;
    friend class FreshOwnerTrialIssuanceBridge;
    friend class FreshOwnerProcessSupervisor;
public:
    FreshOwnerTrialSplit(const FreshOwnerTrialSplit&) = delete;
    FreshOwnerTrialSplit& operator=(const FreshOwnerTrialSplit&) = delete;
    FreshOwnerTrialSplit(FreshOwnerTrialSplit&&) = delete;
    FreshOwnerTrialSplit& operator=(FreshOwnerTrialSplit&&) = delete;
    FreshOwnerRoundAuthority take_round(unsigned round);
    BaselineOwnerRosterAuthority take_baseline_roster();
    FreshOwnerPersistentActivationAuthority take_persistent_activation();
    FreshOwnerProducerClosureAuthority take_producer_closure();
};

struct PublicBaselineOwnerRosterReceiverReceipt {
    registered_driver::CaptureClassification classification{};
    unsigned round{};
    unsigned role{};
    Digest run{};
    Digest trial{};
    Digest root_identity{};
    Digest policy_identity{};
    Digest roster_authority_identity{};
    Digest receiver_identity{};
};

class BaselineOwnerRosterReceiverAuthority final {
    PublicBaselineOwnerRosterReceiverReceipt receipt_;
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids_{};
    std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
        verifiers_{};
    std::atomic_bool live_{true};
    BaselineOwnerRosterReceiverAuthority(
        PublicBaselineOwnerRosterReceiverReceipt,
        std::array<LogicalOwnerIdentity, 3>,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>);
    friend class BaselineOwnerRosterReceiverSplit;
    friend class BaselineOwnerRosterBridge;
    friend class BaselineOwnerRosterReceiverBridge;
public:
    BaselineOwnerRosterReceiverAuthority(
        const BaselineOwnerRosterReceiverAuthority&) = delete;
    BaselineOwnerRosterReceiverAuthority& operator=(
        const BaselineOwnerRosterReceiverAuthority&) = delete;
    BaselineOwnerRosterReceiverAuthority(
        BaselineOwnerRosterReceiverAuthority&&) noexcept;
    BaselineOwnerRosterReceiverAuthority& operator=(
        BaselineOwnerRosterReceiverAuthority&&) = delete;
    const PublicBaselineOwnerRosterReceiverReceipt& public_receipt() const {
        return receipt_;
    }
};

class BaselineOwnerRosterReceiverSplit final {
    std::array<std::optional<BaselineOwnerRosterReceiverAuthority>, 6>
        receivers_{};
    BaselineOwnerRosterReceiverSplit(
        const PublicBaselineOwnerRosterReceipt&,
        const std::array<LogicalOwnerIdentity, 3>&,
        const std::array<
            std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>&);
    friend class BaselineOwnerRosterBridge;
public:
    BaselineOwnerRosterReceiverSplit(
        const BaselineOwnerRosterReceiverSplit&) = delete;
    BaselineOwnerRosterReceiverSplit& operator=(
        const BaselineOwnerRosterReceiverSplit&) = delete;
    BaselineOwnerRosterReceiverSplit(
        BaselineOwnerRosterReceiverSplit&&) = delete;
    BaselineOwnerRosterReceiverSplit& operator=(
        BaselineOwnerRosterReceiverSplit&&) = delete;
    BaselineOwnerRosterReceiverAuthority take(unsigned round, unsigned role);
};

class VerifiedLogicalOwnerConsent final {
    unsigned owner_{};
    LogicalOwnerIdentity logical_owner_identity_{};
    std::atomic_bool live_{true};
    VerifiedLogicalOwnerConsent(unsigned, LogicalOwnerIdentity);
    friend class BaselineOwnerRosterReceiverSession;
    friend class BaselineOwnerRosterVerifiedBridge;
public:
    VerifiedLogicalOwnerConsent(const VerifiedLogicalOwnerConsent&) = delete;
    VerifiedLogicalOwnerConsent& operator=(
        const VerifiedLogicalOwnerConsent&) = delete;
    VerifiedLogicalOwnerConsent(VerifiedLogicalOwnerConsent&&) noexcept;
    VerifiedLogicalOwnerConsent& operator=(
        VerifiedLogicalOwnerConsent&&) = delete;
};

class VerifiedBaselineOwnerRoster final {
    PublicBaselineOwnerRosterReceiverReceipt receipt_;
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids_{};
    std::atomic_bool live_{true};
    VerifiedBaselineOwnerRoster(
        PublicBaselineOwnerRosterReceiverReceipt,
        std::array<LogicalOwnerIdentity, 3>);
    friend class BaselineOwnerRosterReceiverSession;
    friend class BaselineOwnerRosterVerifiedBridge;
public:
    VerifiedBaselineOwnerRoster(const VerifiedBaselineOwnerRoster&) = delete;
    VerifiedBaselineOwnerRoster& operator=(
        const VerifiedBaselineOwnerRoster&) = delete;
    VerifiedBaselineOwnerRoster(VerifiedBaselineOwnerRoster&&) noexcept;
    VerifiedBaselineOwnerRoster& operator=(
        VerifiedBaselineOwnerRoster&&) = delete;
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    const std::array<LogicalOwnerIdentity, 3>&
    test_only_logical_owner_ids() const { return logical_owner_ids_; }
#endif
};

// Complete capability bridge.  Stable IDs are absent from every public
// receipt; a caller can obtain them only by consuming a genuine verified
// possession capability exactly once.
class ConsumedVerifiedLogicalOwnerConsent final {
    unsigned owner_{};
    LogicalOwnerIdentity logical_owner_identity_{};
    ConsumedVerifiedLogicalOwnerConsent(unsigned, LogicalOwnerIdentity);
    friend class BaselineOwnerRosterVerifiedBridge;
public:
    ConsumedVerifiedLogicalOwnerConsent(
        const ConsumedVerifiedLogicalOwnerConsent&) = delete;
    ConsumedVerifiedLogicalOwnerConsent& operator=(
        const ConsumedVerifiedLogicalOwnerConsent&) = delete;
    ConsumedVerifiedLogicalOwnerConsent(
        ConsumedVerifiedLogicalOwnerConsent&&) noexcept = default;
    ConsumedVerifiedLogicalOwnerConsent& operator=(
        ConsumedVerifiedLogicalOwnerConsent&&) = delete;
    unsigned owner() const { return owner_; }
    const LogicalOwnerIdentity& logical_owner_identity() const {
        return logical_owner_identity_;
    }
};

class ConsumedVerifiedBaselineOwnerRoster final {
    PublicBaselineOwnerRosterReceiverReceipt receipt_;
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids_{};
    ConsumedVerifiedBaselineOwnerRoster(
        PublicBaselineOwnerRosterReceiverReceipt,
        std::array<LogicalOwnerIdentity, 3>);
    friend class BaselineOwnerRosterVerifiedBridge;
public:
    ConsumedVerifiedBaselineOwnerRoster(
        const ConsumedVerifiedBaselineOwnerRoster&) = delete;
    ConsumedVerifiedBaselineOwnerRoster& operator=(
        const ConsumedVerifiedBaselineOwnerRoster&) = delete;
    ConsumedVerifiedBaselineOwnerRoster(
        ConsumedVerifiedBaselineOwnerRoster&&) noexcept = default;
    ConsumedVerifiedBaselineOwnerRoster& operator=(
        ConsumedVerifiedBaselineOwnerRoster&&) = delete;
    const PublicBaselineOwnerRosterReceiverReceipt& public_receipt() const {
        return receipt_;
    }
    const std::array<LogicalOwnerIdentity, 3>& logical_owner_ids() const {
        return logical_owner_ids_;
    }
};

class BaselineOwnerRosterVerifiedBridge final {
public:
    static ConsumedVerifiedLogicalOwnerConsent consume(
        VerifiedLogicalOwnerConsent&&);
    static ConsumedVerifiedBaselineOwnerRoster consume(
        VerifiedBaselineOwnerRoster&&);
};

class BaselineOwnerRosterReceiverSession final {
    PublicBaselineOwnerRosterReceiverReceipt receipt_;
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids_{};
    std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
        verifiers_{};
    std::array<bool, 3> verified_{};
    bool poisoned_{};
    bool finished_{};
    BaselineOwnerRosterReceiverSession(
        PublicBaselineOwnerRosterReceiverReceipt,
        std::array<LogicalOwnerIdentity, 3>,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>);
    friend class BaselineOwnerRosterReceiverBridge;
public:
    BaselineOwnerRosterReceiverSession(
        const BaselineOwnerRosterReceiverSession&) = delete;
    BaselineOwnerRosterReceiverSession& operator=(
        const BaselineOwnerRosterReceiverSession&) = delete;
    BaselineOwnerRosterReceiverSession(
        BaselineOwnerRosterReceiverSession&&) = delete;
    BaselineOwnerRosterReceiverSession& operator=(
        BaselineOwnerRosterReceiverSession&&) = delete;
    VerifiedLogicalOwnerConsent verify_owner_proof(
        unsigned owner, std::span<const unsigned char> challenge,
        std::span<const unsigned char> proof);
    VerifiedBaselineOwnerRoster finish();
};

class FreshOwnerTrialIssuanceBridge final {
    static FreshOwnerTrialIssuanceAuthority join_exact_three_impl(
        registered_driver::RegisteredPreidentityReadyIssuanceResidual*,
        std::array<OwnerLocalIssuanceAuthority, 3>&&,
        OwnerIssuanceReplayGuardAuthority&&,
        const Digest& roster_authority_identity);
public:
    static FreshOwnerTrialIssuanceAuthority join_exact_three(
        registered_driver::RegisteredPreidentityReadyIssuanceResidual&&,
        std::array<OwnerLocalIssuanceAuthority, 3>&&,
        OwnerIssuanceReplayGuardAuthority&&,
        const Digest& roster_authority_identity);
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    static FreshOwnerTrialIssuanceAuthority join_exact_three(
        std::array<OwnerLocalIssuanceAuthority, 3>&&,
        OwnerIssuanceReplayGuardAuthority&&,
        const Digest& roster_authority_identity);
#endif
    static FreshOwnerTrialSplit split(
        FreshOwnerTrialIssuanceAuthority&&);
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
    static void test_only_set_split_postprepare_hook(
        void (*hook)()) noexcept;
#endif
};

class BaselineOwnerRosterBridge final {
public:
    static BaselineOwnerRosterReceiverSplit split(
        BaselineOwnerRosterAuthority&&);
};

class BaselineOwnerRosterReceiverBridge final {
public:
    static BaselineOwnerRosterReceiverSession consume(
        BaselineOwnerRosterReceiverAuthority&&,
        registered_driver::CaptureClassification,
        unsigned round, unsigned role,
        const Digest& run, const Digest& trial,
        const Digest& policy_identity);
};

// The exact public identity of the known consumed 20261028-05 owner root.  It
// is a tombstone only; no path is accepted by any issuance API.
Digest mandatory_consumed_owner_root_identity();

struct FreshOwnerIssuanceSourceStatus {
    std::string schema;
    std::string status;
    bool exact_three_owner_process_authorities;
    bool two_fresh_round_contracts;
    bool round2_history_metadata_bound;
    bool controller_reads_or_hashes_private_body;
    bool stable_logical_owner_ids_public;
    bool baseline_roster_possession_verification;
    bool permission_separated_replay_registry_interface;
    bool preidentity_owner_permit_gate;
    bool causal_selected_owner_plan_factory;
    bool transactional_replay_prepare_commit;
    bool persistent_activation_child;
    bool producer_closure_child;
    bool postissuance_failure_composite;
    bool authenticated_owner_process_adapter;
    bool private_lifecycle_owner_process_adapter;
    bool round2_accepted_history_capability_gate;
    bool permission_separated_replay_registry_minter;
    bool selected_driver_round_adapter;
    bool registered_driver_configured;
    bool launch_authorized;
};

FreshOwnerIssuanceSourceStatus fresh_owner_issuance_source_status();

} // namespace kpi::mpc::financial::fresh_owner_issuance
