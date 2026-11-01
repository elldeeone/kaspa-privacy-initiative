#pragma once

#include "../mpc-prover/financial/owner_truth_score_handoff.hpp"
#include "../mpc-prover/financial/candidate_owner_truth_post_barrier_bridge.hpp"
#include "../mpc-prover/financial/registered_measurement_capture_bridge_contract.hpp"
#include "privacy_capture_producer_runtime_contract.hpp"
#include "privacy_measurement_observer_capture_bridge.hpp"
#include "privacy_measurement_parent_manifest_contract.hpp"
#include "privacy_measurement_runtime_bridge_contract.hpp"
#include "privacy_owner_score_output_split_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <mutex>
#include <memory>
#include <optional>
#include <string>

namespace kpb::native_terminal {
class MatchedNativeTerminalProducerBundle;
class PaymentLifecycleCompletionAuthority;
class TerminalV2ModelAdmissionAuthority;
}

namespace kpb::measurement {

namespace runtime_bridge { class SealedChildOutputAuthority; }
namespace phase_scope { class ObservationOutputJoinAuthority; }

using Digest = std::array<unsigned char, 32>;

enum class Classification : unsigned char {
    HiddenCandidate = 1,
    TransparentBaseline = 2,
};

enum class ManifestComponent : unsigned char {
    FinancialCore = 1,
    P1Capture = 2,
    C1Supervisor = 3,
    TerminalCapture = 4,
    Dispatcher = 5,
    Producer = 6,
    Observer = 7,
    OwnerScore = 8,
    Aggregate = 9,
    OwnerComparison = 10,
};

struct ManifestEntry {
    ManifestComponent component{};
    Digest source_identity{};
    Digest build_identity{};
    Digest runtime_identity{};
    Digest assets_identity{};
    Digest pinned_executable_identity{};
    Digest launcher_identity{};
    bool operator==(const ManifestEntry&) const = default;
};

Digest recompute_finite_manifest_identity(
    const std::array<ManifestEntry, 10>& entries);

struct FiniteManifestBinding {
    Digest manifest_identity{};
    Digest parent_recomputation_identity{};
    std::array<ManifestEntry, 10> entries{};
    bool operator==(const FiniteManifestBinding&) const = default;
};

struct WorkerBinding {
    Digest source_identity{};
    Digest build_identity{};
    Digest runtime_identity{};
    Digest assets_identity{};
    Digest pinned_executable_identity{};
    Digest launcher_identity{};
    bool operator==(const WorkerBinding&) const = default;
};

struct RunBinding {
    Classification classification{};
    Digest comparison_selection{};
    Digest run_selection{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest capture{};
    Digest method{};
    Digest workload{};
    Digest source_closure{};
    Digest runtime{};
    FiniteManifestBinding finite_manifest;
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest capture_source{};
    Digest capture_build{};
    Digest capture_runtime{};
    Digest capture_launcher{};
    WorkerBinding observer_worker;
    WorkerBinding score_worker;
    WorkerBinding aggregate_worker;
    std::array<Digest, 2> financial_runs{};
    std::array<Digest, 2> round_attempts{};
    std::array<Digest, 2> round_cohorts{};
    std::array<Digest, 2> round_capture_plans{};
    std::array<Digest, 2> projections{};
    bool operator==(const RunBinding&) const = default;
};

// Pure structural validation only. This does not mint or consume authority.
// Shared private data planes use it to avoid weaker duplicate validators.
void validate_measurement_run_binding(const RunBinding&);

class Refused final : public std::exception {
public:
    const char* what() const noexcept override;
};

struct PublicParentManifestRecomputation {
    FiniteManifestBinding manifest;
    Digest parent_process_identity{};
    Digest parent_executable_identity{};
    Digest recomputation_receipt{};
};

class ParentManifestRecomputationAuthority final {
    PublicParentManifestRecomputation receipt_;
    std::atomic_bool live_{true};
    explicit ParentManifestRecomputationAuthority(
        PublicParentManifestRecomputation);
    friend class TrialCaptureJoiner;
    friend class ParentManifestRecomputationFactory;
public:
    ParentManifestRecomputationAuthority(
        const ParentManifestRecomputationAuthority&) = delete;
    ParentManifestRecomputationAuthority& operator=(
        const ParentManifestRecomputationAuthority&) = delete;
    ParentManifestRecomputationAuthority(
        ParentManifestRecomputationAuthority&&) noexcept;
    ParentManifestRecomputationAuthority& operator=(
        ParentManifestRecomputationAuthority&&) = delete;
    const PublicParentManifestRecomputation& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static ParentManifestRecomputationAuthority test_only_mint(
        PublicParentManifestRecomputation);
#endif
};

struct PublicPartyCompletion {
    RunBinding binding;
    unsigned round{};
    unsigned role{};
    Digest financial_run{};
    Digest trial{};
    Digest attempt{};
    Digest cohort{};
    Digest child_exit{};
    Digest driver_completion{};
    Digest selection_identity{};
    Digest proposal_identity{};
    Digest accepted_head{};
    Digest postlock_accepted_head{};
    Digest durable_lock{};
    Digest capture_source{};
    Digest capture_build{};
    Digest capture_runtime{};
    Digest capture_launcher{};
    Digest process_identity{};
    Digest egress{};
    Digest proof{};
    Digest projection{};
};

class PartyCompletionAuthority final {
    PublicPartyCompletion receipt_;
    std::atomic_bool live_{true};
    explicit PartyCompletionAuthority(PublicPartyCompletion);
    friend class TrialCaptureJoiner;
    friend class kpi::mpc::financial::registered_driver::
        RegisteredMeasurementCaptureBridge;
public:
    PartyCompletionAuthority(const PartyCompletionAuthority&) = delete;
    PartyCompletionAuthority& operator=(const PartyCompletionAuthority&) = delete;
    PartyCompletionAuthority(PartyCompletionAuthority&&) noexcept;
    PartyCompletionAuthority& operator=(PartyCompletionAuthority&&) = delete;
    const PublicPartyCompletion& public_receipt() const { return receipt_; }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static PartyCompletionAuthority test_only_mint(PublicPartyCompletion);
#endif
};

enum class CaptureKind : unsigned char {
    PublicProjection = 1,
    TerminalHistory = 2,
    Dispatcher = 3,
    CorruptServer = 4,
    ColluderWallet = 5,
};

enum class ConstructionPolicy : unsigned char {
    ExplicitOwnerPublicEffects = 1,
    SecretPermutationIndependent = 2,
};

struct PublicStreamClosure {
    unsigned round{};
    CaptureKind kind{};
    unsigned fixed_fd{};
    ManifestComponent manifest_component{};
    Digest source_identity{};
    Digest build_identity{};
    Digest runtime_identity{};
    Digest launcher_identity{};
    Digest process_identity{};
    Digest child_exit_identity{};
    bool root_closed{};
    bool end_observed{};
    bool eof_observed{};
    bool operator==(const PublicStreamClosure&) const = default;
};

struct PublicProducerClosure {
    RunBinding binding;
    Digest opaque_closure_authority_identity{};
    WorkerBinding producer_worker;
    Digest producer_process_identity{};
    Digest role_closure_identity{};
    Digest manifest_seal{};
    ConstructionPolicy construction_policy{};
    Digest construction_classification_receipt{};
    std::array<PublicStreamClosure, 10> streams{};
    unsigned stream_count{};
    unsigned closed_root_count{};
    unsigned unknown_record_count{};
    bool operator==(const PublicProducerClosure&) const = default;
};

struct ProducerStreamClosureEvidence {
    Digest record_root{};
    Digest end_frame_identity{};
    Digest eof_identity{};
    std::uint64_t record_count{};
    std::uint64_t payload_bytes{};
    std::uint64_t raw_wire_bytes{};
    bool operator==(const ProducerStreamClosureEvidence&) const = default;
};

// Join-only evidence. It is never returned by public_receipt() and is never
// copied into, or hashed by, the public trial-capture completion.
struct ProducerClosureEvidence {
    Digest opaque_closure_authority_identity{};
    Digest producer_child_exit{};
    Digest producer_receipt{};
    Digest producer_identity{};
    std::array<ProducerStreamClosureEvidence, 10> streams{};
    bool operator==(const ProducerClosureEvidence&) const = default;
};

class ProducerClosureAuthority final {
    PublicProducerClosure receipt_;
    ProducerClosureEvidence evidence_;
    std::atomic_bool live_{true};
    explicit ProducerClosureAuthority(
        PublicProducerClosure, ProducerClosureEvidence);
    void validate_for_native_terminal_join() const;
    friend class TrialCaptureJoiner;
    friend class producer_runtime::ParentOwnedCaptureProducer;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    ProducerClosureAuthority(const ProducerClosureAuthority&) = delete;
    ProducerClosureAuthority& operator=(const ProducerClosureAuthority&) = delete;
    ProducerClosureAuthority(ProducerClosureAuthority&&) noexcept;
    ProducerClosureAuthority& operator=(ProducerClosureAuthority&&) = delete;
    const PublicProducerClosure& public_receipt() const { return receipt_; }
    ProducerClosureAuthority transfer_for_native_terminal_join() &&;
    kpb::native_terminal::MatchedNativeTerminalProducerBundle
        match_native_terminal_streams(
            kpb::native_terminal::PaymentLifecycleCompletionAuthority&&
                round1,
            kpb::native_terminal::PaymentLifecycleCompletionAuthority&&
                round2) &&;
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static ProducerClosureAuthority test_only_mint(
        PublicProducerClosure, ProducerClosureEvidence);
#endif
};

struct PublicTrialCaptureCompletion {
    RunBinding binding;
    std::array<std::array<Digest, 3>, 2> party_completion{};
    std::array<std::array<Digest, 3>, 2> party_selection{};
    std::array<std::array<Digest, 3>, 2> party_proposal{};
    std::array<std::array<Digest, 3>, 2> party_process{};
    std::array<std::array<Digest, 3>, 2> party_child_exit{};
    std::array<std::array<Digest, 3>, 2> party_egress{};
    std::array<std::array<Digest, 3>, 2> party_proof{};
    std::array<Digest, 2> projections{};
    Digest opaque_closure_authority_identity{};
    WorkerBinding producer_worker;
    Digest producer_process_identity{};
    Digest role_closure_identity{};
    Digest manifest_seal{};
    ConstructionPolicy construction_policy{};
    Digest construction_classification_receipt{};
    Digest manifest_parent_process_identity{};
    Digest manifest_parent_executable_identity{};
    Digest manifest_recomputation_receipt{};
    std::array<PublicStreamClosure, 10> streams{};
    unsigned stream_count{};
    unsigned closed_root_count{};
    unsigned unknown_record_count{};
    Digest completion_identity{};
};

class TrialCaptureCompletionAuthority final {
    PublicTrialCaptureCompletion receipt_;
    std::optional<runtime_bridge::ObserverAdmissionAuthority> admission_;
    std::optional<kpi::mpc::financial::registered_driver::
        RegisteredMeasurementCaptureRetention> registered_trial_;
    std::atomic_bool live_{true};
    TrialCaptureCompletionAuthority(
        PublicTrialCaptureCompletion,
        runtime_bridge::ObserverAdmissionAuthority&&,
        std::optional<kpi::mpc::financial::registered_driver::
            RegisteredMeasurementCaptureRetention>&& = std::nullopt);
    friend class TrialCaptureJoiner;
    friend class RunMeasurement;
public:
    TrialCaptureCompletionAuthority(
        const TrialCaptureCompletionAuthority&) = delete;
    TrialCaptureCompletionAuthority& operator=(
        const TrialCaptureCompletionAuthority&) = delete;
    TrialCaptureCompletionAuthority(
        TrialCaptureCompletionAuthority&&) noexcept;
    TrialCaptureCompletionAuthority& operator=(
        TrialCaptureCompletionAuthority&&) = delete;
    const PublicTrialCaptureCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static TrialCaptureCompletionAuthority test_only_mint(
        PublicTrialCaptureCompletion);
#endif
};

class TrialCaptureJoiner final {
    RunBinding binding_;
    PublicParentManifestRecomputation manifest_recomputation_;
    std::array<std::array<std::optional<PublicPartyCompletion>, 3>, 2>
        parties_;
    std::optional<PublicProducerClosure> producer_;
    std::optional<ProducerClosureEvidence> producer_evidence_;
    std::optional<runtime_bridge::ObserverAdmissionAuthority>
        observer_admission_;
    std::optional<kpi::mpc::financial::registered_driver::
        RegisteredMeasurementCaptureRetention> registered_trial_;
    std::mutex mutex_;
    bool poisoned_{};
    bool finished_{};
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    bool allow_fixture_without_registered_trial_{true};
#endif
    void submit_terminal_authority(
        runtime_bridge::ObserverAdmissionAuthority&&,
        kpb::native_terminal::TerminalV2ModelAdmissionAuthority&);
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
    friend class kpi::mpc::financial::registered_driver::
        RegisteredMeasurementCaptureBridge;
public:
    TrialCaptureJoiner(RunBinding,
                       ParentManifestRecomputationAuthority&&);
    TrialCaptureJoiner(const TrialCaptureJoiner&) = delete;
    TrialCaptureJoiner& operator=(const TrialCaptureJoiner&) = delete;
    void submit(PartyCompletionAuthority&&);
    void submit(
        ProducerClosureAuthority&&,
        runtime_bridge::ObserverAdmissionAuthority&&);
    void submit(runtime_bridge::ObserverTerminalCaptureJoin&&);
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    // Existing authority controls deliberately bypass the producer supervisor,
    // but production has no receipt-only capture-completion route.
    void submit(ProducerClosureAuthority&&);
    // Lets registered-capture controls exercise the production retention
    // requirement while retaining the narrowly test-only producer mint.
    void test_only_require_registered_trial_for_finish() {
        allow_fixture_without_registered_trial_ = false;
    }
#endif
    TrialCaptureCompletionAuthority finish();
};

struct PublicObserverPermit {
    RunBinding binding;
    Digest trial_capture_identity{};
    Digest permit_identity{};
};

class ObserverPermitAuthority final {
    PublicObserverPermit receipt_;
    std::optional<runtime_bridge::ObserverAdmissionAuthority> admission_;
    std::atomic_bool live_{true};
    ObserverPermitAuthority(
        PublicObserverPermit,
        runtime_bridge::ObserverAdmissionAuthority&&);
    friend class RunMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    ObserverPermitAuthority(const ObserverPermitAuthority&) = delete;
    ObserverPermitAuthority& operator=(const ObserverPermitAuthority&) = delete;
    ObserverPermitAuthority(ObserverPermitAuthority&&) noexcept;
    ObserverPermitAuthority& operator=(ObserverPermitAuthority&&) = delete;
    const PublicObserverPermit& public_receipt() const { return receipt_; }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static ObserverPermitAuthority test_only_mint(PublicObserverPermit);
    ObserverExecutionPermitAuthority test_only_take_execution() &&;
#endif
};

// The residual returned only after ObserverCaptureCapsuleBridge has consumed
// the live private admission.  It cannot be split or used to create FD40.
class ObserverExecutionPermitAuthority final {
    PublicObserverPermit receipt_;
    std::atomic_bool live_{true};
    explicit ObserverExecutionPermitAuthority(PublicObserverPermit);
    friend class ObserverPermitAuthority;
    friend class RunMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    ObserverExecutionPermitAuthority(
        const ObserverExecutionPermitAuthority&) = delete;
    ObserverExecutionPermitAuthority& operator=(
        const ObserverExecutionPermitAuthority&) = delete;
    ObserverExecutionPermitAuthority(
        ObserverExecutionPermitAuthority&&) noexcept;
    ObserverExecutionPermitAuthority& operator=(
        ObserverExecutionPermitAuthority&&) = delete;
    const PublicObserverPermit& public_receipt() const { return receipt_; }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static ObserverExecutionPermitAuthority test_only_mint(
        PublicObserverPermit);
#endif
};

struct PublicObservationCompletion {
    RunBinding binding;
    Digest permit_identity{};
    Digest trial_capture_identity{};
    Digest child_exit{};
    Digest observation_receipt{};
    WorkerBinding worker;
    Digest process_identity{};
};

class ObservationCompletionAuthority final {
    PublicObservationCompletion receipt_;
    std::unique_ptr<phase_scope::ObservationOutputJoinAuthority>
        private_output_;
    std::atomic_bool live_{true};
    ObservationCompletionAuthority(
        PublicObservationCompletion,
        std::unique_ptr<phase_scope::ObservationOutputJoinAuthority>);
    friend class RunMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
public:
    ~ObservationCompletionAuthority();
    ObservationCompletionAuthority(
        const ObservationCompletionAuthority&) = delete;
    ObservationCompletionAuthority& operator=(
        const ObservationCompletionAuthority&) = delete;
    ObservationCompletionAuthority(
        ObservationCompletionAuthority&&) noexcept;
    ObservationCompletionAuthority& operator=(
        ObservationCompletionAuthority&&) = delete;
    const PublicObservationCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static ObservationCompletionAuthority test_only_mint(
        PublicObservationCompletion);
#endif
};

struct PublicBarrierFreeze {
    RunBinding binding;
    Digest trial_capture_identity{};
    Digest observation_receipt{};
    Digest barrier_receipt{};
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest manifest_recomputation_receipt{};
};

class BarrierFreezeAuthority final {
    PublicBarrierFreeze receipt_;
    std::atomic_bool live_{true};
    explicit BarrierFreezeAuthority(PublicBarrierFreeze);
    friend class RunMeasurement;
public:
    BarrierFreezeAuthority(const BarrierFreezeAuthority&) = delete;
    BarrierFreezeAuthority& operator=(const BarrierFreezeAuthority&) = delete;
    BarrierFreezeAuthority(BarrierFreezeAuthority&&) noexcept;
    BarrierFreezeAuthority& operator=(BarrierFreezeAuthority&&) = delete;
    const PublicBarrierFreeze& public_receipt() const { return receipt_; }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static BarrierFreezeAuthority test_only_mint(PublicBarrierFreeze);
#endif
};

struct PublicCandidateTruthBarrierRelease {
    RunBinding binding;
    Digest trial_capture_identity{};
    Digest observation_receipt{};
    Digest barrier{};
    Digest release_identity{};
};

Digest recompute_candidate_truth_barrier_release_identity(
    const PublicCandidateTruthBarrierRelease&);

class CandidateTruthBarrierReleaseAuthority final {
    PublicCandidateTruthBarrierRelease receipt_;
    std::atomic_bool live_{true};
    explicit CandidateTruthBarrierReleaseAuthority(
        PublicCandidateTruthBarrierRelease);
    friend class RunMeasurement;
    friend class ::kpi::mpc::financial::fresh_owner_issuance::
        CandidateOwnerTruthPostBarrierBridge;
public:
    CandidateTruthBarrierReleaseAuthority(
        const CandidateTruthBarrierReleaseAuthority&) = delete;
    CandidateTruthBarrierReleaseAuthority& operator=(
        const CandidateTruthBarrierReleaseAuthority&) = delete;
    CandidateTruthBarrierReleaseAuthority(
        CandidateTruthBarrierReleaseAuthority&&) noexcept;
    CandidateTruthBarrierReleaseAuthority& operator=(
        CandidateTruthBarrierReleaseAuthority&&) = delete;
    const PublicCandidateTruthBarrierRelease& public_receipt() const {
        return receipt_;
    }
};

struct PublicOwnerScorePermit {
    RunBinding binding;
    unsigned owner{};
    Digest trial_capture_identity{};
    Digest observation_receipt{};
    Digest barrier{};
    Digest permit_identity{};
};

class OwnerScorePermitSplit;
class OwnerScoreExecutionPermitAuthority;

class OwnerScorePermitAuthority final {
    PublicOwnerScorePermit receipt_;
    std::atomic_bool live_{true};
    explicit OwnerScorePermitAuthority(PublicOwnerScorePermit);
    friend class RunMeasurement;
public:
    OwnerScorePermitAuthority(const OwnerScorePermitAuthority&) = delete;
    OwnerScorePermitAuthority& operator=(const OwnerScorePermitAuthority&) = delete;
    OwnerScorePermitAuthority(OwnerScorePermitAuthority&&) noexcept;
    OwnerScorePermitAuthority& operator=(OwnerScorePermitAuthority&&) = delete;
    const PublicOwnerScorePermit& public_receipt() const { return receipt_; }
    OwnerScorePermitSplit split_for_truth_release() &&;
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static OwnerScorePermitAuthority test_only_mint(PublicOwnerScorePermit);
#endif
};

class OwnerScoreExecutionPermitAuthority final {
    PublicOwnerScorePermit receipt_;
    std::atomic_bool live_{true};
    explicit OwnerScoreExecutionPermitAuthority(PublicOwnerScorePermit);
    friend class OwnerScorePermitAuthority;
    friend class OwnerScorePermitSplit;
    friend class RunMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
    friend class score_output_split::OwnerScoreOutputSplitBridge;
public:
    OwnerScoreExecutionPermitAuthority(
        const OwnerScoreExecutionPermitAuthority&) = delete;
    OwnerScoreExecutionPermitAuthority& operator=(
        const OwnerScoreExecutionPermitAuthority&) = delete;
    OwnerScoreExecutionPermitAuthority(
        OwnerScoreExecutionPermitAuthority&&) noexcept;
    OwnerScoreExecutionPermitAuthority& operator=(
        OwnerScoreExecutionPermitAuthority&&) = delete;
    const PublicOwnerScorePermit& public_receipt() const { return receipt_; }
};

struct PublicOwnerTruthReleasePermit {
    RunBinding binding;
    unsigned owner{};
    Digest trial_capture_identity{};
    Digest observation_receipt{};
    Digest barrier{};
    Digest score_permit_identity{};
    Digest release_identity{};
};

class OwnerTruthReleasePermitAuthority final {
    PublicOwnerTruthReleasePermit receipt_;
    std::atomic_bool live_{true};
    explicit OwnerTruthReleasePermitAuthority(
        PublicOwnerTruthReleasePermit);
    friend class OwnerScorePermitAuthority;
    friend class ::kpi::mpc::financial::registered_driver::
        owner_truth_handoff::OwnerTruthScoreHandoffBridge;
public:
    OwnerTruthReleasePermitAuthority(
        const OwnerTruthReleasePermitAuthority&) = delete;
    OwnerTruthReleasePermitAuthority& operator=(
        const OwnerTruthReleasePermitAuthority&) = delete;
    OwnerTruthReleasePermitAuthority(
        OwnerTruthReleasePermitAuthority&&) noexcept;
    OwnerTruthReleasePermitAuthority& operator=(
        OwnerTruthReleasePermitAuthority&&) = delete;
    const PublicOwnerTruthReleasePermit& public_receipt() const {
        return receipt_;
    }
};

class OwnerScorePermitSplit final {
    std::optional<OwnerScoreExecutionPermitAuthority> execution_;
    std::optional<OwnerTruthReleasePermitAuthority> truth_release_;
    OwnerScorePermitSplit(OwnerScoreExecutionPermitAuthority&&,
                          OwnerTruthReleasePermitAuthority&&);
    friend class OwnerScorePermitAuthority;
public:
    OwnerScorePermitSplit(const OwnerScorePermitSplit&) = delete;
    OwnerScorePermitSplit& operator=(const OwnerScorePermitSplit&) = delete;
    OwnerScorePermitSplit(OwnerScorePermitSplit&&) noexcept;
    OwnerScorePermitSplit& operator=(OwnerScorePermitSplit&&) = delete;
    OwnerScoreExecutionPermitAuthority take_execution_permit();
    OwnerTruthReleasePermitAuthority take_truth_release_permit();
};

struct PublicOwnerScoreCompletion {
    RunBinding binding;
    unsigned owner{};
    Digest permit_identity{};
    Digest barrier{};
    Digest child_exit{};
    Digest score_receipt{};
    Digest capsule_seal{};
    WorkerBinding worker;
    Digest process_identity{};
};

class OwnerScoreCompletionAuthority final {
    PublicOwnerScoreCompletion receipt_;
    std::unique_ptr<runtime_bridge::SealedChildOutputAuthority>
        private_output_;
    std::atomic_bool live_{true};
    OwnerScoreCompletionAuthority(
        PublicOwnerScoreCompletion,
        std::unique_ptr<runtime_bridge::SealedChildOutputAuthority>);
    friend class RunMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
    friend class score_output_split::OwnerScoreOutputSplitBridge;
public:
    ~OwnerScoreCompletionAuthority();
    OwnerScoreCompletionAuthority(
        const OwnerScoreCompletionAuthority&) = delete;
    OwnerScoreCompletionAuthority& operator=(
        const OwnerScoreCompletionAuthority&) = delete;
    OwnerScoreCompletionAuthority(OwnerScoreCompletionAuthority&&) noexcept;
    OwnerScoreCompletionAuthority& operator=(
        OwnerScoreCompletionAuthority&&) = delete;
    const PublicOwnerScoreCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static OwnerScoreCompletionAuthority test_only_mint(
        PublicOwnerScoreCompletion);
#endif
};

struct PublicAggregatePermit {
    RunBinding binding;
    Digest trial_capture_identity{};
    Digest observation_receipt{};
    Digest barrier{};
    std::array<Digest, 3> score_receipts{};
    std::array<Digest, 3> capsule_seals{};
    Digest permit_identity{};
};

class AggregatePermitAuthority final {
    PublicAggregatePermit receipt_;
    std::atomic_bool live_{true};
    explicit AggregatePermitAuthority(PublicAggregatePermit);
    friend class RunMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
public:
    AggregatePermitAuthority(const AggregatePermitAuthority&) = delete;
    AggregatePermitAuthority& operator=(const AggregatePermitAuthority&) = delete;
    AggregatePermitAuthority(AggregatePermitAuthority&&) noexcept;
    AggregatePermitAuthority& operator=(AggregatePermitAuthority&&) = delete;
    const PublicAggregatePermit& public_receipt() const { return receipt_; }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static AggregatePermitAuthority test_only_mint(PublicAggregatePermit);
#endif
};

enum class AggregateOutcome : unsigned char {
    BaselineControlDetected = 1,
    CandidatePass = 2,
    Fail = 3,
    Unqualified = 4,
};

struct PublicAggregateCompletion {
    RunBinding binding;
    Digest permit_identity{};
    Digest barrier{};
    Digest child_exit{};
    Digest aggregate_receipt{};
    AggregateOutcome outcome{};
    WorkerBinding worker;
    Digest process_identity{};
};

class AggregateCompletionAuthority final {
    PublicAggregateCompletion receipt_;
    std::atomic_bool live_{true};
    explicit AggregateCompletionAuthority(PublicAggregateCompletion);
    friend class RunMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
public:
    AggregateCompletionAuthority(const AggregateCompletionAuthority&) = delete;
    AggregateCompletionAuthority& operator=(
        const AggregateCompletionAuthority&) = delete;
    AggregateCompletionAuthority(AggregateCompletionAuthority&&) noexcept;
    AggregateCompletionAuthority& operator=(
        AggregateCompletionAuthority&&) = delete;
    const PublicAggregateCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static AggregateCompletionAuthority test_only_mint(
        PublicAggregateCompletion);
#endif
};

struct PublicRunAggregateCompletion {
    RunBinding binding;
    Digest trial_capture_identity{};
    Digest observation_receipt{};
    Digest observation_process{};
    Digest barrier{};
    std::array<Digest, 3> score_receipts{};
    std::array<Digest, 3> capsule_seals{};
    std::array<Digest, 3> score_processes{};
    Digest aggregate_child_exit{};
    Digest aggregate_process{};
    Digest aggregate_receipt{};
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest manifest_recomputation_receipt{};
    AggregateOutcome outcome{};
    Digest completion_identity{};
};

class RunAggregateCompletionAuthority final {
    PublicRunAggregateCompletion receipt_;
    std::atomic_bool live_{true};
    explicit RunAggregateCompletionAuthority(PublicRunAggregateCompletion);
    friend class RunMeasurement;
    friend class ComparisonMeasurement;
public:
    RunAggregateCompletionAuthority(
        const RunAggregateCompletionAuthority&) = delete;
    RunAggregateCompletionAuthority& operator=(
        const RunAggregateCompletionAuthority&) = delete;
    RunAggregateCompletionAuthority(
        RunAggregateCompletionAuthority&&) noexcept;
    RunAggregateCompletionAuthority& operator=(
        RunAggregateCompletionAuthority&&) = delete;
    const PublicRunAggregateCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static RunAggregateCompletionAuthority test_only_mint(
        PublicRunAggregateCompletion);
#endif
};

class RunMeasurement final {
    enum class State {
        CaptureReady,
        ObserverIssued,
        ObserverComplete,
        BarrierFrozen,
        OwnerScoreOutcomeRetained,
        AggregateIssued,
        Completed,
        Poisoned,
    };
    PublicTrialCaptureCompletion capture_;
    std::optional<kpi::mpc::financial::registered_driver::
        RegisteredMeasurementCaptureRetention> registered_trial_;
    std::optional<runtime_bridge::ObserverAdmissionAuthority>
        observer_admission_;
    std::optional<PublicObserverPermit> observer_permit_;
    std::optional<PublicObservationCompletion> observation_;
    std::unique_ptr<phase_scope::ObservationOutputJoinAuthority>
        observation_output_;
    Digest barrier_{};
    bool candidate_truth_barrier_release_issued_{};
    std::array<bool, 3> score_issued_{};
    std::array<std::optional<PublicOwnerScorePermit>, 3> score_permits_;
    std::array<std::optional<PublicOwnerScoreCompletion>, 3> scores_;
    std::array<std::unique_ptr<runtime_bridge::SealedChildOutputAuthority>, 3>
        score_outputs_;
    // Retains success and STOP identically. This is not a terminal STOP sink:
    // destruction releases process-local capabilities, so selected/configured
    // status remains false until a mandatory residual consumer exists.
    void* owner_score_outcome_storage_{};
    void (*destroy_owner_score_outcome_storage_)(void*) noexcept{};
    std::optional<PublicAggregatePermit> aggregate_permit_;
    std::mutex mutex_;
    State state_{State::CaptureReady};
    void accept_owner_score_split_impl(
        score_output_split::OwnerScoreOutputSplitOutcomeAuthority&&,
        unsigned char fault);
public:
    explicit RunMeasurement(TrialCaptureCompletionAuthority&&);
    ~RunMeasurement();
    RunMeasurement(const RunMeasurement&) = delete;
    RunMeasurement& operator=(const RunMeasurement&) = delete;
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    bool test_only_has_registered_trial_retention() const {
        return registered_trial_.has_value();
    }
#endif
    ObserverPermitAuthority issue_observer();
    void accept_observer(ObserverExecutionPermitAuthority&&,
                         ObservationCompletionAuthority&&);
    void freeze_barrier(BarrierFreezeAuthority&&);
    CandidateTruthBarrierReleaseAuthority
        issue_candidate_truth_barrier_release();
    OwnerScorePermitAuthority issue_score(unsigned owner);
    void accept_owner_score_split(
        score_output_split::OwnerScoreOutputSplitOutcomeAuthority&&);
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    enum class TestOnlyOwnerScoreRetentionFault : unsigned char {
        None,
        BeforeClaimAllocation,
        AfterClaim,
    };
    void test_only_accept_owner_score_split(
        score_output_split::OwnerScoreOutputSplitOutcomeAuthority&&,
        TestOnlyOwnerScoreRetentionFault);
    bool test_only_has_owner_score_split() const {
        return owner_score_outcome_storage_ != nullptr;
    }
    // Legacy state-machine controls only. Production must consume the opaque
    // all-three OwnerScoreOutputSplitOutcomeAuthority; that final consumer is
    // deliberately absent while compact-lineage minting and the STOP sink are
    // unselected.
    void accept_score(OwnerScoreExecutionPermitAuthority&&,
                      OwnerScoreCompletionAuthority&&);
    AggregatePermitAuthority issue_aggregate();
#endif
    RunAggregateCompletionAuthority accept_aggregate(
        AggregatePermitAuthority&&, AggregateCompletionAuthority&&);
};

struct PublicComparisonSelection {
    Digest comparison_selection{};
    Digest selection_identity{};
    Digest method{};
    Digest workload{};
    Digest source_closure{};
    Digest runtime{};
    FiniteManifestBinding finite_manifest;
    WorkerBinding comparison_worker;
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest manifest_recomputation_receipt{};
    Digest baseline_run{};
    Digest candidate_run{};
};

class ComparisonSelectionAuthority final {
    PublicComparisonSelection receipt_;
    std::atomic_bool live_{true};
    explicit ComparisonSelectionAuthority(PublicComparisonSelection);
    friend class ComparisonMeasurement;
public:
    ComparisonSelectionAuthority(const ComparisonSelectionAuthority&) = delete;
    ComparisonSelectionAuthority& operator=(
        const ComparisonSelectionAuthority&) = delete;
    ComparisonSelectionAuthority(ComparisonSelectionAuthority&&) noexcept;
    ComparisonSelectionAuthority& operator=(
        ComparisonSelectionAuthority&&) = delete;
    const PublicComparisonSelection& public_receipt() const { return receipt_; }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static ComparisonSelectionAuthority test_only_mint(
        PublicComparisonSelection);
#endif
};

struct PublicOwnerComparisonPermit {
    PublicComparisonSelection selection;
    Digest baseline_aggregate{};
    Digest candidate_aggregate{};
    Digest permit_identity{};
};

class OwnerComparisonPermitAuthority final {
    PublicOwnerComparisonPermit receipt_;
    std::atomic_bool live_{true};
    explicit OwnerComparisonPermitAuthority(PublicOwnerComparisonPermit);
    friend class ComparisonMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
public:
    OwnerComparisonPermitAuthority(
        const OwnerComparisonPermitAuthority&) = delete;
    OwnerComparisonPermitAuthority& operator=(
        const OwnerComparisonPermitAuthority&) = delete;
    OwnerComparisonPermitAuthority(OwnerComparisonPermitAuthority&&) noexcept;
    OwnerComparisonPermitAuthority& operator=(
        OwnerComparisonPermitAuthority&&) = delete;
    const PublicOwnerComparisonPermit& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static OwnerComparisonPermitAuthority test_only_mint(
        PublicOwnerComparisonPermit);
#endif
};

enum class OwnerComparisonOutcome : unsigned char {
    NonRegressionPass = 1,
    Fail = 2,
    Unqualified = 3,
};

struct PublicOwnerComparisonCompletion {
    Digest comparison_selection{};
    Digest permit_identity{};
    Digest baseline_aggregate{};
    Digest candidate_aggregate{};
    Digest child_exit{};
    Digest comparison_receipt{};
    OwnerComparisonOutcome outcome{};
    WorkerBinding worker;
    Digest process_identity{};
};

class OwnerComparisonCompletionAuthority final {
    PublicOwnerComparisonCompletion receipt_;
    std::atomic_bool live_{true};
    explicit OwnerComparisonCompletionAuthority(
        PublicOwnerComparisonCompletion);
    friend class ComparisonMeasurement;
    friend class runtime_bridge::RuntimeCompletionBridge;
public:
    OwnerComparisonCompletionAuthority(
        const OwnerComparisonCompletionAuthority&) = delete;
    OwnerComparisonCompletionAuthority& operator=(
        const OwnerComparisonCompletionAuthority&) = delete;
    OwnerComparisonCompletionAuthority(
        OwnerComparisonCompletionAuthority&&) noexcept;
    OwnerComparisonCompletionAuthority& operator=(
        OwnerComparisonCompletionAuthority&&) = delete;
    const PublicOwnerComparisonCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    static OwnerComparisonCompletionAuthority test_only_mint(
        PublicOwnerComparisonCompletion);
#endif
};

enum class PrivacyScope : unsigned char {
    BatchPaymentPreNetworkOnly = 1,
};

struct PublicBatchPrivacyPass {
    PrivacyScope scope{};
    PublicComparisonSelection selection;
    Digest comparison_selection{};
    Digest baseline_aggregate{};
    Digest candidate_aggregate{};
    Digest candidate_trial{};
    std::array<Digest, 2> candidate_projections{};
    Digest owner_comparison_child_exit{};
    Digest owner_comparison_process{};
    Digest owner_comparison_receipt{};
    Digest finite_manifest_identity{};
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest manifest_recomputation_receipt{};
    Digest pass_identity{};
};

class BatchPrivacyPassAuthority final {
    PublicBatchPrivacyPass receipt_;
    std::atomic_bool live_{true};
    explicit BatchPrivacyPassAuthority(PublicBatchPrivacyPass);
    friend class ComparisonMeasurement;
public:
    BatchPrivacyPassAuthority(const BatchPrivacyPassAuthority&) = delete;
    BatchPrivacyPassAuthority& operator=(
        const BatchPrivacyPassAuthority&) = delete;
    BatchPrivacyPassAuthority(BatchPrivacyPassAuthority&&) noexcept;
    BatchPrivacyPassAuthority& operator=(BatchPrivacyPassAuthority&&) = delete;
    const PublicBatchPrivacyPass& public_receipt() const { return receipt_; }
    BatchPrivacyPassAuthority transfer_for_pre_network_safety() &&;
    PublicBatchPrivacyPass consume_for_testnet_activation();
};

class ComparisonMeasurement final {
    enum class State {
        Ready,
        OwnerComparisonIssued,
        Completed,
        Poisoned,
    };
    PublicComparisonSelection selection_;
    PublicRunAggregateCompletion baseline_;
    PublicRunAggregateCompletion candidate_;
    std::optional<PublicOwnerComparisonPermit> permit_;
    std::mutex mutex_;
    State state_{State::Ready};
public:
    ComparisonMeasurement(ComparisonSelectionAuthority&&,
                          RunAggregateCompletionAuthority&& baseline,
                          RunAggregateCompletionAuthority&& candidate);
    ComparisonMeasurement(const ComparisonMeasurement&) = delete;
    ComparisonMeasurement& operator=(const ComparisonMeasurement&) = delete;
    OwnerComparisonPermitAuthority issue_owner_comparison();
    BatchPrivacyPassAuthority accept_owner_comparison(
        OwnerComparisonPermitAuthority&&,
        OwnerComparisonCompletionAuthority&&);
};

// Source architecture only. No producer/adapter/launcher currently exists.
// These flags must remain false until the corresponding parent-owned closure
// is implemented and reviewed; public receipts cannot change them.
struct SourceStatus {
    bool finite_manifest_parent_tooling{};
    bool party_completion_adapter{};
    bool producer_closure_adapter{};
    bool registered_capture_supervisor{};
    bool observation_child_adapter{};
    bool barrier_freeze_adapter{};
    bool owner_score_child_adapter{};
    bool aggregate_child_adapter{};
    bool owner_comparison_child_adapter{};
    bool run_measurement_supervisor{};
    bool comparison_supervisor{};
    bool pre_network_safety_authority{};
    bool accepted_payment_terminal_authority{};
    bool terminal_exit_privacy_authority{};
    bool activation_supervisor{};
    bool configured{};
    bool launch_enabled{};
    bool actual_privacy_pass{};
};

inline constexpr SourceStatus kSourceStatus{};

} // namespace kpb::measurement
