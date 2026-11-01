#pragma once

// Exact-three long-lived owner-process topology for fresh two-round issuance.
// The selected parent transfers three O_DIRECTORY capabilities into fixed
// child-only descriptors, authenticates every fixed packet with SCM_CREDENTIALS
// and retains no root descriptor, path, private body or body digest.

#include "fresh_owner_trial_issuance.hpp"
#include "fresh_owner_candidate_truth_schema.hpp"
#include "candidate_owner_truth_post_barrier_bridge.hpp"
#include "owner_truth_score_handoff.hpp"
#include "fresh_owner_v3_lifecycle_contract.hpp"
#include "../../private_batch_trial/privacy_fresh_owner_round1_outcome_consumer_contract.hpp"
#include "../../private_batch_trial/privacy_fresh_owner_round2_outcome_consumer_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace kpb::testnet_history {
class AcceptedRound1InputChainAuthority;
class AcceptedRound1SuccessorChainAuthority;
struct PublicAcceptedHistoryStage;
}

namespace kpi::mpc::financial::fresh_owner_issuance {

class FreshOwnerRound1AttemptOutcomeAuthority;

inline constexpr int FRESH_OWNER_FIXED_CONTROL_FD = 39;
inline constexpr int FRESH_OWNER_FIXED_ROOT_FD = 40;
inline constexpr int FRESH_OWNER_FIXED_TRUTH_FD = 42;

struct PrivateOwnerCandidateRoundTruth {
    Digest actual_public_nullifier{};
    std::array<Digest, 2> created_row_sha256s{};
    std::array<Digest, 2> created_commitments{};
    bool operator==(const PrivateOwnerCandidateRoundTruth&) const = default;
};

struct PublicOwnerPrivateRoot {
    unsigned owner_component{};
    Digest root_identity{};
    Digest owner_root_metadata_identity{};
};

class OwnerPrivateRootAuthority final {
    PublicOwnerPrivateRoot receipt_;
    std::uint64_t device_{};
    std::uint64_t inode_{};
    int fd_{-1};
    std::atomic_bool live_{true};
    OwnerPrivateRootAuthority(PublicOwnerPrivateRoot, int owned_fd);
    friend class FreshOwnerProcessSupervisor;
public:
    OwnerPrivateRootAuthority(const OwnerPrivateRootAuthority&) = delete;
    OwnerPrivateRootAuthority& operator=(
        const OwnerPrivateRootAuthority&) = delete;
    OwnerPrivateRootAuthority(OwnerPrivateRootAuthority&&) noexcept;
    OwnerPrivateRootAuthority& operator=(OwnerPrivateRootAuthority&&) = delete;
    ~OwnerPrivateRootAuthority();
    const PublicOwnerPrivateRoot& public_receipt() const { return receipt_; }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static OwnerPrivateRootAuthority test_only_mint(
        PublicOwnerPrivateRoot, int owned_fd);
#endif
};

struct PrivateOwnerChildRoundResult {
    Digest file_identity{};
    Digest file_metadata_identity{};
    Digest input_lineage_identity{};
    LogicalOwnerIdentity logical_owner_identity{};
    Digest binding_nonce{};
    std::array<unsigned char, 64> verifier_record{};
    // Retained only inside the owner child. The control packet deliberately
    // omits this value; it can leave only through the post-barrier FD42 feed.
    PrivateOwnerCandidateRoundTruth candidate_truth{};
};

struct PrivateOwnerChildIdentity {
    LogicalOwnerIdentity logical_owner_identity{};
    Digest binding_nonce{};
    // Owner-local opaque nonces. They are created before any body generation,
    // are never body/path hashes, and cannot be supplied by the parent plan.
    std::array<Digest, 2> file_identities{};
    std::array<Digest, 2> file_metadata_identities{};
    // Private per-round lineage. R1 and R2 must differ; only a future
    // same-round retry authority may preserve one of these values.
    std::array<Digest, 2> input_lineage_identities{};
    std::array<unsigned char, 64> verifier_record{};
};

// A production implementation will be the exact admitted private_lifecycle
// owner executable adapter.  The process topology is executable now, but no
// selected production implementation or authority minter exists.
class PrivateLifecycleOwnerChildProgram {
public:
    virtual ~PrivateLifecycleOwnerChildProgram() = default;
    virtual PrivateOwnerChildRoundResult issue_round(
        unsigned owner, unsigned round, int fixed_root_fd,
        const PublicOwnerRoundIssuance& selected) = 0;
    virtual PrivateOwnerChildIdentity owner_identity(unsigned owner) const = 0;
    virtual std::shared_ptr<const LongLivedOwnerProofVerifier>
    admit_parent_verifier(
        unsigned owner,
        const std::array<unsigned char, 64>& private_record) const = 0;
    virtual int exit_code_after_round2(unsigned) const { return 0; }
};

struct PublicOwnerProcessSelection {
    unsigned owner_component{};
    std::array<PublicOwnerRoundIssuance, 2> rounds{};
};

struct PublicFreshOwnerProcessPlan {
    registered_driver::CaptureClassification classification{};
    Digest process_authority_identity{};
    Digest registration_identity{};
    Digest service_identity{};
    Digest controller_source_identity{};
    Digest controller_build_identity{};
    Digest owner_issuer_source_identity{};
    Digest owner_issuer_build_identity{};
    Digest owner_runtime_identity{};
    // Exact SHA-256 of the canonical measurement::RunBinding for the hidden
    // candidate. Baseline keeps this zero. The field is source data only;
    // it cannot mint a lifecycle controller without the one-shot accepted-
    // history residual emitted after both issuance gates validate.
    Digest measurement_run_binding_identity{};
    Digest run{};
    Digest trial{};
    Digest root_identity{};
    Digest baseline_policy_identity{};
    Digest roster_authority_identity{};
    // Hidden scorer lineage is selected by the admitted compiled plan before
    // any post-barrier release exists. Baseline plans keep all four zero.
    std::array<Digest, 2> candidate_truth_financial_runs{};
    std::array<Digest, 2> candidate_truth_capture_plan_identities{};
    std::array<Digest, 2> candidate_truth_projection_identities{};
    std::array<Digest, 2> candidate_truth_context_identities{};
    std::array<PublicOwnerProcessSelection, 3> owners{};
};

class CompiledPrivateLifecycleOwnerProgramAuthority final {
    PublicFreshOwnerProcessPlan plan_;
    std::shared_ptr<PrivateLifecycleOwnerChildProgram> program_;
    std::atomic_bool live_{true};
    CompiledPrivateLifecycleOwnerProgramAuthority(
        PublicFreshOwnerProcessPlan,
        std::shared_ptr<PrivateLifecycleOwnerChildProgram>);
    friend class FreshOwnerProcessSupervisor;
public:
    CompiledPrivateLifecycleOwnerProgramAuthority(
        const CompiledPrivateLifecycleOwnerProgramAuthority&) = delete;
    CompiledPrivateLifecycleOwnerProgramAuthority& operator=(
        const CompiledPrivateLifecycleOwnerProgramAuthority&) = delete;
    CompiledPrivateLifecycleOwnerProgramAuthority(
        CompiledPrivateLifecycleOwnerProgramAuthority&&) noexcept;
    CompiledPrivateLifecycleOwnerProgramAuthority& operator=(
        CompiledPrivateLifecycleOwnerProgramAuthority&&) = delete;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static CompiledPrivateLifecycleOwnerProgramAuthority test_only_mint(
        PublicFreshOwnerProcessPlan,
        std::shared_ptr<PrivateLifecycleOwnerChildProgram>);
#endif
};

struct PublicAcceptedRound1SuccessorHistory {
    Digest authority_identity{};
    Digest run{};
    Digest trial{};
    Digest round1_attempt{};
    Digest round1_cohort{};
    Digest accepted_successor_head_identity{};
    Digest history_gate_identity{};
};

struct PublicAcceptedRound1InputHistory {
    Digest authority_identity{};
    Digest run{};
    Digest trial{};
    Digest round1_attempt{};
    Digest round1_cohort{};
    Digest accepted_input_head_identity{};
    Digest history_gate_identity{};
};

class AcceptedRound1InputHistoryAuthority final {
    PublicAcceptedRound1InputHistory receipt_;
    std::array<Digest, 3> input_lineages_{};
    std::atomic_bool live_{true};
    explicit AcceptedRound1InputHistoryAuthority(
        PublicAcceptedRound1InputHistory, std::array<Digest, 3>);
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRoundBootstrapBridge;
    friend class FreshOwnerRound1AttemptOutcomeAuthority;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound1AttemptOutcomeTestBridge;
#endif
public:
    AcceptedRound1InputHistoryAuthority(
        const AcceptedRound1InputHistoryAuthority&) = delete;
    AcceptedRound1InputHistoryAuthority& operator=(
        const AcceptedRound1InputHistoryAuthority&) = delete;
    AcceptedRound1InputHistoryAuthority(
        AcceptedRound1InputHistoryAuthority&&) noexcept;
    AcceptedRound1InputHistoryAuthority& operator=(
        AcceptedRound1InputHistoryAuthority&&) = delete;
    const PublicAcceptedRound1InputHistory& public_receipt() const {
        return receipt_;
    }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static AcceptedRound1InputHistoryAuthority test_only_mint(
        PublicAcceptedRound1InputHistory, std::array<Digest, 3>);
#endif
};

class AcceptedRound1InputHistoryBootstrapAuthority final {
    PublicAcceptedRound1InputHistory receipt_;
    std::atomic_bool live_{true};
    explicit AcceptedRound1InputHistoryBootstrapAuthority(
        PublicAcceptedRound1InputHistory) noexcept;
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRoundBootstrapBridge;
public:
    AcceptedRound1InputHistoryBootstrapAuthority(
        const AcceptedRound1InputHistoryBootstrapAuthority&) = delete;
    AcceptedRound1InputHistoryBootstrapAuthority& operator=(
        const AcceptedRound1InputHistoryBootstrapAuthority&) = delete;
    AcceptedRound1InputHistoryBootstrapAuthority(
        AcceptedRound1InputHistoryBootstrapAuthority&&) noexcept;
    AcceptedRound1InputHistoryBootstrapAuthority& operator=(
        AcceptedRound1InputHistoryBootstrapAuthority&&) = delete;
};

class AcceptedRound1SuccessorHistoryAuthority final {
    PublicAcceptedRound1SuccessorHistory receipt_;
    std::array<Digest, 3> successor_input_lineages_{};
    std::atomic_bool live_{true};
    explicit AcceptedRound1SuccessorHistoryAuthority(
        PublicAcceptedRound1SuccessorHistory, std::array<Digest, 3>);
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRoundBootstrapBridge;
public:
    AcceptedRound1SuccessorHistoryAuthority(
        const AcceptedRound1SuccessorHistoryAuthority&) = delete;
    AcceptedRound1SuccessorHistoryAuthority& operator=(
        const AcceptedRound1SuccessorHistoryAuthority&) = delete;
    AcceptedRound1SuccessorHistoryAuthority(
        AcceptedRound1SuccessorHistoryAuthority&&) noexcept;
    AcceptedRound1SuccessorHistoryAuthority& operator=(
        AcceptedRound1SuccessorHistoryAuthority&&) = delete;
    const PublicAcceptedRound1SuccessorHistory& public_receipt() const {
        return receipt_;
    }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static AcceptedRound1SuccessorHistoryAuthority test_only_mint(
        PublicAcceptedRound1SuccessorHistory, std::array<Digest, 3>);
#endif
};

// Opaque one-shot conjunction emitted only after issue_round1 and
// issue_round2 have consumed and validated both accepted-history authorities,
// all six private owner lineages, and the hidden plan's exact measurement
// binding. It has no public receipt/body/hash accessor.
class V3AcceptedRound1HistoryResidualAuthority final {
    PublicAcceptedRound1InputHistory input_;
    PublicAcceptedRound1SuccessorHistory successor_;
    std::array<Digest, 3> input_lineages_{};
    std::array<Digest, 3> successor_lineages_{};
    Digest measurement_run_binding_identity_{};
    std::array<Digest, 2> financial_runs_{};
    std::array<Digest, 2> capture_plans_{};
    std::array<Digest, 2> projections_{};
    std::array<Digest, 2> contexts_{};
    Digest supervisor_session_identity_{};
    Digest continuation_identity_{};
    Digest residual_identity_{};
    std::atomic_bool live_{true};
    static Digest recompute_identity(
        const PublicAcceptedRound1InputHistory&,
        const PublicAcceptedRound1SuccessorHistory&,
        const std::array<Digest, 3>&, const std::array<Digest, 3>&,
        const Digest&, const std::array<Digest, 2>&,
        const std::array<Digest, 2>&, const std::array<Digest, 2>&,
        const std::array<Digest, 2>&, const Digest&, const Digest&);
    V3AcceptedRound1HistoryResidualAuthority(
        PublicAcceptedRound1InputHistory,
        PublicAcceptedRound1SuccessorHistory,
        std::array<Digest, 3>, std::array<Digest, 3>, Digest,
        std::array<Digest, 2>, std::array<Digest, 2>,
        std::array<Digest, 2>, std::array<Digest, 2>, Digest, Digest);
    friend class FreshOwnerProcessSupervisor;
    friend class kpb::future_recipient::v3_native::
        V3LifecycleControllerMinter;
public:
    V3AcceptedRound1HistoryResidualAuthority(
        const V3AcceptedRound1HistoryResidualAuthority&) = delete;
    V3AcceptedRound1HistoryResidualAuthority& operator=(
        const V3AcceptedRound1HistoryResidualAuthority&) = delete;
    V3AcceptedRound1HistoryResidualAuthority(
        V3AcceptedRound1HistoryResidualAuthority&&) noexcept;
    V3AcceptedRound1HistoryResidualAuthority& operator=(
        V3AcceptedRound1HistoryResidualAuthority&&) = delete;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static V3AcceptedRound1HistoryResidualAuthority
    test_only_corrupt_successor_head(
        V3AcceptedRound1HistoryResidualAuthority&&);
#endif
};

class AcceptedRound1SuccessorHistoryBootstrapAuthority final {
    PublicAcceptedRound1SuccessorHistory receipt_;
    std::atomic_bool live_{true};
    explicit AcceptedRound1SuccessorHistoryBootstrapAuthority(
        PublicAcceptedRound1SuccessorHistory);
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRoundBootstrapBridge;
public:
    AcceptedRound1SuccessorHistoryBootstrapAuthority(
        const AcceptedRound1SuccessorHistoryBootstrapAuthority&) = delete;
    AcceptedRound1SuccessorHistoryBootstrapAuthority& operator=(
        const AcceptedRound1SuccessorHistoryBootstrapAuthority&) = delete;
    AcceptedRound1SuccessorHistoryBootstrapAuthority(
        AcceptedRound1SuccessorHistoryBootstrapAuthority&&) noexcept;
    AcceptedRound1SuccessorHistoryBootstrapAuthority& operator=(
        AcceptedRound1SuccessorHistoryBootstrapAuthority&&) = delete;
};

struct PublicOwnerProcessChild {
    unsigned owner_component{};
    std::int64_t child_pid{};
    Digest child_session_identity{};
    Digest owner_process_identity{};
    Digest root_metadata_identity{};
};

struct PublicFreshOwnerProcessLaunch {
    std::int64_t parent_pid{};
    Digest process_authority_identity{};
    Digest supervisor_session_identity{};
    Digest run{};
    Digest trial{};
    Digest root_identity{};
    std::array<PublicOwnerProcessChild, 3> children{};
};

struct PublicFreshOwnerProcessCompletion {
    Digest supervisor_session_identity{};
    std::array<PublicOwnerProcessChild, 3> children{};
    bool all_children_exited_zero{};
};

// Macro-gated fixture only. Six-element arrays are ordered
// [round-1 owners 0..2, round-2 owners 0..2].
#ifdef KPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP
struct PrivateArmIsolationTestEvidence {
    registered_driver::CaptureClassification classification{};
    Digest process_authority_identity{};
    Digest supervisor_session_identity{};
    std::array<std::int64_t, 3> child_pids{};
    std::array<Digest, 3> child_sessions{};
    std::array<std::array<std::uint64_t, 2>, 3> root_slots{};
    std::array<LogicalOwnerIdentity, 3> logical_owner_ids{};
    std::array<Digest, 6> contract_ids{};
    std::array<Digest, 6> owner_tls_cert_ids{};
    std::array<Digest, 6> owner_tls_spki_ids{};
    std::array<std::array<Digest, 3>, 6> server_tls_cert_ids{};
    std::array<std::array<Digest, 3>, 6> server_tls_spki_ids{};
};
#endif

class FreshOwnerPrivateArmLaunchAuthority;
class FreshOwnerArmIsolationAuthority;

// Complete, narrow bridge declaration: its separately implemented isolated
// join is the only production consumer of the raw private evidence.
class FreshOwnerArmIsolationBridge final {
public:
    static FreshOwnerArmIsolationAuthority join(
        FreshOwnerPrivateArmLaunchAuthority&& baseline,
        FreshOwnerPrivateArmLaunchAuthority&& hidden_candidate);
};

class FreshOwnerPrivateArmLaunchAuthority final {
    struct Evidence {
        registered_driver::CaptureClassification classification{};
        Digest process_authority_identity{};
        Digest supervisor_session_identity{};
        std::array<std::int64_t, 3> child_pids{};
        std::array<Digest, 3> child_sessions{};
        std::array<std::array<std::uint64_t, 2>, 3> root_slots{};
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids{};
        std::array<Digest, 6> contract_ids{};
        std::array<Digest, 6> owner_tls_cert_ids{};
        std::array<Digest, 6> owner_tls_spki_ids{};
        std::array<std::array<Digest, 3>, 6> server_tls_cert_ids{};
        std::array<std::array<Digest, 3>, 6> server_tls_spki_ids{};
    };
    Evidence evidence_{};
    std::atomic_bool live_{true};
    explicit FreshOwnerPrivateArmLaunchAuthority(Evidence);
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerArmIsolationBridge;
public:
    FreshOwnerPrivateArmLaunchAuthority(
        const FreshOwnerPrivateArmLaunchAuthority&) = delete;
    FreshOwnerPrivateArmLaunchAuthority& operator=(
        const FreshOwnerPrivateArmLaunchAuthority&) = delete;
    FreshOwnerPrivateArmLaunchAuthority(
        FreshOwnerPrivateArmLaunchAuthority&&) noexcept;
    FreshOwnerPrivateArmLaunchAuthority& operator=(
        FreshOwnerPrivateArmLaunchAuthority&&) = delete;
    ~FreshOwnerPrivateArmLaunchAuthority();
#ifdef KPI_FRESH_OWNER_ARM_ISOLATION_TEST_SETUP
    static FreshOwnerPrivateArmLaunchAuthority test_only_mint(
        PrivateArmIsolationTestEvidence);
#endif
};

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
struct PrivateArmIsolationResidualTestEvidence {
    registered_driver::CaptureClassification classification{};
    Digest isolation_authority_identity{};
    Digest process_authority_identity{};
    Digest supervisor_session_identity{};
};
#endif

// One of exactly two opaque residuals minted by the successful two-arm join.
// It is required and burned before either arm can generate its R1 file.
class FreshOwnerArmIsolationResidualAuthority final {
    registered_driver::CaptureClassification classification_{};
    Digest isolation_authority_identity_{};
    Digest process_authority_identity_{};
    Digest supervisor_session_identity_{};
    std::atomic_bool live_{true};
    FreshOwnerArmIsolationResidualAuthority(
        registered_driver::CaptureClassification,
        Digest isolation_authority_identity,
        Digest process_authority_identity,
        Digest supervisor_session_identity);
    friend class FreshOwnerArmIsolationBridge;
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRound1AttemptOutcomeAuthority;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound1AttemptOutcomeTestBridge;
#endif
public:
    FreshOwnerArmIsolationResidualAuthority(
        const FreshOwnerArmIsolationResidualAuthority&) = delete;
    FreshOwnerArmIsolationResidualAuthority& operator=(
        const FreshOwnerArmIsolationResidualAuthority&) = delete;
    FreshOwnerArmIsolationResidualAuthority(
        FreshOwnerArmIsolationResidualAuthority&&) noexcept;
    FreshOwnerArmIsolationResidualAuthority& operator=(
        FreshOwnerArmIsolationResidualAuthority&&) = delete;
    ~FreshOwnerArmIsolationResidualAuthority();
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static FreshOwnerArmIsolationResidualAuthority test_only_mint(
        PrivateArmIsolationResidualTestEvidence);
#endif
};

class AuthenticatedOwnerProcessBundle final {
    PublicOwnerIssuanceReceipt receipt_;
    std::shared_ptr<const LongLivedOwnerProofVerifier> verifier_;
    LogicalOwnerIdentity logical_owner_identity_{};
    Digest binding_nonce_{};
    std::atomic_bool live_{true};
    AuthenticatedOwnerProcessBundle(
        PublicOwnerIssuanceReceipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier>,
        LogicalOwnerIdentity, Digest);
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerProcessMintBridge;
    friend class FreshOwnerTransactionalIssuanceBridge;
public:
    AuthenticatedOwnerProcessBundle(
        const AuthenticatedOwnerProcessBundle&) = delete;
    AuthenticatedOwnerProcessBundle& operator=(
        const AuthenticatedOwnerProcessBundle&) = delete;
    AuthenticatedOwnerProcessBundle(
        AuthenticatedOwnerProcessBundle&&) noexcept;
    AuthenticatedOwnerProcessBundle& operator=(
        AuthenticatedOwnerProcessBundle&&) = delete;
};

// Private, one-shot proof that a round authority came from the same live
// exact-three process tree/root slots/logical roster and from the child-local
// lineage precommitted for this round. It has no receipt or field getter.
class FreshOwnerRoundContinuityAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    std::atomic_bool live_{true};
    explicit FreshOwnerRoundContinuityAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRoundBootstrapBridge;
public:
    FreshOwnerRoundContinuityAuthority(
        const FreshOwnerRoundContinuityAuthority&) = delete;
    FreshOwnerRoundContinuityAuthority& operator=(
        const FreshOwnerRoundContinuityAuthority&) = delete;
    FreshOwnerRoundContinuityAuthority(
        FreshOwnerRoundContinuityAuthority&&) noexcept;
    FreshOwnerRoundContinuityAuthority& operator=(
        FreshOwnerRoundContinuityAuthority&&) = delete;
    ~FreshOwnerRoundContinuityAuthority();
};

// Deliberately has no production consumer yet. A future retry minter must
// consume and reissue this exact round lineage under a fresh attempt; it may
// never substitute a changed owner cohort. No private lineage is public.
class FreshOwnerSameRoundRetryAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    std::atomic_bool live_{true};
    explicit FreshOwnerSameRoundRetryAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class FreshOwnerProcessSupervisor;
public:
    FreshOwnerSameRoundRetryAuthority(
        const FreshOwnerSameRoundRetryAuthority&) = delete;
    FreshOwnerSameRoundRetryAuthority& operator=(
        const FreshOwnerSameRoundRetryAuthority&) = delete;
    FreshOwnerSameRoundRetryAuthority(
        FreshOwnerSameRoundRetryAuthority&&) noexcept;
    FreshOwnerSameRoundRetryAuthority& operator=(
        FreshOwnerSameRoundRetryAuthority&&) = delete;
    ~FreshOwnerSameRoundRetryAuthority();
};

struct PublicCandidateOwnerTruthPostBarrier {
    registered_driver::CaptureClassification classification{};
    Digest authority_identity{};
    Digest trial{};
    Digest barrier_identity{};
    std::array<Digest, 2> financial_runs{};
    std::array<Digest, 2> attempts{};
    std::array<Digest, 2> cohorts{};
    std::array<Digest, 2> capture_plan_identities{};
    std::array<Digest, 2> projection_identities{};
    std::array<Digest, 2> context_identities{};
};

// Production minting belongs only to the genuine frozen measurement barrier.
// The narrow bridge exists, but runtime selection remains separately closed.
class CandidateOwnerTruthPostBarrierAuthority final {
    PublicCandidateOwnerTruthPostBarrier receipt_;
    Digest supervisor_session_{};
    Digest continuation_identity_{};
    std::atomic_bool live_{true};
    explicit CandidateOwnerTruthPostBarrierAuthority(
        PublicCandidateOwnerTruthPostBarrier);
    CandidateOwnerTruthPostBarrierAuthority(
        PublicCandidateOwnerTruthPostBarrier, Digest, Digest);
    friend class FreshOwnerProcessSupervisor;
    friend class CandidateOwnerTruthPostBarrierBridge;
public:
    CandidateOwnerTruthPostBarrierAuthority(
        const CandidateOwnerTruthPostBarrierAuthority&) = delete;
    CandidateOwnerTruthPostBarrierAuthority& operator=(
        const CandidateOwnerTruthPostBarrierAuthority&) = delete;
    CandidateOwnerTruthPostBarrierAuthority(
        CandidateOwnerTruthPostBarrierAuthority&&) noexcept;
    CandidateOwnerTruthPostBarrierAuthority& operator=(
        CandidateOwnerTruthPostBarrierAuthority&&) = delete;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static CandidateOwnerTruthPostBarrierAuthority test_only_mint(
        PublicCandidateOwnerTruthPostBarrier);
#endif
};

class CandidateOwnerTruthPendingAuthority final {
    Digest supervisor_session_{};
    Digest continuation_identity_{};
    std::array<Digest, 2> financial_runs_{};
    std::array<Digest, 2> capture_plan_identities_{};
    std::array<Digest, 2> projection_identities_{};
    std::array<Digest, 2> context_identities_{};
    std::atomic_bool live_{true};
    CandidateOwnerTruthPendingAuthority(
        Digest, Digest, std::array<Digest, 2>, std::array<Digest, 2>,
        std::array<Digest, 2>, std::array<Digest, 2>);
    friend class FreshOwnerProcessSupervisor;
    friend class CandidateOwnerTruthPostBarrierBridge;
public:
    CandidateOwnerTruthPendingAuthority(
        const CandidateOwnerTruthPendingAuthority&) = delete;
    CandidateOwnerTruthPendingAuthority& operator=(
        const CandidateOwnerTruthPendingAuthority&) = delete;
    CandidateOwnerTruthPendingAuthority(
        CandidateOwnerTruthPendingAuthority&&) noexcept;
    CandidateOwnerTruthPendingAuthority& operator=(
        CandidateOwnerTruthPendingAuthority&&) = delete;
};

struct PublicCandidateOwnerTruthEndpoint {
    registered_driver::CaptureClassification classification{};
    unsigned owner_component{};
    int fixed_fd{-1};
    Digest endpoint_identity{};
    Digest feeder_session_identity{};
    Digest trial{};
    Digest barrier_identity{};
    std::array<Digest, 2> financial_runs{};
    std::array<Digest, 2> attempts{};
    std::array<Digest, 2> cohorts{};
    std::array<Digest, 2> capture_plan_identities{};
    std::array<Digest, 2> projection_identities{};
    std::array<Digest, 2> context_identities{};
    std::int64_t feeder_pid{};
    Digest feeder_exit_identity{};
};

class CandidateOwnerTruthEndpointAuthority final {
    PublicCandidateOwnerTruthEndpoint receipt_;
    std::uint64_t device_{}, inode_{};
    int fd_{-1};
    CandidateOwnerTruthEndpointAuthority(
        PublicCandidateOwnerTruthEndpoint, int owned_fd);
    friend class FreshOwnerProcessSupervisor;
    friend class registered_driver::owner_truth_handoff::
        OwnerTruthScoreHandoffBridge;
public:
    CandidateOwnerTruthEndpointAuthority(
        const CandidateOwnerTruthEndpointAuthority&) = delete;
    CandidateOwnerTruthEndpointAuthority& operator=(
        const CandidateOwnerTruthEndpointAuthority&) = delete;
    CandidateOwnerTruthEndpointAuthority(
        CandidateOwnerTruthEndpointAuthority&&) noexcept;
    CandidateOwnerTruthEndpointAuthority& operator=(
        CandidateOwnerTruthEndpointAuthority&&) = delete;
    ~CandidateOwnerTruthEndpointAuthority();
    const PublicCandidateOwnerTruthEndpoint& public_receipt() const {
        return receipt_;
    }
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    static CandidateOwnerTruthEndpointAuthority test_only_mint(
        PublicCandidateOwnerTruthEndpoint, int owned_fd);
    std::array<unsigned char, candidate_truth_schema::PACKET_BYTES>
        test_only_receive_packet();
#endif
};

class CandidateOwnerTruthEndpointSplit final {
    std::array<std::optional<CandidateOwnerTruthEndpointAuthority>, 3>
        endpoints_;
    explicit CandidateOwnerTruthEndpointSplit(
        std::array<CandidateOwnerTruthEndpointAuthority, 3>&&);
    friend class FreshOwnerProcessSupervisor;
public:
    CandidateOwnerTruthEndpointSplit(
        const CandidateOwnerTruthEndpointSplit&) = delete;
    CandidateOwnerTruthEndpointSplit& operator=(
        const CandidateOwnerTruthEndpointSplit&) = delete;
    CandidateOwnerTruthEndpointSplit(
        CandidateOwnerTruthEndpointSplit&&) = delete;
    CandidateOwnerTruthEndpointSplit& operator=(
        CandidateOwnerTruthEndpointSplit&&) = delete;
    CandidateOwnerTruthEndpointAuthority take(unsigned owner);
};

class FreshOwnerRound1IssuedAuthority final {
    std::optional<FreshOwnerRoundAuthority> driver_round_;
    std::optional<AcceptedRound1InputHistoryBootstrapAuthority>
        bootstrap_history_;
    std::optional<FreshOwnerRoundContinuityAuthority> continuity_;
    std::optional<FreshOwnerSameRoundRetryAuthority> retry_;
    std::optional<FreshOwnerPersistentActivationAuthority>
        persistent_activation_;
    std::optional<FreshOwnerProducerClosureAuthority> producer_closure_;
    Digest supervisor_session_identity_{};
    Digest continuation_identity_{};
    PublicAcceptedRound1InputHistory v3_input_history_{};
    std::array<Digest, 3> v3_input_lineages_{};
    Digest v3_measurement_run_binding_identity_{};
    std::array<Digest, 2> v3_financial_runs_{};
    std::array<Digest, 2> v3_capture_plans_{};
    std::array<Digest, 2> v3_projections_{};
    std::array<Digest, 2> v3_contexts_{};
    std::atomic_bool live_{true};
    FreshOwnerRound1IssuedAuthority(
        FreshOwnerRoundAuthority&&,
        AcceptedRound1InputHistoryBootstrapAuthority&&,
        FreshOwnerRoundContinuityAuthority&&,
        FreshOwnerSameRoundRetryAuthority&&,
        FreshOwnerPersistentActivationAuthority&&,
        FreshOwnerProducerClosureAuthority&&,
        Digest, Digest, PublicAcceptedRound1InputHistory,
        std::array<Digest, 3>, Digest, std::array<Digest, 2>,
        std::array<Digest, 2>, std::array<Digest, 2>,
        std::array<Digest, 2>) noexcept;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    FreshOwnerRound1IssuedAuthority(
        FreshOwnerRoundAuthority&&,
        AcceptedRound1InputHistoryBootstrapAuthority&&,
        FreshOwnerRoundContinuityAuthority&&,
        FreshOwnerSameRoundRetryAuthority&&,
        Digest, Digest, PublicAcceptedRound1InputHistory,
        std::array<Digest, 3>, Digest, std::array<Digest, 2>,
        std::array<Digest, 2>, std::array<Digest, 2>,
        std::array<Digest, 2>) noexcept;
#endif
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRound2AttemptOutcomeAuthority;
public:
    FreshOwnerRound1IssuedAuthority(
        const FreshOwnerRound1IssuedAuthority&) = delete;
    FreshOwnerRound1IssuedAuthority& operator=(
        const FreshOwnerRound1IssuedAuthority&) = delete;
    FreshOwnerRound1IssuedAuthority(
        FreshOwnerRound1IssuedAuthority&&) noexcept;
    FreshOwnerRound1IssuedAuthority& operator=(
        FreshOwnerRound1IssuedAuthority&&) = delete;
    FreshOwnerRoundAuthority take_driver_round();
    AcceptedRound1InputHistoryBootstrapAuthority take_bootstrap_history();
    FreshOwnerRoundContinuityAuthority take_continuity();
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    FreshOwnerSameRoundRetryAuthority take_same_round_retry();
#endif
    FreshOwnerPersistentActivationAuthority take_persistent_activation();
    FreshOwnerProducerClosureAuthority take_producer_closure();
};

struct FreshOwnerRound1AttemptOutcomeStorage;

// Opaque result of consuming the accepted-input and arm-isolation gates. It
// keeps their exact source metadata after the two live authorities are burned;
// a moved-from authority or copied receipt cannot reconstruct it.
class FreshOwnerRound1ConsumedGateResidual final {
    PublicAcceptedRound1InputHistory history_{};
    std::array<Digest, 3> input_lineages_{};
    registered_driver::CaptureClassification classification_{};
    Digest isolation_authority_identity_{};
    Digest process_authority_identity_{};
    Digest supervisor_session_identity_{};
    std::atomic_bool live_{true};
    FreshOwnerRound1ConsumedGateResidual(
        PublicAcceptedRound1InputHistory, std::array<Digest, 3>,
        registered_driver::CaptureClassification, Digest isolation,
        Digest process, Digest supervisor) noexcept;
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRound1AttemptOutcomeAuthority;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound1AttemptOutcomeTestBridge;
#endif
public:
    FreshOwnerRound1ConsumedGateResidual(
        const FreshOwnerRound1ConsumedGateResidual&) = delete;
    FreshOwnerRound1ConsumedGateResidual& operator=(
        const FreshOwnerRound1ConsumedGateResidual&) = delete;
    FreshOwnerRound1ConsumedGateResidual(
        FreshOwnerRound1ConsumedGateResidual&&) noexcept;
    FreshOwnerRound1ConsumedGateResidual& operator=(
        FreshOwnerRound1ConsumedGateResidual&&) = delete;
};

// Atomic result of the source-owned Round 1 attempt. Success retains the
// complete issued authority. STOP retains the poisoned exact-three process
// supervisor and every transactional issuance descendant; no public receipt,
// boolean, or partial capability can substitute for this closed sum.
class FreshOwnerRound1AttemptOutcomeAuthority final {
    std::unique_ptr<FreshOwnerRound1AttemptOutcomeStorage> storage_;
    explicit FreshOwnerRound1AttemptOutcomeAuthority(
        std::unique_ptr<FreshOwnerRound1AttemptOutcomeStorage>&&) noexcept;
    bool valid_for_outer_consumer() const noexcept;
    friend class FreshOwnerProcessSupervisor;
    friend class ::kpb::measurement::fresh_trial_owner::
        FreshOwnerRound1AttemptConsumerBridge;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound1AttemptOutcomeTestBridge;
#endif
public:
    FreshOwnerRound1AttemptOutcomeAuthority(
        const FreshOwnerRound1AttemptOutcomeAuthority&) = delete;
    FreshOwnerRound1AttemptOutcomeAuthority& operator=(
        const FreshOwnerRound1AttemptOutcomeAuthority&) = delete;
    FreshOwnerRound1AttemptOutcomeAuthority(
        FreshOwnerRound1AttemptOutcomeAuthority&&) noexcept;
    FreshOwnerRound1AttemptOutcomeAuthority& operator=(
        FreshOwnerRound1AttemptOutcomeAuthority&&) = delete;
    ~FreshOwnerRound1AttemptOutcomeAuthority();
};

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
enum class TestFreshOwnerRound1AttemptOutcome : unsigned char {
    Success,
    UnavailableStop,
    Invalid,
};

enum class FreshOwnerRound1AttemptTestFault : unsigned char {
    None,
    AfterTransactionalJoin,
    AfterFirstChildSend,
    AfterFirstChildResponse,
    AfterAllChildResponses,
    BeforeIssuanceSplit,
    AfterSplitDescendantsRetained,
    AfterContinuityPrepared,
};

enum class FreshOwnerOwnerPidfdWaitTestFault : unsigned char {
    None,
    FirstInterrupted,
    PersistentChildUnavailable,
};

class FreshOwnerRound1AttemptOutcomeTestBridge final {
    FreshOwnerRound1AttemptOutcomeTestBridge() = delete;
public:
    static TestFreshOwnerRound1AttemptOutcome inspect(
        const FreshOwnerRound1AttemptOutcomeAuthority&) noexcept;
    static FreshOwnerRound1IssuedAuthority take_success(
        FreshOwnerRound1AttemptOutcomeAuthority&&);
    static bool stop_retains_claimed_lineage(
        const FreshOwnerRound1AttemptOutcomeAuthority&) noexcept;
    static bool stop_retains_unsettled_pidfds(
        const FreshOwnerRound1AttemptOutcomeAuthority&) noexcept;
    static void discard_stop_for_test(
        FreshOwnerRound1AttemptOutcomeAuthority&&) noexcept;
    static void set_fault(FreshOwnerRound1AttemptTestFault) noexcept;
    static void set_pidfd_wait_fault(
        FreshOwnerOwnerPidfdWaitTestFault) noexcept;
};
#endif

class FreshOwnerRound2IssuedAuthority final {
    std::optional<FreshOwnerRoundAuthority> driver_round_;
    std::optional<AcceptedRound1SuccessorHistoryBootstrapAuthority>
        bootstrap_history_;
    std::optional<FreshOwnerRoundContinuityAuthority> continuity_;
    std::optional<FreshOwnerSameRoundRetryAuthority> retry_;
    std::optional<BaselineOwnerRosterAuthority> roster_;
    std::optional<CandidateOwnerTruthPendingAuthority> candidate_truth_;
    std::optional<V3AcceptedRound1HistoryResidualAuthority> v3_history_;
    FreshOwnerRound2IssuedAuthority(
        FreshOwnerRoundAuthority&&,
        AcceptedRound1SuccessorHistoryBootstrapAuthority&&,
        FreshOwnerRoundContinuityAuthority&&,
        FreshOwnerSameRoundRetryAuthority&&,
        std::optional<BaselineOwnerRosterAuthority>&&,
        std::optional<CandidateOwnerTruthPendingAuthority>&&,
        std::optional<V3AcceptedRound1HistoryResidualAuthority>&&) noexcept;
    friend class FreshOwnerProcessSupervisor;
    friend class FreshOwnerRound2AttemptOutcomeAuthority;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound2AttemptOutcomeTestBridge;
#endif
public:
    FreshOwnerRound2IssuedAuthority(
        const FreshOwnerRound2IssuedAuthority&) = delete;
    FreshOwnerRound2IssuedAuthority& operator=(
        const FreshOwnerRound2IssuedAuthority&) = delete;
    FreshOwnerRound2IssuedAuthority(
        FreshOwnerRound2IssuedAuthority&&) noexcept;
    FreshOwnerRound2IssuedAuthority& operator=(
        FreshOwnerRound2IssuedAuthority&&) = delete;
    FreshOwnerRoundAuthority take_driver_round();
    AcceptedRound1SuccessorHistoryBootstrapAuthority
        take_bootstrap_history();
    FreshOwnerRoundContinuityAuthority take_continuity();
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    FreshOwnerSameRoundRetryAuthority take_same_round_retry();
#endif
    BaselineOwnerRosterAuthority take_baseline_roster();
    CandidateOwnerTruthPendingAuthority take_candidate_truth_pending();
    V3AcceptedRound1HistoryResidualAuthority take_v3_history_residual();
};

struct FreshOwnerRound2AttemptOutcomeStorage;

// Atomic source result for Round 2. Success retains the complete issued
// authority and the consumed successor lineage. STOP retains the poisoned
// exact-three owner supervisor, the emptied Round-1 continuation, every
// partially observed packet/wait fact, and all prebuilt Round-2 descendants.
// Silent destruction is fail-stop until the future causal outer consumer
// takes the whole closed sum.
class FreshOwnerRound2AttemptOutcomeAuthority final {
    std::unique_ptr<FreshOwnerRound2AttemptOutcomeStorage> storage_;
    explicit FreshOwnerRound2AttemptOutcomeAuthority(
        std::unique_ptr<FreshOwnerRound2AttemptOutcomeStorage>&&) noexcept;
    bool valid_for_outer_consumer() const noexcept;
    friend class FreshOwnerProcessSupervisor;
    friend class ::kpb::measurement::fresh_trial_owner::
        FreshOwnerRound2AttemptConsumerBridge;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound2AttemptOutcomeTestBridge;
#endif
public:
    FreshOwnerRound2AttemptOutcomeAuthority(
        const FreshOwnerRound2AttemptOutcomeAuthority&) = delete;
    FreshOwnerRound2AttemptOutcomeAuthority& operator=(
        const FreshOwnerRound2AttemptOutcomeAuthority&) = delete;
    FreshOwnerRound2AttemptOutcomeAuthority(
        FreshOwnerRound2AttemptOutcomeAuthority&&) noexcept;
    FreshOwnerRound2AttemptOutcomeAuthority& operator=(
        FreshOwnerRound2AttemptOutcomeAuthority&&) = delete;
    ~FreshOwnerRound2AttemptOutcomeAuthority();
};

#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
enum class TestFreshOwnerRound2AttemptOutcome : unsigned char {
    Success,
    UnavailableStop,
    Invalid,
};

enum class FreshOwnerRound2AttemptTestFault : unsigned char {
    None,
    AfterInputClaim,
    AfterFirstChildSend,
    AfterFirstChildResponse,
    AfterAllChildResponses,
    BeforeCommit,
};

class FreshOwnerRound2AttemptOutcomeTestBridge final {
    FreshOwnerRound2AttemptOutcomeTestBridge() = delete;
public:
    static TestFreshOwnerRound2AttemptOutcome inspect(
        const FreshOwnerRound2AttemptOutcomeAuthority&) noexcept;
    static FreshOwnerRound2IssuedAuthority take_success(
        FreshOwnerRound2AttemptOutcomeAuthority&&);
    static bool stop_retains_claimed_lineage(
        const FreshOwnerRound2AttemptOutcomeAuthority&) noexcept;
    static void discard_stop_for_test(
        FreshOwnerRound2AttemptOutcomeAuthority&&) noexcept;
    static void set_fault(FreshOwnerRound2AttemptTestFault) noexcept;
};
#endif

class FreshOwnerProcessSupervisor final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit FreshOwnerProcessSupervisor(std::unique_ptr<Storage>);
    CandidateOwnerTruthEndpointSplit release_candidate_truth(
        CandidateOwnerTruthPostBarrierAuthority&&);
    void poison_candidate_truth_release() noexcept;
    FreshOwnerRound1IssuedAuthority issue_round1_from_testnet_history(
        const kpb::testnet_history::PublicAcceptedHistoryStage&,
        registered_driver::RegisteredPreidentityReadyAuthority*,
        OwnerIssuanceReplayGuardAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
    FreshOwnerRound1IssuedAuthority issue_round1_impl(
        AcceptedRound1InputHistoryAuthority&&,
        registered_driver::RegisteredPreidentityReadyAuthority*,
        OwnerIssuanceReplayGuardAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
    FreshOwnerRound1AttemptOutcomeAuthority issue_round1_transactional_impl(
        AcceptedRound1InputHistoryAuthority&&,
        registered_driver::RegisteredPreidentityReadyAuthority&&,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
    FreshOwnerRound2AttemptOutcomeAuthority issue_round2_transactional_impl(
        FreshOwnerRound1IssuedAuthority&&,
        AcceptedRound1SuccessorHistoryAuthority&&);
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    FreshOwnerRound2IssuedAuthority issue_round2_from_testnet_history(
        FreshOwnerRound1IssuedAuthority&&,
        const kpb::testnet_history::PublicAcceptedHistoryStage&);
    void poison_testnet_history_admission() noexcept;
#endif
    bool retains_transactional_round1_lineage() const noexcept;
    friend class CandidateOwnerTruthPostBarrierBridge;
    friend class FreshOwnerRound1AttemptOutcomeAuthority;
    friend class FreshOwnerRound2AttemptOutcomeAuthority;
    friend class ::kpb::measurement::fresh_trial_owner::
        FreshOwnerRound2AttemptConsumerBridge;
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    friend class FreshOwnerRound1AttemptOutcomeTestBridge;
    friend class FreshOwnerRound2AttemptOutcomeTestBridge;
#endif
public:
    FreshOwnerProcessSupervisor(const FreshOwnerProcessSupervisor&) = delete;
    FreshOwnerProcessSupervisor& operator=(
        const FreshOwnerProcessSupervisor&) = delete;
    FreshOwnerProcessSupervisor(FreshOwnerProcessSupervisor&&) noexcept;
    FreshOwnerProcessSupervisor& operator=(
        FreshOwnerProcessSupervisor&&) = delete;
    ~FreshOwnerProcessSupervisor();

    static FreshOwnerProcessSupervisor launch_exact_three(
        CompiledPrivateLifecycleOwnerProgramAuthority&&,
        std::array<OwnerPrivateRootAuthority, 3>&&);
    const PublicFreshOwnerProcessLaunch& public_receipt() const;
    FreshOwnerPrivateArmLaunchAuthority take_private_arm_launch();
#ifndef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    [[nodiscard]] FreshOwnerRound1AttemptOutcomeAuthority issue_round1(
        AcceptedRound1InputHistoryAuthority&&,
        registered_driver::RegisteredPreidentityReadyAuthority&&,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
#else
    [[nodiscard]] FreshOwnerRound1AttemptOutcomeAuthority
    issue_round1_transactional(
        AcceptedRound1InputHistoryAuthority&&,
        registered_driver::RegisteredPreidentityReadyAuthority&&,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
#endif
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    FreshOwnerRound1IssuedAuthority issue_round1(
        AcceptedRound1InputHistoryAuthority&&,
        registered_driver::RegisteredPreidentityReadyAuthority&&,
        OwnerIssuanceReplayGuardAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
    FreshOwnerRound1IssuedAuthority issue_round1(
        kpb::testnet_history::AcceptedRound1InputChainAuthority&&,
        registered_driver::RegisteredPreidentityReadyAuthority&&,
        OwnerIssuanceReplayGuardAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
    // Legacy controls exercise owner-process mechanics only. Production
    // headers expose no issuance route that omits the causal Ready authority.
    FreshOwnerRound1IssuedAuthority issue_round1(
        AcceptedRound1InputHistoryAuthority&&,
        OwnerIssuanceReplayGuardAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
    FreshOwnerRound1IssuedAuthority issue_round1(
        kpb::testnet_history::AcceptedRound1InputChainAuthority&&,
        OwnerIssuanceReplayGuardAuthority&&,
        FreshOwnerArmIsolationResidualAuthority&&);
#endif
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    [[nodiscard]] FreshOwnerRound2AttemptOutcomeAuthority
    issue_round2_transactional(
        FreshOwnerRound1IssuedAuthority&&,
        AcceptedRound1SuccessorHistoryAuthority&&);
    FreshOwnerRound2IssuedAuthority issue_round2(
        FreshOwnerRound1IssuedAuthority&&,
        AcceptedRound1SuccessorHistoryAuthority&&);
    FreshOwnerRound2IssuedAuthority issue_round2(
        FreshOwnerRound1IssuedAuthority&&,
        kpb::testnet_history::AcceptedRound1SuccessorChainAuthority&&);
#endif
#ifdef KPI_FRESH_OWNER_PROCESS_ADAPTER_TEST_SETUP
    CandidateOwnerTruthEndpointSplit test_only_release_candidate_truth(
        CandidateOwnerTruthPendingAuthority&&,
        CandidateOwnerTruthPostBarrierAuthority&&);
#endif
    bool completed() const;
    const PublicFreshOwnerProcessCompletion& public_completion() const;
};

struct FreshOwnerProcessAdapterSourceStatus {
    std::string schema;
    std::string status;
    bool exact_three_long_lived_children;
    bool inherited_seqpacket_scm_credentials;
    bool fixed_private_root_descriptors;
    bool parent_root_aliases_after_ack;
    bool round2_requires_typed_accepted_history;
    bool round2_typed_attempt_outcome;
    bool round2_postclaim_typed_stop;
    bool production_round2_consumer;
    bool path_body_or_body_hash_export;
    bool selected_private_lifecycle_program;
    bool production_root_authority_minter;
    bool production_history_authority_minter;
    bool typed_testnet_history_adapter;
    bool issuance_validated_v3_history_residual;
    bool production_v3_lifecycle_controller_minter;
    bool production_replay_store_minter;
    bool same_round_retry_minter;
    bool hidden_candidate_fd42_truth_endpoint;
    bool production_post_barrier_truth_minter;
    bool registered_driver_configured;
    bool launch_authorized;
};

FreshOwnerProcessAdapterSourceStatus
fresh_owner_process_adapter_source_status();

} // namespace kpi::mpc::financial::fresh_owner_issuance
