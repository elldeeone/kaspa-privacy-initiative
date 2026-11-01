#pragma once

#include "privacy_measurement_runtime_types.hpp"
#include "privacy_observation_barrier_fanout_contract.hpp"
#include "privacy_owner_score_output_split_contract.hpp"
#include "../mpc-prover/financial/baseline_owner_truth_capsule_bridge.hpp"
#include "../mpc-prover/financial/owner_truth_score_handoff.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

namespace kpb::measurement::empirical_result {
class NativeEmpiricalResultAuthority;
}

namespace kpb::measurement::runtime_bridge {

inline constexpr int MEASUREMENT_OBSERVER_INPUT_FD = 40;
inline constexpr int MEASUREMENT_SCORE_OBSERVATION_FD = 41;
inline constexpr int MEASUREMENT_SCORE_OWNER_TRUTH_FD = 42;
inline constexpr int MEASUREMENT_AGGREGATE_OWNER0_FD = 43;
inline constexpr int MEASUREMENT_AGGREGATE_OWNER1_FD = 44;
inline constexpr int MEASUREMENT_AGGREGATE_OWNER2_FD = 45;
inline constexpr int MEASUREMENT_COMPARISON_BASELINE0_FD = 46;
inline constexpr int MEASUREMENT_COMPARISON_BASELINE1_FD = 47;
inline constexpr int MEASUREMENT_COMPARISON_BASELINE2_FD = 48;
inline constexpr int MEASUREMENT_COMPARISON_CANDIDATE0_FD = 49;
inline constexpr int MEASUREMENT_COMPARISON_CANDIDATE1_FD = 50;
inline constexpr int MEASUREMENT_COMPARISON_CANDIDATE2_FD = 51;
inline constexpr int MEASUREMENT_SOURCE_CAPSULE_FD = 60;
inline constexpr int MEASUREMENT_ASSET_CAPSULE_FD = 61;
inline constexpr int MEASUREMENT_CHILD_FIXED_FD = 63;
inline constexpr unsigned MAX_MEASUREMENT_INPUTS = 6;

class MeasurementWorkerCapsuleAuthority;
class ChildCompletionEvidenceAuthority;
class ObservationRuntimeCompletion;
class OwnerScoreRuntimeCompletion;
class AggregateRuntimeCompletion;
class OwnerComparisonRuntimeCompletion;
class SealedChildOutputAuthority;
struct PublicRuntimeChildOffer;

// Fully defined before it receives friendship from the capsule/evidence
// authorities. There is no forward-friend surface for a lookalike class.
class MeasurementChildSupervisor final {
    MeasurementChildSupervisor() = delete;
    static ChildCompletionEvidenceAuthority supervise(
        const PublicRuntimeChildOffer&, MeasurementWorkerCapsuleAuthority&&,
        const RunBinding*,
        std::unique_ptr<SealedChildOutputAuthority>*);
public:
    static ObservationRuntimeCompletion run_observer(
        ObserverExecutionPermitAuthority&&,
        MeasurementWorkerCapsuleAuthority&&,
        empirical_result::NativeEmpiricalResultAuthority&&);
    static OwnerScoreRuntimeCompletion run_owner_score(
        OwnerScoreExecutionPermitAuthority&&,
        MeasurementWorkerCapsuleAuthority&&);
    static AggregateRuntimeCompletion run_aggregate(
        AggregatePermitAuthority&&, MeasurementWorkerCapsuleAuthority&&);
    static OwnerComparisonRuntimeCompletion run_owner_comparison(
        OwnerComparisonPermitAuthority&&,
        MeasurementWorkerCapsuleAuthority&&);
};

enum class MeasurementInputKind : unsigned char {
    ObserverCapture = 1,
    ScoreObservation = 2,
    OwnerTruth = 3,
    AggregateOwnerScore = 4,
    ComparisonBaselineOwnerScore = 5,
    ComparisonCandidateOwnerScore = 6,
};

struct PublicMeasurementInputEndpoint {
    struct PublicLineage {
        Classification classification{};
        Digest trial{};
        Digest barrier{};
        std::array<Digest, 2> capture_plan_identities{};
        std::array<Digest, 2> financial_runs{};
        std::array<Digest, 2> round_attempts{};
        std::array<Digest, 2> round_cohorts{};
        std::array<Digest, 2> projections{};
        bool operator==(const PublicLineage&) const = default;
    };
    MeasurementInputKind kind{};
    unsigned owner{NO_OWNER};
    int fixed_fd{-1};
    Digest identity{};
    PublicLineage lineage;
    bool operator==(const PublicMeasurementInputEndpoint&) const = default;
};

class MeasurementInputEndpointAuthority final {
    PublicMeasurementInputEndpoint receipt_;
    std::uint64_t device_{};
    std::uint64_t inode_{};
    std::uint32_t file_type_{};
    std::int64_t feeder_pid_{-1};
    Digest feeder_session_{};
    Digest feeder_exit_identity_{};
    int fd_{-1};
    std::atomic_bool live_{true};
    MeasurementInputEndpointAuthority(
        MeasurementInputKind, unsigned owner, int source_fd, Digest,
        PublicMeasurementInputEndpoint::PublicLineage,
        std::int64_t feeder_pid, Digest feeder_session,
        Digest feeder_exit_identity);
    friend class MeasurementWorkerCapsuleAuthority;
    friend class ObserverCaptureCapsuleBridge;
    friend class kpb::measurement::observation_fanout::
        ObservationBarrierFanoutBridge;
    friend class kpb::measurement::score_output_split::
        OwnerScoreOutputSplitBridge;
    friend class kpi::mpc::financial::registered_driver::
        baseline_disclosure::BaselineOwnerTruthCapsuleBridge;
    friend class kpi::mpc::financial::registered_driver::
        owner_truth_handoff::OwnerTruthScoreHandoffBridge;
public:
    MeasurementInputEndpointAuthority(
        const MeasurementInputEndpointAuthority&) = delete;
    MeasurementInputEndpointAuthority& operator=(
        const MeasurementInputEndpointAuthority&) = delete;
    MeasurementInputEndpointAuthority(
        MeasurementInputEndpointAuthority&&) noexcept;
    MeasurementInputEndpointAuthority& operator=(
        MeasurementInputEndpointAuthority&&) = delete;
    ~MeasurementInputEndpointAuthority();
    const PublicMeasurementInputEndpoint& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP
    static MeasurementInputEndpointAuthority test_only_mint(
        MeasurementInputKind, unsigned owner, int source_fd, Digest,
        PublicMeasurementInputEndpoint::PublicLineage = {},
        std::int64_t feeder_pid = 4001,
        Digest feeder_session = {}, Digest feeder_exit_identity = {});
#endif
};

struct PublicMeasurementWorkerCapsule {
    RuntimeChildRole role{};
    unsigned owner{NO_OWNER};
    WorkerBinding worker;
    Digest descriptor_manifest_identity{};
    std::array<PublicMeasurementInputEndpoint,
               MAX_MEASUREMENT_INPUTS> inputs{};
    unsigned input_count{};
    Digest capsule_identity{};
    bool operator==(const PublicMeasurementWorkerCapsule&) const = default;
};

WorkerBinding recompute_native_worker_binding(
    RuntimeChildRole, const Digest& pinned_runtime,
    const Digest& canonical_source, const Digest& canonical_assets);

Digest recompute_worker_capsule_identity(
    const PublicMeasurementWorkerCapsule&);

class MeasurementWorkerCapsuleAuthority final {
    struct RetainedInput {
        PublicMeasurementInputEndpoint receipt;
        std::uint64_t device{};
        std::uint64_t inode{};
        std::uint32_t file_type{};
        std::int64_t feeder_pid{-1};
        Digest feeder_session{};
        Digest feeder_exit_identity{};
        int fd{-1};
    };
    PublicMeasurementWorkerCapsule receipt_;
    int runtime_fd_{-1};
    int source_fd_{-1};
    int assets_fd_{-1};
    std::array<RetainedInput, MAX_MEASUREMENT_INPUTS> inputs_{};
    std::atomic_bool live_{true};
    MeasurementWorkerCapsuleAuthority() = default;
    void close_fds() noexcept;
    friend class MeasurementChildSupervisor;
public:
    MeasurementWorkerCapsuleAuthority(
        const MeasurementWorkerCapsuleAuthority&) = delete;
    MeasurementWorkerCapsuleAuthority& operator=(
        const MeasurementWorkerCapsuleAuthority&) = delete;
    MeasurementWorkerCapsuleAuthority(
        MeasurementWorkerCapsuleAuthority&&) noexcept;
    MeasurementWorkerCapsuleAuthority& operator=(
        MeasurementWorkerCapsuleAuthority&&) = delete;
    ~MeasurementWorkerCapsuleAuthority();

    static MeasurementWorkerCapsuleAuthority seal_native(
        RuntimeChildRole, unsigned owner, int runtime_fd,
        int canonical_source_fd, int canonical_assets_fd,
        std::vector<MeasurementInputEndpointAuthority>&&);

    const PublicMeasurementWorkerCapsule& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_MEASUREMENT_WORKER_CAPSULE_TEST_SETUP
    void test_only_verify_seals_and_read_only() const;
#endif
};

struct WorkerCapsuleSourceStatus {
    bool canonical_archive_parser{};
    bool static_native_runtime{};
    bool fixed_descriptor_manifest{};
    bool deny_unselected_filesystem{};
    bool deny_network_and_introspection{};
    bool production_input_adapter{};
    bool configured{};
    bool launch_enabled{};
};

inline constexpr WorkerCapsuleSourceStatus kWorkerCapsuleSourceStatus{
    .canonical_archive_parser = true,
    .static_native_runtime = true,
    .fixed_descriptor_manifest = true,
    .deny_unselected_filesystem = false,
    .deny_network_and_introspection = false,
};

} // namespace kpb::measurement::runtime_bridge
