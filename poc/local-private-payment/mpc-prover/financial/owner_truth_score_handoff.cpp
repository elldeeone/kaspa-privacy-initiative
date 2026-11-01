#include "owner_truth_score_handoff.hpp"

#include "authenticated_baseline_owner_receiver.hpp"
#include "baseline_owner_truth_capsule_bridge.hpp"
#include "fresh_owner_process_adapter.hpp"
#include "../../private_batch_trial/privacy_measurement_worker_capsule.hpp"

#include <algorithm>
#include <cerrno>
#include <optional>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace kpi::mpc::financial::registered_driver::owner_truth_handoff {
namespace {
using kpb::measurement::Classification;
using kpb::measurement::Digest;
using kpb::measurement::OwnerScoreExecutionPermitAuthority;
using kpb::measurement::OwnerScorePermitSplit;
using kpb::measurement::PublicOwnerTruthReleasePermit;
using kpb::measurement::runtime_bridge::MeasurementInputEndpointAuthority;
using kpb::measurement::runtime_bridge::MeasurementInputKind;
using PublicEndpoint =
    kpb::measurement::runtime_bridge::PublicMeasurementInputEndpoint;

[[noreturn]] void refuse() { throw kpb::measurement::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

class OwnedFd final {
    int value_{-1};
public:
    explicit OwnedFd(int value) : value_(value) {}
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
    ~OwnedFd() {
        if (value_ < 0) return;
        while (::close(value_) != 0 && errno == EINTR) {}
    }
    int get() const { return value_; }
};

void require_split_match(
        const kpb::measurement::PublicOwnerScorePermit& execution,
        const PublicOwnerTruthReleasePermit& release) {
    need(execution.binding == release.binding &&
         execution.owner == release.owner &&
         execution.trial_capture_identity ==
             release.trial_capture_identity &&
         execution.observation_receipt == release.observation_receipt &&
         execution.barrier == release.barrier &&
         execution.permit_identity == release.score_permit_identity &&
         nonzero(release.barrier));
}

void require_lineage(
        const PublicEndpoint& endpoint,
        const PublicOwnerTruthReleasePermit& release,
        Classification classification) {
    const auto& binding = release.binding;
    const auto& lineage = endpoint.lineage;
    need(binding.classification == classification &&
         endpoint.kind == MeasurementInputKind::OwnerTruth &&
         endpoint.owner == release.owner &&
         endpoint.fixed_fd ==
             kpb::measurement::runtime_bridge::
                 MEASUREMENT_SCORE_OWNER_TRUTH_FD &&
         nonzero(endpoint.identity) &&
         lineage.classification == classification &&
         lineage.trial == binding.trial &&
         lineage.barrier == release.barrier &&
         lineage.capture_plan_identities == binding.round_capture_plans &&
         lineage.financial_runs == binding.financial_runs &&
         lineage.round_attempts == binding.round_attempts &&
         lineage.round_cohorts == binding.round_cohorts &&
         lineage.projections == binding.projections);
}
} // namespace

struct OwnerTruthScoreHandoff::Storage final {
    std::optional<OwnerScoreExecutionPermitAuthority> execution;
    std::optional<MeasurementInputEndpointAuthority> endpoint;
    Storage(OwnerScoreExecutionPermitAuthority&& supplied_execution,
            MeasurementInputEndpointAuthority&& supplied_endpoint)
        : execution(std::move(supplied_execution)),
          endpoint(std::move(supplied_endpoint)) {}
};

OwnerTruthScoreHandoff::OwnerTruthScoreHandoff(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr && storage_->execution.has_value() &&
         storage_->endpoint.has_value());
}

OwnerTruthScoreHandoff::OwnerTruthScoreHandoff(
        OwnerTruthScoreHandoff&&) noexcept = default;
OwnerTruthScoreHandoff::~OwnerTruthScoreHandoff() = default;

OwnerScoreExecutionPermitAuthority
OwnerTruthScoreHandoff::take_execution_permit() {
    need(storage_ != nullptr && storage_->execution.has_value());
    OwnerScoreExecutionPermitAuthority result(
        std::move(*storage_->execution));
    storage_->execution.reset();
    return result;
}

MeasurementInputEndpointAuthority
OwnerTruthScoreHandoff::take_truth_endpoint() {
    need(storage_ != nullptr && storage_->endpoint.has_value());
    MeasurementInputEndpointAuthority result(
        std::move(*storage_->endpoint));
    storage_->endpoint.reset();
    return result;
}

OwnerTruthScoreHandoff OwnerTruthScoreHandoffBridge::prepare(
        OwnerScorePermitSplit&& split,
        baseline_disclosure::OwnerScoreTruthAuthority&& truth) {
    auto execution = split.take_execution_permit();
    auto release = split.take_truth_release_permit();
    need(release.live_.exchange(false));
    const auto expected = release.receipt_;
    require_split_match(execution.public_receipt(), expected);
    auto endpoint = baseline_disclosure::BaselineOwnerTruthCapsuleBridge::
        prepare(std::move(truth), expected);
    require_lineage(endpoint.public_receipt(), expected,
                    Classification::TransparentBaseline);
    return OwnerTruthScoreHandoff(
        std::make_unique<OwnerTruthScoreHandoff::Storage>(
            std::move(execution), std::move(endpoint)));
}

OwnerTruthScoreHandoff OwnerTruthScoreHandoffBridge::prepare(
        OwnerScorePermitSplit&& split,
        fresh_owner_issuance::CandidateOwnerTruthEndpointAuthority&& truth) {
    auto execution = split.take_execution_permit();
    auto release = split.take_truth_release_permit();
    need(release.live_.exchange(false));
    const auto expected = release.receipt_;
    require_split_match(execution.public_receipt(), expected);
    const auto& source = truth.receipt_;
    using registered_driver::CaptureClassification;
    need(source.classification == CaptureClassification::HiddenCandidate &&
         expected.binding.classification == Classification::HiddenCandidate &&
         source.owner_component == expected.owner &&
         source.fixed_fd == fresh_owner_issuance::FRESH_OWNER_FIXED_TRUTH_FD &&
         source.trial == expected.binding.trial &&
         source.barrier_identity == expected.barrier &&
         source.financial_runs == expected.binding.financial_runs &&
         source.attempts == expected.binding.round_attempts &&
         source.cohorts == expected.binding.round_cohorts &&
         source.capture_plan_identities ==
             expected.binding.round_capture_plans &&
         source.projection_identities == expected.binding.projections &&
         source.context_identities[0] != source.context_identities[1]);
    for (const auto& value : source.context_identities) need(nonzero(value));

    struct stat state{};
    int socket_type = 0;
    socklen_t socket_type_bytes = sizeof(socket_type);
    need(truth.fd_ >= 0 && ::fstat(truth.fd_, &state) == 0 &&
         S_ISSOCK(state.st_mode) &&
         static_cast<std::uint64_t>(state.st_dev) == truth.device_ &&
         static_cast<std::uint64_t>(state.st_ino) == truth.inode_ &&
         ::getsockopt(truth.fd_, SOL_SOCKET, SO_TYPE, &socket_type,
                      &socket_type_bytes) == 0 &&
         socket_type_bytes == sizeof(socket_type) &&
         socket_type == SOCK_SEQPACKET);
    OwnedFd source_fd(std::exchange(truth.fd_, -1));
    PublicEndpoint::PublicLineage lineage{
        .classification = Classification::HiddenCandidate,
        .trial = source.trial,
        .barrier = source.barrier_identity,
        .capture_plan_identities = source.capture_plan_identities,
        .financial_runs = source.financial_runs,
        .round_attempts = source.attempts,
        .round_cohorts = source.cohorts,
        .projections = source.projection_identities,
    };
    MeasurementInputEndpointAuthority endpoint(
        MeasurementInputKind::OwnerTruth, source.owner_component,
        source_fd.get(), source.endpoint_identity, std::move(lineage),
        source.feeder_pid, source.feeder_session_identity,
        source.feeder_exit_identity);
    require_lineage(endpoint.public_receipt(), expected,
                    Classification::HiddenCandidate);
    return OwnerTruthScoreHandoff(
        std::make_unique<OwnerTruthScoreHandoff::Storage>(
            std::move(execution), std::move(endpoint)));
}

} // namespace kpi::mpc::financial::registered_driver::owner_truth_handoff
