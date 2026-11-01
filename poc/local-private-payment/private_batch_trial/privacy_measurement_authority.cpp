#include "privacy_measurement_authority.hpp"
#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_native_phase_scope_authority.hpp"
#include "privacy_measurement_observer_admission_storage.hpp"

#include <algorithm>
#include <cerrno>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace kpb::measurement {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool retained_output_present(bool present) {
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
    // Legacy state-machine unit controls use receipt-only test authorities.
    // Production never compiles this exception; end-to-end runtime controls
    // exercise the genuine sealed-output path.
    (void)present;
    return true;
#else
    return present;
#endif
}

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

template<std::size_t Size>
void distinct_nonzero(const std::array<Digest, Size>& values) {
    for (std::size_t left = 0; left < values.size(); ++left) {
        need(nonzero(values[left]));
        for (std::size_t right = left + 1; right < values.size(); ++right)
            need(values[left] != values[right]);
    }
}

void valid(const WorkerBinding& value) {
    for (const auto* digest : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity,
             &value.launcher_identity})
        need(nonzero(*digest));
}

const ManifestEntry& entry(const FiniteManifestBinding& manifest,
                           ManifestComponent component) {
    const auto index = static_cast<unsigned>(component) - 1;
    need(index < manifest.entries.size());
    need(manifest.entries[index].component == component);
    return manifest.entries[index];
}

WorkerBinding worker_binding(const ManifestEntry& value) {
    return WorkerBinding{
        .source_identity = value.source_identity,
        .build_identity = value.build_identity,
        .runtime_identity = value.runtime_identity,
        .assets_identity = value.assets_identity,
        .pinned_executable_identity = value.pinned_executable_identity,
        .launcher_identity = value.launcher_identity,
    };
}

ManifestComponent stream_component(CaptureKind kind) {
    switch (kind) {
    case CaptureKind::PublicProjection:
        return ManifestComponent::FinancialCore;
    case CaptureKind::TerminalHistory:
        return ManifestComponent::TerminalCapture;
    case CaptureKind::Dispatcher:
        return ManifestComponent::Dispatcher;
    case CaptureKind::CorruptServer:
        return ManifestComponent::P1Capture;
    case CaptureKind::ColluderWallet:
        return ManifestComponent::C1Supervisor;
    }
    refuse();
}

void valid(const FiniteManifestBinding& value) {
    need(nonzero(value.manifest_identity) &&
         nonzero(value.parent_recomputation_identity) &&
         value.manifest_identity != value.parent_recomputation_identity &&
         value.manifest_identity ==
             recompute_finite_manifest_identity(value.entries));
    for (unsigned index = 0; index < value.entries.size(); ++index) {
        const auto& entry = value.entries[index];
        need(entry.component ==
             static_cast<ManifestComponent>(index + 1));
        for (const auto* digest : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            need(nonzero(*digest));
    }
}

void valid(const RunBinding& value) {
    need(value.classification == Classification::TransparentBaseline ||
         value.classification == Classification::HiddenCandidate);
    for (const auto* digest : {
             &value.comparison_selection, &value.run_selection, &value.trial,
             &value.attempt, &value.cohort, &value.capture, &value.method,
             &value.workload, &value.source_closure, &value.runtime,
             &value.outer_parent_process, &value.outer_parent_executable,
             &value.capture_source, &value.capture_build,
             &value.capture_runtime, &value.capture_launcher,
             &value.financial_runs[0], &value.financial_runs[1],
             &value.round_attempts[0], &value.round_attempts[1],
             &value.round_cohorts[0], &value.round_cohorts[1],
             &value.round_capture_plans[0],
             &value.round_capture_plans[1],
             &value.projections[0], &value.projections[1]})
        need(nonzero(*digest));
    valid(value.finite_manifest);
    valid(value.observer_worker);
    valid(value.score_worker);
    valid(value.aggregate_worker);
    const auto& capture = entry(
        value.finite_manifest, ManifestComponent::P1Capture);
    need(value.capture_source == capture.source_identity &&
         value.capture_build == capture.build_identity &&
         value.capture_runtime == capture.runtime_identity &&
         value.capture_launcher == capture.launcher_identity &&
         value.observer_worker == worker_binding(entry(
             value.finite_manifest, ManifestComponent::Observer)) &&
         value.score_worker == worker_binding(entry(
             value.finite_manifest, ManifestComponent::OwnerScore)) &&
         value.aggregate_worker == worker_binding(entry(
             value.finite_manifest, ManifestComponent::Aggregate)));
    need(value.financial_runs[0] != value.financial_runs[1] &&
         value.round_attempts[0] != value.round_attempts[1] &&
         value.round_cohorts[0] != value.round_cohorts[1] &&
         value.round_capture_plans[0] !=
             value.round_capture_plans[1] &&
         value.projections[0] != value.projections[1] &&
         value.run_selection != value.comparison_selection &&
         value.trial != value.attempt && value.attempt != value.cohort);
}

void valid(const PublicPartyCompletion& value) {
    valid(value.binding);
    need((value.round == 1 || value.round == 2) && value.role < 3 &&
         value.financial_run ==
             value.binding.financial_runs[value.round - 1] &&
         value.trial == value.binding.trial &&
         value.attempt == value.binding.round_attempts[value.round - 1] &&
         value.cohort == value.binding.round_cohorts[value.round - 1] &&
         value.projection == value.binding.projections[value.round - 1] &&
         value.postlock_accepted_head == value.accepted_head &&
         value.capture_source == value.binding.capture_source &&
         value.capture_build == value.binding.capture_build &&
         value.capture_runtime == value.binding.capture_runtime &&
         value.capture_launcher == value.binding.capture_launcher);
    for (const auto* digest : {
             &value.child_exit, &value.driver_completion,
             &value.selection_identity, &value.proposal_identity,
             &value.accepted_head, &value.postlock_accepted_head,
             &value.durable_lock, &value.process_identity, &value.egress,
             &value.proof})
        need(nonzero(*digest));
}

void valid(const PublicProducerClosure& value) {
    valid(value.binding);
    valid(value.producer_worker);
    for (const auto* digest : {
             &value.opaque_closure_authority_identity,
             &value.role_closure_identity, &value.manifest_seal,
             &value.construction_classification_receipt})
        need(nonzero(*digest));
    need(nonzero(value.producer_process_identity) &&
         value.producer_worker == worker_binding(entry(
             value.binding.finite_manifest, ManifestComponent::Producer)));
    need((value.binding.classification ==
              Classification::TransparentBaseline &&
          value.construction_policy ==
              ConstructionPolicy::ExplicitOwnerPublicEffects) ||
         (value.binding.classification == Classification::HiddenCandidate &&
          value.construction_policy ==
              ConstructionPolicy::SecretPermutationIndependent));
    need(value.stream_count == 10 && value.closed_root_count == 10 &&
         value.unknown_record_count == 0);
    for (unsigned index = 0; index < value.streams.size(); ++index) {
        const auto& stream = value.streams[index];
        need(stream.round == index / 5 + 1 &&
             stream.kind == static_cast<CaptureKind>(index % 5 + 1) &&
             stream.fixed_fd == 20 + index &&
             stream.manifest_component == stream_component(stream.kind));
        const auto& component = entry(
            value.binding.finite_manifest, stream.manifest_component);
        need(stream.source_identity == component.source_identity &&
             stream.build_identity == component.build_identity &&
             stream.runtime_identity == component.runtime_identity &&
             stream.launcher_identity == component.launcher_identity);
        for (const auto* digest : {
                 &stream.source_identity, &stream.build_identity,
                 &stream.runtime_identity, &stream.launcher_identity,
                 &stream.process_identity, &stream.child_exit_identity})
            need(nonzero(*digest));
        need(stream.root_closed && stream.end_observed &&
             stream.eof_observed);
    }
}

void valid(const ProducerClosureEvidence& evidence,
           const PublicProducerClosure& receipt) {
    need(evidence.opaque_closure_authority_identity ==
         receipt.opaque_closure_authority_identity);
    distinct_nonzero(std::array<Digest, 4>{
        evidence.opaque_closure_authority_identity,
        evidence.producer_child_exit,
        evidence.producer_receipt,
        evidence.producer_identity,
    });
    for (const auto& stream : evidence.streams)
    {
        for (const auto* digest : {
                 &stream.record_root, &stream.end_frame_identity,
                 &stream.eof_identity})
            need(nonzero(*digest));
        need(stream.record_count > 0 && stream.payload_bytes > 0 &&
             stream.raw_wire_bytes > stream.payload_bytes);
    }
}

void append(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void append_binding(std::vector<unsigned char>& out,
                    const RunBinding& value) {
    out.push_back(static_cast<unsigned char>(value.classification));
    for (const auto* digest : {
             &value.comparison_selection, &value.run_selection, &value.trial,
             &value.attempt, &value.cohort, &value.capture, &value.method,
             &value.workload, &value.source_closure, &value.runtime,
             &value.outer_parent_process, &value.outer_parent_executable,
             &value.capture_source, &value.capture_build,
             &value.capture_runtime, &value.capture_launcher,
             &value.financial_runs[0], &value.financial_runs[1],
             &value.round_attempts[0], &value.round_attempts[1],
             &value.round_cohorts[0], &value.round_cohorts[1],
             &value.round_capture_plans[0],
             &value.round_capture_plans[1],
             &value.projections[0], &value.projections[1]})
        append(out, *digest);
    append(out, value.finite_manifest.manifest_identity);
    append(out, value.finite_manifest.parent_recomputation_identity);
    for (const auto& entry : value.finite_manifest.entries) {
        out.push_back(static_cast<unsigned char>(entry.component));
        append(out, entry.source_identity);
        append(out, entry.build_identity);
        append(out, entry.runtime_identity);
        append(out, entry.assets_identity);
        append(out, entry.pinned_executable_identity);
        append(out, entry.launcher_identity);
    }
    for (const auto* worker : {
             &value.observer_worker, &value.score_worker,
             &value.aggregate_worker}) {
        append(out, worker->source_identity);
        append(out, worker->build_identity);
        append(out, worker->runtime_identity);
        append(out, worker->assets_identity);
        append(out, worker->pinned_executable_identity);
        append(out, worker->launcher_identity);
    }
}

Digest identity(std::string_view label, const RunBinding& binding,
                std::span<const Digest> values,
                std::optional<unsigned char> discriminator = std::nullopt) {
    std::vector<unsigned char> bytes(label.begin(), label.end());
    append_binding(bytes, binding);
    if (discriminator.has_value()) bytes.push_back(*discriminator);
    for (const auto& value : values) append(bytes, value);
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}

Digest truth_release_identity(const PublicOwnerScorePermit& value) {
    const std::array<Digest, 4> inputs{
        value.trial_capture_identity,
        value.observation_receipt,
        value.barrier,
        value.permit_identity,
    };
    return identity("KPB_OWNER_TRUTH_RELEASE_PERMIT_V1\n",
                    value.binding, inputs,
                    static_cast<unsigned char>(value.owner));
}

Digest candidate_truth_barrier_release_identity_impl(
        const PublicCandidateTruthBarrierRelease& value) {
    const std::array<Digest, 3> inputs{
        value.trial_capture_identity,
        value.observation_receipt,
        value.barrier,
    };
    return identity("KPB_CANDIDATE_TRUTH_BARRIER_RELEASE_V1\n",
                    value.binding, inputs);
}

Digest completion_identity(const PublicTrialCaptureCompletion& value) {
    static constexpr char label[] = "KPB_TRIAL_CAPTURE_COMPLETION_V2\n";
    std::vector<unsigned char> bytes(label, label + sizeof(label) - 1);
    append_binding(bytes, value.binding);
    for (const auto& round : value.party_completion)
        for (const auto& party : round) append(bytes, party);
    for (const auto& round : value.party_selection)
        for (const auto& party : round) append(bytes, party);
    for (const auto& round : value.party_proposal)
        for (const auto& party : round) append(bytes, party);
    for (const auto& round : value.party_process)
        for (const auto& party : round) append(bytes, party);
    for (const auto& round : value.party_child_exit)
        for (const auto& party : round) append(bytes, party);
    for (const auto& round : value.party_egress)
        for (const auto& party : round) append(bytes, party);
    for (const auto& round : value.party_proof)
        for (const auto& party : round) append(bytes, party);
    append(bytes, value.projections[0]);
    append(bytes, value.projections[1]);
    append(bytes, value.opaque_closure_authority_identity);
    append(bytes, value.producer_worker.source_identity);
    append(bytes, value.producer_worker.build_identity);
    append(bytes, value.producer_worker.runtime_identity);
    append(bytes, value.producer_worker.assets_identity);
    append(bytes, value.producer_worker.pinned_executable_identity);
    append(bytes, value.producer_worker.launcher_identity);
    append(bytes, value.producer_process_identity);
    append(bytes, value.role_closure_identity);
    append(bytes, value.manifest_seal);
    bytes.push_back(static_cast<unsigned char>(value.construction_policy));
    append(bytes, value.construction_classification_receipt);
    append(bytes, value.manifest_parent_process_identity);
    append(bytes, value.manifest_parent_executable_identity);
    append(bytes, value.manifest_recomputation_receipt);
    for (const auto& stream : value.streams) {
        bytes.push_back(static_cast<unsigned char>(stream.round));
        bytes.push_back(static_cast<unsigned char>(stream.kind));
        bytes.push_back(static_cast<unsigned char>(stream.fixed_fd));
        bytes.push_back(
            static_cast<unsigned char>(stream.manifest_component));
        append(bytes, stream.source_identity);
        append(bytes, stream.build_identity);
        append(bytes, stream.runtime_identity);
        append(bytes, stream.launcher_identity);
        append(bytes, stream.process_identity);
        append(bytes, stream.child_exit_identity);
        bytes.push_back(stream.root_closed ? 1 : 0);
        bytes.push_back(stream.end_observed ? 1 : 0);
        bytes.push_back(stream.eof_observed ? 1 : 0);
    }
    append(bytes, value.stream_count);
    append(bytes, value.closed_root_count);
    append(bytes, value.unknown_record_count);
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}

void valid(const PublicObservationCompletion& value) {
    valid(value.binding);
    valid(value.worker);
    for (const auto* digest : {
             &value.permit_identity, &value.trial_capture_identity,
             &value.child_exit, &value.observation_receipt,
             &value.process_identity})
        need(nonzero(*digest));
}

void valid(const PublicBarrierFreeze& value) {
    valid(value.binding);
    for (const auto* digest : {
             &value.trial_capture_identity, &value.observation_receipt,
             &value.barrier_receipt, &value.outer_parent_process,
             &value.outer_parent_executable,
             &value.manifest_recomputation_receipt})
        need(nonzero(*digest));
    need(value.outer_parent_process == value.binding.outer_parent_process &&
         value.outer_parent_executable ==
             value.binding.outer_parent_executable &&
         value.manifest_recomputation_receipt ==
             value.binding.finite_manifest.parent_recomputation_identity);
}

void valid(const PublicOwnerScorePermit& value) {
    valid(value.binding);
    need(value.owner < 3);
    for (const auto* digest : {
             &value.trial_capture_identity, &value.observation_receipt,
             &value.barrier, &value.permit_identity})
        need(nonzero(*digest));
}

void valid(const PublicCandidateTruthBarrierRelease& value) {
    valid(value.binding);
    need(value.binding.classification == Classification::HiddenCandidate);
    for (const auto* digest : {
             &value.trial_capture_identity, &value.observation_receipt,
             &value.barrier, &value.release_identity})
        need(nonzero(*digest));
    need(value.release_identity ==
         recompute_candidate_truth_barrier_release_identity(value));
}

void valid(const PublicOwnerTruthReleasePermit& value) {
    valid(value.binding);
    need(value.owner < 3);
    for (const auto* digest : {
             &value.trial_capture_identity, &value.observation_receipt,
             &value.barrier, &value.score_permit_identity,
             &value.release_identity})
        need(nonzero(*digest));
    const PublicOwnerScorePermit score{
        .binding = value.binding,
        .owner = value.owner,
        .trial_capture_identity = value.trial_capture_identity,
        .observation_receipt = value.observation_receipt,
        .barrier = value.barrier,
        .permit_identity = value.score_permit_identity,
    };
    need(value.release_identity == truth_release_identity(score));
}

void valid(const PublicOwnerScoreCompletion& value) {
    valid(value.binding);
    valid(value.worker);
    need(value.owner < 3);
    for (const auto* digest : {
             &value.permit_identity, &value.barrier, &value.child_exit,
             &value.score_receipt, &value.capsule_seal})
        need(nonzero(*digest));
    need(nonzero(value.process_identity));
}

void valid(const PublicAggregateCompletion& value) {
    valid(value.binding);
    valid(value.worker);
    for (const auto* digest : {
             &value.permit_identity, &value.barrier, &value.child_exit,
             &value.aggregate_receipt})
        need(nonzero(*digest));
    need(nonzero(value.process_identity));
    need(value.outcome == AggregateOutcome::BaselineControlDetected ||
         value.outcome == AggregateOutcome::CandidatePass ||
         value.outcome == AggregateOutcome::Fail ||
         value.outcome == AggregateOutcome::Unqualified);
    if (value.outcome == AggregateOutcome::BaselineControlDetected)
        need(value.binding.classification ==
             Classification::TransparentBaseline);
    if (value.outcome == AggregateOutcome::CandidatePass)
        need(value.binding.classification == Classification::HiddenCandidate);
}

} // namespace

Digest recompute_candidate_truth_barrier_release_identity(
        const PublicCandidateTruthBarrierRelease& value) {
    valid(value.binding);
    need(value.binding.classification == Classification::HiddenCandidate &&
         nonzero(value.trial_capture_identity) &&
         nonzero(value.observation_receipt) && nonzero(value.barrier));
    return candidate_truth_barrier_release_identity_impl(value);
}

Digest recompute_finite_manifest_identity(
        const std::array<ManifestEntry, 10>& entries) {
    static constexpr char label[] = "KPB_FINITE_MULTILANGUAGE_MANIFEST_V1\n";
    std::vector<unsigned char> bytes(label, label + sizeof(label) - 1);
    for (const auto& entry : entries) {
        bytes.push_back(static_cast<unsigned char>(entry.component));
        append(bytes, entry.source_identity);
        append(bytes, entry.build_identity);
        append(bytes, entry.runtime_identity);
        append(bytes, entry.assets_identity);
        append(bytes, entry.pinned_executable_identity);
        append(bytes, entry.launcher_identity);
    }
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}

const char* Refused::what() const noexcept {
    return "KPB_MEASUREMENT_AUTHORITY_REFUSED";
}

void validate_measurement_run_binding(const RunBinding& binding) {
    valid(binding);
}

runtime_bridge::ObserverAdmissionAuthority::Storage::~Storage() {
    if (terminal_v2_model_admission != nullptr) {
        if (destroy_terminal_v2_model_admission != nullptr)
            destroy_terminal_v2_model_admission(
                terminal_v2_model_admission);
        terminal_v2_model_admission = nullptr;
        destroy_terminal_v2_model_admission = nullptr;
    }
    if (directory_fd >= 0) {
        while (::close(directory_fd) != 0 && errno == EINTR) {}
        directory_fd = -1;
    }
    for (auto& fd : archive_fds) {
        if (fd < 0) continue;
        while (::close(fd) != 0 && errno == EINTR) {}
        fd = -1;
    }
    if (structural_continuity_fd >= 0) {
        while (::close(structural_continuity_fd) != 0 && errno == EINTR) {}
        structural_continuity_fd = -1;
    }
}

runtime_bridge::ObserverAdmissionAuthority::ObserverAdmissionAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

runtime_bridge::ObserverAdmissionAuthority::ObserverAdmissionAuthority(
        ObserverAdmissionAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

runtime_bridge::ObserverAdmissionAuthority::~ObserverAdmissionAuthority() =
    default;

void runtime_bridge::ObserverAdmissionAuthority::require_matches(
        const RunBinding& binding,
        const PublicProducerClosure& closure,
        const ProducerClosureEvidence& evidence) {
    need(storage_ != nullptr && storage_->binding == binding);
    if (storage_->test_only) return;
    need(!storage_->matched_producer_closure.has_value() &&
         closure.binding == binding &&
         closure.opaque_closure_authority_identity ==
             storage_->opaque_closure_authority_identity &&
         evidence.opaque_closure_authority_identity ==
             storage_->opaque_closure_authority_identity &&
         closure.producer_process_identity ==
             storage_->producer_process_identity &&
         evidence.producer_child_exit ==
             storage_->c03_producer_child_exit &&
         evidence.producer_receipt ==
             storage_->c03_producer_receipt);
    if (storage_->sealed_archive) {
        need(storage_->directory_fd < 0 &&
             evidence.streams == storage_->archive_stream_evidence);
        for (int fd : storage_->archive_fds) need(fd >= 0);
    } else {
        need(storage_->directory_fd >= 0 &&
             evidence == storage_->producer_closure_evidence);
    }
    const auto p1_index =
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1;
    need(p1_index < binding.finite_manifest.entries.size());
    const auto& p1 = binding.finite_manifest.entries[p1_index];
    need(p1.component == ManifestComponent::P1Capture);
    for (unsigned index = 0; index < storage_->c03_rounds.size(); ++index) {
        const auto& admitted = storage_->c03_rounds[index];
        const auto& stream = closure.streams[index * 5 + 3];
        need(admitted.round == index + 1 &&
             admitted.fixed_fd == 23 + 5 * index &&
             admitted.source_identity == p1.source_identity &&
             admitted.build_identity == p1.build_identity &&
             admitted.runtime_identity == p1.runtime_identity &&
             admitted.launcher_identity == p1.launcher_identity &&
             stream.round == admitted.round &&
             stream.kind == CaptureKind::CorruptServer &&
             stream.fixed_fd == admitted.fixed_fd &&
             stream.manifest_component == ManifestComponent::P1Capture &&
             stream.source_identity == admitted.source_identity &&
             stream.build_identity == admitted.build_identity &&
             stream.runtime_identity == admitted.runtime_identity &&
             stream.launcher_identity == admitted.launcher_identity &&
             stream.process_identity == admitted.process_identity &&
             stream.child_exit_identity == admitted.child_exit_identity);
    }
    for (unsigned index = 0; index < storage_->c1_rounds.size(); ++index) {
        const auto& admitted = storage_->c1_rounds[index];
        const auto& stream = closure.streams[index * 5 + 4];
        need(admitted.round == index + 1 &&
             admitted.fixed_capture_fd == 24 + 5 * index &&
             stream.round == admitted.round &&
             stream.kind == CaptureKind::ColluderWallet &&
             stream.fixed_fd == admitted.fixed_capture_fd &&
             stream.source_identity == admitted.worker.source_identity &&
             stream.build_identity == admitted.worker.build_identity &&
             stream.runtime_identity == admitted.worker.runtime_identity &&
             stream.launcher_identity ==
                 admitted.worker.launcher_identity &&
             stream.process_identity == admitted.process_identity &&
             stream.child_exit_identity ==
                 admitted.expected_child_exit_identity);
    }
    if (storage_->sealed_archive)
        storage_->producer_closure_evidence = evidence;
    storage_->matched_producer_closure = closure;
}

#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
runtime_bridge::ObserverAdmissionAuthority
runtime_bridge::ObserverAdmissionAuthority::test_only_mint(
        const RunBinding& binding) {
    auto storage = std::make_unique<Storage>();
    storage->binding = binding;
    storage->test_only = true;
    return ObserverAdmissionAuthority(std::move(storage));
}
#endif

ParentManifestRecomputationAuthority::ParentManifestRecomputationAuthority(
        PublicParentManifestRecomputation receipt)
    : receipt_(std::move(receipt)) {
    valid(receipt_.manifest);
    need(nonzero(receipt_.parent_process_identity) &&
         nonzero(receipt_.parent_executable_identity) &&
         receipt_.recomputation_receipt ==
             receipt_.manifest.parent_recomputation_identity);
}
ParentManifestRecomputationAuthority::ParentManifestRecomputationAuthority(
        ParentManifestRecomputationAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
ParentManifestRecomputationAuthority
ParentManifestRecomputationAuthority::test_only_mint(
        PublicParentManifestRecomputation receipt) {
    return ParentManifestRecomputationAuthority(std::move(receipt));
}
#endif

PartyCompletionAuthority::PartyCompletionAuthority(
        PublicPartyCompletion receipt) : receipt_(std::move(receipt)) {
    valid(receipt_);
}
PartyCompletionAuthority::PartyCompletionAuthority(
        PartyCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
PartyCompletionAuthority PartyCompletionAuthority::test_only_mint(
        PublicPartyCompletion receipt) {
    return PartyCompletionAuthority(std::move(receipt));
}
#endif

ProducerClosureAuthority::ProducerClosureAuthority(
        PublicProducerClosure receipt, ProducerClosureEvidence evidence)
    : receipt_(std::move(receipt)), evidence_(std::move(evidence)) {
    valid(receipt_);
    valid(evidence_, receipt_);
}
ProducerClosureAuthority::ProducerClosureAuthority(
        ProducerClosureAuthority&& other) noexcept
    : receipt_(other.receipt_), evidence_(other.evidence_),
      live_(other.live_.exchange(false)) {}
void ProducerClosureAuthority::validate_for_native_terminal_join() const {
    valid(receipt_);
    valid(evidence_, receipt_);
}
ProducerClosureAuthority
ProducerClosureAuthority::transfer_for_native_terminal_join() && {
    need(live_.exchange(false));
    valid(receipt_);
    valid(evidence_, receipt_);
    return ProducerClosureAuthority(receipt_, evidence_);
}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
ProducerClosureAuthority ProducerClosureAuthority::test_only_mint(
        PublicProducerClosure receipt, ProducerClosureEvidence evidence) {
    return ProducerClosureAuthority(
        std::move(receipt), std::move(evidence));
}
#endif

TrialCaptureCompletionAuthority::TrialCaptureCompletionAuthority(
        PublicTrialCaptureCompletion receipt,
        runtime_bridge::ObserverAdmissionAuthority&& admission,
        std::optional<kpi::mpc::financial::registered_driver::
            RegisteredMeasurementCaptureRetention>&& registered_trial)
    : receipt_(std::move(receipt)), admission_(std::move(admission)),
      registered_trial_(std::move(registered_trial)) {}
TrialCaptureCompletionAuthority::TrialCaptureCompletionAuthority(
        TrialCaptureCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), admission_(std::move(other.admission_)),
      registered_trial_(std::move(other.registered_trial_)),
      live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
TrialCaptureCompletionAuthority
TrialCaptureCompletionAuthority::test_only_mint(
        PublicTrialCaptureCompletion receipt) {
    auto admission =
        runtime_bridge::ObserverAdmissionAuthority::test_only_mint(
            receipt.binding);
    return TrialCaptureCompletionAuthority(
        std::move(receipt), std::move(admission));
}
#endif

TrialCaptureJoiner::TrialCaptureJoiner(
        RunBinding binding,
        ParentManifestRecomputationAuthority&& manifest_recomputation)
    : binding_(std::move(binding)) {
    try {
        need(manifest_recomputation.live_.exchange(false));
        valid(binding_);
        need(manifest_recomputation.receipt_.manifest ==
                 binding_.finite_manifest &&
             manifest_recomputation.receipt_.parent_process_identity ==
                 binding_.outer_parent_process &&
             manifest_recomputation.receipt_.parent_executable_identity ==
                 binding_.outer_parent_executable);
        manifest_recomputation_ = manifest_recomputation.receipt_;
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

void TrialCaptureJoiner::submit(PartyCompletionAuthority&& authority) {
    std::lock_guard guard(mutex_);
    try {
        const bool live = authority.live_.exchange(false);
        need(live && !poisoned_ && !finished_);
        valid(authority.receipt_);
        need(authority.receipt_.binding == binding_);
        auto& selected_round = parties_[authority.receipt_.round - 1];
        for (const auto& existing : selected_round) {
            if (!existing.has_value()) continue;
            need(existing->accepted_head == authority.receipt_.accepted_head &&
                 existing->selection_identity ==
                     authority.receipt_.selection_identity &&
                 existing->durable_lock == authority.receipt_.durable_lock &&
                 existing->egress == authority.receipt_.egress &&
                 existing->proof == authority.receipt_.proof &&
                 existing->projection == authority.receipt_.projection);
        }
        auto& slot = selected_round[authority.receipt_.role];
        need(!slot.has_value());
        slot = authority.receipt_;
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

void TrialCaptureJoiner::submit(
        ProducerClosureAuthority&& authority,
        runtime_bridge::ObserverAdmissionAuthority&& admission) {
    std::lock_guard guard(mutex_);
    try {
        const bool live = authority.live_.exchange(false);
        need(live && !poisoned_ && !finished_ && !producer_.has_value() &&
             !observer_admission_.has_value());
        valid(authority.receipt_);
        valid(authority.evidence_, authority.receipt_);
        need(authority.receipt_.binding == binding_);
        admission.require_matches(
            binding_, authority.receipt_, authority.evidence_);
        producer_ = authority.receipt_;
        producer_evidence_ = authority.evidence_;
        observer_admission_.emplace(std::move(admission));
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
void TrialCaptureJoiner::submit(ProducerClosureAuthority&& authority) {
    auto admission =
        runtime_bridge::ObserverAdmissionAuthority::test_only_mint(binding_);
    submit(std::move(authority), std::move(admission));
}
#endif

TrialCaptureCompletionAuthority TrialCaptureJoiner::finish() {
    std::lock_guard guard(mutex_);
    try {
        need(!poisoned_ && !finished_ && producer_.has_value() &&
             producer_evidence_.has_value() &&
             observer_admission_.has_value());
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
        need(registered_trial_.has_value() ||
             allow_fixture_without_registered_trial_);
#else
        need(registered_trial_.has_value());
#endif
        valid(*producer_evidence_, *producer_);
        PublicTrialCaptureCompletion receipt{
            .binding = binding_,
            .projections = binding_.projections,
            .opaque_closure_authority_identity =
                producer_->opaque_closure_authority_identity,
            .producer_worker = producer_->producer_worker,
            .producer_process_identity = producer_->producer_process_identity,
            .role_closure_identity = producer_->role_closure_identity,
            .manifest_seal = producer_->manifest_seal,
            .construction_policy = producer_->construction_policy,
            .construction_classification_receipt =
                producer_->construction_classification_receipt,
            .manifest_parent_process_identity =
                manifest_recomputation_.parent_process_identity,
            .manifest_parent_executable_identity =
                manifest_recomputation_.parent_executable_identity,
            .manifest_recomputation_receipt =
                manifest_recomputation_.recomputation_receipt,
            .streams = producer_->streams,
            .stream_count = producer_->stream_count,
            .closed_root_count = producer_->closed_root_count,
            .unknown_record_count = producer_->unknown_record_count,
        };
        for (unsigned round = 0; round < 2; ++round)
            for (unsigned role = 0; role < 3; ++role) {
                need(parties_[round][role].has_value());
                receipt.party_completion[round][role] =
                    parties_[round][role]->driver_completion;
                receipt.party_selection[round][role] =
                    parties_[round][role]->selection_identity;
                receipt.party_proposal[round][role] =
                    parties_[round][role]->proposal_identity;
                receipt.party_process[round][role] =
                    parties_[round][role]->process_identity;
                receipt.party_child_exit[round][role] =
                    parties_[round][role]->child_exit;
                receipt.party_egress[round][role] =
                    parties_[round][role]->egress;
                receipt.party_proof[round][role] =
                    parties_[round][role]->proof;
            }
        receipt.completion_identity = completion_identity(receipt);
        finished_ = true;
        auto admission = std::move(*observer_admission_);
        observer_admission_.reset();
        auto registered_trial = std::move(registered_trial_);
        registered_trial_.reset();
        return TrialCaptureCompletionAuthority(
            std::move(receipt), std::move(admission),
            std::move(registered_trial));
    } catch (...) {
        poisoned_ = true;
        refuse();
    }
}

ObserverPermitAuthority::ObserverPermitAuthority(
        PublicObserverPermit receipt,
        runtime_bridge::ObserverAdmissionAuthority&& admission)
    : receipt_(std::move(receipt)), admission_(std::move(admission)) {}
ObserverPermitAuthority::ObserverPermitAuthority(
        ObserverPermitAuthority&& other) noexcept
    : receipt_(other.receipt_), admission_(std::move(other.admission_)),
      live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
ObserverPermitAuthority ObserverPermitAuthority::test_only_mint(
        PublicObserverPermit receipt) {
    auto admission =
        runtime_bridge::ObserverAdmissionAuthority::test_only_mint(
            receipt.binding);
    return ObserverPermitAuthority(
        std::move(receipt), std::move(admission));
}
ObserverExecutionPermitAuthority
ObserverPermitAuthority::test_only_take_execution() && {
    need(live_.exchange(false) && admission_.has_value());
    admission_.reset();
    return ObserverExecutionPermitAuthority(receipt_);
}
#endif

ObserverExecutionPermitAuthority::ObserverExecutionPermitAuthority(
        PublicObserverPermit receipt) : receipt_(std::move(receipt)) {}
ObserverExecutionPermitAuthority::ObserverExecutionPermitAuthority(
        ObserverExecutionPermitAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
ObserverExecutionPermitAuthority
ObserverExecutionPermitAuthority::test_only_mint(
        PublicObserverPermit receipt) {
    return ObserverExecutionPermitAuthority(std::move(receipt));
}
#endif

ObservationCompletionAuthority::ObservationCompletionAuthority(
        PublicObservationCompletion receipt,
        std::unique_ptr<phase_scope::ObservationOutputJoinAuthority> output)
    : receipt_(std::move(receipt)), private_output_(std::move(output)) {
    valid(receipt_);
}
ObservationCompletionAuthority::~ObservationCompletionAuthority() = default;
ObservationCompletionAuthority::ObservationCompletionAuthority(
        ObservationCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_),
      private_output_(std::move(other.private_output_)),
      live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
ObservationCompletionAuthority
ObservationCompletionAuthority::test_only_mint(
        PublicObservationCompletion receipt) {
    return ObservationCompletionAuthority(std::move(receipt), nullptr);
}
#endif

BarrierFreezeAuthority::BarrierFreezeAuthority(PublicBarrierFreeze receipt)
    : receipt_(std::move(receipt)) {
    valid(receipt_);
}
BarrierFreezeAuthority::BarrierFreezeAuthority(
        BarrierFreezeAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
BarrierFreezeAuthority BarrierFreezeAuthority::test_only_mint(
        PublicBarrierFreeze receipt) {
    return BarrierFreezeAuthority(std::move(receipt));
}
#endif

CandidateTruthBarrierReleaseAuthority::
CandidateTruthBarrierReleaseAuthority(
        PublicCandidateTruthBarrierRelease receipt)
    : receipt_(std::move(receipt)) {
    valid(receipt_);
}
CandidateTruthBarrierReleaseAuthority::
CandidateTruthBarrierReleaseAuthority(
        CandidateTruthBarrierReleaseAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

OwnerScorePermitAuthority::OwnerScorePermitAuthority(
        PublicOwnerScorePermit receipt) : receipt_(std::move(receipt)) {
    valid(receipt_);
}
OwnerScorePermitAuthority::OwnerScorePermitAuthority(
        OwnerScorePermitAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
OwnerScorePermitSplit
OwnerScorePermitAuthority::split_for_truth_release() && {
    try {
        need(live_.exchange(false));
        valid(receipt_);
        PublicOwnerTruthReleasePermit release{
            .binding = receipt_.binding,
            .owner = receipt_.owner,
            .trial_capture_identity = receipt_.trial_capture_identity,
            .observation_receipt = receipt_.observation_receipt,
            .barrier = receipt_.barrier,
            .score_permit_identity = receipt_.permit_identity,
            .release_identity = truth_release_identity(receipt_),
        };
        return OwnerScorePermitSplit(
            OwnerScoreExecutionPermitAuthority(receipt_),
            OwnerTruthReleasePermitAuthority(std::move(release)));
    } catch (...) {
        refuse();
    }
}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
OwnerScorePermitAuthority OwnerScorePermitAuthority::test_only_mint(
        PublicOwnerScorePermit receipt) {
    return OwnerScorePermitAuthority(std::move(receipt));
}
#endif

OwnerScoreExecutionPermitAuthority::OwnerScoreExecutionPermitAuthority(
        PublicOwnerScorePermit receipt) : receipt_(std::move(receipt)) {
    valid(receipt_);
}
OwnerScoreExecutionPermitAuthority::OwnerScoreExecutionPermitAuthority(
        OwnerScoreExecutionPermitAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

OwnerTruthReleasePermitAuthority::OwnerTruthReleasePermitAuthority(
        PublicOwnerTruthReleasePermit receipt)
    : receipt_(std::move(receipt)) {
    valid(receipt_);
}
OwnerTruthReleasePermitAuthority::OwnerTruthReleasePermitAuthority(
        OwnerTruthReleasePermitAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

OwnerScorePermitSplit::OwnerScorePermitSplit(
        OwnerScoreExecutionPermitAuthority&& execution,
        OwnerTruthReleasePermitAuthority&& truth_release)
    : execution_(std::move(execution)),
      truth_release_(std::move(truth_release)) {}

OwnerScorePermitSplit::OwnerScorePermitSplit(
        OwnerScorePermitSplit&& other) noexcept
    : execution_(std::move(other.execution_)),
      truth_release_(std::move(other.truth_release_)) {
    other.execution_.reset();
    other.truth_release_.reset();
}

OwnerScoreExecutionPermitAuthority
OwnerScorePermitSplit::take_execution_permit() {
    need(execution_.has_value());
    OwnerScoreExecutionPermitAuthority result(std::move(*execution_));
    execution_.reset();
    return result;
}

OwnerTruthReleasePermitAuthority
OwnerScorePermitSplit::take_truth_release_permit() {
    need(truth_release_.has_value());
    OwnerTruthReleasePermitAuthority result(std::move(*truth_release_));
    truth_release_.reset();
    return result;
}

OwnerScoreCompletionAuthority::OwnerScoreCompletionAuthority(
        PublicOwnerScoreCompletion receipt,
        std::unique_ptr<runtime_bridge::SealedChildOutputAuthority> output)
    : receipt_(std::move(receipt)), private_output_(std::move(output)) {
    valid(receipt_);
}
OwnerScoreCompletionAuthority::~OwnerScoreCompletionAuthority() = default;
OwnerScoreCompletionAuthority::OwnerScoreCompletionAuthority(
        OwnerScoreCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_),
      private_output_(std::move(other.private_output_)),
      live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
OwnerScoreCompletionAuthority
OwnerScoreCompletionAuthority::test_only_mint(
        PublicOwnerScoreCompletion receipt) {
    return OwnerScoreCompletionAuthority(std::move(receipt), nullptr);
}
#endif

AggregatePermitAuthority::AggregatePermitAuthority(
        PublicAggregatePermit receipt) : receipt_(std::move(receipt)) {}
AggregatePermitAuthority::AggregatePermitAuthority(
        AggregatePermitAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
AggregatePermitAuthority AggregatePermitAuthority::test_only_mint(
        PublicAggregatePermit receipt) {
    return AggregatePermitAuthority(std::move(receipt));
}
#endif

AggregateCompletionAuthority::AggregateCompletionAuthority(
        PublicAggregateCompletion receipt) : receipt_(std::move(receipt)) {
    valid(receipt_);
}
AggregateCompletionAuthority::AggregateCompletionAuthority(
        AggregateCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
AggregateCompletionAuthority AggregateCompletionAuthority::test_only_mint(
        PublicAggregateCompletion receipt) {
    return AggregateCompletionAuthority(std::move(receipt));
}
#endif

RunAggregateCompletionAuthority::RunAggregateCompletionAuthority(
        PublicRunAggregateCompletion receipt) : receipt_(std::move(receipt)) {}
RunAggregateCompletionAuthority::RunAggregateCompletionAuthority(
        RunAggregateCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
RunAggregateCompletionAuthority
RunAggregateCompletionAuthority::test_only_mint(
        PublicRunAggregateCompletion receipt) {
    return RunAggregateCompletionAuthority(std::move(receipt));
}
#endif

RunMeasurement::RunMeasurement(
        TrialCaptureCompletionAuthority&& authority) {
    try {
        need(authority.live_.exchange(false));
        valid(authority.receipt_.binding);
        need(nonzero(authority.receipt_.completion_identity) &&
             authority.admission_.has_value());
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
        // Legacy state-machine controls use receipt-only fixture captures.
        // Registered bridge controls require and exercise the retained trial.
#else
        need(authority.registered_trial_.has_value());
#endif
        capture_ = authority.receipt_;
        if (authority.registered_trial_.has_value()) {
            registered_trial_.emplace(
                std::move(*authority.registered_trial_));
            authority.registered_trial_.reset();
        }
        observer_admission_.emplace(
            std::move(*authority.admission_));
        authority.admission_.reset();
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

RunMeasurement::~RunMeasurement() {
    if (owner_score_outcome_storage_ != nullptr &&
        destroy_owner_score_outcome_storage_ != nullptr)
        destroy_owner_score_outcome_storage_(owner_score_outcome_storage_);
}

ObserverPermitAuthority RunMeasurement::issue_observer() {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::CaptureReady &&
             observer_admission_.has_value());
        const std::array<Digest, 1> inputs{capture_.completion_identity};
        PublicObserverPermit permit{
            .binding = capture_.binding,
            .trial_capture_identity = capture_.completion_identity,
            .permit_identity = identity(
                "KPB_OBSERVER_PERMIT_V1\n", capture_.binding, inputs),
        };
        observer_permit_ = permit;
        state_ = State::ObserverIssued;
        auto admission = std::move(*observer_admission_);
        observer_admission_.reset();
        return ObserverPermitAuthority(
            std::move(permit), std::move(admission));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

void RunMeasurement::accept_observer(
        ObserverExecutionPermitAuthority&& permit,
        ObservationCompletionAuthority&& completion) {
    std::lock_guard guard(mutex_);
    try {
        const bool permit_live = permit.live_.exchange(false);
        const bool completion_live = completion.live_.exchange(false);
        need(permit_live && completion_live &&
             state_ == State::ObserverIssued && observer_permit_.has_value() &&
             retained_output_present(completion.private_output_ != nullptr));
        valid(completion.receipt_);
        need(permit.receipt_.binding == capture_.binding &&
             permit.receipt_.permit_identity ==
                 observer_permit_->permit_identity &&
             permit.receipt_.trial_capture_identity ==
                 capture_.completion_identity &&
             completion.receipt_.binding == capture_.binding &&
             completion.receipt_.permit_identity ==
                 permit.receipt_.permit_identity &&
             completion.receipt_.trial_capture_identity ==
                 capture_.completion_identity &&
             completion.receipt_.worker == capture_.binding.observer_worker);
        observation_ = completion.receipt_;
        observation_output_ = std::move(completion.private_output_);
        state_ = State::ObserverComplete;
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

void RunMeasurement::freeze_barrier(BarrierFreezeAuthority&& authority) {
    std::lock_guard guard(mutex_);
    try {
        const bool live = authority.live_.exchange(false);
        valid(authority.receipt_);
        need(state_ == State::ObserverComplete && observation_.has_value() &&
             retained_output_present(observation_output_ != nullptr) &&
             live && authority.receipt_.binding == capture_.binding &&
             authority.receipt_.trial_capture_identity ==
                 capture_.completion_identity &&
             authority.receipt_.observation_receipt ==
                 observation_->observation_receipt);
        barrier_ = authority.receipt_.barrier_receipt;
        state_ = State::BarrierFrozen;
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

CandidateTruthBarrierReleaseAuthority
RunMeasurement::issue_candidate_truth_barrier_release() {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::BarrierFrozen && observation_.has_value() &&
             retained_output_present(observation_output_ != nullptr) &&
             capture_.binding.classification ==
                 Classification::HiddenCandidate &&
             !candidate_truth_barrier_release_issued_);
        PublicCandidateTruthBarrierRelease release{
            .binding = capture_.binding,
            .trial_capture_identity = capture_.completion_identity,
            .observation_receipt = observation_->observation_receipt,
            .barrier = barrier_,
        };
        release.release_identity =
            recompute_candidate_truth_barrier_release_identity(release);
        candidate_truth_barrier_release_issued_ = true;
        return CandidateTruthBarrierReleaseAuthority(std::move(release));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

OwnerScorePermitAuthority RunMeasurement::issue_score(unsigned owner) {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::BarrierFrozen && observation_.has_value() &&
             owner < 3 && !score_issued_[owner] &&
             (capture_.binding.classification ==
                  Classification::TransparentBaseline ||
              candidate_truth_barrier_release_issued_));
        const std::array<Digest, 3> inputs{
            capture_.completion_identity,
            observation_->observation_receipt,
            barrier_,
        };
        PublicOwnerScorePermit permit{
            .binding = capture_.binding,
            .owner = owner,
            .trial_capture_identity = capture_.completion_identity,
            .observation_receipt = observation_->observation_receipt,
            .barrier = barrier_,
            .permit_identity = identity(
                "KPB_OWNER_SCORE_PERMIT_V1\n", capture_.binding, inputs,
                static_cast<unsigned char>(owner)),
        };
        score_issued_[owner] = true;
        score_permits_[owner] = permit;
        return OwnerScorePermitAuthority(std::move(permit));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
void RunMeasurement::accept_score(
        OwnerScoreExecutionPermitAuthority&& permit,
        OwnerScoreCompletionAuthority&& completion) {
    std::lock_guard guard(mutex_);
    try {
        const bool permit_live = permit.live_.exchange(false);
        const bool completion_live = completion.live_.exchange(false);
        need(permit_live && completion_live &&
             state_ == State::BarrierFrozen && observation_.has_value() &&
             retained_output_present(observation_output_ != nullptr) &&
             retained_output_present(completion.private_output_ != nullptr));
        valid(completion.receipt_);
        const unsigned owner = permit.receipt_.owner;
        need(owner < 3 && score_issued_[owner] && !scores_[owner].has_value() &&
             permit.receipt_.binding == capture_.binding &&
             permit.receipt_.trial_capture_identity ==
                 capture_.completion_identity &&
             permit.receipt_.observation_receipt ==
                 observation_->observation_receipt &&
             permit.receipt_.barrier == barrier_ &&
             completion.receipt_.binding == capture_.binding &&
             completion.receipt_.owner == owner &&
             completion.receipt_.permit_identity ==
                 permit.receipt_.permit_identity &&
             completion.receipt_.barrier == barrier_ &&
             completion.receipt_.worker == capture_.binding.score_worker);
        scores_[owner] = completion.receipt_;
        score_outputs_[owner] = std::move(completion.private_output_);
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

AggregatePermitAuthority RunMeasurement::issue_aggregate() {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::BarrierFrozen && observation_.has_value() &&
             retained_output_present(observation_output_ != nullptr) &&
             std::all_of(scores_.begin(), scores_.end(),
                         [](const auto& row) { return row.has_value(); }) &&
             retained_output_present(std::all_of(
                 score_outputs_.begin(), score_outputs_.end(),
                 [](const auto& row) { return row != nullptr; })));
        PublicAggregatePermit permit{
            .binding = capture_.binding,
            .trial_capture_identity = capture_.completion_identity,
            .observation_receipt = observation_->observation_receipt,
            .barrier = barrier_,
        };
        std::array<Digest, 3> child_exits{};
        std::array<Digest, 3> score_processes{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            permit.score_receipts[owner] = scores_[owner]->score_receipt;
            permit.capsule_seals[owner] = scores_[owner]->capsule_seal;
            child_exits[owner] = scores_[owner]->child_exit;
            score_processes[owner] = scores_[owner]->process_identity;
        }
        distinct_nonzero(permit.score_receipts);
        distinct_nonzero(permit.capsule_seals);
        distinct_nonzero(child_exits);
        distinct_nonzero(score_processes);
        std::array<Digest, 9> inputs{
            permit.trial_capture_identity, permit.observation_receipt,
            permit.barrier,
            permit.score_receipts[0], permit.score_receipts[1],
            permit.score_receipts[2], permit.capsule_seals[0],
            permit.capsule_seals[1], permit.capsule_seals[2],
        };
        permit.permit_identity = identity(
            "KPB_AGGREGATE_PERMIT_V1\n", capture_.binding, inputs);
        aggregate_permit_ = permit;
        state_ = State::AggregateIssued;
        return AggregatePermitAuthority(std::move(permit));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}
#endif

RunAggregateCompletionAuthority RunMeasurement::accept_aggregate(
        AggregatePermitAuthority&& permit,
        AggregateCompletionAuthority&& completion) {
    std::lock_guard guard(mutex_);
    try {
        const bool permit_live = permit.live_.exchange(false);
        const bool completion_live = completion.live_.exchange(false);
        need(permit_live && completion_live &&
             state_ == State::AggregateIssued &&
             aggregate_permit_.has_value() && observation_.has_value());
        valid(completion.receipt_);
        need(permit.receipt_.binding == capture_.binding &&
             permit.receipt_.permit_identity ==
                 aggregate_permit_->permit_identity &&
             permit.receipt_.barrier == barrier_ &&
             completion.receipt_.binding == capture_.binding &&
             completion.receipt_.permit_identity ==
                 permit.receipt_.permit_identity &&
             completion.receipt_.barrier == barrier_ &&
             completion.receipt_.worker == capture_.binding.aggregate_worker);
        PublicRunAggregateCompletion result{
            .binding = capture_.binding,
            .trial_capture_identity = capture_.completion_identity,
            .observation_receipt = observation_->observation_receipt,
            .observation_process = observation_->process_identity,
            .barrier = barrier_,
            .score_receipts = permit.receipt_.score_receipts,
            .capsule_seals = permit.receipt_.capsule_seals,
            .aggregate_child_exit = completion.receipt_.child_exit,
            .aggregate_process = completion.receipt_.process_identity,
            .aggregate_receipt = completion.receipt_.aggregate_receipt,
            .outer_parent_process =
                capture_.manifest_parent_process_identity,
            .outer_parent_executable =
                capture_.manifest_parent_executable_identity,
            .manifest_recomputation_receipt =
                capture_.manifest_recomputation_receipt,
            .outcome = completion.receipt_.outcome,
        };
        for (unsigned owner = 0; owner < 3; ++owner)
            result.score_processes[owner] = scores_[owner]->process_identity;
        std::array<Digest, 19> inputs{
            result.trial_capture_identity, result.observation_receipt,
            result.observation_process, result.barrier,
            result.score_receipts[0], result.score_receipts[1],
            result.score_receipts[2], result.capsule_seals[0],
            result.capsule_seals[1], result.capsule_seals[2],
            result.score_processes[0], result.score_processes[1],
            result.score_processes[2], result.aggregate_child_exit,
            result.aggregate_process, result.aggregate_receipt,
            result.outer_parent_process, result.outer_parent_executable,
            result.manifest_recomputation_receipt,
        };
        result.completion_identity = identity(
            "KPB_RUN_AGGREGATE_COMPLETION_V1\n", result.binding, inputs,
            static_cast<unsigned char>(result.outcome));
        state_ = State::Completed;
        return RunAggregateCompletionAuthority(std::move(result));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

ComparisonSelectionAuthority::ComparisonSelectionAuthority(
        PublicComparisonSelection receipt) : receipt_(std::move(receipt)) {
    valid(receipt_.finite_manifest);
    valid(receipt_.comparison_worker);
    need(receipt_.comparison_worker == worker_binding(entry(
        receipt_.finite_manifest, ManifestComponent::OwnerComparison)));
    for (const auto* digest : {
             &receipt_.comparison_selection, &receipt_.selection_identity,
             &receipt_.method, &receipt_.workload, &receipt_.source_closure,
             &receipt_.runtime, &receipt_.outer_parent_process,
             &receipt_.outer_parent_executable,
             &receipt_.manifest_recomputation_receipt,
             &receipt_.baseline_run,
             &receipt_.candidate_run})
        need(nonzero(*digest));
    need(receipt_.baseline_run != receipt_.candidate_run &&
         receipt_.manifest_recomputation_receipt ==
             receipt_.finite_manifest.parent_recomputation_identity);
}
ComparisonSelectionAuthority::ComparisonSelectionAuthority(
        ComparisonSelectionAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
ComparisonSelectionAuthority ComparisonSelectionAuthority::test_only_mint(
        PublicComparisonSelection receipt) {
    return ComparisonSelectionAuthority(std::move(receipt));
}
#endif

OwnerComparisonPermitAuthority::OwnerComparisonPermitAuthority(
        PublicOwnerComparisonPermit receipt) : receipt_(std::move(receipt)) {}
OwnerComparisonPermitAuthority::OwnerComparisonPermitAuthority(
        OwnerComparisonPermitAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
OwnerComparisonPermitAuthority
OwnerComparisonPermitAuthority::test_only_mint(
        PublicOwnerComparisonPermit receipt) {
    return OwnerComparisonPermitAuthority(std::move(receipt));
}
#endif

OwnerComparisonCompletionAuthority::OwnerComparisonCompletionAuthority(
        PublicOwnerComparisonCompletion receipt) : receipt_(std::move(receipt)) {
    valid(receipt_.worker);
    for (const auto* digest : {
             &receipt_.comparison_selection, &receipt_.permit_identity,
             &receipt_.baseline_aggregate, &receipt_.candidate_aggregate,
             &receipt_.child_exit, &receipt_.comparison_receipt,
             &receipt_.process_identity})
        need(nonzero(*digest));
    need(receipt_.baseline_aggregate != receipt_.candidate_aggregate &&
         (receipt_.outcome == OwnerComparisonOutcome::NonRegressionPass ||
          receipt_.outcome == OwnerComparisonOutcome::Fail ||
          receipt_.outcome == OwnerComparisonOutcome::Unqualified));
}
OwnerComparisonCompletionAuthority::OwnerComparisonCompletionAuthority(
        OwnerComparisonCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
#ifdef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
OwnerComparisonCompletionAuthority
OwnerComparisonCompletionAuthority::test_only_mint(
        PublicOwnerComparisonCompletion receipt) {
    return OwnerComparisonCompletionAuthority(std::move(receipt));
}
#endif

BatchPrivacyPassAuthority::BatchPrivacyPassAuthority(
        PublicBatchPrivacyPass receipt) : receipt_(std::move(receipt)) {}
BatchPrivacyPassAuthority::BatchPrivacyPassAuthority(
        BatchPrivacyPassAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}
BatchPrivacyPassAuthority
BatchPrivacyPassAuthority::transfer_for_pre_network_safety() && {
    need(live_.exchange(false));
    return BatchPrivacyPassAuthority(receipt_);
}
PublicBatchPrivacyPass
BatchPrivacyPassAuthority::consume_for_testnet_activation() {
    need(live_.exchange(false));
    return receipt_;
}

ComparisonMeasurement::ComparisonMeasurement(
        ComparisonSelectionAuthority&& selection,
        RunAggregateCompletionAuthority&& baseline,
        RunAggregateCompletionAuthority&& candidate) {
    try {
        const bool selection_live = selection.live_.exchange(false);
        const bool baseline_live = baseline.live_.exchange(false);
        const bool candidate_live = candidate.live_.exchange(false);
        need(selection_live && baseline_live && candidate_live);
        valid(baseline.receipt_.binding);
        valid(candidate.receipt_.binding);
        const auto& base = baseline.receipt_;
        const auto& test = candidate.receipt_;
        const auto& chosen = selection.receipt_;
        need(nonzero(base.completion_identity) &&
             nonzero(test.completion_identity) &&
             base.completion_identity != test.completion_identity &&
             base.binding.classification ==
                 Classification::TransparentBaseline &&
             test.binding.classification == Classification::HiddenCandidate &&
             base.outcome == AggregateOutcome::BaselineControlDetected &&
             test.outcome == AggregateOutcome::CandidatePass &&
             base.binding.comparison_selection == chosen.comparison_selection &&
             test.binding.comparison_selection == chosen.comparison_selection &&
             base.binding.run_selection == chosen.baseline_run &&
             test.binding.run_selection == chosen.candidate_run &&
             base.binding.method == chosen.method &&
             test.binding.method == chosen.method &&
             base.binding.workload == chosen.workload &&
             test.binding.workload == chosen.workload &&
             base.binding.source_closure == chosen.source_closure &&
             test.binding.source_closure == chosen.source_closure &&
             base.binding.runtime == chosen.runtime &&
             test.binding.runtime == chosen.runtime &&
             base.binding.finite_manifest == chosen.finite_manifest &&
             test.binding.finite_manifest == chosen.finite_manifest &&
             base.outer_parent_process == chosen.outer_parent_process &&
             test.outer_parent_process == chosen.outer_parent_process &&
             base.outer_parent_executable ==
                 chosen.outer_parent_executable &&
             test.outer_parent_executable ==
                 chosen.outer_parent_executable &&
             base.manifest_recomputation_receipt ==
                 chosen.manifest_recomputation_receipt &&
             test.manifest_recomputation_receipt ==
                 chosen.manifest_recomputation_receipt &&
             base.outer_parent_process ==
                 base.binding.outer_parent_process &&
             test.outer_parent_process ==
                 test.binding.outer_parent_process &&
             base.outer_parent_executable ==
                 base.binding.outer_parent_executable &&
             test.outer_parent_executable ==
                 test.binding.outer_parent_executable &&
             base.manifest_recomputation_receipt ==
                 base.binding.finite_manifest.parent_recomputation_identity &&
             test.manifest_recomputation_receipt ==
                 test.binding.finite_manifest.parent_recomputation_identity &&
             base.binding.capture_source == test.binding.capture_source &&
             base.binding.capture_build == test.binding.capture_build &&
             base.binding.capture_runtime == test.binding.capture_runtime &&
             base.binding.capture_launcher == test.binding.capture_launcher &&
             base.binding.observer_worker == test.binding.observer_worker &&
             base.binding.score_worker == test.binding.score_worker &&
             base.binding.aggregate_worker == test.binding.aggregate_worker &&
             base.binding.run_selection != test.binding.run_selection &&
             base.binding.trial != test.binding.trial &&
             base.binding.attempt != test.binding.attempt &&
             base.binding.cohort != test.binding.cohort &&
             base.binding.capture != test.binding.capture &&
             base.binding.financial_runs != test.binding.financial_runs &&
             base.binding.round_attempts != test.binding.round_attempts &&
             base.binding.round_cohorts != test.binding.round_cohorts &&
             base.binding.projections != test.binding.projections);
        selection_ = chosen;
        baseline_ = base;
        candidate_ = test;
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

OwnerComparisonPermitAuthority
ComparisonMeasurement::issue_owner_comparison() {
    std::lock_guard guard(mutex_);
    try {
        need(state_ == State::Ready);
        const std::array<Digest, 3> inputs{
            selection_.selection_identity,
            baseline_.completion_identity,
            candidate_.completion_identity,
        };
        PublicOwnerComparisonPermit permit{
            .selection = selection_,
            .baseline_aggregate = baseline_.completion_identity,
            .candidate_aggregate = candidate_.completion_identity,
            .permit_identity = identity(
                "KPB_OWNER_COMPARISON_PERMIT_V1\n", baseline_.binding,
                inputs),
        };
        permit_ = permit;
        state_ = State::OwnerComparisonIssued;
        return OwnerComparisonPermitAuthority(std::move(permit));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

BatchPrivacyPassAuthority ComparisonMeasurement::accept_owner_comparison(
        OwnerComparisonPermitAuthority&& permit,
        OwnerComparisonCompletionAuthority&& completion) {
    std::lock_guard guard(mutex_);
    try {
        const bool permit_live = permit.live_.exchange(false);
        const bool completion_live = completion.live_.exchange(false);
        need(permit_live && completion_live &&
             state_ == State::OwnerComparisonIssued && permit_.has_value() &&
             permit.receipt_.selection.comparison_selection ==
                 selection_.comparison_selection &&
             permit.receipt_.selection.selection_identity ==
                 selection_.selection_identity &&
             permit.receipt_.baseline_aggregate ==
                 baseline_.completion_identity &&
             permit.receipt_.candidate_aggregate ==
                 candidate_.completion_identity &&
             permit.receipt_.permit_identity == permit_->permit_identity &&
             completion.receipt_.comparison_selection ==
                 selection_.comparison_selection &&
             completion.receipt_.permit_identity ==
                 permit.receipt_.permit_identity &&
             completion.receipt_.baseline_aggregate ==
                 baseline_.completion_identity &&
             completion.receipt_.candidate_aggregate ==
                 candidate_.completion_identity &&
             completion.receipt_.worker == selection_.comparison_worker &&
             completion.receipt_.outcome ==
                 OwnerComparisonOutcome::NonRegressionPass);
        const std::array<Digest, 14> inputs{
            selection_.selection_identity,
            baseline_.completion_identity,
            candidate_.completion_identity,
            candidate_.binding.trial,
            candidate_.binding.projections[0],
            candidate_.binding.projections[1],
            permit.receipt_.permit_identity,
            completion.receipt_.child_exit,
            completion.receipt_.process_identity,
            completion.receipt_.comparison_receipt,
            selection_.finite_manifest.manifest_identity,
            selection_.outer_parent_process,
            selection_.outer_parent_executable,
            selection_.manifest_recomputation_receipt,
        };
        PublicBatchPrivacyPass result{
            .scope = PrivacyScope::BatchPaymentPreNetworkOnly,
            .selection = selection_,
            .comparison_selection = selection_.comparison_selection,
            .baseline_aggregate = baseline_.completion_identity,
            .candidate_aggregate = candidate_.completion_identity,
            .candidate_trial = candidate_.binding.trial,
            .candidate_projections = candidate_.binding.projections,
            .owner_comparison_child_exit = completion.receipt_.child_exit,
            .owner_comparison_process = completion.receipt_.process_identity,
            .owner_comparison_receipt =
                completion.receipt_.comparison_receipt,
            .finite_manifest_identity =
                selection_.finite_manifest.manifest_identity,
            .outer_parent_process = selection_.outer_parent_process,
            .outer_parent_executable = selection_.outer_parent_executable,
            .manifest_recomputation_receipt =
                selection_.manifest_recomputation_receipt,
            .pass_identity = identity(
                "KPB_BATCH_PRIVACY_PASS_PRENETWORK_V2\n", baseline_.binding,
                inputs),
        };
        state_ = State::Completed;
        return BatchPrivacyPassAuthority(std::move(result));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

} // namespace kpb::measurement
