#include "privacy_measurement_runtime_bridge.hpp"
#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_native_empirical_result_authority.hpp"
#include "privacy_native_phase_scope_authority.hpp"

#include <algorithm>
#include <openssl/sha.h>
#include <span>
#include <vector>

namespace kpb::measurement::runtime_bridge {
namespace {

using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}

void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest private_output_receipt(
        const char* domain, const Digest& retained,
        const PublicRuntimeChildCompletion& child) {
    Bytes bytes;
    text(bytes, domain);
    add(bytes, retained);
    add(bytes, child.process_identity);
    add(bytes, child.child_exit_identity);
    add(bytes, child.offer_identity);
    return hash(bytes);
}

void add_worker(Bytes& out, const WorkerBinding& worker) {
    for (const auto* value : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity,
             &worker.launcher_identity})
        add(out, *value);
}

void valid_worker(const WorkerBinding& worker) {
    for (const auto* value : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity,
             &worker.launcher_identity})
        need(nonzero(*value));
}

void valid(const PublicRuntimeChildCompletion& value) {
    const bool observer = value.role == RuntimeChildRole::Observer;
    const bool owner_score = value.role == RuntimeChildRole::OwnerScore;
    const bool aggregate = value.role == RuntimeChildRole::Aggregate;
    const bool comparison = value.role == RuntimeChildRole::OwnerComparison;
    need((observer || owner_score || aggregate || comparison) &&
         nonzero(value.permit_identity));
    valid_worker(value.worker);
    for (const auto* field : {
             &value.outer_parent_process,
             &value.outer_parent_executable,
             &value.transport_session, &value.offer_identity,
             &value.child_exit_identity,
             &value.opaque_completion_authority_identity,
             &value.process_identity})
        need(nonzero(*field));
    need(((observer && value.owner == NO_OWNER &&
           !nonzero(value.opaque_capsule_authority_identity)) ||
          (owner_score && value.owner < 3 &&
           nonzero(value.opaque_capsule_authority_identity)) ||
          (aggregate && value.owner == NO_OWNER &&
           !nonzero(value.opaque_capsule_authority_identity)) ||
          (comparison && value.owner == NO_OWNER &&
           !nonzero(value.opaque_capsule_authority_identity))) &&
         value.authenticated_pid > 1 &&
         value.authenticated_pid == value.waited_pid &&
         value.exit_code == 0 && value.term_signal == 0 &&
         value.credentials_verified && value.offer_acknowledged &&
         value.eof_observed &&
         ((aggregate &&
           (value.aggregate_outcome ==
                AggregateOutcome::BaselineControlDetected ||
            value.aggregate_outcome == AggregateOutcome::CandidatePass ||
            value.aggregate_outcome == AggregateOutcome::Fail ||
            value.aggregate_outcome == AggregateOutcome::Unqualified)) ||
          (!aggregate &&
           static_cast<unsigned char>(value.aggregate_outcome) == 0)) &&
         ((comparison &&
           (value.comparison_outcome ==
                OwnerComparisonOutcome::NonRegressionPass ||
            value.comparison_outcome == OwnerComparisonOutcome::Fail ||
            value.comparison_outcome ==
                OwnerComparisonOutcome::Unqualified)) ||
          (!comparison &&
           static_cast<unsigned char>(value.comparison_outcome) == 0)) &&
         value.process_identity == recompute_process_identity(value));
}

} // namespace

Digest recompute_process_identity(
        const PublicRuntimeChildCompletion& value) {
    Bytes bytes;
    text(bytes, "KPB_MEASUREMENT_RUNTIME_CHILD_COMPLETION_V1\n");
    bytes.push_back(static_cast<unsigned char>(value.role));
    integer(bytes, value.owner);
    add(bytes, value.permit_identity);
    add_worker(bytes, value.worker);
    for (const auto* field : {
             &value.outer_parent_process,
             &value.outer_parent_executable,
             &value.transport_session, &value.offer_identity,
             &value.child_exit_identity,
             &value.opaque_completion_authority_identity,
             &value.opaque_capsule_authority_identity})
        add(bytes, *field);
    integer(bytes, value.authenticated_pid);
    integer(bytes, value.waited_pid);
    integer(bytes, static_cast<std::uint64_t>(value.exit_code));
    integer(bytes, static_cast<std::uint64_t>(value.term_signal));
    bytes.push_back(value.credentials_verified ? 1 : 0);
    bytes.push_back(value.offer_acknowledged ? 1 : 0);
    bytes.push_back(value.eof_observed ? 1 : 0);
    bytes.push_back(static_cast<unsigned char>(value.aggregate_outcome));
    bytes.push_back(static_cast<unsigned char>(value.comparison_outcome));
    return hash(bytes);
}

ChildCompletionEvidenceAuthority::ChildCompletionEvidenceAuthority(
        PublicRuntimeChildCompletion receipt)
    : receipt_(std::move(receipt)) {
    valid(receipt_);
}

ChildCompletionEvidenceAuthority::ChildCompletionEvidenceAuthority(
        ChildCompletionEvidenceAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

ObservationRuntimeCompletion::ObservationRuntimeCompletion(
        ObserverExecutionPermitAuthority&& selected_permit,
        ObservationCompletionAuthority&& selected_completion)
    : permit(std::move(selected_permit)),
      completion(std::move(selected_completion)) {}

OwnerScoreRuntimeCompletion::OwnerScoreRuntimeCompletion(
        OwnerScoreExecutionPermitAuthority&& selected_permit,
        OwnerScoreCompletionAuthority&& selected_completion)
    : permit(std::move(selected_permit)),
      completion(std::move(selected_completion)) {}

AggregateRuntimeCompletion::AggregateRuntimeCompletion(
        AggregatePermitAuthority&& selected_permit,
        AggregateCompletionAuthority&& selected_completion)
    : permit(std::move(selected_permit)),
      completion(std::move(selected_completion)) {}

OwnerComparisonRuntimeCompletion::OwnerComparisonRuntimeCompletion(
        OwnerComparisonPermitAuthority&& selected_permit,
        OwnerComparisonCompletionAuthority&& selected_completion)
    : permit(std::move(selected_permit)),
      completion(std::move(selected_completion)) {}

ObservationRuntimeCompletion RuntimeCompletionBridge::observation(
        ObserverExecutionPermitAuthority&& supplied_permit,
        ChildCompletionEvidenceAuthority&& supplied_evidence,
        SealedChildOutputAuthority&& supplied_output,
        empirical_result::NativeEmpiricalResultAuthority&&
            supplied_empirical) {
    ObserverExecutionPermitAuthority permit(std::move(supplied_permit));
    ChildCompletionEvidenceAuthority evidence(std::move(supplied_evidence));
    SealedChildOutputAuthority sealed_output(std::move(supplied_output));
    empirical_result::NativeEmpiricalResultAuthority empirical(
        std::move(supplied_empirical));
    need(permit.live_.load() && evidence.live_.exchange(false));
    valid(evidence.receipt_);
    const auto& selected = permit.receipt_;
    const auto& child = evidence.receipt_;
    need(child.role == RuntimeChildRole::Observer &&
         child.owner == NO_OWNER &&
         child.permit_identity == selected.permit_identity &&
         child.worker == selected.binding.observer_worker &&
         child.outer_parent_process ==
             selected.binding.outer_parent_process &&
         child.outer_parent_executable ==
             selected.binding.outer_parent_executable);
    const auto& sealed = sealed_output.retained_completion();
    const auto* abi = measurement_output_abi(RuntimeChildRole::Observer);
    need(abi != nullptr && sealed.offer.binding == selected.binding &&
         sealed.offer.role == RuntimeChildRole::Observer &&
         sealed.offer.owner == NO_OWNER &&
         sealed.offer.permit_identity == selected.permit_identity &&
         sealed.offer.worker == selected.binding.observer_worker &&
         sealed.offer.transport_session == child.transport_session &&
         sealed.offer.output_abi_identity == abi->identity &&
         sealed.offer.exact_size == abi->exact_bytes &&
         sealed.process_identity == child.process_identity &&
         sealed.child_exit_identity == child.child_exit_identity &&
         sealed.authenticated_pid == child.authenticated_pid &&
         sealed.waited_pid == child.waited_pid &&
         sealed.exit_code == child.exit_code &&
         sealed.term_signal == child.term_signal &&
         sealed.credentials_verified == child.credentials_verified &&
         sealed.eof_observed == child.eof_observed);
    const auto output_receipt = private_output_receipt(
        "KPB_OBSERVER_SEALED_OUTPUT_RECEIPT_V1\n",
        sealed_output.retained_identity(), child);
    PublicObservationCompletion completion{
        .binding = selected.binding,
        .permit_identity = selected.permit_identity,
        .trial_capture_identity = selected.trial_capture_identity,
        .child_exit = child.child_exit_identity,
        .observation_receipt = output_receipt,
        .worker = child.worker,
        .process_identity = child.process_identity,
    };
    auto joined_output = std::make_unique<
        phase_scope::ObservationOutputJoinAuthority>(
            phase_scope::NativePrivacyPhaseScopeBridge::
                validate_for_observation(
                    std::move(sealed_output),
                    std::move(empirical)));
    return ObservationRuntimeCompletion(
        std::move(permit),
        ObservationCompletionAuthority(
            std::move(completion), std::move(joined_output)));
}

OwnerScoreRuntimeCompletion RuntimeCompletionBridge::owner_score(
        OwnerScoreExecutionPermitAuthority&& supplied_permit,
        ChildCompletionEvidenceAuthority&& supplied_evidence,
        SealedChildOutputAuthority&& supplied_output) {
    OwnerScoreExecutionPermitAuthority permit(std::move(supplied_permit));
    ChildCompletionEvidenceAuthority evidence(std::move(supplied_evidence));
    auto output = std::make_unique<SealedChildOutputAuthority>(
        std::move(supplied_output));
    need(permit.live_.load() && evidence.live_.exchange(false));
    valid(evidence.receipt_);
    const auto& selected = permit.receipt_;
    const auto& child = evidence.receipt_;
    need(child.role == RuntimeChildRole::OwnerScore &&
         child.owner == selected.owner &&
         child.permit_identity == selected.permit_identity &&
         child.worker == selected.binding.score_worker &&
         child.outer_parent_process ==
             selected.binding.outer_parent_process &&
         child.outer_parent_executable ==
             selected.binding.outer_parent_executable);
    const auto& sealed = output->retained_completion();
    const auto* abi = measurement_output_abi(RuntimeChildRole::OwnerScore);
    need(abi != nullptr && sealed.offer.binding == selected.binding &&
         sealed.offer.role == RuntimeChildRole::OwnerScore &&
         sealed.offer.owner == selected.owner &&
         sealed.offer.permit_identity == selected.permit_identity &&
         sealed.offer.worker == selected.binding.score_worker &&
         sealed.offer.transport_session == child.transport_session &&
         sealed.offer.output_abi_identity == abi->identity &&
         sealed.offer.exact_size == abi->exact_bytes &&
         sealed.process_identity == child.process_identity &&
         sealed.child_exit_identity == child.child_exit_identity &&
         sealed.authenticated_pid == child.authenticated_pid &&
         sealed.waited_pid == child.waited_pid &&
         sealed.exit_code == child.exit_code &&
         sealed.term_signal == child.term_signal &&
         sealed.credentials_verified == child.credentials_verified &&
         sealed.eof_observed == child.eof_observed);
    const auto score_receipt = private_output_receipt(
        "KPB_OWNER_SCORE_SEALED_OUTPUT_RECEIPT_V1\n",
        output->retained_identity(), child);
    const auto capsule_seal = private_output_receipt(
        "KPB_OWNER_SCORE_SEALED_CAPSULE_V1\n",
        output->retained_identity(), child);
    need(score_receipt != capsule_seal);
    PublicOwnerScoreCompletion completion{
        .binding = selected.binding,
        .owner = selected.owner,
        .permit_identity = selected.permit_identity,
        .barrier = selected.barrier,
        .child_exit = child.child_exit_identity,
        .score_receipt = score_receipt,
        .capsule_seal = capsule_seal,
        .worker = child.worker,
        .process_identity = child.process_identity,
    };
    return OwnerScoreRuntimeCompletion(
        std::move(permit),
        OwnerScoreCompletionAuthority(
            std::move(completion), std::move(output)));
}

AggregateRuntimeCompletion RuntimeCompletionBridge::aggregate(
        AggregatePermitAuthority&& supplied_permit,
        ChildCompletionEvidenceAuthority&& supplied_evidence) {
    AggregatePermitAuthority permit(std::move(supplied_permit));
    ChildCompletionEvidenceAuthority evidence(std::move(supplied_evidence));
    need(permit.live_.load() && evidence.live_.exchange(false));
    valid(evidence.receipt_);
    const auto& selected = permit.receipt_;
    const auto& child = evidence.receipt_;
    need(child.role == RuntimeChildRole::Aggregate &&
         child.owner == NO_OWNER &&
         child.permit_identity == selected.permit_identity &&
         child.worker == selected.binding.aggregate_worker &&
         child.outer_parent_process ==
             selected.binding.outer_parent_process &&
         child.outer_parent_executable ==
             selected.binding.outer_parent_executable);
    PublicAggregateCompletion completion{
        .binding = selected.binding,
        .permit_identity = selected.permit_identity,
        .barrier = selected.barrier,
        .child_exit = child.child_exit_identity,
        .aggregate_receipt = child.opaque_completion_authority_identity,
        .outcome = child.aggregate_outcome,
        .worker = child.worker,
        .process_identity = child.process_identity,
    };
    return AggregateRuntimeCompletion(
        std::move(permit),
        AggregateCompletionAuthority(std::move(completion)));
}

OwnerComparisonRuntimeCompletion
RuntimeCompletionBridge::owner_comparison(
        OwnerComparisonPermitAuthority&& supplied_permit,
        ChildCompletionEvidenceAuthority&& supplied_evidence) {
    OwnerComparisonPermitAuthority permit(std::move(supplied_permit));
    ChildCompletionEvidenceAuthority evidence(std::move(supplied_evidence));
    need(permit.live_.load() && evidence.live_.exchange(false));
    valid(evidence.receipt_);
    const auto& selected = permit.receipt_;
    const auto& child = evidence.receipt_;
    need(child.role == RuntimeChildRole::OwnerComparison &&
         child.owner == NO_OWNER &&
         child.permit_identity == selected.permit_identity &&
         child.worker == selected.selection.comparison_worker &&
         child.outer_parent_process ==
             selected.selection.outer_parent_process &&
         child.outer_parent_executable ==
             selected.selection.outer_parent_executable);
    PublicOwnerComparisonCompletion completion{
        .comparison_selection = selected.selection.comparison_selection,
        .permit_identity = selected.permit_identity,
        .baseline_aggregate = selected.baseline_aggregate,
        .candidate_aggregate = selected.candidate_aggregate,
        .child_exit = child.child_exit_identity,
        .comparison_receipt =
            child.opaque_completion_authority_identity,
        .outcome = child.comparison_outcome,
        .worker = child.worker,
        .process_identity = child.process_identity,
    };
    return OwnerComparisonRuntimeCompletion(
        std::move(permit),
        OwnerComparisonCompletionAuthority(std::move(completion)));
}

#ifdef KPB_MEASUREMENT_RUNTIME_BRIDGE_TEST_SETUP
ChildCompletionEvidenceAuthority
ChildCompletionEvidenceAuthority::test_only_mint(
        PublicRuntimeChildCompletion receipt) {
    return ChildCompletionEvidenceAuthority(std::move(receipt));
}

void RuntimeCompletionBridge::test_only_consume(
        ChildCompletionEvidenceAuthority&& authority) {
    need(authority.live_.exchange(false));
    valid(authority.receipt_);
}
#endif

} // namespace kpb::measurement::runtime_bridge
