#include "c1_registered_plan_route_bridge.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>
#include <unistd.h>

namespace kpb::measurement::c1_capture {
namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::string_view REGISTERED_TRIAL_DOMAIN =
    "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n";
constexpr std::string_view ATTEMPT_DOMAIN =
    "KPB_CAPTURE_ATTEMPT_ID_V1\n";
constexpr std::string_view CAPTURE_DOMAIN =
    "KPB_CAPTURE_IDENTITY_V1\n";
constexpr std::string_view SELECTION_DOMAIN =
    "KPB_C1_ACCEPTED_CONTROLLER_SELECTION_V1\n";
constexpr std::string_view ROUTE_SOURCE_DOMAIN =
    "KPB_C1_REGISTERED_ROUTE_SOURCE_V1\n";
constexpr std::string_view STAGE_PLAN_DOMAIN =
    "KPB_C1_CONTACT_VALUE_STAGE_PLAN_V1\n";
constexpr std::string_view ROUTE_DOMAIN =
    "KPB_C1_AUTHENTICATED_INVOICE_ROUTE_V1\n";
constexpr std::string_view OBSERVED_ROUTE_ARTIFACT_DOMAIN =
    "KPB_C1_OBSERVED_INVOICE_ROUTE_ARTIFACT_V1\n";
constexpr std::string_view TERMINAL_HISTORY_DOMAIN =
    "KPB_C1_CONTROLLER_TERMINAL_HISTORY_V1\n";

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

bool uuid4(std::string_view value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) == std::string_view::npos)
        return false;
    for (unsigned index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            continue;
        const char byte = value[index];
        if (!((byte >= '0' && byte <= '9') ||
              (byte >= 'a' && byte <= 'f')))
            return false;
    }
    return true;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const Digest& value) { add(out, std::span(value)); }
void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add_u64(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_worker(Bytes& out, const WorkerBinding& value) {
    add(out, value.source_identity);
    add(out, value.build_identity);
    add(out, value.runtime_identity);
    add(out, value.assets_identity);
    add(out, value.pinned_executable_identity);
    add(out, value.launcher_identity);
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

Digest offer_file_hash(int fd) {
    std::array<unsigned char, C1_CONTACT_VALUE_OFFER_BYTES> bytes{};
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::pread(
            fd, bytes.data() + at, bytes.size() - at,
            static_cast<off_t>(at));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    unsigned char extra{};
    need(::pread(fd, &extra, 1, static_cast<off_t>(bytes.size())) == 0);
    return hash(bytes);
}

Digest domain_hash(std::string_view domain, std::string_view value) {
    Bytes bytes(domain.begin(), domain.end());
    add(bytes, value);
    return hash(bytes);
}

Digest registered_trial_identity(std::string_view value) {
    Bytes bytes(REGISTERED_TRIAL_DOMAIN.begin(),
                REGISTERED_TRIAL_DOMAIN.end());
    add_u64(bytes, value.size());
    add(bytes, value);
    return hash(bytes);
}

const ManifestEntry& manifest_entry(
        const FiniteManifestBinding& manifest,
        ManifestComponent component) {
    const auto index = static_cast<unsigned>(component) - 1;
    need(index < manifest.entries.size() &&
         manifest.entries[index].component == component);
    return manifest.entries[index];
}

WorkerBinding worker(const ManifestEntry& value) {
    return {
        .source_identity = value.source_identity,
        .build_identity = value.build_identity,
        .runtime_identity = value.runtime_identity,
        .assets_identity = value.assets_identity,
        .pinned_executable_identity = value.pinned_executable_identity,
        .launcher_identity = value.launcher_identity,
    };
}

void require_worker(const WorkerBinding& value) {
    for (const auto* field : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity, &value.launcher_identity})
        need(nonzero(*field));
}

void require_lineage(const PublicRegisteredC1RoundLineage& value) {
    need((value.round == 1 || value.round == 2) &&
         uuid4(value.capture_trial_id) &&
         uuid4(value.capture_attempt_id) &&
         value.capture_trial_id != value.capture_attempt_id &&
         value.trial == registered_trial_identity(value.capture_trial_id) &&
         value.round_attempt == domain_hash(
             ATTEMPT_DOMAIN, value.capture_attempt_id) &&
         value.finite_manifest.manifest_identity == value.manifest_seal &&
         recompute_finite_manifest_identity(
             value.finite_manifest.entries) ==
                 value.finite_manifest.manifest_identity &&
         value.producer_process_identity == value.outer_parent_process);
    for (const auto* field : {
             &value.registered_prelaunch_identity,
             &value.comparison_selection, &value.run_selection,
             &value.trial, &value.measurement_attempt,
             &value.measurement_cohort, &value.capture, &value.method,
             &value.workload, &value.source_closure, &value.runtime,
             &value.finite_manifest.manifest_identity,
             &value.finite_manifest.parent_recomputation_identity,
             &value.outer_parent_process, &value.outer_parent_executable,
             &value.capture_source, &value.capture_build,
             &value.capture_runtime, &value.capture_launcher,
             &value.financial_run, &value.round_attempt,
             &value.round_cohort, &value.round_capture_plan,
             &value.process_reservation_identity,
             &value.persistent_process_session_identity,
             &value.fork_plan_identity, &value.route_capability_identity,
             &value.producer_process_identity, &value.role_closure_identity,
             &value.manifest_seal,
             &value.construction_classification_receipt,
             &value.c1_process_identity,
             &value.c1_expected_exit_policy_identity})
        need(nonzero(*field));
    require_worker(value.observer_worker);
    require_worker(value.score_worker);
    require_worker(value.aggregate_worker);
    const auto p1 = worker(manifest_entry(
        value.finite_manifest, ManifestComponent::P1Capture));
    const bool hidden =
        value.classification == Classification::HiddenCandidate &&
        value.construction_policy ==
            ConstructionPolicy::SecretPermutationIndependent;
    const bool baseline =
        value.classification == Classification::TransparentBaseline &&
        value.construction_policy ==
            ConstructionPolicy::ExplicitOwnerPublicEffects;
    need(hidden != baseline &&
         value.capture_source == p1.source_identity &&
         value.capture_build == p1.build_identity &&
         value.capture_runtime == p1.runtime_identity &&
         value.capture_launcher == p1.launcher_identity);
}

void require_operations(const std::array<std::string, 3>& operations) {
    for (const auto& value : operations) need(uuid4(value));
    need(operations[0] != operations[1] &&
         operations[0] != operations[2] &&
         operations[1] != operations[2]);
}

std::array<unsigned, 3> expected_contacts(unsigned round) {
    need(round == 1 || round == 2);
    return round == 1 ? std::array<unsigned, 3>{0, 2, 0}
                      : std::array<unsigned, 3>{2, 0, 2};
}

Digest selection_identity(
        const PublicC1AcceptedControllerSelection& value) {
    Bytes bytes(SELECTION_DOMAIN.begin(), SELECTION_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(value.round));
    add(bytes, value.capture_trial_id);
    add(bytes, value.capture_attempt_id);
    add(bytes, value.capture_identity);
    add(bytes, value.registered_prelaunch_identity);
    add(bytes, value.round_capture_plan_identity);
    add_worker(bytes, value.generator_worker);
    add(bytes, value.accepted_selection_history_identity);
    for (unsigned index = 0; index < value.operation_ids.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        add(bytes, value.operation_ids[index]);
        bytes.push_back(static_cast<unsigned char>(
            value.contact_owner_components[index]));
        add(bytes, value.accepted_stage_selection_identities[index]);
    }
    return hash(bytes);
}

void require_selection(const PublicC1AcceptedControllerSelection& value) {
    need((value.round == 1 || value.round == 2) &&
         uuid4(value.capture_trial_id) &&
         uuid4(value.capture_attempt_id) &&
         uuid4(value.capture_identity) &&
         value.capture_trial_id != value.capture_attempt_id &&
         value.capture_trial_id != value.capture_identity &&
         value.capture_attempt_id != value.capture_identity &&
         value.contact_owner_components == expected_contacts(value.round));
    require_operations(value.operation_ids);
    for (const auto* field : {
             &value.registered_prelaunch_identity,
             &value.round_capture_plan_identity,
             &value.accepted_stage_selection_identities[0],
             &value.accepted_stage_selection_identities[1],
             &value.accepted_stage_selection_identities[2],
             &value.accepted_selection_history_identity})
        need(nonzero(*field));
    require_worker(value.generator_worker);
    need(value.accepted_stage_selection_identities[0] !=
             value.accepted_stage_selection_identities[1] &&
         value.accepted_stage_selection_identities[0] !=
             value.accepted_stage_selection_identities[2] &&
         value.accepted_stage_selection_identities[1] !=
             value.accepted_stage_selection_identities[2]);
}

Digest stage_plan_identity(
        unsigned round, const std::array<std::string, 3>& operations) {
    Bytes bytes(STAGE_PLAN_DOMAIN.begin(), STAGE_PLAN_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(1);
    for (unsigned index = 0; index < operations.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        bytes.push_back(static_cast<unsigned char>(index + 1));
        add(bytes, operations[index]);
        bytes.push_back(index == 1 ? 1 : 0);
        if (index == 1)
            add(bytes, operations[0]);
        else
            bytes.insert(bytes.end(), 36, 0);
    }
    return hash(bytes);
}

Digest route_source_identity(
        const PublicRegisteredC1RoundLineage& lineage,
        const PublicC1AcceptedControllerSelection& selection,
        const Digest& accepted_selection_identity) {
    Bytes bytes(ROUTE_SOURCE_DOMAIN.begin(), ROUTE_SOURCE_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(lineage.round));
    add(bytes, lineage.registered_prelaunch_identity);
    add(bytes, lineage.round_capture_plan);
    add(bytes, accepted_selection_identity);
    add(bytes, lineage.trial);
    add(bytes, lineage.measurement_attempt);
    add(bytes, lineage.measurement_cohort);
    add(bytes, lineage.capture);
    add(bytes, lineage.method);
    add(bytes, lineage.workload);
    add(bytes, lineage.source_closure);
    add(bytes, lineage.financial_run);
    add(bytes, lineage.round_attempt);
    add(bytes, lineage.round_cohort);
    add(bytes, lineage.fork_plan_identity);
    add(bytes, lineage.route_capability_identity);
    add(bytes, lineage.c1_process_identity);
    add(bytes, lineage.c1_expected_exit_policy_identity);
    add_worker(bytes, selection.generator_worker);
    add(bytes, selection.accepted_selection_history_identity);
    add_worker(bytes, worker(manifest_entry(
        lineage.finite_manifest, ManifestComponent::P1Capture)));
    add_worker(bytes, worker(manifest_entry(
        lineage.finite_manifest, ManifestComponent::C1Supervisor)));
    for (unsigned index = 0; index < selection.operation_ids.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        add(bytes, selection.operation_ids[index]);
        bytes.push_back(static_cast<unsigned char>(
            selection.contact_owner_components[index]));
        add(bytes, selection.accepted_stage_selection_identities[index]);
    }
    return hash(bytes);
}

Digest route_identity(
        unsigned round, const std::array<unsigned, 3>& contacts,
        const std::array<std::string, 3>& operations,
        const Digest& route_source) {
    Bytes bytes(ROUTE_DOMAIN.begin(), ROUTE_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(1);
    add(bytes, route_source);
    for (unsigned index = 0; index < operations.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        bytes.push_back(static_cast<unsigned char>(contacts[index]));
        add(bytes, operations[index]);
        bytes.push_back(index == 1 ? 1 : 0);
        if (index == 1)
            add(bytes, operations[0]);
        else
            bytes.insert(bytes.end(), 36, 0);
    }
    return hash(bytes);
}

void require_parent_matches(
        const producer_runtime::PublicProducerLaunchPlan& parent,
        const PublicRegisteredC1RoundLineage& lineage,
        const PublicC1AcceptedControllerSelection& selection) {
    validate_measurement_run_binding(parent.binding);
    const auto index = lineage.round - 1;
    need(selection.round == lineage.round &&
         selection.capture_trial_id == lineage.capture_trial_id &&
         selection.capture_attempt_id == lineage.capture_attempt_id &&
         registered_trial_identity(selection.capture_trial_id) ==
             lineage.trial &&
         domain_hash(ATTEMPT_DOMAIN, selection.capture_attempt_id) ==
             lineage.round_attempt &&
         domain_hash(CAPTURE_DOMAIN, selection.capture_identity) ==
             lineage.capture &&
         selection.registered_prelaunch_identity ==
             lineage.registered_prelaunch_identity &&
         selection.round_capture_plan_identity ==
             lineage.round_capture_plan &&
         parent.binding.classification == lineage.classification &&
         parent.binding.comparison_selection ==
             lineage.comparison_selection &&
         parent.binding.run_selection == lineage.run_selection &&
         parent.binding.trial == lineage.trial &&
         parent.binding.attempt == lineage.measurement_attempt &&
         parent.binding.cohort == lineage.measurement_cohort &&
         parent.binding.capture == lineage.capture &&
         parent.binding.method == lineage.method &&
         parent.binding.workload == lineage.workload &&
         parent.binding.source_closure == lineage.source_closure &&
         parent.binding.runtime == lineage.runtime &&
         parent.binding.finite_manifest == lineage.finite_manifest &&
         parent.binding.outer_parent_process ==
             lineage.outer_parent_process &&
         parent.binding.outer_parent_executable ==
             lineage.outer_parent_executable &&
         parent.binding.capture_source == lineage.capture_source &&
         parent.binding.capture_build == lineage.capture_build &&
         parent.binding.capture_runtime == lineage.capture_runtime &&
         parent.binding.capture_launcher == lineage.capture_launcher &&
         parent.binding.observer_worker == lineage.observer_worker &&
         parent.binding.score_worker == lineage.score_worker &&
         parent.binding.aggregate_worker == lineage.aggregate_worker &&
         parent.binding.financial_runs[index] == lineage.financial_run &&
         parent.binding.round_attempts[index] == lineage.round_attempt &&
         parent.binding.round_cohorts[index] == lineage.round_cohort &&
         parent.binding.round_capture_plans[index] ==
             lineage.round_capture_plan &&
         parent.capture_trial_id == lineage.capture_trial_id &&
         parent.capture_attempt_ids[index] == lineage.capture_attempt_id &&
         parent.producer_process_identity ==
             lineage.producer_process_identity &&
         parent.role_closure_identity == lineage.role_closure_identity &&
         parent.manifest_seal == lineage.manifest_seal &&
         parent.construction_policy == lineage.construction_policy &&
         parent.construction_classification_receipt ==
             lineage.construction_classification_receipt);
    const auto c1 = worker(manifest_entry(
        lineage.finite_manifest, ManifestComponent::C1Supervisor));
    const auto observer = worker(manifest_entry(
        lineage.finite_manifest, ManifestComponent::Observer));
    need(selection.generator_worker == c1 &&
         lineage.observer_worker == observer &&
         selection.generator_worker != lineage.observer_worker);
    const auto stream_index = index * 5 + 4;
    const auto& stream = parent.streams[stream_index];
    need(stream.round == lineage.round &&
         stream.kind == CaptureKind::ColluderWallet &&
         stream.fixed_fd == (lineage.round == 1 ? 24U : 29U) &&
         stream.process_identity == lineage.c1_process_identity &&
         stream.child_exit_identity ==
             lineage.c1_expected_exit_policy_identity);
}

bool same_raw_selection(
        const PublicC1AcceptedControllerSelection& selection,
        const PublicC1AcceptedControllerResult& result) {
    return result.round == selection.round &&
        result.capture_trial_id == selection.capture_trial_id &&
        result.capture_attempt_id == selection.capture_attempt_id &&
        result.capture_identity == selection.capture_identity &&
        result.operation_ids == selection.operation_ids &&
        result.registered_prelaunch_identity ==
            selection.registered_prelaunch_identity &&
        result.round_capture_plan_identity ==
            selection.round_capture_plan_identity &&
        result.generator_worker == selection.generator_worker;
}

Digest terminal_history_identity(
        const PublicC1AcceptedControllerResult& result) {
    Bytes bytes(TERMINAL_HISTORY_DOMAIN.begin(),
                TERMINAL_HISTORY_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(result.round));
    add(bytes, result.accepted_selection_identity);
    add(bytes, result.fd31_authenticated_completion_identity);
    add(bytes, result.retry_history_identity);
    for (const auto& identity : result.controller_result_identities)
        add(bytes, identity);
    add_u64(bytes, result.completed_stage_count);
    add_u64(bytes, result.retry_count);
    return hash(bytes);
}

bool same_raw_route(
        const PublicC1AcceptedControllerSelection& selection,
        const PublicC1ObservedInvoiceRoute& route) {
    return route.round == selection.round &&
        route.capture_trial_id == selection.capture_trial_id &&
        route.capture_attempt_id == selection.capture_attempt_id &&
        route.capture_identity == selection.capture_identity &&
        route.operation_ids == selection.operation_ids &&
        route.contact_owner_components ==
            selection.contact_owner_components &&
        route.registered_prelaunch_identity ==
            selection.registered_prelaunch_identity &&
        route.round_capture_plan_identity ==
            selection.round_capture_plan_identity;
}

bool same_raw_ack(
        const PublicC1AcceptedControllerSelection& selection,
        const PublicC1Fd31QualifiedCompletionAck& ack) {
    return ack.round == selection.round &&
        ack.capture_trial_id == selection.capture_trial_id &&
        ack.capture_attempt_id == selection.capture_attempt_id &&
        ack.capture_identity == selection.capture_identity &&
        ack.operation_ids == selection.operation_ids &&
        ack.contact_owner_components == selection.contact_owner_components &&
        ack.registered_prelaunch_identity ==
            selection.registered_prelaunch_identity &&
        ack.round_capture_plan_identity ==
            selection.round_capture_plan_identity;
}

void require_distinct_ack_identities(
        const PublicC1Fd31QualifiedCompletionAck& ack) {
    const std::array<const Digest*, 5> identities{
        &ack.exact_offer_parse_identity,
        &ack.authenticated_completion_identity,
        &ack.writer_close_identity,
        &ack.eof_identity,
        &ack.exit_join_identity,
    };
    for (unsigned left = 0; left < identities.size(); ++left) {
        need(nonzero(*identities[left]));
        for (unsigned right = left + 1; right < identities.size(); ++right)
            need(*identities[left] != *identities[right]);
    }
}

void require_ack(
        const PublicC1AcceptedControllerSelection& selection,
        const PublicC1Fd31QualifiedCompletionAck& ack) {
    need(same_raw_ack(selection, ack) &&
         ack.offer_byte_count == C1_CONTACT_VALUE_OFFER_BYTES &&
         ack.fixed_fd == C1_CONTACT_VALUE_OFFER_FIXED_FD &&
         ack.supervisor_worker == selection.generator_worker &&
         ack.exact_fd31_read && ack.fallback_offer_absent &&
         ack.authenticated_completion && ack.writer_closed &&
         ack.eof_observed && ack.expected_exit_observed &&
         ack.offer_parse_monotonic_ns > 0 &&
         ack.offer_parse_monotonic_ns <
             ack.completion_ack_monotonic_ns &&
         ack.completion_ack_monotonic_ns <
             ack.writer_close_monotonic_ns &&
         ack.writer_close_monotonic_ns < ack.eof_monotonic_ns &&
         ack.eof_monotonic_ns < ack.exit_join_monotonic_ns);
    require_worker(ack.supervisor_worker);
    require_distinct_ack_identities(ack);
}

Digest route_artifact_identity(
        unsigned round, const PublicC1ObservedRouteArtifact& value) {
    Bytes bytes(OBSERVED_ROUTE_ARTIFACT_DOMAIN.begin(),
                OBSERVED_ROUTE_ARTIFACT_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(static_cast<unsigned char>(value.source_owner_component));
    bytes.push_back(static_cast<unsigned char>(value.target_owner_component));
    add_u64(bytes, value.source_operation_id.size());
    add(bytes, value.source_operation_id);
    add_u64(bytes, value.target_invoice_operation_id.size());
    add(bytes, value.target_invoice_operation_id);
    add(bytes, value.raw_bytes_sha256);
    add_u64(bytes, value.device);
    add_u64(bytes, value.inode);
    add_u64(bytes, value.byte_count);
    return hash(bytes);
}

void require_route_artifacts(
        const PublicC1AcceptedControllerSelection& selection,
        const PublicC1ObservedInvoiceRoute& route) {
    for (unsigned index = 0; index < route.route_artifacts.size(); ++index) {
        const auto& artifact = route.route_artifacts[index];
        need(artifact.source_owner_component == index &&
             artifact.target_owner_component ==
                 (index + selection.round) % 3 &&
             artifact.source_operation_id == selection.operation_ids[1] &&
             artifact.target_invoice_operation_id ==
                 selection.operation_ids[0] &&
             nonzero(artifact.raw_bytes_sha256) &&
             artifact.device > 0 && artifact.inode > 0 &&
             artifact.byte_count > 0 &&
             artifact.record_identity ==
                 route_artifact_identity(selection.round, artifact));
    }
    for (unsigned left = 0; left < route.route_artifacts.size(); ++left) {
        for (unsigned right = left + 1;
             right < route.route_artifacts.size(); ++right) {
            const auto& a = route.route_artifacts[left];
            const auto& b = route.route_artifacts[right];
            need(a.record_identity != b.record_identity &&
                 a.raw_bytes_sha256 != b.raw_bytes_sha256 &&
                 (a.device != b.device || a.inode != b.inode));
        }
    }
}

} // namespace

RegisteredC1RoundLineageAuthority::RegisteredC1RoundLineageAuthority(
        PublicRegisteredC1RoundLineage value) : value_(std::move(value)) {
    require_lineage(value_);
}

RegisteredC1RoundLineageAuthority::RegisteredC1RoundLineageAuthority(
        RegisteredC1RoundLineageAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
RegisteredC1RoundLineageAuthority
RegisteredC1RoundLineageAuthority::test_only_mint(
        PublicRegisteredC1RoundLineage value) {
    return RegisteredC1RoundLineageAuthority(std::move(value));
}
#endif

C1AcceptedControllerSelectionAuthority::
C1AcceptedControllerSelectionAuthority(
        PublicC1AcceptedControllerSelection value)
    : value_(std::move(value)) {
    require_selection(value_);
    identity_ = selection_identity(value_);
}

C1AcceptedControllerSelectionAuthority::
C1AcceptedControllerSelectionAuthority(
        C1AcceptedControllerSelectionAuthority&& other) noexcept
    : value_(std::move(other.value_)), identity_(other.identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
C1AcceptedControllerSelectionAuthority
C1AcceptedControllerSelectionAuthority::test_only_mint(
        PublicC1AcceptedControllerSelection value) {
    return C1AcceptedControllerSelectionAuthority(std::move(value));
}
#endif

C1Fd31QualifiedCompletionAckAuthority::
C1Fd31QualifiedCompletionAckAuthority(
        PublicC1Fd31QualifiedCompletionAck value)
    : value_(std::move(value)) {
    need((value_.round == 1 || value_.round == 2) &&
         uuid4(value_.capture_trial_id) &&
         uuid4(value_.capture_attempt_id) &&
         uuid4(value_.capture_identity));
    require_operations(value_.operation_ids);
}

C1Fd31QualifiedCompletionAckAuthority::
C1Fd31QualifiedCompletionAckAuthority(
        C1Fd31QualifiedCompletionAckAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
C1Fd31QualifiedCompletionAckAuthority
C1Fd31QualifiedCompletionAckAuthority::test_only_mint(
        PublicC1Fd31QualifiedCompletionAck value) {
    return C1Fd31QualifiedCompletionAckAuthority(std::move(value));
}
#endif

RegisteredC1PendingTerminalAuthority::
RegisteredC1PendingTerminalAuthority(
        C1PostcaptureAdmissionAuthority&& residual,
        PublicC1AcceptedControllerSelection selection,
        Digest selection_identity, Digest projection,
        WorkerBinding validator_worker,
        Digest contact_value_authority_identity,
        Digest offer_file_sha256, std::uint64_t offer_device,
        std::uint64_t offer_inode, Digest c1_process_identity,
        Digest c1_exit_policy_identity)
    : residual_(std::move(residual)), selection_(std::move(selection)),
      selection_identity_(selection_identity),
      expected_projection_identity_(projection),
      expected_validator_worker_(validator_worker),
      expected_contact_value_authority_identity_(
          contact_value_authority_identity),
      expected_offer_file_sha256_(offer_file_sha256),
      expected_offer_device_(offer_device),
      expected_offer_inode_(offer_inode),
      expected_c1_process_identity_(c1_process_identity),
      expected_c1_exit_policy_identity_(c1_exit_policy_identity) {
    need(residual_.has_value() && nonzero(selection_identity_) &&
         nonzero(expected_projection_identity_) &&
         nonzero(expected_contact_value_authority_identity_) &&
         nonzero(expected_offer_file_sha256_) &&
         expected_offer_device_ > 0 && expected_offer_inode_ > 0 &&
         nonzero(expected_c1_process_identity_) &&
         nonzero(expected_c1_exit_policy_identity_));
    require_worker(expected_validator_worker_);
    need(selection_.generator_worker != expected_validator_worker_);
}

RegisteredC1PendingTerminalAuthority::
RegisteredC1PendingTerminalAuthority(
        RegisteredC1PendingTerminalAuthority&& other) noexcept
    : residual_(std::move(other.residual_)),
      selection_(std::move(other.selection_)),
      selection_identity_(other.selection_identity_),
      expected_projection_identity_(other.expected_projection_identity_),
      expected_validator_worker_(other.expected_validator_worker_),
      expected_contact_value_authority_identity_(
          other.expected_contact_value_authority_identity_),
      expected_offer_file_sha256_(other.expected_offer_file_sha256_),
      expected_offer_device_(other.expected_offer_device_),
      expected_offer_inode_(other.expected_offer_inode_),
      expected_c1_process_identity_(other.expected_c1_process_identity_),
      expected_c1_exit_policy_identity_(
          other.expected_c1_exit_policy_identity_),
      live_(other.live_.exchange(false)) {}

RegisteredC1LaunchSplit::RegisteredC1LaunchSplit(
        C1ContactValueOfferAuthority&& offer,
        RegisteredC1PendingTerminalAuthority&& pending)
    : offer_(std::move(offer)), pending_(std::move(pending)) {}

C1ContactValueOfferAuthority RegisteredC1LaunchSplit::take_offer() {
    need(offer_.has_value());
    C1ContactValueOfferAuthority result(std::move(*offer_));
    offer_.reset();
    return result;
}

RegisteredC1PendingTerminalAuthority
RegisteredC1LaunchSplit::take_pending_terminal() {
    need(pending_.has_value());
    RegisteredC1PendingTerminalAuthority result(std::move(*pending_));
    pending_.reset();
    return result;
}

C1AcceptedControllerResultAuthority::C1AcceptedControllerResultAuthority(
        PublicC1AcceptedControllerResult value) : value_(std::move(value)) {
    need((value_.round == 1 || value_.round == 2) &&
         uuid4(value_.capture_trial_id) &&
         uuid4(value_.capture_attempt_id) &&
         uuid4(value_.capture_identity));
    require_operations(value_.operation_ids);
}

C1AcceptedControllerResultAuthority::C1AcceptedControllerResultAuthority(
        C1AcceptedControllerResultAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
C1AcceptedControllerResultAuthority
C1AcceptedControllerResultAuthority::test_only_mint(
        PublicC1AcceptedControllerResult value) {
    return C1AcceptedControllerResultAuthority(std::move(value));
}
#endif

C1ObservedInvoiceRouteAuthority::C1ObservedInvoiceRouteAuthority(
        PublicC1ObservedInvoiceRoute value) : value_(std::move(value)) {
    need((value_.round == 1 || value_.round == 2) &&
         uuid4(value_.capture_trial_id) &&
         uuid4(value_.capture_attempt_id) &&
         uuid4(value_.capture_identity));
    require_operations(value_.operation_ids);
}

C1ObservedInvoiceRouteAuthority::C1ObservedInvoiceRouteAuthority(
        C1ObservedInvoiceRouteAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
C1ObservedInvoiceRouteAuthority
C1ObservedInvoiceRouteAuthority::test_only_mint(
        PublicC1ObservedInvoiceRoute value) {
    return C1ObservedInvoiceRouteAuthority(std::move(value));
}
#endif

RegisteredC1LaunchSplit RegisteredC1PlanRouteBridge::prepare(
        producer_runtime::ParentTenReadEndsAuthority& parent,
        RegisteredC1RoundLineageAuthority&& supplied_lineage,
        C1AcceptedControllerSelectionAuthority&& supplied_selection) {
    RegisteredC1RoundLineageAuthority lineage(
        std::move(supplied_lineage));
    C1AcceptedControllerSelectionAuthority selection(
        std::move(supplied_selection));
    try {
        need(lineage.live_.exchange(false));
        const auto round = lineage.value_.round;
        need((round == 1 || round == 2) && parent.live_.load());
        const auto index = round - 1;
        // Burn the topology round before inspecting the controller source.
        // A bad/stale/substituted selection therefore cannot probe and retry.
        need(!parent.c1_contact_value_prepared_[index].exchange(true));
        need(selection.live_.exchange(false));
        require_lineage(lineage.value_);
        require_selection(selection.value_);
        require_parent_matches(
            parent.plan_, lineage.value_, selection.value_);

        const auto stage_identity = stage_plan_identity(
            round, selection.value_.operation_ids);
        const auto route_source = route_source_identity(
            lineage.value_, selection.value_, selection.identity_);
        const auto selected_route_identity = route_identity(
            round, selection.value_.contact_owner_components,
            selection.value_.operation_ids, route_source);
        C1LifecycleStagePlanAuthority stage(
            PublicC1LifecycleStagePlan{
                .binding = parent.plan_.binding,
                .round = round,
                .capture_attempt_id =
                    selection.value_.capture_attempt_id,
                .capture_identity = selection.value_.capture_identity,
                .operation_ids = selection.value_.operation_ids,
                .expected_route_identity = selected_route_identity,
                .expected_route_source_identity = route_source,
                .stage_plan_identity = stage_identity,
            });
        C1InvoiceRouteAuthority route(PublicC1InvoiceRoute{
            .binding = parent.plan_.binding,
            .round = round,
            .contact_owner_components =
                selection.value_.contact_owner_components,
            .operation_ids = selection.value_.operation_ids,
            .route_identity = selected_route_identity,
            .route_source_identity = route_source,
        });
        auto prepared = C1ContactValueAuthorityBridge::
            prepare_after_registered_claim(
                parent, std::move(stage), std::move(route));
        auto offer = prepared.take_offer();
        auto residual = prepared.take_postcapture_residual();
        need(offer.live_.load() && offer.fd_ >= 0 &&
             residual.live_.load() &&
             residual.round_ == round &&
             residual.process_identity_ == lineage.value_.c1_process_identity &&
             residual.expected_child_exit_identity_ ==
                 lineage.value_.c1_expected_exit_policy_identity);
        const auto offer_sha256 = offer_file_hash(offer.fd_);
        const auto contact_value_authority_identity =
            residual.contact_value_authority_identity_;
        RegisteredC1PendingTerminalAuthority pending(
            std::move(residual), selection.value_, selection.identity_,
            parent.plan_.binding.projections[index],
            lineage.value_.observer_worker,
            contact_value_authority_identity, offer_sha256,
            offer.device_, offer.inode_, lineage.value_.c1_process_identity,
            lineage.value_.c1_expected_exit_policy_identity);
        return RegisteredC1LaunchSplit(
            std::move(offer), std::move(pending));
    } catch (...) { refuse(); }
}

C1PostcaptureAdmissionAuthority
RegisteredC1PlanRouteBridge::admit_terminal(
        RegisteredC1PendingTerminalAuthority&& supplied_pending,
        C1Fd31QualifiedCompletionAckAuthority&& supplied_ack,
        C1AcceptedControllerResultAuthority&& supplied_result,
        C1ObservedInvoiceRouteAuthority&& supplied_route) {
    RegisteredC1PendingTerminalAuthority pending(
        std::move(supplied_pending));
    C1Fd31QualifiedCompletionAckAuthority ack(std::move(supplied_ack));
    C1AcceptedControllerResultAuthority result(std::move(supplied_result));
    C1ObservedInvoiceRouteAuthority route(std::move(supplied_route));
    try {
        need(pending.live_.exchange(false) && ack.live_.exchange(false) &&
             result.live_.exchange(false) && route.live_.exchange(false) &&
             pending.residual_.has_value());
        const auto& selection = pending.selection_;
        const auto& completion = ack.value_;
        const auto& terminal = result.value_;
        const auto& observed = route.value_;
        require_ack(selection, completion);
        need(completion.accepted_selection_identity ==
                 pending.selection_identity_ &&
             completion.contact_value_authority_identity ==
                 pending.expected_contact_value_authority_identity_ &&
             completion.offer_file_sha256 ==
                 pending.expected_offer_file_sha256_ &&
             completion.offer_device == pending.expected_offer_device_ &&
             completion.offer_inode == pending.expected_offer_inode_ &&
             completion.c1_process_identity ==
                 pending.expected_c1_process_identity_ &&
             completion.expected_exit_policy_identity ==
                 pending.expected_c1_exit_policy_identity_ &&
             same_raw_selection(selection, terminal) &&
             same_raw_route(selection, observed) &&
             terminal.fd31_authenticated_completion_identity ==
                 completion.authenticated_completion_identity &&
             observed.fd31_authenticated_completion_identity ==
                 completion.authenticated_completion_identity &&
             terminal.accepted_selection_identity ==
                 pending.selection_identity_ &&
             observed.accepted_selection_identity ==
                 pending.selection_identity_ &&
             terminal.completed_stage_count == 3 &&
             terminal.retry_count == 0 &&
             nonzero(terminal.retry_history_identity) &&
             nonzero(terminal.terminal_history_identity) &&
             terminal.retry_history_identity !=
                 terminal.terminal_history_identity &&
             terminal.terminal_history_identity ==
                 terminal_history_identity(terminal) &&
             terminal.controller_result_identities[0] !=
                 terminal.controller_result_identities[1] &&
             terminal.controller_result_identities[0] !=
                 terminal.controller_result_identities[2] &&
             terminal.controller_result_identities[1] !=
                 terminal.controller_result_identities[2]);
        for (const auto& identity : terminal.controller_result_identities)
            need(nonzero(identity));
        need(observed.invoice_result_identity ==
                 terminal.controller_result_identities[0] &&
             observed.pay_result_identity ==
                 terminal.controller_result_identities[1] &&
             observed.retry_history_identity ==
                 terminal.retry_history_identity &&
             observed.terminal_history_identity ==
                 terminal.terminal_history_identity &&
             observed.projection_identity ==
                 pending.expected_projection_identity_ &&
             observed.generator_worker == selection.generator_worker &&
             observed.validator_worker ==
                 pending.expected_validator_worker_ &&
             observed.generator_worker != observed.validator_worker);
        require_worker(observed.generator_worker);
        require_worker(observed.validator_worker);
        require_route_artifacts(selection, observed);
        for (const auto returncode : observed.worker_returncodes)
            need(returncode == 0);
        C1PostcaptureAdmissionAuthority admitted(
            std::move(*pending.residual_));
        pending.residual_.reset();
        return admitted;
    } catch (...) { refuse(); }
}

RegisteredC1PlanRouteSourceStatus registered_c1_plan_route_source_status() {
    return {
        .schema = "kpb-registered-c1-plan-route-source/v1",
        .status = "UNQUALIFIED_SOURCE_BRIDGE_CONFIGURED0",
        // The structural split exists, but the selected activation source
        // still cannot mint/consume it.  Keep the registered path false until
        // that genuine compiler/callsite lands.
        .registered_prelaunch_split_core = false,
        .exact_p1_c1_public_provenance = true,
        .controller_selection_authority_type = true,
        .fd31_completion_ack_authority_type = true,
        .observed_route_terminal_authority_type = true,
        .distinct_generator_validator_provenance = true,
        .exact_route_artifact_file_binding = true,
        .stage_plan_route_compiler_core = true,
        .parent_round_burns_before_validation = true,
        .sealed_offer_withheld_terminal_residual = true,
        .retry_and_terminal_history_required = true,
        .archive_observer_admission_join_exists = true,
        .caller_event_or_digest_factory = false,
        .production_controller_selection_minter = false,
        .production_fd31_completion_ack_minter = false,
        .production_controller_terminal_minter = false,
        .production_observed_route_minter = false,
        .selected_launcher_consumes_offer = false,
        .selected_terminal_admission_callsite = false,
        .owner_truth_input = false,
        .actual_receipt_emitted = false,
        .configured = false,
        .actual_launch = false,
        .complete = false,
    };
}

} // namespace kpb::measurement::c1_capture
