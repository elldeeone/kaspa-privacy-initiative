#include "registered_selected_producer_run_binding.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

using Digest = identity_registry::Digest;
using Plan = RegisteredSelectedProducerPrelaunchPlan;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}
bool uuid_v4(std::string_view value) {
    if (value.size() != 36 || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) ==
            std::string_view::npos)
        return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-') return false;
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}
void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void number(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void add_worker(std::vector<unsigned char>& out,
                const kpb::measurement::WorkerBinding& value) {
    add(out, value.source_identity); add(out, value.build_identity);
    add(out, value.runtime_identity); add(out, value.assets_identity);
    add(out, value.pinned_executable_identity);
    add(out, value.launcher_identity);
}
void require_worker(const kpb::measurement::WorkerBinding& value) {
    need(nonzero(value.source_identity) && nonzero(value.build_identity) &&
         nonzero(value.runtime_identity) && nonzero(value.assets_identity) &&
         nonzero(value.pinned_executable_identity) &&
         nonzero(value.launcher_identity));
}
void require_manifest(
        const kpb::measurement::FiniteManifestBinding& manifest) {
    need(nonzero(manifest.manifest_identity) &&
         nonzero(manifest.parent_recomputation_identity) &&
         manifest.manifest_identity !=
             manifest.parent_recomputation_identity &&
         kpb::measurement::recompute_finite_manifest_identity(
             manifest.entries) == manifest.manifest_identity);
    for (unsigned index = 0; index < manifest.entries.size(); ++index) {
        const auto& entry = manifest.entries[index];
        need(static_cast<unsigned>(entry.component) == index + 1 &&
             nonzero(entry.source_identity) && nonzero(entry.build_identity) &&
             nonzero(entry.runtime_identity) && nonzero(entry.assets_identity) &&
             nonzero(entry.pinned_executable_identity) &&
             nonzero(entry.launcher_identity));
    }
}
const kpb::measurement::ManifestEntry& manifest_entry(
        const kpb::measurement::FiniteManifestBinding& manifest,
        kpb::measurement::ManifestComponent component) {
    const auto index = static_cast<unsigned>(component) - 1;
    need(index < manifest.entries.size() &&
         manifest.entries[index].component == component);
    return manifest.entries[index];
}
kpb::measurement::WorkerBinding worker_from_manifest(
        const kpb::measurement::ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}
void require_plan(const Plan& plan) {
    need(uuid_v4(plan.capture_trial_id) &&
         uuid_v4(plan.capture_attempt_ids[0]) &&
         uuid_v4(plan.capture_attempt_ids[1]) &&
         plan.capture_attempt_ids[0] != plan.capture_attempt_ids[1] &&
         plan.trial == RegisteredCapturePlanRosterBridge::trial_identity(
             plan.capture_trial_id) &&
         plan.round_attempts[0] ==
             RegisteredCapturePlanRosterBridge::attempt_identity(
                 plan.capture_attempt_ids[0]) &&
         plan.round_attempts[1] ==
             RegisteredCapturePlanRosterBridge::attempt_identity(
                 plan.capture_attempt_ids[1]));
    for (const auto* value : {
             &plan.comparison_selection, &plan.run_selection,
             &plan.trial, &plan.measurement_attempt,
             &plan.measurement_cohort, &plan.capture, &plan.method,
             &plan.workload, &plan.source_closure, &plan.runtime,
             &plan.accepted_head_policy_identity,
             &plan.selected_main_policy_identity,
             &plan.prelaunch_policy_manifest_identity,
             &plan.outer_parent_process, &plan.outer_parent_executable,
             &plan.capture_source, &plan.capture_build,
             &plan.capture_runtime, &plan.capture_launcher,
             &plan.process_reservation_identity,
             &plan.persistent_process_session_identity,
             &plan.producer_process_identity, &plan.role_closure_identity,
             &plan.manifest_seal,
             &plan.construction_classification_receipt})
        need(nonzero(*value));
    require_manifest(plan.finite_manifest);
    require_worker(plan.observer_worker);
    require_worker(plan.score_worker);
    require_worker(plan.aggregate_worker);
    const auto& p1 = manifest_entry(
        plan.finite_manifest, kpb::measurement::ManifestComponent::P1Capture);
    need(plan.manifest_seal == plan.finite_manifest.manifest_identity &&
         plan.accepted_head_policy_identity !=
             plan.selected_main_policy_identity &&
         plan.prelaunch_policy_manifest_identity !=
             plan.accepted_head_policy_identity &&
         plan.prelaunch_policy_manifest_identity !=
             plan.selected_main_policy_identity &&
         plan.producer_process_identity == plan.outer_parent_process &&
         plan.run_selection != plan.comparison_selection &&
         plan.trial != plan.measurement_attempt &&
         plan.trial != plan.measurement_cohort &&
         plan.measurement_attempt != plan.measurement_cohort &&
         plan.capture_source == p1.source_identity &&
         plan.capture_build == p1.build_identity &&
         plan.capture_runtime == p1.runtime_identity &&
         plan.capture_launcher == p1.launcher_identity &&
         plan.observer_worker == worker_from_manifest(manifest_entry(
             plan.finite_manifest,
             kpb::measurement::ManifestComponent::Observer)) &&
         plan.score_worker == worker_from_manifest(manifest_entry(
             plan.finite_manifest,
             kpb::measurement::ManifestComponent::OwnerScore)) &&
         plan.aggregate_worker == worker_from_manifest(manifest_entry(
             plan.finite_manifest,
             kpb::measurement::ManifestComponent::Aggregate)));
    const bool hidden =
        plan.classification ==
            kpb::measurement::Classification::HiddenCandidate &&
        plan.construction_policy == kpb::measurement::ConstructionPolicy::
            SecretPermutationIndependent;
    const bool baseline =
        plan.classification ==
            kpb::measurement::Classification::TransparentBaseline &&
        plan.construction_policy == kpb::measurement::ConstructionPolicy::
            ExplicitOwnerPublicEffects;
    need(hidden != baseline);
    for (unsigned round = 0; round < 2; ++round) {
        need(nonzero(plan.financial_runs[round]) &&
             nonzero(plan.round_attempts[round]) &&
             nonzero(plan.round_cohorts[round]) &&
             nonzero(plan.round_capture_plans[round]) &&
             nonzero(plan.fork_plan_identities[round]));
        const auto& route = plan.route_policies[round];
        need(route.round == round + 1 &&
             nonzero(route.route_capability_identity) &&
             route.projection_bytes == 10685 &&
             route.route_endpoint_count == 1 &&
             route.owner_ack_count == 0 && route.role_blind_required &&
             route.after_full_cohort_barrier_required &&
             route.owner_socket_or_path_derivation_forbidden);
    }
    need(plan.financial_runs[0] != plan.financial_runs[1] &&
         plan.round_attempts[0] != plan.round_attempts[1] &&
         plan.round_cohorts[0] != plan.round_cohorts[1] &&
         plan.round_capture_plans[0] != plan.round_capture_plans[1] &&
         plan.fork_plan_identities[0] != plan.fork_plan_identities[1] &&
         plan.route_policies[0].route_capability_identity !=
             plan.route_policies[1].route_capability_identity);
    for (unsigned slot = 0; slot < plan.streams.size(); ++slot) {
        const auto& stream = plan.streams[slot];
        need(stream.round == slot / 5 + 1 &&
             static_cast<unsigned>(stream.kind) == slot % 5 + 1 &&
             stream.fixed_fd == slot + 20 &&
             nonzero(stream.process_identity) &&
             nonzero(stream.expected_exit_policy_identity));
    }
}
Digest authority_identity(const Plan& plan) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_REGISTERED_SELECTED_PRODUCER_PRELAUNCH_V1\n");
    bytes.push_back(static_cast<unsigned char>(plan.classification));
    for (const auto* value : {
             &plan.comparison_selection, &plan.run_selection, &plan.trial,
             &plan.measurement_attempt, &plan.measurement_cohort,
             &plan.capture, &plan.method, &plan.workload,
             &plan.source_closure, &plan.runtime,
             &plan.accepted_head_policy_identity,
             &plan.selected_main_policy_identity,
             &plan.prelaunch_policy_manifest_identity,
             &plan.finite_manifest.manifest_identity,
             &plan.finite_manifest.parent_recomputation_identity,
             &plan.outer_parent_process, &plan.outer_parent_executable,
             &plan.capture_source, &plan.capture_build,
             &plan.capture_runtime, &plan.capture_launcher,
             &plan.process_reservation_identity,
             &plan.persistent_process_session_identity,
             &plan.producer_process_identity, &plan.role_closure_identity,
             &plan.manifest_seal,
             &plan.construction_classification_receipt})
        add(bytes, *value);
    add(bytes, plan.capture_trial_id);
    add_worker(bytes, plan.observer_worker);
    add_worker(bytes, plan.score_worker);
    add_worker(bytes, plan.aggregate_worker);
    bytes.push_back(static_cast<unsigned char>(plan.construction_policy));
    for (unsigned round = 0; round < 2; ++round) {
        add(bytes, plan.capture_attempt_ids[round]);
        add(bytes, plan.financial_runs[round]);
        add(bytes, plan.round_attempts[round]);
        add(bytes, plan.round_cohorts[round]);
        add(bytes, plan.round_capture_plans[round]);
        add(bytes, plan.fork_plan_identities[round]);
        const auto& route = plan.route_policies[round];
        number(bytes, route.round);
        add(bytes, route.route_capability_identity);
        number(bytes, route.projection_bytes);
        number(bytes, route.route_endpoint_count);
        number(bytes, route.owner_ack_count);
        bytes.push_back(route.role_blind_required ? 1 : 0);
        bytes.push_back(route.after_full_cohort_barrier_required ? 1 : 0);
        bytes.push_back(
            route.owner_socket_or_path_derivation_forbidden ? 1 : 0);
    }
    for (const auto& stream : plan.streams) {
        number(bytes, stream.round);
        number(bytes, static_cast<unsigned>(stream.kind));
        number(bytes, stream.fixed_fd);
        add(bytes, stream.process_identity);
        add(bytes, stream.expected_exit_policy_identity);
    }
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_RECEIVER_TEST_SETUP
void test_need(bool value, const char* category) {
    if (!value) throw std::runtime_error(category);
}
Digest test_file_digest(int fd, bool executable) {
    const auto flags = ::fcntl(fd, F_GETFL);
    const auto descriptor_flags = ::fcntl(fd, F_GETFD);
    struct stat info{};
    test_need(fd >= 0 && flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
         descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 &&
         ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
         info.st_uid == ::getuid() && info.st_size > 0 &&
         (info.st_mode & 0022) == 0 &&
         (!executable || (info.st_mode & 0100) != 0),
         executable ? "lineage-test-worker-file" :
                      "lineage-test-selection-file");
    std::vector<unsigned char> bytes(static_cast<std::size_t>(info.st_size));
    std::size_t offset{};
    while (offset < bytes.size()) {
        const auto count = ::pread(fd, bytes.data() + offset,
            bytes.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        test_need(count > 0, "lineage-test-read");
        offset += static_cast<std::size_t>(count);
    }
    Digest result{};
    test_need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result), "lineage-test-hash");
    return result;
}

Digest test_lineage_identity(const Plan& plan, const Digest& worker) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_OWNER_SCORE_LINEAGE_TEST_BINDING_V1\n");
    for (const auto* value : {
             &plan.comparison_selection, &plan.run_selection,
             &plan.measurement_attempt, &plan.method,
             &plan.source_closure, &plan.runtime, &worker})
        add(bytes, *value);
    add(bytes, plan.capture_trial_id);
    Digest result{};
    test_need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result), "lineage-test-identity");
    return result;
}
#endif

} // namespace

RegisteredSelectedProducerPrelaunchInputAuthority::
RegisteredSelectedProducerPrelaunchInputAuthority(Plan plan)
    : plan_(std::move(plan)) {}
RegisteredSelectedProducerPrelaunchInputAuthority::
RegisteredSelectedProducerPrelaunchInputAuthority(
        RegisteredSelectedProducerPrelaunchInputAuthority&& other) noexcept
    : plan_(std::move(other.plan_)), live_(other.live_.exchange(false)) {}
RegisteredSelectedProducerPrelaunchInputAuthority::~
RegisteredSelectedProducerPrelaunchInputAuthority() = default;

RegisteredSelectedProducerPrelaunchBindingAuthority::
RegisteredSelectedProducerPrelaunchBindingAuthority(
        Plan plan, Digest identity)
    : plan_(std::move(plan)), authority_identity_(identity) {}
RegisteredSelectedProducerPrelaunchBindingAuthority::
RegisteredSelectedProducerPrelaunchBindingAuthority(
        RegisteredSelectedProducerPrelaunchBindingAuthority&& other) noexcept
    : plan_(std::move(other.plan_)),
      authority_identity_(std::exchange(other.authority_identity_, {})),
      live_(other.live_.exchange(false)),
      c1_round_lineage_issued_(
          other.c1_round_lineage_issued_.exchange(true)),
      lineage_selection_fd_(
          std::exchange(other.lineage_selection_fd_, -1)),
      lineage_worker_fd_(std::exchange(other.lineage_worker_fd_, -1)),
      lineage_worker_sha256_(
          std::exchange(other.lineage_worker_sha256_, {})),
      lineage_receiver_live_(other.lineage_receiver_live_.exchange(false)),
      lineage_worker_selected_(
          std::exchange(other.lineage_worker_selected_, false)) {}
RegisteredSelectedProducerPrelaunchBindingAuthority::~
RegisteredSelectedProducerPrelaunchBindingAuthority() {
    if (lineage_selection_fd_ >= 0) ::close(lineage_selection_fd_);
    if (lineage_worker_fd_ >= 0) ::close(lineage_worker_fd_);
}

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_RECEIVER_TEST_SETUP
RegisteredSelectedProducerPrelaunchBindingAuthority
RegisteredSelectedProducerPrelaunchBindingAuthority::
test_only_lineage_binding(RegisteredSelectedProducerPrelaunchPlan plan,
                          int selection_fd, int worker_fd) {
    try {
        const auto selection = test_file_digest(selection_fd, false);
        const auto worker = test_file_digest(worker_fd, true);
        test_need(selection == plan.comparison_selection,
                  "lineage-test-selection");
        const auto identity = test_lineage_identity(plan, worker);
        RegisteredSelectedProducerPrelaunchBindingAuthority result(
            std::move(plan), identity);
        result.lineage_selection_fd_ = selection_fd;
        result.lineage_worker_fd_ = worker_fd;
        result.lineage_worker_sha256_ = worker;
        result.lineage_receiver_live_.store(true);
        result.lineage_worker_selected_ = true;
        return result;
    } catch (...) {
        if (selection_fd >= 0) ::close(selection_fd);
        if (worker_fd >= 0) ::close(worker_fd);
        throw;
    }
}
#endif

RegisteredSelectedProducerPrelaunchBindingAuthority
RegisteredSelectedProducerPrelaunchBindingFactory::compile(
        RegisteredSelectedProducerPrelaunchInputAuthority&& supplied) {
    const bool live = supplied.live_.exchange(false);
    auto plan = std::move(supplied.plan_);
    try {
        need(live);
        require_plan(plan);
        const auto identity = authority_identity(plan);
        return RegisteredSelectedProducerPrelaunchBindingAuthority(
            std::move(plan), identity);
    } catch (...) { refuse(); }
}

RegisteredSelectedProducerRunBindingSourceStatus
registered_selected_producer_run_binding_source_status() {
    return {
        .schema = "kpb-registered-selected-producer-prelaunch/v1",
        .status = "UNQUALIFIED_CHRONOLOGY_SPLIT_CONFIGURED0",
        .structural_prelaunch_factory_core = true,
        .raw_uuid_domain_binding = true,
        .accepted_head_and_selected_main_plan_authorities = false,
        .source_owned_outer_attempt_domain = false,
        .producer_plus_two_capsule_prelaunch_split = false,
        .round_capsule_prelaunch_children = false,
        .exact_two_round_lineage = true,
        .finite_manifest_binding = true,
        .process_reservation_and_session_binding = true,
        .route_capability_policy_binding = true,
        .expected_exit_policy_binding = true,
        .caller_prelaunch_factory = false,
        .post_reservation_activation_minter = false,
        .postrun_projection_residual = false,
        .postrun_pidfd_exit_residual = false,
        .observer_v5_preidentity_recorder = false,
        .persistent_two_round_capsule_owner = false,
        .observer_v5_state_capsule_residual = false,
        .final_run_binding_join = false,
        .selected_parent_callsite = false,
        .configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver
