#include "c1_registered_plan_route_bridge.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::c1_capture;
using namespace kpb::measurement::producer_runtime;

namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::string_view TRIAL =
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
constexpr std::string_view OTHER_TRIAL =
    "abababab-abab-4bab-8bab-abababababab";
constexpr std::string_view ATTEMPT1 =
    "11111111-1111-4111-8111-111111111111";
constexpr std::string_view ATTEMPT2 =
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
constexpr std::string_view CAPTURE =
    "22222222-2222-4222-8222-222222222222";
constexpr std::array<std::string_view, 3> OPS{
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
};

template<class Function>
void refuses(Function&& function) {
    bool rejected = false;
    try { function(); } catch (const Refused&) { rejected = true; }
    assert(rejected);
}

Digest digest(unsigned value) {
    Digest result{};
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(value + index * 17);
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}
Digest hash(std::string_view value) {
    return hash(std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add_u64(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
Digest domain_hash(std::string_view domain, std::string_view value) {
    Bytes bytes(domain.begin(), domain.end());
    add(bytes, value);
    return hash(bytes);
}
Digest trial_identity(std::string_view value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n");
    add_u64(bytes, value.size());
    add(bytes, value);
    return hash(bytes);
}

WorkerBinding worker(const ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

void add_worker(Bytes& out, const WorkerBinding& value) {
    add(out, value.source_identity);
    add(out, value.build_identity);
    add(out, value.runtime_identity);
    add(out, value.assets_identity);
    add(out, value.pinned_executable_identity);
    add(out, value.launcher_identity);
}

std::array<std::string, 3> operations() {
    return {std::string(OPS[0]), std::string(OPS[1]),
            std::string(OPS[2])};
}

RunBinding binding() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = 0x100 + index * 10;
        entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(seed + 1),
            .runtime_identity = digest(seed + 2),
            .assets_identity = digest(seed + 3),
            .pinned_executable_identity = digest(seed + 4),
            .launcher_identity = digest(seed + 5),
        };
    }
    FiniteManifestBinding manifest{
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest(0x80),
        .entries = entries,
    };
    const auto& p1 = manifest.entries[1];
    return {
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest(1),
        .run_selection = digest(2),
        .trial = trial_identity(TRIAL),
        .attempt = digest(4),
        .cohort = digest(5),
        .capture = domain_hash(
            "KPB_CAPTURE_IDENTITY_V1\n", CAPTURE),
        .method = digest(7),
        .workload = digest(8),
        .source_closure = digest(9),
        .runtime = digest(10),
        .finite_manifest = manifest,
        .outer_parent_process = digest(11),
        .outer_parent_executable = digest(12),
        .capture_source = p1.source_identity,
        .capture_build = p1.build_identity,
        .capture_runtime = p1.runtime_identity,
        .capture_launcher = p1.launcher_identity,
        .observer_worker = worker(manifest.entries[6]),
        .score_worker = worker(manifest.entries[7]),
        .aggregate_worker = worker(manifest.entries[8]),
        .financial_runs = {digest(20), digest(21)},
        .round_attempts = {
            domain_hash("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPT1),
            domain_hash("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPT2),
        },
        .round_cohorts = {digest(24), digest(25)},
        .round_capture_plans = {digest(26), digest(27)},
        .projections = {digest(28), digest(29)},
    };
}

PublicProducerLaunchPlan plan() {
    const auto selected = binding();
    PublicProducerLaunchPlan result{
        .binding = selected,
        .capture_trial_id = std::string(TRIAL),
        .capture_attempt_ids = {
            std::string(ATTEMPT1), std::string(ATTEMPT2)},
        .producer_process_identity = selected.outer_parent_process,
        .role_closure_identity = selected.source_closure,
        .manifest_seal = selected.finite_manifest.manifest_identity,
        .construction_policy =
            ConstructionPolicy::SecretPermutationIndependent,
        .construction_classification_receipt = digest(30),
        .opaque_closure_authority_identity = digest(31),
        .route_requirements = {
            PublicAggregateMailboxRouteRequirement{
                .round = 1,
                .projection_identity = selected.projections[0],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true,
            },
            PublicAggregateMailboxRouteRequirement{
                .round = 2,
                .projection_identity = selected.projections[1],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true,
            },
        },
    };
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        result.streams[index] = {
            .round = index / 5 + 1,
            .kind = static_cast<CaptureKind>(index % 5 + 1),
            .fixed_fd = 20 + index,
            .process_identity = digest(40 + index),
            .child_exit_identity = digest(60 + index),
        };
    }
    return result;
}

PublicRegisteredC1RoundLineage lineage(
        const PublicProducerLaunchPlan& selected, unsigned round = 1) {
    const auto index = round - 1;
    const auto& b = selected.binding;
    const auto& stream = selected.streams[index * 5 + 4];
    return {
        .classification = b.classification,
        .round = round,
        .capture_trial_id = selected.capture_trial_id,
        .capture_attempt_id = selected.capture_attempt_ids[index],
        .registered_prelaunch_identity = digest(90),
        .comparison_selection = b.comparison_selection,
        .run_selection = b.run_selection,
        .trial = b.trial,
        .measurement_attempt = b.attempt,
        .measurement_cohort = b.cohort,
        .capture = b.capture,
        .method = b.method,
        .workload = b.workload,
        .source_closure = b.source_closure,
        .runtime = b.runtime,
        .finite_manifest = b.finite_manifest,
        .outer_parent_process = b.outer_parent_process,
        .outer_parent_executable = b.outer_parent_executable,
        .capture_source = b.capture_source,
        .capture_build = b.capture_build,
        .capture_runtime = b.capture_runtime,
        .capture_launcher = b.capture_launcher,
        .observer_worker = b.observer_worker,
        .score_worker = b.score_worker,
        .aggregate_worker = b.aggregate_worker,
        .financial_run = b.financial_runs[index],
        .round_attempt = b.round_attempts[index],
        .round_cohort = b.round_cohorts[index],
        .round_capture_plan = b.round_capture_plans[index],
        .process_reservation_identity = digest(91),
        .persistent_process_session_identity = digest(92),
        .fork_plan_identity = digest(93 + index),
        .route_capability_identity = digest(95 + index),
        .producer_process_identity = selected.producer_process_identity,
        .role_closure_identity = selected.role_closure_identity,
        .manifest_seal = selected.manifest_seal,
        .construction_policy = selected.construction_policy,
        .construction_classification_receipt =
            selected.construction_classification_receipt,
        .c1_process_identity = stream.process_identity,
        .c1_expected_exit_policy_identity = stream.child_exit_identity,
    };
}

PublicC1AcceptedControllerSelection selection(
        const PublicRegisteredC1RoundLineage& selected) {
    const auto& c1 = selected.finite_manifest.entries[2];
    return {
        .round = selected.round,
        .capture_trial_id = selected.capture_trial_id,
        .capture_attempt_id = selected.capture_attempt_id,
        .capture_identity = std::string(CAPTURE),
        .operation_ids = operations(),
        .contact_owner_components = selected.round == 1
            ? std::array<unsigned, 3>{0, 2, 0}
            : std::array<unsigned, 3>{2, 0, 2},
        .registered_prelaunch_identity =
            selected.registered_prelaunch_identity,
        .round_capture_plan_identity = selected.round_capture_plan,
        .generator_worker = worker(c1),
        .accepted_stage_selection_identities = {
            digest(100), digest(101), digest(102)},
        .accepted_selection_history_identity = digest(103),
    };
}

Digest selection_identity(
        const PublicC1AcceptedControllerSelection& value) {
    Bytes bytes;
    add(bytes, "KPB_C1_ACCEPTED_CONTROLLER_SELECTION_V1\n");
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

Digest terminal_history_identity(
        const PublicC1AcceptedControllerResult& result) {
    Bytes bytes;
    add(bytes, "KPB_C1_CONTROLLER_TERMINAL_HISTORY_V1\n");
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

PublicC1AcceptedControllerResult terminal(
        const PublicC1AcceptedControllerSelection& selected,
        const Digest& completion_identity) {
    PublicC1AcceptedControllerResult result{
        .round = selected.round,
        .capture_trial_id = selected.capture_trial_id,
        .capture_attempt_id = selected.capture_attempt_id,
        .capture_identity = selected.capture_identity,
        .operation_ids = selected.operation_ids,
        .registered_prelaunch_identity =
            selected.registered_prelaunch_identity,
        .round_capture_plan_identity =
            selected.round_capture_plan_identity,
        .accepted_selection_identity = selection_identity(selected),
        .fd31_authenticated_completion_identity = completion_identity,
        .controller_result_identities = {
            digest(110), digest(111), digest(112)},
        .retry_history_identity = digest(113),
        .generator_worker = selected.generator_worker,
        .completed_stage_count = 3,
        .retry_count = 0,
    };
    result.terminal_history_identity = terminal_history_identity(result);
    return result;
}

Digest route_artifact_identity(
        unsigned round, const PublicC1ObservedRouteArtifact& value) {
    Bytes bytes;
    add(bytes, "KPB_C1_OBSERVED_INVOICE_ROUTE_ARTIFACT_V1\n");
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

std::array<PublicC1ObservedRouteArtifact, 3> route_artifacts(
        const PublicC1AcceptedControllerSelection& selected) {
    std::array<PublicC1ObservedRouteArtifact, 3> result{};
    for (unsigned index = 0; index < result.size(); ++index) {
        result[index] = {
            .source_owner_component = index,
            .target_owner_component = (index + selected.round) % 3,
            .source_operation_id = selected.operation_ids[1],
            .target_invoice_operation_id = selected.operation_ids[0],
            .raw_bytes_sha256 = digest(120 + index),
            .device = 200 + index,
            .inode = 300 + index,
            .byte_count = 400 + index,
        };
        result[index].record_identity =
            route_artifact_identity(selected.round, result[index]);
    }
    return result;
}

PublicC1ObservedInvoiceRoute observed(
        const PublicC1AcceptedControllerSelection& selected,
        const PublicC1AcceptedControllerResult& result,
        const Digest& projection, const WorkerBinding& validator) {
    return {
        .round = selected.round,
        .capture_trial_id = selected.capture_trial_id,
        .capture_attempt_id = selected.capture_attempt_id,
        .capture_identity = selected.capture_identity,
        .operation_ids = selected.operation_ids,
        .contact_owner_components = selected.contact_owner_components,
        .registered_prelaunch_identity =
            selected.registered_prelaunch_identity,
        .round_capture_plan_identity =
            selected.round_capture_plan_identity,
        .accepted_selection_identity = result.accepted_selection_identity,
        .fd31_authenticated_completion_identity =
            result.fd31_authenticated_completion_identity,
        .invoice_result_identity = result.controller_result_identities[0],
        .pay_result_identity = result.controller_result_identities[1],
        .route_artifacts = route_artifacts(selected),
        .retry_history_identity = result.retry_history_identity,
        .terminal_history_identity = result.terminal_history_identity,
        .projection_identity = projection,
        .generator_worker = selected.generator_worker,
        .validator_worker = validator,
        .worker_returncodes = {0, 0, 0},
    };
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    (void)::close(fd);
    fd = -1;
}

struct PipeSet final {
    std::array<int, 10> reads{};
    std::array<int, 10> writes{};
    PipeSet() {
        reads.fill(-1);
        writes.fill(-1);
        for (unsigned index = 0; index < reads.size(); ++index) {
            int pair[2]{};
            assert(::pipe2(pair, O_CLOEXEC) == 0);
            reads[index] = pair[0];
            writes[index] = pair[1];
        }
    }
    ~PipeSet() {
        for (auto& value : reads) close_fd(value);
        for (auto& value : writes) close_fd(value);
    }
};

ParentTenReadEndsAuthority parent(
        PipeSet& pipes, const PublicProducerLaunchPlan& selected) {
    auto reads = pipes.reads;
    pipes.reads.fill(-1);
    return ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(reads));
}

struct Prepared final {
    PublicProducerLaunchPlan selected_plan;
    PublicRegisteredC1RoundLineage selected_lineage;
    PublicC1AcceptedControllerSelection selected_controller;
    PipeSet pipes;
    ParentTenReadEndsAuthority topology;
    std::optional<RegisteredC1LaunchSplit> launch;

    Prepared()
        : selected_plan(plan()),
          selected_lineage(lineage(selected_plan)),
          selected_controller(selection(selected_lineage)),
          topology(parent(pipes, selected_plan)) {
        auto lineage_authority =
            RegisteredC1RoundLineageAuthority::test_only_mint(
                selected_lineage);
        auto controller_authority =
            C1AcceptedControllerSelectionAuthority::test_only_mint(
                selected_controller);
        launch.emplace(RegisteredC1PlanRouteBridge::prepare(
            topology, std::move(lineage_authority),
            std::move(controller_authority)));
    }
};

Digest stage_identity(
        const std::array<std::string, 3>& selected, unsigned round = 1) {
    Bytes bytes;
    add(bytes, "KPB_C1_CONTACT_VALUE_STAGE_PLAN_V1\n");
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(1);
    for (unsigned index = 0; index < selected.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        bytes.push_back(static_cast<unsigned char>(index + 1));
        add(bytes, selected[index]);
        bytes.push_back(index == 1 ? 1 : 0);
        if (index == 1) add(bytes, selected[0]);
        else bytes.insert(bytes.end(), 36, 0);
    }
    return hash(bytes);
}

struct OfferEvidence final {
    Digest authority_identity{};
    Digest file_sha256{};
    std::uint64_t device{};
    std::uint64_t inode{};
};

OfferEvidence evidence_from_offer(C1ContactValueOfferAuthority&& offer) {
    int fd = offer.test_only_take_fd();
    struct stat state{};
    assert(::fstat(fd, &state) == 0 && S_ISREG(state.st_mode));
    std::array<unsigned char, C1_CONTACT_VALUE_OFFER_BYTES> bytes{};
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::pread(fd, bytes.data() + at,
            bytes.size() - at, static_cast<off_t>(at));
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
    close_fd(fd);
    OfferEvidence result{
        .file_sha256 = hash(bytes),
        .device = static_cast<std::uint64_t>(state.st_dev),
        .inode = static_cast<std::uint64_t>(state.st_ino),
    };
    std::copy(bytes.end() - result.authority_identity.size(), bytes.end(),
              result.authority_identity.begin());
    return result;
}

PublicC1Fd31QualifiedCompletionAck completion_ack(
        const PublicC1AcceptedControllerSelection& selected,
        const PublicRegisteredC1RoundLineage& selected_lineage,
        const OfferEvidence& offer) {
    return {
        .round = selected.round,
        .capture_trial_id = selected.capture_trial_id,
        .capture_attempt_id = selected.capture_attempt_id,
        .capture_identity = selected.capture_identity,
        .operation_ids = selected.operation_ids,
        .contact_owner_components = selected.contact_owner_components,
        .registered_prelaunch_identity =
            selected.registered_prelaunch_identity,
        .round_capture_plan_identity =
            selected.round_capture_plan_identity,
        .accepted_selection_identity = selection_identity(selected),
        .contact_value_authority_identity = offer.authority_identity,
        .offer_file_sha256 = offer.file_sha256,
        .offer_device = offer.device,
        .offer_inode = offer.inode,
        .offer_byte_count = C1_CONTACT_VALUE_OFFER_BYTES,
        .fixed_fd = C1_CONTACT_VALUE_OFFER_FIXED_FD,
        .c1_process_identity = selected_lineage.c1_process_identity,
        .expected_exit_policy_identity =
            selected_lineage.c1_expected_exit_policy_identity,
        .supervisor_worker = selected.generator_worker,
        .exact_offer_parse_identity = digest(130),
        .authenticated_completion_identity = digest(131),
        .writer_close_identity = digest(132),
        .eof_identity = digest(133),
        .exit_join_identity = digest(134),
        .offer_parse_monotonic_ns = 1000,
        .completion_ack_monotonic_ns = 2000,
        .writer_close_monotonic_ns = 3000,
        .eof_monotonic_ns = 4000,
        .exit_join_monotonic_ns = 5000,
        .exact_fd31_read = true,
        .fallback_offer_absent = true,
        .authenticated_completion = true,
        .writer_closed = true,
        .eof_observed = true,
        .expected_exit_observed = true,
    };
}

void positive_terminal_and_replay() {
    Prepared value;
    auto offer = evidence_from_offer(value.launch->take_offer());
    auto pending = value.launch->take_pending_terminal();
    const auto completion_value = completion_ack(
        value.selected_controller, value.selected_lineage, offer);
    const auto terminal_value = terminal(
        value.selected_controller,
        completion_value.authenticated_completion_identity);
    const auto route_value = observed(
        value.selected_controller, terminal_value,
        value.selected_plan.binding.projections[0],
        value.selected_lineage.observer_worker);
    auto terminal_authority =
        C1AcceptedControllerResultAuthority::test_only_mint(terminal_value);
    auto completion_authority =
        C1Fd31QualifiedCompletionAckAuthority::test_only_mint(
            completion_value);
    auto route_authority =
        C1ObservedInvoiceRouteAuthority::test_only_mint(route_value);
    auto admitted = RegisteredC1PlanRouteBridge::admit_terminal(
        std::move(pending), std::move(completion_authority),
        std::move(terminal_authority),
        std::move(route_authority));
    std::array<Digest, 3> operation_identities{};
    for (unsigned index = 0; index < operations().size(); ++index)
        operation_identities[index] = hash(operations()[index]);
    assert(admitted.test_only_matches(
        value.selected_plan.binding, 1, offer.authority_identity,
        stage_identity(operations()), operation_identities));
    refuses([&] { (void)value.launch->take_offer(); });
    refuses([&] { (void)value.launch->take_pending_terminal(); });
    refuses([&] {
        (void)RegisteredC1PlanRouteBridge::admit_terminal(
            std::move(pending), std::move(completion_authority),
            std::move(terminal_authority),
            std::move(route_authority));
    });
}

void wrong_trial_and_prelaunch_burn_parent() {
    auto selected_plan = plan();
    auto selected_lineage = lineage(selected_plan);
    auto wrong = selection(selected_lineage);
    wrong.capture_trial_id = std::string(OTHER_TRIAL);
    PipeSet pipes;
    auto topology = parent(pipes, selected_plan);
    auto lineage_authority =
        RegisteredC1RoundLineageAuthority::test_only_mint(
            selected_lineage);
    auto wrong_authority =
        C1AcceptedControllerSelectionAuthority::test_only_mint(wrong);
    refuses([&] {
        (void)RegisteredC1PlanRouteBridge::prepare(
            topology, std::move(lineage_authority),
            std::move(wrong_authority));
    });
    auto correct_lineage =
        RegisteredC1RoundLineageAuthority::test_only_mint(
            selected_lineage);
    auto correct =
        C1AcceptedControllerSelectionAuthority::test_only_mint(
            selection(selected_lineage));
    refuses([&] {
        (void)RegisteredC1PlanRouteBridge::prepare(
            topology, std::move(correct_lineage), std::move(correct));
    });

    auto prelaunch_plan = plan();
    auto prelaunch_lineage = lineage(prelaunch_plan);
    auto wrong_prelaunch = selection(prelaunch_lineage);
    wrong_prelaunch.registered_prelaunch_identity = digest(0xef);
    PipeSet prelaunch_pipes;
    auto prelaunch_parent = parent(prelaunch_pipes, prelaunch_plan);
    auto prelaunch_lineage_authority =
        RegisteredC1RoundLineageAuthority::test_only_mint(
            prelaunch_lineage);
    auto wrong_prelaunch_authority =
        C1AcceptedControllerSelectionAuthority::test_only_mint(
            wrong_prelaunch);
    refuses([&] {
        (void)RegisteredC1PlanRouteBridge::prepare(
            prelaunch_parent, std::move(prelaunch_lineage_authority),
            std::move(wrong_prelaunch_authority));
    });

    auto copied_plan = plan();
    auto copied_lineage = lineage(copied_plan);
    copied_lineage.round_capture_plan = digest(0xf0);
    auto copied_selection = selection(copied_lineage);
    PipeSet second_pipes;
    auto second_parent = parent(second_pipes, copied_plan);
    auto copied_lineage_authority =
        RegisteredC1RoundLineageAuthority::test_only_mint(
            copied_lineage);
    auto copied_selection_authority =
        C1AcceptedControllerSelectionAuthority::test_only_mint(
            copied_selection);
    refuses([&] {
        (void)RegisteredC1PlanRouteBridge::prepare(
            second_parent, std::move(copied_lineage_authority),
            std::move(copied_selection_authority));
    });
}

template<class Mutator>
void terminal_refuses(Mutator&& mutate) {
    Prepared value;
    const auto offer = evidence_from_offer(value.launch->take_offer());
    auto pending = value.launch->take_pending_terminal();
    auto completion = completion_ack(
        value.selected_controller, value.selected_lineage, offer);
    auto result = terminal(
        value.selected_controller,
        completion.authenticated_completion_identity);
    auto route = observed(value.selected_controller, result,
        value.selected_plan.binding.projections[0],
        value.selected_lineage.observer_worker);
    if constexpr (std::is_invocable_v<
                      Mutator, PublicC1AcceptedControllerResult&,
                      PublicC1ObservedInvoiceRoute&,
                      PublicC1Fd31QualifiedCompletionAck&>)
        mutate(result, route, completion);
    else
        mutate(result, route);
    auto completion_authority =
        C1Fd31QualifiedCompletionAckAuthority::test_only_mint(completion);
    auto result_authority =
        C1AcceptedControllerResultAuthority::test_only_mint(result);
    auto route_authority =
        C1ObservedInvoiceRouteAuthority::test_only_mint(route);
    refuses([&] {
        (void)RegisteredC1PlanRouteBridge::admit_terminal(
            std::move(pending), std::move(completion_authority),
            std::move(result_authority),
            std::move(route_authority));
    });
}

void hostile_terminal_controls() {
    terminal_refuses([](auto& result, auto&) {
        result.retry_history_identity = {};
    });
    terminal_refuses([](auto& result, auto&) {
        result.terminal_history_identity = {};
    });
    terminal_refuses([](auto& result, auto& route) {
        result.terminal_history_identity = result.retry_history_identity;
        route.terminal_history_identity = result.terminal_history_identity;
    });
    terminal_refuses([](auto&, auto& route) {
        route.terminal_history_identity = route.retry_history_identity;
    });
    terminal_refuses([](auto& result, auto&) {
        result.completed_stage_count = 2;
    });
    terminal_refuses([](auto& result, auto&) {
        result.retry_count = 1;
    });
    terminal_refuses([](auto& result, auto&) {
        result.fd31_authenticated_completion_identity = digest(0xd3);
        result.terminal_history_identity = terminal_history_identity(result);
    });
    terminal_refuses([](auto&, auto& route) {
        route.fd31_authenticated_completion_identity = digest(0xd4);
    });
    terminal_refuses([](auto&, auto& route) {
        route.contact_owner_components = {2, 0, 2};
    });
    terminal_refuses([](auto&, auto& route) {
        route.operation_ids[2] =
            "66666666-6666-4666-8666-666666666666";
    });
    terminal_refuses([](auto&, auto& route) {
        route.registered_prelaunch_identity = digest(0xe0);
    });
    terminal_refuses([](auto&, auto& route) {
        route.round_capture_plan_identity = digest(0xe1);
    });
    terminal_refuses([](auto&, auto& route) {
        route.worker_returncodes[1] = 1;
    });
    terminal_refuses([](auto&, auto& route) {
        route.projection_identity = digest(0xe2);
    });
    terminal_refuses([](auto& result, auto&) {
        result.generator_worker.source_identity = digest(0xe3);
    });
    terminal_refuses([](auto&, auto& route) {
        route.generator_worker.source_identity = digest(0xe4);
    });
    terminal_refuses([](auto&, auto& route) {
        route.validator_worker.source_identity = digest(0xe5);
    });
    terminal_refuses([](auto&, auto& route) {
        route.validator_worker = route.generator_worker;
    });
    terminal_refuses([](auto&, auto& route) {
        route.route_artifacts[0].raw_bytes_sha256 = digest(0xe6);
    });
    terminal_refuses([](auto&, auto& route) {
        route.route_artifacts[0].inode =
            route.route_artifacts[1].inode;
        route.route_artifacts[0].device =
            route.route_artifacts[1].device;
        route.route_artifacts[0].record_identity = route_artifact_identity(
            route.round, route.route_artifacts[0]);
    });
    terminal_refuses([](auto&, auto& route) {
        route.route_artifacts[0].source_owner_component = 2;
    });
    terminal_refuses([](auto&, auto& route) {
        route.route_artifacts[0].target_invoice_operation_id =
            route.operation_ids[2];
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.contact_value_authority_identity = digest(0xd0);
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.offer_file_sha256 = digest(0xd1);
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ++ack.offer_inode;
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.c1_process_identity = digest(0xd2);
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.exact_fd31_read = false;
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.fallback_offer_absent = false;
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.authenticated_completion = false;
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.completion_ack_monotonic_ns = ack.offer_parse_monotonic_ns;
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.eof_observed = false;
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.expected_exit_observed = false;
    });
    terminal_refuses([](auto&, auto&, auto& ack) {
        ack.eof_identity = ack.writer_close_identity;
    });
}

void status_stays_false() {
    const auto value = registered_c1_plan_route_source_status();
    assert(!value.registered_prelaunch_split_core);
    assert(value.exact_p1_c1_public_provenance);
    assert(value.fd31_completion_ack_authority_type);
    assert(value.distinct_generator_validator_provenance);
    assert(value.exact_route_artifact_file_binding);
    assert(value.stage_plan_route_compiler_core);
    assert(value.parent_round_burns_before_validation);
    assert(value.sealed_offer_withheld_terminal_residual);
    assert(value.retry_and_terminal_history_required);
    assert(value.archive_observer_admission_join_exists);
    assert(!value.caller_event_or_digest_factory);
    assert(!value.production_controller_selection_minter);
    assert(!value.production_fd31_completion_ack_minter);
    assert(!value.production_controller_terminal_minter);
    assert(!value.production_observed_route_minter);
    assert(!value.selected_launcher_consumes_offer);
    assert(!value.selected_terminal_admission_callsite);
    assert(!value.owner_truth_input);
    assert(!value.actual_receipt_emitted);
    assert(!value.configured && !value.actual_launch && !value.complete);
}

} // namespace

int main() {
    positive_terminal_and_replay();
    wrong_trial_and_prelaunch_burn_parent();
    hostile_terminal_controls();
    status_stays_false();
    return 0;
}
