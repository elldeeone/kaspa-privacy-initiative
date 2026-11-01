#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "native_terminal_completion.hpp"
#include "native_terminal_completion_test_fixture.hpp"
#include "native_terminal_mapping_source.hpp"
#include "native_terminal_projection_test_fixture.hpp"
#include "privacy_capture_producer_archive.hpp"
#include "privacy_capture_producer_runtime.hpp"
#include "privacy_measurement_observer_capture_bridge.hpp"
#include "privacy_measurement_run_binding_wire.hpp"
#ifdef KPB_NATIVE_TERMINAL_ARCHIVE_INTEGRATION_TEST_SETUP
#include "c1_contact_value_authority.hpp"
#include "privacy_capture_producer_supervisor.hpp"
#include "privacy_measurement_observer_spool_capsule_schema.hpp"
#include "privacy_measurement_structural_continuity_section_schema.hpp"
#endif
#include "../mpc-prover/financial/registered_projection_route.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <linux/memfd.h>
#include <openssl/sha.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::producer_runtime;
using namespace kpb::measurement::runtime_bridge;
using namespace kpb::native_terminal;
using namespace kpb::testnet_activation;
namespace registered = kpi::mpc::financial::registered_driver;
namespace projection_route = registered::projection_route;
namespace honest_owner_material = kpb::honest_owner_material;

namespace {

unsigned refusal_sequence{};

template<class Function>
void expect_refused(Function&& function) {
    const unsigned selected_sequence = ++refusal_sequence;
    bool refused = false;
    try { function(); }
    catch (const Refused&) { refused = true; }
    catch (const kpb::capture::CaptureRefused&) { refused = true; }
    catch (const kpb::honest_owner_material::HonestOwnerRefused&) {
        refused = true;
    }
    if (!refused)
        std::fprintf(stderr, "missing refusal %u\n", selected_sequence);
    assert(refused);
}

Digest digest(unsigned value) {
    Digest result{};
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            (value + index * 17U) & 0xffU);
    return result;
}
Digest sha(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()));
    return result;
}
Digest string_identity(const char* domain, const std::string& value) {
    std::vector<unsigned char> bytes;
    while (*domain) bytes.push_back(static_cast<unsigned char>(*domain++));
    bytes.insert(bytes.end(), value.begin(), value.end());
    return sha(bytes);
}
Digest registered_trial_identity(const std::string& value) {
    std::vector<unsigned char> bytes;
    const char* domain = "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n";
    while (*domain) bytes.push_back(static_cast<unsigned char>(*domain++));
    const auto size = static_cast<std::uint64_t>(value.size());
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<unsigned char>(size >> shift));
    bytes.insert(bytes.end(), value.begin(), value.end());
    return sha(bytes);
}
std::string hex(const Digest& value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 0xf]);
    }
    return result;
}
void close_fd(int& fd) {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}
void write_all(int fd, std::span<const unsigned char> value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto count = ::write(fd, value.data() + offset,
                                   value.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) _exit(120);
        offset += static_cast<std::size_t>(count);
    }
}
Digest hash_fd(int fd) {
    struct stat stat{};
    assert(::fstat(fd, &stat) == 0 && stat.st_size > 0);
    std::vector<unsigned char> bytes(static_cast<std::size_t>(stat.st_size));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::pread(fd, bytes.data() + offset,
                                   bytes.size() - offset, offset);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    return sha(bytes);
}
int sealed_self() {
    const int result = ::memfd_create(
        "kpb-native-terminal-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(result >= 0);
    int self = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    assert(self >= 0);
    std::array<unsigned char, 1U << 16> buffer{};
    for (;;) {
        ssize_t count;
        do { count = ::read(self, buffer.data(), buffer.size()); }
        while (count < 0 && errno == EINTR);
        assert(count >= 0);
        if (count == 0) break;
        write_all(result, {buffer.data(), static_cast<std::size_t>(count)});
    }
    close_fd(self);
    assert(::fchmod(result, 0500) == 0);
    assert(::fcntl(result, F_ADD_SEALS,
        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) == 0);
    return result;
}
Digest current_executable() {
    int fd = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    const auto result = hash_fd(fd);
    close_fd(fd);
    return result;
}
Digest outer_process(const Digest& executable) {
    std::vector<unsigned char> bytes;
    const char* domain = "KPB_NATIVE_TERMINAL_OUTER_PARENT_V1\n";
    while (*domain) bytes.push_back(static_cast<unsigned char>(*domain++));
    bytes.insert(bytes.end(), executable.begin(), executable.end());
    const auto pid = static_cast<std::uint64_t>(::getpid());
    for (unsigned index = 0; index < 8; ++index)
        bytes.push_back(static_cast<unsigned char>(pid >> (8 * index)));
    return sha(bytes);
}
WorkerBinding worker(const ManifestEntry& entry) {
    return {.source_identity = entry.source_identity,
            .build_identity = entry.build_identity,
            .runtime_identity = entry.runtime_identity,
            .assets_identity = entry.assets_identity,
            .pinned_executable_identity = entry.pinned_executable_identity,
            .launcher_identity = entry.launcher_identity};
}

constexpr const char* CAPTURE_ID =
    "22222222-2222-4222-8222-222222222222";
constexpr const char* TRIAL_ID =
    "11111111-1111-4111-8111-111111111111";
constexpr std::array<const char*, 2> ATTEMPTS{
    "33333333-3333-4333-8333-333333333331",
    "33333333-3333-4333-8333-333333333332",
};

RunBinding binding(const Digest& executable) {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const unsigned seed = 0x300 + index * 12;
        entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(seed + 1),
            .runtime_identity = digest(seed + 2),
            .assets_identity = digest(seed + 3),
            .pinned_executable_identity =
                index == 0 ? executable : digest(seed + 4),
            .launcher_identity = digest(seed + 5),
        };
    }
    const auto outer_executable = current_executable();
    FiniteManifestBinding manifest{
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest(0x390),
        .entries = entries,
    };
    const auto& capture = entries[1];
    return {
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest(0x101),
        .run_selection = digest(0x102),
        .trial = registered_trial_identity(TRIAL_ID),
        .attempt = digest(0x104),
        .cohort = digest(0x105),
        .capture = string_identity(
            "KPB_CAPTURE_IDENTITY_V1\n", CAPTURE_ID),
        .method = digest(0x107), .workload = digest(0x108),
        .source_closure = digest(0x109), .runtime = digest(0x10a),
        .finite_manifest = manifest,
        .outer_parent_process = outer_process(outer_executable),
        .outer_parent_executable = outer_executable,
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(entries[6]),
        .score_worker = worker(entries[7]),
        .aggregate_worker = worker(entries[8]),
        .financial_runs = {digest(0x120), digest(0x121)},
        .round_attempts = {
            string_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPTS[0]),
            string_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPTS[1])},
        .round_cohorts = {digest(0x124), digest(0x125)},
        .round_capture_plans = {digest(0x128), digest(0x129)},
        .projections = {
            kpb::native_terminal::projection_test_fixture::identity(
                kpb::native_terminal::projection_test_fixture::make(1)),
            kpb::native_terminal::projection_test_fixture::identity(
                kpb::native_terminal::projection_test_fixture::make(2))},
    };
}

RunBinding canonical_wire_fixture() {
    RunBinding value{};
    value.classification = Classification::HiddenCandidate;
    unsigned seed = 1;
    const auto next = [&] { return digest(seed++); };
    for (auto* field : {
             &value.comparison_selection, &value.run_selection,
             &value.trial, &value.attempt, &value.cohort, &value.capture,
             &value.method, &value.workload, &value.source_closure,
             &value.runtime})
        *field = next();
    value.finite_manifest.manifest_identity = next();
    value.finite_manifest.parent_recomputation_identity = next();
    for (auto* field : {
             &value.outer_parent_process, &value.outer_parent_executable,
             &value.capture_source, &value.capture_build,
             &value.capture_runtime, &value.capture_launcher})
        *field = next();
    for (unsigned index = 0;
         index < value.finite_manifest.entries.size(); ++index) {
        auto& entry = value.finite_manifest.entries[index];
        entry.component = static_cast<ManifestComponent>(index + 1);
        for (auto* field : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            *field = next();
    }
    for (auto* worker : {
             &value.observer_worker, &value.score_worker,
             &value.aggregate_worker})
        for (auto* field : {
                 &worker->source_identity, &worker->build_identity,
                 &worker->runtime_identity, &worker->assets_identity,
                 &worker->pinned_executable_identity,
                 &worker->launcher_identity})
            *field = next();
    for (auto* values : {
             &value.financial_runs, &value.round_attempts,
             &value.round_cohorts, &value.round_capture_plans,
             &value.projections})
        for (auto& field : *values) field = next();
    assert(seed == 107);
    return value;
}

[[maybe_unused]] void canonical_binding_wire_known_vector() {
    const auto bytes = kpb::measurement::wire::canonical_run_binding_bytes(
        canonical_wire_fixture());
    assert(bytes.size() == kpb::measurement::wire::RUN_BINDING_BYTES);
    assert(hex(sha(bytes)) ==
           "4e8f946c47189e9db77556584218058eab1678c69b5c9bf4721205ffb0f1b591");
}

ParentManifestRecomputationAuthority parent_manifest(
        const RunBinding& selected) {
    return ParentManifestRecomputationAuthority::test_only_mint({
        .manifest = selected.finite_manifest,
        .parent_process_identity = selected.outer_parent_process,
        .parent_executable_identity = selected.outer_parent_executable,
        .recomputation_receipt =
            selected.finite_manifest.parent_recomputation_identity,
    });
}

kpb::capture::Binding capture_binding(const RunBinding& selected,
                                      unsigned round) {
    const auto index = round - 1;
    return {ATTEMPTS[index], hex(selected.round_cohorts[index]),
            hex(selected.financial_runs[index]), CAPTURE_ID,
            hex(selected.projections[index]),
            static_cast<unsigned>(selected.classification),
            hex(selected.attempt),
            hex(selected.round_capture_plans[index])};
}

NativeTerminalSelection native_selection(
        const RunBinding& selected, unsigned ordinal) {
    const unsigned seed = 0x500 + ordinal * 32;
    const Digest input = ordinal == 0 ? digest(0x480) :
        (ordinal == 1 ? digest(0x481) : digest(0x482));
    const Digest successor = ordinal == 0 ? digest(0x481) :
        (ordinal == 1 ? digest(0x482) : digest(0x483));
    const std::uint64_t input_value =
        ordinal == 0 ? 300000 : (ordinal == 1 ? 290000 : 280000);
    return {
        .network = NetworkScope::KaspaTestnet10,
        .kind = static_cast<NativeCandidateKind>(ordinal + 1),
        .ordinal = ordinal,
        .trial = selected.trial,
        .funding_identity = digest(0x490),
        .component_profile = digest(0x491),
        .immutable_tail = digest(0x492),
        .accepted_input_head = input,
        .successor_head = successor,
        .projection = ordinal == 0 ? digest(0x493) :
            selected.projections[ordinal - 1],
        .core = digest(seed), .proof = digest(seed + 1),
        .case_identity = digest(seed + 2),
        .durable_final_checkpoint = digest(seed + 3),
        .signed_case_completion = digest(seed + 4),
        .native_full_completion = digest(seed + 5),
        .r0_completion = digest(seed + 6),
        .value_conservation_completion = digest(seed + 7),
        .input_value_sompi = input_value,
        .successor_value_sompi = input_value - 10000,
        .fee_sompi = 10000,
        .worker = worker(selected.finite_manifest.entries[0]),
        .outer_parent_process = selected.outer_parent_process,
        .outer_parent_executable = selected.outer_parent_executable,
    };
}

PaymentTerminalSelection payment_selection(
        const RunBinding& selected, unsigned round) {
    return {.native = native_selection(selected, round),
            .producer_binding = selected,
            .capture_binding = capture_binding(selected, round)};
}

GenesisTerminalChildResult native_result(
        const NativeTerminalSelection& selected) {
    return {.accepted_input_head = selected.accepted_input_head,
            .successor_head = selected.successor_head,
            .projection = selected.projection,
            .core = selected.core, .proof = selected.proof,
            .case_identity = selected.case_identity,
            .durable_final_checkpoint = selected.durable_final_checkpoint,
            .signed_case_completion = selected.signed_case_completion,
            .native_full_completion = selected.native_full_completion,
            .r0_completion = selected.r0_completion,
            .value_conservation_completion =
                selected.value_conservation_completion,
            .input_value_sompi = selected.input_value_sompi,
            .successor_value_sompi = selected.successor_value_sompi,
            .fee_sompi = selected.fee_sompi};
}

class GenesisProgram final : public GenesisTerminalChildProgram {
    GenesisTerminalChildResult execute(
            const PublicGenesisTerminalOffer& offer) override {
        return native_result(offer.selection);
    }
};

class PaymentProgram final : public PaymentTerminalChildProgram {
    PaymentTerminalChildResult execute(
            const PublicPaymentTerminalOffer& offer,
            kpb::capture::TerminalCaptureV2& terminal,
            NativeTerminalMappingSourceAuthority&& mapping) override {
        auto candidate = terminal.after_candidate_constructed(
            10, hex(offer.native.successor_head),
            hex(offer.native.case_identity));
        auto r0 = terminal.after_r0_verified(
            std::move(candidate), 11, hex(offer.native.r0_completion),
            hex(offer.native.projection));
        auto native = terminal.after_native_full_verified(
            std::move(r0), 12, hex(offer.native.native_full_completion),
            hex(offer.native.case_identity), hex(offer.native.projection));
        auto final = terminal.after_durable_final(
            std::move(native), 13,
            hex(offer.native.durable_final_checkpoint));
        terminal.after_complete_mapping_source(
            final, std::move(mapping));
        auto closed = terminal.after_pre_network_capture_closed(
            std::move(final), 14);
        return PaymentTerminalChildResult(
            native_result(offer.native), std::move(closed));
    }
};

void be64(unsigned char* out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out[index] = static_cast<unsigned char>(value >> (56 - 8 * index));
}
void be32(unsigned char* out, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out[index] = static_cast<unsigned char>(value >> (24 - 8 * index));
}
void event_frame(int fd, unsigned char tag,
                 std::span<const unsigned char> payload) {
    std::array<unsigned char, 17> header{
        'K','P','B','C','E','V','0','1'};
    header[8] = tag;
    be64(header.data() + 9, payload.size());
    write_all(fd, header);
    write_all(fd, payload);
}
void p1_frame(int fd, unsigned char type, unsigned char semantic,
              std::uint64_t monotonic, std::uint64_t sequence,
              std::span<const unsigned char> payload) {
    std::array<unsigned char, 112> header{};
    const std::array<unsigned char, 8> magic{
        'K','P','B','P','1','C','0','3'};
    std::copy(magic.begin(), magic.end(), header.begin());
    header[8] = type; header[9] = semantic; header[10] = 3;
    header[11] = 0xff; header[12] = 3;
    be64(header.data() + 16, monotonic);
    be64(header.data() + 24, sequence);
    be32(header.data() + 44, payload.size());
    const auto payload_digest = sha(payload);
    std::copy(payload_digest.begin(), payload_digest.end(),
              header.begin() + 80);
    write_all(fd, header);
    write_all(fd, payload);
}
void write_event_stream(int fd, CaptureKind kind) {
    std::array<unsigned char, 7> hello{}; hello.fill(0x61);
    event_frame(fd, 1, hello);
    if (kind == CaptureKind::PublicProjection) {
        std::array<unsigned char, 10685> projection{};
        projection.fill(0x62);
        event_frame(fd, 4, projection);
    } else {
        std::array<unsigned char, 8> metadata{}; metadata.fill(0x63);
        std::array<unsigned char, 9> record{}; record.fill(0x64);
        event_frame(fd, 2, metadata);
        event_frame(fd, 3, record);
    }
    event_frame(fd, 5, {});
}
void write_p1_stream(int fd) {
    std::array<unsigned char, 332> hello{}; hello.fill(0x70);
    std::array<unsigned char, 32> data{}; data.fill(0x71);
    std::array<unsigned char, 16> scalar{};
    scalar[0] = 1; scalar[1] = 1; scalar[3] = 2; scalar[11] = 1;
    std::array<unsigned char, 32> seal{}; seal.fill(0x72);
    std::array<unsigned char, 496> completeness{}; completeness.fill(0x73);
    p1_frame(fd, 1, 1, 1, 0, hello);
    p1_frame(fd, 2, 14, 2, 1, data);
    p1_frame(fd, 2, 17, 3, 2, scalar);
    p1_frame(fd, 2, 3, 4, 3, data);
    p1_frame(fd, 2, 4, 5, 4, data);
    p1_frame(fd, 3, 9, 6, 5, seal);
    p1_frame(fd, 4, 9, 7, 6, completeness);
    p1_frame(fd, 5, 9, 8, 7, {});
}

struct PipeSet {
    std::array<int, 10> reads{};
    std::array<int, 10> writes{};
    PipeSet() {
        reads.fill(-1); writes.fill(-1);
        for (unsigned index = 0; index < reads.size(); ++index) {
            int pair[2]{};
            assert(::pipe2(pair, O_CLOEXEC) == 0);
            reads[index] = pair[0]; writes[index] = pair[1];
        }
    }
    ~PipeSet() {
        for (auto& fd : reads) close_fd(fd);
        for (auto& fd : writes) close_fd(fd);
    }
};

enum class Mismatch {
    None, Attempt, Run, Cohort, CapturePlan, Process, ChildExit,
};

enum class ProjectionContinuityFault {
    None, OldCmRoot, OldNfRoot, Counts, Reserve, OldScript, Profile,
    AcceptedOutpointOnly, InvalidCounts,
};

PublicProducerLaunchPlan producer_plan(
        const RunBinding& selected,
        const std::array<PaymentTerminalSelection, 2>& payments,
        Mismatch mismatch) {
    auto producer_binding = selected;
    if (mismatch == Mismatch::Attempt)
        producer_binding.round_attempts[0] = digest(0xa01);
    if (mismatch == Mismatch::Run)
        producer_binding.run_selection = digest(0xee);
    if (mismatch == Mismatch::Cohort)
        producer_binding.round_cohorts[0] = digest(0xa03);
    if (mismatch == Mismatch::CapturePlan)
        producer_binding.round_capture_plans[0] = digest(0xa06);
    PublicProducerLaunchPlan result{
        .binding = producer_binding,
        .capture_trial_id = TRIAL_ID,
        .capture_attempt_ids = {ATTEMPTS[0], ATTEMPTS[1]},
        .producer_process_identity = producer_binding.outer_parent_process,
        .role_closure_identity = producer_binding.source_closure,
        .manifest_seal = producer_binding.finite_manifest.manifest_identity,
        .construction_policy =
            ConstructionPolicy::SecretPermutationIndependent,
        .construction_classification_receipt = digest(0x801),
        .opaque_closure_authority_identity = digest(0x802),
        .route_requirements = {
            PublicAggregateMailboxRouteRequirement{
                .round = 1,
                .projection_identity = producer_binding.projections[0],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true},
            PublicAggregateMailboxRouteRequirement{
                .round = 2,
                .projection_identity = producer_binding.projections[1],
                .projection_bytes = 10685,
                .route_endpoint_count = 1,
                .owner_ack_count = 0,
                .role_blind_required = true,
                .after_full_cohort_barrier_required = true,
                .owner_socket_or_path_derivation_forbidden = true},
        },
    };
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        result.streams[index] = {
            .round = index / 5 + 1,
            .kind = static_cast<CaptureKind>(index % 5 + 1),
            .fixed_fd = 20 + index,
            .process_identity = digest(0x820 + index),
            .child_exit_identity = digest(0x840 + index),
        };
    }
    result.streams[1].process_identity =
        recompute_terminal_stream_process_identity(payments[0]);
    result.streams[1].child_exit_identity =
        recompute_terminal_stream_child_exit_identity(payments[0]);
    result.streams[6].process_identity =
        recompute_terminal_stream_process_identity(payments[1]);
    result.streams[6].child_exit_identity =
        recompute_terminal_stream_child_exit_identity(payments[1]);
    if (mismatch == Mismatch::Process)
        result.streams[1].process_identity = digest(0xa04);
    if (mismatch == Mismatch::ChildExit)
        result.streams[1].child_exit_identity = digest(0xa05);
    return result;
}

std::array<PublicAggregateMailboxRouteCompletion, 2> routes(
        const PublicProducerLaunchPlan& selected) {
    return {
        PublicAggregateMailboxRouteCompletion{
            .round = 1, .route_identity = digest(0x860),
            .full_cohort_barrier_identity = digest(0x861),
            .projection_identity =
                selected.route_requirements[0].projection_identity,
            .projection_bytes = 10685,
            .full_cohort_barrier_observed_monotonic_ns = 10,
            .route_observed_monotonic_ns = 11,
            .route_endpoint_count = 1, .owner_ack_count = 0,
            .role_blind = true, .after_full_cohort_barrier = true,
            .owner_socket_or_path_derived = false},
        PublicAggregateMailboxRouteCompletion{
            .round = 2, .route_identity = digest(0x862),
            .full_cohort_barrier_identity = digest(0x863),
            .projection_identity =
                selected.route_requirements[1].projection_identity,
            .projection_bytes = 10685,
            .full_cohort_barrier_observed_monotonic_ns = 20,
            .route_observed_monotonic_ns = 21,
            .route_endpoint_count = 1, .owner_ack_count = 0,
            .role_blind = true, .after_full_cohort_barrier = true,
            .owner_socket_or_path_derived = false},
    };
}

pid_t start_other_writers(PipeSet& pipes) {
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        for (auto& fd : pipes.reads) close_fd(fd);
        close_fd(pipes.writes[1]);
        close_fd(pipes.writes[6]);
        for (unsigned index = 0; index < pipes.writes.size(); ++index) {
            if (index == 1 || index == 6) continue;
            const auto kind = static_cast<CaptureKind>(index % 5 + 1);
            if (kind == CaptureKind::CorruptServer)
                write_p1_stream(pipes.writes[index]);
            else
                write_event_stream(pipes.writes[index], kind);
            close_fd(pipes.writes[index]);
        }
        _exit(0);
    }
    for (unsigned index = 0; index < pipes.writes.size(); ++index)
        if (index != 1 && index != 6) close_fd(pipes.writes[index]);
    return child;
}

void wait_clean(pid_t child) {
    int status = 0;
    pid_t result;
    do { result = ::waitpid(child, &status, 0); }
    while (result < 0 && errno == EINTR);
    assert(result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

projection_route::PublicProjectionRoutePlan projection_plan(
        const RunBinding& selected, unsigned round) {
    const auto index = round - 1;
    return {
        .classification = registered::CaptureClassification::HiddenCandidate,
        .round = round,
        .computing_role = 0,
        .trial = selected.trial,
        .attempt = selected.attempt,
        .cohort = selected.round_cohorts[index],
        .financial_run = selected.financial_runs[index],
        .capture_plan_identity = selected.round_capture_plans[index],
        .producer_process_authority = digest(0xc00 + round * 16),
        .producer_exit_authority = digest(0xc01 + round * 16),
        .dispatcher_process_authority = digest(0xc02 + round * 16),
        .dispatcher_exit_authority = digest(0xc03 + round * 16),
    };
}

kpb::native_terminal::projection_test_fixture::Projection projection_body(
        unsigned round, ProjectionContinuityFault fault) {
    auto result = kpb::native_terminal::projection_test_fixture::make(round);
    if (round != 2 || fault == ProjectionContinuityFault::None)
        return result;
    auto* prefix = result.data();
    auto* body = result.data() + 193;
    switch (fault) {
    case ProjectionContinuityFault::OldCmRoot:
        body[204] ^= std::byte{1}; break;
    case ProjectionContinuityFault::OldNfRoot:
        body[236] ^= std::byte{1}; break;
    case ProjectionContinuityFault::Counts:
        kpb::native_terminal::projection_test_fixture::put32(body + 268, 8);
        kpb::native_terminal::projection_test_fixture::put32(body + 348, 14);
        break;
    case ProjectionContinuityFault::Reserve:
        kpb::native_terminal::projection_test_fixture::put64(
            prefix + 56, 5'970'000'001ULL);
        kpb::native_terminal::projection_test_fixture::put64(
            body + 276, 5'970'000'001ULL);
        kpb::native_terminal::projection_test_fixture::put64(
            prefix + 105, 5'940'000'001ULL);
        kpb::native_terminal::projection_test_fixture::put64(
            body + 356, 5'940'000'001ULL);
        break;
    case ProjectionContinuityFault::OldScript:
        prefix[70] ^= std::byte{1}; break;
    case ProjectionContinuityFault::Profile:
        body[8] ^= std::byte{1}; break;
    case ProjectionContinuityFault::AcceptedOutpointOnly:
        prefix[12] ^= std::byte{1};
        body[168] ^= std::byte{1};
        break;
    case ProjectionContinuityFault::InvalidCounts:
        kpb::native_terminal::projection_test_fixture::put32(body + 268, 0);
        kpb::native_terminal::projection_test_fixture::put32(body + 348, 6);
        break;
    case ProjectionContinuityFault::None:
        break;
    }
    return result;
}

honest_owner_material::HonestOwnerTwoRoundProductionAuthority
honest_owner_production(
        const RunBinding& selected,
        ProjectionContinuityFault projection_fault =
            ProjectionContinuityFault::None,
        honest_owner_material::HonestOwnerTestFault authority_fault =
            honest_owner_material::HonestOwnerTestFault::None) {
    const std::array<honest_owner_material::Projection10685, 2> projections{
        projection_body(1, ProjectionContinuityFault::None),
        projection_body(2, projection_fault),
    };
    return honest_owner_material::HonestOwnerMaterialTestFixture::two_rounds(
        selected, projections, authority_fault);
}

projection_route::NativeTerminalRetainedProjectionAuthority
retained_projection(
        const RunBinding& selected, unsigned round,
        ProjectionContinuityFault fault = ProjectionContinuityFault::None) {
    const auto plan = projection_plan(selected, round);
    const auto body = projection_body(round, fault);
    assert(kpb::native_terminal::projection_test_fixture::identity(body) ==
           selected.projections[round - 1]);
    auto plan_authority =
        projection_route::ProjectionRoutePlanAuthority::test_only_mint(plan);
    auto endpoints = projection_route::RegisteredProjectionRoute::
        mint_pre_intake(std::move(plan_authority));
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        try {
            auto unused_parent = endpoints.take_parent();
            std::move(unused_parent).discard();
            auto writer = endpoints.take_role0_writer();
            writer.test_only_bind_role0_process(
                0, round, ::getpid(), digest(0xcd1), digest(0xcd2),
                digest(0xcd3), digest(0xcd4));
            auto delivery = projection_route::ProjectionDeliveryAuthority::
                test_only_mint(plan, body);
            (void)projection_route::RegisteredProjectionRoute::
                deliver_after_release(
                    std::move(writer), std::move(delivery));
            _exit(0);
        } catch (...) { _exit(91); }
    }
    auto parent = endpoints.take_parent();
    auto unused_writer = endpoints.take_role0_writer();
    std::move(unused_writer).discard();
    parent.test_only_bind_role0_process(
        0, round, child, digest(0xcd1), digest(0xcd2), digest(0xcd3),
        digest(0xcd4));
    auto retained = projection_route::RegisteredProjectionRoute::
        receive_and_retain(std::move(parent));
    wait_clean(child);
    return projection_route::RegisteredProjectionRoute::
        test_only_transfer_for_native_terminal(std::move(retained));
}

struct CaptureCompletion {
    ProducerClosureAuthority producer;
    std::array<PaymentLifecycleCompletionAuthority, 2> lifecycle;
    kpb::measurement::producer_archive::ProducerSealedArchiveAuthority
        archive;
};

CaptureCompletion complete_capture(
        int executable_fd, const RunBinding& selected,
        Mismatch mismatch = Mismatch::None,
        std::array<TestNativeTerminalFault, 2> faults = {
            TestNativeTerminalFault::None,
            TestNativeTerminalFault::None},
        ProjectionContinuityFault projection_fault =
            ProjectionContinuityFault::None) {
    const std::array<PaymentTerminalSelection, 2> payments{
        payment_selection(selected, 1), payment_selection(selected, 2)};
    const auto plan = producer_plan(selected, payments, mismatch);
    PipeSet pipes;
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        plan, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(read_authority));
    const pid_t writer = start_other_writers(pipes);
    const int round1_writer = pipes.writes[1];
    pipes.writes[1] = -1;
    auto round1 = NativeTerminalSupervisor::test_only_run_payment(
        payments[0], executable_fd, round1_writer,
        retained_projection(selected, 1, projection_fault), faults[0]);
    const int round2_writer = pipes.writes[6];
    pipes.writes[6] = -1;
    auto round2 = NativeTerminalSupervisor::test_only_run_payment(
        payments[1], executable_fd, round2_writer,
        retained_projection(selected, 2, projection_fault), faults[1]);
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(routes(plan));
    auto completion = ParentOwnedCaptureProducer::finish(
        std::move(running), std::move(route_authority));
    wait_clean(writer);
    return {.producer = completion.take_authority(),
            .lifecycle = {std::move(round1), std::move(round2)},
            .archive = completion.take_archive()};
}

void drain_and_close(int& fd) {
    std::array<unsigned char, 4096> buffer{};
    for (;;) {
        ssize_t count;
        do { count = ::read(fd, buffer.data(), buffer.size()); }
        while (count < 0 && errno == EINTR);
        assert(count >= 0);
        if (count == 0) break;
    }
    close_fd(fd);
}

void payment_fault_refuses(
        int executable_fd, const PaymentTerminalSelection& selected,
        TestNativeTerminalFault fault) {
    int pair[2]{};
    assert(::pipe2(pair, O_CLOEXEC) == 0);
    const int writer = pair[1];
    pair[1] = -1;
    expect_refused([&] {
        (void)NativeTerminalSupervisor::test_only_run_payment(
            selected, executable_fd, writer,
            retained_projection(
                selected.producer_binding, selected.native.ordinal),
            fault);
    });
    drain_and_close(pair[0]);
}

template<class Mutator>
void invalid_payment_selection_refuses(
        int executable_fd, PaymentTerminalSelection selected,
        Mutator&& mutate) {
    auto retained = retained_projection(
        selected.producer_binding, selected.native.ordinal);
    mutate(selected);
    int pair[2]{};
    assert(::pipe2(pair, O_CLOEXEC) == 0);
    const int writer = pair[1];
    pair[1] = -1;
    expect_refused([&] {
        (void)NativeTerminalSupervisor::run_payment(
            selected, executable_fd, writer, std::move(retained));
    });
    drain_and_close(pair[0]);
}

[[maybe_unused]] void happy_path(
        int executable_fd, const RunBinding& selected) {
    auto genesis = NativeTerminalSupervisor::run_genesis(
        native_selection(selected, 0), executable_fd);
    assert(genesis.public_receipt().kind == NativeCandidateKind::Genesis);
    auto completed = complete_capture(executable_fd, selected);
    auto matched = std::move(completed.producer).match_native_terminal_streams(
        std::move(completed.lifecycle[0]),
        std::move(completed.lifecycle[1]));
    auto bundle = NativeTerminalProducerJoin::mint_from_matched(
        std::move(matched));
    expect_refused([&] {
        (void)NativeTerminalProducerJoin::mint_from_matched(
            std::move(matched));
    });
    auto native = bundle.take_native();
    assert(native[0].public_receipt().kind ==
               NativeCandidateKind::PaymentRound1 &&
           native[1].public_receipt().kind ==
               NativeCandidateKind::PaymentRound2);
    expect_refused([&] { (void)bundle.take_native(); });
    auto producer = bundle.take_producer();
    auto continuation =
        std::move(producer).transfer_for_native_terminal_join();
    expect_refused([&] {
        (void)std::move(producer).transfer_for_native_terminal_join();
    });
    (void)continuation;
    expect_refused([&] { (void)bundle.take_producer(); });
}

[[maybe_unused]] void authenticated_child_faults_refuse(
        int executable_fd, const RunBinding& selected) {
    const auto payment = payment_selection(selected, 1);
    for (const auto fault : {
             TestNativeTerminalFault::WrongAckOffer,
             TestNativeTerminalFault::CredentialRelay,
             TestNativeTerminalFault::WrongCompletionKind,
             TestNativeTerminalFault::WrongInputHead,
             TestNativeTerminalFault::WrongProjection,
             TestNativeTerminalFault::WrongCore,
             TestNativeTerminalFault::WrongProof,
             TestNativeTerminalFault::WrongR0,
             TestNativeTerminalFault::WrongNativeFull,
             TestNativeTerminalFault::WrongConservation,
             TestNativeTerminalFault::WrongAmounts,
             TestNativeTerminalFault::DuplicateCompletion,
             TestNativeTerminalFault::NoCompletion,
             TestNativeTerminalFault::NonzeroExit,
             TestNativeTerminalFault::ZeroLengthRecordBeforeClose,
             TestNativeTerminalFault::WrongProjectionRoute})
        payment_fault_refuses(executable_fd, payment, fault);

    invalid_payment_selection_refuses(
        executable_fd, payment, [](auto& value) {
            value.native.kind = NativeCandidateKind::PaymentRound2;
        });
    invalid_payment_selection_refuses(
        executable_fd, payment, [](auto& value) {
            value.capture_binding.attempt_id = ATTEMPTS[1];
        });
    invalid_payment_selection_refuses(
        executable_fd, payment, [](auto& value) {
            value.capture_binding.financial_run_id = hex(digest(0xb01));
        });
    invalid_payment_selection_refuses(
        executable_fd, payment, [](auto& value) {
            value.capture_binding.cohort_sha256 = hex(digest(0xb02));
        });
    invalid_payment_selection_refuses(
        executable_fd, payment, [](auto& value) {
            value.producer_binding.round_capture_plans[0] = {};
        });
    invalid_payment_selection_refuses(
        executable_fd, payment, [](auto& value) {
            value.producer_binding.round_capture_plans[1] =
                value.producer_binding.round_capture_plans[0];
        });
    invalid_payment_selection_refuses(
        executable_fd, payment, [](auto& value) {
            ++value.native.successor_value_sompi;
        });
}

[[maybe_unused]] void private_join_counterexamples_refuse(
        int executable_fd, const RunBinding& selected) {
    for (const auto mismatch : {
             Mismatch::Attempt, Mismatch::Run, Mismatch::Cohort,
             Mismatch::CapturePlan, Mismatch::Process,
             Mismatch::ChildExit}) {
        // Attempt identity is part of the producer plan's registered trial
        // binding, so that substitution is now rejected before any child is
        // launched.  The remaining substitutions are well-formed producer
        // plans and are rejected by the terminal-stream join below.
        if (mismatch == Mismatch::Attempt) {
            expect_refused([&] {
                (void)complete_capture(executable_fd, selected, mismatch);
            });
            continue;
        }
        auto completed = complete_capture(executable_fd, selected, mismatch);
        expect_refused([&] {
            (void)std::move(completed.producer)
                .match_native_terminal_streams(
                    std::move(completed.lifecycle[0]),
                    std::move(completed.lifecycle[1]));
        });
    }
    for (const auto fault : {
             TestNativeTerminalFault::WrongTerminalRoot,
             TestNativeTerminalFault::WrongTerminalEnd,
             TestNativeTerminalFault::WrongTerminalCount}) {
        auto completed = complete_capture(
            executable_fd, selected, Mismatch::None,
            {fault, TestNativeTerminalFault::None});
        expect_refused([&] {
            (void)std::move(completed.producer)
                .match_native_terminal_streams(
                    std::move(completed.lifecycle[0]),
                    std::move(completed.lifecycle[1]));
        });
    }
    {
        auto completed = complete_capture(executable_fd, selected);
        expect_refused([&] {
            (void)std::move(completed.producer)
                .match_native_terminal_streams(
                    std::move(completed.lifecycle[1]),
                    std::move(completed.lifecycle[0]));
        });
    }
    {
        auto completed = complete_capture(executable_fd, selected);
        auto retained = std::move(completed.lifecycle[0]);
        expect_refused([&] {
            (void)std::move(completed.producer)
                .match_native_terminal_streams(
                    std::move(completed.lifecycle[0]),
                    std::move(completed.lifecycle[1]));
        });
        (void)retained;
    }
    {
        auto completed = complete_capture(executable_fd, selected);
        auto retained = std::move(completed.producer)
            .transfer_for_native_terminal_join();
        expect_refused([&] {
            (void)std::move(completed.producer)
                .match_native_terminal_streams(
                    std::move(completed.lifecycle[0]),
                    std::move(completed.lifecycle[1]));
        });
        (void)retained;
    }
}

[[maybe_unused]] void terminal_model_admission_is_linear(
        int executable_fd, const RunBinding& selected) {
    auto completed = complete_capture(executable_fd, selected);
    auto matched = std::move(completed.producer).match_native_terminal_streams(
        std::move(completed.lifecycle[0]),
        std::move(completed.lifecycle[1]));
    auto honest_owner = honest_owner_production(selected);
    auto admission = std::move(matched).transfer_for_terminal_v2_model(
        std::move(honest_owner));
    expect_refused([&] {
        (void)std::move(matched).transfer_for_terminal_v2_model(
            std::move(honest_owner));
    });
    auto retained = std::move(admission);
    (void)retained;
}

[[maybe_unused]] void observer_terminal_model_join_is_linear(
        int executable_fd, const RunBinding& selected) {
    static_assert(!std::is_default_constructible_v<
                  ObserverTerminalCaptureJoin>);
    static_assert(!std::is_copy_constructible_v<
                  ObserverTerminalCaptureJoin>);
    static_assert(std::is_move_constructible_v<
                  ObserverTerminalCaptureJoin>);

    auto completed = complete_capture(executable_fd, selected);
    auto matched = std::move(completed.producer).match_native_terminal_streams(
        std::move(completed.lifecycle[0]),
        std::move(completed.lifecycle[1]));
    auto honest_owner = honest_owner_production(selected);
    auto terminal = std::move(matched).transfer_for_terminal_v2_model(
        std::move(honest_owner));
    auto observer = ObserverAdmissionAuthority::test_only_mint(selected);
    auto joined = ObserverCaptureCapsuleBridge::attach_terminal_v2(
        std::move(observer), std::move(terminal));
    expect_refused([&] {
        (void)ObserverCaptureCapsuleBridge::attach_terminal_v2(
            std::move(observer), std::move(terminal));
    });

    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    joiner.submit(std::move(joined));
    expect_refused([&] { joiner.submit(std::move(joined)); });

    auto other = selected;
    other.trial = digest(0x7f1);
    auto other_completed = complete_capture(executable_fd, selected);
    auto other_matched =
        std::move(other_completed.producer).match_native_terminal_streams(
            std::move(other_completed.lifecycle[0]),
            std::move(other_completed.lifecycle[1]));
    auto other_honest_owner = honest_owner_production(selected);
    auto other_terminal =
        std::move(other_matched).transfer_for_terminal_v2_model(
            std::move(other_honest_owner));
    auto wrong_observer = ObserverAdmissionAuthority::test_only_mint(other);
    expect_refused([&] {
        (void)ObserverCaptureCapsuleBridge::attach_terminal_v2(
            std::move(wrong_observer), std::move(other_terminal));
    });
    expect_refused([&] {
        (void)ObserverCaptureCapsuleBridge::attach_terminal_v2(
            std::move(wrong_observer), std::move(other_terminal));
    });
}

[[maybe_unused]] void honest_owner_authority_counterexamples_refuse(
        int executable_fd, const RunBinding& selected) {
    for (const auto fault : {
             honest_owner_material::HonestOwnerTestFault::WrongRound,
             honest_owner_material::HonestOwnerTestFault::WrongOwner,
             honest_owner_material::HonestOwnerTestFault::WrongNullifier,
             honest_owner_material::HonestOwnerTestFault::WrongOutputRow,
             honest_owner_material::HonestOwnerTestFault::WrongProjection,
             honest_owner_material::HonestOwnerTestFault::WrongRunBinding}) {
        auto completed = complete_capture(executable_fd, selected);
        auto matched =
            std::move(completed.producer).match_native_terminal_streams(
                std::move(completed.lifecycle[0]),
                std::move(completed.lifecycle[1]));
        auto honest_owner = honest_owner_production(
            selected, ProjectionContinuityFault::None, fault);
        expect_refused([&] {
            (void)std::move(matched).transfer_for_terminal_v2_model(
                std::move(honest_owner));
        });
        expect_refused([&] {
            (void)std::move(matched).transfer_for_terminal_v2_model(
                std::move(honest_owner));
        });
    }
}

[[maybe_unused]] void structural_projection_continuity_is_narrow(
        int executable_fd, const RunBinding& selected) {
    for (const auto fault : {
             ProjectionContinuityFault::OldCmRoot,
             ProjectionContinuityFault::OldNfRoot,
             ProjectionContinuityFault::Counts,
             ProjectionContinuityFault::Reserve,
             ProjectionContinuityFault::OldScript,
             ProjectionContinuityFault::Profile}) {
        auto changed = selected;
        changed.projections[1] =
            kpb::native_terminal::projection_test_fixture::identity(
                projection_body(2, fault));
        auto completed = complete_capture(
            executable_fd, changed, Mismatch::None,
            {TestNativeTerminalFault::None,
             TestNativeTerminalFault::None}, fault);
        auto matched =
            std::move(completed.producer).match_native_terminal_streams(
                std::move(completed.lifecycle[0]),
                std::move(completed.lifecycle[1]));
        expect_refused([&] {
            auto honest_owner = honest_owner_production(changed, fault);
            (void)std::move(matched).transfer_for_terminal_v2_model(
                std::move(honest_owner));
        });
    }

    // A changed accepted reserve outpoint is bound into the exact R2
    // projection, but projection-only evidence cannot prove or disprove that
    // native history accepted it. Structural continuity may still exist; the
    // resulting private residual is explicitly non-accepted-chain authority.
    auto changed = selected;
    changed.projections[1] =
        kpb::native_terminal::projection_test_fixture::identity(
            projection_body(
                2, ProjectionContinuityFault::AcceptedOutpointOnly));
    auto completed = complete_capture(
        executable_fd, changed, Mismatch::None,
        {TestNativeTerminalFault::None,
         TestNativeTerminalFault::None},
        ProjectionContinuityFault::AcceptedOutpointOnly);
    auto matched = std::move(completed.producer).match_native_terminal_streams(
        std::move(completed.lifecycle[0]),
        std::move(completed.lifecycle[1]));
    auto honest_owner = honest_owner_production(
        changed, ProjectionContinuityFault::AcceptedOutpointOnly);
    auto structural_only =
        std::move(matched).transfer_for_terminal_v2_model(
            std::move(honest_owner));
    (void)structural_only;

    // Structural parsing happens before the sealed native child starts. The
    // terminal writer is still owned and closed on refusal, so the sole reader
    // observes EOF instead of hanging on malformed projection bytes.
    auto invalid = selected;
    invalid.projections[1] =
        kpb::native_terminal::projection_test_fixture::identity(
            projection_body(2, ProjectionContinuityFault::InvalidCounts));
    auto payment = payment_selection(invalid, 2);
    int pair[2]{};
    assert(::pipe2(pair, O_CLOEXEC) == 0);
    const int writer = pair[1]; pair[1] = -1;
    expect_refused([&] {
        (void)NativeTerminalSupervisor::run_payment(
            payment, executable_fd, writer,
            retained_projection(
                invalid, 2, ProjectionContinuityFault::InvalidCounts));
    });
    drain_and_close(pair[0]);
}

[[maybe_unused]] void producer_partition_counterexamples_refuse(
        const RunBinding& selected) {
    const std::array<PaymentTerminalSelection, 2> payments{
        payment_selection(selected, 1), payment_selection(selected, 2)};
    for (unsigned mode = 0; mode < 2; ++mode) {
        PipeSet pipes;
        auto plan = producer_plan(selected, payments, Mismatch::None);
        if (mode == 0) plan.streams[1].fixed_fd = 22;
        else plan.streams[1].kind = CaptureKind::Dispatcher;
        expect_refused([&] {
            (void)ParentTenReadEndsAuthority::test_only_mint(
                plan, std::move(pipes.reads));
        });
        pipes.reads.fill(-1);
    }
}

#ifdef KPB_NATIVE_TERMINAL_ARCHIVE_INTEGRATION_TEST_SETUP

using kpb::measurement::c1_capture::C1PostcaptureAdmissionAuthority;
using kpb::measurement::producer_supervisor::C03RoleLaunchRoundBinding;
namespace observer_schema =
    kpb::measurement::runtime_bridge::observer_spool_schema;
namespace structural_schema =
    kpb::measurement::runtime_bridge::
        structural_continuity_section_schema;

void append_little(std::vector<unsigned char>& out, std::uint64_t value,
                   unsigned width) {
    for (unsigned index = 0; index < width; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

std::vector<unsigned char> canonical_worker_archive(
        bool source, std::span<const unsigned char> content) {
    constexpr std::array<unsigned char, 8> source_magic{
        'K', 'P', 'B', 'S', 'R', 'C', '1', 0};
    constexpr std::array<unsigned char, 8> asset_magic{
        'K', 'P', 'B', 'A', 'S', 'T', '1', 0};
    constexpr std::array<unsigned char, 10> path{
        'w', 'o', 'r', 'k', 'e', 'r', '.', 'b', 'i', 'n'};
    std::vector<unsigned char> result;
    const auto& magic = source ? source_magic : asset_magic;
    result.insert(result.end(), magic.begin(), magic.end());
    append_little(result, 1, 4);
    append_little(result, path.size(), 2);
    append_little(result, content.size(), 8);
    result.insert(result.end(), path.begin(), path.end());
    const auto content_identity = sha(content);
    result.insert(result.end(), content_identity.begin(),
                  content_identity.end());
    result.insert(result.end(), content.begin(), content.end());
    return result;
}

int memory_file(std::span<const unsigned char> bytes) {
    const int fd = ::memfd_create(
        "kpb-native-terminal-worker-file",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(fd >= 0);
    write_all(fd, bytes);
    return fd;
}

struct CapsuleFiles final {
    int runtime{-1};
    int source{-1};
    int assets{-1};
    explicit CapsuleFiles(const char* runtime_path) {
        runtime = ::open(runtime_path, O_RDONLY | O_CLOEXEC);
        assert(runtime >= 0);
        const std::array<unsigned char, 3> source_content{1, 2, 3};
        const std::array<unsigned char, 3> asset_content{4, 5, 6};
        const auto source_bytes = canonical_worker_archive(
            true, source_content);
        const auto asset_bytes = canonical_worker_archive(
            false, asset_content);
        source = memory_file(source_bytes);
        assets = memory_file(asset_bytes);
    }
    CapsuleFiles(const CapsuleFiles&) = delete;
    CapsuleFiles& operator=(const CapsuleFiles&) = delete;
    ~CapsuleFiles() {
        close_fd(runtime); close_fd(source); close_fd(assets);
    }
};

RunBinding observer_ready_binding(
        const Digest& executable, const CapsuleFiles& files) {
    auto result = binding(executable);
    const auto observer = recompute_native_worker_binding(
        RuntimeChildRole::Observer, hash_fd(files.runtime),
        hash_fd(files.source), hash_fd(files.assets));
    auto& manifest = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1];
    assert(manifest.component == ManifestComponent::Observer);
    manifest.source_identity = observer.source_identity;
    manifest.build_identity = observer.build_identity;
    manifest.runtime_identity = observer.runtime_identity;
    manifest.assets_identity = observer.assets_identity;
    manifest.pinned_executable_identity =
        observer.pinned_executable_identity;
    manifest.launcher_identity = observer.launcher_identity;
    result.observer_worker = observer;
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(
            result.finite_manifest.entries);
    return result;
}

std::array<C03RoleLaunchRoundBinding, 2> c03_rounds_for(
        const RunBinding& selected,
        const PublicProducerClosure& closure) {
    std::array<C03RoleLaunchRoundBinding, 2> result{};
    for (unsigned index = 0; index < result.size(); ++index) {
        const auto& stream = closure.streams[index * 5 + 3];
        result[index] = {
            .round = index + 1,
            .fixed_fd = 23 + 5 * index,
            .financial_run = selected.financial_runs[index],
            .attempt = selected.round_attempts[index],
            .cohort = selected.round_cohorts[index],
            .capture_plan = selected.round_capture_plans[index],
            .projection = selected.projections[index],
            .source_identity = stream.source_identity,
            .build_identity = stream.build_identity,
            .runtime_identity = stream.runtime_identity,
            .launcher_identity = stream.launcher_identity,
            .process_identity = stream.process_identity,
            .child_exit_identity = stream.child_exit_identity,
            .model_preimage_identity = digest(0xd0 + index * 3),
            .query_store_preimage_identity = digest(0xd1 + index * 3),
            .scalar_capture_manifest_identity = digest(0xd2 + index * 3),
        };
    }
    return result;
}

C1PostcaptureAdmissionAuthority c1_for(
        const RunBinding& selected,
        const PublicProducerClosure& closure, unsigned round) {
    const unsigned index = round - 1;
    const auto& stream = closure.streams[index * 5 + 4];
    const auto base = 0xe0 + index * 16;
    return C1PostcaptureAdmissionAuthority::test_only_mint(
        selected, round, 24 + 5 * index,
        digest(base), selected.source_closure, digest(base + 1),
        digest(base + 2), digest(base + 3), stream.process_identity,
        stream.child_exit_identity,
        worker(selected.finite_manifest.entries[
            static_cast<unsigned>(ManifestComponent::C1Supervisor) - 1]),
        {0, 2, 0},
        {digest(base + 4), digest(base + 5), digest(base + 6)});
}

PartyCompletionAuthority party_completion(
        const RunBinding& selected, unsigned round, unsigned role) {
    const unsigned common = 0x20 + round * 16;
    const unsigned unique = 0x80 + round * 16 + role * 4;
    return PartyCompletionAuthority::test_only_mint({
        .binding = selected,
        .round = round,
        .role = role,
        .financial_run = selected.financial_runs[round - 1],
        .trial = selected.trial,
        .attempt = selected.round_attempts[round - 1],
        .cohort = selected.round_cohorts[round - 1],
        .child_exit = digest(unique),
        .driver_completion = digest(unique + 1),
        .selection_identity = digest(common),
        .proposal_identity = digest(unique + 2),
        .accepted_head = digest(common + 1),
        .postlock_accepted_head = digest(common + 1),
        .durable_lock = digest(common + 2),
        .capture_source = selected.capture_source,
        .capture_build = selected.capture_build,
        .capture_runtime = selected.capture_runtime,
        .capture_launcher = selected.capture_launcher,
        .process_identity = digest(unique + 3),
        .egress = digest(common + 3),
        .proof = digest(common + 4),
        .projection = selected.projections[round - 1],
    });
}

ObserverPermitAuthority genuine_observer_permit(
        int executable_fd, const RunBinding& selected) {
    auto completed = complete_capture(executable_fd, selected);
    const auto closure = completed.producer.public_receipt();
    auto c03 = ObserverCaptureCapsuleBridge::test_only_c03_for_producer(
        completed.producer, c03_rounds_for(selected, closure));
    auto observer = ObserverCaptureCapsuleBridge::admit(
        std::move(completed.archive), std::move(c03),
        c1_for(selected, closure, 1), c1_for(selected, closure, 2));
    auto matched = std::move(completed.producer).match_native_terminal_streams(
        std::move(completed.lifecycle[0]),
        std::move(completed.lifecycle[1]));
    auto honest_owner = honest_owner_production(selected);
    auto terminal = std::move(matched).transfer_for_terminal_v2_model(
        std::move(honest_owner));
    auto joined = ObserverCaptureCapsuleBridge::attach_terminal_v2(
        std::move(observer), std::move(terminal));
    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    joiner.submit(std::move(joined));
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            joiner.submit(party_completion(selected, round, role));
    RunMeasurement measurement(joiner.finish());
    return measurement.issue_observer();
}

std::vector<unsigned char> read_file(int fd) {
    struct stat status{};
    assert(::fstat(fd, &status) == 0 && status.st_size > 0);
    std::vector<unsigned char> result(
        static_cast<std::size_t>(status.st_size));
    std::size_t at = 0;
    while (at < result.size()) {
        ssize_t count;
        do {
            count = ::pread(fd, result.data() + at,
                            result.size() - at,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return result;
}

std::uint64_t read_little(
        std::span<const unsigned char> bytes, std::size_t offset,
        unsigned width) {
    assert(offset + width <= bytes.size() && width <= 8);
    std::uint64_t result = 0;
    for (unsigned index = 0; index < width; ++index)
        result |= static_cast<std::uint64_t>(bytes[offset + index]) <<
            (8 * index);
    return result;
}

void verify_snapshot(int fd, const RunBinding& selected) {
    constexpr std::size_t binding_offset = 8 + 4 + 32 + 32;
    constexpr std::size_t closure_metadata_bytes =
        32 + 32 + 6 * 32 + 32 + 32 + 1 + 4 * 32 + 3 * 4;
    constexpr std::size_t c03_metadata_bytes =
        2 * (2 + 14 * 32);
    constexpr std::size_t c1_metadata_bytes =
        2 * (2 + 7 * 32 + 6 * 32 + 3 + 3 * 32);
    constexpr std::size_t structural_offset =
        binding_offset + kpb::measurement::wire::RUN_BINDING_BYTES +
        closure_metadata_bytes + c03_metadata_bytes + c1_metadata_bytes;
    static_assert(binding_offset == 76);
    static_assert(structural_offset == 5874);
    constexpr std::size_t leaf_count_offset =
        structural_offset + structural_schema::SECTION_BYTES;
    constexpr int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert((::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY);
    assert((::fcntl(fd, F_GET_SEALS) & required_seals) == required_seals);
    const auto bytes = read_file(fd);
    assert(bytes.size() > leaf_count_offset);
    assert(std::equal(observer_schema::MAGIC.begin(),
                      observer_schema::MAGIC.end(), bytes.begin()));
    assert(read_little(bytes, 8, 4) == observer_schema::VERSION);
    const auto binding_bytes =
        kpb::measurement::wire::canonical_run_binding_bytes(selected);
    assert(std::equal(binding_bytes.begin(), binding_bytes.end(),
                      bytes.begin() + binding_offset));
    assert(std::equal(structural_schema::MAGIC.begin(),
                      structural_schema::MAGIC.end(),
                      bytes.begin() + structural_offset));
    assert(read_little(bytes, structural_offset + 8, 4) ==
           structural_schema::VERSION);
    assert(read_little(bytes, structural_offset + 12, 4) ==
           structural_schema::SECTION_BYTES);
    assert(bytes[structural_offset + structural_schema::FLAGS_OFFSET] ==
           static_cast<unsigned char>(selected.classification));
    assert(bytes[structural_offset + structural_schema::FLAGS_OFFSET + 1] ==
           1);
    assert(bytes[structural_offset + structural_schema::FLAGS_OFFSET + 2] ==
           0);
    assert(bytes[structural_offset + structural_schema::FLAGS_OFFSET + 3] ==
           structural_schema::ROUND_COUNT);
    assert(std::any_of(
        bytes.begin() + structural_offset +
            structural_schema::IDENTITY_OFFSET,
        bytes.begin() + structural_offset +
            structural_schema::IDENTITY_OFFSET + 32,
        [](unsigned char value) { return value != 0; }));
    assert(bytes[leaf_count_offset] == observer_schema::LEAF_COUNT);

    std::size_t at = leaf_count_offset + 1;
    for (unsigned index = 0; index < observer_schema::LEAF_COUNT; ++index) {
        constexpr std::size_t leaf_header_bytes =
            4 + 6 * 32 + 3 + 3 * 32 + 3 * 8;
        assert(at + leaf_header_bytes <= bytes.size());
        assert(bytes[at] == index / 5 + 1);
        assert(bytes[at + 1] == index % 5 + 1);
        assert(bytes[at + 2] == 20 + index);
        assert(bytes[at + 4 + 6 * 32] == 1 &&
               bytes[at + 4 + 6 * 32 + 1] == 1 &&
               bytes[at + 4 + 6 * 32 + 2] == 1);
        const auto raw_bytes = read_little(
            bytes, at + leaf_header_bytes - 8, 8);
        assert(raw_bytes > 0 && at + leaf_header_bytes + raw_bytes <=
               bytes.size());
        const auto raw_at = at + leaf_header_bytes;
        if (index % 5 == 3) {
            constexpr std::array<unsigned char, 8> p1_magic{
                'K', 'P', 'B', 'P', '1', 'C', '0', '3'};
            assert(std::equal(p1_magic.begin(), p1_magic.end(),
                              bytes.begin() + raw_at));
        } else {
            constexpr std::array<unsigned char, 8> event_magic{
                'K', 'P', 'B', 'C', 'E', 'V', '0', '1'};
            assert(std::equal(event_magic.begin(), event_magic.end(),
                              bytes.begin() + raw_at));
        }
        at += leaf_header_bytes + static_cast<std::size_t>(raw_bytes);
    }
    assert(at == bytes.size());
}

void genuine_archive_terminal_snapshot_is_exact(
        int executable_fd, const char* runtime_path) {
    CapsuleFiles files(runtime_path);
    const auto selected = observer_ready_binding(
        hash_fd(executable_fd), files);
    auto permit = genuine_observer_permit(executable_fd, selected);
    int snapshot = ObserverCaptureCapsuleBridge::test_only_prepare_archive(
        std::move(permit));
    verify_snapshot(snapshot, selected);
    close_fd(snapshot);
    expect_refused([&] {
        (void)ObserverCaptureCapsuleBridge::test_only_prepare_archive(
            std::move(permit));
    });
}

void genuine_archive_production_prepare_controls(
        int executable_fd, const char* runtime_path) {
    {
        CapsuleFiles files(runtime_path);
        const auto selected = observer_ready_binding(
            hash_fd(executable_fd), files);
        auto permit = genuine_observer_permit(executable_fd, selected);
        auto handoff = ObserverCaptureCapsuleBridge::prepare(
            std::move(permit), files.runtime, files.source, files.assets);
        const auto& public_permit = permit.public_receipt();
        assert(public_permit.binding == selected);
        auto execution = handoff.take_execution_permit();
        auto capsule = handoff.take_worker_capsule();
        assert(execution.public_receipt().binding == selected);
        assert(capsule.public_receipt().worker == selected.observer_worker);
        assert(capsule.public_receipt().role == RuntimeChildRole::Observer);
        assert(capsule.public_receipt().input_count == 1);
        capsule.test_only_verify_seals_and_read_only();
        expect_refused([&] { (void)handoff.take_execution_permit(); });
        expect_refused([&] { (void)handoff.take_worker_capsule(); });
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::prepare(
                std::move(permit), files.runtime, files.source,
                files.assets);
        });
    }

    for (unsigned fault = 0; fault < 3; ++fault) {
        CapsuleFiles files(runtime_path);
        const auto selected = observer_ready_binding(
            hash_fd(executable_fd), files);
        auto permit = genuine_observer_permit(executable_fd, selected);
        int wrong = -1;
        if (fault == 0) {
            wrong = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
        } else {
            const std::array<unsigned char, 3> content{
                7, 8, static_cast<unsigned char>(9 + fault)};
            const auto bytes = canonical_worker_archive(
                fault == 1, content);
            wrong = memory_file(bytes);
        }
        assert(wrong >= 0);
        const int runtime = fault == 0 ? wrong : files.runtime;
        const int source = fault == 1 ? wrong : files.source;
        const int assets = fault == 2 ? wrong : files.assets;
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::prepare(
                std::move(permit), runtime, source, assets);
        });
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::prepare(
                std::move(permit), files.runtime, files.source,
                files.assets);
        });
        close_fd(wrong);
    }
}

#endif

} // namespace

namespace kpb::native_terminal::test_fixture {

std::optional<int> run_selected_child() {
    if (const char* mode = std::getenv("KPB_NATIVE_TERMINAL_CHILD")) {
        if (std::string(mode) == "GENESIS") {
            GenesisProgram program;
            return std::optional<int>(
                test_only_run_genesis_terminal_child(program));
        }
        if (std::string(mode) == "PAYMENT") {
            PaymentProgram program;
            return std::optional<int>(
                test_only_run_payment_terminal_child(program));
        }
        return std::optional<int>(77);
    }
    return std::nullopt;
}

GenuineCandidateAuthorities complete_genuine_candidate_authorities() {
    int executable = sealed_self();
    const auto selected = binding(hash_fd(executable));
    auto genesis = NativeTerminalSupervisor::run_genesis(
        native_selection(selected, 0), executable);
    auto completed = complete_capture(executable, selected);
    auto matched = std::move(completed.producer).match_native_terminal_streams(
        std::move(completed.lifecycle[0]),
        std::move(completed.lifecycle[1]));
    auto bundle = NativeTerminalProducerJoin::mint_from_matched(
        std::move(matched));
    auto payments = bundle.take_native();
    auto producer = bundle.take_producer();
    close_fd(executable);
    return {.binding = selected, .genesis = std::move(genesis),
            .payments = std::move(payments),
            .producer_continuation = std::move(producer)};
}

} // namespace kpb::native_terminal::test_fixture

#ifndef KPB_NATIVE_TERMINAL_FIXTURE_NO_MAIN
int main(int argc, char** argv) {
    if (const auto child =
            kpb::native_terminal::test_fixture::run_selected_child())
        return *child;
    int executable = sealed_self();
    const auto selected = binding(hash_fd(executable));
    canonical_binding_wire_known_vector();
    happy_path(executable, selected);
    authenticated_child_faults_refuse(executable, selected);
    private_join_counterexamples_refuse(executable, selected);
    terminal_model_admission_is_linear(executable, selected);
    observer_terminal_model_join_is_linear(executable, selected);
    honest_owner_authority_counterexamples_refuse(executable, selected);
    structural_projection_continuity_is_narrow(executable, selected);
    producer_partition_counterexamples_refuse(selected);
#ifdef KPB_NATIVE_TERMINAL_ARCHIVE_INTEGRATION_TEST_SETUP
    assert(argc == 2);
    genuine_archive_terminal_snapshot_is_exact(executable, argv[1]);
    genuine_archive_production_prepare_controls(executable, argv[1]);
#else
    (void)argc; (void)argv;
#endif
    close_fd(executable);
    return 0;
}
#endif
