#include "privacy_capture_producer_runtime.hpp"
#include "privacy_capture_producer_archive.hpp"
#include "privacy_all_branch_fresh_trial_owner_authority.hpp"
#include "../mpc-prover/financial/registered_fresh_trial_history_ledger.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <openssl/sha.h>
#include <new>
#include <span>
#include <string_view>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::producer_runtime;
namespace attempt_history =
    kpi::mpc::financial::registered_driver::attempt_history;
namespace registered_driver = kpi::mpc::financial::registered_driver;

namespace {
std::atomic_bool runtime_fail_allocation{false};
}

void* operator new(std::size_t size) {
    if (runtime_fail_allocation.load()) throw std::bad_alloc();
    if (void* value = std::malloc(size)) return value;
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete[](void* value, std::size_t) noexcept {
    std::free(value);
}

namespace {

constexpr std::string_view CAPTURE_TRIAL_ID =
    "6f87aef8-106f-4d0f-9ee8-35ab56885be7";
constexpr std::array<std::string_view, 2> CAPTURE_ATTEMPT_IDS{
    "a3647d17-b5d7-46bc-86ac-8421f93cdb46",
    "7be6fa9e-1604-4d30-bc1d-29553a8b4607",
};

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest sha256(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest text_identity(std::string_view domain, std::string_view value) {
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    bytes.insert(bytes.end(), value.begin(), value.end());
    return sha256(bytes);
}

Digest trial_identity(std::string_view value) {
    constexpr std::string_view domain =
        "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n";
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    const auto size = static_cast<std::uint64_t>(value.size());
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<unsigned char>(size >> shift));
    bytes.insert(bytes.end(), value.begin(), value.end());
    return sha256(bytes);
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

RunBinding binding() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0xb0 + index * 6);
        entries[index] = ManifestEntry{
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(static_cast<unsigned char>(seed + 1)),
            .runtime_identity = digest(static_cast<unsigned char>(seed + 2)),
            .assets_identity = digest(static_cast<unsigned char>(seed + 3)),
            .pinned_executable_identity =
                digest(static_cast<unsigned char>(seed + 4)),
            .launcher_identity = digest(static_cast<unsigned char>(seed + 5)),
        };
    }
    FiniteManifestBinding manifest{
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest(0xaf),
        .entries = entries,
    };
    const auto& capture = manifest.entries[1];
    return RunBinding{
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest(0x10),
        .run_selection = digest(0x11),
        .trial = trial_identity(CAPTURE_TRIAL_ID),
        .attempt = digest(0x13),
        .cohort = digest(0x14),
        .capture = digest(0x15),
        .method = digest(0x16),
        .workload = digest(0x17),
        .source_closure = digest(0x18),
        .runtime = digest(0x19),
        .finite_manifest = manifest,
        .outer_parent_process = digest(0x1a),
        .outer_parent_executable = digest(0x1b),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(manifest.entries[6]),
        .score_worker = worker(manifest.entries[7]),
        .aggregate_worker = worker(manifest.entries[8]),
        .financial_runs = {digest(0x20), digest(0x21)},
        .round_attempts = {
            text_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n",
                          CAPTURE_ATTEMPT_IDS[0]),
            text_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n",
                          CAPTURE_ATTEMPT_IDS[1]),
        },
        .round_cohorts = {digest(0x24), digest(0x25)},
        .round_capture_plans = {digest(0x26), digest(0x27)},
        .projections = {digest(0x28), digest(0x29)},
    };
}

PublicProducerLaunchPlan plan() {
    const auto selected = binding();
    PublicProducerLaunchPlan result{
        .binding = selected,
        .capture_trial_id = std::string(CAPTURE_TRIAL_ID),
        .capture_attempt_ids = {
            std::string(CAPTURE_ATTEMPT_IDS[0]),
            std::string(CAPTURE_ATTEMPT_IDS[1]),
        },
        .producer_process_identity = selected.outer_parent_process,
        .role_closure_identity = selected.source_closure,
        .manifest_seal = selected.finite_manifest.manifest_identity,
        .construction_policy =
            ConstructionPolicy::SecretPermutationIndependent,
        .construction_classification_receipt = digest(0x30),
        .opaque_closure_authority_identity = digest(0x35),
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
        result.streams[index] = PublicProducerStreamPlan{
            .round = index / 5 + 1,
            .kind = static_cast<CaptureKind>(index % 5 + 1),
            .fixed_fd = 20 + index,
            .process_identity =
                digest(static_cast<unsigned char>(0x40 + index)),
            .child_exit_identity =
                digest(static_cast<unsigned char>(0x50 + index)),
        };
    }
    return result;
}

std::array<PublicAggregateMailboxRouteCompletion, 2> routes(
        const PublicProducerLaunchPlan& selected) {
    return {
        PublicAggregateMailboxRouteCompletion{
            .round = 1,
            .route_identity = digest(0x31),
            .full_cohort_barrier_identity = digest(0x33),
            .projection_identity =
                selected.route_requirements[0].projection_identity,
            .projection_bytes = 10685,
            .full_cohort_barrier_observed_monotonic_ns = 10,
            .route_observed_monotonic_ns = 11,
            .route_endpoint_count = 1,
            .owner_ack_count = 0,
            .role_blind = true,
            .after_full_cohort_barrier = true,
            .owner_socket_or_path_derived = false,
        },
        PublicAggregateMailboxRouteCompletion{
            .round = 2,
            .route_identity = digest(0x32),
            .full_cohort_barrier_identity = digest(0x34),
            .projection_identity =
                selected.route_requirements[1].projection_identity,
            .projection_bytes = 10685,
            .full_cohort_barrier_observed_monotonic_ns = 20,
            .route_observed_monotonic_ns = 21,
            .route_endpoint_count = 1,
            .owner_ack_count = 0,
            .role_blind = true,
            .after_full_cohort_barrier = true,
            .owner_socket_or_path_derived = false,
        },
    };
}

void close_fd(int& fd) {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
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
    Digest payload_digest{};
    assert(SHA256(payload.data(), payload.size(), payload_digest.data()));
    std::copy(payload_digest.begin(), payload_digest.end(),
              header.begin() + 80);
    write_all(fd, header);
    write_all(fd, payload);
}

enum class InvalidStream { None, MissingEnd, BytesAfterEnd, WrongRole };

void write_event_stream(int fd, CaptureKind kind, InvalidStream invalid) {
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
    if (invalid != InvalidStream::MissingEnd) event_frame(fd, 5, {});
    if (invalid == InvalidStream::BytesAfterEnd) {
        const std::array<unsigned char, 1> trailing{0xff};
        write_all(fd, trailing);
    }
}

void write_p1_stream(int fd) {
    std::array<unsigned char, 332> hello{}; hello.fill(0x70);
    std::array<unsigned char, 32> data{}; data.fill(0x71);
    std::array<unsigned char, 16> scalar_binding{};
    scalar_binding[0] = 1;
    scalar_binding[1] = 1;
    scalar_binding[3] = 2;
    scalar_binding[11] = 1;
    std::array<unsigned char, 32> seal{}; seal.fill(0x72);
    std::array<unsigned char, 496> completeness{}; completeness.fill(0x73);
    p1_frame(fd, 1, 1, 1, 0, hello);
    p1_frame(fd, 2, 14, 2, 1, data);
    p1_frame(fd, 2, 17, 3, 2, scalar_binding);
    p1_frame(fd, 2, 3, 4, 3, data);
    p1_frame(fd, 2, 4, 5, 4, data);
    p1_frame(fd, 3, 9, 6, 5, seal);
    p1_frame(fd, 4, 9, 7, 6, completeness);
    p1_frame(fd, 5, 9, 8, 7, {});
}

pid_t start_writer(PipeSet& pipes, InvalidStream invalid,
                   unsigned invalid_index) {
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        for (auto& fd : pipes.reads) close_fd(fd);
        for (unsigned index = 0; index < pipes.writes.size(); ++index) {
            const auto kind = static_cast<CaptureKind>(index % 5 + 1);
            if (invalid == InvalidStream::WrongRole &&
                index == invalid_index)
                write_p1_stream(pipes.writes[index]);
            else if (kind == CaptureKind::CorruptServer)
                write_p1_stream(pipes.writes[index]);
            else
                write_event_stream(pipes.writes[index], kind,
                    index == invalid_index ? invalid : InvalidStream::None);
            close_fd(pipes.writes[index]);
        }
        _exit(0);
    }
    for (auto& fd : pipes.writes) close_fd(fd);
    return child;
}

std::vector<unsigned char> partial_p1_header(std::size_t bytes) {
    assert(bytes > 0 && bytes < 112);
    std::array<unsigned char, 112> header{};
    const std::array<unsigned char, 8> magic{
        'K','P','B','P','1','C','0','3'};
    std::copy(magic.begin(), magic.end(), header.begin());
    header[8] = 1;
    header[9] = 1;
    header[10] = 3;
    header[11] = 0xff;
    header[12] = 3;
    be64(header.data() + 16, 1);
    be64(header.data() + 24, 0);
    be32(header.data() + 44, 332);
    std::array<unsigned char, 332> hello{};
    hello.fill(0x70);
    const auto selected_hash = sha256(hello);
    std::copy(selected_hash.begin(), selected_hash.end(),
              header.begin() + 80);
    return {header.begin(), header.begin() + bytes};
}

pid_t start_partial_c03_writer(
        PipeSet& pipes, unsigned partial_slot,
        std::span<const unsigned char> partial) {
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        (void)::signal(SIGPIPE, SIG_IGN);
        for (auto& fd : pipes.reads) close_fd(fd);
        for (unsigned index = 0; index < pipes.writes.size(); ++index) {
            const auto kind = static_cast<CaptureKind>(index % 5 + 1);
            if (index == partial_slot)
                write_all(pipes.writes[index], partial);
            else if (kind == CaptureKind::CorruptServer)
                write_p1_stream(pipes.writes[index]);
            else
                write_event_stream(
                    pipes.writes[index], kind, InvalidStream::None);
            close_fd(pipes.writes[index]);
        }
        _exit(0);
    }
    for (auto& fd : pipes.writes) close_fd(fd);
    return child;
}

void wait_writer(pid_t child, bool require_success = true) {
    int status = 0;
    pid_t result;
    do { result = ::waitpid(child, &status, 0); }
    while (result < 0 && errno == EINTR);
    assert(result == child);
    if (require_success) assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void complete_ten_stream_runtime_is_one_shot() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    const auto selected = plan();
    auto authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    // Drain starts before post-EGRESS route completion authority exists.
    auto running = ParentOwnedCaptureProducer::start(std::move(authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto completion = ParentOwnedCaptureProducer::finish(
        std::move(running), std::move(route_authority));
    wait_writer(writer);
    const auto& receipt = completion.public_receipt();
    assert(receipt.schema == "kpb-capture-producer-receipt/v1");
    assert(receipt.opaque_closure_authority_identity == digest(0x35));
    assert(receipt.stream_count == 10 && receipt.closed_root_count == 10 &&
           receipt.unknown_record_count == 0);
    assert(receipt.role_hooks_integrated &&
           receipt.fixed_fd_inheritance_selected &&
           receipt.launcher_selected && receipt.launch_authorized &&
           receipt.actual_receipt_emitted);
    assert(receipt.routes[0].projection_bytes == 10685 &&
           receipt.routes[0].route_endpoint_count == 1 &&
           receipt.routes[0].owner_ack_count == 0 &&
           receipt.routes[0].role_blind_required &&
           receipt.routes[0].after_full_cohort_barrier_required &&
           receipt.routes[0].owner_socket_or_path_derivation_forbidden);
    for (unsigned index = 0; index < receipt.streams.size(); ++index) {
        const auto& stream = receipt.streams[index];
        assert(stream.round == index / 5 + 1);
        assert(stream.kind == static_cast<CaptureKind>(index % 5 + 1));
        assert(stream.fixed_fd == 20 + index);
        assert(stream.root_closed && stream.end_observed &&
               stream.eof_observed);
    }
    auto closure = completion.take_authority();
    auto archive = completion.take_archive();
    (void)closure;
    (void)archive;
    expect_refused([&] { (void)completion.take_authority(); });
    expect_refused([&] { (void)completion.take_archive(); });
    expect_refused([&] {
        (void)ParentOwnedCaptureProducer::start(std::move(authority));
    });
    expect_refused([&] {
        (void)ParentOwnedCaptureProducer::finish(
            std::move(running), std::move(route_authority));
    });
}

template<class Mutator>
void invalid_plan_refuses(Mutator&& mutate) {
    PipeSet pipes;
    auto selected = plan();
    mutate(selected);
    bool refused = false;
    try {
        auto authority = ParentTenReadEndsAuthority::test_only_mint(
            std::move(selected), std::move(pipes.reads));
        (void)authority;
    } catch (const Refused&) {
        refused = true;
        // The refusing constructor consumed and closed every read endpoint.
        pipes.reads.fill(-1);
    }
    assert(refused);
}

void aggregate_route_counterexamples_refuse() {
    invalid_plan_refuses([](auto& value) {
        value.route_requirements[0].owner_socket_or_path_derivation_forbidden =
            false;
    });
    invalid_plan_refuses([](auto& value) {
        value.route_requirements[0].owner_ack_count = 1;
    });
    invalid_plan_refuses([](auto& value) {
        value.route_requirements[0].after_full_cohort_barrier_required = false;
    });
    invalid_plan_refuses([](auto& value) {
        value.route_requirements[0].projection_bytes = 10684;
    });
    invalid_plan_refuses([](auto& value) {
        value.route_requirements[0].route_endpoint_count = 2;
    });
    invalid_plan_refuses([](auto& value) {
        value.route_requirements[0].role_blind_required = false;
    });
    invalid_plan_refuses([](auto& value) {
        value.route_requirements[0].projection_identity = digest(0xee);
    });

    const auto selected = plan();
    const auto route_before_barrier = [&] {
        auto changed = routes(selected);
        changed[0].route_observed_monotonic_ns =
            changed[0].full_cohort_barrier_observed_monotonic_ns;
        return changed;
    }();
    expect_refused([&] {
        (void)ParentAggregateMailboxRoutesAuthority::test_only_mint(
            route_before_barrier);
    });
    const auto owner_derived = [&] {
        auto changed = routes(selected);
        changed[0].owner_socket_or_path_derived = true;
        return changed;
    }();
    expect_refused([&] {
        (void)ParentAggregateMailboxRoutesAuthority::test_only_mint(
            owner_derived);
    });
    const auto per_owner_ack = [&] {
        auto changed = routes(selected);
        changed[0].owner_ack_count = 1;
        return changed;
    }();
    expect_refused([&] {
        (void)ParentAggregateMailboxRoutesAuthority::test_only_mint(
            per_owner_ack);
    });
    const auto multiple_endpoints = [&] {
        auto changed = routes(selected);
        changed[0].route_endpoint_count = 2;
        return changed;
    }();
    expect_refused([&] {
        (void)ParentAggregateMailboxRoutesAuthority::test_only_mint(
            multiple_endpoints);
    });

    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(read_authority));
    auto mismatched = routes(selected);
    mismatched[0].projection_identity = digest(0xef);
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(mismatched);
    expect_refused([&] {
        (void)ParentOwnedCaptureProducer::finish(
            std::move(running), std::move(route_authority));
    });
    wait_writer(writer, false);
}

void identity_and_fixed_partition_counterexamples_refuse() {
    invalid_plan_refuses([](auto& value) {
        value.capture_trial_id =
            "11111111-1111-4111-8111-111111111111";
    });
    invalid_plan_refuses([](auto& value) {
        value.capture_attempt_ids[0] =
            "22222222-2222-4222-8222-222222222222";
    });
    invalid_plan_refuses([](auto& value) {
        value.binding.trial = digest(0xee);
    });
    invalid_plan_refuses([](auto& value) {
        value.binding.round_attempts[1] = digest(0xee);
    });
    invalid_plan_refuses([](auto& value) {
        value.streams[4].fixed_fd = 29;
    });
    invalid_plan_refuses([](auto& value) {
        value.streams[4].kind = CaptureKind::CorruptServer;
    });
    invalid_plan_refuses([](auto& value) {
        value.producer_process_identity = digest(0xee);
    });
    invalid_plan_refuses([](auto& value) {
        value.role_closure_identity = digest(0xee);
    });
    invalid_plan_refuses([](auto& value) {
        value.manifest_seal = digest(0xee);
    });
    invalid_plan_refuses([](auto& value) {
        value.opaque_closure_authority_identity = {};
    });
    invalid_plan_refuses([](auto& value) {
        value.construction_policy =
            ConstructionPolicy::ExplicitOwnerPublicEffects;
    });
}

void invalid_stream_refuses(InvalidStream invalid, unsigned index) {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, invalid, index);
    const auto selected = plan();
    auto authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(std::move(authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    expect_refused([&] {
        (void)ParentOwnedCaptureProducer::finish(
            std::move(running), std::move(route_authority));
    });
    wait_writer(writer, false);
}

void end_eof_and_role_framing_counterexamples_refuse() {
    invalid_stream_refuses(InvalidStream::MissingEnd, 2);
    invalid_stream_refuses(InvalidStream::BytesAfterEnd, 4);
    invalid_stream_refuses(InvalidStream::WrongRole, 0);
}

void zero_length_child_record_is_not_eof() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    auto selected = plan();
    selected.test_only_send_zero_record_before_close = true;
    auto authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(std::move(authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    expect_refused([&] {
        (void)ParentOwnedCaptureProducer::finish(
            std::move(running), std::move(route_authority));
    });
    wait_writer(writer, false);
}

void archive_transport_fault_refuses(
        TestProducerArchiveTransportFault fault) {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    auto selected = plan();
    selected.test_only_archive_fault = fault;
    auto authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(std::move(authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    expect_refused([&] {
        (void)ParentOwnedCaptureProducer::finish(
            std::move(running), std::move(route_authority));
    });
    wait_writer(writer);
}

void archive_ancillary_order_lineage_and_exit_counterexamples_refuse() {
    for (const auto fault : {
             TestProducerArchiveTransportFault::MissingFd,
             TestProducerArchiveTransportFault::ExtraFd,
             TestProducerArchiveTransportFault::SwappedFdOrder,
             TestProducerArchiveTransportFault::SwappedFdAndEvidence,
             TestProducerArchiveTransportFault::WritableFd,
             TestProducerArchiveTransportFault::UnsealedFd,
             TestProducerArchiveTransportFault::DuplicateFd,
             TestProducerArchiveTransportFault::WrongBinding,
             TestProducerArchiveTransportFault::WrongClosure,
             TestProducerArchiveTransportFault::SecondPacket,
             TestProducerArchiveTransportFault::NonzeroExit,
         })
        archive_transport_fault_refuses(fault);
}

void finish_attempt_success_retains_history_and_completion() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    const auto selected = plan();
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(read_authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto result = ParentOwnedCaptureProducer::finish_attempt(
        std::move(running), std::move(route_authority));
    wait_writer(writer);
    assert(result.complete());
    auto history = result.take_history();
    const auto summary =
        ProducerAttemptC03HistoryAuthority::test_only_consume(
            std::move(history));
    assert(summary.binding == selected.binding &&
           summary.attempt_failure == ProducerAttemptDrainFailure::None &&
           summary.states[0] == ProducerAttemptC03StreamState::CompleteEnd &&
           summary.states[1] == ProducerAttemptC03StreamState::CompleteEnd &&
           summary.failures[0] == ProducerAttemptDrainFailure::None &&
           summary.failures[1] == ProducerAttemptDrainFailure::None &&
           summary.sizes[0] > 0 && summary.sizes[1] > 0 &&
           summary.devices[0] != 0 && summary.devices[1] != 0 &&
           summary.inodes[0] != summary.inodes[1] &&
           summary.seals[0] == 0 && summary.seals[1] == 0 &&
           summary.writer_aliases_closed &&
           summary.read_only[0] && summary.read_only[1] &&
           summary.sha256[0] != Digest{} && summary.sha256[1] != Digest{} &&
           summary.start_monotonic_ns > 0 &&
           summary.end_monotonic_ns >= summary.start_monotonic_ns &&
           summary.producer_pid > 1 &&
           summary.producer_child_exit_identity != Digest{});
    auto completion = result.take_completion();
    assert(completion.public_receipt().stream_count == 10);
    expect_refused([&] { (void)result.take_history(); });
    expect_refused([&] { (void)result.take_completion(); });
}

void finish_attempt_partial_c03_is_retained() {
    const auto partial = partial_p1_header(31);
    for (const unsigned slot : {3U, 8U}) {
        PipeSet pipes;
        const pid_t writer = start_partial_c03_writer(pipes, slot, partial);
        const auto selected = plan();
        auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
            selected, std::move(pipes.reads));
        pipes.reads.fill(-1);
        auto running = ParentOwnedCaptureProducer::start(
            std::move(read_authority));
        auto route_authority =
            ParentAggregateMailboxRoutesAuthority::test_only_mint(
                routes(selected));
        auto result = ParentOwnedCaptureProducer::finish_attempt(
            std::move(running), std::move(route_authority));
        wait_writer(writer);
        assert(!result.complete());
        const auto summary =
            ProducerAttemptC03HistoryAuthority::test_only_consume(
                result.take_history());
        const unsigned round = slot / 5;
        assert(summary.states[round] ==
                   ProducerAttemptC03StreamState::PartialHeader &&
               summary.failures[round] ==
                   ProducerAttemptDrainFailure::PartialHeader &&
               summary.sizes[round] == partial.size() &&
               summary.sha256[round] == sha256(partial) &&
               summary.sizes[1 - round] > 0 && summary.read_only[0] &&
               summary.read_only[1] && summary.writer_aliases_closed &&
               summary.attempt_failure ==
                   ProducerAttemptDrainFailure::PartialHeader);
        expect_refused([&] { (void)result.take_completion(); });
    }
}

void finish_attempt_survives_no_packet_signal(
        TestProducerDrainFault fault, int expected_signal) {
    PipeSet pipes;
    const auto partial = partial_p1_header(23);
    const bool second_round =
        fault == TestProducerDrainFault::SigkillAfterSecondC03Write ||
        fault == TestProducerDrainFault::SigsegvAfterSecondC03Write;
    const unsigned selected_round = second_round ? 1 : 0;
    const pid_t writer = start_partial_c03_writer(
        pipes, second_round ? 8 : 3, partial);
    auto selected = plan();
    selected.test_only_drain_fault = fault;
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(read_authority));
    auto result = ParentOwnedCaptureProducer::finish_attempt(
        std::move(running));
    wait_writer(writer, false);
    assert(!result.complete());
    const auto summary =
        ProducerAttemptC03HistoryAuthority::test_only_consume(
            result.take_history());
    assert(summary.sizes[selected_round] == partial.size() &&
           summary.sha256[selected_round] == sha256(partial) &&
           summary.read_only[0] &&
           summary.read_only[1] && summary.writer_aliases_closed &&
           WIFSIGNALED(summary.producer_wait_status) &&
           WTERMSIG(summary.producer_wait_status) == expected_signal &&
           summary.attempt_failure ==
               ProducerAttemptDrainFailure::ProducerChildSignaled);
}

void finish_attempt_recovers_after_first_waitpid_failure() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    auto selected = plan();
    selected.test_only_wait_fault = TestProducerWaitFault::FailFirstWaitpid;
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(read_authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto result = ParentOwnedCaptureProducer::finish_attempt(
        std::move(running), std::move(route_authority));
    wait_writer(writer, false);
    const auto summary = ProducerAttemptC03HistoryAuthority::
        test_only_consume(result.take_history());
    assert(summary.wait_observed && summary.producer_pid > 1 &&
           summary.writer_aliases_closed && summary.read_only[0] &&
           summary.read_only[1]);
    if (result.complete()) (void)result.take_completion();
}

void finish_attempt_pidfd_seals_unknown_wait_history() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    auto selected = plan();
    selected.test_only_wait_fault = TestProducerWaitFault::FailAllWaitpid;
    auto recorder = attempt_history::
        RegisteredTrialAttemptHistoryTestBridge::begin({
            .classification = static_cast<
                registered_driver::CaptureClassification>(
                    static_cast<std::uint8_t>(
                        selected.binding.classification)),
            .capture_trial_id = selected.capture_trial_id,
            .trial_identity = selected.binding.trial,
        });
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(read_authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto result = ParentOwnedCaptureProducer::finish_attempt(
        std::move(running), std::move(route_authority));
    wait_writer(writer, false);
    assert(!result.complete());
    attempt_history::RegisteredCaptureAttemptHistoryBridge::append_failed(
        recorder, std::move(result));
    const auto summary = attempt_history::
        RegisteredTrialAttemptHistoryTestBridge::consume_failed(
            attempt_history::RegisteredTrialAttemptHistoryRecorder::
                seal_failed(std::move(recorder)));
    assert(summary.rows.size() == 2);
    for (const auto& row : summary.rows)
        assert(row.failure ==
                   attempt_history::AttemptFailure::WaitStatusUnavailable &&
               row.wait_exit_code == -1 && row.wait_signal == 0 &&
               row.c03_bytes > 0 &&
               row.c03_sha256 != attempt_history::Digest{} &&
               row.sealed_c03_access_mode == O_RDONLY &&
               row.child_exit_identity != attempt_history::Digest{});
}

void finish_attempt_refuses_completion_without_routes_or_clean_child() {
    {
        PipeSet pipes;
        const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
        const auto selected = plan();
        auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
            selected, std::move(pipes.reads));
        pipes.reads.fill(-1);
        auto result = ParentOwnedCaptureProducer::finish_attempt(
            ParentOwnedCaptureProducer::start(std::move(read_authority)));
        wait_writer(writer);
        assert(!result.complete());
        const auto summary =
            ProducerAttemptC03HistoryAuthority::test_only_consume(
                result.take_history());
        assert(summary.attempt_failure ==
               ProducerAttemptDrainFailure::RouteUnavailable);
    }
    for (const auto fault : {
             TestProducerArchiveTransportFault::MissingFd,
             TestProducerArchiveTransportFault::WritableFd,
             TestProducerArchiveTransportFault::NonzeroExit}) {
        PipeSet pipes;
        const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
        auto selected = plan();
        selected.test_only_archive_fault = fault;
        auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
            selected, std::move(pipes.reads));
        pipes.reads.fill(-1);
        auto running = ParentOwnedCaptureProducer::start(
            std::move(read_authority));
        auto route_authority =
            ParentAggregateMailboxRoutesAuthority::test_only_mint(
                routes(selected));
        auto result = ParentOwnedCaptureProducer::finish_attempt(
            std::move(running), std::move(route_authority));
        wait_writer(writer);
        assert(!result.complete());
        const auto summary =
            ProducerAttemptC03HistoryAuthority::test_only_consume(
                result.take_history());
        assert(summary.sizes[0] > 0 && summary.sizes[1] > 0 &&
               summary.read_only[0] && summary.read_only[1] &&
               summary.writer_aliases_closed &&
               summary.attempt_failure != ProducerAttemptDrainFailure::None);
    }
}

void finish_attempt_atomically_enters_fresh_trial_ledger() {
    auto ledger = attempt_history::
        RegisteredFreshTrialHistoryLedgerTestBridge::begin();

    const auto failed_plan = plan();
    auto failed_recorder = attempt_history::
        RegisteredTrialAttemptHistoryTestBridge::begin({
            .classification = static_cast<
                registered_driver::CaptureClassification>(
                    static_cast<std::uint8_t>(
                        failed_plan.binding.classification)),
            .capture_trial_id = failed_plan.capture_trial_id,
            .trial_identity = failed_plan.binding.trial,
        });
    {
        PipeSet pipes;
        const auto partial = partial_p1_header(31);
        const pid_t writer = start_partial_c03_writer(pipes, 3, partial);
        auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
            failed_plan, std::move(pipes.reads));
        pipes.reads.fill(-1);
        auto running = ParentOwnedCaptureProducer::start(
            std::move(read_authority));
        auto route_authority =
            ParentAggregateMailboxRoutesAuthority::test_only_mint(
                routes(failed_plan));
        auto result = ParentOwnedCaptureProducer::finish_attempt(
            std::move(running), std::move(route_authority));
        wait_writer(writer, false);
        assert(!result.complete());
        attempt_history::RegisteredCaptureAttemptHistoryBridge::
            append_failed(failed_recorder, std::move(result));
    }
    auto failed_history = attempt_history::
        RegisteredTrialAttemptHistoryRecorder::seal_failed(
            std::move(failed_recorder));
    attempt_history::RegisteredFreshTrialHistoryLedgerBridge::append_failed(
        ledger, std::move(failed_history));

    auto fresh_plan = plan();
    fresh_plan.capture_trial_id =
        "11111111-1111-4111-8111-111111111111";
    fresh_plan.capture_attempt_ids = {
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
    };
    fresh_plan.binding.trial = trial_identity(fresh_plan.capture_trial_id);
    for (unsigned index = 0; index < 2; ++index)
        fresh_plan.binding.round_attempts[index] = text_identity(
            "KPB_CAPTURE_ATTEMPT_ID_V1\n",
            fresh_plan.capture_attempt_ids[index]);
    auto fresh_recorder = attempt_history::
        RegisteredTrialAttemptHistoryTestBridge::begin({
            .classification = static_cast<
                registered_driver::CaptureClassification>(
                    static_cast<std::uint8_t>(
                        fresh_plan.binding.classification)),
            .capture_trial_id = fresh_plan.capture_trial_id,
            .trial_identity = fresh_plan.binding.trial,
        });
    PipeSet fresh_pipes;
    const pid_t fresh_writer = start_writer(
        fresh_pipes, InvalidStream::None, 0);
    auto fresh_read_authority = ParentTenReadEndsAuthority::test_only_mint(
        fresh_plan, std::move(fresh_pipes.reads));
    fresh_pipes.reads.fill(-1);
    auto fresh_running = ParentOwnedCaptureProducer::start(
        std::move(fresh_read_authority));
    auto fresh_routes =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(fresh_plan));
    auto fresh_result = ParentOwnedCaptureProducer::finish_attempt(
        std::move(fresh_running), std::move(fresh_routes));
    wait_writer(fresh_writer);
    assert(fresh_result.complete());
    auto completion = attempt_history::RegisteredCaptureAttemptHistoryBridge::
        append_complete(fresh_recorder, std::move(fresh_result));
    assert(completion.public_receipt().stream_count == 10);
    auto complete_history = attempt_history::
        RegisteredTrialAttemptHistoryRecorder::seal(
            std::move(fresh_recorder));
    attempt_history::RegisteredFreshTrialHistoryLedgerBridge::append_complete(
        ledger, std::move(complete_history));
    const auto summary = attempt_history::
        RegisteredFreshTrialHistoryLedgerTestBridge::consume(
            attempt_history::RegisteredFreshTrialHistoryLedgerBridge::seal(
                std::move(ledger)));
    assert(summary.capture_trial_ids.size() == 2 &&
           summary.capture_trial_ids[0] == failed_plan.capture_trial_id &&
           summary.capture_trial_ids[1] == fresh_plan.capture_trial_id &&
           summary.failed.size() == 2 && summary.failed[0] &&
           !summary.failed[1]);
}

void finish_outcome_quarantines_all_streams_after_c03_inspection_failure() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    auto selected = plan();
    selected.test_only_drain_fault =
        TestProducerDrainFault::FailC03InspectionAfterSeal;
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(read_authority));
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto outcome = ParentOwnedCaptureProducer::finish_outcome(
        std::move(running), std::move(route_authority));
    wait_writer(writer);
    const auto summary = ProducerAttemptOutcomeAuthority::
        test_only_consume_unavailable(std::move(outcome));
    assert(summary.unavailable && summary.retained_quarantine &&
           summary.retained_partial_c03 &&
           summary.stage == producer_archive::
               ProducerArchiveQuarantineStage::Inspection &&
           summary.error_number != 0 && summary.producer_pid > 1 &&
           summary.wait_observed && summary.pidfd_exit_observed);
    expect_refused([&] {
        (void)ProducerAttemptOutcomeAuthority::
            test_only_consume_unavailable(std::move(outcome));
    });
}

void finish_outcome_quarantines_on_injected_allocation_failure(
        TestProducerDrainFault fault, bool expect_partial) {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    auto selected = plan();
    selected.test_only_drain_fault = fault;
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto outcome = ParentOwnedCaptureProducer::finish_outcome(
        ParentOwnedCaptureProducer::start(std::move(read_authority)),
        std::move(route_authority));
    wait_writer(writer, fault != TestProducerDrainFault::
        FailAllocationAfterClaim);
    const auto summary = ProducerAttemptOutcomeAuthority::
        test_only_consume_unavailable(std::move(outcome));
    assert(summary.unavailable && summary.retained_quarantine &&
           summary.retained_partial_c03 == expect_partial &&
           summary.error_number != 0);
}

void stale_running_does_not_burn_a_fresh_route() {
    const auto selected = plan();
    PipeSet first_pipes;
    const pid_t first_writer = start_writer(
        first_pipes, InvalidStream::None, 0);
    auto first_reads = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(first_pipes.reads));
    first_pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(
        std::move(first_reads));
    auto first_routes = ParentAggregateMailboxRoutesAuthority::test_only_mint(
        routes(selected));
    auto first_result = ParentOwnedCaptureProducer::finish_attempt(
        std::move(running), std::move(first_routes));
    wait_writer(first_writer);
    assert(first_result.complete());

    auto reusable_routes =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    expect_refused([&] {
        (void)ParentOwnedCaptureProducer::finish_outcome(
            std::move(running), std::move(reusable_routes));
    });

    PipeSet second_pipes;
    const pid_t second_writer = start_writer(
        second_pipes, InvalidStream::None, 0);
    auto second_reads = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(second_pipes.reads));
    second_pipes.reads.fill(-1);
    auto second_result = ParentOwnedCaptureProducer::finish_attempt(
        ParentOwnedCaptureProducer::start(std::move(second_reads)),
        std::move(reusable_routes));
    wait_writer(second_writer);
    assert(second_result.complete());
}

void malformed_live_running_retains_quarantine() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    const auto selected = plan();
    auto reads = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto running = ParentOwnedCaptureProducer::start(std::move(reads));
    ParentOwnedCaptureProducer::test_only_invalidate_running_packet_fd(
        running);
    auto selected_routes =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto outcome = ParentOwnedCaptureProducer::finish_outcome(
        std::move(running), std::move(selected_routes));
    wait_writer(writer, false);
    const auto summary = ProducerAttemptOutcomeAuthority::
        test_only_consume_unavailable(std::move(outcome));
    assert(summary.unavailable && summary.retained_quarantine &&
           !summary.retained_partial_c03 && summary.error_number != 0);
}

void finish_outcome_and_recorder_are_claimed_as_one_closed_sum() {
    PipeSet pipes;
    const pid_t writer = start_writer(pipes, InvalidStream::None, 0);
    const auto selected = plan();
    auto recorder = attempt_history::
        RegisteredTrialAttemptHistoryTestBridge::begin({
            .classification = static_cast<
                registered_driver::CaptureClassification>(
                    static_cast<std::uint8_t>(
                        selected.binding.classification)),
            .capture_trial_id = selected.capture_trial_id,
            .trial_identity = selected.binding.trial,
        });
    auto read_authority = ParentTenReadEndsAuthority::test_only_mint(
        selected, std::move(pipes.reads));
    pipes.reads.fill(-1);
    auto route_authority =
        ParentAggregateMailboxRoutesAuthority::test_only_mint(
            routes(selected));
    auto outcome = ParentOwnedCaptureProducer::finish_outcome(
        ParentOwnedCaptureProducer::start(std::move(read_authority)),
        std::move(route_authority));
    wait_writer(writer);
    runtime_fail_allocation.store(true);
    auto appended = attempt_history::RegisteredCaptureAttemptHistoryBridge::
        append_outcome(std::move(recorder), std::move(outcome));
    runtime_fail_allocation.store(false);
    static_assert(!std::is_copy_constructible_v<decltype(appended)>);
    auto owner = fresh_trial_owner::AllBranchFreshTrialOwnerAuthority::
        test_only_begin();
    runtime_fail_allocation.store(true);
    auto stop = fresh_trial_owner::AllBranchFreshTrialOwnerBridge::append(
        std::move(owner), std::move(appended));
    runtime_fail_allocation.store(false);
    assert(stop.test_only_is_unavailable_stop());
    bool replay_refused = false;
    try {
        (void)fresh_trial_owner::AllBranchFreshTrialOwnerBridge::append(
            std::move(owner), std::move(appended));
    } catch (const Refused&) {
        replay_refused = true;
    }
    assert(replay_refused);
}

} // namespace

int main() {
    complete_ten_stream_runtime_is_one_shot();
    aggregate_route_counterexamples_refuse();
    identity_and_fixed_partition_counterexamples_refuse();
    end_eof_and_role_framing_counterexamples_refuse();
    zero_length_child_record_is_not_eof();
    archive_ancillary_order_lineage_and_exit_counterexamples_refuse();
    finish_attempt_success_retains_history_and_completion();
    finish_attempt_partial_c03_is_retained();
    finish_attempt_survives_no_packet_signal(
        TestProducerDrainFault::SigkillAfterFirstC03Write, SIGKILL);
    finish_attempt_survives_no_packet_signal(
        TestProducerDrainFault::SigsegvAfterFirstC03Write, SIGSEGV);
    finish_attempt_survives_no_packet_signal(
        TestProducerDrainFault::SigkillAfterSecondC03Write, SIGKILL);
    finish_attempt_survives_no_packet_signal(
        TestProducerDrainFault::SigsegvAfterSecondC03Write, SIGSEGV);
    finish_attempt_recovers_after_first_waitpid_failure();
    finish_attempt_pidfd_seals_unknown_wait_history();
    finish_attempt_refuses_completion_without_routes_or_clean_child();
    finish_attempt_atomically_enters_fresh_trial_ledger();
    finish_outcome_quarantines_all_streams_after_c03_inspection_failure();
    finish_outcome_quarantines_on_injected_allocation_failure(
        TestProducerDrainFault::FailAllocationAfterClaim, false);
    finish_outcome_quarantines_on_injected_allocation_failure(
        TestProducerDrainFault::FailAllocationAfterPartialSeal, true);
    finish_outcome_quarantines_on_injected_allocation_failure(
        TestProducerDrainFault::FailAllocationAfterC03Inspection, true);
    stale_running_does_not_burn_a_fresh_route();
    malformed_live_running_retains_quarantine();
#ifdef KPB_CAPTURE_PRODUCER_RUNTIME_TEST_TRACE
    std::fprintf(stderr, "before-closed-sum\n");
#endif
    finish_outcome_and_recorder_are_claimed_as_one_closed_sum();
}
