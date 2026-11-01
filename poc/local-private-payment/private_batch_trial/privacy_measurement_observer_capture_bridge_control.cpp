#include "c1_contact_value_authority.hpp"
#include "privacy_capture_producer_archive.hpp"
#include "privacy_capture_producer_supervisor.hpp"
#include "privacy_measurement_observer_capture_bridge.hpp"
#include "privacy_measurement_observer_spool_capsule_schema.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::producer_supervisor;
using namespace kpb::measurement::producer_archive;
using namespace kpb::measurement::runtime_bridge;
using namespace kpb::measurement::c1_capture;

namespace {

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

Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    assert(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void big_integer(std::vector<unsigned char>& out, std::uint64_t value,
                 unsigned width) {
    for (int shift = static_cast<int>((width - 1) * 8);
         shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

std::vector<unsigned char> raw_wire(unsigned slot) {
    std::vector<unsigned char> result(200 + slot);
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(slot * 19 + index);
    return result;
}

RunBinding binding(unsigned char seed = 0x10) {
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = digest(seed);
    result.run_selection = digest(seed + 1);
    result.trial = digest(seed + 2);
    result.attempt = digest(seed + 3);
    result.cohort = digest(seed + 4);
    result.capture = digest(seed + 5);
    result.method = digest(seed + 6);
    result.workload = digest(seed + 7);
    result.source_closure = digest(0xaf);
    result.runtime = digest(seed + 8);
    result.outer_parent_process = digest(seed + 9);
    result.outer_parent_executable = digest(seed + 10);
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto base = static_cast<unsigned char>(0xb0 + index * 6);
        result.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(base),
            .build_identity = digest(static_cast<unsigned char>(base + 1)),
            .runtime_identity = digest(static_cast<unsigned char>(base + 2)),
            .assets_identity = digest(static_cast<unsigned char>(base + 3)),
            .pinned_executable_identity =
                digest(static_cast<unsigned char>(base + 4)),
            .launcher_identity = digest(static_cast<unsigned char>(base + 5)),
        };
    }
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.finite_manifest.parent_recomputation_identity = digest(0xfe);
    const auto as_worker = [](const ManifestEntry& entry) {
        return WorkerBinding{
            .source_identity = entry.source_identity,
            .build_identity = entry.build_identity,
            .runtime_identity = entry.runtime_identity,
            .assets_identity = entry.assets_identity,
            .pinned_executable_identity = entry.pinned_executable_identity,
            .launcher_identity = entry.launcher_identity,
        };
    };
    const auto& p1 = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    result.capture_source = p1.source_identity;
    result.capture_build = p1.build_identity;
    result.capture_runtime = p1.runtime_identity;
    result.capture_launcher = p1.launcher_identity;
    result.observer_worker = as_worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = as_worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = as_worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    result.round_capture_plans = {digest(seed + 11), digest(seed + 12)};
    result.financial_runs = {digest(seed + 13), digest(seed + 14)};
    result.round_attempts = {digest(seed + 15), digest(seed + 16)};
    result.round_cohorts = {digest(seed + 17), digest(seed + 18)};
    result.projections = {digest(seed + 19), digest(seed + 20)};
    return result;
}

ProducerClosureEvidence evidence(const Digest& closure) {
    ProducerClosureEvidence result{};
    result.opaque_closure_authority_identity = closure;
    result.producer_child_exit = digest(0x71);
    result.producer_receipt = digest(0x72);
    result.producer_identity = digest(0x73);
    for (unsigned index = 0; index < result.streams.size(); ++index) {
        const auto bytes = raw_wire(index);
        result.streams[index].record_root = hash(bytes);
        result.streams[index].end_frame_identity =
            digest(static_cast<unsigned char>(0x30 + index));
        result.streams[index].record_count = index + 1;
        result.streams[index].payload_bytes = 100 + index;
        result.streams[index].raw_wire_bytes = bytes.size();
        static constexpr char label[] =
            "KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n";
        std::vector<unsigned char> preimage(
            label, label + sizeof(label) - 1);
        big_integer(preimage, index / 5 + 1, 4);
        preimage.push_back(static_cast<unsigned char>(index % 5 + 1));
        big_integer(preimage, result.streams[index].record_count, 8);
        big_integer(preimage, result.streams[index].payload_bytes, 8);
        big_integer(preimage, result.streams[index].raw_wire_bytes, 8);
        add(preimage, result.streams[index].record_root);
        add(preimage, result.streams[index].end_frame_identity);
        result.streams[index].eof_identity = hash(preimage);
    }
    return result;
}

ProducerSealedArchiveAuthority archive(
        const RunBinding& selected, const Digest& closure,
        const ProducerClosureEvidence& private_evidence) {
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        selected, closure);
    for (unsigned slot = 0; slot < private_evidence.streams.size(); ++slot) {
        const auto bytes = raw_wire(slot);
        builder.append(slot, bytes);
        builder.finish_after_end_and_eof(
            slot, private_evidence.streams[slot]);
    }
    return std::move(builder).finish();
}

void close_fd(int fd) {
    while (::close(fd) != 0 && errno == EINTR) {}
}

void write_leaf(const std::string& path, unsigned char value) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                          O_CLOEXEC, 0400);
    assert(fd >= 0 && ::write(fd, &value, 1) == 1);
    close_fd(fd);
}

std::string make_spool_directory() {
    std::array<char, 64> path{};
    const char pattern[] = "/tmp/kpb-observer-admission-XXXXXX";
    std::copy(std::begin(pattern), std::end(pattern), path.begin());
    char* root = ::mkdtemp(path.data());
    assert(root != nullptr);
    const std::string directory(root);
    write_leaf(directory + "/PRODUCER.json", 0x70);
    constexpr std::array<const char*, 5> names{
        "projection.bin", "terminal.json", "dispatcher.json",
        "corrupt-server.json", "colluder-wallet.json",
    };
    for (unsigned round = 1; round <= 2; ++round) {
        const std::string child = directory + "/round-" +
                                  std::to_string(round);
        assert(::mkdir(child.c_str(), 0700) == 0);
        for (unsigned index = 0; index < names.size(); ++index)
            write_leaf(child + "/" + names[index],
                       static_cast<unsigned char>(round * 16 + index));
    }
    return directory;
}

void remove_spool_directory(const std::string& directory) {
    constexpr std::array<const char*, 5> names{
        "projection.bin", "terminal.json", "dispatcher.json",
        "corrupt-server.json", "colluder-wallet.json",
    };
    assert(::unlink((directory + "/PRODUCER.json").c_str()) == 0);
    for (unsigned round = 1; round <= 2; ++round) {
        const std::string child = directory + "/round-" +
                                  std::to_string(round);
        for (const char* name : names)
            assert(::unlink((child + "/" + name).c_str()) == 0);
        assert(::rmdir(child.c_str()) == 0);
    }
    assert(::rmdir(directory.c_str()) == 0);
}

ProducerSpoolAuthority spool(
        const std::string& directory, const RunBinding& selected,
        const Digest& closure, const Digest& process,
        const ProducerClosureEvidence& private_evidence) {
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY |
                          O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0);
    return ProducerSpoolAuthority::test_only_mint(
        selected, closure, digest(0x74), process, digest(0x75),
        digest(0x76), private_evidence, fd);
}

std::array<C03RoleLaunchRoundBinding, 2> c03_rounds(
        const RunBinding& selected) {
    const auto& p1 = selected.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    std::array<C03RoleLaunchRoundBinding, 2> result{};
    for (unsigned index = 0; index < result.size(); ++index) {
        result[index] = {
            .round = index + 1,
            .fixed_fd = 23 + 5 * index,
            .financial_run = selected.financial_runs[index],
            .attempt = selected.round_attempts[index],
            .cohort = selected.round_cohorts[index],
            .capture_plan = selected.round_capture_plans[index],
            .projection = selected.projections[index],
            .source_identity = p1.source_identity,
            .build_identity = p1.build_identity,
            .runtime_identity = p1.runtime_identity,
            .launcher_identity = p1.launcher_identity,
            .process_identity = digest(
                static_cast<unsigned char>(0x88 + index)),
            .child_exit_identity = digest(
                static_cast<unsigned char>(0x8a + index)),
            .model_preimage_identity = digest(
                static_cast<unsigned char>(0x8c + index)),
            .query_store_preimage_identity = digest(
                static_cast<unsigned char>(0x8e + index)),
            .scalar_capture_manifest_identity = digest(
                static_cast<unsigned char>(0x90 + index)),
        };
    }
    return result;
}

C03RoleLaunchAdmissionAuthority c03(
        const RunBinding& selected, const Digest& closure,
        const Digest& process, const ProducerClosureEvidence& private_evidence) {
    return C03RoleLaunchAdmissionAuthority::test_only_mint(
        selected, closure, process, private_evidence.producer_child_exit,
        private_evidence.producer_receipt, c03_rounds(selected));
}

WorkerBinding c1_worker(const RunBinding& selected) {
    const auto& entry = selected.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::C1Supervisor) - 1];
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

C1PostcaptureAdmissionAuthority c1(
        const RunBinding& selected, unsigned round) {
    const auto seed = static_cast<unsigned char>(0xc0 + 8 * round);
    return C1PostcaptureAdmissionAuthority::test_only_mint(
        selected, round, round == 1 ? 24 : 29,
        digest(seed), selected.source_closure, digest(seed + 2),
        digest(seed + 3), digest(seed + 4), digest(seed + 5),
        digest(seed + 6), c1_worker(selected), {0, 2, 0},
        {digest(static_cast<unsigned char>(seed + 8)),
         digest(static_cast<unsigned char>(seed + 9)),
         digest(static_cast<unsigned char>(seed + 10))});
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

ProducerClosureAuthority producer(
        const RunBinding& selected, const Digest& closure,
        const Digest& process, ProducerClosureEvidence private_evidence,
        bool swap_c03_rounds = false,
        bool wrong_c03_process = false,
        bool wrong_c03_exit = false) {
    constexpr std::array<unsigned, 5> manifest_indexes{0, 3, 4, 1, 2};
    const auto c03_bindings = c03_rounds(selected);
    std::array<PublicStreamClosure, 10> streams{};
    for (unsigned index = 0; index < streams.size(); ++index) {
        const unsigned round = index / 5 + 1;
        const unsigned kind = index % 5;
        const auto& manifest =
            selected.finite_manifest.entries[manifest_indexes[kind]];
        Digest stream_process =
            digest(static_cast<unsigned char>(0x41 + index));
        Digest stream_exit =
            digest(static_cast<unsigned char>(0x51 + index));
        if (kind == 3) {
            stream_process = c03_bindings[round - 1].process_identity;
            stream_exit = c03_bindings[round - 1].child_exit_identity;
        } else if (kind == 4) {
            const auto seed =
                static_cast<unsigned char>(0xc0 + 8 * round);
            stream_process = digest(static_cast<unsigned char>(seed + 5));
            stream_exit = digest(static_cast<unsigned char>(seed + 6));
        }
        streams[index] = {
            .round = round,
            .kind = static_cast<CaptureKind>(kind + 1),
            .fixed_fd = 20 + index,
            .manifest_component = manifest.component,
            .source_identity = manifest.source_identity,
            .build_identity = manifest.build_identity,
            .runtime_identity = manifest.runtime_identity,
            .launcher_identity = manifest.launcher_identity,
            .process_identity = stream_process,
            .child_exit_identity = stream_exit,
            .root_closed = true,
            .end_observed = true,
            .eof_observed = true,
        };
    }
    if (swap_c03_rounds) {
        streams[3].round = 2;
        streams[8].round = 1;
    }
    if (wrong_c03_process) streams[3].process_identity = digest(0x06);
    if (wrong_c03_exit) streams[8].child_exit_identity = digest(0x07);
    const auto& producer_manifest = selected.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Producer) - 1];
    WorkerBinding producer_worker{
        .source_identity = producer_manifest.source_identity,
        .build_identity = producer_manifest.build_identity,
        .runtime_identity = producer_manifest.runtime_identity,
        .assets_identity = producer_manifest.assets_identity,
        .pinned_executable_identity =
            producer_manifest.pinned_executable_identity,
        .launcher_identity = producer_manifest.launcher_identity,
    };
    return ProducerClosureAuthority::test_only_mint({
        .binding = selected,
        .opaque_closure_authority_identity = closure,
        .producer_worker = producer_worker,
        .producer_process_identity = process,
        .role_closure_identity = selected.source_closure,
        .manifest_seal = digest(0x08),
        .construction_policy =
            ConstructionPolicy::SecretPermutationIndependent,
        .construction_classification_receipt = digest(0x09),
        .streams = streams,
        .stream_count = 10,
        .closed_root_count = 10,
        .unknown_record_count = 0,
    }, std::move(private_evidence));
}

ObserverAdmissionAuthority admission(
        const std::string& directory, const RunBinding& selected,
        const Digest& closure, const Digest& process,
        const ProducerClosureEvidence& private_evidence,
        std::array<C03RoleLaunchRoundBinding, 2> rounds) {
    auto spool_capability = spool(
        directory, selected, closure, process, private_evidence);
    auto c03_capability = C03RoleLaunchAdmissionAuthority::test_only_mint(
        selected, closure, process, private_evidence.producer_child_exit,
        private_evidence.producer_receipt, std::move(rounds));
    auto c1_round1 = c1(selected, 1);
    auto c1_round2 = c1(selected, 2);
    return ObserverCaptureCapsuleBridge::admit(
        std::move(spool_capability), std::move(c03_capability),
        std::move(c1_round1), std::move(c1_round2));
}

void exact_live_capabilities_are_required_once() {
    static_assert(!std::is_copy_constructible_v<
                  ObserverAdmissionAuthority>);
    static_assert(std::is_move_constructible_v<
                  ObserverAdmissionAuthority>);
    const auto selected = binding();
    const auto closure = digest(0x77);
    const auto process = digest(0x78);
    const auto private_evidence = evidence(closure);
    const auto directory = make_spool_directory();
    auto spool_capability = spool(
        directory, selected, closure, process, private_evidence);
    auto c03_capability = c03(
        selected, closure, process, private_evidence);
    auto c1_round1 = c1(selected, 1);
    auto c1_round2 = c1(selected, 2);
    auto admission = ObserverCaptureCapsuleBridge::admit(
        std::move(spool_capability), std::move(c03_capability),
        std::move(c1_round1), std::move(c1_round2));
    ObserverAdmissionAuthority moved(std::move(admission));
    (void)moved;
    expect_refused([&] {
        (void)ObserverCaptureCapsuleBridge::admit(
            std::move(spool_capability), std::move(c03_capability),
            std::move(c1_round1), std::move(c1_round2));
    });
    remove_spool_directory(directory);
}

void sealed_archive_is_the_production_admission_and_binds_closure() {
    const auto selected = binding();
    const auto closure = digest(0x77);
    const auto process = digest(0x78);
    const auto private_evidence = evidence(closure);
    {
        auto archive_capability = archive(
            selected, closure, private_evidence);
        auto c03_capability = c03(
            selected, closure, process, private_evidence);
        auto c1_round1 = c1(selected, 1);
        auto c1_round2 = c1(selected, 2);
        auto admitted = ObserverCaptureCapsuleBridge::admit(
            std::move(archive_capability), std::move(c03_capability),
            std::move(c1_round1), std::move(c1_round2));
        TrialCaptureJoiner joiner(selected, parent_manifest(selected));
        joiner.submit(producer(
            selected, closure, process, private_evidence),
            std::move(admitted));
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::admit(
                std::move(archive_capability), std::move(c03_capability),
                std::move(c1_round1), std::move(c1_round2));
        });
    }
    {
        const auto other = binding(0x50);
        auto archive_capability = archive(
            selected, closure, private_evidence);
        auto c03_capability = c03(
            other, closure, process, private_evidence);
        auto c1_round1 = c1(selected, 1);
        auto c1_round2 = c1(selected, 2);
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::admit(
                std::move(archive_capability), std::move(c03_capability),
                std::move(c1_round1), std::move(c1_round2));
        });
    }
    {
        auto archive_capability = archive(
            selected, closure, private_evidence);
        const auto other_closure = digest(0x79);
        auto c03_capability = c03(
            selected, other_closure, process, evidence(other_closure));
        auto c1_round1 = c1(selected, 1);
        auto c1_round2 = c1(selected, 2);
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::admit(
                std::move(archive_capability), std::move(c03_capability),
                std::move(c1_round1), std::move(c1_round2));
        });
    }
}

void sealed_archive_without_structural_continuity_refuses_snapshot() {
    const auto selected = binding();
    const auto closure = digest(0x77);
    const auto process = digest(0x78);
    const auto private_evidence = evidence(closure);
    auto archive_capability = archive(
        selected, closure, private_evidence);
    auto c03_capability = c03(
        selected, closure, process, private_evidence);
    auto c1_round1 = c1(selected, 1);
    auto c1_round2 = c1(selected, 2);
    auto admitted = ObserverCaptureCapsuleBridge::admit(
        std::move(archive_capability), std::move(c03_capability),
        std::move(c1_round1), std::move(c1_round2));
    auto closure_authority = producer(
        selected, closure, process, private_evidence);
    admitted.require_matches(
        selected, closure_authority.public_receipt(), private_evidence);
    const PublicObserverPermit permit{
        .binding = selected,
        .trial_capture_identity = digest(0xa1),
        .permit_identity = digest(0xa2),
    };
    expect_refused([&] {
        (void)ObserverCaptureCapsuleBridge::test_only_snapshot_archive(
            std::move(admitted), permit);
    });
}

void cross_binding_and_closure_substitution_burns_inputs() {
    const auto selected = binding();
    const auto other = binding(0x50);
    const auto closure = digest(0x77);
    const auto process = digest(0x78);
    const auto private_evidence = evidence(closure);
    {
        const auto directory = make_spool_directory();
        auto spool_capability = spool(
            directory, selected, closure, process, private_evidence);
        auto c03_capability = c03(
            other, closure, process, private_evidence);
        auto c1_round1 = c1(selected, 1);
        auto c1_round2 = c1(selected, 2);
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::admit(
                std::move(spool_capability), std::move(c03_capability),
                std::move(c1_round1), std::move(c1_round2));
        });
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::admit(
                std::move(spool_capability), std::move(c03_capability),
                std::move(c1_round1), std::move(c1_round2));
        });
        remove_spool_directory(directory);
    }
    {
        const auto directory = make_spool_directory();
        auto spool_capability = spool(
            directory, selected, closure, process, private_evidence);
        auto c03_capability = c03(
            selected, digest(0x79), process, evidence(digest(0x79)));
        auto c1_round1 = c1(selected, 1);
        auto c1_round2 = c1(selected, 2);
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::admit(
                std::move(spool_capability), std::move(c03_capability),
                std::move(c1_round1), std::move(c1_round2));
        });
        remove_spool_directory(directory);
    }
    {
        const auto directory = make_spool_directory();
        auto spool_capability = spool(
            directory, selected, closure, process, private_evidence);
        auto c03_capability = c03(
            selected, closure, process, private_evidence);
        auto c1_round1 = c1(selected, 1);
        auto c1_round2 = c1(selected, 2);
        expect_refused([&] {
            (void)ObserverCaptureCapsuleBridge::admit(
                std::move(spool_capability), std::move(c03_capability),
                std::move(c1_round2), std::move(c1_round1));
        });
        remove_spool_directory(directory);
    }
}

void c03_streams_match_exact_round_source_process_and_exit() {
    const auto selected = binding();
    const auto closure = digest(0x77);
    const auto process = digest(0x78);
    const auto private_evidence = evidence(closure);
    {
        const auto directory = make_spool_directory();
        auto admitted = admission(
            directory, selected, closure, process, private_evidence,
            c03_rounds(selected));
        TrialCaptureJoiner joiner(selected, parent_manifest(selected));
        joiner.submit(producer(
            selected, closure, process, private_evidence),
            std::move(admitted));
        remove_spool_directory(directory);
    }
    {
        auto wrong_source = c03_rounds(selected);
        wrong_source[0].source_identity = digest(0x05);
        const auto directory = make_spool_directory();
        auto admitted = admission(
            directory, selected, closure, process, private_evidence,
            wrong_source);
        TrialCaptureJoiner joiner(selected, parent_manifest(selected));
        expect_refused([&] {
            joiner.submit(producer(
                selected, closure, process, private_evidence),
                std::move(admitted));
        });
        remove_spool_directory(directory);
    }
    {
        const auto directory = make_spool_directory();
        auto admitted = admission(
            directory, selected, closure, process, private_evidence,
            c03_rounds(selected));
        TrialCaptureJoiner joiner(selected, parent_manifest(selected));
        expect_refused([&] {
            joiner.submit(producer(
                selected, closure, process, private_evidence,
                false, true, false), std::move(admitted));
        });
        remove_spool_directory(directory);
    }
    {
        const auto directory = make_spool_directory();
        auto admitted = admission(
            directory, selected, closure, process, private_evidence,
            c03_rounds(selected));
        TrialCaptureJoiner joiner(selected, parent_manifest(selected));
        expect_refused([&] {
            joiner.submit(producer(
                selected, closure, process, private_evidence,
                false, false, true), std::move(admitted));
        });
        remove_spool_directory(directory);
    }
    expect_refused([&] {
        (void)producer(selected, closure, process, private_evidence,
                       true, false, false);
    });
}

void fixture_admission_never_reaches_fd40() {
    auto permit = ObserverPermitAuthority::test_only_mint(
        PublicObserverPermit{.binding = binding(),
                             .trial_capture_identity = digest(0xa1),
                             .permit_identity = digest(0xa2)});
    expect_refused([&] {
        (void)ObserverCaptureCapsuleBridge::prepare(
            std::move(permit), -1, -1, -1);
    });
}

void endpoint_identity_is_salted_and_entropy_fails_closed() {
    const PublicObserverPermit permit{
        .binding = binding(),
        .trial_capture_identity = digest(0xa1),
        .permit_identity = digest(0xa2),
    };
    const auto snapshot_hash = digest(0xb1);
    const auto first_nonce = digest(0xb2);
    const auto second_nonce = digest(0xb3);
    const auto first =
        ObserverCaptureCapsuleBridge::test_only_endpoint_identity(
            snapshot_hash, 123456, permit, first_nonce);
    const auto repeated =
        ObserverCaptureCapsuleBridge::test_only_endpoint_identity(
            snapshot_hash, 123456, permit, first_nonce);
    const auto second =
        ObserverCaptureCapsuleBridge::test_only_endpoint_identity(
            snapshot_hash, 123456, permit, second_nonce);
    assert(first == repeated && first != second &&
           first != snapshot_hash && second != snapshot_hash &&
           first != first_nonce && second != second_nonce);
    ObserverCaptureCapsuleBridge::test_only_force_entropy_failure(true);
    expect_refused([] {
        ObserverCaptureCapsuleBridge::test_only_require_entropy();
    });
    ObserverCaptureCapsuleBridge::test_only_force_entropy_failure(false);
    ObserverCaptureCapsuleBridge::test_only_force_entropy_short_read(true);
    expect_refused([] {
        ObserverCaptureCapsuleBridge::test_only_require_entropy();
    });
    ObserverCaptureCapsuleBridge::test_only_force_entropy_short_read(false);
    ObserverCaptureCapsuleBridge::test_only_require_entropy();
}

} // namespace

int main() {
    sealed_archive_is_the_production_admission_and_binds_closure();
    sealed_archive_without_structural_continuity_refuses_snapshot();
    exact_live_capabilities_are_required_once();
    cross_binding_and_closure_substitution_burns_inputs();
    c03_streams_match_exact_round_source_process_and_exit();
    fixture_admission_never_reaches_fd40();
    endpoint_identity_is_salted_and_entropy_fails_closed();
}
