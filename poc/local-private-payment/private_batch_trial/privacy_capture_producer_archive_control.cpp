#include "privacy_capture_producer_archive.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include <openssl/sha.h>
#include <new>
#include <signal.h>
#include <set>
#include <span>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::producer_archive;

namespace {
std::atomic_bool fail_allocation{false};
}

void* operator new(std::size_t size) {
    if (fail_allocation.load()) throw std::bad_alloc();
    if (void* value = std::malloc(size)) return value;
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
    return ::operator new(size);
}

void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete[](void* value, std::size_t) noexcept {
    std::free(value);
}

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

RunBinding binding() {
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = digest(0x10);
    result.run_selection = digest(0x11);
    result.trial = digest(0x12);
    result.attempt = digest(0x13);
    result.cohort = digest(0x14);
    result.capture = digest(0x15);
    result.method = digest(0x16);
    result.workload = digest(0x17);
    result.source_closure = digest(0x18);
    result.runtime = digest(0x19);
    result.outer_parent_process = digest(0x1a);
    result.outer_parent_executable = digest(0x1b);
    result.financial_runs = {digest(0x20), digest(0x21)};
    result.round_attempts = {digest(0x22), digest(0x23)};
    result.round_cohorts = {digest(0x24), digest(0x25)};
    result.round_capture_plans = {digest(0x26), digest(0x27)};
    result.projections = {digest(0x28), digest(0x29)};
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0x40 + index * 7);
        result.finite_manifest.entries[index] = {
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
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.finite_manifest.parent_recomputation_identity = digest(0xfc);
    const auto to_worker = [](const ManifestEntry& entry) {
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
    result.observer_worker = to_worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = to_worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = to_worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    return result;
}

std::vector<unsigned char> wire(unsigned slot) {
    std::vector<unsigned char> result(64 + slot);
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(slot * 19 + index);
    return result;
}

ProducerStreamClosureEvidence evidence(
        unsigned slot, std::span<const unsigned char> bytes) {
    ProducerStreamClosureEvidence result{
        .record_root = hash(bytes),
        .end_frame_identity = digest(
            static_cast<unsigned char>(0x50 + slot)),
        .record_count = 3 + slot,
        .payload_bytes = bytes.size() - 1,
        .raw_wire_bytes = bytes.size(),
    };
    static constexpr char label[] =
        "KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n";
    std::vector<unsigned char> preimage(
        label, label + sizeof(label) - 1);
    big_integer(preimage, slot / 5 + 1, 4);
    preimage.push_back(static_cast<unsigned char>(slot % 5 + 1));
    big_integer(preimage, result.record_count, 8);
    big_integer(preimage, result.payload_bytes, 8);
    big_integer(preimage, result.raw_wire_bytes, 8);
    add(preimage, result.record_root);
    add(preimage, result.end_frame_identity);
    result.eof_identity = hash(preimage);
    return result;
}

struct Built {
    ProducerSealedArchiveAuthority authority;
    std::array<ProducerStreamClosureEvidence,
               PRODUCER_ARCHIVE_STREAM_COUNT> evidence;
};

Built build(const RunBinding& selected, const Digest& closure) {
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        selected, closure);
    std::array<ProducerStreamClosureEvidence,
               PRODUCER_ARCHIVE_STREAM_COUNT> results{};
    for (unsigned slot = 0; slot < results.size(); ++slot) {
        const auto bytes = wire(slot);
        const auto middle = bytes.size() / 2;
        builder.append(slot, std::span(bytes).first(middle));
        builder.append(slot, std::span(bytes).subspan(middle));
        results[slot] = evidence(slot, bytes);
        builder.finish_after_end_and_eof(slot, results[slot]);
    }
    return {std::move(builder).finish(), results};
}

void exact_ten_slots_seal_transport_and_adopt_once() {
    static_assert(!std::is_copy_constructible_v<
                  ProducerSealedArchiveBuilder>);
    static_assert(!std::is_copy_constructible_v<
                  ProducerSealedArchiveAuthority>);
    static_assert(std::is_move_constructible_v<
                  ProducerSealedArchiveAuthority>);
    static_assert(noexcept(
        ProducerSealedArchiveBuilder::test_only_quarantine(
            std::declval<ProducerSealedArchiveBuilder&&>(),
            ProducerArchiveQuarantineStage::Internal, EPROTO)));
    const auto selected = binding();
    const auto closure = digest(0x33);
    auto built = build(selected, closure);
    assert(built.authority.test_only_matches(
        selected, closure, built.evidence));
    auto c03 = built.authority.test_only_duplicate_c03_for_runtime();
    const auto c03_summary = c03.test_only_summary();
    assert(c03_summary.reservation_identity != Digest{});
    assert((c03_summary.source_slots == std::array<unsigned, 2>{3, 8}));
    assert((c03_summary.fixed_fds == std::array<unsigned, 2>{23, 28}));
    assert(c03_summary.complete_end_and_eof[0] &&
           c03_summary.complete_end_and_eof[1]);
    assert(c03_summary.sizes[0] == built.evidence[3].raw_wire_bytes &&
           c03_summary.sizes[1] == built.evidence[8].raw_wire_bytes &&
           c03_summary.sha256[0] == built.evidence[3].record_root &&
           c03_summary.sha256[1] == built.evidence[8].record_root);
    expect_refused([&] {
        (void)built.authority.test_only_duplicate_c03_for_runtime();
    });
    auto fds = built.authority.test_only_duplicate_transport_fds();
    for (int fd : fds) {
        assert(fd >= 80);
        assert((::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
        assert((::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY);
        errno = 0;
        assert(::fcntl(fd, F_GET_SEALS) == -1 && errno == EINVAL);
        struct stat value{};
        assert(::fstat(fd, &value) == 0 && S_ISREG(value.st_mode) &&
               (value.st_mode & 0777) == 0600 && value.st_nlink == 0);
    }
    expect_refused([&] {
        (void)built.authority.test_only_duplicate_transport_fds();
    });
    auto adopted =
        ProducerSealedArchiveAuthority::test_only_adopt_received(
            selected, closure, std::move(fds), built.evidence);
    assert(adopted.test_only_matches(selected, closure, built.evidence));
    for (int fd : fds) assert(fd == -1);
}

void wrong_root_eof_missing_slot_and_replay_refuse() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    {
        auto builder = ProducerSealedArchiveBuilder::test_only_begin(
            selected, closure);
        const auto bytes = wire(0);
        builder.append(0, bytes);
        auto wrong = evidence(0, bytes);
        wrong.record_root = digest(0xee);
        expect_refused([&] {
            builder.finish_after_end_and_eof(0, wrong);
        });
        expect_refused([&] { builder.append(0, bytes); });
    }
    {
        auto builder = ProducerSealedArchiveBuilder::test_only_begin(
            selected, closure);
        const auto bytes = wire(0);
        builder.append(0, bytes);
        auto wrong = evidence(0, bytes);
        wrong.eof_identity = digest(0xef);
        expect_refused([&] {
            builder.finish_after_end_and_eof(0, wrong);
        });
    }
    {
        auto builder = ProducerSealedArchiveBuilder::test_only_begin(
            selected, closure);
        for (unsigned slot = 0;
             slot + 1 < PRODUCER_ARCHIVE_STREAM_COUNT; ++slot) {
            const auto bytes = wire(slot);
            builder.append(slot, bytes);
            builder.finish_after_end_and_eof(
                slot, evidence(slot, bytes));
        }
        expect_refused([&] { (void)std::move(builder).finish(); });
        expect_refused([&] { (void)std::move(builder).finish(); });
    }
}

void parent_rejects_writable_and_duplicate_descriptors() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    {
        auto built = build(selected, closure);
        auto fds = built.authority.test_only_duplicate_transport_fds();
        std::array<char, 64> path{};
        const int count = std::snprintf(
            path.data(), path.size(), "/proc/self/fd/%d", fds[0]);
        assert(count > 0 && static_cast<std::size_t>(count) < path.size());
        const int writable = ::open(path.data(), O_RDWR | O_CLOEXEC);
        assert(writable >= 0);
        assert(::close(fds[0]) == 0);
        fds[0] = writable;
        expect_refused([&] {
            (void)ProducerSealedArchiveAuthority::test_only_adopt_received(
                selected, closure, std::move(fds), built.evidence);
        });
    }
    {
        auto built = build(selected, closure);
        auto fds = built.authority.test_only_duplicate_transport_fds();
        assert(::close(fds[1]) == 0);
        fds[1] = ::fcntl(fds[0], F_DUPFD_CLOEXEC, 90);
        assert(fds[1] >= 90);
        expect_refused([&] {
            (void)ProducerSealedArchiveAuthority::test_only_adopt_received(
                selected, closure, std::move(fds), built.evidence);
        });
    }
}

void partial_c03_slots_seal_empty_and_partial_and_roundtrip_once() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        selected, closure);
    const auto discarded = wire(0);
    const auto round2_partial = wire(8);
    builder.append(0, discarded);
    builder.append(8, std::span(round2_partial).first(17));
    auto partial = ProducerSealedArchiveBuilder::
        test_only_seal_partial_c03(std::move(builder));
    const auto before = partial.test_only_summary();
    assert(before.binding == selected && before.closure_identity == closure);
    assert((before.source_slots == std::array<unsigned, 2>{3, 8}));
    assert((before.fixed_fds == std::array<unsigned, 2>{23, 28}));
    assert((before.sizes == std::array<std::uint64_t, 2>{0, 17}));
    assert(!before.complete_end_and_eof[0] &&
           !before.complete_end_and_eof[1]);
    for (unsigned index = 0; index < 2; ++index) {
        assert(before.devices[index] != 0 && before.inodes[index] != 0);
        assert(before.seals[index] == 0);
        assert(before.read_only[index]);
        assert(before.writer_aliases_closed[index]);
        assert(before.sha256[index] != Digest{});
    }
    auto adopted = std::move(partial).test_only_transport_roundtrip();
    const auto after = adopted.test_only_summary();
    assert(after.binding == before.binding &&
           after.closure_identity == before.closure_identity &&
           after.devices == before.devices && after.inodes == before.inodes &&
           after.sizes == before.sizes && after.seals == before.seals &&
           after.sha256 == before.sha256 &&
           after.complete_end_and_eof == before.complete_end_and_eof);
    expect_refused([&] {
        (void)std::move(partial).test_only_transport_roundtrip();
    });
}

void completed_c03_slot_preserves_private_closure_and_failure_recovers() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    {
        auto builder = ProducerSealedArchiveBuilder::test_only_begin(
            selected, closure);
        const auto complete = wire(3);
        const auto partial = wire(8);
        builder.append(3, complete);
        builder.finish_after_end_and_eof(3, evidence(3, complete));
        builder.append(8, std::span(partial).first(9));
        auto authority = ProducerSealedArchiveBuilder::
            test_only_seal_partial_c03(std::move(builder));
        const auto summary = authority.test_only_summary();
        assert(summary.complete_end_and_eof[0]);
        assert(!summary.complete_end_and_eof[1]);
        auto roundtrip =
            std::move(authority).test_only_transport_roundtrip();
        const auto transported = roundtrip.test_only_summary();
        assert(transported.complete_end_and_eof ==
               summary.complete_end_and_eof);
    }
    {
        auto builder = ProducerSealedArchiveBuilder::test_only_begin(
            selected, closure);
        const auto bytes = wire(3);
        builder.append(3, bytes);
        auto wrong = evidence(3, bytes);
        wrong.record_root = digest(0xee);
        expect_refused([&] {
            builder.finish_after_end_and_eof(3, wrong);
        });
        auto recovered = ProducerSealedArchiveBuilder::
            test_only_seal_partial_c03(std::move(builder));
        const auto summary = recovered.test_only_summary();
        assert(summary.sizes[0] == bytes.size() &&
               !summary.complete_end_and_eof[0] &&
               summary.writer_aliases_closed[0]);
    }
}

void partial_transport_rejects_forged_metadata_and_descriptors() {
    using Fault = ProducerPartialC03ArchiveAuthority::TestOnlyTransportFault;
    const auto selected = binding();
    const auto closure = digest(0x33);
    const std::array faults{
        Fault::MissingFd,
        Fault::WritableFd,
        Fault::DuplicateInode,
        Fault::WrongSourceSlot,
        Fault::WrongSize,
        Fault::WrongHash,
        Fault::FalseComplete,
    };
    for (const auto fault : faults) {
        auto builder = ProducerSealedArchiveBuilder::test_only_begin(
            selected, closure);
        const auto bytes = wire(8);
        builder.append(8, std::span(bytes).first(11));
        auto partial = ProducerSealedArchiveBuilder::
            test_only_seal_partial_c03(std::move(builder));
        expect_refused([&] {
            (void)std::move(partial).test_only_transport_roundtrip(fault);
        });
        expect_refused([&] {
            (void)std::move(partial).test_only_transport_roundtrip();
        });
    }
}

void parent_retained_prefork_alias_survives_mid_drain_sigkill() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        selected, closure);
    const auto retained_writers = ProducerSealedArchiveBuilder::
        test_only_inherited_writer_fds(builder);
    std::array<struct stat, 2> original{};
    assert(::fstat(retained_writers[3], &original[0]) == 0 &&
           ::fstat(retained_writers[8], &original[1]) == 0);
    const auto round1_partial = wire(3);
    const auto round2_partial = wire(8);
    int ready[2]{-1, -1};
    assert(::pipe2(ready, O_CLOEXEC) == 0);
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        assert(::close(ready[0]) == 0);
        try {
            builder.append(3, std::span(round1_partial).first(21));
            builder.append(8, std::span(round2_partial).first(37));
            const unsigned char complete = 1;
            if (::write(ready[1], &complete, 1) != 1) _exit(120);
            for (;;) ::pause();
        } catch (...) {
            _exit(121);
        }
    }
    assert(::close(ready[1]) == 0);
    unsigned char complete = 0;
    assert(::read(ready[0], &complete, 1) == 1 && complete == 1);
    assert(::close(ready[0]) == 0);
    assert(::kill(child, SIGKILL) == 0);
    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

    auto recovered = ProducerSealedArchiveBuilder::
        test_only_seal_partial_c03(std::move(builder));
    const auto summary = recovered.test_only_summary();
    assert(summary.devices[0] ==
               static_cast<std::uint64_t>(original[0].st_dev) &&
           summary.inodes[0] ==
               static_cast<std::uint64_t>(original[0].st_ino) &&
           summary.devices[1] ==
               static_cast<std::uint64_t>(original[1].st_dev) &&
           summary.inodes[1] ==
               static_cast<std::uint64_t>(original[1].st_ino));
    assert((summary.sizes == std::array<std::uint64_t, 2>{21, 37}));
    assert(summary.sha256[0] ==
           hash(std::span(round1_partial).first(21)));
    assert(summary.sha256[1] ==
           hash(std::span(round2_partial).first(37)));
    assert(!summary.complete_end_and_eof[0] &&
           !summary.complete_end_and_eof[1]);
    for (unsigned index = 0; index < 2; ++index) {
        assert(summary.seals[index] == 0);
        assert(summary.read_only[index]);
        assert(summary.writer_aliases_closed[index]);
    }
}

void consumed_builder_failure_retains_all_ten_in_quarantine() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        selected, closure);
    const auto first = wire(3);
    const auto second = wire(8);
    builder.append(3, first);
    builder.append(8, second);
    ProducerSealedArchiveBuilder::
        test_only_fail_partial_after_first_transition(builder);
    expect_refused([&] {
        (void)ProducerSealedArchiveBuilder::test_only_seal_partial_c03(
            std::move(builder));
    });

    auto quarantine = ProducerSealedArchiveBuilder::test_only_quarantine(
        std::move(builder),
        ProducerArchiveQuarantineStage::PartialC03Seal, EIO);
    const auto summary = quarantine.test_only_summary();
    assert(summary.binding == selected &&
           summary.closure_identity == closure &&
           summary.reservation_identity != Digest{} &&
           summary.stage == ProducerArchiveQuarantineStage::PartialC03Seal &&
           summary.error_number == EIO);
    std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
    for (unsigned slot = 0; slot < PRODUCER_ARCHIVE_STREAM_COUNT; ++slot) {
        assert(summary.descriptor_retained[slot]);
        assert(summary.devices[slot] != 0 && summary.inodes[slot] != 0);
        assert(identities.emplace(
            summary.devices[slot], summary.inodes[slot]).second);
        assert(summary.access_modes[slot] == O_RDWR ||
               summary.access_modes[slot] == O_RDONLY);
    }
    assert(summary.sizes[3] == first.size() &&
           summary.sizes[8] == second.size() &&
           summary.access_modes[3] == O_RDONLY &&
           summary.access_modes[8] == O_RDWR);
    auto replay = ProducerSealedArchiveBuilder::test_only_quarantine(
        std::move(builder),
        ProducerArchiveQuarantineStage::PartialC03Seal, EIO);
    expect_refused([&] { (void)replay.test_only_summary(); });
}

void failed_full_finish_is_transactional_and_quarantinable() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        selected, closure);
    const auto bytes = wire(0);
    builder.append(0, bytes);
    builder.finish_after_end_and_eof(0, evidence(0, bytes));
    expect_refused([&] { (void)std::move(builder).finish(); });
    auto quarantine = ProducerSealedArchiveBuilder::test_only_quarantine(
        std::move(builder), ProducerArchiveQuarantineStage::FullSeal,
        EPROTO);
    const auto summary = quarantine.test_only_summary();
    assert(summary.descriptor_retained[0] &&
           summary.access_modes[0] == O_RDONLY && summary.finished[0]);
    for (unsigned slot = 1; slot < PRODUCER_ARCHIVE_STREAM_COUNT; ++slot) {
        assert(summary.descriptor_retained[slot] &&
               summary.access_modes[slot] == O_RDWR &&
               !summary.finished[slot]);
    }
}

void later_inspection_failure_retains_all_ten_after_partial_seal() {
    const auto selected = binding();
    const auto closure = digest(0x33);
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        selected, closure);
    const auto first = wire(3);
    const auto second = wire(8);
    builder.append(3, first);
    builder.append(8, second);

    auto partial = ProducerSealedArchiveBuilder::test_only_seal_partial_c03(
        std::move(builder));
    const auto partial_summary = partial.test_only_summary();
    auto quarantine = ProducerSealedArchiveBuilder::test_only_quarantine(
        std::move(builder), ProducerArchiveQuarantineStage::Inspection,
        EPROTO);
    const auto quarantine_summary = quarantine.test_only_summary();

    std::set<std::pair<std::uint64_t, std::uint64_t>> identities;
    for (unsigned slot = 0; slot < PRODUCER_ARCHIVE_STREAM_COUNT; ++slot) {
        assert(quarantine_summary.descriptor_retained[slot]);
        assert(identities.emplace(
            quarantine_summary.devices[slot],
            quarantine_summary.inodes[slot]).second);
    }
    assert(partial_summary.devices[0] == quarantine_summary.devices[3] &&
           partial_summary.inodes[0] == quarantine_summary.inodes[3] &&
           partial_summary.devices[1] == quarantine_summary.devices[8] &&
           partial_summary.inodes[1] == quarantine_summary.inodes[8] &&
           partial_summary.read_only[0] && partial_summary.read_only[1] &&
           quarantine_summary.access_modes[3] == O_RDONLY &&
           quarantine_summary.access_modes[8] == O_RDONLY);
}

void quarantine_transition_is_noalloc_after_claim() {
    auto builder = ProducerSealedArchiveBuilder::test_only_begin(
        binding(), digest(0x33));
    fail_allocation.store(true);
    ProducerArchiveQuarantineAuthority quarantine =
        ProducerSealedArchiveBuilder::test_only_quarantine(
            std::move(builder),
            ProducerArchiveQuarantineStage::Internal, ENOMEM);
    fail_allocation.store(false);
    const auto summary = quarantine.test_only_summary();
    assert(summary.error_number == ENOMEM &&
           summary.stage == ProducerArchiveQuarantineStage::Internal &&
           summary.reservation_identity != Digest{});
    for (const bool retained : summary.descriptor_retained) assert(retained);
}

} // namespace

int main() {
    exact_ten_slots_seal_transport_and_adopt_once();
    wrong_root_eof_missing_slot_and_replay_refuse();
    parent_rejects_writable_and_duplicate_descriptors();
    partial_c03_slots_seal_empty_and_partial_and_roundtrip_once();
    completed_c03_slot_preserves_private_closure_and_failure_recovers();
    partial_transport_rejects_forged_metadata_and_descriptors();
    parent_retained_prefork_alias_survives_mid_drain_sigkill();
    consumed_builder_failure_retains_all_ten_in_quarantine();
    failed_full_finish_is_transactional_and_quarantinable();
    later_inspection_failure_retains_all_ten_after_partial_seal();
    quarantine_transition_is_noalloc_after_claim();
}
