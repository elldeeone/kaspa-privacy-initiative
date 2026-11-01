#include "privacy_native_empirical_terminal_source.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <functional>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using namespace kpb::measurement;
using namespace kpb::measurement::empirical_terminal_source;
using Bytes = std::vector<unsigned char>;

constexpr std::array<unsigned char, 8> P1_MAGIC{
    'K', 'P', 'B', 'P', '1', 'C', '0', '3'};
constexpr std::string_view ATTEMPT_IDS[2]{
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
};
constexpr std::string_view CAPTURE_ID =
    "33333333-3333-4333-8333-333333333333";

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest word(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest text_identity(std::string_view domain, std::string_view value) {
    Bytes preimage(domain.begin(), domain.end());
    preimage.insert(preimage.end(), value.begin(), value.end());
    return hash(preimage);
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
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = word(0x10);
    result.run_selection = word(0x11);
    result.trial = word(0x12);
    result.attempt = word(0x13);
    result.cohort = word(0x14);
    result.capture = text_identity(
        "KPB_CAPTURE_IDENTITY_V1\n", CAPTURE_ID);
    result.method = word(0x16);
    result.workload = word(0x17);
    result.source_closure = word(0x18);
    result.runtime = word(0x19);
    result.outer_parent_process = word(0x1a);
    result.outer_parent_executable = word(0x1b);
    result.financial_runs = {word(0x20), word(0x21)};
    result.round_attempts = {
        text_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPT_IDS[0]),
        text_identity("KPB_CAPTURE_ATTEMPT_ID_V1\n", ATTEMPT_IDS[1]),
    };
    result.round_cohorts = {word(0x24), word(0x25)};
    result.round_capture_plans = {word(0x26), word(0x27)};
    result.projections = {word(0x28), word(0x29)};
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0x40 + index * 7);
        result.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = word(seed),
            .build_identity = word(static_cast<unsigned char>(seed + 1)),
            .runtime_identity = word(static_cast<unsigned char>(seed + 2)),
            .assets_identity = word(static_cast<unsigned char>(seed + 3)),
            .pinned_executable_identity =
                word(static_cast<unsigned char>(seed + 4)),
            .launcher_identity = word(static_cast<unsigned char>(seed + 5)),
        };
    }
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.finite_manifest.parent_recomputation_identity = word(0xfc);
    const auto& p1 = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    result.capture_source = p1.source_identity;
    result.capture_build = p1.build_identity;
    result.capture_runtime = p1.runtime_identity;
    result.capture_launcher = p1.launcher_identity;
    result.observer_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    validate_measurement_run_binding(result);
    return result;
}

void add_be32(Bytes& out, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out.push_back(static_cast<unsigned char>(
            value >> (8 * (3 - index))));
}

void add_be64(Bytes& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(
            value >> (8 * (7 - index))));
}

void set_be32(Bytes& out, std::size_t at, std::uint32_t value) {
    assert(at + 4 <= out.size());
    for (unsigned index = 0; index < 4; ++index)
        out[at + index] = static_cast<unsigned char>(
            value >> (8 * (3 - index)));
}

void set_be64(Bytes& out, std::size_t at, std::uint64_t value) {
    assert(at + 8 <= out.size());
    for (unsigned index = 0; index < 8; ++index)
        out[at + index] = static_cast<unsigned char>(
            value >> (8 * (7 - index)));
}

Bytes frame(std::uint8_t type, std::uint8_t semantic,
            std::uint8_t direction, std::uint8_t peer,
            std::uint64_t monotonic, std::uint64_t sequence,
            std::uint64_t message, std::span<const unsigned char> payload) {
    Bytes result(112, 0);
    std::copy(P1_MAGIC.begin(), P1_MAGIC.end(), result.begin());
    result[8] = type;
    result[9] = semantic;
    result[10] = direction;
    result[11] = peer;
    result[12] = 3;
    set_be64(result, 16, monotonic);
    set_be64(result, 24, sequence);
    set_be64(result, 32, message);
    set_be32(result, 40, 0);
    set_be32(result, 44, static_cast<std::uint32_t>(payload.size()));
    const auto digest = hash(payload);
    std::copy(digest.begin(), digest.end(), result.begin() + 80);
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

Bytes hello(const RunBinding& selected, unsigned index,
            const FinalC03RoundBinding& round) {
    Bytes result;
    result.push_back(static_cast<unsigned char>(round.round));
    result.push_back(1);
    result.push_back(0);
    result.push_back(static_cast<unsigned char>(round.fixed_fd));
    result.insert(result.end(), ATTEMPT_IDS[index].begin(),
                  ATTEMPT_IDS[index].end());
    result.insert(result.end(), round.cohort.begin(), round.cohort.end());
    result.insert(result.end(), round.financial_run.begin(),
                  round.financial_run.end());
    result.insert(result.end(), CAPTURE_ID.begin(), CAPTURE_ID.end());
    for (const auto* value : {
             &round.source_identity, &round.build_identity,
             &round.launcher_identity, &round.model_preimage_identity,
             &round.query_store_preimage_identity,
             &round.scalar_capture_manifest_identity})
        result.insert(result.end(), value->begin(), value->end());
    assert(result.size() == 332 && selected.capture == text_identity(
        "KPB_CAPTURE_IDENTITY_V1\n", CAPTURE_ID));
    return result;
}

Bytes completeness(std::uint64_t first_time,
                   std::uint64_t prior_time) {
    Bytes result(496, 0);
    set_be32(result, 0, 9);
    set_be32(result, 4, 17);
    set_be64(result, 8, 1);
    set_be64(result, 16, 1);
    set_be64(result, 24, 3);
    // The sole data row uses semantic PeerTransport (2).
    set_be64(result, 32 + 24, 1);
    set_be64(result, 32 + 24 + 8, 1);
    set_be64(result, 32 + 24 + 16, 3);
    set_be64(result, 440, (std::uint64_t{1} << 17) - 1);
    set_be64(result, 448, 7);
    set_be64(result, 456, 7);
    set_be64(result, 464, 1);
    set_be64(result, 472, 3);
    set_be64(result, 480, first_time);
    set_be64(result, 488, prior_time);
    return result;
}

struct StreamBody {
    Bytes raw;
    Bytes end;
};

StreamBody final_stream(const RunBinding& selected, unsigned index,
                        const FinalC03RoundBinding& round) {
    const std::uint64_t base = 1000 + 100 * index;
    const auto hello_payload = hello(selected, index, round);
    const std::array<unsigned char, 3> data{1, 2, 3};
    const auto completeness_payload = completeness(base, base + 2);
    const auto hello_frame = frame(1, 1, 3, 0xff, base, 0, 0,
                                   hello_payload);
    const auto data_frame = frame(2, 2, 1, 0, base + 1, 1, 1, data);
    const auto seal_frame = frame(3, 9, 3, 0xff, base + 2, 2, 2,
                                  round.projection);
    const auto complete_frame = frame(4, 9, 3, 0xff, base + 3, 3, 3,
                                      completeness_payload);
    const auto end_frame = frame(5, 9, 3, 0xff, base + 4, 4, 4, {});
    StreamBody result;
    for (const auto* value : {
             &hello_frame, &data_frame, &seal_frame, &complete_frame,
             &end_frame})
        result.raw.insert(result.raw.end(), value->begin(), value->end());
    result.end = end_frame;
    return result;
}

ProducerStreamClosureEvidence evidence(
        const Bytes& raw, unsigned round, const Bytes& end,
        std::uint64_t records = 5, std::uint64_t payload_bytes = 863) {
    ProducerStreamClosureEvidence result{
        .record_root = hash(raw),
        .end_frame_identity = hash(end),
        .record_count = records,
        .payload_bytes = payload_bytes,
        .raw_wire_bytes = raw.size(),
    };
    Bytes eof;
    constexpr std::string_view domain =
        "KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n";
    eof.insert(eof.end(), domain.begin(), domain.end());
    add_be32(eof, round);
    eof.push_back(4);
    add_be64(eof, records);
    add_be64(eof, payload_bytes);
    add_be64(eof, raw.size());
    eof.insert(eof.end(), result.record_root.begin(),
               result.record_root.end());
    eof.insert(eof.end(), result.end_frame_identity.begin(),
               result.end_frame_identity.end());
    result.eof_identity = hash(eof);
    return result;
}

int sealed_read_fd(std::span<const unsigned char> value,
                   bool reopen_read_only = true) {
    const int writer = ::memfd_create(
        "kpb-native-empirical-final-c03",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writer >= 0);
    std::size_t at = 0;
    while (at < value.size()) {
        ssize_t count;
        do {
            count = ::write(writer, value.data() + at, value.size() - at);
        } while (count < 0 && errno == EINTR);
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert(::fcntl(writer, F_ADD_SEALS, seals) == 0);
    if (!reopen_read_only) return writer;
    char path[64]{};
    assert(std::snprintf(path, sizeof(path), "/proc/self/fd/%d", writer) > 0);
    const int reader = ::open(path, O_RDONLY | O_CLOEXEC);
    assert(reader >= 0 && ::close(writer) == 0);
    return reader;
}

std::array<FinalC03RoundBinding, 2> round_bindings(
        const RunBinding& selected) {
    const auto& p1 = selected.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    std::array<FinalC03RoundBinding, 2> result{};
    for (unsigned index = 0; index < result.size(); ++index) {
        result[index] = {
            .round = index + 1,
            .fixed_fd = FINAL_C03_FIXED_FDS[index],
            .financial_run = selected.financial_runs[index],
            .attempt = selected.round_attempts[index],
            .cohort = selected.round_cohorts[index],
            .capture_plan = selected.round_capture_plans[index],
            .projection = selected.projections[index],
            .source_identity = p1.source_identity,
            .build_identity = p1.build_identity,
            .runtime_identity = p1.runtime_identity,
            .launcher_identity = p1.launcher_identity,
            .process_identity = word(static_cast<unsigned char>(0xd0 + index)),
            .child_exit_identity =
                word(static_cast<unsigned char>(0xd2 + index)),
            .model_preimage_identity =
                word(static_cast<unsigned char>(0xd4 + index)),
            .query_store_preimage_identity =
                word(static_cast<unsigned char>(0xd6 + index)),
            .scalar_capture_manifest_identity =
                word(static_cast<unsigned char>(0xd8 + index)),
        };
    }
    return result;
}

struct Fixture {
    RunBinding selected{binding()};
    std::array<FinalC03RoundBinding, 2> rounds{round_bindings(selected)};
    std::array<StreamBody, 2> streams{
        final_stream(selected, 0, rounds[0]),
        final_stream(selected, 1, rounds[1]),
    };

    Fixture() {
        for (unsigned index = 0; index < rounds.size(); ++index)
            rounds[index].closure_evidence = evidence(
                streams[index].raw, index + 1, streams[index].end);
    }

    std::array<int, 2> fds(bool read_only = true) const {
        return {
            sealed_read_fd(streams[0].raw, read_only),
            sealed_read_fd(streams[1].raw, read_only),
        };
    }
};

void valid_final_source_is_opaque_and_one_shot() {
    Fixture fixture;
    auto authority = NativeEmpiricalTerminalSourceParser::test_only_parse(
        fixture.selected, fixture.rounds, fixture.fds());
    const auto summary =
        NativeEmpiricalTerminalSourceParser::test_only_consume(
            std::move(authority));
    assert((summary.frame_counts == std::array<std::uint64_t, 2>{5, 5}));
    assert(summary.raw_wire_bytes[0] == fixture.streams[0].raw.size() &&
           summary.raw_wire_bytes[1] == fixture.streams[1].raw.size() &&
           !summary.complete_attempt_history);
    expect_refused([&] {
        (void)NativeEmpiricalTerminalSourceParser::test_only_consume(
            std::move(authority));
    });
}

void malformed_streams_refuse() {
    const std::array<std::function<void(Fixture&)>, 8> mutations{
        [](Fixture& value) {
            value.streams[0].raw.pop_back();
            value.rounds[0].closure_evidence = evidence(
                value.streams[0].raw, 1, value.streams[0].end);
        },
        [](Fixture& value) {
            value.streams[0].raw.push_back(0);
            value.rounds[0].closure_evidence = evidence(
                value.streams[0].raw, 1, value.streams[0].end);
        },
        [](Fixture& value) {
            value.streams[0].raw[112] ^= 1;
            value.rounds[0].closure_evidence = evidence(
                value.streams[0].raw, 1, value.streams[0].end);
        },
        [](Fixture& value) {
            const auto duplicate = value.streams[0].end;
            value.streams[0].raw.insert(value.streams[0].raw.end(),
                                        duplicate.begin(), duplicate.end());
            value.rounds[0].closure_evidence = evidence(
                value.streams[0].raw, 1, value.streams[0].end, 6, 863);
        },
        [](Fixture& value) {
            // First data frame sequence is immediately after HELLO+payload.
            const std::size_t data_header = 112 + 332;
            set_be64(value.streams[0].raw, data_header + 24, 9);
            value.rounds[0].closure_evidence = evidence(
                value.streams[0].raw, 1, value.streams[0].end);
        },
        [](Fixture& value) { value.rounds[0].attempt[0] ^= 1; },
        [](Fixture& value) {
            value.rounds[0].closure_evidence.record_root[0] ^= 1;
        },
        [](Fixture& value) {
            std::swap(value.streams[0], value.streams[1]);
            value.rounds[0].closure_evidence = evidence(
                value.streams[0].raw, 1, value.streams[0].end);
            value.rounds[1].closure_evidence = evidence(
                value.streams[1].raw, 2, value.streams[1].end);
        },
    };
    for (const auto& mutate : mutations) {
        Fixture fixture;
        mutate(fixture);
        expect_refused([&] {
            (void)NativeEmpiricalTerminalSourceParser::test_only_parse(
                fixture.selected, fixture.rounds, fixture.fds());
        });
    }
}

void writable_and_cross_process_lineage_refuse() {
    {
        Fixture fixture;
        expect_refused([&] {
            (void)NativeEmpiricalTerminalSourceParser::test_only_parse(
                fixture.selected, fixture.rounds, fixture.fds(false));
        });
    }
    {
        Fixture fixture;
        fixture.rounds[1].process_identity =
            fixture.rounds[0].process_identity;
        expect_refused([&] {
            (void)NativeEmpiricalTerminalSourceParser::test_only_parse(
                fixture.selected, fixture.rounds, fixture.fds());
        });
    }
}

} // namespace

int main() {
    static_assert(FINAL_C03_ARCHIVE_SLOTS ==
        std::array<unsigned, 2>{3, 8});
    static_assert(FINAL_C03_FIXED_FDS ==
        std::array<unsigned, 2>{23, 28});
    valid_final_source_is_opaque_and_one_shot();
    malformed_streams_refuse();
    writable_and_cross_process_lineage_refuse();
}
