#include "privacy_p1_observed_transcript_authority.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::p1_observed_transcript;

namespace {

constexpr std::size_t HEADER = 112;
constexpr std::size_t CHUNK = 1U << 16;

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

std::size_t frame_payload_size(const std::vector<unsigned char>& raw,
                               std::size_t at) {
    assert(at + HEADER <= raw.size());
    return (static_cast<std::size_t>(raw[at + 44]) << 24) |
        (static_cast<std::size_t>(raw[at + 45]) << 16) |
        (static_cast<std::size_t>(raw[at + 46]) << 8) |
        raw[at + 47];
}

std::size_t find_frame(const std::vector<unsigned char>& raw, unsigned type,
                       unsigned semantic, unsigned occurrence = 0) {
    for (std::size_t at = 0; at + HEADER <= raw.size();) {
        if (raw[at + 8] == type && raw[at + 9] == semantic) {
            if (occurrence == 0) return at;
            --occurrence;
        }
        at += HEADER + frame_payload_size(raw, at);
    }
    assert(false);
    return 0;
}

void rehash_frame(std::vector<unsigned char>& raw, std::size_t at) {
    const auto size = frame_payload_size(raw, at);
    const auto digest = hash(std::span(raw).subspan(at + HEADER, size));
    std::copy(digest.begin(), digest.end(), raw.begin() + at + 80);
}

void be32(unsigned char* out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        *out++ = static_cast<unsigned char>(value >> shift);
}

void be64(unsigned char* out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        *out++ = static_cast<unsigned char>(value >> shift);
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
    const auto worker = [](const ManifestEntry& entry) {
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
    result.observer_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    return result;
}

WorkerBinding p1_worker(const RunBinding& selected) {
    const auto& entry = selected.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

struct Counter {
    std::uint64_t messages{};
    std::uint64_t chunks{};
    std::uint64_t bytes{};
};

struct WireBuilder {
    std::vector<unsigned char> raw;
    std::uint64_t sequence{};
    std::uint64_t message{};
    std::uint64_t monotonic{1'000};
    std::uint64_t first_monotonic{};
    std::uint64_t last_monotonic{};
    std::array<Counter, 17> counters{};
    std::array<unsigned char, 32> root{};

    void emit(unsigned type, unsigned semantic, unsigned direction,
              unsigned peer, const std::array<unsigned char, 32>& fork,
              std::span<const unsigned char> payload, bool count) {
        const std::size_t chunks = payload.empty()
            ? 1 : (payload.size() - 1) / CHUNK + 1;
        for (std::size_t chunk = 0; chunk < chunks; ++chunk) {
            const std::size_t offset = chunk * CHUNK;
            const std::size_t size = payload.empty()
                ? 0 : std::min(CHUNK, payload.size() - offset);
            const auto selected = payload.subspan(offset, size);
            std::array<unsigned char, HEADER> header{};
            std::copy_n("KPBP1C03", 8, header.begin());
            header[8] = static_cast<unsigned char>(type);
            header[9] = static_cast<unsigned char>(semantic);
            header[10] = static_cast<unsigned char>(direction);
            header[11] = static_cast<unsigned char>(peer);
            header[12] = static_cast<unsigned char>(
                (chunk == 0 ? 1 : 0) | (chunk + 1 == chunks ? 2 : 0));
            be64(header.data() + 16, monotonic++);
            if (first_monotonic == 0)
                first_monotonic = monotonic - 1;
            last_monotonic = monotonic - 1;
            be64(header.data() + 24, sequence++);
            be64(header.data() + 32, message);
            be32(header.data() + 40, static_cast<std::uint32_t>(chunk));
            be32(header.data() + 44, static_cast<std::uint32_t>(size));
            std::copy(fork.begin(), fork.end(), header.begin() + 48);
            const auto selected_hash = hash(selected);
            std::copy(selected_hash.begin(), selected_hash.end(),
                      header.begin() + 80);
            raw.insert(raw.end(), header.begin(), header.end());
            raw.insert(raw.end(), selected.begin(), selected.end());
            if (count) {
                auto& lane = counters.at(semantic - 1);
                ++lane.chunks;
                lane.bytes += size;
            }
        }
        if (count) ++counters.at(semantic - 1).messages;
        ++message;
    }
};

std::vector<unsigned char> completeness(const WireBuilder& wire) {
    std::vector<unsigned char> result(496);
    be32(result.data(), 9);
    be32(result.data() + 4, 17);
    std::uint64_t messages = 0, chunks = 0, bytes = 0;
    for (const auto& lane : wire.counters) {
        messages += lane.messages;
        chunks += lane.chunks;
        bytes += lane.bytes;
    }
    be64(result.data() + 8, messages);
    be64(result.data() + 16, chunks);
    be64(result.data() + 24, bytes);
    for (unsigned semantic = 0; semantic < wire.counters.size(); ++semantic) {
        const auto offset = 32 + semantic * 24;
        be64(result.data() + offset, wire.counters[semantic].messages);
        be64(result.data() + offset + 8, wire.counters[semantic].chunks);
        be64(result.data() + offset + 16, wire.counters[semantic].bytes);
    }
    be64(result.data() + 440, (1U << 17) - 1);
    be64(result.data() + 448, 7);
    be64(result.data() + 456, 7);
    be64(result.data() + 464, (1U << 22) - 1);
    be64(result.data() + 472, wire.sequence);
    be64(result.data() + 480, wire.first_monotonic);
    be64(result.data() + 488, wire.last_monotonic);
    return result;
}

struct Fixture {
    StaticTranscriptPlan plan;
    std::vector<unsigned char> raw;
    std::uint64_t peer_payload_bytes{};
    std::uint64_t peer_wire_bytes{};
    std::uint64_t peer_chunks{};
};

Fixture fixture() {
    WireBuilder wire;
    std::vector<unsigned char> hello(332, 0x31);
    hello[0] = 1;
    hello[1] = 1;
    hello[2] = 0;
    hello[3] = 23;
    wire.emit(1, 1, 3, 0xff, wire.root, hello, false);

    std::array<unsigned char, 32> key{};
    key.fill(0x41);
    wire.emit(2, 14, 3, 0xff, wire.root, key, true);
    for (unsigned owner = 0; owner < 3; ++owner) {
        std::vector<unsigned char> preprocessing(160, 0x50 + owner);
        std::vector<unsigned char> offset(32, 0x60 + owner);
        wire.emit(2, 11, 1, owner, wire.root, preprocessing, true);
        wire.emit(2, 1, 2, owner, wire.root, offset, true);
    }

    const std::array<unsigned char, 3> first_peer{0x10, 0x11, 0x12};
    wire.emit(2, 2, 1, 2, wire.root, first_peer, true);
    std::array<unsigned char, 32> child{};
    child.fill(0x71);
    std::vector<unsigned char> fork_payload;
    fork_payload.insert(fork_payload.end(), wire.root.begin(), wire.root.end());
    fork_payload.insert(fork_payload.end(), child.begin(), child.end());
    const auto suffix = digest(0x72);
    fork_payload.insert(fork_payload.end(), suffix.begin(), suffix.end());
    wire.emit(6, 2, 3, 0xff, wire.root, fork_payload, false);
    std::vector<unsigned char> second_peer(3 * CHUNK + 17, 0xa7);
    wire.emit(2, 2, 2, 0, child, second_peer, true);

    for (unsigned site = 1; site <= 22; ++site) {
        const bool random = site == 1 || site == 7 || site == 20 || site == 21;
        std::array<unsigned char, 16> binding{};
        binding[0] = 1;
        binding[1] = random ? 2 : 1;
        binding[2] = static_cast<unsigned char>(site >> 8);
        binding[3] = static_cast<unsigned char>(site);
        be64(binding.data() + 4, 1);
        wire.emit(2, 17, 3, 0xff, wire.root, binding, true);
        std::array<unsigned char, 32> share{};
        share.fill(static_cast<unsigned char>(site));
        std::array<unsigned char, 32> mac{};
        mac.fill(static_cast<unsigned char>(site + 32));
        wire.emit(2, random ? 5 : 3, 3, 0xff, wire.root, share, true);
        wire.emit(2, random ? 6 : 4, 3, 0xff, wire.root, mac, true);
    }

    std::array<unsigned char, 32> field{};
    field.fill(0x81);
    wire.emit(2, 10, 3, 0xff, wire.root, field, true);
    const auto group = [&](unsigned semantic, unsigned size, unsigned stage,
                           unsigned fill) {
        std::vector<unsigned char> body(size, static_cast<unsigned char>(fill));
        if (semantic == 15 || semantic == 16)
            body[0] = static_cast<unsigned char>(stage);
        wire.emit(2, semantic, 3, 0xff, wire.root, body, true);
        return body;
    };
    const auto base_a = group(15, 521, 1, 0x91);
    const auto base_b2 = group(16, 259, 1, 0x92);
    (void)group(15, 781, 2, 0x93);
    (void)group(13, 64, 0, 0x94);
    (void)group(12, 130, 0, 0x95);
    (void)group(15, 261, 3, 0x96);
    std::vector<unsigned char> final_a(261, 0x97);
    final_a[0] = 4;
    std::copy_n(base_a.begin() + 1, 130, final_a.begin() + 1);
    wire.emit(2, 15, 3, 0xff, wire.root, final_a, true);
    std::vector<unsigned char> final_b2(259, 0x98);
    final_b2[0] = 4;
    std::copy_n(base_b2.begin() + 1, 258, final_b2.begin() + 1);
    wire.emit(2, 16, 3, 0xff, wire.root, final_b2, true);
    (void)group(7, 130, 0, 0x99);
    (void)group(8, 129, 0, 0x9a);
    std::vector<unsigned char> projection(10685, 0xb1);
    wire.emit(2, 9, 3, 0xff, wire.root, projection, true);
    const auto projection_hash = hash(projection);
    wire.emit(3, 9, 3, 0xff, wire.root, projection_hash, false);
    const auto footer = completeness(wire);
    wire.emit(4, 9, 3, 0xff, wire.root, footer, false);
    wire.emit(5, 9, 3, 0xff, wire.root, {}, false);

    const auto selected = binding();
    StaticTranscriptPlan plan{
        .binding = selected,
        .round = 1,
        .fixed_fd = 23,
        .accepted_head_identity = digest(0x30),
        .historical_nullifier_count = 17,
        .p1_worker = p1_worker(selected),
        .selected_main_identity = digest(0x31),
        .p1_capture_source_identity = selected.capture_source,
        .p1_capture_build_identity = selected.capture_build,
        .model_preimage_identity = digest(0x32),
        .query_store_identity = digest(0x33),
        .scalar_manifest_identity = digest(0x34),
        .online_options_identity = digest(0x35),
        .ot_extension = OtExtensionProfile::SoftSpoken,
        .ot_parameters_identity = digest(0x36),
        .mascot_secrets_policy = MascotSecretsPolicy::FreshRegeneration,
        .mascot_secrets_policy_identity = digest(0x37),
        .player_virtual_surface_identity = digest(0x38),
        .expected_hello_payload_sha256 = hash(hello),
        .archive_filesystem_identity = digest(0x39),
    };
    const std::uint64_t peer_payload = first_peer.size() + second_peer.size();
    const std::uint64_t peer_chunks = 1 +
        (second_peer.size() + CHUNK - 1) / CHUNK;
    return {
        .plan = std::move(plan),
        .raw = std::move(wire.raw),
        .peer_payload_bytes = peer_payload,
        .peer_wire_bytes = peer_payload + HEADER * peer_chunks,
        .peer_chunks = peer_chunks,
    };
}

ObservedTranscriptCompletionAuthority build(const Fixture& selected) {
    auto plan = ObservedTranscriptPlanAuthority::test_only_mint(selected.plan);
    auto writer = std::move(plan).begin_capture();
    std::size_t offset = 0;
    const std::array<std::size_t, 5> pieces{7, 113, 4093, 65539, 8191};
    unsigned piece = 0;
    while (offset < selected.raw.size()) {
        const auto amount = std::min(
            pieces[piece++ % pieces.size()], selected.raw.size() - offset);
        writer.append(std::span(selected.raw).subspan(offset, amount));
        offset += amount;
    }
    return std::move(writer).finish_after_kernel_eof();
}

void exact_actual_transcript_is_writer_closed_and_one_shot() {
    static_assert(!std::is_copy_constructible_v<
                  ObservedTranscriptPlanAuthority>);
    static_assert(!std::is_copy_constructible_v<
                  ObservedTranscriptWriterAuthority>);
    static_assert(!std::is_copy_constructible_v<
                  ObservedTranscriptCompletionAuthority>);
    static_assert(std::is_move_constructible_v<
                  ObservedTranscriptCompletionAuthority>);
    const auto selected = fixture();
    auto completion = build(selected);
    const auto summary = completion.test_only_summary();
    assert(summary.plan == selected.plan);
    assert(summary.raw_wire_bytes == selected.raw.size());
    assert(summary.peer_messages == 2);
    assert(summary.peer_chunks == selected.peer_chunks);
    assert(summary.peer_payload_bytes == selected.peer_payload_bytes);
    assert(summary.peer_wire_bytes == selected.peer_wire_bytes);
    assert(summary.fork_messages == 1 && summary.fork_wire_bytes == 208);
    assert(summary.read_only && summary.anonymous_disk_backed &&
           summary.writer_closed);
    assert(completion.test_only_read_all() == selected.raw);
}

void framing_transcript_footer_and_truncation_mutations_refuse() {
    const auto original = fixture();
    std::vector<std::vector<unsigned char>> variants;

    auto payload = original.raw;
    payload[HEADER] ^= 1;
    variants.push_back(std::move(payload));

    auto sequence = original.raw;
    sequence[24] ^= 1;
    variants.push_back(std::move(sequence));

    auto fork = original.raw;
    std::size_t at = 0;
    while (!(fork[at + 8] == 2 && fork[at + 9] == 2 &&
             fork[at + 11] == 0))
        at += HEADER + static_cast<std::size_t>(
            (fork[at + 44] << 24) | (fork[at + 45] << 16) |
            (fork[at + 46] << 8) | fork[at + 47]);
    fork[at + 48] ^= 1;
    variants.push_back(std::move(fork));

    auto compensated_fork = original.raw;
    at = find_frame(compensated_fork, 6, 2);
    compensated_fork[at + HEADER + 32] ^= 1;
    rehash_frame(compensated_fork, at);
    variants.push_back(std::move(compensated_fork));

    auto wrong_group_stage = original.raw;
    at = find_frame(wrong_group_stage, 2, 15, 0);
    wrong_group_stage[at + HEADER] = 2;
    rehash_frame(wrong_group_stage, at);
    variants.push_back(std::move(wrong_group_stage));

    auto wrong_repeated_a = original.raw;
    at = find_frame(wrong_repeated_a, 2, 15, 3);
    wrong_repeated_a[at + HEADER + 1] ^= 1;
    rehash_frame(wrong_repeated_a, at);
    variants.push_back(std::move(wrong_repeated_a));

    auto wrong_repeated_b2 = original.raw;
    at = find_frame(wrong_repeated_b2, 2, 16, 1);
    wrong_repeated_b2[at + HEADER + 1] ^= 1;
    rehash_frame(wrong_repeated_b2, at);
    variants.push_back(std::move(wrong_repeated_b2));

    auto wrong_projection_seal = original.raw;
    at = find_frame(wrong_projection_seal, 3, 9);
    wrong_projection_seal[at + HEADER] ^= 1;
    rehash_frame(wrong_projection_seal, at);
    variants.push_back(std::move(wrong_projection_seal));

    auto wrong_scalar_count = original.raw;
    at = find_frame(wrong_scalar_count, 2, 17);
    wrong_scalar_count[at + HEADER + 11] = 2;
    rehash_frame(wrong_scalar_count, at);
    variants.push_back(std::move(wrong_scalar_count));

    auto footer = original.raw;
    at = 0;
    while (footer[at + 8] != 4)
        at += HEADER + static_cast<std::size_t>(
            (footer[at + 44] << 24) | (footer[at + 45] << 16) |
            (footer[at + 46] << 8) | footer[at + 47]);
    const auto footer_payload = at + HEADER;
    footer[footer_payload + 32 + 24] ^= 1; // peer messages
    const auto footer_size = static_cast<std::size_t>(
        (footer[at + 44] << 24) | (footer[at + 45] << 16) |
        (footer[at + 46] << 8) | footer[at + 47]);
    const auto new_hash = hash(std::span(footer).subspan(
        footer_payload, footer_size));
    std::copy(new_hash.begin(), new_hash.end(), footer.begin() + at + 80);
    variants.push_back(std::move(footer));

    auto truncated = original.raw;
    truncated.pop_back();
    variants.push_back(std::move(truncated));

    for (const auto& raw : variants) {
        auto plan = ObservedTranscriptPlanAuthority::test_only_mint(
            original.plan);
        auto writer = std::move(plan).begin_capture();
        expect_refused([&] {
            writer.append(raw);
            (void)std::move(writer).finish_after_kernel_eof();
        });
    }
}

void static_binding_cross_round_and_replay_refuse() {
    const auto selected = fixture();
    auto wrong_fd = selected.plan;
    wrong_fd.fixed_fd = 28;
    expect_refused([&] {
        (void)ObservedTranscriptPlanAuthority::test_only_mint(wrong_fd);
    });

    auto wrong_worker = selected.plan;
    wrong_worker.p1_worker.source_identity[0] ^= 1;
    expect_refused([&] {
        (void)ObservedTranscriptPlanAuthority::test_only_mint(wrong_worker);
    });

    auto wrong_round = selected.plan;
    wrong_round.round = 2;
    wrong_round.fixed_fd = 28;
    auto plan = ObservedTranscriptPlanAuthority::test_only_mint(wrong_round);
    auto writer = std::move(plan).begin_capture();
    expect_refused([&] { writer.append(selected.raw); });

    auto live_plan = ObservedTranscriptPlanAuthority::test_only_mint(
        selected.plan);
    auto live_writer = std::move(live_plan).begin_capture();
    expect_refused([&] {
        (void)std::move(live_plan).begin_capture();
    });
    live_writer.append(selected.raw);
    auto completion = std::move(live_writer).finish_after_kernel_eof();
    expect_refused([&] {
        (void)std::move(live_writer).finish_after_kernel_eof();
    });
    assert(completion.test_only_summary().writer_closed);
}

} // namespace

int main() {
    exact_actual_transcript_is_writer_closed_and_one_shot();
    framing_transcript_footer_and_truncation_mutations_refuse();
    static_binding_cross_round_and_replay_refuse();
}
