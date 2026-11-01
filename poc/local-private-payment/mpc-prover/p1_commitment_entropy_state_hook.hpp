#pragma once

// Private, child-local evidence for MP-SPDZ commitment-opening randomness.
// The selected source callsite supplies the exact returned bytes; a future
// capsule adapter supplies the source-owned process/thread epochs. Nothing in
// this interface is a public receipt or a recorder factory.

#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace kpb::measurement::p1_state_capsule {
class P1EntropyStateAdapter;
}

namespace kpi::mpc::p1_private_state {

inline constexpr std::string_view COMMITMENT_ENTROPY_MP_SPDZ_COMMIT =
    "113c4e47dd94bca9ecab029d2f0abe649bea5c52";
inline constexpr std::string_view COMMITMENT_ENTROPY_EVENT_ENCODING_DOMAIN =
    "KPI_P1_COMMITMENT_ENTROPY_STATE_V1\n";
inline constexpr std::string_view COMMITMENT_ENTROPY_MANIFEST_ENCODING_DOMAIN =
    "KPI_P1_COMMITMENT_ENTROPY_MANIFEST_V1\n";
inline constexpr std::string_view COMMITMENT_ENTROPY_COMMIT_CPP_SHA256 =
    "3f99027fc0c31b847617d63043f3dfab1f8dc70e4337c8f1491032e7d8bcce8d";

enum class CommitmentEntropySourceSite : std::uint8_t {
    LegacyCommitFunction = 1,
    CommitmentObject = 2,
};

inline constexpr std::string_view commitment_entropy_source_domain(
        CommitmentEntropySourceSite site) {
    switch (site) {
    case CommitmentEntropySourceSite::LegacyCommitFunction:
        return "MP-SPDZ/Tools/Commit.cpp:Commit:open.append_random";
    case CommitmentEntropySourceSite::CommitmentObject:
        return "MP-SPDZ/Tools/Commit.cpp:Commitment::commit:"
               "open.append_random";
    }
    return {};
}

inline constexpr std::uint64_t COMMITMENT_ENTROPY_BYTES = 16;

struct CommitmentEntropyManifestEvent final {
    CommitmentEntropySourceSite source_site{};
    std::uint64_t commitment_owner{};
    std::uint64_t logical_thread_epoch{};
    bool operator==(const CommitmentEntropyManifestEvent&) const = default;
};

struct CommitmentEntropyView final {
    CommitmentEntropySourceSite source_site{};
    std::uint64_t commitment_owner{};
    std::uint64_t logical_process_epoch{};
    std::uint64_t logical_thread_epoch{};
    std::uint64_t object_epoch{};
    std::uint64_t counter_before{};
    std::uint64_t counter_after{};
    std::span<const unsigned char> exact_entropy;
};

namespace commitment_entropy_detail {

inline void append_u64(
        std::vector<unsigned char>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

inline void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    if (value.size() > std::numeric_limits<std::uint64_t>::max() ||
        output.size() > std::numeric_limits<std::size_t>::max() - 8 ||
        value.size() >
            std::numeric_limits<std::size_t>::max() - output.size() - 8)
        throw std::runtime_error("P1-commitment-entropy-size-overflow");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

} // namespace commitment_entropy_detail

// Canonical private payload. Integers are big-endian u64. The fixed source
// domain is encoded before the exact opening randomness, so the two semantic
// callsites cannot be relabelled by a consumer.
inline std::vector<unsigned char> encode_commitment_entropy(
        const CommitmentEntropyView& value) {
    const auto site = static_cast<std::uint64_t>(value.source_site);
    const auto domain = commitment_entropy_source_domain(value.source_site);
    if (site == 0 || site > 2 || domain.empty() ||
        value.logical_process_epoch == 0 ||
        value.logical_thread_epoch == 0 || value.object_epoch == 0 ||
        value.counter_before == std::numeric_limits<std::uint64_t>::max() ||
        value.counter_after != value.counter_before + 1 ||
        value.exact_entropy.size() != COMMITMENT_ENTROPY_BYTES)
        throw std::runtime_error("invalid-P1-commitment-entropy-event");

    std::vector<unsigned char> output;
    // Seven scalar fields plus two length prefixes. Exact reservation avoids
    // leaving stale copies of the raw opening entropy during reallocation.
    output.reserve(COMMITMENT_ENTROPY_EVENT_ENCODING_DOMAIN.size() +
                   9 * 8 + domain.size() +
                   COMMITMENT_ENTROPY_BYTES);
    output.insert(
        output.end(), COMMITMENT_ENTROPY_EVENT_ENCODING_DOMAIN.begin(),
        COMMITMENT_ENTROPY_EVENT_ENCODING_DOMAIN.end());
    for (const auto field : {
             site, value.commitment_owner, value.logical_process_epoch,
             value.logical_thread_epoch, value.object_epoch,
             value.counter_before, value.counter_after})
        commitment_entropy_detail::append_u64(output, field);
    commitment_entropy_detail::append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(domain.data()),
            domain.size()));
    commitment_entropy_detail::append_bytes(output, value.exact_entropy);
    return output;
}

// Canonical prelaunch branch grammar. The capsule hashes these bytes into the
// existing MpSpdzPrng ordered-hook manifest; the selected source closure binds
// the instrumentation patch separately. Runtime process/object/counter epochs
// remain source-owned and are checked against their monotonic adapter state.
inline std::vector<unsigned char> encode_commitment_entropy_manifest(
        std::span<const CommitmentEntropyManifestEvent> events) {
    if (events.size() > std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("P1-commitment-entropy-manifest-overflow");
    std::vector<unsigned char> output;
    output.insert(
        output.end(), COMMITMENT_ENTROPY_MANIFEST_ENCODING_DOMAIN.begin(),
        COMMITMENT_ENTROPY_MANIFEST_ENCODING_DOMAIN.end());
    commitment_entropy_detail::append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(
                COMMITMENT_ENTROPY_EVENT_ENCODING_DOMAIN.data()),
            COMMITMENT_ENTROPY_EVENT_ENCODING_DOMAIN.size()));
    commitment_entropy_detail::append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(
                COMMITMENT_ENTROPY_MP_SPDZ_COMMIT.data()),
            COMMITMENT_ENTROPY_MP_SPDZ_COMMIT.size()));
    commitment_entropy_detail::append_u64(output, events.size());
    for (std::size_t index = 0; index < events.size(); ++index) {
        const auto& event = events[index];
        const auto site = static_cast<std::uint64_t>(event.source_site);
        const auto domain = commitment_entropy_source_domain(
            event.source_site);
        if (site == 0 || site > 2 || domain.empty() ||
            event.logical_thread_epoch == 0)
            throw std::runtime_error(
                "invalid-P1-commitment-entropy-manifest-event");
        commitment_entropy_detail::append_u64(output, index + 1);
        commitment_entropy_detail::append_u64(output, site);
        commitment_entropy_detail::append_u64(
            output, event.commitment_owner);
        commitment_entropy_detail::append_u64(
            output, event.logical_thread_epoch);
        commitment_entropy_detail::append_u64(
            output, COMMITMENT_ENTROPY_BYTES);
        commitment_entropy_detail::append_bytes(
            output,
            std::span(
                reinterpret_cast<const unsigned char*>(domain.data()),
                domain.size()));
        commitment_entropy_detail::append_bytes(
            output,
            std::span(
                reinterpret_cast<const unsigned char*>(
                    COMMITMENT_ENTROPY_COMMIT_CPP_SHA256.data()),
                COMMITMENT_ENTROPY_COMMIT_CPP_SHA256.size()));
    }
    return output;
}

class CommitmentEntropyStateHook {
    CommitmentEntropyStateHook() = default;
    friend class ::kpb::measurement::p1_state_capsule::
        P1EntropyStateAdapter;
#ifdef KPI_P1_COMMITMENT_ENTROPY_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit CommitmentEntropyStateHook(TestOnlyConstruction) {}
#endif

public:
    CommitmentEntropyStateHook(const CommitmentEntropyStateHook&) = delete;
    CommitmentEntropyStateHook& operator=(
        const CommitmentEntropyStateHook&) = delete;
    virtual ~CommitmentEntropyStateHook() = default;
    virtual bool record_commitment_entropy(
        const CommitmentEntropyView&) noexcept = 0;
    // This closes only the commitment-entropy source slice. The future capsule
    // adapter must join it with the other MpSpdzPrng seed/consume events before
    // it may close StateFamily::MpSpdzPrng.
    virtual bool commitment_entropy_terminal_noexcept() noexcept = 0;
    virtual void commitment_entropy_unavailable_noexcept() noexcept = 0;
};

struct CommitmentEntropySourceStatus final {
    bool semantic_source_sites_fixed{};
    bool exact_opening_entropy_retained{};
    bool explicit_process_and_thread_epochs{};
    bool callback_order_thread_identity_absent{};
    bool source_patch_selected{};
    bool capsule_family_adapter{};
    bool selected_role1_installation{};
    bool complete_mp_spdz_prng_family{};
    bool complete_corrupt_p1_view{};
    bool configured{};
};

inline constexpr CommitmentEntropySourceStatus
    kCommitmentEntropySourceStatus{
        .semantic_source_sites_fixed = true,
        .exact_opening_entropy_retained = true,
        .explicit_process_and_thread_epochs = true,
        .callback_order_thread_identity_absent = true,
        .source_patch_selected = false,
        .capsule_family_adapter = false,
        .selected_role1_installation = false,
        .complete_mp_spdz_prng_family = false,
        .complete_corrupt_p1_view = false,
        .configured = false,
    };

} // namespace kpi::mpc::p1_private_state
