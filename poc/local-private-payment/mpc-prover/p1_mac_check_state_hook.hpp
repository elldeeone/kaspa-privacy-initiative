#pragma once

// Private, child-local evidence for the selected field MAC check. The source
// adapter receives exact state at four semantic edges. It is not a public
// receipt, generic recorder, or caller-selected family factory.

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace kpb::measurement::p1_state_capsule {
class P1MacCheckStateAdapter;
}

namespace kpi::mpc::p1_private_state {

inline constexpr std::string_view MAC_CHECK_MP_SPDZ_COMMIT =
    "113c4e47dd94bca9ecab029d2f0abe649bea5c52";
inline constexpr std::string_view MAC_CHECK_EVENT_ENCODING_DOMAIN =
    "KPI_P1_FIELD_MAC_CHECK_STATE_V1\n";
inline constexpr std::string_view MAC_CHECK_MANIFEST_ENCODING_DOMAIN =
    "KPI_P1_FIELD_MAC_CHECK_MANIFEST_V1\n";
inline constexpr std::string_view MAC_CHECK_UNAVAILABLE_ENCODING_DOMAIN =
    "KPI_P1_FIELD_MAC_CHECK_UNAVAILABLE_V1\n";
inline constexpr std::string_view MAC_CHECK_UPSTREAM_FILE_SHA256 =
    "6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8";
inline constexpr std::string_view MAC_CHECK_SELECTED_FIELD_MODULUS =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
inline constexpr std::uint64_t MAC_CHECK_SEED_BYTES = 16;
inline constexpr std::uint64_t MAC_CHECK_FIELD_BYTES = 32;

enum class MacCheckSourceSite : std::uint8_t {
    CheckBegin = 1,
    CollectiveSeed = 2,
    LocalTau = 3,
    SuccessReset = 4,
};

// An installed family never becomes Missing. These closed sites and reasons
// terminate its exact retained prefix as Unavailable. They are deliberately
// independent of MASCOT's abort-event grammar.
enum class MacCheckUnavailableSite : std::uint8_t {
    CheckBegin = 1,
    CollectiveSeed = 2,
    LocalTau = 3,
    SuccessReset = 4,
    FailureReset = 5,
    AttemptScope = 6,
    ThreadScope = 7,
    CaptureTerminal = 8,
    CaptureScope = 9,
    DebugBranch = 10,
};

enum class MacCheckUnavailableReason : std::uint8_t {
    BeginConcurrent = 1,
    BeginMetadataInvalid = 2,
    BeginThreadUnbound = 3,
    EdgeAttemptMissing = 4,
    EdgeGenerationMismatch = 5,
    EdgeCheckMismatch = 6,
    EdgeOrderMismatch = 7,
    EdgeThreadMismatch = 8,
    EdgePayloadInvalid = 9,
    HookRejected = 10,
    ProtocolMacFailure = 11,
    AttemptDropped = 12,
    ThreadScopeViolation = 13,
    TerminalOwnerMismatch = 14,
    TerminalIncomplete = 15,
    TerminalRejected = 16,
    CaptureScopeDropped = 17,
    UnsupportedDebugBranch = 18,
    AttemptUnwound = 19,
};

inline constexpr std::string_view mac_check_source_domain(
        MacCheckSourceSite site) {
    switch (site) {
    case MacCheckSourceSite::CheckBegin:
        return "MP-SPDZ/Protocols/MAC_Check.hpp:MAC_Check_::Check:begin";
    case MacCheckSourceSite::CollectiveSeed:
        return "MP-SPDZ/Protocols/MAC_Check.hpp:MAC_Check_::Check:"
               "Create_Random_Seed:returned";
    case MacCheckSourceSite::LocalTau:
        return "MP-SPDZ/Protocols/MAC_Check.hpp:MAC_Check_::Check:"
               "coefficient-loop:local-tau";
    case MacCheckSourceSite::SuccessReset:
        return "MP-SPDZ/Protocols/MAC_Check.hpp:MAC_Check_::Check:"
               "zero-verified:reset";
    }
    return {};
}

inline constexpr std::string_view mac_check_unavailable_source_domain(
        MacCheckUnavailableSite site) {
    switch (site) {
    case MacCheckUnavailableSite::CheckBegin:
        return mac_check_source_domain(MacCheckSourceSite::CheckBegin);
    case MacCheckUnavailableSite::CollectiveSeed:
        return mac_check_source_domain(MacCheckSourceSite::CollectiveSeed);
    case MacCheckUnavailableSite::LocalTau:
        return mac_check_source_domain(MacCheckSourceSite::LocalTau);
    case MacCheckUnavailableSite::SuccessReset:
        return mac_check_source_domain(MacCheckSourceSite::SuccessReset);
    case MacCheckUnavailableSite::FailureReset:
        return "MP-SPDZ/Protocols/MAC_Check.hpp:MAC_Check_::Check:"
               "nonzero-verified:reset";
    case MacCheckUnavailableSite::AttemptScope:
        return "KPI/p1_mac_check_source_capture:attempt-scope-destructor";
    case MacCheckUnavailableSite::ThreadScope:
        return "KPI/p1_mac_check_source_capture:thread-scope-destructor";
    case MacCheckUnavailableSite::CaptureTerminal:
        return "KPI/p1_mac_check_source_capture:capture-terminal";
    case MacCheckUnavailableSite::CaptureScope:
        return "KPI/p1_mac_check_source_capture:capture-scope-destructor";
    case MacCheckUnavailableSite::DebugBranch:
        return "MP-SPDZ/Protocols/MAC_Check.hpp:MAC_Check_::Check:"
               "debug-mac-branch";
    }
    return {};
}

struct MacCheckEventIdentity final {
    std::uint64_t logical_process_epoch{};
    std::uint64_t logical_thread_epoch{};
    std::uint64_t source_round{};
    std::uint64_t check_epoch{};
    std::uint64_t event_counter_before{};
    std::uint64_t event_counter_after{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    std::uint64_t pending_open_count{};
};

struct MacCheckBeginView final {
    MacCheckEventIdentity identity;
    std::span<const unsigned char> exact_alpha_share;
    std::span<const unsigned char> exact_pending_values;
    std::span<const unsigned char> exact_pending_macs;
};

struct MacCheckCollectiveSeedView final {
    MacCheckEventIdentity identity;
    // Create_Random_Seed has returned only after the local contribution was
    // committed and every selected opening was checked. The source closure
    // separately binds that routine plus the typed Commit entropy event.
    std::span<const unsigned char> exact_collective_seed;
};

struct MacCheckLocalTauView final {
    MacCheckEventIdentity identity;
    std::uint64_t coefficient_count{};
    // Canonical Fr packings in consumption order. Together with the exact
    // collective seed, this proves PRNG initialization and consumption.
    std::span<const unsigned char> exact_coefficients;
    std::span<const unsigned char> exact_local_tau;
};

struct MacCheckSuccessResetView final {
    MacCheckEventIdentity identity;
    std::uint64_t pending_after_reset{};
    std::span<const unsigned char> exact_tau_sum;
};

struct MacCheckUnavailableView final {
    MacCheckUnavailableSite site{};
    MacCheckUnavailableReason reason{};
    std::uint64_t logical_process_epoch{};
    std::uint64_t source_round{};
    std::uint64_t completed_check_count{};
    // Zero means no check is active. Otherwise this is exactly
    // completed_check_count + 1.
    std::uint64_t active_check_epoch{};
    // The fixed successful-event prefix CheckBegin..SuccessReset. An active
    // unavailable check can retain 0..3 events; 4 closes as success instead.
    std::uint64_t completed_edge_count{};
    std::uint64_t expected_thread_epoch{};
    // Zero means the rejecting source edge ran on an unbound thread.
    std::uint64_t observed_thread_epoch{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    std::uint64_t pending_open_count{};
    // Populated only for ProtocolMacFailure, after reset and before the
    // existing MP-SPDZ failure is thrown.
    std::uint64_t pending_after_reset{};
    std::span<const unsigned char> exact_tau_sum;
};

struct MacCheckManifestCheck final {
    std::uint64_t source_round{};
    std::uint64_t logical_thread_epoch{};
    bool operator==(const MacCheckManifestCheck&) const = default;
};

namespace mac_check_detail {

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
        throw std::runtime_error("P1-MAC-check-state-size-overflow");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

inline void validate_identity(
        const MacCheckEventIdentity& value, MacCheckSourceSite site) {
    const auto ordinal = static_cast<std::uint64_t>(site);
    if (ordinal == 0 || ordinal > 4 ||
        mac_check_source_domain(site).empty() ||
        value.logical_process_epoch == 0 ||
        value.logical_thread_epoch == 0 ||
        (value.source_round != 1 && value.source_round != 2) ||
        value.check_epoch == 0 ||
        value.event_counter_before != ordinal - 1 ||
        value.event_counter_after != ordinal ||
        value.local_role >= value.player_count || value.player_count == 0 ||
        value.pending_open_count == 0)
        throw std::runtime_error("invalid-P1-MAC-check-event-identity");
}

inline std::size_t packed_field_bytes(std::uint64_t count) {
    if (count > std::numeric_limits<std::size_t>::max() /
                    MAC_CHECK_FIELD_BYTES)
        throw std::runtime_error("P1-MAC-check-field-size-overflow");
    return static_cast<std::size_t>(count * MAC_CHECK_FIELD_BYTES);
}

inline std::size_t checked_add_size(
        std::size_t left, std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left)
        throw std::runtime_error("P1-MAC-check-encoding-size-overflow");
    return left + right;
}

inline std::size_t encoded_bytes_size(std::size_t value_size) {
    return checked_add_size(8, value_size);
}

inline std::vector<unsigned char> event_prefix(
        const MacCheckEventIdentity& value, MacCheckSourceSite site,
        std::size_t exact_suffix_size) {
    validate_identity(value, site);
    const auto domain = mac_check_source_domain(site);
    auto final_size = checked_add_size(
        MAC_CHECK_EVENT_ENCODING_DOMAIN.size(), 10 * 8);
    final_size = checked_add_size(final_size, encoded_bytes_size(domain.size()));
    final_size = checked_add_size(final_size, exact_suffix_size);
    std::vector<unsigned char> output;
    // Reserve the complete encoding before any secret bytes are inserted.
    // This prevents allocator growth from leaving stale secret-bearing copies.
    output.reserve(final_size);
    output.insert(
        output.end(), MAC_CHECK_EVENT_ENCODING_DOMAIN.begin(),
        MAC_CHECK_EVENT_ENCODING_DOMAIN.end());
    for (const auto field : {
             static_cast<std::uint64_t>(site),
             value.logical_process_epoch, value.logical_thread_epoch,
             value.source_round, value.check_epoch,
             value.event_counter_before, value.event_counter_after,
             value.local_role, value.player_count,
             value.pending_open_count})
        append_u64(output, field);
    append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(domain.data()),
            domain.size()));
    return output;
}

} // namespace mac_check_detail

inline std::vector<unsigned char> encode_mac_check_begin(
        const MacCheckBeginView& value) {
    using namespace mac_check_detail;
    validate_identity(value.identity, MacCheckSourceSite::CheckBegin);
    const auto packed = packed_field_bytes(value.identity.pending_open_count);
    if (value.exact_alpha_share.size() != MAC_CHECK_FIELD_BYTES ||
        value.exact_pending_values.size() != packed ||
        value.exact_pending_macs.size() != packed)
        throw std::runtime_error("invalid-P1-MAC-check-begin-state");
    const auto suffix_size = checked_add_size(
        encoded_bytes_size(value.exact_alpha_share.size()),
        checked_add_size(
            encoded_bytes_size(value.exact_pending_values.size()),
            encoded_bytes_size(value.exact_pending_macs.size())));
    auto output = event_prefix(
        value.identity, MacCheckSourceSite::CheckBegin, suffix_size);
    append_bytes(output, value.exact_alpha_share);
    append_bytes(output, value.exact_pending_values);
    append_bytes(output, value.exact_pending_macs);
    return output;
}

inline std::vector<unsigned char> encode_mac_check_collective_seed(
        const MacCheckCollectiveSeedView& value) {
    using namespace mac_check_detail;
    validate_identity(value.identity, MacCheckSourceSite::CollectiveSeed);
    if (value.exact_collective_seed.size() != MAC_CHECK_SEED_BYTES)
        throw std::runtime_error("invalid-P1-MAC-check-collective-seed");
    auto output = event_prefix(
        value.identity, MacCheckSourceSite::CollectiveSeed,
        encoded_bytes_size(value.exact_collective_seed.size()));
    append_bytes(output, value.exact_collective_seed);
    return output;
}

inline std::vector<unsigned char> encode_mac_check_local_tau(
        const MacCheckLocalTauView& value) {
    using namespace mac_check_detail;
    validate_identity(value.identity, MacCheckSourceSite::LocalTau);
    if (value.coefficient_count != value.identity.pending_open_count ||
        value.exact_coefficients.size() !=
            packed_field_bytes(value.coefficient_count) ||
        value.exact_local_tau.size() != MAC_CHECK_FIELD_BYTES)
        throw std::runtime_error("invalid-P1-MAC-check-local-tau");
    const auto suffix_size = checked_add_size(
        8, checked_add_size(
            encoded_bytes_size(value.exact_coefficients.size()),
            encoded_bytes_size(value.exact_local_tau.size())));
    auto output = event_prefix(
        value.identity, MacCheckSourceSite::LocalTau, suffix_size);
    append_u64(output, value.coefficient_count);
    append_bytes(output, value.exact_coefficients);
    append_bytes(output, value.exact_local_tau);
    return output;
}

inline std::vector<unsigned char> encode_mac_check_success_reset(
        const MacCheckSuccessResetView& value) {
    using namespace mac_check_detail;
    validate_identity(value.identity, MacCheckSourceSite::SuccessReset);
    if (value.pending_after_reset != 0 ||
        value.exact_tau_sum.size() != MAC_CHECK_FIELD_BYTES ||
        !std::all_of(
            value.exact_tau_sum.begin(), value.exact_tau_sum.end(),
            [](unsigned char byte) { return byte == 0; }))
        throw std::runtime_error("invalid-P1-MAC-check-success-reset");
    auto output = event_prefix(
        value.identity, MacCheckSourceSite::SuccessReset,
        checked_add_size(
            8, encoded_bytes_size(value.exact_tau_sum.size())));
    append_u64(output, value.pending_after_reset);
    append_bytes(output, value.exact_tau_sum);
    return output;
}

namespace mac_check_detail {

inline bool unavailable_site_reason_match(
        MacCheckUnavailableSite site,
        MacCheckUnavailableReason reason) noexcept {
    switch (reason) {
    case MacCheckUnavailableReason::BeginConcurrent:
    case MacCheckUnavailableReason::BeginMetadataInvalid:
    case MacCheckUnavailableReason::BeginThreadUnbound:
        return site == MacCheckUnavailableSite::CheckBegin;
    case MacCheckUnavailableReason::EdgeAttemptMissing:
    case MacCheckUnavailableReason::EdgeGenerationMismatch:
    case MacCheckUnavailableReason::EdgeCheckMismatch:
    case MacCheckUnavailableReason::EdgeOrderMismatch:
    case MacCheckUnavailableReason::EdgeThreadMismatch:
    case MacCheckUnavailableReason::EdgePayloadInvalid:
        return (site >= MacCheckUnavailableSite::CollectiveSeed &&
                site <= MacCheckUnavailableSite::FailureReset) ||
            site == MacCheckUnavailableSite::DebugBranch;
    case MacCheckUnavailableReason::HookRejected:
        return site >= MacCheckUnavailableSite::CheckBegin &&
            site <= MacCheckUnavailableSite::SuccessReset;
    case MacCheckUnavailableReason::ProtocolMacFailure:
        return site == MacCheckUnavailableSite::FailureReset;
    case MacCheckUnavailableReason::AttemptDropped:
    case MacCheckUnavailableReason::AttemptUnwound:
        return site == MacCheckUnavailableSite::AttemptScope;
    case MacCheckUnavailableReason::ThreadScopeViolation:
        return site == MacCheckUnavailableSite::ThreadScope;
    case MacCheckUnavailableReason::TerminalOwnerMismatch:
    case MacCheckUnavailableReason::TerminalIncomplete:
    case MacCheckUnavailableReason::TerminalRejected:
        return site == MacCheckUnavailableSite::CaptureTerminal;
    case MacCheckUnavailableReason::CaptureScopeDropped:
        return site == MacCheckUnavailableSite::CaptureScope;
    case MacCheckUnavailableReason::UnsupportedDebugBranch:
        return site == MacCheckUnavailableSite::DebugBranch;
    }
    return false;
}

inline void validate_unavailable(const MacCheckUnavailableView& value) {
    const auto site = static_cast<std::uint64_t>(value.site);
    const auto reason = static_cast<std::uint64_t>(value.reason);
    if (site == 0 || site > 10 || reason == 0 || reason > 19 ||
        mac_check_unavailable_source_domain(value.site).empty() ||
        !unavailable_site_reason_match(value.site, value.reason) ||
        value.logical_process_epoch == 0 ||
        (value.source_round != 1 && value.source_round != 2) ||
        value.player_count == 0 || value.local_role >= value.player_count ||
        value.completed_edge_count > 3)
        throw std::runtime_error("invalid-P1-MAC-check-unavailable");

    if (value.active_check_epoch == 0) {
        if (value.completed_edge_count != 0 ||
            value.pending_open_count != 0)
            throw std::runtime_error(
                "invalid-P1-MAC-check-unavailable-empty-prefix");
    } else {
        if (value.completed_check_count ==
                std::numeric_limits<std::uint64_t>::max() ||
            value.active_check_epoch != value.completed_check_count + 1 ||
            (value.pending_open_count == 0 &&
             value.reason !=
                MacCheckUnavailableReason::BeginMetadataInvalid))
            throw std::runtime_error(
                "invalid-P1-MAC-check-unavailable-active-prefix");
    }

    if (value.reason == MacCheckUnavailableReason::HookRejected) {
        const auto rejected_site = static_cast<std::uint64_t>(value.site);
        if (value.active_check_epoch == 0 ||
            value.completed_edge_count != rejected_site - 1)
            throw std::runtime_error(
                "invalid-P1-MAC-check-rejected-prefix");
    }

    const bool protocol_failure =
        value.reason == MacCheckUnavailableReason::ProtocolMacFailure;
    if (protocol_failure) {
        if (value.active_check_epoch == 0 ||
            value.completed_edge_count != 3 ||
            value.pending_after_reset != 0 ||
            value.exact_tau_sum.size() != MAC_CHECK_FIELD_BYTES ||
            std::all_of(
                value.exact_tau_sum.begin(), value.exact_tau_sum.end(),
                [](unsigned char byte) { return byte == 0; }))
            throw std::runtime_error(
                "invalid-P1-MAC-check-protocol-failure");
    } else if (value.pending_after_reset != 0 ||
               !value.exact_tau_sum.empty()) {
        throw std::runtime_error(
            "invalid-P1-MAC-check-unavailable-payload");
    }
}

} // namespace mac_check_detail

inline std::vector<unsigned char> encode_mac_check_unavailable(
        const MacCheckUnavailableView& value) {
    using namespace mac_check_detail;
    validate_unavailable(value);
    const auto source_domain =
        mac_check_unavailable_source_domain(value.site);
    auto final_size = checked_add_size(
        MAC_CHECK_UNAVAILABLE_ENCODING_DOMAIN.size(), 13 * 8);
    final_size = checked_add_size(
        final_size, encoded_bytes_size(source_domain.size()));
    for (std::uint64_t ordinal = 1;
         ordinal <= value.completed_edge_count; ++ordinal) {
        const auto domain = mac_check_source_domain(
            static_cast<MacCheckSourceSite>(ordinal));
        final_size = checked_add_size(final_size, 8);
        final_size = checked_add_size(
            final_size, encoded_bytes_size(domain.size()));
    }
    final_size = checked_add_size(
        final_size, encoded_bytes_size(value.exact_tau_sum.size()));

    std::vector<unsigned char> output;
    // Reserve before the optional non-zero tau is inserted.
    output.reserve(final_size);
    output.insert(
        output.end(), MAC_CHECK_UNAVAILABLE_ENCODING_DOMAIN.begin(),
        MAC_CHECK_UNAVAILABLE_ENCODING_DOMAIN.end());
    for (const auto field : {
             static_cast<std::uint64_t>(value.site),
             static_cast<std::uint64_t>(value.reason),
             value.logical_process_epoch, value.source_round,
             value.completed_check_count, value.active_check_epoch,
             value.completed_edge_count, value.expected_thread_epoch,
             value.observed_thread_epoch, value.local_role,
             value.player_count, value.pending_open_count,
             value.pending_after_reset})
        append_u64(output, field);
    append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(source_domain.data()),
            source_domain.size()));
    for (std::uint64_t ordinal = 1;
         ordinal <= value.completed_edge_count; ++ordinal) {
        append_u64(output, ordinal);
        const auto domain = mac_check_source_domain(
            static_cast<MacCheckSourceSite>(ordinal));
        append_bytes(
            output,
            std::span(
                reinterpret_cast<const unsigned char*>(domain.data()),
                domain.size()));
    }
    append_bytes(output, value.exact_tau_sum);
    return output;
}

// Canonical source grammar only. The future all-family compiler must consume
// a private authority that hashes these bytes; it must never accept a caller-
// supplied count, digest, or public descriptor vector.
inline std::vector<unsigned char> encode_mac_check_manifest(
        std::span<const MacCheckManifestCheck> checks) {
    using namespace mac_check_detail;
    if (checks.empty() ||
        checks.size() > std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("invalid-P1-MAC-check-manifest-size");
    std::vector<unsigned char> output;
    output.insert(
        output.end(), MAC_CHECK_MANIFEST_ENCODING_DOMAIN.begin(),
        MAC_CHECK_MANIFEST_ENCODING_DOMAIN.end());
    append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(
                MAC_CHECK_EVENT_ENCODING_DOMAIN.data()),
            MAC_CHECK_EVENT_ENCODING_DOMAIN.size()));
    append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(
                MAC_CHECK_MP_SPDZ_COMMIT.data()),
            MAC_CHECK_MP_SPDZ_COMMIT.size()));
    append_bytes(
        output,
        std::span(
            reinterpret_cast<const unsigned char*>(
                MAC_CHECK_UPSTREAM_FILE_SHA256.data()),
            MAC_CHECK_UPSTREAM_FILE_SHA256.size()));
    append_u64(output, checks.size());
    for (std::size_t index = 0; index < checks.size(); ++index) {
        const auto& check = checks[index];
        if ((check.source_round != 1 && check.source_round != 2) ||
            check.logical_thread_epoch == 0)
            throw std::runtime_error("invalid-P1-MAC-check-manifest-check");
        append_u64(output, index + 1);
        append_u64(output, check.source_round);
        append_u64(output, check.logical_thread_epoch);
        append_u64(output, 4);
        for (unsigned site = 1; site <= 4; ++site) {
            const auto selected = static_cast<MacCheckSourceSite>(site);
            const auto domain = mac_check_source_domain(selected);
            append_u64(output, site);
            append_bytes(
                output,
                std::span(
                    reinterpret_cast<const unsigned char*>(domain.data()),
                    domain.size()));
        }
    }
    return output;
}

class MacCheckStateHook {
    MacCheckStateHook() = default;
    friend class ::kpb::measurement::p1_state_capsule::
        P1MacCheckStateAdapter;
#ifdef KPI_P1_MAC_CHECK_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit MacCheckStateHook(TestOnlyConstruction) {}
#endif

public:
    MacCheckStateHook(const MacCheckStateHook&) = delete;
    MacCheckStateHook& operator=(const MacCheckStateHook&) = delete;
    virtual ~MacCheckStateHook() = default;
    virtual bool record_mac_check_begin(
        const MacCheckBeginView&) noexcept = 0;
    virtual bool record_mac_check_collective_seed(
        const MacCheckCollectiveSeedView&) noexcept = 0;
    virtual bool record_mac_check_local_tau(
        const MacCheckLocalTauView&) noexcept = 0;
    virtual bool record_mac_check_success_reset(
        const MacCheckSuccessResetView&) noexcept = 0;
    // Returning false means the typed Unavailable terminal was not retained.
    // A false return is transactional: the adapter must not retain a partial
    // encoding. Source edges that can still fail-stop abort in that case.
    virtual bool record_mac_check_unavailable(
        const MacCheckUnavailableView&) noexcept = 0;
    virtual bool mac_check_capture_terminal_noexcept() noexcept = 0;
};

struct MacCheckStateSourceStatus final {
    bool semantic_source_sites_fixed{};
    bool exact_pending_state_schema{};
    bool exact_collective_seed{};
    bool exact_coefficient_consumption{};
    bool exact_local_tau_and_reset{};
    bool explicit_process_round_thread_epochs{};
    bool typed_partial_unavailable{};
    bool source_patch_selected{};
    bool capsule_family_adapter{};
    bool selected_role1_installation{};
    bool complete_mac_check_family{};
    bool complete_corrupt_p1_view{};
    bool configured{};
};

inline constexpr MacCheckStateSourceStatus kMacCheckStateSourceStatus{
    .semantic_source_sites_fixed = true,
    .exact_pending_state_schema = true,
    .exact_collective_seed = true,
    .exact_coefficient_consumption = true,
    .exact_local_tau_and_reset = true,
    .explicit_process_round_thread_epochs = true,
    .typed_partial_unavailable = true,
    .source_patch_selected = false,
    .capsule_family_adapter = false,
    .selected_role1_installation = false,
    .complete_mac_check_family = false,
    .complete_corrupt_p1_view = false,
    .configured = false,
};

} // namespace kpi::mpc::p1_private_state
