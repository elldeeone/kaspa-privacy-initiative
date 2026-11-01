#pragma once

// Source-only prototype for retaining the actual, potentially unbounded P1
// C03 transcript. This authority deliberately binds no predicted peer-event
// count or byte cap. It is not connected to the selected launcher or observer.

#include "privacy_measurement_authority.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace kpb::measurement::p1_observed_transcript {

enum class OtExtensionProfile : std::uint8_t {
    SoftSpoken = 1,
    Kos = 2,
};

enum class MascotSecretsPolicy : std::uint8_t {
    FreshRegeneration = 1,
    PinnedValidCache = 2,
};

// Public static preimage only. Possession does not authorize opening an
// archive. A future genuine minter must derive every field from the selected
// RunBinding, accepted head, selected executable and immutable MP-SPDZ setup.
struct StaticTranscriptPlan {
    RunBinding binding;
    unsigned round{};
    unsigned fixed_fd{};
    Digest accepted_head_identity{};
    std::uint64_t historical_nullifier_count{};
    WorkerBinding p1_worker;
    Digest selected_main_identity{};
    Digest p1_capture_source_identity{};
    Digest p1_capture_build_identity{};
    Digest model_preimage_identity{};
    Digest query_store_identity{};
    Digest scalar_manifest_identity{};
    Digest online_options_identity{};
    OtExtensionProfile ot_extension{};
    Digest ot_parameters_identity{};
    MascotSecretsPolicy mascot_secrets_policy{};
    Digest mascot_secrets_policy_identity{};
    Digest player_virtual_surface_identity{};
    Digest expected_hello_payload_sha256{};
    Digest archive_filesystem_identity{};
    bool operator==(const StaticTranscriptPlan&) const = default;
};

class ObservedTranscriptWriterAuthority;
class ObservedTranscriptCompletionAuthority;

// Complete before friendship is granted. It has no minting operation in this
// source state, so an arbitrary caller-authored StaticTranscriptPlan cannot
// become authority.
class ObservedTranscriptSourceBridge final {
public:
    ObservedTranscriptSourceBridge() = delete;
};

class ObservedTranscriptPlanAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ObservedTranscriptPlanAuthority(std::unique_ptr<Storage>);
    friend class ObservedTranscriptSourceBridge;

public:
    ObservedTranscriptPlanAuthority(
        const ObservedTranscriptPlanAuthority&) = delete;
    ObservedTranscriptPlanAuthority& operator=(
        const ObservedTranscriptPlanAuthority&) = delete;
    ObservedTranscriptPlanAuthority(
        ObservedTranscriptPlanAuthority&&) noexcept;
    ObservedTranscriptPlanAuthority& operator=(
        ObservedTranscriptPlanAuthority&&) = delete;
    ~ObservedTranscriptPlanAuthority();

    ObservedTranscriptWriterAuthority begin_capture() &&;

#ifdef KPB_P1_OBSERVED_TRANSCRIPT_TEST_SETUP
    static ObservedTranscriptPlanAuthority test_only_mint(
        StaticTranscriptPlan);
#endif
};

class ObservedTranscriptWriterAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ObservedTranscriptWriterAuthority(std::unique_ptr<Storage>);
    friend class ObservedTranscriptPlanAuthority;

public:
    ObservedTranscriptWriterAuthority(
        const ObservedTranscriptWriterAuthority&) = delete;
    ObservedTranscriptWriterAuthority& operator=(
        const ObservedTranscriptWriterAuthority&) = delete;
    ObservedTranscriptWriterAuthority(
        ObservedTranscriptWriterAuthority&&) noexcept;
    ObservedTranscriptWriterAuthority& operator=(
        ObservedTranscriptWriterAuthority&&) = delete;
    ~ObservedTranscriptWriterAuthority();

    // This is an unbounded streaming append. ENOSPC or any parser/write error
    // poisons the authority and can only make the measurement unqualified.
    void append(std::span<const unsigned char>);

    // The future selected drain may call this only after read(2) returned
    // kernel EOF. The source-only prototype cannot prove that callsite yet.
    ObservedTranscriptCompletionAuthority finish_after_kernel_eof() &&;
};

class ObservedTranscriptCompletionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ObservedTranscriptCompletionAuthority(std::unique_ptr<Storage>);
    friend class ObservedTranscriptWriterAuthority;

public:
    ObservedTranscriptCompletionAuthority(
        const ObservedTranscriptCompletionAuthority&) = delete;
    ObservedTranscriptCompletionAuthority& operator=(
        const ObservedTranscriptCompletionAuthority&) = delete;
    ObservedTranscriptCompletionAuthority(
        ObservedTranscriptCompletionAuthority&&) noexcept;
    ObservedTranscriptCompletionAuthority& operator=(
        ObservedTranscriptCompletionAuthority&&) = delete;
    ~ObservedTranscriptCompletionAuthority();

#ifdef KPB_P1_OBSERVED_TRANSCRIPT_TEST_SETUP
    struct TestOnlySummary {
        StaticTranscriptPlan plan;
        std::uint64_t raw_wire_bytes{};
        std::uint64_t record_count{};
        std::uint64_t peer_messages{};
        std::uint64_t peer_chunks{};
        std::uint64_t peer_payload_bytes{};
        std::uint64_t peer_wire_bytes{};
        std::uint64_t fork_messages{};
        std::uint64_t fork_wire_bytes{};
        Digest raw_wire_sha256{};
        Digest ordered_peer_vector_sha256{};
        Digest ordered_fork_vector_sha256{};
        bool read_only{};
        bool anonymous_disk_backed{};
        bool writer_closed{};
    };
    TestOnlySummary test_only_summary() const;
    std::vector<unsigned char> test_only_read_all() const;
#endif
};

struct SourceStatus {
    bool source_only_prototype{};
    bool no_operational_byte_cap{};
    bool anonymous_disk_backed_stream{};
    bool exact_c03_frame_parser{};
    bool actual_peer_and_fork_vector{};
    bool writer_closed_read_only_authority{};
    bool preopened_topology_archive_consumed{};
    bool internal_random_state_capture{};
    bool complete_passive_p1_view{};
    bool genuine_prelaunch_minter{};
    bool selected_runtime_eof_callsite{};
    bool observer_transfer{};
    bool configured{};
};

inline constexpr SourceStatus kSourceStatus{
    .source_only_prototype = true,
    .no_operational_byte_cap = true,
    .anonymous_disk_backed_stream = true,
    .exact_c03_frame_parser = true,
    .actual_peer_and_fork_vector = true,
    .writer_closed_read_only_authority = true,
    .preopened_topology_archive_consumed = false,
    .internal_random_state_capture = false,
    .complete_passive_p1_view = false,
    .genuine_prelaunch_minter = false,
    .selected_runtime_eof_callsite = false,
    .observer_transfer = false,
    .configured = false,
};

} // namespace kpb::measurement::p1_observed_transcript
