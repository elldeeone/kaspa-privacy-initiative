#pragma once

// Private shared layout for the authority core and the sole observer bridge.
// This header is not a public construction surface.

#include "privacy_measurement_authority.hpp"

#include <array>
#include <cstdint>
#include <optional>

namespace kpb::measurement::runtime_bridge {

struct ObserverAdmissionAuthority::Storage {
    struct Leaf {
        unsigned round{};
        CaptureKind kind{};
        unsigned fixed_fd{};
        std::uint64_t device{};
        std::uint64_t inode{};
        std::uint64_t size{};
        std::uint32_t mode{};
        std::uint32_t uid{};
        std::uint32_t link_count{};
    };
    struct C03Round {
        unsigned round{};
        unsigned fixed_fd{};
        Digest financial_run{};
        Digest attempt{};
        Digest cohort{};
        Digest capture_plan{};
        Digest projection{};
        Digest source_identity{};
        Digest build_identity{};
        Digest runtime_identity{};
        Digest launcher_identity{};
        Digest process_identity{};
        Digest child_exit_identity{};
        Digest model_preimage_identity{};
        Digest query_store_preimage_identity{};
        Digest scalar_capture_manifest_identity{};
    };
    struct C1Round {
        unsigned round{};
        unsigned fixed_capture_fd{};
        Digest contact_value_authority_identity{};
        Digest role_launch_identity{};
        Digest route_manifest_identity{};
        Digest route_source_identity{};
        Digest stage_plan_identity{};
        Digest process_identity{};
        Digest expected_child_exit_identity{};
        WorkerBinding worker;
        std::array<unsigned, 3> contact_owner_components{};
        std::array<Digest, 3> operation_identities{};
    };

    RunBinding binding;
    Digest opaque_closure_authority_identity{};
    Digest spool_identity{};
    Digest producer_process_identity{};
    Digest writer_alias_closure_identity{};
    Digest path_alias_closure_identity{};
    ProducerClosureEvidence producer_closure_evidence;
    std::optional<PublicProducerClosure> matched_producer_closure;
    std::array<Leaf, 10> leaves{};
    Leaf producer_receipt_leaf{};
    std::uint64_t root_device{};
    std::uint64_t root_inode{};
    int directory_fd{-1};
    bool sealed_archive{};
    std::array<int, 10> archive_fds{
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
    std::array<std::uint64_t, 10> archive_devices{};
    std::array<std::uint64_t, 10> archive_inodes{};
    std::array<std::uint64_t, 10> archive_sizes{};
    std::array<ProducerStreamClosureEvidence, 10>
        archive_stream_evidence{};
    int structural_continuity_fd{-1};
    std::uint64_t structural_continuity_size{};
    Digest structural_continuity_identity{};
    Digest c03_producer_child_exit{};
    Digest c03_producer_receipt{};
    std::array<C03Round, 2> c03_rounds{};
    std::array<C1Round, 2> c1_rounds{};
    // Type-specific, unique private ownership without requiring the native
    // terminal definition in every measurement-authority translation unit.
    // The sole bridge installs both pointer and deleter atomically.
    kpb::native_terminal::TerminalV2ModelAdmissionAuthority*
        terminal_v2_model_admission{};
    void (*destroy_terminal_v2_model_admission)(
        kpb::native_terminal::TerminalV2ModelAdmissionAuthority*) noexcept{};
    bool test_only{};

    ~Storage();
};

} // namespace kpb::measurement::runtime_bridge
