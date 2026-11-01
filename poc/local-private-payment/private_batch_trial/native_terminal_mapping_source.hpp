#pragma once

// Opaque child-only terminal mapping capability.  It is minted only from the
// exact retained public projection body (and, for the transparent baseline,
// the separately authenticated explicit-owner policy continuation).  The
// production surface intentionally has no receipt, body, digest, row, count,
// or owner accessor.

#include "native_terminal_projection_intake_bridge.hpp"
#include "privacy_terminal_capture_v2.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <span>

namespace kpi::mpc::financial::registered_driver {
enum class CaptureClassification : std::uint8_t;
}

namespace kpb::native_terminal {

class NativeTerminalMappingSourceAuthority final {
    using Digest = std::array<unsigned char, 32>;

    struct OriginEvidence {
        Digest retained_identity{};
        Digest fork_binding_identity{};
        Digest intake_identity{};
        Digest owner_mapping_authority_identity{};
        Digest trial{};
        Digest outer_parent_process{};
        Digest outer_parent_executable{};
    };

    struct PrivateEvidence {
        unsigned round{};
        kpi::mpc::financial::registered_driver::CaptureClassification
            classification{};
        capture::Binding binding;
        std::array<Digest, 3> nullifiers{};
        std::array<Digest, 6> tuple_hashes{};
        std::array<Digest, 3> owner_nullifiers{};
        std::array<std::array<Digest, 2>, 3> owner_tuple_hashes{};
        OriginEvidence origin;
        Digest source_identity{};
        bool owner_mapping_present{};
        bool owner_mapping_absent{};
        bool grouping_source_complete{};
        bool explicit_owner_mapping_export_source_complete{};
        bool public_continuity_modeled_separately{};
    };

    PrivateEvidence evidence_;
    std::atomic_bool live_{true};
    explicit NativeTerminalMappingSourceAuthority(PrivateEvidence);
    static NativeTerminalMappingSourceAuthority from_projection(
        std::span<const std::byte>, unsigned, const capture::Binding&,
        kpi::mpc::financial::registered_driver::CaptureClassification,
        bool, OriginEvidence,
        const std::array<Digest, 3>& = {},
        const std::array<std::array<Digest, 2>, 3>& = {});

    friend class NativeTerminalProjectionIntake;
    friend class capture::TerminalCaptureV2;
public:
    NativeTerminalMappingSourceAuthority(
        const NativeTerminalMappingSourceAuthority&) = delete;
    NativeTerminalMappingSourceAuthority& operator=(
        const NativeTerminalMappingSourceAuthority&) = delete;
    NativeTerminalMappingSourceAuthority(
        NativeTerminalMappingSourceAuthority&&) noexcept;
    NativeTerminalMappingSourceAuthority& operator=(
        NativeTerminalMappingSourceAuthority&&) = delete;

#ifdef KPB_TERMINAL_MAPPING_SOURCE_TEST_SETUP
    static NativeTerminalMappingSourceAuthority
        test_only_candidate_from_projection(
            std::span<const std::byte>, unsigned,
            const capture::Binding&);
    static NativeTerminalMappingSourceAuthority
        test_only_candidate_from_projection_with_origin_salt(
            std::span<const std::byte>, unsigned,
            const capture::Binding&, unsigned char);
    static NativeTerminalMappingSourceAuthority
        test_only_candidate_with_owner_rows(
            std::span<const std::byte>, unsigned,
            const capture::Binding&, const std::array<Digest, 3>&,
            const std::array<std::array<Digest, 2>, 3>&);
    static NativeTerminalMappingSourceAuthority
        test_only_baseline_from_projection(
            std::span<const std::byte>, unsigned,
            const capture::Binding&, const std::array<Digest, 3>&,
            const std::array<std::array<Digest, 2>, 3>&);
#endif
};

} // namespace kpb::native_terminal
