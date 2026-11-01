#pragma once

// Opaque source authority for the two authenticated final C03 streams.
// This is deliberately not an EmpiricalCaptureHistoryAuthority: the final
// streams contain no complete enumeration or bytes for earlier failed and
// partial attempts. The future v4 observer must linearly join this authority
// with the outer attempt-history authority before deriving any comparison.

#include "privacy_measurement_authority.hpp"
#include "privacy_measurement_observer_capture_bridge_contract.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace kpb::measurement::empirical_terminal_source {

inline constexpr unsigned FINAL_C03_ROUNDS = 2;
inline constexpr std::array<unsigned, FINAL_C03_ROUNDS>
    FINAL_C03_ARCHIVE_SLOTS{3, 8};
inline constexpr std::array<unsigned, FINAL_C03_ROUNDS>
    FINAL_C03_FIXED_FDS{23, 28};

struct FinalC03RoundBinding {
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
    ProducerStreamClosureEvidence closure_evidence{};
};

class NativeEmpiricalTerminalSourceParser;

class TerminalFinalC03ObservationAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    TerminalFinalC03ObservationAuthority(
        const RunBinding&,
        const std::array<FinalC03RoundBinding, FINAL_C03_ROUNDS>&,
        std::array<int, FINAL_C03_ROUNDS> sealed_read_fds);
    friend class NativeEmpiricalTerminalSourceParser;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    TerminalFinalC03ObservationAuthority(
        const TerminalFinalC03ObservationAuthority&) = delete;
    TerminalFinalC03ObservationAuthority& operator=(
        const TerminalFinalC03ObservationAuthority&) = delete;
    TerminalFinalC03ObservationAuthority(
        TerminalFinalC03ObservationAuthority&&) noexcept;
    TerminalFinalC03ObservationAuthority& operator=(
        TerminalFinalC03ObservationAuthority&&) = delete;
    ~TerminalFinalC03ObservationAuthority();
};

#ifdef KPB_NATIVE_EMPIRICAL_TERMINAL_SOURCE_TEST_SETUP
struct TestOnlyFinalC03Summary {
    std::array<std::uint64_t, FINAL_C03_ROUNDS> frame_counts{};
    std::array<std::uint64_t, FINAL_C03_ROUNDS> raw_wire_bytes{};
    bool complete_attempt_history{};
};
#endif

class NativeEmpiricalTerminalSourceParser final {
    NativeEmpiricalTerminalSourceParser() = delete;
public:
#ifdef KPB_NATIVE_EMPIRICAL_TERMINAL_SOURCE_TEST_SETUP
    static TerminalFinalC03ObservationAuthority test_only_parse(
        const RunBinding&,
        const std::array<FinalC03RoundBinding, FINAL_C03_ROUNDS>&,
        std::array<int, FINAL_C03_ROUNDS> sealed_read_fds);
    static TestOnlyFinalC03Summary test_only_consume(
        TerminalFinalC03ObservationAuthority&&);
#endif
};

struct NativeEmpiricalTerminalSourceStatus {
    bool exact_final_c03_parser{};
    bool sealed_two_round_input{};
    bool opaque_one_shot_final_source{};
    bool complete_attempt_history{};
    bool canonical_five_field_observation_encoding{};
    bool empirical_history_minter{};
    bool production_frozen_candidate_set_authority{};
    bool selected_runtime_callsite{};
    bool configured{};
};

inline constexpr NativeEmpiricalTerminalSourceStatus
    kNativeEmpiricalTerminalSourceStatus{
        .exact_final_c03_parser = true,
        .sealed_two_round_input = true,
        .opaque_one_shot_final_source = true,
    };

} // namespace kpb::measurement::empirical_terminal_source
