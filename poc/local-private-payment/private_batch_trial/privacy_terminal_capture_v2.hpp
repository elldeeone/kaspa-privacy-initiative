#pragma once

#include "privacy_capture_hook.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace kpb::capture {

class TerminalCaptureV2;
class PreNetworkTerminalClosedV2;

} // namespace kpb::capture

namespace kpb::native_terminal {

class NativeTerminalMappingSourceAuthority;
class PaymentTerminalChildProgram;
int run_payment_terminal_child(PaymentTerminalChildProgram&) noexcept;

// Complete (not forward-friended) narrow bridge. Its evidence type and
// consumer are private so a production caller cannot turn the child token
// into a terminal-content hash/count oracle.
class NativeTerminalChildEvidenceBridge final {
    struct Evidence {
        unsigned round{};
        capture::Binding binding;
        std::string candidate_sha256;
        std::string case_sha256;
        std::string r0_receipt_sha256;
        std::string native_full_sha256;
        std::string final_checkpoint_sha256;
        std::string mapping_source_identity;
        std::string record_root_sha256;
        std::string end_frame_sha256;
        std::uint64_t record_count{};
        std::uint64_t payload_bytes{};
        std::uint64_t raw_wire_bytes{};
        unsigned explicit_owner_mapping_export_count{};
        bool owner_mapping_present{};
        bool grouping_source_complete{};
        bool explicit_owner_mapping_export_source_complete{};
        bool public_continuity_modeled_separately{};
        bool end_written{};
        bool writer_closed{};
    };
    static Evidence consume(capture::PreNetworkTerminalClosedV2&&);
    friend int run_payment_terminal_child(PaymentTerminalChildProgram&)
        noexcept;
#ifdef KPB_TERMINAL_CAPTURE_V2_TEST_SETUP
    friend class capture::PreNetworkTerminalClosedV2;
#endif
};

} // namespace kpb::native_terminal

namespace kpb::capture {

// Live child-side proof that the same TerminalCaptureV2 object advanced the
// offline candidate -> R0 -> NativeFull -> durable-final path, emitted a
// source-complete owner/NF/tuple grouping plus the narrow statement that this
// terminal grammar has no explicit cross-round owner mapping export, then
// wrote END and closed its fixed endpoint. Public state/head continuity is a
// separate relation and is not claimed absent by this authority.
// The parent must still observe the matching stream root, END and kernel EOF.
class PreNetworkTerminalClosedV2 final {
    struct PrivateEvidence {
        unsigned round{};
        Binding binding;
        std::string candidate_sha256;
        std::string case_sha256;
        std::string r0_receipt_sha256;
        std::string native_full_sha256;
        std::string final_checkpoint_sha256;
        std::string mapping_source_identity;
        std::string record_root_sha256;
        std::string end_frame_sha256;
        std::uint64_t record_count{};
        std::uint64_t payload_bytes{};
        std::uint64_t raw_wire_bytes{};
        unsigned explicit_owner_mapping_export_count{};
        bool owner_mapping_present{};
        bool grouping_source_complete{};
        bool explicit_owner_mapping_export_source_complete{};
        bool public_continuity_modeled_separately{};
        bool end_written{};
        bool writer_closed{};
    };
    PrivateEvidence evidence_;
    bool live_{true};
    explicit PreNetworkTerminalClosedV2(PrivateEvidence evidence)
        : evidence_(std::move(evidence)) {}
    friend class TerminalCaptureV2;
    friend class native_terminal::NativeTerminalChildEvidenceBridge;
public:
    PreNetworkTerminalClosedV2(const PreNetworkTerminalClosedV2&) = delete;
    PreNetworkTerminalClosedV2& operator=(
        const PreNetworkTerminalClosedV2&) = delete;
    PreNetworkTerminalClosedV2(PreNetworkTerminalClosedV2&& other) noexcept
        : evidence_(std::move(other.evidence_)), live_(other.live_) {
        other.live_ = false;
    }
    PreNetworkTerminalClosedV2& operator=(
        PreNetworkTerminalClosedV2&&) = delete;
#ifdef KPB_TERMINAL_CAPTURE_V2_TEST_SETUP
    void test_only_consume();
#endif
};

// These move-only values sequence capture emission in the parent process. They
// are not cryptographic or settlement authority. A future bridge may advance
// them only after the corresponding typed verifier/capability call returns.
#define KPB_TERMINAL_STAGE(NAME)                                             \
class NAME final {                                                          \
    friend class TerminalCaptureV2;                                         \
    const TerminalCaptureV2* owner_{};                                      \
    bool live_{};                                                           \
    explicit NAME(const TerminalCaptureV2* owner)                           \
        : owner_(owner), live_(true) {}                                     \
public:                                                                     \
    NAME(const NAME&) = delete;                                             \
    NAME& operator=(const NAME&) = delete;                                  \
    NAME(NAME&& other) noexcept                                             \
        : owner_(other.owner_), live_(other.live_) { other.live_ = false; } \
    NAME& operator=(NAME&&) = delete;                                       \
};

KPB_TERMINAL_STAGE(CandidateConstructedV2)
KPB_TERMINAL_STAGE(R0VerifiedV2)
KPB_TERMINAL_STAGE(NativeFullVerifiedV2)
KPB_TERMINAL_STAGE(DurableFinalV2)
KPB_TERMINAL_STAGE(SubmitAttemptedV2)
KPB_TERMINAL_STAGE(SubmitAcknowledgedV2)
KPB_TERMINAL_STAGE(AcceptedCaseV2)
KPB_TERMINAL_STAGE(ResolvedSettlementV2)

#undef KPB_TERMINAL_STAGE

class TerminalCaptureV2 final {
public:
    TerminalCaptureV2(int fd, unsigned round, const Binding& binding);
    ~TerminalCaptureV2();
    TerminalCaptureV2(const TerminalCaptureV2&) = delete;
    TerminalCaptureV2& operator=(const TerminalCaptureV2&) = delete;

    CandidateConstructedV2 after_candidate_constructed(
        std::uint64_t monotonic_ns, const std::string& candidate_sha256,
        const std::string& case_sha256);
    R0VerifiedV2 after_r0_verified(
        CandidateConstructedV2&&, std::uint64_t monotonic_ns,
        const std::string& r0_receipt_sha256,
        const std::string& projection_sha256);
    NativeFullVerifiedV2 after_native_full_verified(
        R0VerifiedV2&&, std::uint64_t monotonic_ns,
        const std::string& native_full_sha256,
        const std::string& case_sha256,
        const std::string& projection_sha256);
    DurableFinalV2 after_durable_final(
        NativeFullVerifiedV2&&, std::uint64_t monotonic_ns,
        const std::string& final_checkpoint_sha256);
    // Consumes the opaque source created from the exact retained projection.
    // Candidate ownership is structurally absent; a baseline-labelled source
    // can only originate from the separate explicit-owner policy authority.
    void after_complete_mapping_source(
        const DurableFinalV2&,
        native_terminal::NativeTerminalMappingSourceAuthority&&);
    // Pre-network branch: closes FD21/26 after the offline durable-final
    // capture. Testnet submit/ack/AcceptedCase is deliberately not part of
    // this authority and must start later from the activation permit.
    PreNetworkTerminalClosedV2 after_pre_network_capture_closed(
        DurableFinalV2&&, std::uint64_t monotonic_ns);
    SubmitAttemptedV2 after_testnet_submit_attempted(
        DurableFinalV2&&, std::uint64_t monotonic_ns,
        const std::string& transaction_id_hex32);
    SubmitAcknowledgedV2 after_testnet_submit_acknowledged(
        SubmitAttemptedV2&&, std::uint64_t monotonic_ns,
        const std::string& transaction_id_hex32);
    // An unknown write result closes this capture stream without closing the
    // trial. The consumed attempt has no retransmission transition.
    void after_testnet_submit_unknown(
        SubmitAttemptedV2&&, std::uint64_t monotonic_ns,
        const std::string& transaction_id_hex32);
    [[noreturn]] void after_testnet_submit_rejected(
        SubmitAcknowledgedV2&&, std::uint64_t monotonic_ns);
    AcceptedCaseV2 after_accepted_case(
        SubmitAcknowledgedV2&&, std::uint64_t monotonic_ns,
        const std::string& case_sha256,
        const std::string& transaction_id_hex32,
        const std::string& accepted_head_hex32);
    [[noreturn]] void after_accepted_case_reorged(
        AcceptedCaseV2&&, std::uint64_t monotonic_ns,
        const std::string& old_head_hex32,
        const std::string& new_head_hex32, std::uint64_t depth);
    [[noreturn]] void after_accepted_case_orphaned(
        AcceptedCaseV2&&, std::uint64_t monotonic_ns);
    ResolvedSettlementV2 after_durable_settlement_resolved(
        AcceptedCaseV2&&, std::uint64_t monotonic_ns,
        const std::string& settlement_sha256);
    void after_trial_closed(ResolvedSettlementV2&&,
                            std::uint64_t monotonic_ns);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    template<class Stage> void consume(Stage&, unsigned expected_stage);
    template<class Stage> void inspect(const Stage&, unsigned expected_stage);
};

template<int FixedFd, unsigned Round>
class TerminalCaptureV2Hook final {
    static_assert(Round == 1 || Round == 2);
    static_assert(FixedFd == (Round == 1 ? 21 : 26));
public:
    explicit TerminalCaptureV2Hook(const Binding& binding)
        : channel_(FixedFd, Round, binding) {}

    TerminalCaptureV2& channel() { return channel_; }
private:
    TerminalCaptureV2 channel_;
};

} // namespace kpb::capture
