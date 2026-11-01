#pragma once

// Offline GEN3/R1/R2 completion boundary for ADR-0084. Payment completions
// own the existing TerminalCaptureV2 writer chain on FD21/26. The sole reader
// remains ParentOwnedCaptureProducer; its live closure is joined exactly once
// and returned for the measurement path. No RPC or submission exists here.

#include "privacy_terminal_capture_v2.hpp"
#include "native_terminal_projection_intake_bridge.hpp"
#include "testnet_activation_authority.hpp"
#include "honest_owner_material_authority.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

namespace kpb::native_terminal {

using testnet_activation::Digest;
using testnet_activation::NativeCandidateCompletionAuthority;
using testnet_activation::NativeCandidateKind;
using testnet_activation::NetworkScope;
using testnet_activation::PublicNativeCandidateCompletion;

inline constexpr int NATIVE_TERMINAL_CHILD_FIXED_FD = 62;

// Common native candidate selection. Configuration is never authority.
struct NativeTerminalSelection {
    NetworkScope network{};
    NativeCandidateKind kind{};
    unsigned ordinal{};
    Digest trial{};
    Digest funding_identity{};
    Digest component_profile{};
    Digest immutable_tail{};
    Digest accepted_input_head{};
    Digest successor_head{};
    Digest projection{};
    Digest core{};
    Digest proof{};
    Digest case_identity{};
    Digest durable_final_checkpoint{};
    Digest signed_case_completion{};
    Digest native_full_completion{};
    Digest r0_completion{};
    Digest value_conservation_completion{};
    std::uint64_t input_value_sompi{};
    std::uint64_t successor_value_sompi{};
    std::uint64_t fee_sompi{};
    measurement::WorkerBinding worker{};
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    bool operator==(const NativeTerminalSelection&) const = default;
};

struct PublicGenesisTerminalOffer {
    NativeTerminalSelection selection;
    Digest transport_session{};
    Digest offer_identity{};
    std::uint64_t parent_pid{};
    std::uint64_t child_pid{};
};

struct GenesisTerminalChildResult {
    Digest accepted_input_head{};
    Digest successor_head{};
    Digest projection{};
    Digest core{};
    Digest proof{};
    Digest case_identity{};
    Digest durable_final_checkpoint{};
    Digest signed_case_completion{};
    Digest native_full_completion{};
    Digest r0_completion{};
    Digest value_conservation_completion{};
    std::uint64_t input_value_sompi{};
    std::uint64_t successor_value_sompi{};
    std::uint64_t fee_sompi{};
    bool operator==(const GenesisTerminalChildResult&) const = default;
};

class GenesisTerminalChildProgram {
public:
    virtual ~GenesisTerminalChildProgram() = default;
    virtual GenesisTerminalChildResult execute(
        const PublicGenesisTerminalOffer&) = 0;
};

// The caller supplies lineage only. Complete terminal grouping, the narrow
// owner-to-NF/tuple export statement, and terminal wire evidence are created
// inside the child and never appear in a public receipt. Public projection
// continuity is a distinct structural authority.
struct PaymentTerminalSelection {
    NativeTerminalSelection native;
    measurement::RunBinding producer_binding;
    capture::Binding capture_binding;
};

struct PublicPaymentTerminalOffer {
    NativeTerminalSelection native;
    capture::Binding capture_binding;
    Digest transport_session{};
    Digest offer_identity{};
    std::uint64_t parent_pid{};
    std::uint64_t child_pid{};
};

struct PaymentTerminalChildResult {
    GenesisTerminalChildResult native;
    capture::PreNetworkTerminalClosedV2 terminal;
    PaymentTerminalChildResult(
        GenesisTerminalChildResult selected_native,
        capture::PreNetworkTerminalClosedV2&& selected_terminal)
        : native(std::move(selected_native)),
          terminal(std::move(selected_terminal)) {}
    PaymentTerminalChildResult(const PaymentTerminalChildResult&) = delete;
    PaymentTerminalChildResult& operator=(
        const PaymentTerminalChildResult&) = delete;
    PaymentTerminalChildResult(PaymentTerminalChildResult&&) noexcept =
        default;
    PaymentTerminalChildResult& operator=(
        PaymentTerminalChildResult&&) = delete;
};

// The child implementation must return the live token created by the same
// TerminalCaptureV2 object after durable-final, complete terminal grouping,
// the owner-mapping export statement, and END/close. Cross-round public
// projection continuity is proved separately.
class PaymentTerminalChildProgram {
public:
    virtual ~PaymentTerminalChildProgram() = default;
    virtual PaymentTerminalChildResult execute(
        const PublicPaymentTerminalOffer&, capture::TerminalCaptureV2&,
        NativeTerminalMappingSourceAuthority&&) = 0;
};

int run_genesis_terminal_child(GenesisTerminalChildProgram&) noexcept;
int run_payment_terminal_child(PaymentTerminalChildProgram&) noexcept;

#ifdef KPB_NATIVE_TERMINAL_COMPLETION_TEST_SETUP
int test_only_run_genesis_terminal_child(
    GenesisTerminalChildProgram&) noexcept;
int test_only_run_payment_terminal_child(
    PaymentTerminalChildProgram&) noexcept;
#endif

// Public lineage only. Terminal record/END/EOF hashes, byte/event counts,
// complete grouping, owner-mapping export evidence and child PIDs remain in
// the live private authority. Structural projection continuity is separate.
struct PublicPaymentLifecycleCompletion {
    NativeTerminalSelection native;
    measurement::RunBinding producer_binding;
    Digest stream_process_identity{};
    Digest stream_child_exit_identity{};
    Digest transport_session{};
    Digest offer_identity{};
    Digest child_process_observation{};
    Digest child_exit_observation{};
    Digest opaque_lifecycle_authority_identity{};
    bool credentials_verified{};
    bool offer_acknowledged{};
    bool child_control_closed{};
    bool clean_exit{};
    bool operator==(const PublicPaymentLifecycleCompletion&) const = default;
};

class MatchedNativeTerminalProducerBundle;
class TerminalV2ModelAdmissionAuthority;
class StructuralProjectionContinuityAuthority;

class PaymentLifecycleCompletionAuthority final {
    struct PrivateStructuralProjectionEvidence {
        Digest projection_identity{};
        Digest profile_context_identity{};
        Digest old_context_identity{};
        Digest old_reserve_outpoint_identity{};
        Digest old_cm_root{};
        Digest old_nf_root{};
        std::uint32_t old_cm_count{};
        std::uint32_t old_nf_count{};
        std::uint64_t old_reserve_sompi{};
        Digest new_cm_root{};
        Digest new_nf_root{};
        std::uint32_t new_cm_count{};
        std::uint32_t new_nf_count{};
        std::uint64_t new_reserve_sompi{};
        std::uint64_t fee_sompi{};
        Digest old_state_identity{};
        Digest successor_state_identity{};
        Digest old_script_identity{};
        Digest successor_script_identity{};
        Digest structural_old_context_identity{};
        Digest structural_successor_context_identity{};
        Digest structural_projection_identity{};
        std::array<Digest, 3> public_nullifiers{};
        std::array<honest_owner_material::Output520, 6> public_outputs{};
        bool operator==(
            const PrivateStructuralProjectionEvidence&) const = default;
    };

    struct PrivateTerminalStreamEvidence {
        capture::Binding capture_binding;
        PrivateStructuralProjectionEvidence structural_projection;
        Digest record_root{};
        Digest end_frame_identity{};
        Digest expected_eof_identity{};
        Digest retained_projection_identity{};
        Digest projection_fork_binding_identity{};
        Digest projection_intake_identity{};
        Digest terminal_mapping_source_identity{};
        std::uint64_t record_count{};
        std::uint64_t payload_bytes{};
        std::uint64_t raw_wire_bytes{};
        std::uint64_t authenticated_child_pid{};
        std::uint64_t waited_child_pid{};
        Digest private_completion_identity{};
        unsigned explicit_owner_mapping_export_count{};
        bool owner_mapping_present{};
        bool owner_mapping_absent{};
        bool grouping_source_complete{};
        bool explicit_owner_mapping_export_source_complete{};
        bool public_continuity_modeled_separately{};
        bool end_written{};
        bool writer_closed{};
        bool operator==(const PrivateTerminalStreamEvidence&) const = default;
    };

    PublicPaymentLifecycleCompletion receipt_;
    PrivateTerminalStreamEvidence evidence_;
    std::atomic_bool live_{true};
    void validate_for_native_terminal_join() const;
    static PrivateStructuralProjectionEvidence parse_structural_projection(
        std::span<const std::byte>);
    static Digest recompute_structural_projection_identity(
        const PrivateStructuralProjectionEvidence&);
    static void validate_structural_projection(
        const PrivateStructuralProjectionEvidence&);
    PaymentLifecycleCompletionAuthority(
        PublicPaymentLifecycleCompletion,
        PrivateTerminalStreamEvidence);
    friend class NativeTerminalSupervisor;
    friend class NativeTerminalProducerJoin;
    friend class MatchedNativeTerminalProducerBundle;
    friend class TerminalV2ModelAdmissionAuthority;
    friend class StructuralProjectionContinuityAuthority;
    friend class measurement::ProducerClosureAuthority;
public:
    PaymentLifecycleCompletionAuthority(
        const PaymentLifecycleCompletionAuthority&) = delete;
    PaymentLifecycleCompletionAuthority& operator=(
        const PaymentLifecycleCompletionAuthority&) = delete;
    PaymentLifecycleCompletionAuthority(
        PaymentLifecycleCompletionAuthority&&) noexcept;
    PaymentLifecycleCompletionAuthority& operator=(
        PaymentLifecycleCompletionAuthority&&) = delete;
    const PublicPaymentLifecycleCompletion& public_receipt() const {
        return receipt_;
    }
};

Digest recompute_terminal_stream_process_identity(
    const PaymentTerminalSelection&);
Digest recompute_terminal_stream_child_exit_identity(
    const PaymentTerminalSelection&);
bool exact_capture_lineage(
    const measurement::RunBinding&, unsigned round,
    const capture::Binding&) noexcept;

// Created only by ProducerClosureAuthority's authority-to-authority private
// comparison. It contains the sole live producer continuation and the two
// matched, still-private lifecycle continuations.
class MatchedNativeTerminalProducerBundle final {
    std::optional<measurement::ProducerClosureAuthority> producer_;
    std::array<std::optional<PaymentLifecycleCompletionAuthority>, 2>
        lifecycle_;
    std::atomic_bool live_{true};
    MatchedNativeTerminalProducerBundle(
        measurement::ProducerClosureAuthority&&,
        PaymentLifecycleCompletionAuthority&&,
        PaymentLifecycleCompletionAuthority&&);
    friend class measurement::ProducerClosureAuthority;
    friend class NativeTerminalProducerJoin;
    friend class TerminalV2ModelAdmissionAuthority;
    friend class measurement::runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    MatchedNativeTerminalProducerBundle(
        const MatchedNativeTerminalProducerBundle&) = delete;
    MatchedNativeTerminalProducerBundle& operator=(
        const MatchedNativeTerminalProducerBundle&) = delete;
    MatchedNativeTerminalProducerBundle(
        MatchedNativeTerminalProducerBundle&&) noexcept;
    MatchedNativeTerminalProducerBundle& operator=(
        MatchedNativeTerminalProducerBundle&&) = delete;
    TerminalV2ModelAdmissionAuthority transfer_for_terminal_v2_model(
        honest_owner_material::HonestOwnerTwoRoundProductionAuthority&&) &&;
};

// Linear authority for terminal-v2 model admission. It can only be created by
// consuming an already matched producer + ordered R1/R2 terminal bundle. It
// deliberately has no public receipt, terminal hash/count, route identity,
// PID, group, or row accessor. It retains the exact projection-structural
// continuity residual, explicitly not accepted-chain evidence. The model
// bridge must consume that residual and return the retained live continuation;
// CONFIGURED0 remains in force until that bridge exists.
class TerminalV2ModelAdmissionAuthority final {
    struct RoundEvidence {
        PublicPaymentLifecycleCompletion lifecycle;
        capture::Binding capture_binding;
        PaymentLifecycleCompletionAuthority::
            PrivateStructuralProjectionEvidence structural_projection;
        measurement::PublicStreamClosure producer_stream;
        Digest record_root{};
        Digest end_frame_identity{};
        Digest expected_eof_identity{};
        Digest retained_projection_identity{};
        Digest projection_fork_binding_identity{};
        Digest projection_intake_identity{};
        Digest terminal_mapping_source_identity{};
        Digest private_completion_identity{};
        std::uint64_t record_count{};
        std::uint64_t payload_bytes{};
        std::uint64_t raw_wire_bytes{};
        std::uint64_t authenticated_child_pid{};
        std::uint64_t waited_child_pid{};
        unsigned explicit_owner_mapping_export_count{};
        bool owner_mapping_present{};
        bool owner_mapping_absent{};
        bool grouping_source_complete{};
        bool explicit_owner_mapping_export_source_complete{};
        bool public_continuity_modeled_separately{};
        bool end_written{};
        bool writer_closed{};
    };
    struct PrivateEvidence {
        measurement::RunBinding binding;
        measurement::Classification classification{};
        Digest producer_closure_authority_identity{};
        std::array<RoundEvidence, 2> rounds{};
    };

    std::optional<measurement::ProducerClosureAuthority> producer_;
    std::array<std::optional<PaymentLifecycleCompletionAuthority>, 2>
        lifecycle_;
    std::unique_ptr<StructuralProjectionContinuityAuthority>
        structural_continuity_;
    std::optional<
        honest_owner_material::HonestOwnerTwoRoundProductionAuthority>
        honest_owner_production_;
    PrivateEvidence evidence_;
    std::atomic_bool live_{true};
    TerminalV2ModelAdmissionAuthority(
        measurement::ProducerClosureAuthority&&,
        PaymentLifecycleCompletionAuthority&&,
        PaymentLifecycleCompletionAuthority&&,
        StructuralProjectionContinuityAuthority&&,
        honest_owner_material::HonestOwnerTwoRoundProductionAuthority&&,
        PrivateEvidence);
    void validate_model_state(
        bool authority_live, bool continuity_live) const;
    void validate_for_model_join() const;
    void validate_consumed_for_observer_join() const;
    friend class MatchedNativeTerminalProducerBundle;
    friend class measurement::runtime_bridge::ObserverCaptureCapsuleBridge;
    friend class measurement::TrialCaptureJoiner;
public:
    TerminalV2ModelAdmissionAuthority(
        const TerminalV2ModelAdmissionAuthority&) = delete;
    TerminalV2ModelAdmissionAuthority& operator=(
        const TerminalV2ModelAdmissionAuthority&) = delete;
    TerminalV2ModelAdmissionAuthority(
        TerminalV2ModelAdmissionAuthority&&) noexcept;
    ~TerminalV2ModelAdmissionAuthority();
    TerminalV2ModelAdmissionAuthority& operator=(
        TerminalV2ModelAdmissionAuthority&&) = delete;
};

// Proves only the structural equality of the exact matched projection pair:
// R1's new CM/NF roots, counts, profile context, reserve and derived state are
// R2's old structural state. It also binds both projection route/process/exit
// lineages. It does NOT prove that R1 was accepted on Testnet or that R2 read
// an accepted chain head. There is no public receipt/getter/test minter.
class StructuralProjectionContinuityAuthority final {
    struct RoundLineage {
        Digest projection{};
        Digest accepted_input_head{};
        Digest successor_head{};
        Digest retained_projection{};
        Digest fork_binding{};
        Digest intake{};
        Digest mapping_source{};
        Digest stream_process{};
        Digest stream_child_exit{};
        Digest child_process{};
        Digest child_exit{};
        Digest producer_stream_process{};
        Digest producer_stream_child_exit{};
        Digest private_completion{};
        PaymentLifecycleCompletionAuthority::
            PrivateStructuralProjectionEvidence structural;
    };
    struct PrivateEvidence {
        measurement::RunBinding binding;
        measurement::Classification classification{};
        std::array<RoundLineage, 2> rounds{};
        Digest continuity_identity{};
        bool structural_projection_continuity{};
        bool accepted_chain_continuity{};
    };
    PrivateEvidence evidence_;
    std::atomic_bool live_{true};
    explicit StructuralProjectionContinuityAuthority(PrivateEvidence);
    static Digest recompute_identity(const PrivateEvidence&);
    void validate_state(bool authority_live) const;
    void validate() const;
    void validate_consumed() const;
    friend class MatchedNativeTerminalProducerBundle;
    friend class TerminalV2ModelAdmissionAuthority;
    friend class measurement::runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    StructuralProjectionContinuityAuthority(
        const StructuralProjectionContinuityAuthority&) = delete;
    StructuralProjectionContinuityAuthority& operator=(
        const StructuralProjectionContinuityAuthority&) = delete;
    StructuralProjectionContinuityAuthority(
        StructuralProjectionContinuityAuthority&&) noexcept;
    StructuralProjectionContinuityAuthority& operator=(
        StructuralProjectionContinuityAuthority&&) = delete;
};

class NativeTerminalProducerBundle final {
    std::optional<measurement::ProducerClosureAuthority> producer_;
    std::array<std::optional<NativeCandidateCompletionAuthority>, 2> native_;
    std::atomic_bool producer_live_{true};
    std::atomic_bool native_live_{true};
    NativeTerminalProducerBundle(
        measurement::ProducerClosureAuthority&&,
        std::array<NativeCandidateCompletionAuthority, 2>&&);
    friend class NativeTerminalProducerJoin;
public:
    NativeTerminalProducerBundle(const NativeTerminalProducerBundle&) =
        delete;
    NativeTerminalProducerBundle& operator=(
        const NativeTerminalProducerBundle&) = delete;
    NativeTerminalProducerBundle(NativeTerminalProducerBundle&&) noexcept;
    NativeTerminalProducerBundle& operator=(
        NativeTerminalProducerBundle&&) = delete;
    measurement::ProducerClosureAuthority take_producer();
    std::array<NativeCandidateCompletionAuthority, 2> take_native();
};

struct NativeTerminalSourceStatus {
    bool authenticated_child_supervisor{};
    bool terminal_v2_stage_chain{};
    bool sole_producer_stream_join{};
    bool private_terminal_evidence{};
    bool exact_sompi_conservation{};
    bool retained_projection_intake{};
    bool terminal_mapping_source{};
    bool terminal_v2_model_admission_authority{};
    bool structural_projection_continuity{};
    bool honest_owner_production_residual_required{};
    bool exact_honest_owner_nf_output_correspondence{};
    bool accepted_chain_continuity_authority{};
    bool observer_model_admission{};
    bool gen3_lifecycle_adapter{};
    bool payment_lifecycle_adapter{};
    bool accepted_head_producer{};
    bool network_namespace{};
    bool network_adapter{};
    bool configured{};
    bool launch_enabled{};
    bool network_invoked{};
};

inline constexpr NativeTerminalSourceStatus kNativeTerminalSourceStatus{
    .authenticated_child_supervisor = true,
    .terminal_v2_stage_chain = true,
    .sole_producer_stream_join = true,
    .private_terminal_evidence = true,
    .exact_sompi_conservation = true,
    .retained_projection_intake = true,
    .terminal_mapping_source = true,
    .terminal_v2_model_admission_authority = true,
    .structural_projection_continuity = true,
    .honest_owner_production_residual_required = true,
    .exact_honest_owner_nf_output_correspondence = true,
};

} // namespace kpb::native_terminal
