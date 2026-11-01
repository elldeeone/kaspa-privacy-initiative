#pragma once

// Source-only conjunction for ADR-0084's two live pre-network authorities.
// The production safety join and selected-parent capability ordering exist,
// but their typed evidence/parent producers and every network adapter remain
// absent. This module has no namespace builder, RPC client, funding or launch.

#include "privacy_measurement_authority.hpp"
#include "native_terminal_authority_consumer_contract.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>

namespace kpb::testnet_activation {

using Digest = measurement::Digest;

enum class NetworkScope : unsigned char {
    KaspaTestnet10 = 1,
};

// Public configuration is not authority. The safety factory derives this only
// while consuming typed global-capture and GEN3/payment native completions.
struct CandidateActivationBinding {
    NetworkScope network{};
    Digest trial{};
    Digest funding_identity{};
    Digest component_profile{};
    Digest immutable_tail{};
    Digest comparison_selection{};
    Digest selection_identity{};
    Digest baseline_run{};
    Digest candidate_run{};
    Digest baseline_aggregate{};
    Digest candidate_aggregate{};
    Digest privacy_pass_identity{};
    std::array<Digest, 2> projections{};
    measurement::FiniteManifestBinding finite_manifest;
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest manifest_recomputation_receipt{};
    Digest global_payment_capture_completion{};
    std::array<Digest, 2> registered_driver_completions{};
    std::array<Digest, 3> input_heads{};
    std::array<Digest, 3> successor_heads{};
    std::array<Digest, 3> core_completions{};
    std::array<Digest, 3> proof_completions{};
    std::array<Digest, 3> native_candidate_completions{};
    std::array<Digest, 3> signed_case_completions{};
    std::array<Digest, 3> native_full_completions{};
    std::array<Digest, 3> r0_completions{};
    std::array<Digest, 3> value_conservation_completions{};
    std::array<Digest, 3> native_child_processes{};
    std::array<Digest, 3> native_child_exits{};
    std::array<std::uint64_t, 3> input_values_sompi{};
    std::array<std::uint64_t, 3> successor_values_sompi{};
    std::array<std::uint64_t, 3> fees_sompi{};
    bool operator==(const CandidateActivationBinding&) const = default;
};

struct PublicGlobalPaymentCaptureCompletion {
    NetworkScope network{};
    Digest trial{};
    Digest funding_identity{};
    Digest component_profile{};
    Digest immutable_tail{};
    Digest comparison_selection{};
    Digest selection_identity{};
    Digest candidate_run{};
    std::array<Digest, 2> projections{};
    measurement::FiniteManifestBinding finite_manifest;
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest manifest_recomputation_receipt{};
    std::array<Digest, 2> registered_driver_completions{};
    std::array<Digest, 2> registered_driver_heads{};
    Digest completion_identity{};
};

class PreNetworkSafetyFactory;

class GlobalPaymentCaptureCompletionAuthority final {
    PublicGlobalPaymentCaptureCompletion receipt_;
    std::atomic_bool live_{true};
    explicit GlobalPaymentCaptureCompletionAuthority(
        PublicGlobalPaymentCaptureCompletion);
    friend class PreNetworkSafetyFactory;
public:
    GlobalPaymentCaptureCompletionAuthority(
        const GlobalPaymentCaptureCompletionAuthority&) = delete;
    GlobalPaymentCaptureCompletionAuthority& operator=(
        const GlobalPaymentCaptureCompletionAuthority&) = delete;
    GlobalPaymentCaptureCompletionAuthority(
        GlobalPaymentCaptureCompletionAuthority&&) noexcept;
    GlobalPaymentCaptureCompletionAuthority& operator=(
        GlobalPaymentCaptureCompletionAuthority&&) = delete;
    const PublicGlobalPaymentCaptureCompletion& public_receipt() const {
        return receipt_;
    }
#ifdef KPB_TESTNET_ACTIVATION_AUTHORITY_TEST_SETUP
    static GlobalPaymentCaptureCompletionAuthority test_only_mint(
        PublicGlobalPaymentCaptureCompletion);
#endif
};

enum class NativeCandidateKind : unsigned char {
    Genesis = 1,
    PaymentRound1 = 2,
    PaymentRound2 = 3,
};

struct PublicNativeCandidateCompletion {
    NetworkScope network{};
    NativeCandidateKind kind{};
    unsigned ordinal{};
    Digest trial{};
    Digest funding_identity{};
    Digest component_profile{};
    Digest immutable_tail{};
    Digest input_head{};
    Digest successor_head{};
    Digest projection{};
    Digest core{};
    Digest proof{};
    Digest signed_case_completion{};
    Digest native_full_completion{};
    Digest r0_completion{};
    Digest value_conservation_completion{};
    measurement::WorkerBinding worker{};
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest transport_session{};
    Digest offer_identity{};
    Digest child_process_identity{};
    Digest child_exit_identity{};
    std::uint64_t input_value_sompi{};
    std::uint64_t successor_value_sompi{};
    std::uint64_t fee_sompi{};
    bool credentials_verified{};
    bool offer_acknowledged{};
    bool clean_exit{};
    Digest completion_identity{};
};

Digest recompute_native_candidate_completion_identity(
    const PublicNativeCandidateCompletion&);

class NativeCandidateCompletionAuthority final {
    struct PrivateSupervisorEvidence {
        std::uint64_t authenticated_child_pid{};
        std::uint64_t waited_child_pid{};
        bool child_control_closed{};
        Digest private_supervisor_identity{};
    };
    PublicNativeCandidateCompletion receipt_;
    PrivateSupervisorEvidence evidence_;
    std::atomic_bool live_{true};
    NativeCandidateCompletionAuthority(
        PublicNativeCandidateCompletion, std::uint64_t authenticated_child_pid,
        std::uint64_t waited_child_pid, bool child_control_closed);
    friend class PreNetworkSafetyFactory;
    friend class kpb::native_terminal::NativeTerminalSupervisor;
    friend class kpb::native_terminal::NativeTerminalProducerJoin;
public:
    NativeCandidateCompletionAuthority(
        const NativeCandidateCompletionAuthority&) = delete;
    NativeCandidateCompletionAuthority& operator=(
        const NativeCandidateCompletionAuthority&) = delete;
    NativeCandidateCompletionAuthority(
        NativeCandidateCompletionAuthority&&) noexcept;
    NativeCandidateCompletionAuthority& operator=(
        NativeCandidateCompletionAuthority&&) = delete;
    const PublicNativeCandidateCompletion& public_receipt() const {
        return receipt_;
    }
};

struct PublicPreNetworkSafety {
    NetworkScope scope{};
    CandidateActivationBinding binding;
    Digest safety_identity{};
};

class ActivationJoiner;
class PreNetworkSafetyJoin;

class PreNetworkSafetyAuthority final {
    PublicPreNetworkSafety receipt_;
    std::atomic_bool live_{true};
    explicit PreNetworkSafetyAuthority(CandidateActivationBinding);
    friend class ActivationJoiner;
    friend class PreNetworkSafetyFactory;
public:
    PreNetworkSafetyAuthority(const PreNetworkSafetyAuthority&) = delete;
    PreNetworkSafetyAuthority& operator=(
        const PreNetworkSafetyAuthority&) = delete;
    PreNetworkSafetyAuthority(PreNetworkSafetyAuthority&&) noexcept;
    PreNetworkSafetyAuthority& operator=(
        PreNetworkSafetyAuthority&&) = delete;
    const PublicPreNetworkSafety& public_receipt() const { return receipt_; }
};

// Non-detachable conjunction: the live privacy capability that authorized the
// safety comparison remains inside this opaque join until ActivationJoiner
// atomically consumes both. No public take-half or receipt constructor exists.
class PreNetworkSafetyJoin final {
    std::optional<measurement::BatchPrivacyPassAuthority> privacy_;
    std::optional<PreNetworkSafetyAuthority> safety_;
    std::atomic_bool live_{true};
    PreNetworkSafetyJoin(
        measurement::BatchPrivacyPassAuthority&&,
        PreNetworkSafetyAuthority&&);
    friend class PreNetworkSafetyFactory;
    friend class ActivationJoiner;
public:
    PreNetworkSafetyJoin(const PreNetworkSafetyJoin&) = delete;
    PreNetworkSafetyJoin& operator=(const PreNetworkSafetyJoin&) = delete;
    PreNetworkSafetyJoin(PreNetworkSafetyJoin&&) noexcept;
    PreNetworkSafetyJoin& operator=(PreNetworkSafetyJoin&&) = delete;
};

class PreNetworkSafetyFactory final {
public:
    static PreNetworkSafetyJoin join(
        measurement::BatchPrivacyPassAuthority&&,
        GlobalPaymentCaptureCompletionAuthority&&,
        std::array<NativeCandidateCompletionAuthority, 3>&&);
};

struct PublicTestnetActivationPermit {
    NetworkScope scope{};
    CandidateActivationBinding binding;
    Digest privacy_pass_identity{};
    Digest safety_identity{};
    Digest permit_identity{};
};

// This remains an inert move-only capability. A production network consumer is
// intentionally absent, so constructing it cannot perform a network effect.
class TestnetActivationPermit final {
    PublicTestnetActivationPermit receipt_;
    std::atomic_bool live_{true};
    explicit TestnetActivationPermit(PublicTestnetActivationPermit);
    friend class ActivationJoiner;
    friend class SelectedParentNetworkBoundary;
public:
    TestnetActivationPermit(const TestnetActivationPermit&) = delete;
    TestnetActivationPermit& operator=(
        const TestnetActivationPermit&) = delete;
    TestnetActivationPermit(TestnetActivationPermit&&) noexcept;
    TestnetActivationPermit& operator=(TestnetActivationPermit&&) = delete;
    const PublicTestnetActivationPermit& public_receipt() const {
        return receipt_;
    }
};

class ActivationJoiner final {
public:
    static TestnetActivationPermit conjoin(PreNetworkSafetyJoin&&);
};

struct PublicSelectedParent {
    NetworkScope network{};
    CandidateActivationBinding binding;
    Digest selected_rpc_identity{};
    Digest parent_identity{};
};

class SelectedParentNetworkBoundary;

class SelectedParentAuthority final {
    PublicSelectedParent receipt_;
    std::atomic_bool live_{true};
    explicit SelectedParentAuthority(PublicSelectedParent);
    friend class SelectedParentNetworkBoundary;
public:
    SelectedParentAuthority(const SelectedParentAuthority&) = delete;
    SelectedParentAuthority& operator=(
        const SelectedParentAuthority&) = delete;
    SelectedParentAuthority(SelectedParentAuthority&&) noexcept;
    SelectedParentAuthority& operator=(SelectedParentAuthority&&) = delete;
    const PublicSelectedParent& public_receipt() const { return receipt_; }
#ifdef KPB_TESTNET_ACTIVATION_AUTHORITY_TEST_SETUP
    static SelectedParentAuthority test_only_mint(PublicSelectedParent);
#endif
};

struct PublicFirstRpcBoundary {
    NetworkScope scope{};
    CandidateActivationBinding binding;
    Digest selected_rpc_identity{};
    Digest selected_parent_identity{};
    Digest activation_permit_identity{};
    Digest boundary_identity{};
    bool network_invoked{};
};

class FirstRpcBoundaryAuthority final {
    PublicFirstRpcBoundary receipt_;
    std::atomic_bool live_{true};
    explicit FirstRpcBoundaryAuthority(PublicFirstRpcBoundary);
    friend class SelectedParentNetworkBoundary;
public:
    FirstRpcBoundaryAuthority(const FirstRpcBoundaryAuthority&) = delete;
    FirstRpcBoundaryAuthority& operator=(
        const FirstRpcBoundaryAuthority&) = delete;
    FirstRpcBoundaryAuthority(FirstRpcBoundaryAuthority&&) noexcept;
    FirstRpcBoundaryAuthority& operator=(
        FirstRpcBoundaryAuthority&&) = delete;
    const PublicFirstRpcBoundary& public_receipt() const { return receipt_; }
};

// This module owns capability ordering, not network I/O. Its only RPC-shaped
// method requires the live activation permit as an argument and returns an
// inert authority for a future, currently absent network adapter.
class SelectedParentNetworkBoundary final {
    enum class State { AwaitingPermit, Completed, Poisoned };
    PublicSelectedParent parent_;
    std::mutex mutex_;
    State state_{State::AwaitingPermit};
    explicit SelectedParentNetworkBoundary(PublicSelectedParent);
public:
    SelectedParentNetworkBoundary(const SelectedParentNetworkBoundary&) =
        delete;
    SelectedParentNetworkBoundary& operator=(
        const SelectedParentNetworkBoundary&) = delete;
    SelectedParentNetworkBoundary(SelectedParentNetworkBoundary&&) = delete;
    SelectedParentNetworkBoundary& operator=(
        SelectedParentNetworkBoundary&&) = delete;
    static SelectedParentNetworkBoundary open(SelectedParentAuthority&&);
    FirstRpcBoundaryAuthority authorize_first_rpc(
        TestnetActivationPermit&&);
};

struct SourceStatus {
    bool global_capture_evidence_producer{};
    bool native_candidate_evidence_producer{};
    bool selected_parent_authority_producer{};
    bool pre_network_safety_factory{};
    bool activation_conjunction{};
    bool selected_parent_permit_consumer{};
    bool first_rpc_boundary_authority{};
    bool network_namespace_factory{};
    bool network_adapter{};
    bool configured{};
    bool launch_enabled{};
    bool network_invoked{};
};

inline constexpr SourceStatus kSourceStatus{
    .pre_network_safety_factory = true,
    .activation_conjunction = true,
    .selected_parent_permit_consumer = true,
    .first_rpc_boundary_authority = true,
};

} // namespace kpb::testnet_activation
