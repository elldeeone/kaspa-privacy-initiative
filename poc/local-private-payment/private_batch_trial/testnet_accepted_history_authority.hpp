#pragma once

// Source-unreachable Testnet-10 accepted-history core.  This module validates
// typed, parent-owned network-child evidence after the pre-network activation
// boundary.  It has no RPC client, signer, funding source, broadcast path, or
// production mint/open callsite.  A future selected network supervisor must
// supply the two missing live producers recorded in kSourceStatus.

#include "testnet_activation_authority.hpp"

#include <atomic>
#include <cstdint>
#include <exception>
#include <optional>

namespace kpb::testnet_history {

using testnet_activation::CandidateActivationBinding;
using testnet_activation::Digest;
using testnet_activation::NetworkScope;
using testnet_activation::PublicFirstRpcBoundary;

inline constexpr std::uint32_t TESTNET10_CONFIRMATION_DEPTH = 20;

class Refused final : public std::exception {
public:
    const char* what() const noexcept override {
        return "testnet accepted history refused";
    }
};

enum class AcceptedHistoryStage : unsigned char {
    GenesisRound1Input = 1,
    PaymentRound1Successor = 2,
};

struct Round1LifecycleBinding {
    Digest run{};
    Digest round1_attempt{};
    Digest round1_cohort{};
    bool operator==(const Round1LifecycleBinding&) const = default;
};

// Deterministic pre-network metadata only.  It lets the fresh-owner plan name
// the exact later gate without predicting an accepting block.  Possessing this
// digest is never accepted-history authority.
Digest recompute_accepted_history_gate_identity(
    const CandidateActivationBinding&, const Round1LifecycleBinding&,
    AcceptedHistoryStage);

// Plain child output is never authority.  The production child-completion
// constructor is intentionally absent.  Private evidence is kept here rather
// than collapsed to a serialized acceptance Boolean or transaction ID.
struct AcceptedHistoryObservation {
    NetworkScope network{};
    AcceptedHistoryStage stage{};
    Digest network_genesis{};
    Digest run{};
    Digest trial{};
    Digest round1_attempt{};
    Digest round1_cohort{};
    Digest funding_identity{};
    Digest component_profile{};
    Digest immutable_tail{};
    Digest first_rpc_boundary_identity{};
    Digest selected_rpc_identity{};
    Digest selected_parent_identity{};
    Digest activation_permit_identity{};
    Digest native_candidate_completion{};
    Digest signed_case_completion{};
    Digest native_full_completion{};
    Digest r0_completion{};
    Digest value_conservation_completion{};
    Digest accepted_input_head{};
    Digest accepted_successor_head{};
    Digest candidate_case_identity{};
    Digest accepted_whole_case_identity{};
    Digest accepted_contexts_identity{};
    Digest full_pages_identity{};
    Digest accepting_block_identity{};
    Digest fixed_checkpoint_identity{};
    Digest requeried_checkpoint_identity{};
    Digest initial_sink_identity{};
    Digest post_query_sink_identity{};
    Digest current_view_identity{};
    Digest post_query_identity{};
    std::uint64_t accepting_blue_score{};
    std::uint64_t initial_sink_blue_score{};
    std::uint64_t post_query_sink_blue_score{};
    std::uint32_t min_confirmation_count{};
    std::uint32_t removed_chain_block_count{};
    std::uint32_t post_query_removed_chain_block_count{};
    bool node_synced{};
    bool utxo_index_enabled{};
    bool full_prefix_complete{};
    bool whole_case_equal{};
    bool accepted_contexts_equal{};
    bool sdk_transaction_id_recomputed{};
    bool current_successor_present{};
    bool current_successor_exact{};
    bool all_old_inputs_absent{};
    bool birth_anchor_still_selected{};
    bool fixed_checkpoint_still_selected{};
    bool post_query_complete{};
    bool selected_validating_node_only{};
    bool independent_consensus_proved{};
    bool network_invoked{};
    bool signing_or_broadcast_performed{};
    bool automatic_resubmission_permitted{};
};

struct PublicAcceptedHistoryStage {
    NetworkScope network{};
    AcceptedHistoryStage stage{};
    Digest run{};
    Digest trial{};
    Digest round1_attempt{};
    Digest round1_cohort{};
    Digest accepted_head_identity{};
    Digest history_gate_identity{};
    Digest source_session_identity{};
    Digest predecessor_confirmation_identity{};
    Digest confirmation_identity{};
};

class AcceptedHistoryObservationAuthority final {
    AcceptedHistoryObservation evidence_;
    std::atomic_bool live_{true};
    explicit AcceptedHistoryObservationAuthority(
        AcceptedHistoryObservation);
    friend class AcceptedHistoryConfirmationBridge;
public:
    AcceptedHistoryObservationAuthority(
        const AcceptedHistoryObservationAuthority&) = delete;
    AcceptedHistoryObservationAuthority& operator=(
        const AcceptedHistoryObservationAuthority&) = delete;
    AcceptedHistoryObservationAuthority(
        AcceptedHistoryObservationAuthority&&) noexcept;
    AcceptedHistoryObservationAuthority& operator=(
        AcceptedHistoryObservationAuthority&&) = delete;
#ifdef KPB_TESTNET_ACCEPTED_HISTORY_TEST_SETUP
    static AcceptedHistoryObservationAuthority test_only_mint(
        AcceptedHistoryObservation);
#endif
};

class AcceptedHistoryNetworkSessionAuthority final {
    PublicFirstRpcBoundary boundary_;
    Round1LifecycleBinding lifecycle_;
    Digest source_session_identity_{};
    std::atomic_bool live_{true};
    AcceptedHistoryNetworkSessionAuthority(
        PublicFirstRpcBoundary, Round1LifecycleBinding,
        Digest source_session_identity);
    friend class AcceptedHistoryConfirmationBridge;
public:
    AcceptedHistoryNetworkSessionAuthority(
        const AcceptedHistoryNetworkSessionAuthority&) = delete;
    AcceptedHistoryNetworkSessionAuthority& operator=(
        const AcceptedHistoryNetworkSessionAuthority&) = delete;
    AcceptedHistoryNetworkSessionAuthority(
        AcceptedHistoryNetworkSessionAuthority&&) noexcept;
    AcceptedHistoryNetworkSessionAuthority& operator=(
        AcceptedHistoryNetworkSessionAuthority&&) = delete;
#ifdef KPB_TESTNET_ACCEPTED_HISTORY_TEST_SETUP
    // Test-only because production must consume a live FirstRpcBoundaryAuthority
    // inside the future selected network supervisor, never a public receipt.
    // That live consume must be the sole session for the trial; a failed trial
    // cannot mint a replacement session with the same trial identity.
    static AcceptedHistoryNetworkSessionAuthority test_only_open(
        PublicFirstRpcBoundary, Round1LifecycleBinding,
        Digest source_session_identity);
#endif
};

class AcceptedRound1InputChainAuthority final {
    PublicAcceptedHistoryStage receipt_;
    AcceptedHistoryObservation evidence_;
    PublicFirstRpcBoundary boundary_;
    Round1LifecycleBinding lifecycle_;
    std::atomic_bool live_{true};
    AcceptedRound1InputChainAuthority(
        PublicAcceptedHistoryStage, AcceptedHistoryObservation,
        PublicFirstRpcBoundary, Round1LifecycleBinding);
    friend class AcceptedHistoryConfirmationBridge;
public:
    AcceptedRound1InputChainAuthority(
        const AcceptedRound1InputChainAuthority&) = delete;
    AcceptedRound1InputChainAuthority& operator=(
        const AcceptedRound1InputChainAuthority&) = delete;
    AcceptedRound1InputChainAuthority(
        AcceptedRound1InputChainAuthority&&) noexcept;
    AcceptedRound1InputChainAuthority& operator=(
        AcceptedRound1InputChainAuthority&&) = delete;

    // Burns and revalidates the complete private evidence.  The returned
    // public facts cannot mint an existing fresh-owner authority; only the
    // FreshOwnerProcessSupervisor owns that private constructor and lineages.
    PublicAcceptedHistoryStage consume_for_fresh_owner() &&;
};

class AcceptedRound1SuccessorNetworkContinuationAuthority final {
    PublicFirstRpcBoundary boundary_;
    Round1LifecycleBinding lifecycle_;
    Digest source_session_identity_{};
    Digest input_confirmation_identity_{};
    Digest input_history_gate_identity_{};
    AcceptedHistoryObservation input_evidence_;
    std::atomic_bool live_{true};
    AcceptedRound1SuccessorNetworkContinuationAuthority(
        PublicFirstRpcBoundary, Round1LifecycleBinding, Digest, Digest, Digest,
        AcceptedHistoryObservation);
    friend class AcceptedHistoryConfirmationBridge;
public:
    AcceptedRound1SuccessorNetworkContinuationAuthority(
        const AcceptedRound1SuccessorNetworkContinuationAuthority&) = delete;
    AcceptedRound1SuccessorNetworkContinuationAuthority& operator=(
        const AcceptedRound1SuccessorNetworkContinuationAuthority&) = delete;
    AcceptedRound1SuccessorNetworkContinuationAuthority(
        AcceptedRound1SuccessorNetworkContinuationAuthority&&) noexcept;
    AcceptedRound1SuccessorNetworkContinuationAuthority& operator=(
        AcceptedRound1SuccessorNetworkContinuationAuthority&&) = delete;
};

// Ordered split: the input capability must be taken first.  Its continuation
// can then survive Round-1 construction/submission and is the only value that
// can admit the later Round-1 successor observation.  Any failed successor
// admission burns this continuation.  Retrying requires a different fresh
// trial and a complete new input admission; R2-only and same-trial retry paths
// do not exist here.
class AcceptedRound1InputConfirmationJoin final {
    std::optional<AcceptedRound1InputChainAuthority> input_;
    std::optional<AcceptedRound1SuccessorNetworkContinuationAuthority>
        continuation_;
    bool input_taken_{};
    AcceptedRound1InputConfirmationJoin(
        AcceptedRound1InputChainAuthority&&,
        AcceptedRound1SuccessorNetworkContinuationAuthority&&);
    friend class AcceptedHistoryConfirmationBridge;
public:
    AcceptedRound1InputConfirmationJoin(
        const AcceptedRound1InputConfirmationJoin&) = delete;
    AcceptedRound1InputConfirmationJoin& operator=(
        const AcceptedRound1InputConfirmationJoin&) = delete;
    AcceptedRound1InputConfirmationJoin(
        AcceptedRound1InputConfirmationJoin&&) noexcept;
    AcceptedRound1InputConfirmationJoin& operator=(
        AcceptedRound1InputConfirmationJoin&&) = delete;
    AcceptedRound1InputChainAuthority take_input();
    AcceptedRound1SuccessorNetworkContinuationAuthority
        take_successor_continuation();
};

class AcceptedRound1SuccessorChainAuthority final {
    PublicAcceptedHistoryStage receipt_;
    AcceptedHistoryObservation input_evidence_;
    AcceptedHistoryObservation successor_evidence_;
    PublicFirstRpcBoundary boundary_;
    Round1LifecycleBinding lifecycle_;
    std::atomic_bool live_{true};
    AcceptedRound1SuccessorChainAuthority(
        PublicAcceptedHistoryStage, AcceptedHistoryObservation,
        AcceptedHistoryObservation, PublicFirstRpcBoundary,
        Round1LifecycleBinding);
    friend class AcceptedHistoryConfirmationBridge;
public:
    AcceptedRound1SuccessorChainAuthority(
        const AcceptedRound1SuccessorChainAuthority&) = delete;
    AcceptedRound1SuccessorChainAuthority& operator=(
        const AcceptedRound1SuccessorChainAuthority&) = delete;
    AcceptedRound1SuccessorChainAuthority(
        AcceptedRound1SuccessorChainAuthority&&) noexcept;
    AcceptedRound1SuccessorChainAuthority& operator=(
        AcceptedRound1SuccessorChainAuthority&&) = delete;
    PublicAcceptedHistoryStage consume_for_fresh_owner() &&;
};

class AcceptedHistoryConfirmationBridge final {
public:
    static AcceptedRound1InputConfirmationJoin confirm_genesis_input(
        AcceptedHistoryNetworkSessionAuthority&&,
        AcceptedHistoryObservationAuthority&&);
    static AcceptedRound1SuccessorChainAuthority confirm_round1_successor(
        AcceptedRound1SuccessorNetworkContinuationAuthority&&,
        AcceptedHistoryObservationAuthority&&);
};

struct SourceStatus {
    bool first_rpc_live_consumer{};
    bool authenticated_network_child_producer{};
    bool input_confirmation_validator{};
    bool successor_confirmation_validator{};
    bool fresh_owner_supervisor_adapter{};
    bool selected_history_producer_callsite{};
    bool configured{};
    bool network_enabled{};
    bool funding_enabled{};
    bool broadcast_enabled{};
};

inline constexpr SourceStatus kSourceStatus{
    .input_confirmation_validator = true,
    .successor_confirmation_validator = true,
    .fresh_owner_supervisor_adapter = true,
};

} // namespace kpb::testnet_history
