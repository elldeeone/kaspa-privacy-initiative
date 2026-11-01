#include "testnet_accepted_history_authority.hpp"

#include <algorithm>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::testnet_history {
namespace {

using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void text(Bytes& out, std::string_view value) {
    add(out, std::span(reinterpret_cast<const unsigned char*>(value.data()),
                       value.size()));
}

void add(Bytes& out, std::uint64_t value, unsigned width = 8) {
    for (unsigned offset = 0; offset < width; ++offset)
        out.push_back(static_cast<unsigned char>(value >> (8 * offset)));
}

void add(Bytes& out, bool value) {
    out.push_back(static_cast<unsigned char>(value));
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

unsigned char nibble(char value) {
    if (value >= '0' && value <= '9')
        return static_cast<unsigned char>(value - '0');
    if (value >= 'a' && value <= 'f')
        return static_cast<unsigned char>(value - 'a' + 10);
    refuse();
}

Digest testnet10_genesis() {
    constexpr std::string_view value =
        "f896a3034873be1739fc4359236899fd"
        "3d65d2bc94f9780df0d0da3eb1cc4370";
    Digest result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            (nibble(value[index * 2]) << 4) |
            nibble(value[index * 2 + 1]));
    return result;
}

void require_distinct_nonzero(const std::array<Digest, 3>& values) {
    for (unsigned left = 0; left < values.size(); ++left) {
        need(nonzero(values[left]));
        for (unsigned right = left + 1; right < values.size(); ++right)
            need(values[left] != values[right]);
    }
}

void valid_boundary(const PublicFirstRpcBoundary& boundary) {
    const auto& binding = boundary.binding;
    need(boundary.scope == NetworkScope::KaspaTestnet10 &&
         binding.network == NetworkScope::KaspaTestnet10 &&
         !boundary.network_invoked);
    for (const auto* value : {
             &binding.trial, &binding.funding_identity,
             &binding.component_profile, &binding.immutable_tail,
             &binding.candidate_run, &boundary.selected_rpc_identity,
             &boundary.selected_parent_identity,
             &boundary.activation_permit_identity,
             &boundary.boundary_identity})
        need(nonzero(*value));
    need(boundary.selected_rpc_identity !=
             boundary.selected_parent_identity &&
         boundary.activation_permit_identity != boundary.boundary_identity);
    require_distinct_nonzero(binding.input_heads);
    require_distinct_nonzero(binding.successor_heads);
    require_distinct_nonzero(binding.native_candidate_completions);
    require_distinct_nonzero(binding.signed_case_completions);
    require_distinct_nonzero(binding.native_full_completions);
    require_distinct_nonzero(binding.r0_completions);
    require_distinct_nonzero(binding.value_conservation_completions);
    need(binding.successor_heads[0] == binding.input_heads[1] &&
         binding.successor_heads[1] == binding.input_heads[2]);
}

void valid_source_session_identity(
        const Digest& session,
        const PublicFirstRpcBoundary& boundary,
        const Round1LifecycleBinding& lifecycle) {
    need(nonzero(session));
    for (const auto* value : {
             &boundary.binding.trial,
             &boundary.binding.funding_identity,
             &boundary.binding.component_profile,
             &boundary.binding.immutable_tail,
             &boundary.binding.candidate_run,
             &boundary.selected_rpc_identity,
             &boundary.selected_parent_identity,
             &boundary.activation_permit_identity,
             &boundary.boundary_identity,
             &lifecycle.round1_attempt,
             &lifecycle.round1_cohort})
        need(session != *value);
}

unsigned stage_index(AcceptedHistoryStage stage) {
    if (stage == AcceptedHistoryStage::GenesisRound1Input) return 0;
    if (stage == AcceptedHistoryStage::PaymentRound1Successor) return 1;
    refuse();
}

Digest history_gate_identity(
        const CandidateActivationBinding& binding,
        const Round1LifecycleBinding& lifecycle,
        AcceptedHistoryStage stage) {
    const auto index = stage_index(stage);
    Bytes bytes;
    text(bytes, "KPB_TESTNET10_ACCEPTED_HISTORY_GATE_V1\n");
    add(bytes, static_cast<std::uint64_t>(stage), 1);
    for (const auto* value : {
             &lifecycle.run, &lifecycle.round1_attempt,
             &lifecycle.round1_cohort})
        add(bytes, *value);
    for (const auto* value : {
             &binding.trial, &binding.funding_identity,
             &binding.component_profile, &binding.immutable_tail,
             &binding.candidate_run, &binding.input_heads[index],
             &binding.successor_heads[index],
             &binding.native_candidate_completions[index],
             &binding.signed_case_completions[index],
             &binding.native_full_completions[index],
             &binding.r0_completions[index],
             &binding.value_conservation_completions[index]})
        add(bytes, *value);
    return hash(bytes);
}

void add_observation(Bytes& bytes, const AcceptedHistoryObservation& value) {
    add(bytes, static_cast<std::uint64_t>(value.network), 1);
    add(bytes, static_cast<std::uint64_t>(value.stage), 1);
    for (const auto* field : {
             &value.network_genesis, &value.run, &value.trial,
             &value.round1_attempt, &value.round1_cohort,
             &value.funding_identity, &value.component_profile,
             &value.immutable_tail, &value.first_rpc_boundary_identity,
             &value.selected_rpc_identity, &value.selected_parent_identity,
             &value.activation_permit_identity,
             &value.native_candidate_completion,
             &value.signed_case_completion,
             &value.native_full_completion, &value.r0_completion,
             &value.value_conservation_completion,
             &value.accepted_input_head, &value.accepted_successor_head,
             &value.candidate_case_identity,
             &value.accepted_whole_case_identity,
             &value.accepted_contexts_identity,
             &value.full_pages_identity, &value.accepting_block_identity,
             &value.fixed_checkpoint_identity,
             &value.requeried_checkpoint_identity,
             &value.initial_sink_identity,
             &value.post_query_sink_identity,
             &value.current_view_identity, &value.post_query_identity})
        add(bytes, *field);
    add(bytes, value.accepting_blue_score);
    add(bytes, value.initial_sink_blue_score);
    add(bytes, value.post_query_sink_blue_score);
    add(bytes, value.min_confirmation_count, 4);
    add(bytes, value.removed_chain_block_count, 4);
    add(bytes, value.post_query_removed_chain_block_count, 4);
    for (const bool flag : {
             value.node_synced, value.utxo_index_enabled,
             value.full_prefix_complete, value.whole_case_equal,
             value.accepted_contexts_equal,
             value.sdk_transaction_id_recomputed,
             value.current_successor_present,
             value.current_successor_exact,
             value.all_old_inputs_absent,
             value.birth_anchor_still_selected,
             value.fixed_checkpoint_still_selected,
             value.post_query_complete,
             value.selected_validating_node_only,
             value.independent_consensus_proved,
             value.network_invoked,
             value.signing_or_broadcast_performed,
             value.automatic_resubmission_permitted})
        add(bytes, flag);
}

void valid_observation(
        const PublicFirstRpcBoundary& boundary,
        const Round1LifecycleBinding& lifecycle,
        const AcceptedHistoryObservation& value,
        AcceptedHistoryStage expected_stage) {
    valid_boundary(boundary);
    const auto& binding = boundary.binding;
    const auto index = stage_index(expected_stage);
    for (const auto* field : {
             &lifecycle.run, &lifecycle.round1_attempt,
             &lifecycle.round1_cohort})
        need(nonzero(*field));
    need(lifecycle.round1_attempt != lifecycle.round1_cohort &&
         lifecycle.run == binding.candidate_run);
    need(value.network == NetworkScope::KaspaTestnet10 &&
         value.stage == expected_stage &&
         value.network_genesis == testnet10_genesis() &&
         value.run == lifecycle.run &&
         value.trial == binding.trial &&
         value.round1_attempt == lifecycle.round1_attempt &&
         value.round1_cohort == lifecycle.round1_cohort &&
         value.funding_identity == binding.funding_identity &&
         value.component_profile == binding.component_profile &&
         value.immutable_tail == binding.immutable_tail &&
         value.first_rpc_boundary_identity == boundary.boundary_identity &&
         value.selected_rpc_identity == boundary.selected_rpc_identity &&
         value.selected_parent_identity ==
             boundary.selected_parent_identity &&
         value.activation_permit_identity ==
             boundary.activation_permit_identity &&
         value.native_candidate_completion ==
             binding.native_candidate_completions[index] &&
         value.signed_case_completion ==
             binding.signed_case_completions[index] &&
         value.native_full_completion ==
             binding.native_full_completions[index] &&
         value.r0_completion == binding.r0_completions[index] &&
         value.value_conservation_completion ==
             binding.value_conservation_completions[index] &&
         value.accepted_input_head == binding.input_heads[index] &&
         value.accepted_successor_head == binding.successor_heads[index] &&
         value.candidate_case_identity ==
             value.accepted_whole_case_identity);

    for (const auto* field : {
             &value.candidate_case_identity,
             &value.accepted_contexts_identity,
             &value.full_pages_identity, &value.accepting_block_identity,
             &value.fixed_checkpoint_identity,
             &value.requeried_checkpoint_identity,
             &value.initial_sink_identity,
             &value.post_query_sink_identity,
             &value.current_view_identity, &value.post_query_identity})
        need(nonzero(*field));
    need(value.fixed_checkpoint_identity ==
             value.requeried_checkpoint_identity &&
         value.accepting_block_identity !=
             value.fixed_checkpoint_identity &&
         value.min_confirmation_count == TESTNET10_CONFIRMATION_DEPTH &&
         value.initial_sink_blue_score > value.accepting_blue_score &&
         value.initial_sink_blue_score - value.accepting_blue_score >
             value.min_confirmation_count &&
         value.post_query_sink_blue_score >=
             value.initial_sink_blue_score &&
         value.post_query_sink_blue_score > value.accepting_blue_score &&
         value.post_query_sink_blue_score - value.accepting_blue_score >
             value.min_confirmation_count &&
         value.removed_chain_block_count == 0 &&
         value.post_query_removed_chain_block_count == 0 &&
         value.node_synced && value.utxo_index_enabled &&
         value.full_prefix_complete && value.whole_case_equal &&
         value.accepted_contexts_equal &&
         value.sdk_transaction_id_recomputed &&
         value.current_successor_present &&
         value.current_successor_exact &&
         value.all_old_inputs_absent &&
         value.birth_anchor_still_selected &&
         value.fixed_checkpoint_still_selected &&
         value.post_query_complete &&
         value.selected_validating_node_only &&
         !value.independent_consensus_proved &&
         value.network_invoked &&
         !value.signing_or_broadcast_performed &&
         !value.automatic_resubmission_permitted);
}

Digest confirmation_identity(
        const PublicFirstRpcBoundary& boundary,
        const Digest& session,
        const Digest& predecessor,
        const AcceptedHistoryObservation& observation) {
    Bytes bytes;
    text(bytes, "KPB_TESTNET10_ACCEPTED_HISTORY_CONFIRMATION_V1\n");
    add(bytes, boundary.boundary_identity);
    add(bytes, session);
    add(bytes, predecessor);
    add_observation(bytes, observation);
    return hash(bytes);
}

PublicAcceptedHistoryStage stage_receipt(
        const PublicFirstRpcBoundary& boundary,
        const Round1LifecycleBinding& lifecycle,
        const Digest& session,
        const Digest& predecessor,
        const AcceptedHistoryObservation& observation) {
    return {
        .network = NetworkScope::KaspaTestnet10,
        .stage = observation.stage,
        .run = lifecycle.run,
        .trial = boundary.binding.trial,
        .round1_attempt = lifecycle.round1_attempt,
        .round1_cohort = lifecycle.round1_cohort,
        .accepted_head_identity = observation.accepted_successor_head,
        .history_gate_identity = history_gate_identity(
            boundary.binding, lifecycle, observation.stage),
        .source_session_identity = session,
        .predecessor_confirmation_identity = predecessor,
        .confirmation_identity = confirmation_identity(
            boundary, session, predecessor, observation),
    };
}

void valid_receipt(
        const PublicAcceptedHistoryStage& receipt,
        const PublicFirstRpcBoundary& boundary,
        const Round1LifecycleBinding& lifecycle,
        const Digest& session,
        const Digest& predecessor,
        const AcceptedHistoryObservation& observation) {
    need(receipt.network == NetworkScope::KaspaTestnet10 &&
         receipt.stage == observation.stage &&
         receipt.run == lifecycle.run &&
         receipt.trial == boundary.binding.trial &&
         receipt.round1_attempt == lifecycle.round1_attempt &&
         receipt.round1_cohort == lifecycle.round1_cohort &&
         receipt.accepted_head_identity ==
             observation.accepted_successor_head &&
         receipt.history_gate_identity == history_gate_identity(
             boundary.binding, lifecycle, observation.stage) &&
         receipt.source_session_identity == session &&
         receipt.predecessor_confirmation_identity == predecessor &&
         receipt.confirmation_identity == confirmation_identity(
             boundary, session, predecessor, observation) &&
         nonzero(receipt.confirmation_identity));
}

} // namespace

Digest recompute_accepted_history_gate_identity(
        const CandidateActivationBinding& binding,
        const Round1LifecycleBinding& lifecycle,
        AcceptedHistoryStage stage) {
    for (const auto* value : {
             &lifecycle.run, &lifecycle.round1_attempt,
             &lifecycle.round1_cohort})
        need(nonzero(*value));
    need(lifecycle.round1_attempt != lifecycle.round1_cohort);
    need(lifecycle.run == binding.candidate_run);
    return history_gate_identity(binding, lifecycle, stage);
}

AcceptedHistoryObservationAuthority::AcceptedHistoryObservationAuthority(
        AcceptedHistoryObservation evidence)
    : evidence_(std::move(evidence)) {}

AcceptedHistoryObservationAuthority::AcceptedHistoryObservationAuthority(
        AcceptedHistoryObservationAuthority&& other) noexcept
    : evidence_(other.evidence_), live_(other.live_.exchange(false)) {}

#ifdef KPB_TESTNET_ACCEPTED_HISTORY_TEST_SETUP
AcceptedHistoryObservationAuthority
AcceptedHistoryObservationAuthority::test_only_mint(
        AcceptedHistoryObservation evidence) {
    return AcceptedHistoryObservationAuthority(std::move(evidence));
}
#endif

AcceptedHistoryNetworkSessionAuthority::
AcceptedHistoryNetworkSessionAuthority(
        PublicFirstRpcBoundary boundary, Round1LifecycleBinding lifecycle,
        Digest source_session_identity)
    : boundary_(std::move(boundary)),
      lifecycle_(lifecycle),
      source_session_identity_(source_session_identity) {}

AcceptedHistoryNetworkSessionAuthority::
AcceptedHistoryNetworkSessionAuthority(
        AcceptedHistoryNetworkSessionAuthority&& other) noexcept
    : boundary_(other.boundary_),
      lifecycle_(other.lifecycle_),
      source_session_identity_(other.source_session_identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_TESTNET_ACCEPTED_HISTORY_TEST_SETUP
AcceptedHistoryNetworkSessionAuthority
AcceptedHistoryNetworkSessionAuthority::test_only_open(
        PublicFirstRpcBoundary boundary, Round1LifecycleBinding lifecycle,
        Digest source_session_identity) {
    return AcceptedHistoryNetworkSessionAuthority(
        std::move(boundary), lifecycle, source_session_identity);
}
#endif

AcceptedRound1InputChainAuthority::AcceptedRound1InputChainAuthority(
        PublicAcceptedHistoryStage receipt,
        AcceptedHistoryObservation evidence,
        PublicFirstRpcBoundary boundary,
        Round1LifecycleBinding lifecycle)
    : receipt_(std::move(receipt)), evidence_(std::move(evidence)),
      boundary_(std::move(boundary)), lifecycle_(lifecycle) {}

AcceptedRound1InputChainAuthority::AcceptedRound1InputChainAuthority(
        AcceptedRound1InputChainAuthority&& other) noexcept
    : receipt_(other.receipt_), evidence_(other.evidence_),
      boundary_(other.boundary_), lifecycle_(other.lifecycle_),
      live_(other.live_.exchange(false)) {}

PublicAcceptedHistoryStage
AcceptedRound1InputChainAuthority::consume_for_fresh_owner() && {
    need(live_.exchange(false));
    valid_observation(boundary_, lifecycle_, evidence_,
                      AcceptedHistoryStage::GenesisRound1Input);
    valid_receipt(receipt_, boundary_, lifecycle_,
                  receipt_.source_session_identity, Digest{}, evidence_);
    return receipt_;
}

AcceptedRound1SuccessorNetworkContinuationAuthority::
AcceptedRound1SuccessorNetworkContinuationAuthority(
        PublicFirstRpcBoundary boundary, Round1LifecycleBinding lifecycle,
        Digest source_session_identity,
        Digest input_confirmation_identity,
        Digest input_history_gate_identity,
        AcceptedHistoryObservation input_evidence)
    : boundary_(std::move(boundary)),
      lifecycle_(lifecycle),
      source_session_identity_(source_session_identity),
      input_confirmation_identity_(input_confirmation_identity),
      input_history_gate_identity_(input_history_gate_identity),
      input_evidence_(std::move(input_evidence)) {}

AcceptedRound1SuccessorNetworkContinuationAuthority::
AcceptedRound1SuccessorNetworkContinuationAuthority(
        AcceptedRound1SuccessorNetworkContinuationAuthority&& other) noexcept
    : boundary_(other.boundary_),
      lifecycle_(other.lifecycle_),
      source_session_identity_(other.source_session_identity_),
      input_confirmation_identity_(other.input_confirmation_identity_),
      input_history_gate_identity_(other.input_history_gate_identity_),
      input_evidence_(other.input_evidence_),
      live_(other.live_.exchange(false)) {}

AcceptedRound1InputConfirmationJoin::AcceptedRound1InputConfirmationJoin(
        AcceptedRound1InputChainAuthority&& input,
        AcceptedRound1SuccessorNetworkContinuationAuthority&& continuation)
    : input_(std::in_place, std::move(input)),
      continuation_(std::in_place, std::move(continuation)) {}

AcceptedRound1InputConfirmationJoin::AcceptedRound1InputConfirmationJoin(
        AcceptedRound1InputConfirmationJoin&& other) noexcept
    : input_(std::move(other.input_)),
      continuation_(std::move(other.continuation_)),
      input_taken_(other.input_taken_) {
    other.input_.reset();
    other.continuation_.reset();
    other.input_taken_ = false;
}

AcceptedRound1InputChainAuthority
AcceptedRound1InputConfirmationJoin::take_input() {
    need(!input_taken_ && input_.has_value());
    input_taken_ = true;
    auto result = std::move(*input_);
    input_.reset();
    return result;
}

AcceptedRound1SuccessorNetworkContinuationAuthority
AcceptedRound1InputConfirmationJoin::take_successor_continuation() {
    need(input_taken_ && continuation_.has_value());
    auto result = std::move(*continuation_);
    continuation_.reset();
    return result;
}

AcceptedRound1SuccessorChainAuthority::
AcceptedRound1SuccessorChainAuthority(
        PublicAcceptedHistoryStage receipt,
        AcceptedHistoryObservation input_evidence,
        AcceptedHistoryObservation successor_evidence,
        PublicFirstRpcBoundary boundary,
        Round1LifecycleBinding lifecycle)
    : receipt_(std::move(receipt)),
      input_evidence_(std::move(input_evidence)),
      successor_evidence_(std::move(successor_evidence)),
      boundary_(std::move(boundary)), lifecycle_(lifecycle) {}

AcceptedRound1SuccessorChainAuthority::
AcceptedRound1SuccessorChainAuthority(
        AcceptedRound1SuccessorChainAuthority&& other) noexcept
    : receipt_(other.receipt_), input_evidence_(other.input_evidence_),
      successor_evidence_(other.successor_evidence_),
      boundary_(other.boundary_), lifecycle_(other.lifecycle_),
      live_(other.live_.exchange(false)) {}

PublicAcceptedHistoryStage
AcceptedRound1SuccessorChainAuthority::consume_for_fresh_owner() && {
    need(live_.exchange(false));
    valid_observation(boundary_, lifecycle_, input_evidence_,
                      AcceptedHistoryStage::GenesisRound1Input);
    valid_observation(boundary_, lifecycle_, successor_evidence_,
                      AcceptedHistoryStage::PaymentRound1Successor);
    valid_receipt(receipt_, boundary_, lifecycle_,
                  receipt_.source_session_identity,
                  receipt_.predecessor_confirmation_identity,
                  successor_evidence_);
    need(receipt_.predecessor_confirmation_identity ==
         confirmation_identity(boundary_, receipt_.source_session_identity,
                               Digest{}, input_evidence_));
    return receipt_;
}

AcceptedRound1InputConfirmationJoin
AcceptedHistoryConfirmationBridge::confirm_genesis_input(
        AcceptedHistoryNetworkSessionAuthority&& session,
        AcceptedHistoryObservationAuthority&& observation) {
    const bool session_live = session.live_.exchange(false);
    const bool observation_live = observation.live_.exchange(false);
    need(session_live && observation_live);
    valid_boundary(session.boundary_);
    valid_source_session_identity(
        session.source_session_identity_, session.boundary_,
        session.lifecycle_);
    valid_observation(session.boundary_, session.lifecycle_,
                      observation.evidence_,
                      AcceptedHistoryStage::GenesisRound1Input);
    auto receipt = stage_receipt(
        session.boundary_, session.lifecycle_,
        session.source_session_identity_, Digest{},
        observation.evidence_);
    valid_receipt(receipt, session.boundary_, session.lifecycle_,
                  session.source_session_identity_, Digest{},
                  observation.evidence_);
    auto continuation =
        AcceptedRound1SuccessorNetworkContinuationAuthority(
            session.boundary_, session.lifecycle_,
            session.source_session_identity_,
            receipt.confirmation_identity, receipt.history_gate_identity,
            observation.evidence_);
    return AcceptedRound1InputConfirmationJoin(
        AcceptedRound1InputChainAuthority(
            receipt, observation.evidence_, session.boundary_,
            session.lifecycle_),
        std::move(continuation));
}

AcceptedRound1SuccessorChainAuthority
AcceptedHistoryConfirmationBridge::confirm_round1_successor(
        AcceptedRound1SuccessorNetworkContinuationAuthority&& continuation,
        AcceptedHistoryObservationAuthority&& observation) {
    const bool continuation_live = continuation.live_.exchange(false);
    const bool observation_live = observation.live_.exchange(false);
    need(continuation_live && observation_live);
    valid_boundary(continuation.boundary_);
    valid_source_session_identity(
        continuation.source_session_identity_, continuation.boundary_,
        continuation.lifecycle_);
    need(nonzero(continuation.input_confirmation_identity_) &&
         nonzero(continuation.input_history_gate_identity_));
    valid_observation(continuation.boundary_, continuation.lifecycle_,
                      continuation.input_evidence_,
                      AcceptedHistoryStage::GenesisRound1Input);
    const auto expected_input = stage_receipt(
        continuation.boundary_, continuation.lifecycle_,
        continuation.source_session_identity_, Digest{},
        continuation.input_evidence_);
    need(expected_input.confirmation_identity ==
             continuation.input_confirmation_identity_ &&
         expected_input.history_gate_identity ==
             continuation.input_history_gate_identity_);
    valid_observation(continuation.boundary_, continuation.lifecycle_,
                      observation.evidence_,
                      AcceptedHistoryStage::PaymentRound1Successor);
    need(observation.evidence_.accepted_input_head ==
         continuation.input_evidence_.accepted_successor_head);
    auto receipt = stage_receipt(
        continuation.boundary_, continuation.lifecycle_,
        continuation.source_session_identity_,
        continuation.input_confirmation_identity_, observation.evidence_);
    valid_receipt(receipt, continuation.boundary_,
                  continuation.lifecycle_,
                  continuation.source_session_identity_,
                  continuation.input_confirmation_identity_,
                  observation.evidence_);
    return AcceptedRound1SuccessorChainAuthority(
        receipt, continuation.input_evidence_, observation.evidence_,
        continuation.boundary_, continuation.lifecycle_);
}

} // namespace kpb::testnet_history
