#include "testnet_accepted_history_authority.hpp"

#include <array>
#include <cassert>
#include <functional>
#include <string_view>
#include <utility>

using namespace kpb::testnet_activation;
using namespace kpb::testnet_history;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

Digest word(unsigned value) {
    Digest result{};
    result.fill(static_cast<unsigned char>(value));
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    return result;
}

unsigned char nibble(char value) {
    if (value >= '0' && value <= '9')
        return static_cast<unsigned char>(value - '0');
    if (value >= 'a' && value <= 'f')
        return static_cast<unsigned char>(value - 'a' + 10);
    assert(false);
    return 0;
}

Digest genesis() {
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

PublicFirstRpcBoundary boundary(unsigned seed = 1) {
    PublicFirstRpcBoundary result{};
    result.scope = NetworkScope::KaspaTestnet10;
    result.binding.network = NetworkScope::KaspaTestnet10;
    result.binding.trial = word(seed + 1);
    result.binding.funding_identity = word(seed + 2);
    result.binding.component_profile = word(seed + 3);
    result.binding.immutable_tail = word(seed + 4);
    result.binding.candidate_run = word(seed + 5);
    for (unsigned index = 0; index < 3; ++index) {
        result.binding.input_heads[index] = word(seed + 10 + index * 2);
        result.binding.successor_heads[index] =
            word(seed + 11 + index * 2);
        result.binding.native_candidate_completions[index] =
            word(seed + 30 + index);
        result.binding.signed_case_completions[index] =
            word(seed + 40 + index);
        result.binding.native_full_completions[index] =
            word(seed + 50 + index);
        result.binding.r0_completions[index] =
            word(seed + 60 + index);
        result.binding.value_conservation_completions[index] =
            word(seed + 70 + index);
    }
    result.binding.input_heads[1] = result.binding.successor_heads[0];
    result.binding.input_heads[2] = result.binding.successor_heads[1];
    result.selected_rpc_identity = word(seed + 80);
    result.selected_parent_identity = word(seed + 81);
    result.activation_permit_identity = word(seed + 82);
    result.boundary_identity = word(seed + 83);
    result.network_invoked = false;
    return result;
}

Round1LifecycleBinding lifecycle(const PublicFirstRpcBoundary& selected) {
    return {
        .run = selected.binding.candidate_run,
        .round1_attempt = word(0x101),
        .round1_cohort = word(0x102),
    };
}

AcceptedHistoryObservation observation(
        const PublicFirstRpcBoundary& selected,
        AcceptedHistoryStage stage, unsigned salt = 0) {
    const unsigned index =
        stage == AcceptedHistoryStage::GenesisRound1Input ? 0 : 1;
    const unsigned base = 100 + salt * 20 + index * 40;
    return {
        .network = NetworkScope::KaspaTestnet10,
        .stage = stage,
        .network_genesis = genesis(),
        .run = selected.binding.candidate_run,
        .trial = selected.binding.trial,
        .round1_attempt = word(0x101),
        .round1_cohort = word(0x102),
        .funding_identity = selected.binding.funding_identity,
        .component_profile = selected.binding.component_profile,
        .immutable_tail = selected.binding.immutable_tail,
        .first_rpc_boundary_identity = selected.boundary_identity,
        .selected_rpc_identity = selected.selected_rpc_identity,
        .selected_parent_identity = selected.selected_parent_identity,
        .activation_permit_identity = selected.activation_permit_identity,
        .native_candidate_completion =
            selected.binding.native_candidate_completions[index],
        .signed_case_completion =
            selected.binding.signed_case_completions[index],
        .native_full_completion =
            selected.binding.native_full_completions[index],
        .r0_completion = selected.binding.r0_completions[index],
        .value_conservation_completion =
            selected.binding.value_conservation_completions[index],
        .accepted_input_head = selected.binding.input_heads[index],
        .accepted_successor_head = selected.binding.successor_heads[index],
        .candidate_case_identity = word(base + 1),
        .accepted_whole_case_identity = word(base + 1),
        .accepted_contexts_identity = word(base + 2),
        .full_pages_identity = word(base + 3),
        .accepting_block_identity = word(base + 4),
        .fixed_checkpoint_identity = word(base + 5),
        .requeried_checkpoint_identity = word(base + 5),
        .initial_sink_identity = word(base + 6),
        .post_query_sink_identity = word(base + 7),
        .current_view_identity = word(base + 8),
        .post_query_identity = word(base + 9),
        .accepting_blue_score = 1000,
        .initial_sink_blue_score = 1021,
        .post_query_sink_blue_score = 1022,
        .min_confirmation_count = TESTNET10_CONFIRMATION_DEPTH,
        .removed_chain_block_count = 0,
        .post_query_removed_chain_block_count = 0,
        .node_synced = true,
        .utxo_index_enabled = true,
        .full_prefix_complete = true,
        .whole_case_equal = true,
        .accepted_contexts_equal = true,
        .sdk_transaction_id_recomputed = true,
        .current_successor_present = true,
        .current_successor_exact = true,
        .all_old_inputs_absent = true,
        .birth_anchor_still_selected = true,
        .fixed_checkpoint_still_selected = true,
        .post_query_complete = true,
        .selected_validating_node_only = true,
        .independent_consensus_proved = false,
        .network_invoked = true,
        .signing_or_broadcast_performed = false,
        .automatic_resubmission_permitted = false,
    };
}

AcceptedHistoryObservationAuthority observed(
        const PublicFirstRpcBoundary& selected,
        AcceptedHistoryStage stage, unsigned salt = 0) {
    return AcceptedHistoryObservationAuthority::test_only_mint(
        observation(selected, stage, salt));
}

AcceptedHistoryNetworkSessionAuthority session(
        const PublicFirstRpcBoundary& selected, unsigned salt = 0) {
    return AcceptedHistoryNetworkSessionAuthority::test_only_open(
        selected, lifecycle(selected), word(240 + salt));
}

void exact_staged_happy_path() {
    const auto selected = boundary();
    auto joined = AcceptedHistoryConfirmationBridge::confirm_genesis_input(
        session(selected), observed(
            selected, AcceptedHistoryStage::GenesisRound1Input));
    expect_refused([&] {
        (void)joined.take_successor_continuation();
    });
    auto input = joined.take_input();
    auto continuation = joined.take_successor_continuation();
    const auto input_receipt =
        std::move(input).consume_for_fresh_owner();
    assert(input_receipt.network == NetworkScope::KaspaTestnet10);
    assert(input_receipt.stage ==
           AcceptedHistoryStage::GenesisRound1Input);
    assert(input_receipt.trial == selected.binding.trial);
    assert(input_receipt.run == selected.binding.candidate_run);
    assert(input_receipt.round1_attempt == word(0x101));
    assert(input_receipt.round1_cohort == word(0x102));
    assert(input_receipt.accepted_head_identity ==
           selected.binding.successor_heads[0]);
    assert(input_receipt.predecessor_confirmation_identity == Digest{});

    auto successor =
        AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(continuation), observed(
                selected,
                AcceptedHistoryStage::PaymentRound1Successor));
    const auto successor_receipt =
        std::move(successor).consume_for_fresh_owner();
    assert(successor_receipt.stage ==
           AcceptedHistoryStage::PaymentRound1Successor);
    assert(successor_receipt.accepted_head_identity ==
           selected.binding.successor_heads[1]);
    assert(successor_receipt.source_session_identity ==
           input_receipt.source_session_identity);
    assert(successor_receipt.predecessor_confirmation_identity ==
           input_receipt.confirmation_identity);
    assert(successor_receipt.history_gate_identity !=
           input_receipt.history_gate_identity);
    expect_refused([&] {
        (void)std::move(input).consume_for_fresh_owner();
    });
    expect_refused([&] {
        (void)std::move(successor).consume_for_fresh_owner();
    });
}

void wrong_network_and_binding_refuse() {
    const auto selected = boundary();
    for (const auto& mutate : {
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.network = {}; }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.network_genesis = word(0xf001); }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.trial = word(0xf002); }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.run = word(0xf005); }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.round1_attempt = word(0xf006); }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.round1_cohort = word(0xf007); }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) {
                     value.native_candidate_completion = word(0xf003);
                 }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) {
                     value.accepted_successor_head = word(0xf004);
                 })}) {
        auto value = observation(
            selected, AcceptedHistoryStage::GenesisRound1Input);
        mutate(value);
        auto selected_session = session(selected);
        auto bad = AcceptedHistoryObservationAuthority::test_only_mint(value);
        expect_refused([&] {
            (void)AcceptedHistoryConfirmationBridge::confirm_genesis_input(
                std::move(selected_session), std::move(bad));
        });
        // The bad join burns both supplied linear capabilities before checks.
        auto fresh = observed(
            selected, AcceptedHistoryStage::GenesisRound1Input, 1);
        expect_refused([&] {
            (void)AcceptedHistoryConfirmationBridge::confirm_genesis_input(
                std::move(selected_session), std::move(fresh));
        });
    }
    auto detached = lifecycle(selected);
    detached.run = word(0xf100);
    auto detached_observation = observation(
        selected, AcceptedHistoryStage::GenesisRound1Input);
    detached_observation.run = detached.run;
    auto detached_session =
        AcceptedHistoryNetworkSessionAuthority::test_only_open(
            selected, detached, word(0xf101));
    auto detached_child =
        AcceptedHistoryObservationAuthority::test_only_mint(
            detached_observation);
    expect_refused([&] {
        (void)AcceptedHistoryConfirmationBridge::confirm_genesis_input(
            std::move(detached_session), std::move(detached_child));
    });

    auto aliased_session =
        AcceptedHistoryNetworkSessionAuthority::test_only_open(
            selected, lifecycle(selected), selected.selected_rpc_identity);
    auto aliased_child = observed(
        selected, AcceptedHistoryStage::GenesisRound1Input);
    expect_refused([&] {
        (void)AcceptedHistoryConfirmationBridge::confirm_genesis_input(
            std::move(aliased_session), std::move(aliased_child));
    });
}

void depth_stale_and_reorg_refuse() {
    const auto selected = boundary();
    for (const auto& mutate : {
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.initial_sink_blue_score = 1020; }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.min_confirmation_count = 19; }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.removed_chain_block_count = 1; }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) {
                     value.post_query_removed_chain_block_count = 1;
                 }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) {
                     value.requeried_checkpoint_identity = word(0xf101);
                 }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) {
                     value.fixed_checkpoint_still_selected = false;
                 }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.current_successor_present = false; }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.current_successor_exact = false; }),
             std::function<void(AcceptedHistoryObservation&)>(
                 [](auto& value) { value.all_old_inputs_absent = false; })}) {
        auto value = observation(
            selected, AcceptedHistoryStage::GenesisRound1Input);
        mutate(value);
        auto bad = AcceptedHistoryObservationAuthority::test_only_mint(value);
        expect_refused([&] {
            (void)AcceptedHistoryConfirmationBridge::confirm_genesis_input(
                session(selected), std::move(bad));
        });
    }
}

void successor_order_session_and_replay_refuse() {
    const auto selected = boundary();
    auto joined = AcceptedHistoryConfirmationBridge::confirm_genesis_input(
        session(selected), observed(
            selected, AcceptedHistoryStage::GenesisRound1Input));
    auto input = joined.take_input();
    auto continuation = joined.take_successor_continuation();
    (void)std::move(input).consume_for_fresh_owner();

    auto wrong_stage = observed(
        selected, AcceptedHistoryStage::GenesisRound1Input, 2);
    expect_refused([&] {
        (void)AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(continuation), std::move(wrong_stage));
    });
    auto fresh_successor = observed(
        selected, AcceptedHistoryStage::PaymentRound1Successor, 3);
    expect_refused([&] {
        (void)AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(continuation), std::move(fresh_successor));
    });

    auto joined2 = AcceptedHistoryConfirmationBridge::confirm_genesis_input(
        session(selected, 4), observed(
            selected, AcceptedHistoryStage::GenesisRound1Input, 4));
    auto input2 = joined2.take_input();
    auto continuation2 = joined2.take_successor_continuation();
    (void)std::move(input2).consume_for_fresh_owner();
    auto other = boundary(30);
    auto cross_trial = observed(
        other, AcceptedHistoryStage::PaymentRound1Successor, 5);
    expect_refused([&] {
        (void)AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(continuation2), std::move(cross_trial));
    });
}

void same_trial_r2_retry_refuses_and_fresh_trial_restarts() {
    const auto failed_trial = boundary(60);
    auto failed_join =
        AcceptedHistoryConfirmationBridge::confirm_genesis_input(
            session(failed_trial, 1),
            observed(failed_trial,
                     AcceptedHistoryStage::GenesisRound1Input, 1));
    auto failed_input = failed_join.take_input();
    auto burned_continuation =
        failed_join.take_successor_continuation();
    (void)std::move(failed_input).consume_for_fresh_owner();

    auto failed_r2 = observation(
        failed_trial, AcceptedHistoryStage::PaymentRound1Successor, 2);
    failed_r2.post_query_removed_chain_block_count = 1;
    auto failed_r2_authority =
        AcceptedHistoryObservationAuthority::test_only_mint(failed_r2);
    expect_refused([&] {
        (void)AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(burned_continuation),
            std::move(failed_r2_authority));
    });

    // A valid observation cannot retry the consumed R2 continuation, even
    // inside the same trial identity.
    auto same_trial_retry = observed(
        failed_trial, AcceptedHistoryStage::PaymentRound1Successor, 3);
    expect_refused([&] {
        (void)AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(burned_continuation),
            std::move(same_trial_retry));
    });

    // Retry policy requires a distinct fresh trial and a complete new R1
    // admission before a later R2 observation can succeed.
    const auto fresh_trial = boundary(90);
    assert(fresh_trial.binding.trial != failed_trial.binding.trial);
    auto fresh_join =
        AcceptedHistoryConfirmationBridge::confirm_genesis_input(
            session(fresh_trial, 4),
            observed(fresh_trial,
                     AcceptedHistoryStage::GenesisRound1Input, 4));
    auto fresh_input = fresh_join.take_input();
    auto fresh_continuation =
        fresh_join.take_successor_continuation();
    (void)std::move(fresh_input).consume_for_fresh_owner();
    auto fresh_successor =
        AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(fresh_continuation),
            observed(fresh_trial,
                     AcceptedHistoryStage::PaymentRound1Successor, 5));
    (void)std::move(fresh_successor).consume_for_fresh_owner();
}

void source_status_is_hard_disabled() {
    static_assert(kpb::testnet_history::kSourceStatus
                      .input_confirmation_validator);
    static_assert(kpb::testnet_history::kSourceStatus
                      .successor_confirmation_validator);
    static_assert(!kpb::testnet_history::kSourceStatus
                       .first_rpc_live_consumer);
    static_assert(!kpb::testnet_history::kSourceStatus
                       .authenticated_network_child_producer);
    static_assert(kpb::testnet_history::kSourceStatus
                      .fresh_owner_supervisor_adapter);
    static_assert(!kpb::testnet_history::kSourceStatus
                       .selected_history_producer_callsite);
    static_assert(!kpb::testnet_history::kSourceStatus.configured);
    static_assert(!kpb::testnet_history::kSourceStatus.network_enabled);
    static_assert(!kpb::testnet_history::kSourceStatus.funding_enabled);
    static_assert(!kpb::testnet_history::kSourceStatus.broadcast_enabled);
}

} // namespace

int main() {
    exact_staged_happy_path();
    wrong_network_and_binding_refuse();
    depth_stale_and_reorg_refuse();
    successor_order_session_and_replay_refuse();
    same_trial_r2_retry_refuses_and_fresh_trial_restarts();
    source_status_is_hard_disabled();
}
