#define KPI_FRESH_OWNER_PROCESS_ADAPTER_FIXTURE_NO_MAIN
#include "../mpc-prover/financial/controls/fresh_owner_process_adapter_test.cpp"
#include "testnet_accepted_history_authority.hpp"

#include <cassert>
#include <string_view>
#include <utility>

using namespace kpb::testnet_activation;
using namespace kpb::testnet_history;

namespace {

Digest testnet_genesis() {
    constexpr std::string_view value =
        "f896a3034873be1739fc4359236899fd"
        "3d65d2bc94f9780df0d0da3eb1cc4370";
    Digest result{};
    const auto nibble = [](char byte) -> unsigned char {
        if (byte >= '0' && byte <= '9')
            return static_cast<unsigned char>(byte - '0');
        assert(byte >= 'a' && byte <= 'f');
        return static_cast<unsigned char>(byte - 'a' + 10);
    };
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            (nibble(value[index * 2]) << 4) |
            nibble(value[index * 2 + 1]));
    return result;
}

Round1LifecycleBinding history_lifecycle(
        Digest run = id(8), Digest attempt = id(0x101),
        Digest cohort = id(0x102)) {
    return {
        .run = run,
        .round1_attempt = attempt,
        .round1_cohort = cohort,
    };
}

PublicFirstRpcBoundary history_boundary(
        const Round1LifecycleBinding& lifecycle,
        Digest trial = id(9)) {
    PublicFirstRpcBoundary result{};
    result.scope = NetworkScope::KaspaTestnet10;
    result.binding.network = NetworkScope::KaspaTestnet10;
    result.binding.trial = trial;
    result.binding.funding_identity = id(0x8101);
    result.binding.component_profile = id(0x8102);
    result.binding.immutable_tail = id(0x8103);
    result.binding.candidate_run = lifecycle.run;
    result.binding.input_heads = {id(0x8104), id(0x103), id(0x203)};
    result.binding.successor_heads = {id(0x103), id(0x203), id(0x8105)};
    for (unsigned index = 0; index < 3; ++index) {
        result.binding.native_candidate_completions[index] =
            id(0x8110 + index);
        result.binding.signed_case_completions[index] =
            id(0x8120 + index);
        result.binding.native_full_completions[index] =
            id(0x8130 + index);
        result.binding.r0_completions[index] = id(0x8140 + index);
        result.binding.value_conservation_completions[index] =
            id(0x8150 + index);
    }
    result.selected_rpc_identity = id(0x8160);
    result.selected_parent_identity = id(0x8161);
    result.activation_permit_identity = id(0x8162);
    result.boundary_identity = id(0x8163);
    result.network_invoked = false;
    return result;
}

AcceptedHistoryObservation history_observation(
        const PublicFirstRpcBoundary& selected,
        const Round1LifecycleBinding& lifecycle,
        AcceptedHistoryStage stage, unsigned salt = 0) {
    const unsigned index =
        stage == AcceptedHistoryStage::GenesisRound1Input ? 0 : 1;
    const unsigned base = 0x8200 + salt * 0x20 + index * 0x100;
    return {
        .network = NetworkScope::KaspaTestnet10,
        .stage = stage,
        .network_genesis = testnet_genesis(),
        .run = lifecycle.run,
        .trial = selected.binding.trial,
        .round1_attempt = lifecycle.round1_attempt,
        .round1_cohort = lifecycle.round1_cohort,
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
        .candidate_case_identity = id(base + 1),
        .accepted_whole_case_identity = id(base + 1),
        .accepted_contexts_identity = id(base + 2),
        .full_pages_identity = id(base + 3),
        .accepting_block_identity = id(base + 4),
        .fixed_checkpoint_identity = id(base + 5),
        .requeried_checkpoint_identity = id(base + 5),
        .initial_sink_identity = id(base + 6),
        .post_query_sink_identity = id(base + 7),
        .current_view_identity = id(base + 8),
        .post_query_identity = id(base + 9),
        .accepting_blue_score = 1000,
        .initial_sink_blue_score = 1021,
        .post_query_sink_blue_score = 1022,
        .min_confirmation_count = TESTNET10_CONFIRMATION_DEPTH,
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
        .network_invoked = true,
    };
}

AcceptedRound1InputConfirmationJoin input_join(
        const PublicFirstRpcBoundary& selected,
        const Round1LifecycleBinding& lifecycle, unsigned salt = 0) {
    return AcceptedHistoryConfirmationBridge::confirm_genesis_input(
        AcceptedHistoryNetworkSessionAuthority::test_only_open(
            selected, lifecycle, id(0x8400 + salt)),
        AcceptedHistoryObservationAuthority::test_only_mint(
            history_observation(
                selected, lifecycle,
                AcceptedHistoryStage::GenesisRound1Input, salt)));
}

CompiledPrivateLifecycleOwnerProgramAuthority history_plan(
        const PublicFirstRpcBoundary& selected,
        const Round1LifecycleBinding& lifecycle) {
    auto selected_plan = plan();
    selected_plan.run = lifecycle.run;
    selected_plan.trial = selected.binding.trial;
    const auto input_gate = recompute_accepted_history_gate_identity(
        selected.binding, lifecycle,
        AcceptedHistoryStage::GenesisRound1Input);
    const auto successor_gate = recompute_accepted_history_gate_identity(
        selected.binding, lifecycle,
        AcceptedHistoryStage::PaymentRound1Successor);
    for (auto& owner : selected_plan.owners) {
        owner.rounds[0].attempt = lifecycle.round1_attempt;
        owner.rounds[0].cohort = lifecycle.round1_cohort;
        owner.rounds[0].accepted_input_head_identity =
            selected.binding.successor_heads[0];
        owner.rounds[0].history_gate_identity = input_gate;
        owner.rounds[1].accepted_input_head_identity =
            selected.binding.successor_heads[1];
        owner.rounds[1].history_gate_identity = successor_gate;
        owner.rounds[0].contract.run_nonce =
            identity_registry::hex(lifecycle.round1_attempt);
        owner.rounds[0].contract.cohort_identity =
            identity_registry::hex(lifecycle.round1_cohort);
    }
    return CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
        std::move(selected_plan),
        std::make_shared<TestPrivateLifecycleProgram>());
}

void genuine_staged_history_injects_private_lineages() {
    const auto lifecycle = history_lifecycle();
    const auto selected = history_boundary(lifecycle);
    auto admitted = input_join(selected, lifecycle);
    auto input = admitted.take_input();
    auto continuation = admitted.take_successor_continuation();

    Roots roots;
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        history_plan(selected, lifecycle), root_authorities(roots));
    auto round1 = supervisor.issue_round1(
        std::move(input),
        replay_guard(std::make_shared<MemoryReplayRegistry>()),
        arm_residual(supervisor));
    consume_round1_bootstrap(round1);

    auto successor =
        AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(continuation),
            AcceptedHistoryObservationAuthority::test_only_mint(
                history_observation(
                    selected, lifecycle,
                    AcceptedHistoryStage::PaymentRound1Successor)));
    auto round2 = supervisor.issue_round2(
        std::move(round1), std::move(successor));
    consume_round2_bootstrap(round2);
    (void)round2.take_baseline_roster();
    assert(supervisor.completed());
}

void cross_run_attempt_cohort_and_trial_refuse() {
    const auto expected = history_lifecycle();
    const auto expected_boundary = history_boundary(expected);
    const std::array<Round1LifecycleBinding, 3> substitutions{
        history_lifecycle(id(0x8501), id(0x101), id(0x102)),
        history_lifecycle(id(8), id(0x8502), id(0x102)),
        history_lifecycle(id(8), id(0x101), id(0x8503)),
    };
    for (const auto& substituted : substitutions) {
        const auto source_boundary = history_boundary(substituted);
        auto admitted = input_join(source_boundary, substituted, 1);
        auto input = admitted.take_input();
        (void)admitted.take_successor_continuation();
        Roots roots;
        auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
            history_plan(expected_boundary, expected),
            root_authorities(roots));
        refuses([&] {
            (void)supervisor.issue_round1(
                std::move(input),
                replay_guard(std::make_shared<MemoryReplayRegistry>()),
                arm_residual(supervisor));
        });
    }
    const auto wrong_trial_boundary = history_boundary(expected, id(0x8504));
    auto admitted = input_join(wrong_trial_boundary, expected, 2);
    auto input = admitted.take_input();
    (void)admitted.take_successor_continuation();
    Roots roots;
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        history_plan(expected_boundary, expected), root_authorities(roots));
    refuses([&] {
        (void)supervisor.issue_round1(
            std::move(input),
            replay_guard(std::make_shared<MemoryReplayRegistry>()),
            arm_residual(supervisor));
    });
}

void cross_session_successor_refuses_and_burns_round1() {
    const auto lifecycle = history_lifecycle();
    const auto selected = history_boundary(lifecycle);
    auto admitted = input_join(selected, lifecycle, 3);
    auto input = admitted.take_input();
    (void)admitted.take_successor_continuation();

    Roots roots;
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        history_plan(selected, lifecycle), root_authorities(roots));
    auto round1 = supervisor.issue_round1(
        std::move(input),
        replay_guard(std::make_shared<MemoryReplayRegistry>()),
        arm_residual(supervisor));
    consume_round1_bootstrap(round1);

    auto foreign = input_join(selected, lifecycle, 4);
    auto foreign_input = foreign.take_input();
    (void)std::move(foreign_input).consume_for_fresh_owner();
    auto foreign_continuation = foreign.take_successor_continuation();
    auto foreign_successor =
        AcceptedHistoryConfirmationBridge::confirm_round1_successor(
            std::move(foreign_continuation),
            AcceptedHistoryObservationAuthority::test_only_mint(
                history_observation(
                    selected, lifecycle,
                    AcceptedHistoryStage::PaymentRound1Successor, 4)));
    refuses([&] {
        (void)supervisor.issue_round2(
            std::move(round1), std::move(foreign_successor));
    });
    assert(!supervisor.completed());
}

} // namespace

int main() {
    genuine_staged_history_injects_private_lineages();
    cross_run_attempt_cohort_and_trial_refuse();
    cross_session_successor_refuses_and_burns_round1();
}
