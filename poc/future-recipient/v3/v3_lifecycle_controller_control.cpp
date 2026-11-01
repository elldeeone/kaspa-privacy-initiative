#define KPI_FRESH_OWNER_PROCESS_ADAPTER_FIXTURE_NO_MAIN
#include "../../local-private-payment/mpc-prover/financial/controls/fresh_owner_process_adapter_test.cpp"

#include "v3_native_authority.hpp"

#include <filesystem>
#include <string>
#include <type_traits>

using namespace kpb::future_recipient::v3_native;

namespace {

template<class Function>
void native_refuses(Function&& function) {
    bool refused = false;
    try { function(); }
    catch (const NativeRefused&) { refused = true; }
    assert(refused);
}

Digest native_key() { return id(0x7e01); }

V3AcceptedRound1HistoryResidualAuthority genuine_v3_history(
        const kpb::measurement::RunBinding& selected) {
    auto selected_plan = hidden_plan();
    selected_plan.measurement_run_binding_identity =
        recompute_v3_run_binding_identity(selected);
    Roots roots;
    auto supervisor = FreshOwnerProcessSupervisor::launch_exact_three(
        CompiledPrivateLifecycleOwnerProgramAuthority::test_only_mint(
            selected_plan,
            std::make_shared<CandidatePrivateLifecycleProgram>()),
        root_authorities(roots));
    auto round1 = supervisor.issue_round1(
        accepted_input_history(),
        replay_guard(std::make_shared<MemoryReplayRegistry>()),
        arm_residual(supervisor, CaptureClassification::HiddenCandidate));
    consume_round1_bootstrap(round1);
    auto round2 = supervisor.issue_round2(
        std::move(round1), accepted_history());
    consume_round2_bootstrap(round2);
    return round2.take_v3_history_residual();
}

std::pair<ParentLedgerDescriptorsAuthority,
          ExternalLatestHeadUpdaterAuthority>
fresh_store(const std::filesystem::path& root, const std::string& stem,
            const kpb::measurement::RunBinding& selected) {
    const auto ledger = root / (stem + "-ledger");
    const auto external = root / (stem + "-external");
    assert(::mkdir(ledger.c_str(), 0700) == 0);
    assert(::mkdir(external.c_str(), 0700) == 0);
    return V3NativeAuthorityTestSetup::initialize_fresh_with_external_head(
        ledger.c_str(), external.c_str(), selected, native_key());
}

void genuine_join_and_replay_controls(const std::filesystem::path& root) {
    const auto selected = candidate_measurement_binding();
    auto history = genuine_v3_history(selected);
    auto store = fresh_store(root, "positive", selected);
    auto controller = V3LifecycleControllerMinter::mint(
        selected, std::move(history), std::move(store.second));
    auto parent = V3NativeAuthorityBridge::open_existing(
        std::move(store.first), std::move(controller), selected);
    assert(parent->test_only_latest().first == 0);

    auto replay_store = fresh_store(root, "history-replay", selected);
    native_refuses([&] {
        (void)V3LifecycleControllerMinter::mint(
            selected, std::move(history),
            std::move(replay_store.second));
    });

    auto controller_replay_store = fresh_store(
        root, "controller-replay", selected);
    native_refuses([&] {
        (void)V3NativeAuthorityBridge::open_existing(
            std::move(controller_replay_store.first),
            std::move(controller), selected);
    });
}

void cross_trial_and_wrong_head_refuse(const std::filesystem::path& root) {
    const auto selected = candidate_measurement_binding();
    auto wrong_trial = selected;
    wrong_trial.trial = id(0x7e10);
    kpb::measurement::validate_measurement_run_binding(wrong_trial);
    auto cross_trial_history = genuine_v3_history(selected);
    auto cross_trial_store = fresh_store(root, "cross-trial", wrong_trial);
    native_refuses([&] {
        (void)V3LifecycleControllerMinter::mint(
            wrong_trial, std::move(cross_trial_history),
            std::move(cross_trial_store.second));
    });

    auto corrupted =
        V3AcceptedRound1HistoryResidualAuthority::
            test_only_corrupt_successor_head(genuine_v3_history(selected));
    auto wrong_head_store = fresh_store(root, "wrong-head", selected);
    native_refuses([&] {
        (void)V3LifecycleControllerMinter::mint(
            selected, std::move(corrupted),
            std::move(wrong_head_store.second));
    });
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::filesystem::path root(argv[1]);
    assert(root.is_absolute());
    static_assert(!std::copy_constructible<
                  V3AcceptedRound1HistoryResidualAuthority>);
    static_assert(!std::copy_constructible<V3LifecycleControllerAuthority>);
    static_assert(kV3NativeAuthoritySourceStatus.
                  typed_lifecycle_controller_source_seam);
    static_assert(kV3NativeAuthoritySourceStatus.
                  production_open_requires_lifecycle_controller);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_ledger_descriptor_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_external_updater_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_invoice_material_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  production_accepted_history_minter_available);
    static_assert(!kV3NativeAuthoritySourceStatus.
                  lifecycle_controller_minter_integrated);
    static_assert(!kV3NativeAuthoritySourceStatus.configured);
    genuine_join_and_replay_controls(root);
    cross_trial_and_wrong_head_refuse(root);
    return 0;
}
