#include "native_terminal_completion_test_fixture.hpp"
#include "testnet_activation_authority.hpp"

#include <atomic>
#include <cassert>
#include <thread>
#include <utility>

using namespace kpb::measurement;
using namespace kpb::native_terminal::test_fixture;
using namespace kpb::testnet_activation;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

template<class T>
concept PrePermitRpc = requires(T& value) {
    value.authorize_first_rpc();
};

Digest id(unsigned value) {
    Digest result{};
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            ((value >> ((index % 4U) * 8U)) & 0xffU) ^
            ((0x5bU + index * 29U) & 0xffU));
    return result;
}

WorkerBinding worker(const ManifestEntry& entry) {
    return {.source_identity = entry.source_identity,
            .build_identity = entry.build_identity,
            .runtime_identity = entry.runtime_identity,
            .assets_identity = entry.assets_identity,
            .pinned_executable_identity = entry.pinned_executable_identity,
            .launcher_identity = entry.launcher_identity};
}

struct PrivacyFixture {
    RunBinding candidate;
    RunBinding baseline;
    PublicComparisonSelection selection;

    explicit PrivacyFixture(const RunBinding& selected)
        : candidate(selected), baseline(selected) {
        baseline.classification = Classification::TransparentBaseline;
        baseline.run_selection = id(0xc01);
        baseline.trial = id(0xc02);
        baseline.attempt = id(0xc03);
        baseline.cohort = id(0xc04);
        baseline.capture = id(0xc05);
        baseline.financial_runs = {id(0xc06), id(0xc07)};
        baseline.round_attempts = {id(0xc08), id(0xc09)};
        baseline.round_cohorts = {id(0xc0a), id(0xc0b)};
        baseline.projections = {id(0xc0c), id(0xc0d)};
        baseline.round_capture_plans = {id(0xc0e), id(0xc0f)};
        selection = {
            .comparison_selection = candidate.comparison_selection,
            .selection_identity = id(0xc10),
            .method = candidate.method,
            .workload = candidate.workload,
            .source_closure = candidate.source_closure,
            .runtime = candidate.runtime,
            .finite_manifest = candidate.finite_manifest,
            .comparison_worker = worker(
                candidate.finite_manifest.entries.at(9)),
            .outer_parent_process = candidate.outer_parent_process,
            .outer_parent_executable = candidate.outer_parent_executable,
            .manifest_recomputation_receipt =
                candidate.finite_manifest.parent_recomputation_identity,
            .baseline_run = baseline.run_selection,
            .candidate_run = candidate.run_selection,
        };
    }

    BatchPrivacyPassAuthority privacy_pass() const {
        auto baseline_authority =
            RunAggregateCompletionAuthority::test_only_mint(
                PublicRunAggregateCompletion{
                    .binding = baseline,
                    .outer_parent_process = baseline.outer_parent_process,
                    .outer_parent_executable =
                        baseline.outer_parent_executable,
                    .manifest_recomputation_receipt = baseline.finite_manifest
                        .parent_recomputation_identity,
                    .outcome = AggregateOutcome::BaselineControlDetected,
                    .completion_identity = id(0xc20)});
        auto candidate_authority =
            RunAggregateCompletionAuthority::test_only_mint(
                PublicRunAggregateCompletion{
                    .binding = candidate,
                    .outer_parent_process = candidate.outer_parent_process,
                    .outer_parent_executable =
                        candidate.outer_parent_executable,
                    .manifest_recomputation_receipt = candidate.finite_manifest
                        .parent_recomputation_identity,
                    .outcome = AggregateOutcome::CandidatePass,
                    .completion_identity = id(0xc21)});
        auto selected = ComparisonSelectionAuthority::test_only_mint(
            selection);
        ComparisonMeasurement comparison(
            std::move(selected), std::move(baseline_authority),
            std::move(candidate_authority));
        auto permit = comparison.issue_owner_comparison();
        const auto public_permit = permit.public_receipt();
        auto completion = OwnerComparisonCompletionAuthority::test_only_mint(
            PublicOwnerComparisonCompletion{
                .comparison_selection = selection.comparison_selection,
                .permit_identity = public_permit.permit_identity,
                .baseline_aggregate = public_permit.baseline_aggregate,
                .candidate_aggregate = public_permit.candidate_aggregate,
                .child_exit = id(0xc22),
                .comparison_receipt = id(0xc23),
                .outcome = OwnerComparisonOutcome::NonRegressionPass,
                .worker = selection.comparison_worker,
                .process_identity = id(0xc24)});
        return comparison.accept_owner_comparison(
            std::move(permit), std::move(completion));
    }
};

enum class Mutation {
    None, WrongNetwork, WrongTrial, WrongProfile, WrongTail,
    StaleDriverHead, ReusedDriverRole,
};

struct Ready {
    PreNetworkSafetyJoin joined;
};

Ready ready(Mutation mutation = Mutation::None) {
    auto native = complete_genuine_candidate_authorities();
    const PrivacyFixture privacy_fixture(native.binding);
    auto privacy = privacy_fixture.privacy_pass();
    auto public_privacy = privacy.public_receipt();
    const auto& genesis = native.genesis.public_receipt();
    const auto& round1 = native.payments[0].public_receipt();
    const auto& round2 = native.payments[1].public_receipt();
    PublicGlobalPaymentCaptureCompletion capture{
        .network = genesis.network,
        .trial = genesis.trial,
        .funding_identity = genesis.funding_identity,
        .component_profile = genesis.component_profile,
        .immutable_tail = genesis.immutable_tail,
        .comparison_selection = public_privacy.comparison_selection,
        .selection_identity = public_privacy.selection.selection_identity,
        .candidate_run = public_privacy.selection.candidate_run,
        .projections = public_privacy.candidate_projections,
        .finite_manifest = public_privacy.selection.finite_manifest,
        .outer_parent_process = public_privacy.outer_parent_process,
        .outer_parent_executable = public_privacy.outer_parent_executable,
        .manifest_recomputation_receipt =
            public_privacy.manifest_recomputation_receipt,
        .registered_driver_completions = {id(0xc30), id(0xc31)},
        .registered_driver_heads = {round1.input_head, round2.input_head},
        .completion_identity = id(0xc32),
    };
    if (mutation == Mutation::WrongNetwork)
        capture.network = static_cast<NetworkScope>(0);
    if (mutation == Mutation::WrongTrial) capture.trial = id(0xc40);
    if (mutation == Mutation::WrongProfile)
        capture.component_profile = id(0xc41);
    if (mutation == Mutation::WrongTail)
        capture.immutable_tail = id(0xc42);
    if (mutation == Mutation::StaleDriverHead)
        capture.registered_driver_heads[1] = id(0xc43);
    if (mutation == Mutation::ReusedDriverRole)
        capture.registered_driver_completions[1] =
            capture.registered_driver_completions[0];
    auto capture_authority =
        GlobalPaymentCaptureCompletionAuthority::test_only_mint(capture);
    std::array<NativeCandidateCompletionAuthority, 3> candidates{
        std::move(native.genesis), std::move(native.payments[0]),
        std::move(native.payments[1])};
    auto joined = PreNetworkSafetyFactory::join(
        std::move(privacy), std::move(capture_authority),
        std::move(candidates));
    (void)native.producer_continuation;
    return {.joined = std::move(joined)};
}

void exact_conjunction_and_first_rpc_boundary() {
    static_assert(!PrePermitRpc<SelectedParentNetworkBoundary>);
    auto selected = ready();
    auto permit = ActivationJoiner::conjoin(std::move(selected.joined));
    const auto binding = permit.public_receipt().binding;
    auto parent = SelectedParentAuthority::test_only_mint(
        PublicSelectedParent{
            .network = NetworkScope::KaspaTestnet10,
            .binding = binding,
            .selected_rpc_identity = id(0xc50),
            .parent_identity = id(0xc51)});
    auto boundary = SelectedParentNetworkBoundary::open(std::move(parent));
    auto first_rpc = boundary.authorize_first_rpc(std::move(permit));
    assert(first_rpc.public_receipt().binding == binding);
    assert(!first_rpc.public_receipt().network_invoked);
    expect_refused([&] {
        (void)boundary.authorize_first_rpc(std::move(permit));
    });
}

void replay_and_concurrent_double_conjunction_refuse() {
    {
        auto selected = ready();
        auto permit = ActivationJoiner::conjoin(
            std::move(selected.joined));
        (void)permit;
        expect_refused([&] {
            (void)ActivationJoiner::conjoin(std::move(selected.joined));
        });
    }
    {
        auto selected = ready();
        std::atomic_uint accepted{};
        std::atomic_uint refused{};
        auto race = [&] {
            try {
                auto permit = ActivationJoiner::conjoin(
                    std::move(selected.joined));
                (void)permit;
                ++accepted;
            } catch (const Refused&) { ++refused; }
        };
        std::thread first(race);
        std::thread second(race);
        first.join(); second.join();
        assert(accepted == 1 && refused == 1);
    }
}

void wrong_native_global_bindings_refuse() {
    for (const auto mutation : {
             Mutation::WrongNetwork, Mutation::WrongTrial,
             Mutation::WrongProfile, Mutation::WrongTail,
             Mutation::StaleDriverHead, Mutation::ReusedDriverRole})
        expect_refused([&] { (void)ready(mutation); });
}

void wrong_selected_parent_binding_refuses_without_rpc() {
    auto selected = ready();
    auto permit = ActivationJoiner::conjoin(std::move(selected.joined));
    auto wrong = permit.public_receipt().binding;
    wrong.component_profile = id(0xc60);
    auto parent = SelectedParentAuthority::test_only_mint(
        PublicSelectedParent{
            .network = NetworkScope::KaspaTestnet10,
            .binding = wrong,
            .selected_rpc_identity = id(0xc61),
            .parent_identity = id(0xc62)});
    auto boundary = SelectedParentNetworkBoundary::open(std::move(parent));
    expect_refused([&] {
        (void)boundary.authorize_first_rpc(std::move(permit));
    });
}

} // namespace

int main() {
    if (const auto child = run_selected_child()) return *child;
    exact_conjunction_and_first_rpc_boundary();
    replay_and_concurrent_double_conjunction_refuse();
    wrong_native_global_bindings_refuse();
    wrong_selected_parent_binding_refuses_without_rpc();
    return 0;
}
