#include "privacy_owner_score_output_split_authority.hpp"

#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_measurement_runtime_bridge.hpp"
#include "privacy_measurement_sha256.hpp"

#include <algorithm>
#include <cassert>
#include <concepts>
#include <new>
#include <sys/types.h>
#include <unistd.h>

using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;
using namespace kpb::measurement::score_output_split;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

WorkerBinding worker(const ManifestEntry& value) {
    return {
        .source_identity = value.source_identity,
        .build_identity = value.build_identity,
        .runtime_identity = value.runtime_identity,
        .assets_identity = value.assets_identity,
        .pinned_executable_identity = value.pinned_executable_identity,
        .launcher_identity = value.launcher_identity,
    };
}

FiniteManifestBinding manifest() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0x20 + 6 * index);
        entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(seed + 1),
            .runtime_identity = digest(seed + 2),
            .assets_identity = digest(seed + 3),
            .pinned_executable_identity = digest(seed + 4),
            .launcher_identity = digest(seed + 5),
        };
    }
    return {
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest(0x90),
        .entries = entries,
    };
}

RunBinding binding() {
    const auto selected = manifest();
    const auto& capture = selected.entries.at(1);
    return {
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest(0xa0),
        .run_selection = digest(0xa1),
        .trial = digest(0xa2),
        .attempt = digest(0xa3),
        .cohort = digest(0xa4),
        .capture = digest(0xa5),
        .method = digest(0xa6),
        .workload = digest(0xa7),
        .source_closure = digest(0xa8),
        .runtime = digest(0xa9),
        .finite_manifest = selected,
        .outer_parent_process = digest(0xaa),
        .outer_parent_executable = digest(0xab),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(selected.entries.at(6)),
        .score_worker = worker(selected.entries.at(7)),
        .aggregate_worker = worker(selected.entries.at(8)),
        .financial_runs = {digest(0xb0), digest(0xb1)},
        .round_attempts = {digest(0xb2), digest(0xb3)},
        .round_cohorts = {digest(0xb4), digest(0xb5)},
        .round_capture_plans = {digest(0xb6), digest(0xb7)},
        .projections = {digest(0xb8), digest(0xb9)},
    };
}

PublicOwnerScorePermit score_permit(
        unsigned owner, const RunBinding& run) {
    return {
        .binding = run,
        .owner = owner,
        .trial_capture_identity = digest(0xc0),
        .observation_receipt = digest(0xc1),
        .barrier = digest(0xc2),
        .permit_identity = digest(static_cast<unsigned char>(0xc3 + owner)),
    };
}

OwnerScoreExecutionPermitAuthority execution_permit(
        const PublicOwnerScorePermit& receipt) {
    auto permit = OwnerScorePermitAuthority::test_only_mint(receipt);
    auto split = std::move(permit).split_for_truth_release();
    auto truth = split.take_truth_release_permit();
    (void)truth;
    return split.take_execution_permit();
}

PublicRuntimeChildCompletion child(
        const PublicOwnerScorePermit& permit) {
    PublicRuntimeChildCompletion value{
        .role = RuntimeChildRole::OwnerScore,
        .owner = permit.owner,
        .permit_identity = permit.permit_identity,
        .worker = permit.binding.score_worker,
        .outer_parent_process = permit.binding.outer_parent_process,
        .outer_parent_executable = permit.binding.outer_parent_executable,
        .transport_session = digest(
            static_cast<unsigned char>(0xd0 + permit.owner)),
        .offer_identity = digest(
            static_cast<unsigned char>(0xd3 + permit.owner)),
        .child_exit_identity = digest(
            static_cast<unsigned char>(0xd6 + permit.owner)),
        .opaque_completion_authority_identity = digest(
            static_cast<unsigned char>(0xd9 + permit.owner)),
        .opaque_capsule_authority_identity = digest(
            static_cast<unsigned char>(0xdc + permit.owner)),
        .authenticated_pid = 4100 + permit.owner,
        .waited_pid = 4100 + permit.owner,
        .exit_code = 0,
        .term_signal = 0,
        .credentials_verified = true,
        .offer_acknowledged = true,
        .eof_observed = true,
    };
    value.process_identity = recompute_process_identity(value);
    return value;
}

std::array<OwnerScoreOutputBindingExpectation, 3> output_lineage(
        const RunBinding& run) {
    std::array<OwnerScoreOutputBindingExpectation, 3> result{};
    for (unsigned owner = 0; owner < result.size(); ++owner) {
        auto& value = result[owner];
        value.method_sha256 = run.method;
        value.selection_sha256 = digest(0x71);
        value.trial_id.fill(0x72);
        value.attempt_length = 9;
        constexpr std::array<unsigned char, 9> attempt{
            'a', 't', 't', 'e', 'm', 'p', 't', '-', '1'};
        std::copy(attempt.begin(), attempt.end(), value.attempt_id.begin());
        value.run_selection_sha256 = run.run_selection;
        value.owner = owner;
    }
    return result;
}

OwnerScoreOutputLineageAuthority lineage(
        const RunBinding& run,
        const std::array<OwnerScoreOutputBindingExpectation, 3>& expected) {
    return OwnerScoreOutputLineageAuthority::test_only_mint(
        run, expected, digest(0x73));
}

SealedChildOutputAuthority sealed_output(
        const PublicOwnerScorePermit& permit,
        const PublicRuntimeChildCompletion& selected_child,
        const OwnerScoreOutputBindingExpectation& body_lineage) {
    const auto* abi = measurement_output_abi(RuntimeChildRole::OwnerScore);
    assert(abi != nullptr);
    PrivateChildOutputOffer offer{
        .binding = permit.binding,
        .role = RuntimeChildRole::OwnerScore,
        .owner = permit.owner,
        .permit_identity = permit.permit_identity,
        .worker = permit.binding.score_worker,
        .transport_session = selected_child.transport_session,
        .output_authority_identity = digest(
            static_cast<unsigned char>(0xe0 + permit.owner)),
        .output_abi_identity = abi->identity,
        .exact_size = abi->exact_bytes,
    };
    auto pending = MeasurementChildOutputPlane::test_only_begin(offer);
    const int fd = pending.test_only_take_child_fd();
    const auto body = test_only_owner_score_output_abi_body(body_lineage);
    assert(::pwrite(fd, body.data(), body.size(), 0) ==
           static_cast<ssize_t>(body.size()));
    assert(::close(fd) == 0);
    auto completion =
        AuthenticatedChildOutputCompletionAuthority::test_only_mint({
            .offer = offer,
            .content_hash = detail::sha256(body),
            .process_identity = selected_child.process_identity,
            .child_exit_identity = selected_child.child_exit_identity,
            .authenticated_pid = selected_child.authenticated_pid,
            .waited_pid = selected_child.waited_pid,
            .exit_code = 0,
            .term_signal = 0,
            .credentials_verified = true,
            .eof_observed = true,
        });
    return MeasurementChildOutputPlane::finish(
        std::move(pending), std::move(completion));
}

OwnerScoreRuntimeCompletion runtime(
        unsigned owner, const RunBinding& run,
        const OwnerScoreOutputBindingExpectation& body_lineage) {
    const auto permit_receipt = score_permit(owner, run);
    auto selected_child = child(permit_receipt);
    auto permit = execution_permit(permit_receipt);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        selected_child);
    auto output = sealed_output(
        permit_receipt, selected_child, body_lineage);
    return RuntimeCompletionBridge::owner_score(
        std::move(permit), std::move(evidence), std::move(output));
}

OwnerScoreRuntimeCompletion runtime_from_permit(
        OwnerScorePermitAuthority&& selected_permit,
        const OwnerScoreOutputBindingExpectation& body_lineage) {
    const auto permit_receipt = selected_permit.public_receipt();
    auto selected_child = child(permit_receipt);
    auto split = std::move(selected_permit).split_for_truth_release();
    auto truth = split.take_truth_release_permit();
    (void)truth;
    auto permit = split.take_execution_permit();
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        selected_child);
    auto output = sealed_output(
        permit_receipt, selected_child, body_lineage);
    return RuntimeCompletionBridge::owner_score(
        std::move(permit), std::move(evidence), std::move(output));
}

template<class T>
concept HasReceipt = requires(const T& value) { value.public_receipt(); };
template<class T>
concept HasFd = requires(T& value) { value.fd(); };
template<class T>
concept HasHash = requires(const T& value) { value.content_hash(); };
template<class T>
concept HasBarrier = requires(const T& value) { value.barrier(); };
template<class T>
concept HasAggregateTake = requires(T& value) { value.take_aggregate(); };
template<class T>
concept HasComparisonTake = requires(T& value) { value.take_comparison(); };
template<class T>
concept HasOwnerScoreSplitReadFd = requires(const T& value) {
    value.owner_score_split_read_fd();
};

void assert_stop(
        const OwnerScoreOutputSplitOutcomeAuthority::TestOnlySummary& summary,
        unsigned retained = 3) {
    assert(!summary.success);
    assert(summary.stop_reason != OwnerScoreOutputSplitStopReason::None);
    assert(summary.lineage_retained);
    assert(std::count(summary.retained_outputs.begin(),
                      summary.retained_outputs.end(), true) ==
           static_cast<std::ptrdiff_t>(retained));
    assert(std::count(summary.permit_claimed.begin(),
                      summary.permit_claimed.end(), true) ==
           static_cast<std::ptrdiff_t>(retained));
    assert(std::count(summary.completion_claimed.begin(),
                      summary.completion_claimed.end(), true) ==
           static_cast<std::ptrdiff_t>(retained));
    assert(!summary.bundle.has_value());
}

void valid_all_three_is_indivisible_and_exact() {
    static_assert(!std::default_initializable<
                  OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!std::copy_constructible<
                  OwnerScoreOutputSplitBundleAuthority>);
    static_assert(std::move_constructible<
                  OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!HasReceipt<OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!HasFd<OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!HasHash<OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!HasBarrier<OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!HasAggregateTake<OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!HasComparisonTake<OwnerScoreOutputSplitBundleAuthority>);
    static_assert(!HasOwnerScoreSplitReadFd<SealedChildOutputAuthority>);
    static_assert(!std::default_initializable<
                  OwnerScoreOutputLineageAuthority>);
    static_assert(!std::copy_constructible<
                  OwnerScoreOutputLineageAuthority>);
    static_assert(!HasReceipt<OwnerScoreOutputLineageAuthority>);
    static_assert(!HasFd<OwnerScoreOutputLineageAuthority>);
    static_assert(!HasHash<OwnerScoreOutputLineageAuthority>);
    static_assert(!std::default_initializable<
                  OwnerScoreOutputSplitOutcomeAuthority>);
    static_assert(!std::copy_constructible<
                  OwnerScoreOutputSplitOutcomeAuthority>);
    static_assert(!HasReceipt<OwnerScoreOutputSplitOutcomeAuthority>);
    static_assert(!HasFd<OwnerScoreOutputSplitOutcomeAuthority>);
    static_assert(!HasHash<OwnerScoreOutputSplitOutcomeAuthority>);

    const auto run = binding();
    const auto expected = output_lineage(run);
    auto source_lineage = lineage(run, expected);
    auto owner0 = runtime(0, run, expected[0]);
    auto owner1 = runtime(1, run, expected[1]);
    auto owner2 = runtime(2, run, expected[2]);
    auto original = OwnerScoreOutputSplitBridge::split(
        std::move(source_lineage), std::move(owner0), std::move(owner1),
        std::move(owner2));
    auto outcome = std::move(original);
    expect_refused([&] { (void)original.test_only_summary(); });
    const auto outcome_summary = outcome.test_only_summary();
    assert(outcome_summary.success);
    assert(!outcome_summary.lineage_retained);
    assert(outcome_summary.bundle.has_value());
    const auto& summary = *outcome_summary.bundle;
    assert(summary.lineage_retained);
    assert(summary.binding == binding());
    assert(summary.barrier == digest(0xc2));
    for (unsigned owner = 0; owner < 3; ++owner) {
        assert(summary.completions[owner].owner == owner);
        assert(summary.retained_outputs[owner]);
        assert(summary.output_devices[owner] != 0 &&
               summary.output_inodes[owner] != 0);
        assert(summary.aggregate[owner].kind ==
               MeasurementInputKind::AggregateOwnerScore);
        assert(summary.aggregate[owner].owner == owner);
        assert(summary.aggregate[owner].fixed_fd ==
               MEASUREMENT_AGGREGATE_OWNER0_FD +
                   static_cast<int>(owner));
        assert(summary.comparison[owner].kind ==
               MeasurementInputKind::ComparisonCandidateOwnerScore);
        assert(summary.comparison[owner].owner == owner);
        assert(summary.comparison[owner].fixed_fd ==
               MEASUREMENT_COMPARISON_CANDIDATE0_FD +
                   static_cast<int>(owner));
        assert(summary.aggregate[owner].lineage.barrier == summary.barrier);
        assert(summary.comparison[owner].lineage ==
               summary.aggregate[owner].lineage);
        assert(summary.aggregate_devices[owner] ==
               summary.output_devices[owner]);
        assert(summary.aggregate_inodes[owner] ==
               summary.output_inodes[owner]);
        assert(summary.comparison_devices[owner] ==
               summary.output_devices[owner]);
        assert(summary.comparison_inodes[owner] ==
               summary.output_inodes[owner]);
        assert(summary.aggregate_read_only[owner]);
        assert(summary.comparison_read_only[owner]);
        assert(summary.aggregate[owner].identity !=
               summary.comparison[owner].identity);
    }
    assert(summary.output_inodes[0] != summary.output_inodes[1] &&
           summary.output_inodes[0] != summary.output_inodes[2] &&
           summary.output_inodes[1] != summary.output_inodes[2]);

    auto replay_lineage = lineage(run, expected);
    auto replay = OwnerScoreOutputSplitBridge::split(
        std::move(replay_lineage), std::move(owner0),
        std::move(owner1), std::move(owner2));
    assert_stop(replay.test_only_summary(), 0);
}

void mixed_binding_duplicate_owner_and_swapped_order_burn_all() {
    {
        auto changed = binding(); changed.run_selection = digest(0xf0);
        const auto selected = binding();
        auto expected = output_lineage(selected);
        auto owner0 = runtime(0, selected, expected[0]);
        auto changed_expected = output_lineage(changed);
        auto owner1 = runtime(1, changed, changed_expected[1]);
        auto owner2 = runtime(2, selected, expected[2]);
        auto source_lineage = lineage(selected, expected);
        auto stopped = OwnerScoreOutputSplitBridge::split(
            std::move(source_lineage), std::move(owner0),
            std::move(owner1), std::move(owner2));
        assert_stop(stopped.test_only_summary());
    }
    {
        const auto run = binding(); const auto expected = output_lineage(run);
        auto source_lineage = lineage(run, expected);
        auto owner0a = runtime(0, run, expected[0]);
        auto owner0b = runtime(0, run, expected[0]);
        auto owner2 = runtime(2, run, expected[2]);
        auto stopped = OwnerScoreOutputSplitBridge::split(
            std::move(source_lineage), std::move(owner0a),
            std::move(owner0b), std::move(owner2));
        assert_stop(stopped.test_only_summary());
    }
    {
        const auto run = binding(); const auto expected = output_lineage(run);
        auto source_lineage = lineage(run, expected);
        auto owner1 = runtime(1, run, expected[1]);
        auto owner0 = runtime(0, run, expected[0]);
        auto owner2 = runtime(2, run, expected[2]);
        auto stopped = OwnerScoreOutputSplitBridge::split(
            std::move(source_lineage), std::move(owner1),
            std::move(owner0), std::move(owner2));
        assert_stop(stopped.test_only_summary());
    }
}

void stale_first_burns_fresh_siblings_before_validation() {
    const auto run = binding(); const auto expected = output_lineage(run);
    auto first_lineage = lineage(run, expected);
    auto stale0 = runtime(0, run, expected[0]);
    auto used1 = runtime(1, run, expected[1]);
    auto used2 = runtime(2, run, expected[2]);
    auto consumed = OwnerScoreOutputSplitBridge::split(
        std::move(first_lineage), std::move(stale0),
        std::move(used1), std::move(used2));
    assert(consumed.test_only_summary().success);

    auto second_lineage = lineage(run, expected);
    auto fresh1 = runtime(1, run, expected[1]);
    auto fresh2 = runtime(2, run, expected[2]);
    auto stopped = OwnerScoreOutputSplitBridge::split(
        std::move(second_lineage), std::move(stale0),
        std::move(fresh1), std::move(fresh2));
    assert_stop(stopped.test_only_summary(), 2);
}

void body_and_reopen_substitutions_refuse() {
    for (const auto fault : {
             TestOnlyOwnerScoreSplitFault::BodyMutation,
             TestOnlyOwnerScoreSplitFault::WritableReopen,
             TestOnlyOwnerScoreSplitFault::CrossOwnerReopen,
             TestOnlyOwnerScoreSplitFault::PostClaimAllocation}) {
        const auto run = binding(); const auto expected = output_lineage(run);
        auto source_lineage = lineage(run, expected);
        auto owner0 = runtime(0, run, expected[0]);
        auto owner1 = runtime(1, run, expected[1]);
        auto owner2 = runtime(2, run, expected[2]);
        auto stopped = OwnerScoreOutputSplitBridge::test_only_split(
            std::move(source_lineage), std::move(owner0),
            std::move(owner1), std::move(owner2), fault);
        assert_stop(stopped.test_only_summary());
    }
}

void exact_compact_lineage_substitutions_stop() {
    for (unsigned field = 0; field < 6; ++field) {
        const auto run = binding(); const auto expected = output_lineage(run);
        auto body = expected;
        switch (field) {
        case 0: body[1].method_sha256[0] ^= 1; break;
        case 1: body[1].selection_sha256[0] ^= 1; break;
        case 2: body[1].trial_id[0] ^= 1; break;
        case 3: body[1].attempt_id[0] = 'b'; break;
        case 4: body[1].run_selection_sha256[0] ^= 1; break;
        case 5: body[1].owner = 2; break;
        default: assert(false);
        }
        auto source_lineage = lineage(run, expected);
        auto owner0 = runtime(0, run, body[0]);
        auto owner1 = runtime(1, run, body[1]);
        auto owner2 = runtime(2, run, body[2]);
        auto stopped = OwnerScoreOutputSplitBridge::split(
            std::move(source_lineage), std::move(owner0),
            std::move(owner1), std::move(owner2));
        assert_stop(stopped.test_only_summary());
    }
}

void typed_lineage_cannot_lie_about_live_run_fields() {
    for (unsigned field = 0; field < 2; ++field) {
        const auto run = binding(); auto expected = output_lineage(run);
        for (auto& row : expected) {
            if (field == 0) row.method_sha256 = digest(0x74);
            else row.run_selection_sha256 = digest(0x75);
        }
        auto source_lineage = lineage(run, expected);
        auto owner0 = runtime(0, run, expected[0]);
        auto owner1 = runtime(1, run, expected[1]);
        auto owner2 = runtime(2, run, expected[2]);
        auto stopped = OwnerScoreOutputSplitBridge::split(
            std::move(source_lineage), std::move(owner0),
            std::move(owner1), std::move(owner2));
        assert_stop(stopped.test_only_summary());
    }

    for (unsigned field = 0; field < 3; ++field) {
        const auto run = binding(); auto expected = output_lineage(run);
        if (field == 0) expected[1].selection_sha256 = digest(0x76);
        else if (field == 1) expected[1].trial_id[0] ^= 1;
        else expected[1].attempt_id[0] = 'b';
        auto source_lineage = lineage(run, expected);
        auto owner0 = runtime(0, run, expected[0]);
        auto owner1 = runtime(1, run, expected[1]);
        auto owner2 = runtime(2, run, expected[2]);
        auto stopped = OwnerScoreOutputSplitBridge::split(
            std::move(source_lineage), std::move(owner0),
            std::move(owner1), std::move(owner2));
        assert_stop(stopped.test_only_summary());
    }
}

void preclaim_allocation_leaves_every_input_reusable() {
    const auto run = binding(); const auto expected = output_lineage(run);
    auto source_lineage = lineage(run, expected);
    auto owner0 = runtime(0, run, expected[0]);
    auto owner1 = runtime(1, run, expected[1]);
    auto owner2 = runtime(2, run, expected[2]);
    bool allocated = false;
    try {
        (void)OwnerScoreOutputSplitBridge::test_only_split(
            std::move(source_lineage), std::move(owner0),
            std::move(owner1), std::move(owner2),
            TestOnlyOwnerScoreSplitFault::BeforeClaimAllocation);
    } catch (const std::bad_alloc&) { allocated = true; }
    assert(allocated);
    auto outcome = OwnerScoreOutputSplitBridge::split(
        std::move(source_lineage), std::move(owner0),
        std::move(owner1), std::move(owner2));
    assert(outcome.test_only_summary().success);
}

TrialCaptureCompletionAuthority capture(const RunBinding& run) {
    return TrialCaptureCompletionAuthority::test_only_mint({
        .binding = run,
        .projections = run.projections,
        .producer_worker = worker(run.finite_manifest.entries.at(5)),
        .manifest_parent_process_identity = run.outer_parent_process,
        .manifest_parent_executable_identity = run.outer_parent_executable,
        .manifest_recomputation_receipt =
            run.finite_manifest.parent_recomputation_identity,
        .completion_identity = digest(0xc0),
    });
}

std::unique_ptr<RunMeasurement> score_ready_measurement(
        const RunBinding& run) {
    auto result = std::make_unique<RunMeasurement>(capture(run));
    auto permit = result->issue_observer();
    const auto public_permit = permit.public_receipt();
    auto completion = ObservationCompletionAuthority::test_only_mint({
        .binding = run,
        .permit_identity = public_permit.permit_identity,
        .trial_capture_identity = public_permit.trial_capture_identity,
        .child_exit = digest(0x62),
        .observation_receipt = digest(0xc1),
        .worker = run.observer_worker,
        .process_identity = digest(0x63),
    });
    auto execution = std::move(permit).test_only_take_execution();
    result->accept_observer(std::move(execution), std::move(completion));
    result->freeze_barrier(BarrierFreezeAuthority::test_only_mint({
        .binding = run,
        .trial_capture_identity = public_permit.trial_capture_identity,
        .observation_receipt = digest(0xc1),
        .barrier_receipt = digest(0xc2),
        .outer_parent_process = run.outer_parent_process,
        .outer_parent_executable = run.outer_parent_executable,
        .manifest_recomputation_receipt =
            run.finite_manifest.parent_recomputation_identity,
    }));
    auto release = result->issue_candidate_truth_barrier_release();
    (void)release;
    return result;
}

OwnerScoreOutputSplitOutcomeAuthority outcome_for_measurement(
        RunMeasurement& measurement, const RunBinding& run,
        TestOnlyOwnerScoreSplitFault fault =
            TestOnlyOwnerScoreSplitFault::None,
        unsigned permit_count = 3) {
    const auto expected = output_lineage(run);
    std::array<std::optional<OwnerScoreRuntimeCompletion>, 3> runtimes;
    for (unsigned owner = 0; owner < permit_count; ++owner)
        runtimes[owner].emplace(runtime_from_permit(
            measurement.issue_score(owner), expected[owner]));
    for (unsigned owner = permit_count; owner < 3; ++owner)
        runtimes[owner].emplace(runtime(owner, run, expected[owner]));
    auto selected_lineage = lineage(run, expected);
    return OwnerScoreOutputSplitBridge::test_only_split(
        std::move(selected_lineage), std::move(*runtimes[0]),
        std::move(*runtimes[1]), std::move(*runtimes[2]), fault);
}

void run_measurement_retains_success_or_stop_indivisibly() {
    const auto run = binding();
    {
        auto measurement = score_ready_measurement(run);
        auto outcome = outcome_for_measurement(*measurement, run);
        assert(outcome.test_only_summary().success);
        measurement->accept_owner_score_split(std::move(outcome));
        assert(measurement->test_only_has_owner_score_split());
        expect_refused([&] {
            measurement->accept_owner_score_split(std::move(outcome));
        });
    }
    {
        auto measurement = score_ready_measurement(run);
        auto stopped = outcome_for_measurement(
            *measurement, run,
            TestOnlyOwnerScoreSplitFault::PostClaimAllocation);
        assert(!stopped.test_only_summary().success);
        measurement->accept_owner_score_split(std::move(stopped));
        assert(measurement->test_only_has_owner_score_split());
    }
}

void run_measurement_early_missing_and_moved_inputs_refuse() {
    const auto run = binding();
    {
        RunMeasurement early(capture(run));
        auto producer = score_ready_measurement(run);
        auto outcome = outcome_for_measurement(*producer, run);
        expect_refused([&] {
            early.accept_owner_score_split(std::move(outcome));
        });
        assert(outcome.test_only_summary().success);
    }
    {
        auto missing = score_ready_measurement(run);
        auto outcome = outcome_for_measurement(*missing, run,
            TestOnlyOwnerScoreSplitFault::None, 2);
        expect_refused([&] {
            missing->accept_owner_score_split(std::move(outcome));
        });
        assert(outcome.test_only_summary().success);
    }
    {
        auto first = score_ready_measurement(run);
        auto outcome = outcome_for_measurement(*first, run);
        first->accept_owner_score_split(std::move(outcome));
        auto second = score_ready_measurement(run);
        for (unsigned owner = 0; owner < 3; ++owner)
            (void)second->issue_score(owner);
        expect_refused([&] {
            second->accept_owner_score_split(std::move(outcome));
        });
        assert(!second->test_only_has_owner_score_split());
    }
}

void run_measurement_allocation_faults_do_not_drop_claimed_outcome() {
    const auto run = binding();
    {
        auto measurement = score_ready_measurement(run);
        auto outcome = outcome_for_measurement(*measurement, run);
        bool allocated = false;
        try {
            measurement->test_only_accept_owner_score_split(
                std::move(outcome),
                RunMeasurement::TestOnlyOwnerScoreRetentionFault::
                    BeforeClaimAllocation);
        } catch (const std::bad_alloc&) { allocated = true; }
        assert(allocated);
        assert(outcome.test_only_summary().success);
        measurement->accept_owner_score_split(std::move(outcome));
        assert(measurement->test_only_has_owner_score_split());
    }
    {
        auto measurement = score_ready_measurement(run);
        auto outcome = outcome_for_measurement(*measurement, run);
        expect_refused([&] {
            measurement->test_only_accept_owner_score_split(
                std::move(outcome),
                RunMeasurement::TestOnlyOwnerScoreRetentionFault::
                    AfterClaim);
        });
        assert(measurement->test_only_has_owner_score_split());
    }
}

void run_measurement_cross_run_success_is_retained_and_poisoned() {
    const auto first_run = binding();
    auto second_run = binding();
    second_run.run_selection = digest(0x7a);
    second_run.trial = digest(0x7b);
    second_run.attempt = digest(0x7c);
    second_run.cohort = digest(0x7d);
    second_run.capture = digest(0x7e);
    second_run.financial_runs = {digest(0x80), digest(0x81)};
    second_run.round_attempts = {digest(0x82), digest(0x83)};
    second_run.round_cohorts = {digest(0x84), digest(0x85)};
    second_run.round_capture_plans = {digest(0x86), digest(0x87)};
    second_run.projections = {digest(0x88), digest(0x89)};

    auto first = score_ready_measurement(first_run);
    auto outcome = outcome_for_measurement(*first, first_run);
    auto second = score_ready_measurement(second_run);
    for (unsigned owner = 0; owner < 3; ++owner)
        (void)second->issue_score(owner);
    expect_refused([&] {
        second->accept_owner_score_split(std::move(outcome));
    });
    assert(second->test_only_has_owner_score_split());
}

} // namespace

int main() {
    static_assert(kOwnerScoreOutputSplitSourceStatus.all_three_atomic);
    static_assert(kOwnerScoreOutputSplitSourceStatus.exact_body_revalidation);
    static_assert(kOwnerScoreOutputSplitSourceStatus.independent_ro_reopen);
    static_assert(kOwnerScoreOutputSplitSourceStatus
                      .indivisible_aggregate_comparison_bundle);
    static_assert(kOwnerScoreOutputSplitSourceStatus
                      .typed_compact_lineage_required);
    static_assert(kOwnerScoreOutputSplitSourceStatus
                      .semantic_body_lineage_validation);
    static_assert(kOwnerScoreOutputSplitSourceStatus
                      .post_claim_closed_sum);
    static_assert(kOwnerScoreOutputSplitSourceStatus
                      .legacy_individual_accept_path_production_absent);
    static_assert(!kOwnerScoreOutputSplitSourceStatus
                       .source_compact_lineage_minter);
    static_assert(!kOwnerScoreOutputSplitSourceStatus
                       .mandatory_stop_sink_integrated);
    static_assert(kOwnerScoreOutputSplitSourceStatus
                      .run_measurement_integrated);
    static_assert(!kOwnerScoreOutputSplitSourceStatus
                       .aggregate_completion_retains_comparison);
    static_assert(!kOwnerScoreOutputSplitSourceStatus.configured);
    valid_all_three_is_indivisible_and_exact();
    mixed_binding_duplicate_owner_and_swapped_order_burn_all();
    stale_first_burns_fresh_siblings_before_validation();
    body_and_reopen_substitutions_refuse();
    exact_compact_lineage_substitutions_stop();
    typed_lineage_cannot_lie_about_live_run_fields();
    preclaim_allocation_leaves_every_input_reusable();
    run_measurement_retains_success_or_stop_indivisibly();
    run_measurement_early_missing_and_moved_inputs_refuse();
    run_measurement_allocation_faults_do_not_drop_claimed_outcome();
    run_measurement_cross_run_success_is_retained_and_poisoned();
}
