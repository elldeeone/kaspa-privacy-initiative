#include "privacy_measurement_capsule_test_fixture.hpp"
#include "privacy_measurement_runtime_bridge.hpp"
#include "privacy_native_empirical_result_test_fixture.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;
namespace fixture = kpb::measurement::runtime_bridge::test_fixture;
namespace empirical_fixture =
    kpb::measurement::empirical_result::test_fixture;

namespace {

WorkerBinding worker(const ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

ManifestEntry manifest_entry(ManifestComponent component,
                             const WorkerBinding& selected) {
    return {
        .component = component,
        .source_identity = selected.source_identity,
        .build_identity = selected.build_identity,
        .runtime_identity = selected.runtime_identity,
        .assets_identity = selected.assets_identity,
        .pinned_executable_identity = selected.pinned_executable_identity,
        .launcher_identity = selected.launcher_identity,
    };
}

FiniteManifestBinding manifest(const std::string& runtime) {
    const auto workers = fixture::workers(runtime);
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < 6; ++index) {
        const auto seed = static_cast<unsigned char>(0x10 + 6 * index);
        entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = fixture::digest(seed),
            .build_identity = fixture::digest(seed + 1),
            .runtime_identity = fixture::digest(seed + 2),
            .assets_identity = fixture::digest(seed + 3),
            .pinned_executable_identity = fixture::digest(seed + 4),
            .launcher_identity = fixture::digest(seed + 5),
        };
    }
    entries[6] = manifest_entry(ManifestComponent::Observer,
                                workers.observer);
    entries[7] = manifest_entry(ManifestComponent::OwnerScore,
                                workers.score);
    entries[8] = manifest_entry(ManifestComponent::Aggregate,
                                workers.aggregate);
    entries[9] = manifest_entry(ManifestComponent::OwnerComparison,
                                workers.comparison);
    return {
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = fixture::digest(0x90),
        .entries = entries,
    };
}

RunBinding binding(const std::string& runtime, Classification classification,
                   unsigned char run) {
    const auto selected = manifest(runtime);
    const auto& capture = selected.entries.at(1);
    return {
        .classification = classification,
        .comparison_selection = fixture::digest(0x91),
        .run_selection = fixture::digest(run),
        .trial = fixture::digest(run + 1),
        .attempt = fixture::digest(run + 2),
        .cohort = fixture::digest(run + 3),
        .capture = fixture::digest(run + 4),
        .method = fixture::digest(0x92),
        .workload = fixture::digest(0x93),
        .source_closure = fixture::digest(0x94),
        .runtime = fixture::digest(0x95),
        .finite_manifest = selected,
        .outer_parent_process = fixture::digest(0x96),
        .outer_parent_executable = fixture::digest(0x97),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(selected.entries.at(6)),
        .score_worker = worker(selected.entries.at(7)),
        .aggregate_worker = worker(selected.entries.at(8)),
        .financial_runs = {fixture::digest(run + 5),
                           fixture::digest(run + 6)},
        .round_attempts = {fixture::digest(run + 9),
                           fixture::digest(run + 10)},
        .round_cohorts = {fixture::digest(run + 11),
                          fixture::digest(run + 12)},
        .round_capture_plans = {fixture::digest(run + 13),
                                fixture::digest(run + 14)},
        .projections = {fixture::digest(run + 7),
                        fixture::digest(run + 8)},
    };
}

ObserverExecutionPermitAuthority observer_permit(
        const RunBinding& selected, unsigned char seed) {
    return ObserverExecutionPermitAuthority::test_only_mint(
        PublicObserverPermit{
        .binding = selected,
        .trial_capture_identity = fixture::digest(0xc0),
        .permit_identity = fixture::digest(seed),
    });
}

OwnerScorePermitAuthority score_permit(
        const RunBinding& selected, unsigned owner) {
    return OwnerScorePermitAuthority::test_only_mint(PublicOwnerScorePermit{
        .binding = selected,
        .owner = owner,
        .trial_capture_identity = fixture::digest(0xc0),
        .observation_receipt = fixture::digest(0xc1),
        .barrier = fixture::digest(0xc2),
        .permit_identity = fixture::digest(
            static_cast<unsigned char>(0xc3 + owner)),
    });
}

OwnerScoreExecutionPermitAuthority score_execution(
        const RunBinding& selected, unsigned owner) {
    auto split = std::move(score_permit(selected, owner))
        .split_for_truth_release();
    auto release = split.take_truth_release_permit();
    (void)release;
    return split.take_execution_permit();
}

AggregatePermitAuthority aggregate_permit(const RunBinding& selected) {
    return AggregatePermitAuthority::test_only_mint(PublicAggregatePermit{
        .binding = selected,
        .trial_capture_identity = fixture::digest(0xc0),
        .observation_receipt = fixture::digest(0xc1),
        .barrier = fixture::digest(0xc2),
        .score_receipts = {fixture::digest(0xc3), fixture::digest(0xc4),
                           fixture::digest(0xc5)},
        .capsule_seals = {fixture::digest(0xc6), fixture::digest(0xc7),
                          fixture::digest(0xc8)},
        .permit_identity = fixture::digest(0xc9),
    });
}

OwnerComparisonPermitAuthority comparison_permit(
        const RunBinding& baseline, const RunBinding& candidate) {
    return OwnerComparisonPermitAuthority::test_only_mint(
        PublicOwnerComparisonPermit{
            .selection = {
                .comparison_selection = candidate.comparison_selection,
                .selection_identity = fixture::digest(0xca),
                .method = candidate.method,
                .workload = candidate.workload,
                .source_closure = candidate.source_closure,
                .runtime = candidate.runtime,
                .finite_manifest = candidate.finite_manifest,
                .comparison_worker = worker(
                    candidate.finite_manifest.entries.at(9)),
                .outer_parent_process = candidate.outer_parent_process,
                .outer_parent_executable =
                    candidate.outer_parent_executable,
                .manifest_recomputation_receipt =
                    candidate.finite_manifest.parent_recomputation_identity,
                .baseline_run = baseline.run_selection,
                .candidate_run = candidate.run_selection,
            },
            .baseline_aggregate = fixture::digest(0xcc),
            .candidate_aggregate = fixture::digest(0xcd),
            .permit_identity = fixture::digest(0xce),
        });
}

template<class Function>
void refused(Function&& function) {
    bool rejected = false;
    try { function(); }
    catch (const Refused&) { rejected = true; }
    assert(rejected);
}

void every_role_runs_through_authenticated_capsule(
        const std::string& runtime) {
    const auto candidate = binding(
        runtime, Classification::HiddenCandidate, 0xa0);
    auto candidate_lineage = fixture::lineage(candidate, 0xd0);
    candidate_lineage.barrier = fixture::digest(0xc2);
    Digest first_observation{};
    {
        auto permit = observer_permit(candidate, 0xb4);
        auto completed = MeasurementChildSupervisor::run_observer(
            std::move(permit), fixture::capsule(
                runtime, RuntimeChildRole::Observer, NO_OWNER,
                candidate_lineage), empirical_fixture::exact(candidate));
        const auto& receipt = completed.completion.public_receipt();
        assert(receipt.permit_identity == fixture::digest(0xb4));
        assert(receipt.observation_receipt != Digest{} &&
               receipt.child_exit != Digest{} &&
               receipt.process_identity != Digest{});
        first_observation = receipt.observation_receipt;
        refused([&] {
            (void)MeasurementChildSupervisor::run_observer(
                std::move(permit), fixture::capsule(
                    runtime, RuntimeChildRole::Observer, NO_OWNER,
                    candidate_lineage),
                empirical_fixture::exact(candidate));
        });
    }
    {
        auto completed = MeasurementChildSupervisor::run_observer(
            observer_permit(candidate, 0xb5), fixture::capsule(
                runtime, RuntimeChildRole::Observer, NO_OWNER,
                candidate_lineage), empirical_fixture::exact(candidate));
        assert(completed.completion.public_receipt().observation_receipt !=
               first_observation);
    }
    {
        auto completed = MeasurementChildSupervisor::run_owner_score(
            score_execution(candidate, 2), fixture::capsule(
                runtime, RuntimeChildRole::OwnerScore, 2,
                candidate_lineage));
        const auto& receipt = completed.completion.public_receipt();
        assert(receipt.owner == 2 && receipt.score_receipt != Digest{} &&
               receipt.capsule_seal != Digest{} &&
               receipt.score_receipt != receipt.capsule_seal);
    }
    {
        auto completed = MeasurementChildSupervisor::run_aggregate(
            aggregate_permit(candidate), fixture::capsule(
                runtime, RuntimeChildRole::Aggregate, NO_OWNER,
                candidate_lineage));
        const auto& receipt = completed.completion.public_receipt();
        assert(receipt.aggregate_receipt != Digest{} &&
               receipt.outcome == AggregateOutcome::CandidatePass);
    }
    {
        const auto baseline = binding(
            runtime, Classification::TransparentBaseline, 0x70);
        auto completed = MeasurementChildSupervisor::run_owner_comparison(
            comparison_permit(baseline, candidate), fixture::capsule(
                runtime, RuntimeChildRole::OwnerComparison, NO_OWNER,
                fixture::lineage(baseline, 0x60), candidate_lineage));
        const auto& receipt = completed.completion.public_receipt();
        assert(receipt.comparison_receipt != Digest{} &&
               receipt.outcome ==
                   OwnerComparisonOutcome::NonRegressionPass);
    }
}

void transport_fault_refuses(const std::string& runtime) {
    const auto selected = binding(
        runtime, Classification::HiddenCandidate, 0xa0);
    bool rejected = false;
    try {
        (void)MeasurementChildSupervisor::run_observer(
            observer_permit(selected, 0xb4), fixture::capsule(
                runtime, RuntimeChildRole::Observer, NO_OWNER,
                fixture::lineage(selected, 0xd0)),
            empirical_fixture::exact(selected));
    } catch (const Refused&) {
        rejected = true;
    }
    if (!rejected)
        std::fprintf(stderr, "transport fault accepted: %s\n",
                     runtime.c_str());
    assert(rejected);
}

void wrong_runtime_and_owner_refuse(const std::string& selected_runtime,
                                    const std::string& substituted_runtime) {
    const auto selected = binding(
        selected_runtime, Classification::HiddenCandidate, 0xa0);
    auto empirical = empirical_fixture::exact(selected);
    refused([&] {
        (void)MeasurementChildSupervisor::run_observer(
            observer_permit(selected, 0xb4), fixture::capsule(
                substituted_runtime, RuntimeChildRole::Observer, NO_OWNER,
                fixture::lineage(selected, 0xd0)),
            std::move(empirical));
    });
    refused([&] {
        (void)MeasurementChildSupervisor::run_observer(
            observer_permit(selected, 0xb5), fixture::capsule(
                selected_runtime, RuntimeChildRole::Observer, NO_OWNER,
                fixture::lineage(selected, 0xd0)),
            std::move(empirical));
    });
    refused([&] {
        (void)MeasurementChildSupervisor::run_owner_score(
            score_execution(selected, 2), fixture::capsule(
                selected_runtime, RuntimeChildRole::OwnerScore, 1,
                fixture::lineage(selected, 0xd0)));
    });
}

void zero_offer_record_before_close_refuses() {
    int channels[2]{-1, -1};
    assert(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                        0, channels) == 0);
    const int enabled = 1;
    assert(::setsockopt(channels[0], SOL_SOCKET, SO_PASSCRED,
                        &enabled, sizeof(enabled)) == 0);
    assert(::send(channels[1], nullptr, 0, MSG_NOSIGNAL) == 0);
    assert(::close(channels[1]) == 0);
    channels[1] = -1;
    assert(test_only_zero_offer_record_refused(channels[0]));
    assert(::close(channels[0]) == 0);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 17);
    zero_offer_record_before_close_refuses();
    every_role_runs_through_authenticated_capsule(argv[1]);
    wrong_runtime_and_owner_refuse(argv[1], argv[2]);
    for (int index = 2; index < 16; ++index)
        transport_fault_refuses(argv[index]);
    // The finite static observer has no selected model/ACK path yet.  It must
    // still execute only through the genuine capsule + preexec supervisor and
    // fail closed before acknowledging the authenticated offer.
    transport_fault_refuses(argv[16]);
}
