#include "privacy_selected_producer_byte_schedule_authority.hpp"

#include <cassert>
#include <concepts>
#include <cstdint>
#include <limits>
#include <utility>

using namespace kpb::measurement;
using namespace kpb::measurement::producer_schedule;

namespace {

Digest digest(unsigned seed) {
    Digest result{};
    for (unsigned index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(seed + 3 * index);
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

RunBinding binding(Classification classification) {
    unsigned seed = 1;
    const auto next = [&]() { return digest(seed++); };
    RunBinding result{};
    result.classification = classification;
    result.comparison_selection = next();
    result.run_selection = next();
    result.trial = next();
    result.attempt = next();
    result.cohort = next();
    result.capture = next();
    result.method = next();
    result.workload = next();
    result.source_closure = next();
    result.runtime = next();
    result.finite_manifest.parent_recomputation_identity = next();
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        auto& entry = result.finite_manifest.entries[index];
        entry = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = next(),
            .build_identity = next(),
            .runtime_identity = next(),
            .assets_identity = next(),
            .pinned_executable_identity = next(),
            .launcher_identity = next(),
        };
    }
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.outer_parent_process = next();
    result.outer_parent_executable = next();
    const auto& p1 = result.finite_manifest.entries[1];
    result.capture_source = p1.source_identity;
    result.capture_build = p1.build_identity;
    result.capture_runtime = p1.runtime_identity;
    result.capture_launcher = p1.launcher_identity;
    result.observer_worker = worker(result.finite_manifest.entries[6]);
    result.score_worker = worker(result.finite_manifest.entries[7]);
    result.aggregate_worker = worker(result.finite_manifest.entries[8]);
    for (auto* values : {
             &result.financial_runs, &result.round_attempts,
             &result.round_cohorts, &result.round_capture_plans,
             &result.projections})
        for (auto& value : *values) value = next();
    return result;
}

bool refused(auto&& operation) {
    try { operation(); }
    catch (const Refused&) { return true; }
    return false;
}

void exact_candidate_schedule() {
    const auto selected = binding(Classification::HiddenCandidate);
    const auto report = derive_non_authorizing_source_bounded_schedule(selected);
    assert(report.schema ==
               "kpb-nonauthorizing-producer-byte-schedule-blocker/v2" &&
           report.binding == selected && report.trial == selected.trial &&
           report.classification == Classification::HiddenCandidate &&
           report.workload == selected.workload && !report.complete &&
           report.source_bounded_slot_count == 8 &&
           report.missing_slot_count == 2 &&
           report.schedule_derivation_formula_identity != Digest{} &&
           report.schedule_derivation_source_identity == Digest{} &&
           report.schedule_derivation_build_identity == Digest{} &&
           !report.schedule_derivation_source_bound &&
           !report.schedule_derivation_build_bound);
    const std::array<std::uint64_t, 10> expected{
        11'094, 5'452, 3'841, 0, 6'140,
        11'094, 5'452, 3'841, 0, 6'140,
    };
    for (unsigned ordinal = 0; ordinal < report.slots.size(); ++ordinal) {
        const auto& slot = report.slots[ordinal];
        assert(slot.ordinal == ordinal && slot.round == ordinal / 5 + 1 &&
               slot.kind == static_cast<CaptureKind>(ordinal % 5 + 1) &&
               slot.fixed_fd == 20 + ordinal &&
               slot.max_wire_bytes == expected[ordinal] &&
               slot.source_derivation_identity != Digest{});
        if (ordinal == 3 || ordinal == 8) {
            assert(slot.grammar == ProducerWireGrammar::P1ChunkV9 &&
                   slot.bound_kind == ProducerByteBoundKind::Missing);
        } else if (ordinal == 0 || ordinal == 5) {
            assert(slot.grammar ==
                       ProducerWireGrammar::PublicProjectionEventV1 &&
                   slot.bound_kind == ProducerByteBoundKind::ExactBytes);
        } else if (ordinal == 4 || ordinal == 9) {
            assert(slot.grammar == ProducerWireGrammar::C1CaptureV2 &&
                   slot.bound_kind ==
                       ProducerByteBoundKind::ProtocolUpperBound);
        } else {
            assert(slot.bound_kind ==
                   ProducerByteBoundKind::ProtocolUpperBound);
        }
    }
    assert(report.producer_worker == worker(
               selected.finite_manifest.entries[5]) &&
           report.producer_executable_identity ==
               report.producer_worker.pinned_executable_identity &&
           report.producer_launcher_identity ==
               report.producer_worker.launcher_identity &&
           report.schedule_identity != Digest{});
}

void baseline_and_substitution_controls() {
    auto hidden_binding = binding(Classification::HiddenCandidate);
    auto baseline_binding = hidden_binding;
    baseline_binding.classification = Classification::TransparentBaseline;
    const auto hidden =
        derive_non_authorizing_source_bounded_schedule(hidden_binding);
    const auto baseline =
        derive_non_authorizing_source_bounded_schedule(baseline_binding);
    assert(baseline.slots[1].max_wire_bytes == 6'095 &&
           baseline.slots[2].max_wire_bytes == 6'990 &&
           baseline.slots[6].max_wire_bytes == 6'095 &&
           baseline.slots[7].max_wire_bytes == 6'990 &&
           baseline.slots[0].max_wire_bytes == 11'094 &&
           baseline.slots[4].max_wire_bytes == 6'140 &&
           hidden.schedule_identity != baseline.schedule_identity);

    auto changed_workload = hidden_binding;
    changed_workload.workload = digest(240);
    const auto workload =
        derive_non_authorizing_source_bounded_schedule(changed_workload);
    assert(workload.schedule_identity != hidden.schedule_identity);

    auto changed_trial = hidden_binding;
    changed_trial.trial = digest(239);
    const auto trial =
        derive_non_authorizing_source_bounded_schedule(changed_trial);
    assert(trial.trial != hidden.trial &&
           trial.schedule_identity != hidden.schedule_identity);

    auto changed_writer = hidden_binding;
    changed_writer.finite_manifest.entries[0].source_identity = digest(241);
    changed_writer.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(
            changed_writer.finite_manifest.entries);
    const auto writer_report =
        derive_non_authorizing_source_bounded_schedule(changed_writer);
    assert(writer_report.slots[0].writer.source_identity !=
               hidden.slots[0].writer.source_identity &&
           writer_report.schedule_identity != hidden.schedule_identity);

    auto changed_producer = hidden_binding;
    changed_producer.finite_manifest.entries[5].launcher_identity = digest(242);
    changed_producer.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(
            changed_producer.finite_manifest.entries);
    const auto producer_report =
        derive_non_authorizing_source_bounded_schedule(changed_producer);
    assert(producer_report.producer_worker.launcher_identity !=
               hidden.producer_worker.launcher_identity &&
           producer_report.schedule_identity != hidden.schedule_identity);

    for (unsigned field = 0; field < 4; ++field) {
        auto changed = hidden_binding;
        auto& producer = changed.finite_manifest.entries[5];
        Digest* selected[] = {
            &producer.source_identity, &producer.build_identity,
            &producer.runtime_identity, &producer.pinned_executable_identity,
        };
        *selected[field] = digest(244 + field);
        changed.finite_manifest.manifest_identity =
            recompute_finite_manifest_identity(
                changed.finite_manifest.entries);
        const auto report =
            derive_non_authorizing_source_bounded_schedule(changed);
        assert(report.schedule_identity != hidden.schedule_identity);
    }

    auto stale_manifest = hidden_binding;
    std::swap(stale_manifest.finite_manifest.entries[0],
              stale_manifest.finite_manifest.entries[1]);
    assert(refused([&] {
        (void)derive_non_authorizing_source_bounded_schedule(stale_manifest);
    }));

    auto wrong_classification = hidden_binding;
    wrong_classification.classification = static_cast<Classification>(0);
    assert(refused([&] {
        (void)derive_non_authorizing_source_bounded_schedule(
            wrong_classification);
    }));

    auto detached_capture = hidden_binding;
    detached_capture.capture_launcher = digest(243);
    assert(refused([&] {
        (void)derive_non_authorizing_source_bounded_schedule(detached_capture);
    }));
}

void overflow_controls() {
    test_only_verify_formula_overflow_controls();
}

} // namespace

static_assert(!std::default_initializable<
    SelectedProducerByteScheduleAuthority>);
static_assert(!std::copy_constructible<
    SelectedProducerByteScheduleAuthority>);
static_assert(std::move_constructible<
    SelectedProducerByteScheduleAuthority>);
static_assert(kProducerByteScheduleSourceStatus.eight_source_bounded_slots);
static_assert(kProducerByteScheduleSourceStatus.
    c1_source_frozen_no_retry_schedule);
static_assert(kProducerByteScheduleSourceStatus.
    c1_retry_invalidates_whole_trial);
static_assert(kProducerByteScheduleSourceStatus.
    c1_retry_evidence_retained_under_trial);
static_assert(!kProducerByteScheduleSourceStatus.
    c1_retry_outer_history_join);
static_assert(!kProducerByteScheduleSourceStatus.p1_round1_schedule);
static_assert(!kProducerByteScheduleSourceStatus.p1_round2_schedule);
static_assert(!kProducerByteScheduleSourceStatus.
    schedule_derivation_source_artifact);
static_assert(!kProducerByteScheduleSourceStatus.
    schedule_derivation_build_artifact);
static_assert(!kProducerByteScheduleSourceStatus.complete_authority_minter);
static_assert(!kProducerByteScheduleSourceStatus.archive_consumer);
static_assert(!kProducerByteScheduleSourceStatus.configured);

int main() {
    exact_candidate_schedule();
    baseline_and_substitution_controls();
    overflow_controls();
}
