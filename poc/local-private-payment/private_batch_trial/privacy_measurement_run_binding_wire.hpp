#pragma once

#include "privacy_measurement_authority.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kpb::measurement::wire {

inline constexpr std::size_t RUN_BINDING_BYTES = 3403;

inline std::vector<unsigned char> canonical_run_binding_bytes(
        const RunBinding& value) {
    std::vector<unsigned char> out;
    out.reserve(RUN_BINDING_BYTES);
    const auto add_digest = [&](const Digest& digest) {
        out.insert(out.end(), digest.begin(), digest.end());
    };
    const auto add_worker = [&](const WorkerBinding& worker) {
        for (const auto* field : {
                 &worker.source_identity, &worker.build_identity,
                 &worker.runtime_identity, &worker.assets_identity,
                 &worker.pinned_executable_identity,
                 &worker.launcher_identity})
            add_digest(*field);
    };
    out.push_back(static_cast<unsigned char>(value.classification));
    for (const auto* field : {
             &value.comparison_selection, &value.run_selection,
             &value.trial, &value.attempt, &value.cohort, &value.capture,
             &value.method, &value.workload, &value.source_closure,
             &value.runtime,
             &value.finite_manifest.manifest_identity,
             &value.finite_manifest.parent_recomputation_identity,
             &value.outer_parent_process, &value.outer_parent_executable,
             &value.capture_source, &value.capture_build,
             &value.capture_runtime, &value.capture_launcher})
        add_digest(*field);
    for (const auto& entry : value.finite_manifest.entries) {
        out.push_back(static_cast<unsigned char>(entry.component));
        for (const auto* field : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            add_digest(*field);
    }
    add_worker(value.observer_worker);
    add_worker(value.score_worker);
    add_worker(value.aggregate_worker);
    for (const auto* values : {
             &value.financial_runs, &value.round_attempts,
             &value.round_cohorts, &value.round_capture_plans,
             &value.projections})
        for (const auto& field : *values) add_digest(field);
    if (out.size() != RUN_BINDING_BYTES) throw Refused();
    return out;
}

} // namespace kpb::measurement::wire
