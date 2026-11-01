#include "candidate_owner_truth_post_barrier_bridge.hpp"

#include "fresh_owner_process_adapter.hpp"
#include "../../private_batch_trial/privacy_measurement_authority.hpp"

#include <utility>

namespace kpi::mpc::financial::fresh_owner_issuance {
namespace {

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

} // namespace

CandidateOwnerTruthEndpointSplit
CandidateOwnerTruthPostBarrierBridge::release(
        FreshOwnerProcessSupervisor& supervisor,
        kpb::measurement::CandidateTruthBarrierReleaseAuthority&& supplied,
        CandidateOwnerTruthPendingAuthority&& pending) {
    // Exchange both before any validation: mismatch, replay and cross-run
    // substitution burn the global release and the exact pending batch.
    const bool release_live = supplied.live_.exchange(false);
    const bool pending_live = pending.live_.exchange(false);
    try {
        const auto release = supplied.receipt_;
        using kpb::measurement::Classification;
        need(release_live && pending_live &&
             release.binding.classification ==
                 Classification::HiddenCandidate &&
             release.release_identity ==
                 kpb::measurement::
                     recompute_candidate_truth_barrier_release_identity(
                         release) &&
             release.binding.financial_runs == pending.financial_runs_ &&
             release.binding.round_capture_plans ==
                 pending.capture_plan_identities_ &&
             release.binding.projections == pending.projection_identities_);
        PublicCandidateOwnerTruthPostBarrier receipt{
            .classification =
                registered_driver::CaptureClassification::HiddenCandidate,
            .authority_identity = release.release_identity,
            .trial = release.binding.trial,
            .barrier_identity = release.barrier,
            .financial_runs = release.binding.financial_runs,
            .attempts = release.binding.round_attempts,
            .cohorts = release.binding.round_cohorts,
            .capture_plan_identities = release.binding.round_capture_plans,
            .projection_identities = release.binding.projections,
            // Contexts never come from the caller/global release. They were
            // fixed in the admitted owner plan and sealed in this batch.
            .context_identities = pending.context_identities_,
        };
        CandidateOwnerTruthPostBarrierAuthority barrier(
            std::move(receipt), pending.supervisor_session_,
            pending.continuation_identity_);
        return supervisor.release_candidate_truth(std::move(barrier));
    } catch (...) {
        supervisor.poison_candidate_truth_release();
        refuse();
    }
}

} // namespace kpi::mpc::financial::fresh_owner_issuance
