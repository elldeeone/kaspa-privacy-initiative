#include "v3_native_authority.hpp"

#include "../../local-private-payment/mpc-prover/financial/fresh_owner_process_adapter.hpp"
#include <utility>

namespace kpb::future_recipient::v3_native {
namespace {

using History = kpi::mpc::financial::fresh_owner_issuance::
    V3AcceptedRound1HistoryResidualAuthority;

[[noreturn]] void refuse() { throw NativeRefused(); }
void need(bool value) { if (!value) refuse(); }

} // namespace

V3LifecycleControllerAuthority V3LifecycleControllerMinter::mint(
        const measurement::RunBinding& binding,
        History&& supplied_history,
        ExternalLatestHeadUpdaterAuthority&& supplied_updater) {
    // Burn both sides before validating either. A failed/cross-bound join
    // cannot be retried with a substituted counterpart.
    ExternalLatestHeadUpdaterAuthority updater(std::move(supplied_updater));
    need(supplied_history.live_.exchange(false));
    const auto binding_id = recompute_v3_run_binding_identity(binding);
    const auto expected_history = History::recompute_identity(
        supplied_history.input_, supplied_history.successor_,
        supplied_history.input_lineages_,
        supplied_history.successor_lineages_,
        supplied_history.measurement_run_binding_identity_,
        supplied_history.financial_runs_, supplied_history.capture_plans_,
        supplied_history.projections_, supplied_history.contexts_,
        supplied_history.supervisor_session_identity_,
        supplied_history.continuation_identity_);
    const auto& input = supplied_history.input_;
    const auto& successor = supplied_history.successor_;
    need(binding.classification ==
             measurement::Classification::HiddenCandidate &&
         supplied_history.measurement_run_binding_identity_ == binding_id &&
         supplied_history.residual_identity_ == expected_history &&
         supplied_history.financial_runs_ == binding.financial_runs &&
         supplied_history.capture_plans_ == binding.round_capture_plans &&
         supplied_history.projections_ == binding.projections &&
         input.trial == binding.trial && successor.trial == binding.trial &&
         input.round1_attempt == binding.round_attempts[0] &&
         successor.round1_attempt == binding.round_attempts[0] &&
         input.round1_cohort == binding.round_cohorts[0] &&
         successor.round1_cohort == binding.round_cohorts[0] &&
         input.run == successor.run &&
         input.authority_identity != successor.authority_identity &&
         input.accepted_input_head_identity !=
             successor.accepted_successor_head_identity &&
         input.history_gate_identity != successor.history_gate_identity &&
         supplied_history.supervisor_session_identity_ != Digest{} &&
         supplied_history.continuation_identity_ != Digest{} &&
         supplied_history.contexts_[0] != Digest{} &&
         supplied_history.contexts_[1] != Digest{} &&
         supplied_history.contexts_[0] != supplied_history.contexts_[1]);
    return V3LifecycleControllerAuthority(
        binding_id, expected_history, std::move(updater));
}

} // namespace kpb::future_recipient::v3_native
