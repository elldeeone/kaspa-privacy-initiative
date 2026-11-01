#include "registered_producer_route_bridge_contract.hpp"

#include "registered_parent_trial_completion_storage.hpp"
#include "../../private_batch_trial/privacy_capture_producer_runtime.hpp"

#include <array>
#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {

using kpb::measurement::producer_runtime::
    ParentAggregateMailboxRoutesAuthority;
using kpb::measurement::producer_runtime::
    PublicAggregateMailboxRouteCompletion;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

} // namespace

ParentAggregateMailboxRoutesAuthority RegisteredProducerRouteBridge::take_once(
        RegisteredParentTrialCompletionAuthority& authority) {
    auto* const storage = authority.storage_.get();
    need(storage != nullptr &&
         !storage->producer_routes_taken.exchange(true) &&
         storage->exit_evidence.all_children_exited_zero_value());

    std::array<PublicAggregateMailboxRouteCompletion, 2> result{};
    for (unsigned index = 0; index < result.size(); ++index) {
        const auto& route = storage->retained_projections[index];
        const auto& party = storage->party_completions[index][0]
            .public_party_completion();
        need(route.live_.load() && route.receipt_.round == index + 1 &&
             route.receipt_.exact_size && route.receipt_.read_complete &&
             route.receipt_.kernel_eof && route.receipt_.clean &&
             route.plan_.round == index + 1 &&
             route.plan_.computing_role == 0 &&
             route.plan_.classification == party.classification &&
             route.plan_.trial == party.trial &&
             route.plan_.financial_run == party.run &&
             route.plan_.attempt == party.attempt &&
             route.plan_.cohort == party.cohort &&
             route.plan_.capture_plan_identity ==
                 party.capture_plan_identity &&
             route.projection_identity_ == party.projection_identity &&
             nonzero(route.route_identity_) &&
             nonzero(route.retained_identity_) &&
             nonzero(route.fork_binding_identity_) &&
             nonzero(party.full_cohort_barrier_identity) &&
             party.full_cohort_barrier_observed_monotonic_ns > 0 &&
             route.route_observed_monotonic_ns_ >
                 party.full_cohort_barrier_observed_monotonic_ns);
        result[index] = {
            .round = index + 1,
            .route_identity = route.route_identity_,
            .full_cohort_barrier_identity =
                party.full_cohort_barrier_identity,
            .projection_identity = route.projection_identity_,
            .projection_bytes = projection_route::PUBLIC_PROJECTION_BYTES,
            .full_cohort_barrier_observed_monotonic_ns =
                party.full_cohort_barrier_observed_monotonic_ns,
            .route_observed_monotonic_ns =
                route.route_observed_monotonic_ns_,
            .route_endpoint_count = 1,
            .owner_ack_count = 0,
            .role_blind = true,
            .after_full_cohort_barrier = true,
            .owner_socket_or_path_derived = false,
        };
    }
    need(result[0].route_identity != result[1].route_identity &&
         result[0].full_cohort_barrier_identity !=
             result[1].full_cohort_barrier_identity);
    return ParentAggregateMailboxRoutesAuthority(std::move(result));
}

} // namespace kpi::mpc::financial::registered_driver
