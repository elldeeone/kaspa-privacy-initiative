#include "registered_projection_route_capture_bridge.hpp"

#include "registered_capture_session.hpp"
#include "registered_projection_route.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {
[[noreturn]] void refuse() {
    throw identity_registry::Refused();
}
void need(bool value) { if (!value) refuse(); }
}

void RegisteredProjectionRouteCaptureBridge::consume(
        RegisteredCaptureSession& session,
        projection_route::Role0ProjectionRouteWriterAuthority&& writer) {
    const auto selected = session.route_capture_plan();
    const auto route_plan = writer.plan_;
    need(route_plan.classification == selected.classification &&
         route_plan.round == selected.round &&
         route_plan.computing_role == CAPTURE_STREAM_OWNER_ROLE &&
         route_plan.trial == selected.trial &&
         route_plan.attempt == selected.attempt &&
         route_plan.cohort == selected.cohort &&
         route_plan.financial_run == selected.run &&
         route_plan.capture_plan_identity == session.plan_identity());
    auto completion = projection_route::RegisteredProjectionRoute::
        deliver_after_release(
            std::move(writer),
            projection_route::ProjectionDeliveryAuthority(
                route_plan, session.retained_projection_for_route()));
    need(completion.live_.exchange(false));
    const auto& receipt = completion.receipt_;
    need(receipt.classification == selected.classification &&
         receipt.round == selected.round &&
         receipt.trial == selected.trial &&
         receipt.attempt == selected.attempt &&
         receipt.cohort == selected.cohort &&
         receipt.financial_run == selected.run &&
         receipt.capture_plan_identity == session.plan_identity() &&
         receipt.exact_size && receipt.parent_read_complete &&
         receipt.parent_kernel_eof && receipt.parent_acknowledged &&
         receipt.parent_writer_closed &&
         completion.projection_identity_ == session.projection_identity() &&
         completion.route_identity_ != Digest{} &&
         completion.retained_identity_ != Digest{} &&
         completion.fork_binding_identity_ != Digest{});
    session.close_after_projection_route(
        completion.route_identity_, completion.projection_identity_);
}

} // namespace kpi::mpc::financial::registered_driver
