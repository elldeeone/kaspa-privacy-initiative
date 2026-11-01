#include "privacy_registered_fresh_trial_capture_topology_reservation.hpp"
#include "../mpc-prover/financial/registered_parent_role_fork.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver {

FreshTrialCaptureTopologyReservation
FreshTrialCaptureTopologyReservationBridge::reserve(
        RegisteredTopologyReservationPermit&& permit) {
    // The permit stays live throughout every potentially failing resource
    // allocation and validation. Only the final source-owned epoch transfer
    // consumes it, so a resource failure cannot burn the process reservation.
    permit.validate_for_topology_reservation();
    auto reservation = open_unbound_resources(false);
    permit.validate_for_topology_reservation();
    auto epoch = std::move(permit).consume_for_topology_reservation();
    reservation.bind_preidentity_epoch(std::move(epoch));
    return reservation;
}

} // namespace kpi::mpc::financial::registered_driver
