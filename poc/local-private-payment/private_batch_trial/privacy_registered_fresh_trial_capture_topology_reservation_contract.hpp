#pragma once

// Complete neutral contract for the only production opener of capture
// topology resources. The permit is minted by the persistent process
// reservation only after all three children and pidfds exist, so none of the
// subsequently opened descriptors can be inherited across the role fork.

namespace kpi::mpc::financial::registered_driver {

class FreshTrialCaptureTopologyReservation;
class RegisteredTopologyReservationPermit;

class FreshTrialCaptureTopologyReservationBridge final {
    FreshTrialCaptureTopologyReservationBridge() = delete;
    static FreshTrialCaptureTopologyReservation
        open_unbound_resources(bool diagnostic_unbound);
public:
    static FreshTrialCaptureTopologyReservation reserve(
        RegisteredTopologyReservationPermit&&);
#ifdef KPI_FRESH_TRIAL_CAPTURE_TOPOLOGY_RESERVATION_TEST_SETUP
    // Diagnostics exercise the resource grammar without constructing a
    // process tree. This entry point is absent from production translation
    // units and cannot authorize activation or launch.
    static FreshTrialCaptureTopologyReservation test_only_reserve_unbound();
    static void test_only_require_valid(
        const FreshTrialCaptureTopologyReservation&);
    static void test_only_close_read_end(
        FreshTrialCaptureTopologyReservation&, unsigned slot);
    static void test_only_close_writer_alias(
        FreshTrialCaptureTopologyReservation&, unsigned slot);
    static void test_only_swap_writer_aliases(
        FreshTrialCaptureTopologyReservation&, unsigned first,
        unsigned second);
    static void test_only_close_archive(
        FreshTrialCaptureTopologyReservation&, unsigned slot);
    static void test_only_close_p1_state_parent_read(
        FreshTrialCaptureTopologyReservation&, unsigned slot);
    static void test_only_close_p1_state_writer_alias(
        FreshTrialCaptureTopologyReservation&, unsigned slot);
#endif
};

} // namespace kpi::mpc::financial::registered_driver
