#pragma once

// Complete dependency-neutral bridge names.  The selected Python receiver has
// no callable operation until a source-owned parent launcher authenticates the
// exact child, descriptor transfer, EOF, and wait status.  The admission
// bridge can only consume that future opaque authority; it accepts no paths,
// text, bytes, digests, JSON, or public receipts.

namespace kpi::mpc::financial::registered_driver {
class RegisteredSelectedProducerPrelaunchBindingAuthority;
struct RegisteredSelectedProducerPrelaunchPlan;
}

namespace kpb::measurement::score_output_lineage_source {

class AuthenticatedPrivacyLaunchLineageSourceAuthority;
class SelectedOwnerScoreLineageSourceTransferAuthority;
class RegisteredOwnerScorePrelaunchResidualAuthority;
class RegisteredOwnerScoreTrialResidualAuthority;
class SelectedOwnerScoreLineagePrelaunchSourceAuthority;
#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP
struct TestOnlyOwnerScoreLineageSummary;
enum class TestOnlyLineageAdmissionFault : unsigned char;
#endif

class PrivacyLaunchLineageSourceReceiverBridge final {
public:
    PrivacyLaunchLineageSourceReceiverBridge() = delete;

    static AuthenticatedPrivacyLaunchLineageSourceAuthority receive(
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerPrelaunchBindingAuthority&);
};

class SelectedOwnerScoreLineageAdmissionBridge final {
public:
    SelectedOwnerScoreLineageAdmissionBridge() = delete;

    static SelectedOwnerScoreLineageSourceTransferAuthority admit(
        AuthenticatedPrivacyLaunchLineageSourceAuthority&&);

#ifdef KPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP
    static SelectedOwnerScoreLineageSourceTransferAuthority test_only_admit(
        AuthenticatedPrivacyLaunchLineageSourceAuthority&&,
        TestOnlyLineageAdmissionFault);
    static TestOnlyOwnerScoreLineageSummary test_only_consume(
        SelectedOwnerScoreLineageSourceTransferAuthority&&);
#endif
};

// Future sole join of the admitted source transfer, the no-throw registered
// prelaunch residual, and the indivisible registered trial residual.  It has
// no method while either registered residual is absent.
class RegisteredOwnerScoreLineageSourceBridge final {
public:
    RegisteredOwnerScoreLineageSourceBridge() = delete;
};

#ifdef KPB_SELECTED_PRODUCER_ACTIVATION_TEST_SETUP
// Hostile controls may create the already-sealed source half.  This does not
// exist in production and cannot bypass the selected activation bridge.
class SelectedOwnerScoreLineagePrelaunchSourceTestBridge final {
public:
    SelectedOwnerScoreLineagePrelaunchSourceTestBridge() = delete;
    static SelectedOwnerScoreLineagePrelaunchSourceAuthority mint(
        kpi::mpc::financial::registered_driver::
            RegisteredSelectedProducerPrelaunchPlan,
        int selection_fd, int worker_fd);
};
#endif

} // namespace kpb::measurement::score_output_lineage_source
