#pragma once

// Dependency-neutral contract for extracting the two state-archive
// descriptions from the already-authorized capture topology.  The complete
// bridge is defined before any produced authority grants friendship, so an
// exact-name class supplied by a caller cannot acquire descriptor authority.

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateCapsuleAuthority;
class P1CorruptStateCapsulePlanAuthority;
class P1CorruptStateRecorderAuthority;
}

namespace kpi::mpc::financial::registered_driver {

class FreshTrialCaptureTopologyActivationTransfer;
class RegisteredP1StateArchiveScmTransfer;
class RegisteredP1StateArchiveChildRoundAuthority;
class P1StateArchiveWriterAdoptionBundle;
class P1StateArchiveWriterAdoptionAuthority;
class ParentAuthenticatedPartyDeliveryAuthority;
class RegisteredRole1P1StatePrelaunchAuthority;
class RegisteredRole1P1StateRuntimeAuthority;
class RegisteredRole1P1StateRecorderFacade;
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
enum class RegisteredP1StateArchiveScmTestFault : unsigned char;
struct RegisteredP1StateArchiveScmTestSummary;
#endif

class RegisteredP1StateArchiveScmBridge final {
public:
    RegisteredP1StateArchiveScmBridge() = delete;

    // Moves only the two P1 state pairs.  The ten capture streams and ten
    // capture archives remain in the activation transfer byte-for-byte.
    static RegisteredP1StateArchiveScmTransfer extract_state_channels(
        FreshTrialCaptureTopologyActivationTransfer&);
    static P1StateArchiveWriterAdoptionBundle prepare_writer_adoption(
        RegisteredP1StateArchiveChildRoundAuthority&&);
    static void attach_role1_prelaunch(
        ParentAuthenticatedPartyDeliveryAuthority&,
        RegisteredP1StateArchiveChildRoundAuthority&&,
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsulePlanAuthority&&);
    static RegisteredRole1P1StateRuntimeAuthority begin_role1_prelaunch(
        RegisteredRole1P1StatePrelaunchAuthority&&);
#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
    static bool test_only_round2_extraction_failure_retains_all(
        FreshTrialCaptureTopologyActivationTransfer&);
    static RegisteredP1StateArchiveScmTestSummary test_only_run(
        FreshTrialCaptureTopologyActivationTransfer&,
        RegisteredP1StateArchiveScmTestFault,
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsuleAuthority (*capsule_factory)(
                P1StateArchiveWriterAdoptionAuthority&&),
        bool (*wrong_round_probe)(
            P1StateArchiveWriterAdoptionAuthority&&),
        bool (*wrong_reservation_probe)(
            P1StateArchiveWriterAdoptionAuthority&&),
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsulePlanAuthority (*plan_factory)(
                const P1StateArchiveWriterAdoptionAuthority&),
        void (*allocation_gate)(bool) noexcept,
        void (*runtime_failure_probe)(
            RegisteredRole1P1StateRecorderFacade&));
#endif
};

} // namespace kpi::mpc::financial::registered_driver

// This mutual include is intentional: direct users of either dependency-
// neutral contract see the complete SCM producer bridge before the opaque
// writer authority grants it friendship.
#include "registered_p1_state_archive_writer_adoption_contract.hpp"
