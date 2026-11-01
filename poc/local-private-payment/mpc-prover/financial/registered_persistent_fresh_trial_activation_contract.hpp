#pragma once

// Complete neutral contract for the only phase-2 consumer of a pre-identity
// three-child process reservation. Keeping this type complete before either
// reservation grants friendship prevents hostile exact-name friend minting.

namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerPersistentActivationAuthority;
}

namespace kpi::mpc::financial::registered_driver {

class ParentRoleForkPlanAuthority;
class RegisteredPersistentRoleActivationResult;
class RegisteredPersistentRoleActivationFailureResidual;
class RegisteredPersistentRoleProcessReservation;
class RegisteredPersistentTopologyActivationAuthority;
class RegisteredPersistentWriterlessRoundPlanAuthority;

class RegisteredPersistentFreshTrialActivationBridge final {
    RegisteredPersistentFreshTrialActivationBridge() = delete;
public:
    // Claims only the causal post-issuance activation child.
    // The activation child privately retains the exact process/topology pair
    // that existed before owner/trial identity issuance. No round plan enters
    // this stage: children retain only the topology's exact writer
    // descriptions until a later source-owned writerless plan is bound.
    static RegisteredPersistentRoleActivationResult activate(
        fresh_owner_issuance::FreshOwnerPersistentActivationAuthority&&);
    static RegisteredPersistentRoleActivationFailureResidual abort_topology(
        RegisteredPersistentTopologyActivationAuthority&&);
#ifdef KPI_REGISTERED_PERSISTENT_FRESH_ACTIVATION_TEST_SETUP
    static void test_only_set_post_storage_hook(void (*)());
    static void test_only_set_process_hook(
        void (*)(RegisteredPersistentRoleProcessReservation&));
    static void test_only_set_post_settle_hook(void (*)());
#ifdef KPI_REGISTERED_PARENT_FORK_TEST_SETUP
    static void test_only_close_pending_reservation_channel(
        RegisteredPersistentTopologyActivationAuthority&,
        unsigned round, unsigned role);
#endif
#endif
};

} // namespace kpi::mpc::financial::registered_driver
