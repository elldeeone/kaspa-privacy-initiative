#pragma once

// Complete, dependency-neutral contract for binding the sole ten-stream
// producer topology to one genuine registered fresh trial.  Both granting
// headers include this definition before friendship, so a hostile translation
// unit cannot define the bridge name and acquire private authority state.

namespace kpb::measurement::producer_runtime {
class ParentTenReadEndsAuthority;
class RunningCaptureProducer;
struct PublicProducerLaunchPlan;
}

namespace kpi::mpc::financial::fresh_owner_issuance {
class FreshOwnerProducerClosureAuthority;
struct PublicFreshOwnerTrialIssuanceReceipt;
}

namespace kpi::mpc::financial::registered_driver {

class FreshTrialCaptureProducerTopologyResidual;
class RegisteredSelectedProducerPrelaunchBindingAuthority;
class RegisteredFreshTrialProducerClosureAuthority;

class RegisteredFreshTrialProducerClosureBridge final {
    RegisteredFreshTrialProducerClosureBridge() = delete;
#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
    static RegisteredFreshTrialProducerClosureAuthority bind_reserved_impl(
        FreshTrialCaptureProducerTopologyResidual&&,
        fresh_owner_issuance::FreshOwnerProducerClosureAuthority&&,
        kpb::measurement::producer_runtime::PublicProducerLaunchPlan);
#endif
public:
    static RegisteredFreshTrialProducerClosureAuthority bind(
        FreshTrialCaptureProducerTopologyResidual&&,
        fresh_owner_issuance::FreshOwnerProducerClosureAuthority&&,
        RegisteredSelectedProducerPrelaunchBindingAuthority&&);
#ifdef KPI_REGISTERED_FRESH_TRIAL_PRODUCER_CLOSURE_TEST_SETUP
    static fresh_owner_issuance::FreshOwnerProducerClosureAuthority
        test_only_mint_fresh_owner_child(
            fresh_owner_issuance::PublicFreshOwnerTrialIssuanceReceipt);
    // Transitional control seam only. Production has no raw prebound
    // ParentTenReadEndsAuthority path; the selected three-authority bind above
    // remains unimplemented until its genuine factory lands.
    static RegisteredFreshTrialProducerClosureAuthority
        test_only_bind_prebound(
        fresh_owner_issuance::FreshOwnerProducerClosureAuthority&&,
        kpb::measurement::producer_runtime::
            ParentTenReadEndsAuthority&&);
    static RegisteredFreshTrialProducerClosureAuthority
        test_only_bind_reserved(
        FreshTrialCaptureProducerTopologyResidual&&,
        fresh_owner_issuance::FreshOwnerProducerClosureAuthority&&,
        kpb::measurement::producer_runtime::PublicProducerLaunchPlan);
#endif
    static kpb::measurement::producer_runtime::RunningCaptureProducer start(
        RegisteredFreshTrialProducerClosureAuthority&&);
};

} // namespace kpi::mpc::financial::registered_driver
