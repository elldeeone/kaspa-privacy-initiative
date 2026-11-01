#pragma once

// Complete, data-free friend contract for the ADR-0092 V3 lifecycle join.
// Keeping this class complete before any friendship prevents another
// translation unit from defining a lookalike friend that can forge or inspect
// the issuance-validated history residual.

namespace kpb::measurement { struct RunBinding; }

namespace kpi::mpc::financial::fresh_owner_issuance {
class V3AcceptedRound1HistoryResidualAuthority;
}

namespace kpb::future_recipient::v3_native {

class ExternalLatestHeadUpdaterAuthority;
class V3LifecycleControllerAuthority;

class V3LifecycleControllerMinter final {
    V3LifecycleControllerMinter() = delete;
public:
    static V3LifecycleControllerAuthority mint(
        const measurement::RunBinding&,
        kpi::mpc::financial::fresh_owner_issuance::
            V3AcceptedRound1HistoryResidualAuthority&&,
        ExternalLatestHeadUpdaterAuthority&&);
};

} // namespace kpb::future_recipient::v3_native
