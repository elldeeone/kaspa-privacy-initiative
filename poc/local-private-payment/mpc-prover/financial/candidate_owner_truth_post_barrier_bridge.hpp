#pragma once

// Complete, lightweight friendship boundary for the sole global hidden-arm
// truth release. The implementation must atomically consume the genuine
// post-freeze RunMeasurement release and the exact private three-owner pending
// batch; no per-owner score permit can call this surface.

namespace kpb::measurement {
class CandidateTruthBarrierReleaseAuthority;
}

namespace kpi::mpc::financial::fresh_owner_issuance {

class FreshOwnerProcessSupervisor;
class CandidateOwnerTruthPendingAuthority;
class CandidateOwnerTruthEndpointSplit;

class CandidateOwnerTruthPostBarrierBridge final {
    CandidateOwnerTruthPostBarrierBridge() = delete;
public:
    static CandidateOwnerTruthEndpointSplit release(
        FreshOwnerProcessSupervisor&,
        kpb::measurement::CandidateTruthBarrierReleaseAuthority&&,
        CandidateOwnerTruthPendingAuthority&&);
};

} // namespace kpi::mpc::financial::fresh_owner_issuance
