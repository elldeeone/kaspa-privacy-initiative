#pragma once

// Lightweight, fully-defined friendship boundary between the registered
// baseline truth authority and the isolated measurement worker input. The
// implementation forks the sole serializer; this surface exposes no file
// descriptor, path, byte span, digest, JSON object, or success Boolean.

#include "owner_truth_score_handoff.hpp"

namespace kpb::measurement::runtime_bridge {
class MeasurementInputEndpointAuthority;
}

namespace kpb::measurement { struct PublicOwnerTruthReleasePermit; }

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {

class OwnerScoreTruthAuthority;

class BaselineOwnerTruthCapsuleBridge final {
    BaselineOwnerTruthCapsuleBridge() = delete;
    static kpb::measurement::runtime_bridge::
        MeasurementInputEndpointAuthority prepare(
            OwnerScoreTruthAuthority&&,
            const kpb::measurement::PublicOwnerTruthReleasePermit&);
    friend class kpi::mpc::financial::registered_driver::
        owner_truth_handoff::OwnerTruthScoreHandoffBridge;
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
public:
    static kpb::measurement::runtime_bridge::
        MeasurementInputEndpointAuthority test_only_prepare(
            OwnerScoreTruthAuthority&&,
            const kpb::measurement::PublicOwnerTruthReleasePermit&);
#endif
};

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
