#pragma once

// One sealed join between a post-barrier owner-score permit and exactly one
// genuine owner-truth feeder.  This surface deliberately exposes neither the
// fixed descriptor, packet bytes, private truth, packet/body digest, path nor
// a caller-supplied success flag.

#include <memory>

namespace kpb::measurement {
class OwnerScoreExecutionPermitAuthority;
class OwnerScorePermitSplit;
namespace runtime_bridge { class MeasurementInputEndpointAuthority; }
}

namespace kpi::mpc::financial::fresh_owner_issuance {
class CandidateOwnerTruthEndpointAuthority;
}

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
class OwnerScoreTruthAuthority;
}

namespace kpi::mpc::financial::registered_driver::owner_truth_handoff {

class OwnerTruthScoreHandoffBridge;

class OwnerTruthScoreHandoff final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit OwnerTruthScoreHandoff(std::unique_ptr<Storage>);
    friend class OwnerTruthScoreHandoffBridge;
public:
    OwnerTruthScoreHandoff(const OwnerTruthScoreHandoff&) = delete;
    OwnerTruthScoreHandoff& operator=(const OwnerTruthScoreHandoff&) = delete;
    OwnerTruthScoreHandoff(OwnerTruthScoreHandoff&&) noexcept;
    OwnerTruthScoreHandoff& operator=(OwnerTruthScoreHandoff&&) = delete;
    ~OwnerTruthScoreHandoff();

    kpb::measurement::OwnerScoreExecutionPermitAuthority
        take_execution_permit();
    kpb::measurement::runtime_bridge::MeasurementInputEndpointAuthority
        take_truth_endpoint();
};

// This class is fully defined here before either endpoint grants friendship;
// a same-named forward declaration cannot acquire private descriptor access.
class OwnerTruthScoreHandoffBridge final {
    OwnerTruthScoreHandoffBridge() = delete;
public:
    static OwnerTruthScoreHandoff prepare(
        kpb::measurement::OwnerScorePermitSplit&&,
        baseline_disclosure::OwnerScoreTruthAuthority&&);
    static OwnerTruthScoreHandoff prepare(
        kpb::measurement::OwnerScorePermitSplit&&,
        fresh_owner_issuance::CandidateOwnerTruthEndpointAuthority&&);
};

} // namespace kpi::mpc::financial::registered_driver::owner_truth_handoff
