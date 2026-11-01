#pragma once

// Complete dependency-neutral contract for the sole consumer of the retained
// Observer v3 output join. It can produce only an explicitly open,
// nonauthorizing fanout bundle; there is no receipt/digest/body overload.

namespace kpb::measurement::phase_scope {
class ObservationOutputJoinAuthority;
}

namespace kpb::measurement::observation_fanout {

class OpenObservationFanoutAuthority;

class ObservationBarrierFanoutBridge final {
    ObservationBarrierFanoutBridge() = delete;
public:
    static OpenObservationFanoutAuthority prepare(
        phase_scope::ObservationOutputJoinAuthority&&);
};

} // namespace kpb::measurement::observation_fanout
