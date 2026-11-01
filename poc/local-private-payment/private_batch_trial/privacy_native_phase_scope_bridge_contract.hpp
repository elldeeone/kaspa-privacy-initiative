#pragma once

// Complete neutral contract for the only native Observer-output join. The
// implementation may read the already-authenticated sealed Observer FD62 body
// only through friendship granted by SealedChildOutputAuthority and must also
// consume the opaque native empirical residual. There is no fd/body/hash/
// count/receipt overload and no Python capability input.

namespace kpb::measurement::runtime_bridge {
class SealedChildOutputAuthority;
}

namespace kpb::measurement::empirical_result {
class NativeEmpiricalResultAuthority;
}

namespace kpb::measurement::phase_scope {

class ObservationOutputJoinAuthority;

class NativePrivacyPhaseScopeBridge final {
    NativePrivacyPhaseScopeBridge() = delete;
public:
    static ObservationOutputJoinAuthority validate_for_observation(
        runtime_bridge::SealedChildOutputAuthority&&,
        empirical_result::NativeEmpiricalResultAuthority&&);
};

} // namespace kpb::measurement::phase_scope
