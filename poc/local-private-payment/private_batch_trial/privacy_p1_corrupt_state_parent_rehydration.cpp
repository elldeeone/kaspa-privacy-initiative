#include "privacy_p1_corrupt_state_parent_rehydration.hpp"

namespace kpb::measurement::p1_state_capsule {

// The authenticated child disposition storage and its sole constructor live
// in the SCM bridge TU.  This file still cannot mint one.
struct P1ParentRehydratedStateCapsuleAuthority::Storage {};

P1ParentRehydratedStateCapsuleAuthority::
P1ParentRehydratedStateCapsuleAuthority(
        P1ParentRehydratedStateCapsuleAuthority&&) noexcept = default;
P1ParentRehydratedStateCapsuleAuthority::
~P1ParentRehydratedStateCapsuleAuthority() = default;

} // namespace kpb::measurement::p1_state_capsule
