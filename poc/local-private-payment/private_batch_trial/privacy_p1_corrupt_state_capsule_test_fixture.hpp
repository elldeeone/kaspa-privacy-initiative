#pragma once

#include "privacy_p1_corrupt_state_capsule_authority.hpp"

#ifndef KPB_P1_STATE_CAPSULE_TEST_SETUP
#error "P1 state-capsule fixture is control-only"
#endif

namespace kpb::measurement::p1_state_capsule::test_fixture {

// Derives the control plan solely from a genuine opaque writer. No caller
// binding, digest, status, round, or reservation field is accepted.
P1CorruptStateCapsulePlanAuthority matching_plan_for_adoption(
    const kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionAuthority&);

// Builds an actual recorder/archive and closes it UNAVAILABLE. The caller can
// select only the protocol round; no binding, state, status, digest or archive
// metadata is caller-authored or returned separately.
P1CorruptStateCapsuleAuthority closed_unavailable(unsigned round);

// Consumes one genuine topology writer, derives round and reservation identity
// privately, writes a real PlayerAllocation prefix record, and closes
// UNAVAILABLE. The caller supplies no binding, digest, status, or body.
P1CorruptStateCapsuleAuthority closed_unavailable_adopting(
    kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionAuthority&&);

bool wrong_round_adoption_refused(
    kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionAuthority&&);
bool wrong_reservation_adoption_refused(
    kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionAuthority&&);

} // namespace kpb::measurement::p1_state_capsule::test_fixture
