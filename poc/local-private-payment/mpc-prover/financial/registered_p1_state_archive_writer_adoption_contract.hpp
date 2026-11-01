#pragma once

// Dependency-neutral opaque writer adoption.  It carries one already
// authenticated role-1 O_WRONLY topology description into the capsule TU;
// no descriptor, fingerprint, identity, role, round, or status is exposed.

#include "registered_p1_state_archive_scm_contract.hpp"

#include <memory>

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateCapsulePlanAuthority;
class P1CorruptStateRecorderAuthority;
#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
struct StaticStateCapsulePlan;
#endif
}

namespace kpi::mpc::financial::registered_driver {

class P1StateArchiveWriterAdoptionAuthority;

// Complete before the writer grants friendship.  Possessing this type name
// alone conveys no authority: begin still requires both opaque rvalues.
class P1StateArchiveWriterAdoptionConsumerBridge final {
public:
    P1StateArchiveWriterAdoptionConsumerBridge() = delete;
    static kpb::measurement::p1_state_capsule::
        P1CorruptStateRecorderAuthority begin(
            kpb::measurement::p1_state_capsule::
                P1CorruptStateCapsulePlanAuthority&&,
            P1StateArchiveWriterAdoptionAuthority&&);
#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
    static kpb::measurement::p1_state_capsule::
        P1CorruptStateCapsulePlanAuthority test_only_bind_plan(
            kpb::measurement::p1_state_capsule::StaticStateCapsulePlan,
            const P1StateArchiveWriterAdoptionAuthority&,
            bool wrong_round,
            bool wrong_reservation);
#endif
};

class P1StateArchiveWriterAdoptionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1StateArchiveWriterAdoptionAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class RegisteredP1StateArchiveScmBridge;
    friend class P1StateArchiveWriterAdoptionConsumerBridge;
public:
    P1StateArchiveWriterAdoptionAuthority(
        const P1StateArchiveWriterAdoptionAuthority&) = delete;
    P1StateArchiveWriterAdoptionAuthority& operator=(
        const P1StateArchiveWriterAdoptionAuthority&) = delete;
    P1StateArchiveWriterAdoptionAuthority(
        P1StateArchiveWriterAdoptionAuthority&&) noexcept;
    P1StateArchiveWriterAdoptionAuthority& operator=(
        P1StateArchiveWriterAdoptionAuthority&&) = delete;
    ~P1StateArchiveWriterAdoptionAuthority();
};

} // namespace kpi::mpc::financial::registered_driver
