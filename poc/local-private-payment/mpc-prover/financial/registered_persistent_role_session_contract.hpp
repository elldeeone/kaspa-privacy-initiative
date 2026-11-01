#pragma once

// Complete capability contract for one forked set of three MPC children that
// executes both financial rounds.  Round 2 is dormant until the parent calls
// activate_round2 after round 1 has been closed into a deferred authority.
// Defining this bridge before friendship prevents hostile exact-name friends.

namespace kpi::mpc::financial::registered_driver {

class ParentRoleChildren;
class ParentRoleForkPlanAuthority;
class RegisteredPreIdentityPersistentRoleChildProgram;
class RegisteredPersistentRoleChildProgram;
class RegisteredPersistentRoleProcessReservation;
class RegisteredPersistentRoleSession;
namespace detail { class PersistentRoleReservationAbortEvidence; }

class RegisteredParentPersistentRoleFork final {
    RegisteredParentPersistentRoleFork() = delete;
public:
    // Phase 1 consumes no trial, round, topology or fresh-owner authority.
    // The three generic children block on authenticated activation channels
    // and are pinned by parent-only pidfds before this returns.
    static RegisteredPersistentRoleProcessReservation reserve(
        RegisteredPreIdentityPersistentRoleChildProgram&);
    // Explicitly closes an unused reservation and retains exact normalized
    // exit evidence for all three children. Activation failures use the same
    // typed drain internally; no caller status or raw PID is accepted.
    static detail::PersistentRoleReservationAbortEvidence abort(
        RegisteredPersistentRoleProcessReservation&&);
    static RegisteredPersistentRoleSession launch(
        ParentRoleForkPlanAuthority&& round1,
        ParentRoleForkPlanAuthority&& round2,
        RegisteredPersistentRoleChildProgram&);
    static ParentRoleChildren& round1(
        RegisteredPersistentRoleSession&);
    static ParentRoleChildren& activate_round2(
        RegisteredPersistentRoleSession&);
};

} // namespace kpi::mpc::financial::registered_driver
