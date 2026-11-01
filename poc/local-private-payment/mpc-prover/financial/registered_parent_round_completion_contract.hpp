#pragma once

// Complete declaration of the only parent-side round join allowed to inspect
// the retained projection authority.  Defining the class here, before private
// friendship is granted, prevents a hostile translation unit from supplying a
// same-named friend implementation.

namespace kpi::mpc::financial::registered_driver {

class ParentObservedRegisteredPartyResult;
class ParentRoleChildren;
class RegisteredParentPendingRoundCompletionAuthority;
class RegisteredParentRoundCompletionAuthority;
class RegisteredParentTrialCompletionAuthority;
class RegisteredPersistentRoleSession;
namespace projection_route { class ParentRetainedProjectionAuthority; }

class RegisteredParentRoundCompletionBridge final {
    RegisteredParentRoundCompletionBridge() = delete;
public:
    static RegisteredParentRoundCompletionAuthority join(
        projection_route::ParentRetainedProjectionAuthority&&,
        ParentObservedRegisteredPartyResult&& role0,
        ParentObservedRegisteredPartyResult&& role1,
        ParentObservedRegisteredPartyResult&& role2,
        ParentRoleChildren&);
    static RegisteredParentPendingRoundCompletionAuthority defer(
        projection_route::ParentRetainedProjectionAuthority&&,
        ParentObservedRegisteredPartyResult&& role0,
        ParentObservedRegisteredPartyResult&& role1,
        ParentObservedRegisteredPartyResult&& role2,
        ParentRoleChildren&);
};

class RegisteredParentTrialCompletionBridge final {
    RegisteredParentTrialCompletionBridge() = delete;
public:
    static RegisteredParentTrialCompletionAuthority join(
        RegisteredParentPendingRoundCompletionAuthority&& round1,
        RegisteredParentPendingRoundCompletionAuthority&& round2,
        RegisteredPersistentRoleSession&);
};

} // namespace kpi::mpc::financial::registered_driver
