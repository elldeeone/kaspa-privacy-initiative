#pragma once

#include "privacy_p1_corrupt_state_capsule_bridge_contract.hpp"
#include "privacy_p1_corrupt_state_parent_rehydration_contract.hpp"

#include <memory>

namespace kpb::measurement::p1_state_capsule {

// Parent-side result of authenticating a role-child terminal disposition. The
// source bridge is intentionally absent: generic bytes, status booleans,
// digests, and HELLO fields cannot construct it.
class P1AuthenticatedChildStateDispositionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1AuthenticatedChildStateDispositionAuthority(
        std::unique_ptr<Storage>);
    friend class kpi::mpc::financial::registered_driver::
        RegisteredP1StateCapsuleChildDispositionBridge;
    friend class kpi::mpc::financial::registered_driver::
        RegisteredP1StateCapsuleParentRehydrationBridge;

public:
    P1AuthenticatedChildStateDispositionAuthority(
        const P1AuthenticatedChildStateDispositionAuthority&) = delete;
    P1AuthenticatedChildStateDispositionAuthority& operator=(
        const P1AuthenticatedChildStateDispositionAuthority&) = delete;
    P1AuthenticatedChildStateDispositionAuthority(
        P1AuthenticatedChildStateDispositionAuthority&&) noexcept;
    P1AuthenticatedChildStateDispositionAuthority& operator=(
        P1AuthenticatedChildStateDispositionAuthority&&) = delete;
    ~P1AuthenticatedChildStateDispositionAuthority();
};

// Opaque parent-side authority. It can exist only after the future bridge has
// independently parsed and replayed both exact state archives and matched the
// dispositions, topology residual, and pidfd-bound completion evidence.
class P1ParentRehydratedStateCapsuleAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1ParentRehydratedStateCapsuleAuthority(
        std::unique_ptr<Storage>);
    friend class kpi::mpc::financial::registered_driver::
        RegisteredP1StateCapsuleParentRehydrationBridge;

public:
    P1ParentRehydratedStateCapsuleAuthority(
        const P1ParentRehydratedStateCapsuleAuthority&) = delete;
    P1ParentRehydratedStateCapsuleAuthority& operator=(
        const P1ParentRehydratedStateCapsuleAuthority&) = delete;
    P1ParentRehydratedStateCapsuleAuthority(
        P1ParentRehydratedStateCapsuleAuthority&&) noexcept;
    P1ParentRehydratedStateCapsuleAuthority& operator=(
        P1ParentRehydratedStateCapsuleAuthority&&) = delete;
    ~P1ParentRehydratedStateCapsuleAuthority();
};

struct ParentRehydrationSourceStatus {
    bool exact_conjunctive_type_contract{};
    bool raw_fd_or_path_overload_absent{};
    bool raw_digest_or_status_overload_absent{};
    bool authenticated_child_disposition_source{};
    bool topology_archive_residual_consumer{};
    bool pidfd_completion_consumer{};
    bool independent_archive_grammar_parser{};
    bool independent_state_replay{};
    bool exact_two_round_order_join{};
    bool parent_rehydration_minter{};
    bool configured{};
};

inline constexpr ParentRehydrationSourceStatus kParentRehydrationSourceStatus{
    .exact_conjunctive_type_contract = true,
    .raw_fd_or_path_overload_absent = true,
    .raw_digest_or_status_overload_absent = true,
    .authenticated_child_disposition_source = false,
    .topology_archive_residual_consumer = false,
    .pidfd_completion_consumer = false,
    .independent_archive_grammar_parser = false,
    .independent_state_replay = false,
    .exact_two_round_order_join = false,
    .parent_rehydration_minter = false,
    .configured = false,
};

} // namespace kpb::measurement::p1_state_capsule
