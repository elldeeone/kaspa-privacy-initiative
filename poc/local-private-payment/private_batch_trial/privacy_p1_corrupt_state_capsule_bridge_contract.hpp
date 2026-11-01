#pragma once

#include <memory>

namespace kpi::mpc::financial::registered_driver {
class RegisteredP1StateCapsuleChildDispositionBridge;
}

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateCapsuleAuthority;
class P1AuthenticatedChildStateDispositionAuthority;

// Opaque one-shot projection of a closed child capsule. Only the capsule TU
// can construct it and only the authenticated channel bridge can consume it.
// It exposes no descriptor, body, digest, size, status, or completion getter.
class P1CorruptStateCapsuleChildDispositionResidual final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1CorruptStateCapsuleChildDispositionResidual(
        std::unique_ptr<Storage>);
    friend class P1CorruptStateCapsuleAuthority;
    friend class ::kpi::mpc::financial::registered_driver::
        RegisteredP1StateCapsuleChildDispositionBridge;
public:
    P1CorruptStateCapsuleChildDispositionResidual(
        const P1CorruptStateCapsuleChildDispositionResidual&) = delete;
    P1CorruptStateCapsuleChildDispositionResidual& operator=(
        const P1CorruptStateCapsuleChildDispositionResidual&) = delete;
    P1CorruptStateCapsuleChildDispositionResidual(
        P1CorruptStateCapsuleChildDispositionResidual&&) noexcept;
    P1CorruptStateCapsuleChildDispositionResidual& operator=(
        P1CorruptStateCapsuleChildDispositionResidual&&) = delete;
    ~P1CorruptStateCapsuleChildDispositionResidual();
};
}

namespace kpi::mpc::financial::registered_driver {

class RegisteredP1StateArchiveChildRoundAuthority;
class RegisteredP1StateArchiveChildTerminalAuthority;
class RegisteredP1StateArchiveParentRoundAuthority;

// Complete, dependency-neutral friend contract for the sole future CHILD-side
// consumer of the opaque observer-v5 state capsule. A C++ authority cannot be
// transferred across the process boundary. This bridge will eventually burn
// the capsule into an authenticated fixed-format child disposition carried by
// the role-completion transport. It intentionally has no mint operation yet.
class RegisteredP1StateCapsuleChildDispositionBridge final {
public:
    RegisteredP1StateCapsuleChildDispositionBridge() = delete;

    // Failure burns both child inputs and yields no parent authority.
    static void send_terminal_noexcept(
        RegisteredP1StateArchiveChildTerminalAuthority&&,
        kpb::measurement::p1_state_capsule::
            P1CorruptStateCapsuleAuthority&&) noexcept;

    // Kernel-authenticated receive is the sole parent-token minter.
    static kpb::measurement::p1_state_capsule::
        P1AuthenticatedChildStateDispositionAuthority
    receive_terminal(
        RegisteredP1StateArchiveParentRoundAuthority&&);
};

} // namespace kpi::mpc::financial::registered_driver
