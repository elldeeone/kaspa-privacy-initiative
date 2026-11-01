#pragma once

// Source-owned C1 controller/launcher/terminal evidence recorders.
//
// These types are the typed minter core, not selected-runtime wiring.  The
// public recorders consume only opaque source authorities; production has no
// constructor for those authorities yet.  A caller therefore cannot submit
// PublicC1* aggregates, claimed digests, paths, file descriptors, exit codes,
// or event dictionaries.  Until selected controller/launcher adapters mint
// the opaque sources from real process boundaries and share one immutable,
// sealed source snapshot with the actual consumer, the repository remains
// CONFIGURED0 and no actual C1 evidence exists.

#include "c1_registered_plan_route_bridge.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace kpb::measurement::c1_capture {

enum class C1ControllerStage : std::uint8_t {
    Invoice = 0,
    Pay = 1,
    Scan = 2,
};

class C1ControllerSelectionSourceAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit C1ControllerSelectionSourceAuthority(std::unique_ptr<Storage>);
    friend class RegisteredC1ControllerSelectionCallsite;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    friend class RegisteredC1RouteMinterTestFixture;
#endif
public:
    C1ControllerSelectionSourceAuthority(
        const C1ControllerSelectionSourceAuthority&) = delete;
    C1ControllerSelectionSourceAuthority& operator=(
        const C1ControllerSelectionSourceAuthority&) = delete;
    C1ControllerSelectionSourceAuthority(
        C1ControllerSelectionSourceAuthority&&) noexcept;
    C1ControllerSelectionSourceAuthority& operator=(
        C1ControllerSelectionSourceAuthority&&) = delete;
    ~C1ControllerSelectionSourceAuthority();
};

class C1Fd31OfferParseSourceAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit C1Fd31OfferParseSourceAuthority(std::unique_ptr<Storage>);
    friend class RegisteredC1TerminalCallsite;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    friend class RegisteredC1RouteMinterTestFixture;
#endif
public:
    C1Fd31OfferParseSourceAuthority(
        const C1Fd31OfferParseSourceAuthority&) = delete;
    C1Fd31OfferParseSourceAuthority& operator=(
        const C1Fd31OfferParseSourceAuthority&) = delete;
    C1Fd31OfferParseSourceAuthority(
        C1Fd31OfferParseSourceAuthority&&) noexcept;
    C1Fd31OfferParseSourceAuthority& operator=(
        C1Fd31OfferParseSourceAuthority&&) = delete;
    ~C1Fd31OfferParseSourceAuthority();
};

class C1ControllerTerminalSourceAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit C1ControllerTerminalSourceAuthority(std::unique_ptr<Storage>);
    friend class RegisteredC1TerminalCallsite;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    friend class RegisteredC1RouteMinterTestFixture;
#endif
public:
    C1ControllerTerminalSourceAuthority(
        const C1ControllerTerminalSourceAuthority&) = delete;
    C1ControllerTerminalSourceAuthority& operator=(
        const C1ControllerTerminalSourceAuthority&) = delete;
    C1ControllerTerminalSourceAuthority(
        C1ControllerTerminalSourceAuthority&&) noexcept;
    C1ControllerTerminalSourceAuthority& operator=(
        C1ControllerTerminalSourceAuthority&&) = delete;
    ~C1ControllerTerminalSourceAuthority();
};

class C1ObservedRouteSourceAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit C1ObservedRouteSourceAuthority(std::unique_ptr<Storage>);
    friend class RegisteredC1TerminalCallsite;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    friend class RegisteredC1RouteMinterTestFixture;
#endif
public:
    C1ObservedRouteSourceAuthority(
        const C1ObservedRouteSourceAuthority&) = delete;
    C1ObservedRouteSourceAuthority& operator=(
        const C1ObservedRouteSourceAuthority&) = delete;
    C1ObservedRouteSourceAuthority(
        C1ObservedRouteSourceAuthority&&) noexcept;
    C1ObservedRouteSourceAuthority& operator=(
        C1ObservedRouteSourceAuthority&&) = delete;
    ~C1ObservedRouteSourceAuthority();
};

class C1Fd31CompletionSourceAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit C1Fd31CompletionSourceAuthority(std::unique_ptr<Storage>);
    friend class RegisteredC1TerminalCallsite;
#ifdef KPB_REGISTERED_C1_PLAN_ROUTE_TEST_SETUP
    friend class RegisteredC1RouteMinterTestFixture;
#endif
public:
    C1Fd31CompletionSourceAuthority(
        const C1Fd31CompletionSourceAuthority&) = delete;
    C1Fd31CompletionSourceAuthority& operator=(
        const C1Fd31CompletionSourceAuthority&) = delete;
    C1Fd31CompletionSourceAuthority(
        C1Fd31CompletionSourceAuthority&&) noexcept;
    C1Fd31CompletionSourceAuthority& operator=(
        C1Fd31CompletionSourceAuthority&&) = delete;
    ~C1Fd31CompletionSourceAuthority();
};

class RegisteredC1SelectedRound final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredC1SelectedRound(std::unique_ptr<Storage>);
    friend class RegisteredC1ControllerSelectionCallsite;
    friend class RegisteredC1RuntimeCallsiteBridge;
public:
    RegisteredC1SelectedRound(const RegisteredC1SelectedRound&) = delete;
    RegisteredC1SelectedRound& operator=(
        const RegisteredC1SelectedRound&) = delete;
    RegisteredC1SelectedRound(RegisteredC1SelectedRound&&) noexcept;
    RegisteredC1SelectedRound& operator=(RegisteredC1SelectedRound&&) =
        delete;
    ~RegisteredC1SelectedRound();
};

class RegisteredC1RoundRouteEvidenceAuthority final {
public:
    // Incomplete outside the implementation.  Publicly naming the opaque
    // storage type does not expose a constructor, fields, or evidence getter.
    struct Storage;
private:
    std::unique_ptr<Storage> storage_;
    explicit RegisteredC1RoundRouteEvidenceAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredC1TerminalCallsite;
    friend class RegisteredC1TwoRoundRouteEvidenceJoiner;
public:
    RegisteredC1RoundRouteEvidenceAuthority(
        const RegisteredC1RoundRouteEvidenceAuthority&) = delete;
    RegisteredC1RoundRouteEvidenceAuthority& operator=(
        const RegisteredC1RoundRouteEvidenceAuthority&) = delete;
    RegisteredC1RoundRouteEvidenceAuthority(
        RegisteredC1RoundRouteEvidenceAuthority&&) noexcept;
    RegisteredC1RoundRouteEvidenceAuthority& operator=(
        RegisteredC1RoundRouteEvidenceAuthority&&) = delete;
    ~RegisteredC1RoundRouteEvidenceAuthority();
};

class RegisteredC1TerminalAdmissionSplit final {
    std::optional<C1PostcaptureAdmissionAuthority> admission_;
    std::optional<RegisteredC1RoundRouteEvidenceAuthority> route_evidence_;
    RegisteredC1TerminalAdmissionSplit(
        C1PostcaptureAdmissionAuthority&&,
        RegisteredC1RoundRouteEvidenceAuthority&&);
    friend class RegisteredC1TerminalCallsite;
public:
    RegisteredC1TerminalAdmissionSplit(
        const RegisteredC1TerminalAdmissionSplit&) = delete;
    RegisteredC1TerminalAdmissionSplit& operator=(
        const RegisteredC1TerminalAdmissionSplit&) = delete;
    RegisteredC1TerminalAdmissionSplit(
        RegisteredC1TerminalAdmissionSplit&&) noexcept = default;
    RegisteredC1TerminalAdmissionSplit& operator=(
        RegisteredC1TerminalAdmissionSplit&&) = delete;

    C1PostcaptureAdmissionAuthority take_admission();
    RegisteredC1RoundRouteEvidenceAuthority take_route_evidence();
};

class RegisteredC1TwoRoundRouteEvidenceAuthority final {
    struct Storage;
    // Storage retains both admitted round authorities, not only a caller-
    // reproducible digest.  Future consumers must be explicitly friended.
    std::unique_ptr<Storage> storage_;
    explicit RegisteredC1TwoRoundRouteEvidenceAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredC1TwoRoundRouteEvidenceJoiner;
public:
    RegisteredC1TwoRoundRouteEvidenceAuthority(
        const RegisteredC1TwoRoundRouteEvidenceAuthority&) = delete;
    RegisteredC1TwoRoundRouteEvidenceAuthority& operator=(
        const RegisteredC1TwoRoundRouteEvidenceAuthority&) = delete;
    RegisteredC1TwoRoundRouteEvidenceAuthority(
        RegisteredC1TwoRoundRouteEvidenceAuthority&&) noexcept;
    RegisteredC1TwoRoundRouteEvidenceAuthority& operator=(
        RegisteredC1TwoRoundRouteEvidenceAuthority&&) = delete;
    ~RegisteredC1TwoRoundRouteEvidenceAuthority();
};

class RegisteredC1TwoRoundRouteEvidenceJoiner final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
public:
    RegisteredC1TwoRoundRouteEvidenceJoiner();
    RegisteredC1TwoRoundRouteEvidenceJoiner(
        const RegisteredC1TwoRoundRouteEvidenceJoiner&) = delete;
    RegisteredC1TwoRoundRouteEvidenceJoiner& operator=(
        const RegisteredC1TwoRoundRouteEvidenceJoiner&) = delete;
    RegisteredC1TwoRoundRouteEvidenceJoiner(
        RegisteredC1TwoRoundRouteEvidenceJoiner&&) noexcept;
    RegisteredC1TwoRoundRouteEvidenceJoiner& operator=(
        RegisteredC1TwoRoundRouteEvidenceJoiner&&) = delete;
    ~RegisteredC1TwoRoundRouteEvidenceJoiner();

    void accept(RegisteredC1RoundRouteEvidenceAuthority&&);
    RegisteredC1TwoRoundRouteEvidenceAuthority finish() &&;
};

} // namespace kpb::measurement::c1_capture
