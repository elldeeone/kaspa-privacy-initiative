#pragma once

// Heavy production boundary for the configured registered driver. It burns
// the authenticated parent capture plan before it constructs any MASCOT
// state. P1 is decorated first; P0/P2 never receive a P1 capability.

#include "registered_p1_capture_bridge.hpp"
#include "../auth_field.hpp"
#include "../p1_capture_seams.hpp"

#include <memory>
#include <optional>

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority;
class P1StateThreadEpochAuthority;
}

namespace kpi::mpc::financial::registered_driver {

class RegisteredRole1P1StateRecorderFacade;

class RegisteredP1Context final {
    Player& roster_pinned_upstream_;
    std::optional<CapturePlanAuthority> session_;
    std::unique_ptr<p1_capture::P1CapturingPlayer> p1_player_;
    std::unique_ptr<p1_capture::P1TypedCaptureSeams> p1_seams_;
    std::unique_ptr<MascotContext> context_;

    explicit RegisteredP1Context(Player& roster_pinned_upstream)
        : roster_pinned_upstream_(roster_pinned_upstream) {}

public:
    RegisteredP1Context(const RegisteredP1Context&) = delete;
    RegisteredP1Context& operator=(const RegisteredP1Context&) = delete;
    RegisteredP1Context(RegisteredP1Context&&) = delete;
    RegisteredP1Context& operator=(RegisteredP1Context&&) = delete;

    static std::unique_ptr<RegisteredP1Context> begin(
        Player& roster_pinned_upstream,
        const CompiledDriverSelection& selected_driver,
        CapturePlanAuthority&& parent_capture_plan,
        MascotContext::PublicStage public_stage = nullptr);

    // Source-only observer-v5 path. The roster/TLS adapter must already have
    // advanced the same recorder to TlsAndPlayerBound. This overload advances
    // exactly to ProtocolSetupStarted and gives MascotContext the sole owned
    // ContextAndRetry adapter before ProtocolSetup construction begins.
    static std::unique_ptr<RegisteredP1Context> begin(
        Player& roster_pinned_upstream,
        const CompiledDriverSelection& selected_driver,
        CapturePlanAuthority&& parent_capture_plan,
        RegisteredRole1P1StateRecorderFacade&,
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority&,
        MascotContext::PublicStage public_stage = nullptr);

    MascotContext& context();
    CapturePlanAuthority take_session();
    bool captures_p1() const noexcept { return p1_player_ != nullptr; }
};

} // namespace kpi::mpc::financial::registered_driver
