#pragma once

// Heavy adapter for splitting one authenticated parent capture plan into the
// early P1 Player-capture capability and the later per-party session residual.
// The lightweight driver/session headers do not depend on MP-SPDZ Player.

#include "registered_driver_bridge.hpp"
#include "../p1_capturing_player.hpp"

#include <optional>

namespace kpi::mpc::financial::registered_driver {

class P1CapturePlanSplit final {
    std::optional<CapturePlanAuthority> session_;
    std::optional<p1_capture::P1PlayerCaptureAuthority> p1_;
    P1CapturePlanSplit(
        CapturePlanAuthority&&,
        std::optional<p1_capture::P1PlayerCaptureAuthority>&&);
    friend class CapturePlanAuthorityBridge;
public:
    P1CapturePlanSplit(const P1CapturePlanSplit&) = delete;
    P1CapturePlanSplit& operator=(const P1CapturePlanSplit&) = delete;
    P1CapturePlanSplit(P1CapturePlanSplit&&) noexcept = default;
    P1CapturePlanSplit& operator=(P1CapturePlanSplit&&) = delete;

    bool has_p1_player_capture() const noexcept { return p1_.has_value(); }
    CapturePlanAuthority take_session();
    p1_capture::P1PlayerCaptureAuthority take_p1_player_capture();
};

} // namespace kpi::mpc::financial::registered_driver
