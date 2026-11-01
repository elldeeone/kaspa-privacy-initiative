#include "registered_p1_capture_bridge.hpp"
#include "../p1_scalar_capture_manifest.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {
[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
} // namespace

P1CapturePlanSplit::P1CapturePlanSplit(
        CapturePlanAuthority&& session,
        std::optional<p1_capture::P1PlayerCaptureAuthority>&& p1)
    : session_(std::move(session)), p1_(std::move(p1)) {}

CapturePlanAuthority P1CapturePlanSplit::take_session() {
    need(session_.has_value());
    auto result = std::move(*session_);
    session_.reset();
    return result;
}

p1_capture::P1PlayerCaptureAuthority
P1CapturePlanSplit::take_p1_player_capture() {
    need(p1_.has_value());
    auto result = std::move(*p1_);
    p1_.reset();
    return result;
}

P1CapturePlanSplit CapturePlanAuthorityBridge::split_for_driver(
        CapturePlanAuthority&& authority,
        const CompiledDriverSelection& driver) {
    try {
        need(authority.live_.exchange(false));
        require_valid(authority);
        require_valid(driver);
        const auto& plan = authority.value_;
        const auto& selected = driver.value_;
        need(authority.scope_ == CapturePlanAuthority::Scope::Parent &&
             authority.computing_role_ == 3 && selected.role < 3 &&
             plan.source_identity == selected.capture_source_identity &&
             plan.build_identity == selected.capture_build_identity &&
             plan.launcher_identity == selected.capture_launcher_identity &&
             plan.model_preimage_identity == selected.model_preimage_identity &&
             plan.query_store_preimage_identity ==
                 selected.query_store_preimage_identity &&
             plan.scalar_capture_manifest_identity ==
                 selected.scalar_capture_manifest_identity &&
             identity_registry::hex(plan.scalar_capture_manifest_identity) ==
                 p1_capture::SCALAR_CAPTURE_MANIFEST_SHA256);

        CapturePlanAuthority residual(
            plan, CapturePlanAuthority::Scope::SessionResidual,
            selected.role);
        std::optional<p1_capture::P1PlayerCaptureAuthority> p1;
        if (selected.role == 1) {
            const int fd = plan.round == 1 ? plan.fixed_fds[3]
                                           : plan.fixed_fds[8];
            need(fd == (plan.round == 1 ? 23 : 28));
            p1.emplace(p1_capture::P1PlayerCaptureAuthority(
                fd, plan.round,
                p1_capture::RunBinding{
                    .attempt_id = plan.capture_attempt_id,
                    .cohort_sha256 = identity_registry::hex(plan.cohort),
                    .financial_run_id = identity_registry::hex(plan.run),
                    .capture_identity = plan.capture_identity,
                    .protocol_source_sha256 =
                        identity_registry::hex(plan.source_identity),
                    .protocol_build_sha256 =
                        identity_registry::hex(plan.build_identity),
                    .protocol_launch_sha256 =
                        identity_registry::hex(plan.launcher_identity),
                    .model_preimage_sha256 =
                        identity_registry::hex(plan.model_preimage_identity),
                    .query_store_preimage_sha256 = identity_registry::hex(
                        plan.query_store_preimage_identity),
                    .scalar_capture_manifest_sha256 = identity_registry::hex(
                        plan.scalar_capture_manifest_identity),
                }));
        }
        return P1CapturePlanSplit(std::move(residual), std::move(p1));
    } catch (...) { refuse(); }
}

} // namespace kpi::mpc::financial::registered_driver
