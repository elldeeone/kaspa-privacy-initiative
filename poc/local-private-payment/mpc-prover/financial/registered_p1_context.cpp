#include "registered_p1_context.hpp"

#include "registered_roster_transport.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {
[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
} // namespace

std::unique_ptr<RegisteredP1Context> RegisteredP1Context::begin(
        Player& upstream, const CompiledDriverSelection& driver,
        CapturePlanAuthority&& parent_capture_plan,
        MascotContext::PublicStage stage) {
    try {
        // This is deliberately first: even a wrong Player burns the parent
        // authority and its derived children cannot escape for a retry.
        auto split = CapturePlanAuthorityBridge::split_for_driver(
            std::move(parent_capture_plan), driver);
        auto result = std::unique_ptr<RegisteredP1Context>(
            new RegisteredP1Context(upstream));
        result->session_.emplace(split.take_session());

        const auto& selected = driver.public_selection();
        need(selected.role < 3 &&
             upstream.my_num() == static_cast<int>(selected.role) &&
             upstream.num_players() == 3 && upstream.is_encrypted() &&
             dynamic_cast<RosterPinnedPlayer*>(&upstream) != nullptr);

        if (selected.role == 1) {
            need(split.has_p1_player_capture());
            result->p1_player_ = p1_capture::P1CapturingPlayer::begin(
                upstream, split.take_p1_player_capture());
            result->p1_seams_ =
                std::make_unique<p1_capture::P1TypedCaptureSeams>(
                    *result->p1_player_);
            // The decorated Player and typed seams exist before setup begins,
            // so setup/fresh_fork traffic cannot bypass the P1 recorder.
            result->context_ = std::make_unique<MascotContext>(
                *result->p1_player_, *result->p1_seams_, stage);
        } else {
            need(!split.has_p1_player_capture());
            result->context_ = std::make_unique<MascotContext>(upstream, stage);
        }
        return result;
    } catch (...) {
        refuse();
    }
}

MascotContext& RegisteredP1Context::context() {
    need(context_ != nullptr);
    context_->require_healthy();
    return *context_;
}

CapturePlanAuthority RegisteredP1Context::take_session() {
    need(context_ != nullptr && session_.has_value());
    auto result = std::move(*session_);
    session_.reset();
    return result;
}

} // namespace kpi::mpc::financial::registered_driver
