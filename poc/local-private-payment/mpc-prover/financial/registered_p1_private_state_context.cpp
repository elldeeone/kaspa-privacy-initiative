#include "registered_p1_context.hpp"

#include "registered_p1_state_archive_scm.hpp"
#include "registered_roster_transport.hpp"
#include "../../private_batch_trial/privacy_p1_corrupt_state_capsule_authority.hpp"

#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {
[[noreturn]] void refuse_private_state_context() {
    throw identity_registry::Refused();
}
void need_private_state_context(bool value) {
    if (!value) refuse_private_state_context();
}
} // namespace

std::unique_ptr<RegisteredP1Context> RegisteredP1Context::begin(
        Player& upstream, const CompiledDriverSelection& driver,
        CapturePlanAuthority&& parent_capture_plan,
        RegisteredRole1P1StateRecorderFacade& private_state,
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority& root_thread,
        MascotContext::PublicStage stage) {
    using namespace kpb::measurement::p1_state_capsule;
    try {
        auto split = CapturePlanAuthorityBridge::split_for_driver(
            std::move(parent_capture_plan), driver);
        auto result = std::unique_ptr<RegisteredP1Context>(
            new RegisteredP1Context(upstream));
        result->session_.emplace(split.take_session());

        const auto& selected = driver.public_selection();
        need_private_state_context(
            selected.role == 1 && upstream.my_num() == 1 &&
            upstream.num_players() == 3 && upstream.is_encrypted() &&
            dynamic_cast<RosterPinnedPlayer*>(&upstream) != nullptr &&
            split.has_p1_player_capture());
        result->p1_player_ = p1_capture::P1CapturingPlayer::begin(
            upstream, split.take_p1_player_capture());
        result->p1_seams_ =
            std::make_unique<p1_capture::P1TypedCaptureSeams>(
                *result->p1_player_);

        private_state.advance_phase(SourcePhase::ProtocolSetupStarted);
        auto mascot_secret_state =
            private_state.take_mascot_secret_state_adapter(root_thread);
        auto context_state = private_state.take_context_and_retry_adapter(
            root_thread);
        result->context_ = std::make_unique<MascotContext>(
            *result->p1_player_, *result->p1_seams_,
            std::move(mascot_secret_state), std::move(context_state), stage);
        return result;
    } catch (...) {
        refuse_private_state_context();
    }
}

} // namespace kpi::mpc::financial::registered_driver
