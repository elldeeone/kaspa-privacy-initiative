#include "unregistered_p1_capture_qualifier.hpp"
#include "../p1_capturing_player.hpp"

#if !defined(KPI_P1_UNREGISTERED_QUALIFIER) || \
    KPI_P1_UNREGISTERED_QUALIFIER != 1
#error "Control-only P1 qualifier requires its separate compile selection"
#endif

#include <cctype>
#include <stdexcept>
#include <utility>

namespace kpi::mpc::financial::qualification {
namespace {
[[noreturn]] void refuse() {
    throw p1_capture::CaptureRefused();
}

void need(bool value) {
    if (!value) refuse();
}

bool word(const std::string& value) {
    if (value.size() != 64) return false;
    for (const unsigned char byte : value)
        if (!std::isdigit(byte) && !(byte >= 'a' && byte <= 'f'))
            return false;
    return true;
}

bool uuid_v4(const std::string& value) {
    if (value.size() != 36 || value[14] != '4' ||
        std::string("89ab").find(value[19]) == std::string::npos)
        return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-') return false;
        } else if (!std::isdigit(static_cast<unsigned char>(value[index])) &&
                   !(value[index] >= 'a' && value[index] <= 'f')) {
            return false;
        }
    }
    return true;
}
} // namespace

ControlOnlyUnregisteredCryptoPlayer::ControlOnlyUnregisteredCryptoPlayer(
        const ::Names& names, std::array<history::Digest, 3> roster,
        std::string id)
    : ::CryptoPlayer(names, id), roster_(std::move(roster)) {}

ControlOnlyUnregisteredCryptoPlayer::ControlOnlyUnregisteredCryptoPlayer(
        const ::Names& names, std::array<history::Digest, 3> roster)
    : ControlOnlyUnregisteredCryptoPlayer(
          names, std::move(roster), "control-only-unregistered") {}

const std::array<history::Digest, 3>&
ControlOnlyUnregisteredCryptoPlayer::authenticated_roster() const noexcept {
    return roster_;
}

const financial::RegisteredRosterBinding&
ControlOnlyUnregisteredCryptoPlayer::authenticated_registered_binding()
        const noexcept {
    return rejected_registered_binding_;
}

::Player* ControlOnlyUnregisteredCryptoPlayer::fresh_fork(
        std::string suffix) {
    if (suffix.empty() || suffix.size() > 128)
        throw p1_capture::CaptureRefused();
    return new ControlOnlyUnregisteredCryptoPlayer(
        N, roster_, get_id() + "-" + suffix);
}

ControlOnlyUnregisteredP1Capture::ControlOnlyUnregisteredP1Capture(
        ControlOnlyP1Selection selection)
    : selection_(std::move(selection)) {}

ControlOnlyUnregisteredP1Capture
ControlOnlyUnregisteredP1Capture::admit(ControlOnlyP1Selection selection) {
    need(p1_capture::P1_CAPTURE_CONFIGURED == 0 &&
         selection.scope ==
            "PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY" &&
         selection.classification == "CONTROL_ONLY_UNREGISTERED" &&
         !selection.actual_authority_requested && selection.party == 1 &&
         (selection.round == 1 || selection.round == 2) &&
         selection.fixed_fd == (selection.round == 1 ? 23 : 28) &&
         uuid_v4(selection.attempt_id) &&
         uuid_v4(selection.capture_identity) &&
         word(selection.cohort_sha256) && word(selection.financial_run_id) &&
         word(selection.protocol_source_sha256) &&
         word(selection.protocol_build_sha256) &&
         word(selection.protocol_launch_sha256) &&
         word(selection.model_preimage_sha256) &&
         word(selection.query_store_preimage_sha256) &&
         word(selection.scalar_capture_manifest_sha256) &&
         selection.scalar_capture_manifest_sha256 ==
             p1_capture::SCALAR_CAPTURE_MANIFEST_SHA256);
    return ControlOnlyUnregisteredP1Capture(std::move(selection));
}

ControlOnlyP1Status ControlOnlyUnregisteredP1Capture::status() const {
    return {
        .schema = "kpb-p1-control-only-unregistered-qualifier/v1",
        .scope = selection_.scope,
        .classification = selection_.classification,
        .configured = false,
        .registered_driver_integrated = false,
        .producer_integrated = false,
        .launch_authorized = false,
        .actual_receipt_enabled = false,
        .serialized_receipt_is_authority = false,
    };
}

std::unique_ptr<p1_capture::P1CapturingPlayer>
ControlOnlyUnregisteredP1Capture::begin(::Player& upstream) {
    need(live_);
    live_ = false;
    p1_capture::P1PlayerCaptureAuthority authority(
        selection_.fixed_fd, selection_.round,
        p1_capture::RunBinding{
            .attempt_id = selection_.attempt_id,
            .cohort_sha256 = selection_.cohort_sha256,
            .financial_run_id = selection_.financial_run_id,
            .capture_identity = selection_.capture_identity,
            .protocol_source_sha256 = selection_.protocol_source_sha256,
            .protocol_build_sha256 = selection_.protocol_build_sha256,
            .protocol_launch_sha256 = selection_.protocol_launch_sha256,
            .model_preimage_sha256 = selection_.model_preimage_sha256,
            .query_store_preimage_sha256 =
                selection_.query_store_preimage_sha256,
            .scalar_capture_manifest_sha256 =
                selection_.scalar_capture_manifest_sha256,
        });
    return p1_capture::P1CapturingPlayer::begin(
        upstream, std::move(authority));
}

} // namespace kpi::mpc::financial::qualification
