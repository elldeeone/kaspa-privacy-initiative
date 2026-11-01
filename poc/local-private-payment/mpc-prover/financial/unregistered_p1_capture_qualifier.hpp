#pragma once

#include "registered_roster_transport.hpp"
#include "Networking/CryptoPlayer.h"

#include <array>
#include <memory>
#include <string>

class Player;

namespace kpi::mpc {
namespace p1_capture { class P1CapturingPlayer; }

namespace financial::qualification {

struct ControlOnlyP1Selection {
    std::string scope;
    std::string classification;
    int fixed_fd;
    unsigned round;
    unsigned party;
    std::string attempt_id;
    std::string cohort_sha256;
    std::string financial_run_id;
    std::string capture_identity;
    std::string protocol_source_sha256;
    std::string protocol_build_sha256;
    std::string protocol_launch_sha256;
    std::string model_preimage_sha256;
    std::string query_store_preimage_sha256;
    std::string scalar_capture_manifest_sha256;
    bool actual_authority_requested;
};

struct ControlOnlyP1Status {
    std::string schema;
    std::string scope;
    std::string classification;
    bool configured;
    bool registered_driver_integrated;
    bool producer_integrated;
    bool launch_authorized;
    bool actual_receipt_enabled;
    bool serialized_receipt_is_authority;
};

// TLS transport for the unfunded control run. Its all-zero registered binding
// is deliberately non-admissible to RegisteredService; only the exact public
// certificate roster is retained across MP-SPDZ forks.
class ControlOnlyUnregisteredCryptoPlayer final
    : public ::CryptoPlayer, public financial::RosterPinnedPlayer {
    std::array<history::Digest, 3> roster_;
    financial::RegisteredRosterBinding rejected_registered_binding_{};

    ControlOnlyUnregisteredCryptoPlayer(
        const ::Names&, std::array<history::Digest, 3>, std::string id);

public:
    ControlOnlyUnregisteredCryptoPlayer(
        const ::Names&, std::array<history::Digest, 3>);
    const std::array<history::Digest, 3>&
        authenticated_roster() const noexcept override;
    const financial::RegisteredRosterBinding&
        authenticated_registered_binding() const noexcept override;
    ::Player* fresh_fork(std::string suffix) override;
};

// This capability exists only in the separately compiled, unfunded qualifier.
// It is evidence plumbing, not a substitute for the registered parent capture
// plan and cannot be serialized back into execution authority.
class ControlOnlyUnregisteredP1Capture final {
    ControlOnlyP1Selection selection_;
    bool live_ = true;

    explicit ControlOnlyUnregisteredP1Capture(ControlOnlyP1Selection);

public:
    ControlOnlyUnregisteredP1Capture(
        const ControlOnlyUnregisteredP1Capture&) = delete;
    ControlOnlyUnregisteredP1Capture& operator=(
        const ControlOnlyUnregisteredP1Capture&) = delete;
    ControlOnlyUnregisteredP1Capture(
        ControlOnlyUnregisteredP1Capture&&) noexcept = default;
    ControlOnlyUnregisteredP1Capture& operator=(
        ControlOnlyUnregisteredP1Capture&&) = delete;

    static ControlOnlyUnregisteredP1Capture admit(ControlOnlyP1Selection);
    ControlOnlyP1Status status() const;
    std::unique_ptr<p1_capture::P1CapturingPlayer> begin(::Player&);
};

} // namespace financial::qualification
} // namespace kpi::mpc
