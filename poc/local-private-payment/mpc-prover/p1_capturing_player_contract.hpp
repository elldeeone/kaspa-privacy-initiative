#pragma once

#include "p1_capture_seams_contract.hpp"
#include "p1_capture_types.hpp"
#include "financial/registered_driver_bridge.hpp"
#include "financial/registered_roster_transport.hpp"
#include "financial/unregistered_p1_capture_qualifier.hpp"
#include "Networking/Player.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>

namespace kpi::mpc::p1_capture {

class P1CaptureStream;
class P1PlayerCaptureAuthority;

// Complete before P1CaptureStream grants friendship. This prevents a direct
// include of the stream contract from defining a lookalike player and gaining
// its private transport and poison operations.
class P1CapturingPlayer final : public Player,
                                public financial::RosterPinnedPlayer {
    Player& upstream_;
    financial::RosterPinnedPlayer& roster_;
    std::shared_ptr<P1CaptureStream> capture_;
    ForkId fork_;
    mutable std::mutex pending_mutex_;
    mutable std::set<std::pair<int, octetStream*>> pending_receives_;

    P1CapturingPlayer(Player& upstream,
                      std::shared_ptr<P1CaptureStream> capture,
                      ForkId fork);
    static void require_p1(Player& upstream);
    static financial::RosterPinnedPlayer& require_roster(Player& upstream);
    static void require_peer(int peer);
    friend class P1TypedCaptureSeams;

public:
    ~P1CapturingPlayer() override = default;
    P1CapturingPlayer(const P1CapturingPlayer&) = delete;
    P1CapturingPlayer& operator=(const P1CapturingPlayer&) = delete;

    static std::unique_ptr<P1CapturingPlayer> begin(
        Player& roster_pinned_upstream,
        P1PlayerCaptureAuthority&& authority);

    std::string get_id() const override;
    bool is_encrypted() override;
    const std::array<history::Digest, 3>&
        authenticated_roster() const noexcept override;
    const financial::RegisteredRosterBinding&
        authenticated_registered_binding() const noexcept override;
    void send_long(int peer, long value) const override;
    long receive_long(int peer) const override;
    void send_to_no_stats(int peer, const octetStream& value) const override;
    void receive_player_no_stats(int peer, octetStream& value) const override;
    std::size_t send_no_stats(int peer, const PlayerBuffer& value,
                              bool block) const override;
    std::size_t recv_no_stats(int peer, const PlayerBuffer& value,
                              bool block) const override;
    void exchange_no_stats(int peer, const octetStream& sent,
                           octetStream& received) const override;
    void pass_around_no_stats(const octetStream& sent,
                              octetStream& received,
                              int offset) const override;
    void Broadcast_Receive_no_stats(
        std::vector<octetStream>& values) const override;
    void send_receive_all_no_stats(
        const std::vector<std::vector<bool>>& channels,
        const std::vector<octetStream>& sent,
        std::vector<octetStream>& received) const override;
    void partial_broadcast_no_stats(
        const std::vector<bool>& senders,
        const std::vector<bool>& receivers,
        std::vector<octetStream>& values) const override;
    void request_receive(int peer, octetStream& value) const override;
    void wait_receive(int peer, octetStream& value) const override;
    Player* fresh_fork(std::string suffix) override;

#ifdef KPI_P1_CAPTURE_TEST_SETUP
    static std::unique_ptr<P1CapturingPlayer> test_only_begin(
        Player& upstream, int fixed_fd, unsigned round, RunBinding binding);
    P1CaptureStream& test_only_capture();
#endif
};

// One-shot production authority derived only by splitting the authenticated
// parent capture plan. It has no public constructor or raw-fd accessor.
class P1PlayerCaptureAuthority final {
    int fixed_fd_;
    unsigned round_;
    RunBinding binding_;
    std::atomic_bool live_{true};

    P1PlayerCaptureAuthority(
        int fixed_fd, unsigned round, RunBinding binding);
    friend class P1CapturingPlayer;
    friend class
        ::kpi::mpc::financial::registered_driver::CapturePlanAuthorityBridge;
    friend class ::kpi::mpc::financial::qualification::
        ControlOnlyUnregisteredP1Capture;

public:
    P1PlayerCaptureAuthority(const P1PlayerCaptureAuthority&) = delete;
    P1PlayerCaptureAuthority& operator=(
        const P1PlayerCaptureAuthority&) = delete;
    P1PlayerCaptureAuthority(P1PlayerCaptureAuthority&&) noexcept;
    P1PlayerCaptureAuthority& operator=(
        P1PlayerCaptureAuthority&&) = delete;
};

} // namespace kpi::mpc::p1_capture
