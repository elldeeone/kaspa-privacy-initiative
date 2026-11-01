#include "p1_capturing_player.hpp"
#include "financial/registered_roster_transport.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace kpi::mpc::p1_capture {
namespace {

std::span<const unsigned char> bytes(const octetStream& value) {
    return {value.get_data(), value.get_length()};
}

std::span<const unsigned char> prefix(
        const PlayerBuffer& value, std::size_t count) {
    if (count > value.size || (count > 0 && value.data == nullptr))
        throw CaptureRefused();
    return {value.data, count};
}

void need_shape(bool value) {
    if (!value) throw CaptureRefused();
}

} // namespace

P1PlayerCaptureAuthority::P1PlayerCaptureAuthority(
        int fixed_fd, unsigned round, RunBinding binding)
    : fixed_fd_(fixed_fd), round_(round), binding_(std::move(binding)) {}

P1PlayerCaptureAuthority::P1PlayerCaptureAuthority(
        P1PlayerCaptureAuthority&& other) noexcept
    : fixed_fd_(other.fixed_fd_), round_(other.round_),
      binding_(std::move(other.binding_)),
      live_(other.live_.exchange(false)) {}

void P1CapturingPlayer::require_p1(Player& upstream) {
    need_shape(upstream.my_num() == 1 && upstream.num_players() == 3 &&
               upstream.is_encrypted());
}

financial::RosterPinnedPlayer& P1CapturingPlayer::require_roster(
        Player& upstream) {
    auto* roster = dynamic_cast<financial::RosterPinnedPlayer*>(&upstream);
    need_shape(roster != nullptr);
    return *roster;
}

void P1CapturingPlayer::require_peer(int peer) {
    need_shape(peer >= 0 && peer < 3 && peer != 1);
}

P1CapturingPlayer::P1CapturingPlayer(
        Player& upstream, std::shared_ptr<P1CaptureStream> capture,
        ForkId fork)
    : Player(upstream.N), upstream_(upstream), roster_(require_roster(upstream)),
      capture_(std::move(capture)), fork_(fork) {
    require_p1(upstream_);
    need_shape(capture_ != nullptr);
}

std::unique_ptr<P1CapturingPlayer> P1CapturingPlayer::begin(
        Player& upstream, P1PlayerCaptureAuthority&& authority) {
    const bool live = authority.live_.exchange(false);
    need_shape(live);
    require_p1(upstream);
    (void)require_roster(upstream);
    auto capture = std::shared_ptr<P1CaptureStream>(new P1CaptureStream(
        authority.fixed_fd_, authority.round_,
        static_cast<unsigned>(upstream.my_num()), upstream.is_encrypted(),
        std::move(authority.binding_)));
    capture->declare_instrumented(Semantic::PeerTransport);
    return std::unique_ptr<P1CapturingPlayer>(new P1CapturingPlayer(
        upstream, capture, capture->root_fork()));
}

std::string P1CapturingPlayer::get_id() const {
    return upstream_.get_id();
}

bool P1CapturingPlayer::is_encrypted() {
    return true;
}

const std::array<history::Digest, 3>&
P1CapturingPlayer::authenticated_roster() const noexcept {
    return roster_.authenticated_roster();
}

const financial::RegisteredRosterBinding&
P1CapturingPlayer::authenticated_registered_binding() const noexcept {
    return roster_.authenticated_registered_binding();
}

void P1CapturingPlayer::send_long(int peer, long value) const {
    require_peer(peer);
    capture_->transport_transaction(
        [&] { upstream_.send_long(peer, value); },
        [&](auto& recorder) {
        recorder.record(Direction::Send, static_cast<unsigned>(peer), fork_, {
            reinterpret_cast<const unsigned char*>(&value), sizeof(value)});
        });
}

long P1CapturingPlayer::receive_long(int peer) const {
    require_peer(peer);
    long result{};
    capture_->transport_transaction(
        [&] { result = upstream_.receive_long(peer); },
        [&](auto& recorder) {
        recorder.record(Direction::Receive, static_cast<unsigned>(peer), fork_, {
            reinterpret_cast<const unsigned char*>(&result), sizeof(result)});
        });
    return result;
}

void P1CapturingPlayer::send_to_no_stats(
        int peer, const octetStream& value) const {
    require_peer(peer);
    capture_->transport_transaction(
        [&] { upstream_.send_to_no_stats(peer, value); },
        [&](auto& recorder) {
        recorder.record(Direction::Send, static_cast<unsigned>(peer), fork_,
                        bytes(value));
        });
}

void P1CapturingPlayer::receive_player_no_stats(
        int peer, octetStream& value) const {
    require_peer(peer);
    capture_->transport_transaction(
        [&] { upstream_.receive_player_no_stats(peer, value); },
        [&](auto& recorder) {
        recorder.record(Direction::Receive, static_cast<unsigned>(peer), fork_,
                        bytes(value));
        });
}

std::size_t P1CapturingPlayer::send_no_stats(
        int peer, const PlayerBuffer& value, bool block) const {
    require_peer(peer); need_shape(value.size == 0 || value.data != nullptr);
    std::size_t result{};
    capture_->transport_transaction(
        [&] { result = upstream_.send_no_stats(peer, value, block); },
        [&](auto& recorder) {
        const auto completed = prefix(value, result);
        recorder.record(Direction::Send, static_cast<unsigned>(peer), fork_,
                        completed);
        });
    return result;
}

std::size_t P1CapturingPlayer::recv_no_stats(
        int peer, const PlayerBuffer& value, bool block) const {
    require_peer(peer); need_shape(value.size == 0 || value.data != nullptr);
    std::size_t result{};
    capture_->transport_transaction(
        [&] { result = upstream_.recv_no_stats(peer, value, block); },
        [&](auto& recorder) {
        const auto completed = prefix(value, result);
        recorder.record(Direction::Receive, static_cast<unsigned>(peer),
                        fork_, completed);
        });
    return result;
}

void P1CapturingPlayer::exchange_no_stats(
        int peer, const octetStream& sent, octetStream& received) const {
    require_peer(peer);
    const octetStream preserved(sent);
    capture_->transport_transaction(
        [&] { upstream_.exchange_no_stats(peer, sent, received); },
        [&](auto& recorder) {
        recorder.record(Direction::Send, static_cast<unsigned>(peer), fork_,
                        bytes(preserved));
        recorder.record(Direction::Receive, static_cast<unsigned>(peer), fork_,
                        bytes(received));
        });
}

void P1CapturingPlayer::pass_around_no_stats(
        const octetStream& sent, octetStream& received, int offset) const {
    need_shape(offset != 0);
    const int send_peer = get_player(offset);
    const int receive_peer = get_player(-offset);
    require_peer(send_peer); require_peer(receive_peer);
    const octetStream preserved(sent);
    capture_->transport_transaction(
        [&] { upstream_.pass_around_no_stats(sent, received, offset); },
        [&](auto& recorder) {
        recorder.record(Direction::Send, static_cast<unsigned>(send_peer),
                        fork_, bytes(preserved));
        recorder.record(Direction::Receive,
                        static_cast<unsigned>(receive_peer), fork_,
                        bytes(received));
        });
}

void P1CapturingPlayer::Broadcast_Receive_no_stats(
        std::vector<octetStream>& values) const {
    need_shape(values.size() == 3);
    const octetStream outgoing(values.at(1));
    capture_->transport_transaction(
        [&] { upstream_.Broadcast_Receive_no_stats(values); },
        [&](auto& recorder) {
        for (unsigned peer : {0U, 2U}) {
            recorder.record(Direction::Send, peer, fork_, bytes(outgoing));
            recorder.record(Direction::Receive, peer, fork_,
                            bytes(values.at(peer)));
        }
        });
}

void P1CapturingPlayer::send_receive_all_no_stats(
        const std::vector<std::vector<bool>>& channels,
        const std::vector<octetStream>& sent,
        std::vector<octetStream>& received) const {
    need_shape(sent.size() == 3 &&
               (channels.empty() ||
                (channels.size() == 3 && channels.at(0).size() == 3 &&
                 channels.at(1).size() == 3 && channels.at(2).size() == 3)));
    capture_->transport_transaction(
        [&] { upstream_.send_receive_all_no_stats(channels, sent, received); },
        [&](auto& recorder) {
        need_shape(received.size() == 3);
        for (unsigned peer : {0U, 2U}) {
            if (channels.empty() || channels.at(1).at(peer))
                recorder.record(Direction::Send, peer, fork_,
                                bytes(sent.at(peer)));
            if (channels.empty() || channels.at(peer).at(1)) {
                recorder.record(Direction::Receive, peer, fork_,
                                bytes(received.at(peer)));
            }
        }
        });
}

void P1CapturingPlayer::partial_broadcast_no_stats(
        const std::vector<bool>& senders,
        const std::vector<bool>& receivers,
        std::vector<octetStream>& values) const {
    need_shape(senders.size() == 3 && receivers.size() == 3 &&
               values.size() == 3);
    const octetStream outgoing(values.at(1));
    capture_->transport_transaction(
        [&] {
            upstream_.partial_broadcast_no_stats(senders, receivers, values);
        },
        [&](auto& recorder) {
        for (unsigned peer : {0U, 2U}) {
            if (receivers.at(peer))
                recorder.record(Direction::Send, peer, fork_, bytes(outgoing));
            if (senders.at(peer)) {
                recorder.record(Direction::Receive, peer, fork_,
                                bytes(values.at(peer)));
            }
        }
        });
}

void P1CapturingPlayer::request_receive(
        int peer, octetStream& value) const {
    require_peer(peer);
    const auto key = std::make_pair(peer, &value);
    {
        std::lock_guard guard(pending_mutex_);
        need_shape(pending_receives_.insert(key).second);
    }
    try {
        capture_->begin_async_receive(
            [&] { upstream_.request_receive(peer, value); });
    } catch (...) {
        std::lock_guard guard(pending_mutex_);
        pending_receives_.erase(key);
        throw;
    }
}

void P1CapturingPlayer::wait_receive(
        int peer, octetStream& value) const {
    require_peer(peer);
    const auto key = std::make_pair(peer, &value);
    {
        std::lock_guard guard(pending_mutex_);
        need_shape(pending_receives_.contains(key));
    }
    capture_->finish_async_receive(
        [&] { upstream_.wait_receive(peer, value); },
        [&](auto& recorder) {
        recorder.record(Direction::Receive, static_cast<unsigned>(peer), fork_,
                        bytes(value));
        });
    std::lock_guard guard(pending_mutex_);
    need_shape(pending_receives_.erase(key) == 1);
}

Player* P1CapturingPlayer::fresh_fork(std::string suffix) {
    need_shape(!suffix.empty() && suffix.size() <= 128);
    ForkId child_fork{};
    Player* upstream_child = nullptr;
    try {
        upstream_child = upstream_.fork(suffix);
        need_shape(upstream_child != nullptr);
        child_fork = capture_->register_fork(fork_, suffix);
        return new P1CapturingPlayer(
            *upstream_child, capture_, child_fork);
    } catch (...) {
        capture_->poison();
        throw;
    }
}

#ifdef KPI_P1_CAPTURE_TEST_SETUP
std::unique_ptr<P1CapturingPlayer> P1CapturingPlayer::test_only_begin(
        Player& upstream, int fixed_fd, unsigned round, RunBinding binding) {
    require_p1(upstream);
    auto capture = P1CaptureStream::test_only_begin(
        fixed_fd, round, static_cast<unsigned>(upstream.my_num()),
        upstream.is_encrypted(), std::move(binding));
    capture->declare_instrumented(Semantic::PeerTransport);
    return std::unique_ptr<P1CapturingPlayer>(new P1CapturingPlayer(
        upstream, capture, capture->root_fork()));
}

P1CaptureStream& P1CapturingPlayer::test_only_capture() {
    return *capture_;
}
#endif

} // namespace kpi::mpc::p1_capture
