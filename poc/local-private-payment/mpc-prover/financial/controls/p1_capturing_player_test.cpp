#include "../../p1_capture_seams.hpp"

#include <array>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace kpi::mpc {
std::string canonical_fr(const Fr& value) {
    bigint canonical;
    to_bigint(canonical, value);
    return canonical.get_str(10);
}
}

namespace {
using namespace kpi::mpc;
using namespace kpi::mpc::p1_capture;

std::string repeated(char value) { return std::string(64, value); }

RunBinding binding() {
    return {
        .attempt_id = "33333333-3333-4333-8333-333333333333",
        .cohort_sha256 = repeated('3'),
        .financial_run_id = repeated('4'),
        .capture_identity = "22222222-2222-4222-8222-222222222222",
        .protocol_source_sha256 = repeated('5'),
        .protocol_build_sha256 = repeated('6'),
        .protocol_launch_sha256 = repeated('7'),
        .model_preimage_sha256 = repeated('8'),
        .query_store_preimage_sha256 = repeated('9'),
        .scalar_capture_manifest_sha256 =
            std::string(SCALAR_CAPTURE_MANIFEST_SHA256),
    };
}

void assign(octetStream& out, std::string value) {
    out.reset_write_head();
    out.append(reinterpret_cast<const octet*>(value.data()), value.size());
}

class FakeEncryptedPlayer final : public Player,
                                  public financial::RosterPinnedPlayer {
    std::string id_;
    bool encrypted_;
    bool fail_fork_;
    std::barrier<>* io_barrier_;

public:
    FakeEncryptedPlayer(const Names& names, std::string id = "fake",
                        bool encrypted = true, bool fail_fork = false,
                        std::barrier<>* io_barrier = nullptr)
        : Player(names), id_(std::move(id)), encrypted_(encrypted),
          fail_fork_(fail_fork), io_barrier_(io_barrier) {}

    std::string get_id() const override { return id_; }
    bool is_encrypted() override { return encrypted_; }
    const std::array<history::Digest, 3>&
    authenticated_roster() const noexcept override {
        static const std::array<history::Digest, 3> roster{};
        return roster;
    }
    const financial::RegisteredRosterBinding&
    authenticated_registered_binding() const noexcept override {
        static const financial::RegisteredRosterBinding binding{};
        return binding;
    }
    void send_long(int, long) const override {}
    long receive_long(int peer) const override { return 0x10203040L + peer; }
    void send_to_no_stats(int, const octetStream&) const override {
        if (io_barrier_) io_barrier_->arrive_and_wait();
    }
    void receive_player_no_stats(int peer, octetStream& out) const override {
        if (io_barrier_) io_barrier_->arrive_and_wait();
        assign(out, "receive-" + std::to_string(peer));
    }
    std::size_t send_no_stats(int, const PlayerBuffer& value,
                              bool) const override {
        return value.size > 1 ? value.size - 1 : value.size;
    }
    std::size_t recv_no_stats(int peer, const PlayerBuffer& value,
                              bool) const override {
        const auto count = value.size > 2 ? value.size - 2 : value.size;
        for (std::size_t index = 0; index < count; ++index)
            value.data[index] = static_cast<octet>(0x60 + peer + index);
        return count;
    }
    void exchange_no_stats(int peer, const octetStream&,
                           octetStream& received) const override {
        assign(received, "exchange-" + std::to_string(peer));
    }
    void pass_around_no_stats(const octetStream&, octetStream& received,
                              int offset) const override {
        assign(received, "pass-" + std::to_string(offset));
    }
    void Broadcast_Receive_no_stats(
            std::vector<octetStream>& values) const override {
        for (int peer = 0; peer < num_players(); ++peer)
            if (peer != my_num())
                assign(values.at(peer), "broadcast-" + std::to_string(peer));
    }
    void send_receive_all_no_stats(
            const std::vector<std::vector<bool>>& channels,
            const std::vector<octetStream>&,
            std::vector<octetStream>& received) const override {
        received.resize(num_players());
        for (int peer = 0; peer < num_players(); ++peer)
            if (peer != my_num() &&
                (channels.empty() || channels.at(peer).at(my_num())))
                assign(received.at(peer), "all-" + std::to_string(peer));
    }
    void partial_broadcast_no_stats(
            const std::vector<bool>& senders,
            const std::vector<bool>&,
            std::vector<octetStream>& values) const override {
        for (int peer = 0; peer < num_players(); ++peer)
            if (peer != my_num() && senders.at(peer))
                assign(values.at(peer), "partial-" + std::to_string(peer));
    }
    void request_receive(int, octetStream&) const override {}
    void wait_receive(int peer, octetStream& out) const override {
        assign(out, "async-" + std::to_string(peer));
    }
    Player* fresh_fork(std::string suffix) override {
        if (fail_fork_) throw std::runtime_error("fake-fork-failure");
        return new FakeEncryptedPlayer(
            N, id_ + "-" + suffix, encrypted_, fail_fork_);
    }
};

octetStream bytes(std::string value) { return octetStream(value); }

std::array<unsigned char, 32> field(unsigned char value) {
    std::array<unsigned char, 32> result{};
    result[0] = value;
    return result;
}

void finish(P1CapturingPlayer& player) {
    P1TypedCaptureSeams seams(player);
    seams.mac_key_share(Fr(0x30));
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto value = field(static_cast<unsigned char>(owner + 1));
        std::array<unsigned char, 5 * 32> preprocessing{};
        preprocessing.fill(static_cast<unsigned char>(owner + 11));
        seams.owner_input_preprocessing_share_frame(owner, preprocessing);
        seams.owner_input_offset_frame(owner, value);
    }
    AuthScalar value;
    value.set_share(Fr(0x31));
    value.set_mac(Fr(0x32));
    const std::array<AuthScalar, 1> authenticated{{value}};
    for (unsigned encoded = 1; encoded <= 22; ++encoded) {
        const auto site = static_cast<ScalarCaptureSite>(encoded);
        if (scalar_capture_kind(site) == ScalarCaptureKind::Randomness)
            seams.randomness_values(site, authenticated);
        else
            seams.authenticated_values(site, authenticated);
    }
    const std::array<Fr, 1> opened{{Fr(0x33)}};
    seams.field_openings(opened);
    const std::array<Fr, 2> masked_fields{{Fr(0x34), Fr(0x35)}};
    const std::array<G1Value, 2> g1{{G1Value(), G1Value()}};
    const std::array<G2Value, 1> g2{{G2Value()}};
    AuthG1 authenticated_g1;
    authenticated_g1.set_share(G1Value());
    authenticated_g1.set_mac(G1Value());
    AuthG2 authenticated_g2;
    authenticated_g2.set_share(G2Value());
    authenticated_g2.set_mac(G2Value());
    const std::array<AuthG1, 4> base_g1{{
        authenticated_g1, authenticated_g1, authenticated_g1,
        authenticated_g1}};
    seams.proof_base_group_state(base_g1, authenticated_g2);
    const std::array<AuthG1, 6> mixed_g1{{
        authenticated_g1, authenticated_g1, authenticated_g1,
        authenticated_g1, authenticated_g1, authenticated_g1}};
    seams.beaver_mixed_group_state(mixed_g1);
    seams.masked_field_differences(masked_fields);
    seams.masked_group_differences(g1);
    const std::array<AuthG1, 2> products_g1{{
        authenticated_g1, authenticated_g1}};
    seams.beaver_product_group_state(products_g1);
    const std::array<AuthG1, 2> final_g1{{
        authenticated_g1, authenticated_g1}};
    seams.test_only_final_group_state_and_openings(
        final_g1, authenticated_g2, g1, g2);
    seams.test_only_bind_query_model(repeated('8'), repeated('9'));
    std::vector<unsigned char> projection(10685, 0x55);
    seams.test_only_released_projection(projection);
    seams.test_only_close_complete();
}

int exercise() {
    if (::dup2(STDOUT_FILENO, 23) != 23) return 1;
    Names names(1, 3);
    bigint::init_thread();
    if (Fr::pr(true) == 0) Fr::init_field(bigint(FR_MODULUS));
    initialize_bn254_groups();
    FakeEncryptedPlayer upstream(names);
    auto player = P1CapturingPlayer::test_only_begin(
        upstream, 23, 1, binding());
    if (player->authenticated_roster() != upstream.authenticated_roster() ||
        !(player->authenticated_registered_binding() ==
          upstream.authenticated_registered_binding()))
        return 3;

    player->send_long(2, 0x11223344);
    (void)player->receive_long(0);
    auto sentinel = bytes("PRIVATE_SENTINEL_TRANSPORT");
    player->send_to(0, sentinel);
    octetStream received;
    player->receive_player(2, received);

    std::array<octet, 8> raw{{1, 2, 3, 4, 5, 6, 7, 8}};
    PlayerBuffer buffer(raw.data(), raw.size());
    (void)player->send_no_stats(2, buffer, false);
    (void)player->recv_no_stats(0, buffer, false);
    PlayerBuffer empty;
    (void)player->send_no_stats(0, empty, false);
    (void)player->recv_no_stats(2, empty, false);

    octetStream exchanged;
    player->exchange(2, sentinel, exchanged);
    octetStream passed;
    player->pass_around(sentinel, passed, 1);

    std::vector<octetStream> broadcast(3);
    broadcast[1] = sentinel;
    player->Broadcast_Receive(broadcast);

    std::vector<octetStream> outgoing(3), incoming;
    outgoing[0] = bytes("to-zero"); outgoing[2] = bytes("to-two");
    player->send_receive_all(outgoing, incoming);

    std::vector<bool> senders{true, true, true};
    std::vector<bool> receivers{true, true, true};
    std::vector<octetStream> partial(3); partial[1] = sentinel;
    player->partial_broadcast(senders, receivers, partial);

    octetStream async;
    player->request_receive(0, async);
    player->wait_receive(0, async);

    VirtualTwoPartyPlayer pair(*player, 2);
    auto pair_send = bytes("pair-send");
    pair.send(pair_send);
    octetStream pair_receive;
    pair.receive(pair_receive);
    std::vector<octetStream> pair_exchange{bytes("pair-exchange"), {}};
    pair.send_receive_player(pair_exchange);
    (void)pair.send(buffer, false);
    (void)pair.recv(buffer, false);

    auto* child = player->fork("child");
    child->send_to(2, bytes("child-private"));
    if (player->fork("child") != child) return 2;
    auto* grandchild = child->fork("grandchild");
    grandchild->send_to(0, bytes("grandchild-private"));

    finish(*player);
    return 0;
}

int role_bypass(bool encrypted, int role, int parties) {
    if (::dup2(STDOUT_FILENO, 23) != 23) return 1;
    Names names(role, parties);
    FakeEncryptedPlayer upstream(names, "bad", encrypted);
    try {
        (void)P1CapturingPlayer::test_only_begin(
            upstream, 23, 1, binding());
    } catch (const CaptureRefused&) {
        return 0;
    }
    return 2;
}

int failed_fork_poison() {
    if (::dup2(STDOUT_FILENO, 23) != 23) return 1;
    Names names(1, 3);
    FakeEncryptedPlayer upstream(names, "fork-fails", true, true);
    auto player = P1CapturingPlayer::test_only_begin(
        upstream, 23, 1, binding());
    try {
        (void)player->fork("fail");
    } catch (...) {
        try {
            player->send_to(0, bytes("must-not-escape"));
        } catch (const CaptureRefused&) {
            return 0;
        }
    }
    return 2;
}

int concurrent_fork_io() {
    if (::dup2(STDOUT_FILENO, 23) != 23) return 1;
    Names names(1, 3);
    bigint::init_thread();
    if (Fr::pr(true) == 0) Fr::init_field(bigint(FR_MODULUS));
    initialize_bn254_groups();
    std::barrier rendezvous(2);
    FakeEncryptedPlayer upstream(
        names, "concurrent", true, false, &rendezvous);
    auto player = P1CapturingPlayer::test_only_begin(
        upstream, 23, 1, binding());
    std::thread sender([&] {
        player->send_to(0, bytes("concurrent-send"));
    });
    std::thread receiver([&] {
        octetStream value;
        player->receive_player(2, value);
    });
    sender.join(); receiver.join();
    finish(*player);
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 1) return exercise();
        if (argc != 2) return 64;
        const std::string selected(argv[1]);
        if (selected == "wrong-role") return role_bypass(true, 0, 3);
        if (selected == "unencrypted") return role_bypass(false, 1, 3);
        if (selected == "wrong-parties") return role_bypass(true, 1, 2);
        if (selected == "failed-fork") return failed_fork_poison();
        if (selected == "concurrent-io") return concurrent_fork_io();
        return 64;
    } catch (...) {
        return 78;
    }
}
