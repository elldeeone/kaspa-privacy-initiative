#include "../unregistered_p1_capture_qualifier.hpp"
#include "../../p1_capturing_player.hpp"
#include "../../bn254_values.hpp"

#include <array>
#include <string>
#include <unistd.h>

namespace kpi::mpc {
std::string canonical_fr(const Fr& value) {
    bigint canonical;
    to_bigint(canonical, value);
    return canonical.get_str(10);
}
}

namespace {
using namespace kpi::mpc;
using namespace kpi::mpc::financial::qualification;

class FakeRosterPlayer final : public Player,
                               public financial::RosterPinnedPlayer {
public:
    explicit FakeRosterPlayer(const Names& names) : Player(names) {}

    std::string get_id() const override { return "control-only-p1"; }
    bool is_encrypted() override { return true; }
    const std::array<history::Digest, 3>&
    authenticated_roster() const noexcept override {
        static const std::array<history::Digest, 3> value{};
        return value;
    }
    const financial::RegisteredRosterBinding&
    authenticated_registered_binding() const noexcept override {
        static const financial::RegisteredRosterBinding value{};
        return value;
    }
    void send_long(int, long) const override {}
    long receive_long(int) const override { return 0; }
    void send_to_no_stats(int, const octetStream&) const override {}
    void receive_player_no_stats(int, octetStream&) const override {}
    std::size_t send_no_stats(int, const PlayerBuffer& value,
                              bool) const override { return value.size; }
    std::size_t recv_no_stats(int, const PlayerBuffer& value,
                              bool) const override { return value.size; }
    void exchange_no_stats(int, const octetStream&,
                           octetStream&) const override {}
    void pass_around_no_stats(const octetStream&, octetStream&,
                              int) const override {}
    void Broadcast_Receive_no_stats(
        std::vector<octetStream>&) const override {}
    void send_receive_all_no_stats(
        const std::vector<std::vector<bool>>&,
        const std::vector<octetStream>&,
        std::vector<octetStream>& values) const override {
        values.resize(3);
    }
    void partial_broadcast_no_stats(
        const std::vector<bool>&, const std::vector<bool>&,
        std::vector<octetStream>&) const override {}
    Player* fresh_fork(std::string) override {
        return new FakeRosterPlayer(N);
    }
};

std::string repeated(char value) { return std::string(64, value); }

ControlOnlyP1Selection selected() {
    return {
        .scope = "PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY",
        .classification = "CONTROL_ONLY_UNREGISTERED",
        .fixed_fd = 23,
        .round = 1,
        .party = 1,
        .attempt_id = "33333333-3333-4333-8333-333333333333",
        .cohort_sha256 = repeated('3'),
        .financial_run_id = repeated('4'),
        .capture_identity = "22222222-2222-4222-8222-222222222222",
        .protocol_source_sha256 = repeated('5'),
        .protocol_build_sha256 = repeated('6'),
        .protocol_launch_sha256 = repeated('7'),
        .model_preimage_sha256 = repeated('8'),
        .query_store_preimage_sha256 = repeated('9'),
        .scalar_capture_manifest_sha256 = std::string(
            kpi::mpc::p1_capture::SCALAR_CAPTURE_MANIFEST_SHA256),
        .actual_authority_requested = false,
    };
}

int refuses(ControlOnlyP1Selection value) {
    try {
        (void)ControlOnlyUnregisteredP1Capture::admit(std::move(value));
    } catch (...) {
        return 0;
    }
    return 1;
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2) {
            auto value = selected();
            const std::string scenario(argv[1]);
            if (scenario == "actual") value.actual_authority_requested = true;
            else if (scenario == "scope") value.scope = "ACTUAL";
            else if (scenario == "fd") value.fixed_fd = 24;
            else if (scenario == "party") value.party = 0;
            else if (scenario == "manifest")
                value.scalar_capture_manifest_sha256 = repeated('0');
            else return 64;
            return refuses(std::move(value));
        }
        if (argc != 1 || ::dup2(STDOUT_FILENO, 23) != 23) return 64;
        Names names(1, 3);
        FakeRosterPlayer upstream(names);
        auto authority = ControlOnlyUnregisteredP1Capture::admit(selected());
        const auto status = authority.status();
        if (status.schema !=
                "kpb-p1-control-only-unregistered-qualifier/v1" ||
            status.classification != "CONTROL_ONLY_UNREGISTERED" ||
            status.configured || status.registered_driver_integrated ||
            status.producer_integrated || status.launch_authorized ||
            status.actual_receipt_enabled ||
            status.serialized_receipt_is_authority)
            return 2;
        auto player = authority.begin(upstream);
        if (!player) return 3;
        try {
            (void)authority.begin(upstream);
        } catch (...) {
            return 0;
        }
        return 4;
    } catch (...) {
        return 78;
    }
}
