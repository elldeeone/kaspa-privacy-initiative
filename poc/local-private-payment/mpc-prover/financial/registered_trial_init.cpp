// One-shot journal initializer/verifier for a fresh unfunded registered trial.
// This binary has no MPC, owner-input, proof, RPC, settlement or reset entry.
#ifndef KPI_HISTORY_UNFUNDED_SETUP
#error "registered trial initializer requires the unfunded setup surface"
#endif
#ifndef KPI_REGISTERED_TRIAL_BOOTSTRAP
#error "registered trial initializer requires an explicit bootstrap build"
#endif

#include "../history/epoch_journal.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using namespace kpi::mpc::history;

void need(bool value) {
    if (!value) throw Refused();
}

std::filesystem::path admitted_root(const char* text) {
    const std::filesystem::path root(text);
    need(root.is_absolute() && root == root.lexically_normal() &&
         std::filesystem::canonical(root) == root);
    for (auto path = root; !path.empty(); path = path.parent_path()) {
        const auto status = std::filesystem::symlink_status(path);
        need(!std::filesystem::is_symlink(status));
        if (path == path.root_path()) break;
    }
    struct stat info{};
    need(::lstat(root.c_str(), &info) == 0 && S_ISDIR(info.st_mode) &&
         info.st_uid == ::geteuid() && (info.st_mode & 07777) == 0700);
    return root;
}

EpochKey selected_key(const std::array<Digest, 3>& certificates) {
    EpochKey key{};
    key.chain = unhex("f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370");
    key.pool = unhex("d68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf");
    key.domain = unhex("a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0");
    key.profile = unhex("ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700");
    key.service = unhex("ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5");
    key.epoch = unhex("1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94");
    key.server_certificates = certificates;
    // encode performs the production key validation, including nonzero and
    // three-distinct certificate pins.
    (void)encode(key);
    return key;
}

void emit(const std::filesystem::path& root, const EpochKey& key,
          const Digest& registration, bool initialize) {
    std::ostringstream output;
    output << "KPB_REGISTERED_TRIAL_STATE_V1\n";
    output << "REGISTRATION " << hex(registration) << "\n";
    output << "KEY " << hex(digest(encode(key))) << "\n";
    Digest common_checkpoint{};
    for (unsigned party = 0; party < 3; ++party) {
        const auto base = root / "state" / ("party-" + std::to_string(party));
        const auto journal_path = base / "journal";
        const auto anchor_path = base / "anchor";
        PublicSnapshot state{};
        if (initialize) {
            auto journal = EpochJournal::initialize_fresh_unfunded(
                journal_path, anchor_path, key, registration);
            state = journal.snapshot();
        } else {
            auto journal = EpochJournal::open_existing(
                journal_path, anchor_path, key, registration);
            state = journal.snapshot();
        }
        need(state.key == key && state.registration == registration &&
             state.sequence == 0 && state.phase == Phase::Ready &&
             !state.attempt && !state.effects && !state.egress &&
             !state.candidate && !state.lock_identity &&
             !state.last_settlement && state.seen_nullifiers.empty());
        if (party == 0) common_checkpoint = state.checkpoint;
        need(state.checkpoint == common_checkpoint);
        output << "PARTY " << party << ' ' << state.sequence << ' '
               << hex(state.checkpoint) << " READY\n";
    }
    output << "END\n";
    std::cout << output.str();
}
} // namespace

int main(int argc, char** argv) {
    try {
        need(argc == 7 && (std::string(argv[1]) == "initialize" ||
                           std::string(argv[1]) == "verify"));
        const auto root = admitted_root(argv[2]);
        const auto registration = unhex(argv[3]);
        need(registration != Digest{});
        std::array<Digest, 3> certificates{
            unhex(argv[4]), unhex(argv[5]), unhex(argv[6])};
        emit(root, selected_key(certificates), registration,
             std::string(argv[1]) == "initialize");
        return 0;
    } catch (...) {
        std::cerr << "registered unfunded trial state refused\n";
        return 1;
    }
}
