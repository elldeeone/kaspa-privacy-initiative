#include "../../p1_softspoken_random_tape_state_hook.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <condition_variable>
#include <mutex>
#include <source_location>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace kpi::mpc::p1_private_state;

namespace {

constexpr std::uintptr_t PLAYER_BITS = 0x1122334455667788ULL;

void need(
        bool value,
        const std::source_location where =
            std::source_location::current()) {
    if (!value) throw std::runtime_error(
        "P1-SoftSpoken-hook-control:" +
        std::to_string(where.line()));
}

const void* player() {
    return reinterpret_cast<const void*>(PLAYER_BITS);
}

std::vector<unsigned char> bytes(unsigned char tag, std::size_t size = 48) {
    std::vector<unsigned char> result(size);
    for (std::size_t index = 0; index < size; ++index)
        result[index] = static_cast<unsigned char>(tag + index * 13U);
    return result;
}

struct Record final {
    SoftSpokenEventKind kind{};
    SoftSpokenRole role{};
    SoftSpokenRolePhase phase{};
    std::uint64_t sequence{};
    std::uint64_t worker{};
    std::uint64_t call{};
    std::vector<unsigned char> encoded;
};

class Hook final : public SoftSpokenRandomTapeStateHook {
public:
    std::vector<Record> records;
    SoftSpokenEventKind reject_kind{};
    bool reject_terminal{};
    unsigned unavailable_count{};
    unsigned terminal_count{};
    std::uint64_t next_worker{700};

    Hook() : SoftSpokenRandomTapeStateHook(TestOnlyConstruction{}) {}

private:
    bool record_softspoken_event(
            const SoftSpokenEventView& view) noexcept override {
        try {
            if (view.kind == reject_kind) return false;
            auto encoded = encode_softspoken_event(view);
            records.push_back(Record{
                .kind = view.kind,
                .role = view.role,
                .phase = view.role_phase,
                .sequence = view.sequence,
                .worker = view.worker_epoch,
                .call = view.call_epoch,
                .encoded = std::vector<unsigned char>(
                    encoded.view().begin(), encoded.view().end()),
            });
            return true;
        } catch (...) {
            return false;
        }
    }

    bool bind_softspoken_worker_epoch(
            SoftSpokenRole role,
            std::uint64_t& logical_worker_epoch) noexcept override {
        if (role != SoftSpokenRole::Receiver) return false;
        logical_worker_epoch = next_worker++;
        return true;
    }

    bool softspoken_terminal_noexcept() noexcept override {
        ++terminal_count;
        return !reject_terminal;
    }

    void softspoken_unavailable_noexcept() noexcept override {
        ++unavailable_count;
    }
};

std::unique_ptr<SoftSpokenRandomTapeStateScope> install(Hook& hook) {
    return SoftSpokenRandomTapeStateTestBridge::install(
        hook, player(), 41, 43, 47, 1, 0);
}

void begin_call(bool existing, std::uint64_t n = 257) {
    need(SoftSpokenRandomTapeStateSourceBridge::path_selected(
        player(), 1, 0, 0x11, 2, false, false, false, false));
    need(SoftSpokenRandomTapeStateSourceBridge::state_lookup(
        player(), existing));
    if (!existing) {
        need(SoftSpokenRandomTapeStateSourceBridge::state_construct_begin(
            player()));
        need(SoftSpokenRandomTapeStateSourceBridge::state_construct_end(
            player(), true));
    }
    need(SoftSpokenRandomTapeStateSourceBridge::call_begin(
        player(), n, false));
}

void complete_role(SoftSpokenRole role, unsigned char tag) {
    need(SoftSpokenRandomTapeStateSourceBridge::role_begin(player(), role));
    auto seed = bytes(tag, 16);
    auto prng0 = bytes(static_cast<unsigned char>(tag + 1), 96);
    auto base = bytes(static_cast<unsigned char>(tag + 2), 160);
    auto object0 = bytes(static_cast<unsigned char>(tag + 3), 512);
    need(SoftSpokenRandomTapeStateSourceBridge::seeded_prng(seed, prng0));
    need(SoftSpokenRandomTapeStateSourceBridge::base_installed(
        base, object0, prng0));

    auto vole_seed = bytes(static_cast<unsigned char>(tag + 4), 16);
    auto prng1 = bytes(static_cast<unsigned char>(tag + 5), 96);
    auto object1 = bytes(static_cast<unsigned char>(tag + 6), 512);
    need(SoftSpokenRandomTapeStateSourceBridge::vole_expanded(
        object1, prng1, vole_seed));

    auto object2 = bytes(static_cast<unsigned char>(tag + 7), 512);
    auto tape_prng = role == SoftSpokenRole::Sender ? prng1 :
        bytes(static_cast<unsigned char>(tag + 8), 96);
    need(SoftSpokenRandomTapeStateSourceBridge::tape_consumed(
        object2, tape_prng));

    auto object3 = bytes(static_cast<unsigned char>(tag + 9), 512);
    auto challenge_prng = role == SoftSpokenRole::Sender ?
        bytes(static_cast<unsigned char>(tag + 10), 96) : tape_prng;
    need(SoftSpokenRandomTapeStateSourceBridge::challenge_bound(
        object3, challenge_prng));

    auto rtcr_prng = role == SoftSpokenRole::Sender ?
        bytes(static_cast<unsigned char>(tag + 11), 96) : challenge_prng;
    auto rtcr = bytes(static_cast<unsigned char>(tag + 12), 1400);
    need(SoftSpokenRandomTapeStateSourceBridge::rtcr_bound(
        object3, rtcr_prng, rtcr));

    auto object4 = bytes(static_cast<unsigned char>(tag + 13), 512);
    auto check = bytes(static_cast<unsigned char>(tag + 14), 800);
    need(SoftSpokenRandomTapeStateSourceBridge::check_derived(
        object4, rtcr_prng, check));
    need(SoftSpokenRandomTapeStateSourceBridge::check_terminal(
        object4, rtcr_prng));
    auto output = bytes(static_cast<unsigned char>(tag + 15), 2048);
    need(SoftSpokenRandomTapeStateSourceBridge::output_ready(
        object4, rtcr_prng, output));
    need(SoftSpokenRandomTapeStateSourceBridge::role_end(role));
}

void finish_call() {
    need(SoftSpokenRandomTapeStateSourceBridge::join(player()));
    need(SoftSpokenRandomTapeStateSourceBridge::call_end(player()));
}

bool contains_pointer(const std::vector<unsigned char>& value) {
    std::array<unsigned char, sizeof(std::uintptr_t)> little{};
    std::array<unsigned char, sizeof(std::uintptr_t)> big{};
    for (std::size_t index = 0; index < little.size(); ++index) {
        little[index] = static_cast<unsigned char>(
            PLAYER_BITS >> (index * 8U));
        big[big.size() - index - 1U] = little[index];
    }
    return std::search(value.begin(), value.end(),
                       little.begin(), little.end()) != value.end() ||
        std::search(value.begin(), value.end(),
                    big.begin(), big.end()) != value.end();
}

void normal() {
    Hook hook;
    auto scope = install(hook);

    begin_call(false);
    std::thread receiver1([] {
        complete_role(SoftSpokenRole::Receiver, 0x80);
    });
    receiver1.join();
    complete_role(SoftSpokenRole::Sender, 0x10);
    finish_call();

    begin_call(true, 511);
    complete_role(SoftSpokenRole::Sender, 0x30);
    std::thread receiver2([] {
        complete_role(SoftSpokenRole::Receiver, 0xa0);
    });
    receiver2.join();
    finish_call();

    need(SoftSpokenRandomTapeStateSourceBridge::state_destructor_begin(
        player()));
    need(SoftSpokenRandomTapeStateSourceBridge::state_destructor_terminal(
        player()));
    scope.reset();

    if (hook.unavailable_count != 0 || hook.terminal_count != 1)
        throw std::runtime_error(
            "P1-SoftSpoken-hook-counts:" +
            std::to_string(hook.unavailable_count) + ":" +
            std::to_string(hook.terminal_count) + ":" +
            std::to_string(hook.records.size()) + ":" +
            std::to_string(static_cast<unsigned>(hook.records.back().kind)));
    need(hook.records.front().kind == SoftSpokenEventKind::Construct);
    need(hook.records.back().kind ==
         SoftSpokenEventKind::StateDestructorTerminal);
    std::uint64_t previous{};
    std::array<std::uint64_t, 2> receiver_workers{};
    for (const auto& record : hook.records) {
        need(record.sequence == ++previous);
        need(!record.encoded.empty());
        need(!contains_pointer(record.encoded));
        if (record.role == SoftSpokenRole::Sender)
            need(record.worker == 47);
        if (record.role == SoftSpokenRole::Receiver) {
            need(record.worker >= 700 && record.worker != 47);
            receiver_workers.at(record.call - 1) = record.worker;
        }
    }
    need(receiver_workers[0] != 0 && receiver_workers[1] != 0 &&
         receiver_workers[0] != receiver_workers[1]);
}

void replay() {
    Hook hook;
    auto scope = install(hook);
    begin_call(false);
    need(SoftSpokenRandomTapeStateSourceBridge::role_begin(
        player(), SoftSpokenRole::Sender));
    auto seed = bytes(1, 16);
    auto prng = bytes(2, 96);
    need(SoftSpokenRandomTapeStateSourceBridge::seeded_prng(seed, prng));
    need(SoftSpokenRandomTapeStateSourceBridge::seeded_prng(seed, prng));
    need(hook.unavailable_count == 1);
}

void wrong_player() {
    Hook hook;
    auto scope = install(hook);
    need(SoftSpokenRandomTapeStateSourceBridge::path_selected(
        player(), 1, 0, 0x11, 2, false, false, false, false));
    const auto* wrong = reinterpret_cast<const void*>(PLAYER_BITS + 1U);
    need(SoftSpokenRandomTapeStateSourceBridge::state_lookup(wrong, false));
    need(hook.unavailable_count == 1);
}

void substitution() {
    Hook hook;
    auto scope = install(hook);
    begin_call(false);
    need(SoftSpokenRandomTapeStateSourceBridge::role_begin(
        player(), SoftSpokenRole::Sender));
    auto seed = bytes(1, 16);
    auto prng = bytes(2, 96);
    auto changed = bytes(3, 96);
    auto base = bytes(4, 128);
    auto object = bytes(5, 512);
    need(SoftSpokenRandomTapeStateSourceBridge::seeded_prng(seed, prng));
    need(SoftSpokenRandomTapeStateSourceBridge::base_installed(
        base, object, changed));
    need(hook.unavailable_count == 1);
}

void drop() {
    Hook hook;
    auto scope = install(hook);
    begin_call(false);
    complete_role(SoftSpokenRole::Sender, 0x10);
    need(SoftSpokenRandomTapeStateSourceBridge::join(player()));
    need(hook.unavailable_count == 1);
}

void cross_thread() {
    Hook hook;
    auto scope = install(hook);
    begin_call(false);
    std::thread wrong([] {
        need(SoftSpokenRandomTapeStateSourceBridge::role_begin(
            player(), SoftSpokenRole::Sender));
    });
    wrong.join();
    need(hook.unavailable_count == 1);
}

void peer_swap() {
    Hook hook;
    auto scope = install(hook);
    need(SoftSpokenRandomTapeStateSourceBridge::path_selected(
        player(), 0, 1, 0x11, 2, false, false, false, false));
    need(hook.unavailable_count == 1);
}

void rejected_path(SoftSpokenPathClass expected) {
    Hook hook;
    auto scope = install(hook);
    bool passive = expected == SoftSpokenPathClass::SemiHonest;
    bool kos = expected == SoftSpokenPathClass::Kos;
    bool silent = expected == SoftSpokenPathClass::Silent;
    bool libote1 = expected == SoftSpokenPathClass::LibOte1;
    auto k = expected == SoftSpokenPathClass::HighOrOtherK ? 8U : 2U;
    auto mask = expected == SoftSpokenPathClass::UnsupportedRole ?
        0x01U : 0x11U;
    need(SoftSpokenRandomTapeStateSourceBridge::path_selected(
        player(), 1, 0, mask, k, passive, kos, silent, libote1));
    need(hook.unavailable_count == 1);
    need(hook.records.back().kind == SoftSpokenEventKind::PathRejected);
    need(hook.records.back().encoded.size() > 64);
}

void abort_role() {
    Hook hook;
    auto scope = install(hook);
    begin_call(false);
    need(SoftSpokenRandomTapeStateSourceBridge::role_begin(
        player(), SoftSpokenRole::Sender));
    SoftSpokenRandomTapeStateSourceBridge::abort_current_noexcept(
        SoftSpokenAbortClass::SenderException,
        SoftSpokenRolePhase::Begun);
    need(hook.unavailable_count == 1);
    need(hook.records.back().kind == SoftSpokenEventKind::Abort);
}

void hook_reject() {
    Hook hook;
    hook.reject_kind = SoftSpokenEventKind::TapeConsumed;
    auto scope = install(hook);
    begin_call(false);
    complete_role(SoftSpokenRole::Sender, 0x10);
    need(hook.unavailable_count == 1);
}

void terminal_reject() {
    Hook hook;
    hook.reject_terminal = true;
    auto scope = install(hook);
    begin_call(false);
    complete_role(SoftSpokenRole::Sender, 0x10);
    std::thread receiver([] {
        complete_role(SoftSpokenRole::Receiver, 0x80);
    });
    receiver.join();
    finish_call();
    need(SoftSpokenRandomTapeStateSourceBridge::state_destructor_begin(
        player()));
    need(SoftSpokenRandomTapeStateSourceBridge::state_destructor_terminal(
        player()));
    need(hook.terminal_count == 1 && hook.unavailable_count == 1);
}

void unlinked() {
    Hook hook;
    {
        auto scope = install(hook);
        need(scope != nullptr);
    }
    need(hook.unavailable_count == 1);
}

void poisoned_retry_stays_selected() {
    Hook hook;
    auto scope = install(hook);
    begin_call(false);
    complete_role(SoftSpokenRole::Sender, 0x10);
    need(SoftSpokenRandomTapeStateSourceBridge::join(player()));
    need(hook.unavailable_count == 1);
    const auto records_after_poison = hook.records.size();

    // A retry after the missing receiver must remain inside the poisoned
    // capture scope.  It may not be reinterpreted as an unselected call.
    need(SoftSpokenRandomTapeStateSourceBridge::
        capture_required_pointer_noexcept(player()));
    need(SoftSpokenRandomTapeStateSourceBridge::path_selected(
        player(), 1, 0, 0x11, 2, false, false, false, false));
    need(SoftSpokenRandomTapeStateSourceBridge::state_lookup(player(), true));
    need(SoftSpokenRandomTapeStateSourceBridge::call_begin(
        player(), 257, false));
    need(hook.unavailable_count == 1 && hook.terminal_count == 0 &&
         hook.records.size() == records_after_poison);
}

void unbound_worker_is_poisoned() {
    Hook hook;
    auto scope = install(hook);
    begin_call(false);
    std::thread unbound([] {
        auto seed = bytes(0x31, 16);
        auto prng = bytes(0x32, 96);
        need(SoftSpokenRandomTapeStateSourceBridge::seeded_prng(
            seed, prng));
    });
    unbound.join();
    need(hook.unavailable_count == 1 &&
         hook.records.back().kind == SoftSpokenEventKind::Abort &&
         hook.records.back().role == SoftSpokenRole::None);
}

void delayed_prior_call_worker_is_poisoned() {
    Hook hook;
    auto scope = install(hook);
    std::mutex mutex;
    std::condition_variable changed;
    bool first_done{};
    bool run_delayed{};

    begin_call(false);
    std::thread worker([&] {
        complete_role(SoftSpokenRole::Receiver, 0x80);
        {
            std::lock_guard lock(mutex);
            first_done = true;
        }
        changed.notify_all();
        {
            std::unique_lock lock(mutex);
            changed.wait(lock, [&] { return run_delayed; });
        }
        auto seed = bytes(0x71, 16);
        auto prng = bytes(0x72, 96);
        need(SoftSpokenRandomTapeStateSourceBridge::seeded_prng(
            seed, prng));
    });
    complete_role(SoftSpokenRole::Sender, 0x10);
    {
        std::unique_lock lock(mutex);
        changed.wait(lock, [&] { return first_done; });
    }
    finish_call();
    begin_call(true, 511);
    {
        std::lock_guard lock(mutex);
        run_delayed = true;
    }
    changed.notify_all();
    worker.join();
    need(hook.unavailable_count == 1 &&
         hook.records.back().kind == SoftSpokenEventKind::Abort);
}

} // namespace

int main(int argc, char** argv) {
    need(argc == 2);
    const std::string mode(argv[1]);
    if (mode == "normal") normal();
    else if (mode == "replay") replay();
    else if (mode == "wrong-player") wrong_player();
    else if (mode == "substitution") substitution();
    else if (mode == "drop") drop();
    else if (mode == "cross-thread") cross_thread();
    else if (mode == "peer-swap") peer_swap();
    else if (mode == "kos") rejected_path(SoftSpokenPathClass::Kos);
    else if (mode == "silent") rejected_path(SoftSpokenPathClass::Silent);
    else if (mode == "semi") rejected_path(SoftSpokenPathClass::SemiHonest);
    else if (mode == "high")
        rejected_path(SoftSpokenPathClass::HighOrOtherK);
    else if (mode == "libote1")
        rejected_path(SoftSpokenPathClass::LibOte1);
    else if (mode == "role")
        rejected_path(SoftSpokenPathClass::UnsupportedRole);
    else if (mode == "abort") abort_role();
    else if (mode == "hook-reject") hook_reject();
    else if (mode == "terminal-reject") terminal_reject();
    else if (mode == "unlinked") unlinked();
    else if (mode == "poisoned-retry") poisoned_retry_stays_selected();
    else if (mode == "unbound-worker") unbound_worker_is_poisoned();
    else if (mode == "delayed-worker")
        delayed_prior_call_worker_is_poisoned();
    else need(false);
}
