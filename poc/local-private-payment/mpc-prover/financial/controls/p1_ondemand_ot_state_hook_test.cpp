#include "../../p1_ondemand_ot_state_hook.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace kpi::mpc::p1_private_state;

namespace {

void need(bool value) {
    if (!value) throw std::runtime_error("P1-OnDemandOT-control");
}

struct Record final {
    OnDemandOtEventKind kind{};
    OnDemandOtTransitionClass transition{};
    OnDemandOtMapBranch branch{};
    OnDemandOtAbortClass abort_class{};
    OnDemandOtPhase phase{};
    std::uint64_t sequence{};
    std::uint64_t round{};
    std::uint64_t call{};
    std::uint64_t player_epoch{};
    std::uint64_t root_epoch{};
    std::uint64_t worker_epoch{};
    std::uint64_t peer_index{};
    std::uint64_t peer_role{};
    std::string source_site;
    std::string source_identity;
    std::vector<unsigned char> encoding;
};

class Hook final : public OnDemandOtStateHook {
public:
    enum class WorkerMode {
        Normal,
        DuplicateEpoch,
        Refuse,
    };

    std::vector<Record> records;
    std::mutex records_mutex;
    std::atomic<unsigned> terminal_count{};
    std::atomic<unsigned> unavailable_count{};
    WorkerMode worker_mode{WorkerMode::Normal};
    std::uint64_t reject_sequence{};
    bool terminal_accept{true};

    Hook() : OnDemandOtStateHook(TestOnlyConstruction{}) {}

    bool record_ondemand_ot_event(
            const OnDemandOtEventView& value) noexcept override {
        try {
            auto encoded = encode_ondemand_ot_event(value);
            Record record{
                .kind = value.kind,
                .transition = value.transition,
                .branch = value.branch,
                .abort_class = value.abort_class,
                .phase = value.phase,
                .sequence = value.sequence,
                .round = value.round,
                .call = value.call_in_round,
                .player_epoch = value.player_epoch,
                .root_epoch = value.root_thread_epoch,
                .worker_epoch = value.worker_thread_epoch,
                .peer_index = value.peer_index,
                .peer_role = value.peer_role,
                .source_site = std::string(value.source_site),
                .source_identity =
                    std::string(value.source_identity_sha256),
                .encoding = std::vector<unsigned char>(
                    encoded.view().begin(), encoded.view().end()),
            };
            std::lock_guard lock(records_mutex);
            records.push_back(std::move(record));
            return reject_sequence == 0 || value.sequence != reject_sequence;
        } catch (...) {
            return false;
        }
    }

    bool bind_ondemand_ot_worker_epoch(
            std::uint64_t, std::uint64_t peer_role,
            std::uint64_t& epoch) noexcept override {
        if (worker_mode == WorkerMode::Refuse) return false;
        epoch = worker_mode == WorkerMode::DuplicateEpoch ?
            700U : 700U + peer_role;
        return true;
    }

    bool ondemand_ot_terminal_noexcept() noexcept override {
        ++terminal_count;
        return terminal_accept;
    }

    void ondemand_ot_unavailable_noexcept() noexcept override {
        ++unavailable_count;
    }
};

constexpr auto PLAYER_BITS =
    static_cast<std::uintptr_t>(0x1122334455667788ULL);

const void* player() {
    return reinterpret_cast<const void*>(PLAYER_BITS);
}

std::vector<unsigned char> snapshot(unsigned char tag) {
    std::vector<unsigned char> result(48);
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(tag + index);
    return result;
}

std::unique_ptr<OnDemandOtStateScope> install(Hook& hook) {
    return OnDemandOtStateTestBridge::install(
        hook, player(), 41, 43, 47, 1, 3);
}

void setup_workers(const void* source_player) {
    std::mutex mutex;
    std::condition_variable condition;
    unsigned begun{};
    std::array<bool, 2> ok{};
    std::array<std::thread, 2> workers;
    for (std::uint64_t index = 0; index < workers.size(); ++index) {
        workers[index] = std::thread([&, index] {
            const auto peer = index == 0 ? 0U : 2U;
            ok[index] = OnDemandOtStateSourceBridge::ot_setup_worker_begin(
                source_player, index, peer);
            {
                std::unique_lock lock(mutex);
                ++begun;
                condition.notify_all();
                condition.wait(lock, [&] { return begun == 2; });
            }
            ok[index] = ok[index] &&
                OnDemandOtStateSourceBridge::ot_setup_worker_end(
                    source_player, index, peer, true);
        });
    }
    for (auto& worker : workers) worker.join();
    need(ok[0] && ok[1]);
}

void fresh_call(
        const void* source_player, bool missing, unsigned char tag,
        std::vector<unsigned char>& entry) {
    if (missing) entry = snapshot(tag);
    need(!entry.empty());
    need(OnDemandOtStateSourceBridge::map_lookup(
        source_player, missing ? 0 : 1, !missing,
        missing ? std::span<const unsigned char>{} :
                  std::span<const unsigned char>{entry}));
    if (missing) {
        auto before = snapshot(static_cast<unsigned char>(tag + 1));
        auto after = snapshot(static_cast<unsigned char>(tag + 2));
        need(OnDemandOtStateSourceBridge::map_entry_create_begin(
            source_player));
        need(OnDemandOtStateSourceBridge::prng_before_choice_consume(
            source_player, before));
        need(OnDemandOtStateSourceBridge::prng_after_choice_consume(
            source_player, after));
        setup_workers(source_player);
        need(OnDemandOtStateSourceBridge::map_entry_created(
            source_player, 1, entry));
    }
    need(OnDemandOtStateSourceBridge::get_fresh_begin(
        source_player, entry));
    for (std::uint64_t index = 0; index < 2; ++index) {
        const auto peer = index == 0 ? 0U : 2U;
        auto before = entry;
        auto seeded = snapshot(
            static_cast<unsigned char>(tag + 11 + index * 4));
        auto stored = snapshot(
            static_cast<unsigned char>(tag + 12 + index * 4));
        auto returned = snapshot(
            static_cast<unsigned char>(tag + 13 + index * 4));
        need(OnDemandOtStateSourceBridge::ot_extend_before(
            source_player, index, peer, before));
        need(OnDemandOtStateSourceBridge::ot_seeded_initial_advance(
            source_player, index, peer, seeded));
        need(OnDemandOtStateSourceBridge::ot_extend_stored_advance(
            source_player, index, peer, stored, seeded));
        entry = stored;
        need(OnDemandOtStateSourceBridge::ot_extend_returned_advance(
            source_player, index, peer, returned));
    }
    auto returned = snapshot(static_cast<unsigned char>(tag + 31));
    need(OnDemandOtStateSourceBridge::get_fresh_end(
        source_player, 1, entry, returned));
}

void complete_round_one(
        OnDemandOtStateScope& scope, std::vector<unsigned char>& entry) {
    need(OnDemandOtStateTestBridge::round_begin(scope, 1));
    fresh_call(player(), true, 0x10, entry);
    need(OnDemandOtStateTestBridge::round_end(scope, 1));
}

void complete_round_two(
        OnDemandOtStateScope& scope, std::vector<unsigned char>& entry) {
    need(OnDemandOtStateTestBridge::round_begin(scope, 2));
    fresh_call(player(), false, 0x50, entry);
    need(OnDemandOtStateTestBridge::round_end(scope, 2));
}

std::size_t count_kind(
        const Hook& hook, OnDemandOtEventKind kind) {
    return static_cast<std::size_t>(std::count_if(
        hook.records.begin(), hook.records.end(),
        [&](const auto& value) { return value.kind == kind; }));
}

bool contains_pointer_bytes(const std::vector<unsigned char>& bytes) {
    std::array<unsigned char, sizeof(std::uintptr_t)> little{};
    std::array<unsigned char, sizeof(std::uintptr_t)> big{};
    for (std::size_t index = 0; index < little.size(); ++index) {
        little[index] = static_cast<unsigned char>(
            PLAYER_BITS >> (index * 8U));
        big[big.size() - index - 1] = little[index];
    }
    return std::search(bytes.begin(), bytes.end(),
                       little.begin(), little.end()) != bytes.end() ||
        std::search(bytes.begin(), bytes.end(),
                    big.begin(), big.end()) != bytes.end();
}

void normal() {
    need(!OnDemandOtStateSourceBridge::capture_required_pointer_noexcept(
        player()));
    Hook hook;
    auto scope = install(hook);
    std::vector<unsigned char> entry;
    complete_round_one(*scope, entry);
    complete_round_two(*scope, entry);
    auto map_state = snapshot(0x90);
    need(OnDemandOtStateSourceBridge::map_destructor_begin(
        player(), 1, map_state, entry));
    need(OnDemandOtStateSourceBridge::map_destructor_terminal(
        player(), 0));
    scope.reset();

    const std::array r1_calls{OnDemandOtMapBranch::MissingCreate};
    const std::array r2_calls{OnDemandOtMapBranch::ExistingReuse};
    const auto r1 = recompute_ondemand_ot_branch_manifest(
        1, r1_calls, 1, 3, true, false);
    const auto r2 = recompute_ondemand_ot_branch_manifest(
        2, r2_calls, 1, 3, false, true);
    need(hook.records.size() == r1.size() + r2.size());
    need(hook.records.front().kind == OnDemandOtEventKind::Construct);
    need(hook.records.back().kind ==
         OnDemandOtEventKind::MapDestructorTerminal);
    need(count_kind(hook, OnDemandOtEventKind::MapLookup) == 2);
    need(count_kind(hook, OnDemandOtEventKind::PrngBeforeChoiceConsume) == 1);
    need(count_kind(hook, OnDemandOtEventKind::PrngAfterChoiceConsume) == 1);
    need(count_kind(hook, OnDemandOtEventKind::OtSetupWorkerBegin) == 2);
    need(count_kind(hook, OnDemandOtEventKind::OtSetupWorkerEnd) == 2);
    need(count_kind(hook, OnDemandOtEventKind::OtExtendBefore) == 4);
    need(count_kind(hook, OnDemandOtEventKind::OtSeededInitialAdvance) == 4);
    need(count_kind(hook, OnDemandOtEventKind::OtExtendStoredAdvance) == 4);
    need(count_kind(hook, OnDemandOtEventKind::OtExtendReturnedAdvance) == 4);
    need(hook.terminal_count == 1 && hook.unavailable_count == 0);

    std::array<std::uint64_t, 2> worker_epochs{};
    for (std::size_t index = 0; index < hook.records.size(); ++index) {
        const auto& record = hook.records[index];
        need(record.sequence == index + 1);
        need(record.player_epoch == 43 && record.root_epoch == 47);
        need(record.source_identity.size() == 64);
        need(!record.source_site.empty() && !record.encoding.empty());
        need(!contains_pointer_bytes(record.encoding));
        if (record.kind == OnDemandOtEventKind::OtSetupWorkerBegin) {
            need(record.worker_epoch != 0 && record.worker_epoch != 47);
            worker_epochs.at(record.peer_index) = record.worker_epoch;
        } else if (record.kind != OnDemandOtEventKind::OtSetupWorkerEnd) {
            need(record.worker_epoch == 0);
        }
    }
    need(worker_epochs[0] != 0 && worker_epochs[1] != 0 &&
         worker_epochs[0] != worker_epochs[1]);
}

void replay_round() {
    Hook hook;
    auto scope = install(hook);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(!OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(hook.unavailable_count == 1);
}

void wrong_player() {
    Hook hook;
    auto scope = install(hook);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 1));
    const auto wrong = reinterpret_cast<const void*>(PLAYER_BITS + 1U);
    need(OnDemandOtStateSourceBridge::map_lookup(wrong, 0, false, {}));
    need(hook.unavailable_count == 1);
}

void partial_transition() {
    Hook hook;
    auto scope = install(hook);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(OnDemandOtStateSourceBridge::map_lookup(
        player(), 0, false, {}));
    need(OnDemandOtStateSourceBridge::map_entry_create_begin(player()));
    auto bytes = snapshot(1);
    need(OnDemandOtStateSourceBridge::prng_before_choice_consume(
        player(), bytes));
    need(OnDemandOtStateSourceBridge::map_entry_created(player(), 1, bytes));
    need(hook.unavailable_count == 1);
}

void rollback_map() {
    Hook hook;
    auto scope = install(hook);
    std::vector<unsigned char> entry;
    complete_round_one(*scope, entry);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 2));
    need(OnDemandOtStateSourceBridge::map_lookup(
        player(), 0, false, {}));
    need(hook.unavailable_count == 1);
}

void substituted_state() {
    Hook hook;
    auto scope = install(hook);
    std::vector<unsigned char> entry;
    complete_round_one(*scope, entry);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 2));
    auto substituted = entry;
    substituted.at(0) ^= 0xffU;
    need(OnDemandOtStateSourceBridge::map_lookup(
        player(), 1, true, substituted));
    need(hook.unavailable_count == 1);
}

void cross_thread_end() {
    Hook hook;
    auto scope = install(hook);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(OnDemandOtStateSourceBridge::map_lookup(
        player(), 0, false, {}));
    need(OnDemandOtStateSourceBridge::map_entry_create_begin(player()));
    auto bytes = snapshot(1);
    need(OnDemandOtStateSourceBridge::prng_before_choice_consume(
        player(), bytes));
    need(OnDemandOtStateSourceBridge::prng_after_choice_consume(
        player(), bytes));
    std::mutex mutex;
    std::condition_variable condition;
    bool begun{};
    bool finish{};
    std::thread worker([&] {
        need(OnDemandOtStateSourceBridge::ot_setup_worker_begin(
            player(), 0, 0));
        std::unique_lock lock(mutex);
        begun = true;
        condition.notify_all();
        condition.wait(lock, [&] { return finish; });
    });
    {
        std::unique_lock lock(mutex);
        condition.wait(lock, [&] { return begun; });
    }
    need(OnDemandOtStateSourceBridge::ot_setup_worker_end(
        player(), 0, 0, true));
    {
        std::lock_guard lock(mutex);
        finish = true;
    }
    condition.notify_all();
    worker.join();
    need(hook.unavailable_count == 1);
}

void duplicate_worker_epoch() {
    Hook hook;
    hook.worker_mode = Hook::WorkerMode::DuplicateEpoch;
    auto scope = install(hook);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(OnDemandOtStateSourceBridge::map_lookup(
        player(), 0, false, {}));
    need(OnDemandOtStateSourceBridge::map_entry_create_begin(player()));
    auto bytes = snapshot(1);
    need(OnDemandOtStateSourceBridge::prng_before_choice_consume(
        player(), bytes));
    need(OnDemandOtStateSourceBridge::prng_after_choice_consume(
        player(), bytes));
    setup_workers(player());
    need(hook.unavailable_count == 1);
}

void swapped_worker_peer() {
    Hook hook;
    auto scope = install(hook);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(OnDemandOtStateSourceBridge::map_lookup(
        player(), 0, false, {}));
    need(OnDemandOtStateSourceBridge::map_entry_create_begin(player()));
    auto bytes = snapshot(1);
    need(OnDemandOtStateSourceBridge::prng_before_choice_consume(
        player(), bytes));
    need(OnDemandOtStateSourceBridge::prng_after_choice_consume(
        player(), bytes));
    std::thread worker([&] {
        need(OnDemandOtStateSourceBridge::ot_setup_worker_begin(
            player(), 0, 2));
    });
    worker.join();
    need(hook.unavailable_count == 1);
}

void dropped_scope() {
    Hook hook;
    auto scope = install(hook);
    scope.reset();
    need(hook.unavailable_count == 1);
    need(!hook.records.empty());
    need(hook.records.back().kind == OnDemandOtEventKind::Abort);
    need(hook.records.back().abort_class ==
         OnDemandOtAbortClass::ScopeUnlinked);
}

void hook_rejection() {
    Hook hook;
    hook.reject_sequence = 2;
    auto scope = install(hook);
    need(!OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(hook.unavailable_count == 1);
}

void terminal_rejection() {
    Hook hook;
    hook.terminal_accept = false;
    auto scope = install(hook);
    std::vector<unsigned char> entry;
    complete_round_one(*scope, entry);
    complete_round_two(*scope, entry);
    auto bytes = snapshot(9);
    need(OnDemandOtStateSourceBridge::map_destructor_begin(
        player(), 1, bytes, entry));
    need(OnDemandOtStateSourceBridge::map_destructor_terminal(
        player(), 0));
    need(hook.terminal_count == 1 && hook.unavailable_count == 1);
}

void source_abort() {
    Hook hook;
    auto scope = install(hook);
    need(OnDemandOtStateTestBridge::round_begin(*scope, 1));
    need(OnDemandOtStateSourceBridge::map_lookup(
        player(), 0, false, {}));
    need(OnDemandOtStateSourceBridge::map_entry_create_begin(player()));
    OnDemandOtStateSourceBridge::get_fresh_abort_noexcept(player());
    need(hook.unavailable_count == 1);
    need(hook.records.back().kind == OnDemandOtEventKind::Abort);
    need(hook.records.back().abort_class ==
         OnDemandOtAbortClass::GetFreshException);
    need(hook.records.back().phase == OnDemandOtPhase::Creating);
    need(hook.records.back().source_site.find("get_fresh/catch") !=
         std::string::npos);
}

} // namespace

int main(int argc, char** argv) {
    need(argc == 2);
    const std::string mode(argv[1]);
    if (mode == "normal") normal();
    else if (mode == "replay") replay_round();
    else if (mode == "wrong-player") wrong_player();
    else if (mode == "partial") partial_transition();
    else if (mode == "rollback") rollback_map();
    else if (mode == "substitution") substituted_state();
    else if (mode == "cross-thread") cross_thread_end();
    else if (mode == "duplicate-worker") duplicate_worker_epoch();
    else if (mode == "peer-swap") swapped_worker_peer();
    else if (mode == "drop") dropped_scope();
    else if (mode == "hook-reject") hook_rejection();
    else if (mode == "terminal-reject") terminal_rejection();
    else if (mode == "abort") source_abort();
    else need(false);
}
