#include "p1_beaver_source_capture.hpp"
#include "p1_scalar_capture_manifest.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace kpi::mpc;
using namespace kpi::mpc::p1_private_state;

namespace {

void expect(bool condition) {
    if (!condition) throw std::runtime_error("p1-beaver-control");
}

struct SavedEvent final {
    BeaverEventKind kind{};
    BeaverAbortClass abort_class{};
    BeaverPhase phase{};
    std::uint64_t sequence{};
    std::uint64_t round{};
    std::uint64_t round_event_index{};
    std::uint64_t batch_epoch{};
    std::uint64_t scalar_capture_site{};
    std::uint64_t expected_multiplications{};
    std::uint64_t item_index{};
    std::uint64_t cache_epoch{};
    std::uint64_t cache_size_before{};
    std::uint64_t cache_size_after{};
    bool source_succeeded{};
    std::string source_site;
    std::string source_identity;
    std::vector<unsigned char> source_state;
    std::vector<unsigned char> encoded;
};

class RecordingHook final : public BeaverStateHook {
    std::size_t reject_record_{};
    bool terminal_accept_{true};

    bool record_beaver_event(const BeaverEventView& view) noexcept override {
        if (reject_record_ != 0 &&
            records.size() + 1 == reject_record_)
            return false;
        try {
            SavedEvent saved{
                .kind = view.kind,
                .abort_class = view.abort_class,
                .phase = view.phase,
                .sequence = view.sequence,
                .round = view.round,
                .round_event_index = view.round_event_index,
                .batch_epoch = view.batch_epoch,
                .scalar_capture_site = view.scalar_capture_site,
                .expected_multiplications = view.expected_multiplications,
                .item_index = view.item_index,
                .cache_epoch = view.cache_epoch,
                .cache_size_before = view.cache_size_before,
                .cache_size_after = view.cache_size_after,
                .source_succeeded = view.source_succeeded,
                .source_site = std::string(view.source_site),
                .source_identity = std::string(view.source_identity_sha256),
                .source_state = std::vector<unsigned char>(
                    view.source_state.begin(), view.source_state.end()),
                .encoded = encode_beaver_event(view),
            };
            records.push_back(std::move(saved));
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool beaver_terminal_noexcept() noexcept override {
        ++terminal_calls;
        return terminal_accept_;
    }

    void beaver_unavailable_noexcept() noexcept override {
        ++unavailable_calls;
    }

public:
    explicit RecordingHook(
            std::size_t reject_record = 0,
            bool terminal_accept = true)
        : BeaverStateHook(TestOnlyConstruction{}),
          reject_record_(reject_record),
          terminal_accept_(terminal_accept) {}

    std::vector<SavedEvent> records;
    std::size_t terminal_calls{};
    std::size_t unavailable_calls{};
};

constexpr std::array<unsigned char, 4> GENERATED{0x81, 0x82, 0x83, 0x84};
constexpr std::array<unsigned char, 3> PREPARE_A{0x11, 0x12, 0x13};
constexpr std::array<unsigned char, 3> PREPARE_B{0x21, 0x22, 0x23};
constexpr std::array<unsigned char, 4> IDENTITY_A{0x31, 0x32, 0x33, 0x34};
constexpr std::array<unsigned char, 4> IDENTITY_B{0x41, 0x42, 0x43, 0x44};
constexpr std::array<unsigned char, 4> MASK_A{0x51, 0x52, 0x53, 0x54};
constexpr std::array<unsigned char, 4> MASK_B{0x61, 0x62, 0x63, 0x64};
constexpr std::array<unsigned char, 3> OPEN_A{0x71, 0x72, 0x73};
constexpr std::array<unsigned char, 3> OPEN_B{0x75, 0x76, 0x77};
constexpr std::array<unsigned char, 3> FINAL_A{0x91, 0x92, 0x93};
constexpr std::array<unsigned char, 3> FINAL_B{0xa1, 0xa2, 0xa3};

bool retained(BeaverRetainResult result) {
    return result == BeaverRetainResult::Retained;
}

std::unique_ptr<BeaverSourceScope> install(RecordingHook& hook) {
    return BeaverStateTestBridge::install(hook, 17, 29, 1, 3);
}

void start_prepared_batch(
        BeaverSourceScope& scope, const void* beaver,
        p1_capture::ScalarCaptureSite site) {
    expect(BeaverStateTestBridge::batch_begin(
        scope, static_cast<std::uint64_t>(site), 2));
    expect(retained(BeaverStateSourceBridge::test_only_init(beaver)));
    expect(retained(BeaverStateSourceBridge::test_only_prepare(
        beaver, PREPARE_A)));
    expect(retained(BeaverStateSourceBridge::test_only_prepare(
        beaver, PREPARE_B)));
}

void consume(
        const void* cache, const void* beaver,
        std::uint64_t before, std::span<const unsigned char> identity,
        std::span<const unsigned char> mask) {
    expect(retained(BeaverStateSourceBridge::test_only_cache_pop(
        cache, before, before - 1, identity, identity)));
    expect(retained(BeaverStateSourceBridge::test_only_triple_mask(
        beaver, mask, identity)));
}

void finish_batch(const void* beaver) {
    expect(retained(BeaverStateSourceBridge::test_only_opened_result(
        beaver, OPEN_A)));
    expect(retained(BeaverStateSourceBridge::test_only_opened_result(
        beaver, OPEN_B)));
    expect(retained(BeaverStateSourceBridge::test_only_finalize_return(
        beaver, FINAL_A)));
    expect(retained(BeaverStateSourceBridge::test_only_finalize_return(
        beaver, FINAL_B)));
}

void complete_two_rounds(
        RecordingHook& hook, std::unique_ptr<BeaverSourceScope>& scope) {
    int cache = 0;
    int first_beaver = 0;
    int second_beaver = 0;

    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    start_prepared_batch(
        *scope, &first_beaver,
        p1_capture::ScalarCaptureSite::FinancialAssignmentResidual);
    expect(retained(BeaverStateSourceBridge::test_only_cache_batch(
        &cache, 0, 4, GENERATED)));
    consume(&cache, &first_beaver, 4, IDENTITY_A, MASK_A);
    consume(&cache, &first_beaver, 3, IDENTITY_B, MASK_B);
    finish_batch(&first_beaver);
    expect(BeaverStateTestBridge::round_end(*scope, 1));

    expect(BeaverStateTestBridge::round_begin(*scope, 2));
    start_prepared_batch(
        *scope, &second_beaver,
        p1_capture::ScalarCaptureSite::StreamedHProduct);
    consume(&cache, &second_beaver, 2, IDENTITY_A, MASK_A);
    consume(&cache, &second_beaver, 1, IDENTITY_B, MASK_B);
    finish_batch(&second_beaver);
    expect(BeaverStateTestBridge::round_end(*scope, 2));

    expect(BeaverStateTestBridge::finish(std::move(scope)));
    expect(hook.terminal_calls == 1);
}

void normal() {
    RecordingHook hook;
    auto scope = install(hook);
    complete_two_rounds(hook, scope);
    expect(hook.unavailable_calls == 0);
    expect(hook.records.size() == 32);
    expect(hook.records.front().kind == BeaverEventKind::Construct);
    expect(hook.records.back().kind == BeaverEventKind::RoundEnd);
    std::set<std::vector<unsigned char>> encodings;
    std::uint64_t previous_round = 0;
    std::uint64_t previous_round_index = 0;
    for (std::size_t index = 0; index < hook.records.size(); ++index) {
        const auto& event = hook.records[index];
        expect(event.sequence == index + 1);
        expect(event.source_succeeded);
        expect(event.abort_class == BeaverAbortClass::None);
        expect(event.source_identity.size() == 64);
        expect(encodings.insert(event.encoded).second);
        if (event.kind == BeaverEventKind::RoundBegin) {
            expect(event.round == previous_round + 1);
            expect(event.round_event_index == 1);
            previous_round = event.round;
            previous_round_index = 1;
        }
        else if (event.round != 0) {
            expect(event.round_event_index == previous_round_index + 1);
            previous_round_index = event.round_event_index;
        }
        if (event.kind >= BeaverEventKind::CacheBatchGenerated &&
            event.kind <= BeaverEventKind::FinalizeReturn &&
            event.kind != BeaverEventKind::BatchBegin &&
            event.kind != BeaverEventKind::Init)
            expect(!event.source_state.empty());
    }
    std::vector<const SavedEvent*> pops;
    for (const auto& event : hook.records)
        if (event.kind == BeaverEventKind::CacheTriplePop)
            pops.push_back(&event);
    expect(pops.size() == 4);
    for (std::size_t index = 0; index < pops.size(); ++index) {
        expect(pops[index]->cache_epoch == 1);
        expect(pops[index]->item_index == index % 2);
    }
    expect(pops[0]->cache_size_before == 4 &&
           pops[0]->cache_size_after == 3);
    expect(pops[3]->cache_size_before == 1 &&
           pops[3]->cache_size_after == 0);
    expect(BeaverStateSourceBridge::test_only_serialization_failure() ==
           BeaverRetainResult::NotRequired);
}

void replay() {
    RecordingHook hook;
    auto scope = install(hook);
    int beaver = 0;
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    expect(BeaverStateTestBridge::batch_begin(
        *scope, static_cast<std::uint64_t>(
            p1_capture::ScalarCaptureSite::FinancialAssignmentResidual), 2));
    expect(retained(BeaverStateSourceBridge::test_only_init(&beaver)));
    expect(BeaverStateSourceBridge::test_only_init(&beaver) ==
           BeaverRetainResult::Failed);
    expect(hook.unavailable_calls == 1);
}

void partial() {
    RecordingHook hook;
    {
        auto scope = install(hook);
        int beaver = 0;
        expect(BeaverStateTestBridge::round_begin(*scope, 1));
        expect(BeaverStateTestBridge::batch_begin(
            *scope, static_cast<std::uint64_t>(
                p1_capture::ScalarCaptureSite::FinancialAssignmentResidual),
            2));
        expect(retained(BeaverStateSourceBridge::test_only_init(&beaver)));
    }
    expect(hook.unavailable_calls == 1);
    expect(hook.records.back().kind == BeaverEventKind::Abort);
    expect(hook.records.back().abort_class == BeaverAbortClass::PartialBatch);
    const std::string state(
        hook.records.back().source_state.begin(),
        hook.records.back().source_state.end());
    expect(state.starts_with("KPI_P1_BEAVER_ABORT_LIVE_STATE_V1\n"));
}

void prepare_for_cache(
        RecordingHook& hook, std::unique_ptr<BeaverSourceScope>& scope,
        int& beaver) {
    scope = install(hook);
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    start_prepared_batch(
        *scope, &beaver,
        p1_capture::ScalarCaptureSite::FinancialAssignmentResidual);
}

void rollback() {
    RecordingHook hook;
    std::unique_ptr<BeaverSourceScope> scope;
    int beaver = 0;
    int cache = 0;
    prepare_for_cache(hook, scope, beaver);
    expect(retained(BeaverStateSourceBridge::test_only_cache_batch(
        &cache, 0, 2, GENERATED)));
    expect(BeaverStateSourceBridge::test_only_cache_batch(
        &cache, 1, 3, GENERATED) == BeaverRetainResult::Failed);
    expect(hook.unavailable_calls == 1);
}

void substitution() {
    RecordingHook hook;
    std::unique_ptr<BeaverSourceScope> scope;
    int beaver = 0;
    int cache = 0;
    int replacement = 0;
    prepare_for_cache(hook, scope, beaver);
    expect(retained(BeaverStateSourceBridge::test_only_cache_batch(
        &cache, 0, 2, GENERATED)));
    expect(BeaverStateSourceBridge::test_only_cache_pop(
        &replacement, 2, 1, IDENTITY_A, IDENTITY_A) ==
        BeaverRetainResult::Failed);
    expect(hook.unavailable_calls == 1);
}

void identity_mismatch() {
    RecordingHook hook;
    std::unique_ptr<BeaverSourceScope> scope;
    int beaver = 0;
    int cache = 0;
    prepare_for_cache(hook, scope, beaver);
    expect(retained(BeaverStateSourceBridge::test_only_cache_batch(
        &cache, 0, 2, GENERATED)));
    expect(retained(BeaverStateSourceBridge::test_only_cache_pop(
        &cache, 2, 1, IDENTITY_A, IDENTITY_A)));
    expect(BeaverStateSourceBridge::test_only_triple_mask(
        &beaver, MASK_A, IDENTITY_B) == BeaverRetainResult::Failed);
    expect(hook.unavailable_calls == 1);
}

void cross_thread() {
    RecordingHook hook;
    auto scope = install(hook);
    int beaver = 0;
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    expect(BeaverStateTestBridge::batch_begin(
        *scope, static_cast<std::uint64_t>(
            p1_capture::ScalarCaptureSite::FinancialAssignmentResidual), 2));
    BeaverRetainResult result = BeaverRetainResult::Retained;
    std::thread worker([&] {
        result = BeaverStateSourceBridge::test_only_init(&beaver);
    });
    worker.join();
    expect(result == BeaverRetainResult::Failed);
    expect(hook.unavailable_calls == 1);
}

void wrong_player() {
    RecordingHook hook;
    bool threw = false;
    try {
        auto scope = BeaverStateTestBridge::install(hook, 17, 29, 0, 3);
        (void)scope;
    }
    catch (const std::runtime_error&) {
        threw = true;
    }
    expect(threw);
    expect(hook.records.empty());
}

void hook_reject() {
    RecordingHook hook(3);
    auto scope = install(hook);
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    expect(!BeaverStateTestBridge::batch_begin(
        *scope, static_cast<std::uint64_t>(
            p1_capture::ScalarCaptureSite::FinancialAssignmentResidual), 2));
    expect(hook.unavailable_calls == 1);
}

void terminal_reject_expected() {
    RecordingHook hook(0, false);
    auto scope = install(hook);
    int cache = 0;
    int beaver_a = 0;
    int beaver_b = 0;
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    start_prepared_batch(
        *scope, &beaver_a,
        p1_capture::ScalarCaptureSite::FinancialAssignmentResidual);
    expect(retained(BeaverStateSourceBridge::test_only_cache_batch(
        &cache, 0, 4, GENERATED)));
    consume(&cache, &beaver_a, 4, IDENTITY_A, MASK_A);
    consume(&cache, &beaver_a, 3, IDENTITY_B, MASK_B);
    finish_batch(&beaver_a);
    expect(BeaverStateTestBridge::round_end(*scope, 1));
    expect(BeaverStateTestBridge::round_begin(*scope, 2));
    start_prepared_batch(
        *scope, &beaver_b,
        p1_capture::ScalarCaptureSite::StreamedHProduct);
    consume(&cache, &beaver_b, 2, IDENTITY_A, MASK_A);
    consume(&cache, &beaver_b, 1, IDENTITY_B, MASK_B);
    finish_batch(&beaver_b);
    expect(BeaverStateTestBridge::round_end(*scope, 2));
    expect(!BeaverStateTestBridge::finish(std::move(scope)));
    expect(hook.terminal_calls == 1);
    expect(hook.unavailable_calls == 1);
}

void explicit_abort() {
    RecordingHook hook;
    std::unique_ptr<BeaverSourceScope> scope;
    int beaver = 0;
    int cache = 0;
    prepare_for_cache(hook, scope, beaver);
    expect(retained(BeaverStateSourceBridge::test_only_cache_batch(
        &cache, 0, 4, GENERATED)));
    consume(&cache, &beaver, 4, IDENTITY_A, MASK_A);
    expect(BeaverStateTestBridge::abort(
        *scope, BeaverAbortClass::UpstreamException));
    expect(hook.records.back().kind == BeaverEventKind::Abort);
    expect(hook.records.back().abort_class ==
           BeaverAbortClass::UpstreamException);
    expect(!hook.records.back().source_succeeded);
    expect(hook.records.back().cache_size_before == 0);
    expect(hook.unavailable_calls == 1);
}

void overlap() {
    RecordingHook first;
    RecordingHook second;
    auto scope = install(first);
    bool threw = false;
    try {
        auto other = install(second);
        (void)other;
    }
    catch (const std::runtime_error&) {
        threw = true;
    }
    expect(threw);
    scope.reset();
    expect(first.records.back().abort_class ==
           BeaverAbortClass::TerminalIncomplete);
    expect(second.records.empty());
}

void wrong_site() {
    RecordingHook hook;
    auto scope = install(hook);
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    expect(!BeaverStateTestBridge::batch_begin(
        *scope, static_cast<std::uint64_t>(
            p1_capture::ScalarCaptureSite::OwnerDdnntRandomV), 2));
    expect(hook.unavailable_calls == 1);
}

void serialization_failure() {
    RecordingHook hook;
    auto scope = install(hook);
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    expect(BeaverStateSourceBridge::test_only_serialization_failure() ==
           BeaverRetainResult::Failed);
    expect(hook.unavailable_calls == 1);
}

void incomplete_finish() {
    RecordingHook hook;
    auto scope = install(hook);
    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    expect(!BeaverStateTestBridge::finish(std::move(scope)));
    expect(hook.records.back().kind == BeaverEventKind::Abort);
    expect(hook.records.back().abort_class ==
           BeaverAbortClass::TerminalIncomplete);
    expect(hook.unavailable_calls == 1);
}

void bad_encoding() {
    const BeaverEventView forged{
        .kind = BeaverEventKind::Construct,
        .abort_class = BeaverAbortClass::None,
        .phase = BeaverPhase::Constructed,
        .sequence = 1,
        .persistent_child_epoch = 1,
        .root_thread_epoch = 1,
        .local_role = 0,
        .player_count = 3,
        .source_succeeded = true,
        .source_site = "forged",
        .source_identity_sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000",
        .source_state = {},
    };
    bool threw = false;
    try {
        (void)encode_beaver_event(forged);
    }
    catch (const std::runtime_error&) {
        threw = true;
    }
    expect(threw);
}

} // namespace

int main(int argc, char** argv) {
    try {
        expect(argc == 2);
        const std::string mode = argv[1];
        if (mode == "normal") normal();
        else if (mode == "replay") replay();
        else if (mode == "partial") partial();
        else if (mode == "rollback") rollback();
        else if (mode == "substitution") substitution();
        else if (mode == "identity-mismatch") identity_mismatch();
        else if (mode == "cross-thread") cross_thread();
        else if (mode == "wrong-player") wrong_player();
        else if (mode == "hook-reject") hook_reject();
        else if (mode == "terminal-reject") terminal_reject_expected();
        else if (mode == "abort") explicit_abort();
        else if (mode == "overlap") overlap();
        else if (mode == "wrong-site") wrong_site();
        else if (mode == "serialization-failure") serialization_failure();
        else if (mode == "incomplete-finish") incomplete_finish();
        else if (mode == "bad-encoding") bad_encoding();
        else expect(false);
        return 0;
    }
    catch (...) {
        return 1;
    }
}
