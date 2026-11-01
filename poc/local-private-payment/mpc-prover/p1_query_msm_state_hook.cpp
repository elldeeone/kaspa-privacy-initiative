#include "p1_query_msm_state_hook.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string_view>

namespace kpi::mpc::p1_private_state {
namespace {

constexpr std::string_view FINANCIAL_PROVER_BASELINE_SHA256 =
    "846ee1ff701ef6f8c0ca028b9dcf62ea9b1ae356c5cb87d55042ba4b725a4073";
constexpr std::string_view AUTH_GROUPS_BASELINE_SHA256 =
    "b6c4a9960c87ec4b46c4651623a9efb5b891315477d6f55bc0f6797417212400";
constexpr std::array<QueryMsmKind, 5> QUERY_ORDER{{
    QueryMsmKind::A, QueryMsmKind::B1, QueryMsmKind::B2,
    QueryMsmKind::H, QueryMsmKind::L}};

bool lower_hex_word(std::string_view value) noexcept {
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](char byte) {
            return (byte >= '0' && byte <= '9') ||
                (byte >= 'a' && byte <= 'f');
        });
}

QueryMsmGroup expected_group(QueryMsmKind kind) noexcept {
    return kind == QueryMsmKind::B2 ? QueryMsmGroup::G2 :
        QueryMsmGroup::G1;
}

std::uint64_t checked_add(
        std::uint64_t left, std::uint64_t right) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left)
        throw std::runtime_error("P1-query-MSM-counter-overflow");
    return left + right;
}

} // namespace

struct QueryMsmStateStorage final {
    std::mutex mutex;
    QueryMsmStateHook* hook{};
    std::uint64_t persistent_child_epoch{};
    std::uint64_t root_thread_epoch{};
    std::uint64_t round{};
    std::uint64_t sequence{};
    QueryMsmPhase phase{QueryMsmPhase::Constructed};
    bool scope_live{true};
    bool terminal{};
    bool unavailable_published{};
    bool abort_recorded{};

    std::uint64_t next_query{};
    QueryMsmKind query{};
    QueryMsmGroup group{};
    std::uint64_t query_points{};
    std::uint64_t query_scalars{};
    std::uint64_t cursor_point{};
    std::uint64_t chunk_ordinal{};
    std::uint64_t chunk_first{};
    std::uint64_t chunk_count{};
    std::uint64_t expected_workers{};
    std::uint64_t completed_workers{};
    std::array<bool, QUERY_MSM_SELECTED_WORKERS> worker_started{};
    std::array<bool, QUERY_MSM_SELECTED_WORKERS> worker_finished{};
    std::array<std::uint64_t, QUERY_MSM_SELECTED_WORKERS> worker_epochs{};
    std::uint8_t next_post_stage{
        static_cast<std::uint8_t>(QueryMsmPostStage::MixedInputs)};

    QueryMsmEventView event(
            QueryMsmEventKind kind,
            std::span<const unsigned char> exact_state = {},
            std::string_view source_site = {},
            std::string_view source_identity = {},
            QueryMsmAbortClass abort_class = QueryMsmAbortClass::None,
            QueryMsmPostStage post_stage = {},
            std::uint64_t worker_ordinal = 0,
            std::uint64_t worker_epoch = 0,
            std::uint64_t worker_first = 0,
            std::uint64_t worker_last = 0) noexcept {
        return {
            .kind = kind,
            .abort_class = abort_class,
            .phase = phase,
            .query = query,
            .group = group,
            .post_stage = post_stage,
            .sequence = ++sequence,
            .persistent_child_epoch = persistent_child_epoch,
            .root_thread_epoch = root_thread_epoch,
            .worker_thread_epoch = worker_epoch,
            .round = round,
            .query_ordinal = next_query < QUERY_ORDER.size() ?
                next_query + 1 : QUERY_ORDER.size(),
            .chunk_ordinal = chunk_ordinal,
            .worker_ordinal = worker_ordinal,
            .query_points = query_points,
            .query_scalars = query_scalars,
            .chunk_first = chunk_first,
            .chunk_count = chunk_count,
            .worker_first = worker_first,
            .worker_last = worker_last,
            .completed_workers = completed_workers,
            .cursor_point = cursor_point,
            .source_site = source_site,
            .source_identity_sha256 = source_identity,
            .exact_state = exact_state,
        };
    }

    bool emit(
            QueryMsmEventKind kind,
            std::span<const unsigned char> exact_state,
            std::string_view source_site,
            std::string_view source_identity,
            QueryMsmAbortClass abort_class = QueryMsmAbortClass::None,
            QueryMsmPostStage post_stage = {},
            std::uint64_t worker_ordinal = 0,
            std::uint64_t worker_epoch = 0,
            std::uint64_t worker_first = 0,
            std::uint64_t worker_last = 0) noexcept {
        const auto view = event(
            kind, exact_state, source_site, source_identity, abort_class,
            post_stage, worker_ordinal, worker_epoch, worker_first,
            worker_last);
        return hook->record_query_msm_event(view);
    }

    void publish_unavailable() noexcept {
        if (!unavailable_published) {
            unavailable_published = true;
            hook->query_msm_unavailable_noexcept();
        }
    }

    void poison(
            QueryMsmAbortClass abort_class,
            std::string_view source_site,
            std::string_view source_identity,
            std::span<const unsigned char> exact_live_state = {}) noexcept {
        if (terminal) {
            terminal = false;
        }
        phase = QueryMsmPhase::Poisoned;
        if (!abort_recorded) {
            abort_recorded = true;
            (void) emit(
                QueryMsmEventKind::Abort, exact_live_state, source_site,
                source_identity, abort_class);
        }
        publish_unavailable();
    }

    [[noreturn]] void refuse(
            QueryMsmAbortClass abort_class,
            std::string_view source_site,
            std::string_view source_identity) {
        poison(abort_class, source_site, source_identity);
        throw std::runtime_error("P1-query-MSM-state-unavailable");
    }

    void require(bool condition, std::string_view source_site,
                 std::string_view source_identity) {
        if (!condition)
            refuse(QueryMsmAbortClass::ReplayOrOrder, source_site,
                   source_identity);
    }
};

QueryMsmStateScope::QueryMsmStateScope(
        std::shared_ptr<QueryMsmStateStorage> storage)
    : storage_(std::move(storage)) {}

std::unique_ptr<QueryMsmStateScope> QueryMsmStateScope::install(
        QueryMsmStateHook& hook, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t round) {
    if (persistent_child_epoch == 0 || root_thread_epoch == 0 ||
        (round != 1 && round != 2)) {
        hook.query_msm_unavailable_noexcept();
        throw std::runtime_error("P1-query-MSM-scope-identity");
    }
    auto storage = std::make_shared<QueryMsmStateStorage>();
    storage->hook = &hook;
    storage->persistent_child_epoch = persistent_child_epoch;
    storage->root_thread_epoch = root_thread_epoch;
    storage->round = round;
    {
        std::lock_guard lock(storage->mutex);
        if (!storage->emit(
                QueryMsmEventKind::ScopeConstructed, {},
                "p1-query-msm-scope-constructed",
                FINANCIAL_PROVER_BASELINE_SHA256)) {
            storage->poison(
                QueryMsmAbortClass::HookRefused,
                "p1-query-msm-scope-constructed",
                FINANCIAL_PROVER_BASELINE_SHA256);
            throw std::runtime_error("P1-query-MSM-hook-refused");
        }
        storage->phase = QueryMsmPhase::BetweenQueries;
    }
    return std::unique_ptr<QueryMsmStateScope>(
        new QueryMsmStateScope(std::move(storage)));
}

QueryMsmStateScope::~QueryMsmStateScope() {
    if (!storage_) return;
    std::lock_guard lock(storage_->mutex);
    storage_->scope_live = false;
    if (!storage_->terminal)
        storage_->poison(
            QueryMsmAbortClass::ScopeUnlinked,
            "p1-query-msm-scope-dropped",
            FINANCIAL_PROVER_BASELINE_SHA256);
}

QueryMsmWorkerToken::QueryMsmWorkerToken(
        std::shared_ptr<QueryMsmStateStorage> storage, std::uint64_t round,
        std::uint64_t query_ordinal, std::uint64_t chunk_ordinal,
        std::uint64_t worker_ordinal, std::uint64_t worker_thread_epoch,
        std::uint64_t worker_first, std::uint64_t worker_last)
    : storage_(std::move(storage)), round_(round),
      query_ordinal_(query_ordinal), chunk_ordinal_(chunk_ordinal),
      worker_ordinal_(worker_ordinal),
      worker_thread_epoch_(worker_thread_epoch),
      worker_first_(worker_first), worker_last_(worker_last), active_(true) {}

QueryMsmWorkerToken::QueryMsmWorkerToken(
        QueryMsmWorkerToken&& other) noexcept
    : storage_(std::move(other.storage_)), round_(other.round_),
      query_ordinal_(other.query_ordinal_),
      chunk_ordinal_(other.chunk_ordinal_),
      worker_ordinal_(other.worker_ordinal_),
      worker_thread_epoch_(other.worker_thread_epoch_),
      worker_first_(other.worker_first_), worker_last_(other.worker_last_),
      active_(other.active_) {
    other.active_ = false;
}

QueryMsmWorkerToken::~QueryMsmWorkerToken() {
    if (!active_ || !storage_) return;
    std::lock_guard lock(storage_->mutex);
    active_ = false;
    if (storage_->scope_live && !storage_->terminal)
        storage_->poison(
            QueryMsmAbortClass::WorkerDropped,
            "p1-query-msm-worker-token-dropped",
            FINANCIAL_PROVER_BASELINE_SHA256);
}

#ifdef KPI_P1_QUERY_MSM_STATE_HOOK_TEST_SETUP
std::unique_ptr<QueryMsmStateScope>
QueryMsmStateSourceBridge::test_only_install(
        QueryMsmStateHook& hook, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t round) {
    return QueryMsmStateScope::install(
        hook, persistent_child_epoch, root_thread_epoch, round);
}
#endif

void QueryMsmStateSourceBridge::query_begin(
        QueryMsmStateScope& scope, QueryMsmKind query, QueryMsmGroup group,
        std::uint64_t points, std::uint64_t scalars,
        std::span<const unsigned char> exact_unused_scalar) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    state.require(
        state.scope_live && !state.terminal &&
            state.phase == QueryMsmPhase::BetweenQueries &&
            state.next_query < QUERY_ORDER.size() &&
            query == QUERY_ORDER[state.next_query] &&
            group == expected_group(query) && points != 0 &&
            ((query == QueryMsmKind::H &&
              scalars == checked_add(points, 1) &&
              !exact_unused_scalar.empty()) ||
             (query != QueryMsmKind::H && scalars == points &&
              exact_unused_scalar.empty())),
        "p1-query-msm-query-begin", FINANCIAL_PROVER_BASELINE_SHA256);
    state.query = query;
    state.group = group;
    state.query_points = points;
    state.query_scalars = scalars;
    state.cursor_point = 0;
    state.chunk_ordinal = 0;
    state.chunk_first = 0;
    state.chunk_count = 0;
    state.expected_workers = 0;
    state.completed_workers = 0;
    state.phase = QueryMsmPhase::Query;
    if (!state.emit(
            QueryMsmEventKind::QueryBegin, exact_unused_scalar,
            "p1-query-msm-query-begin", FINANCIAL_PROVER_BASELINE_SHA256))
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-query-begin", FINANCIAL_PROVER_BASELINE_SHA256);
}

void QueryMsmStateSourceBridge::chunk_begin(
        QueryMsmStateScope& scope, std::uint64_t first,
        std::uint64_t count,
        std::span<const unsigned char> exact_cursor_state) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    const auto remaining = state.cursor_point <= state.query_points ?
        state.query_points - state.cursor_point : 0;
    state.require(
        state.scope_live && !state.terminal &&
            state.phase == QueryMsmPhase::Query &&
            first == state.cursor_point && count != 0 &&
            count <= QUERY_MSM_SELECTED_CHUNK && count <= remaining &&
            !exact_cursor_state.empty(),
        "p1-query-msm-cursor-chunk", FINANCIAL_PROVER_BASELINE_SHA256);
    state.chunk_first = first;
    state.chunk_count = count;
    state.expected_workers =
        std::min<std::uint64_t>(QUERY_MSM_SELECTED_WORKERS, count);
    state.completed_workers = 0;
    state.worker_started.fill(false);
    state.worker_finished.fill(false);
    state.worker_epochs.fill(0);
    state.phase = QueryMsmPhase::Chunk;
    if (!state.emit(
            QueryMsmEventKind::ChunkBegin, exact_cursor_state,
            "p1-query-msm-cursor-chunk",
            FINANCIAL_PROVER_BASELINE_SHA256))
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-cursor-chunk",
            FINANCIAL_PROVER_BASELINE_SHA256);
}

QueryMsmWorkerToken QueryMsmStateSourceBridge::worker_begin(
        QueryMsmStateScope& scope, std::uint64_t worker,
        std::uint64_t first, std::uint64_t last) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    const auto expected_first = checked_add(
        state.chunk_first,
        state.chunk_count * worker / state.expected_workers);
    const auto expected_last = checked_add(
        state.chunk_first,
        state.chunk_count * (worker + 1) / state.expected_workers);
    state.require(
        state.scope_live && !state.terminal &&
            (state.phase == QueryMsmPhase::Chunk ||
             state.phase == QueryMsmPhase::Workers) &&
            worker < state.expected_workers &&
            !state.worker_started[worker] && first == expected_first &&
            last == expected_last && first < last,
        "p1-query-msm-worker-begin", FINANCIAL_PROVER_BASELINE_SHA256);
    std::uint64_t worker_epoch = 0;
    if (!state.hook->bind_query_msm_worker_epoch(
            state.round, state.next_query + 1, state.chunk_ordinal,
            worker, worker_epoch) || worker_epoch == 0 ||
        std::find(state.worker_epochs.begin(), state.worker_epochs.end(),
                  worker_epoch) != state.worker_epochs.end())
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-worker-epoch",
            FINANCIAL_PROVER_BASELINE_SHA256);
    state.worker_started[worker] = true;
    state.worker_epochs[worker] = worker_epoch;
    state.phase = QueryMsmPhase::Workers;
    if (!state.emit(
            QueryMsmEventKind::WorkerBegin, {},
            "p1-query-msm-worker-begin",
            FINANCIAL_PROVER_BASELINE_SHA256, QueryMsmAbortClass::None,
            {}, worker, worker_epoch, first, last))
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-worker-begin",
            FINANCIAL_PROVER_BASELINE_SHA256);
    return QueryMsmWorkerToken(
        scope.storage_, state.round, state.next_query + 1,
        state.chunk_ordinal, worker, worker_epoch, first, last);
}

void QueryMsmStateSourceBridge::worker_transcript(
        QueryMsmWorkerToken&& token,
        std::span<const unsigned char> exact_state) {
    auto storage = token.storage_;
    if (!storage)
        throw std::runtime_error("P1-query-MSM-worker-token-empty");
    std::lock_guard lock(storage->mutex);
    const auto worker = token.worker_ordinal_;
    storage->require(
        token.active_ && storage->scope_live && !storage->terminal &&
            storage->phase == QueryMsmPhase::Workers &&
            token.round_ == storage->round &&
            token.query_ordinal_ == storage->next_query + 1 &&
            token.chunk_ordinal_ == storage->chunk_ordinal &&
            worker < storage->expected_workers &&
            storage->worker_started[worker] &&
            !storage->worker_finished[worker] &&
            token.worker_thread_epoch_ == storage->worker_epochs[worker] &&
            !exact_state.empty(),
        "p1-query-msm-worker-transcript",
        FINANCIAL_PROVER_BASELINE_SHA256);
    token.active_ = false;
    storage->worker_finished[worker] = true;
    ++storage->completed_workers;
    if (!storage->emit(
            QueryMsmEventKind::WorkerTranscript, exact_state,
            "p1-query-msm-worker-transcript",
            FINANCIAL_PROVER_BASELINE_SHA256, QueryMsmAbortClass::None,
            {}, worker, token.worker_thread_epoch_, token.worker_first_,
            token.worker_last_))
        storage->refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-worker-transcript",
            FINANCIAL_PROVER_BASELINE_SHA256);
}

void QueryMsmStateSourceBridge::worker_abort_noexcept(
        QueryMsmWorkerToken&& token, QueryMsmAbortClass abort_class,
        std::span<const unsigned char> exact_live_prefix,
        std::string_view source_site,
        std::string_view source_identity_sha256) noexcept {
    auto storage = token.storage_;
    token.active_ = false;
    if (!storage) return;
    std::lock_guard lock(storage->mutex);
    if (abort_class == QueryMsmAbortClass::None ||
        source_site.empty() || !lower_hex_word(source_identity_sha256)) {
        abort_class = QueryMsmAbortClass::SourceShape;
        source_site = "p1-query-msm-malformed-worker-abort";
        source_identity_sha256 = FINANCIAL_PROVER_BASELINE_SHA256;
    }
    storage->poison(
        abort_class, source_site, source_identity_sha256,
        exact_live_prefix);
}

void QueryMsmStateSourceBridge::chunk_reduced(
        QueryMsmStateScope& scope,
        std::span<const unsigned char> exact_partial_set_and_chunk_sum) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    state.require(
        state.scope_live && !state.terminal &&
            state.phase == QueryMsmPhase::Workers &&
            state.completed_workers == state.expected_workers &&
            std::all_of(
                state.worker_started.begin(),
                state.worker_started.begin() + state.expected_workers,
                [](bool value) { return value; }) &&
            std::all_of(
                state.worker_finished.begin(),
                state.worker_finished.begin() + state.expected_workers,
                [](bool value) { return value; }) &&
            !exact_partial_set_and_chunk_sum.empty(),
        "p1-query-msm-chunk-reduced", FINANCIAL_PROVER_BASELINE_SHA256);
    state.phase = QueryMsmPhase::ChunkReduced;
    if (!state.emit(
            QueryMsmEventKind::ChunkReduced,
            exact_partial_set_and_chunk_sum,
            "p1-query-msm-chunk-reduced",
            FINANCIAL_PROVER_BASELINE_SHA256))
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-chunk-reduced",
            FINANCIAL_PROVER_BASELINE_SHA256);
}

void QueryMsmStateSourceBridge::query_accumulator(
        QueryMsmStateScope& scope,
        std::span<const unsigned char> exact_running_sum) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    state.require(
        state.scope_live && !state.terminal &&
            state.phase == QueryMsmPhase::ChunkReduced &&
            !exact_running_sum.empty(),
        "p1-query-msm-query-accumulator",
        FINANCIAL_PROVER_BASELINE_SHA256);
    state.cursor_point = checked_add(state.chunk_first, state.chunk_count);
    if (!state.emit(
            QueryMsmEventKind::QueryAccumulator, exact_running_sum,
            "p1-query-msm-query-accumulator",
            FINANCIAL_PROVER_BASELINE_SHA256))
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-query-accumulator",
            FINANCIAL_PROVER_BASELINE_SHA256);
    ++state.chunk_ordinal;
    state.phase = QueryMsmPhase::Query;
}

void QueryMsmStateSourceBridge::query_terminal(
        QueryMsmStateScope& scope,
        std::span<const unsigned char> exact_result) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    state.require(
        state.scope_live && !state.terminal &&
            state.phase == QueryMsmPhase::Query &&
            state.cursor_point == state.query_points &&
            state.chunk_ordinal != 0 && !exact_result.empty(),
        "p1-query-msm-query-terminal",
        FINANCIAL_PROVER_BASELINE_SHA256);
    state.phase = QueryMsmPhase::QueryTerminal;
    if (!state.emit(
            QueryMsmEventKind::QueryTerminal, exact_result,
            "p1-query-msm-query-terminal",
            FINANCIAL_PROVER_BASELINE_SHA256))
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-query-terminal",
            FINANCIAL_PROVER_BASELINE_SHA256);
    ++state.next_query;
    state.phase = state.next_query == QUERY_ORDER.size() ?
        QueryMsmPhase::PostQuery : QueryMsmPhase::BetweenQueries;
}

void QueryMsmStateSourceBridge::post_query_buffer(
        QueryMsmStateScope& scope, QueryMsmPostStage stage,
        std::span<const unsigned char> exact_state) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    state.require(
        state.scope_live && !state.terminal &&
            state.phase == QueryMsmPhase::PostQuery &&
            state.next_query == QUERY_ORDER.size() &&
            static_cast<std::uint8_t>(stage) == state.next_post_stage &&
            !exact_state.empty(),
        "p1-query-msm-post-query-buffer",
        AUTH_GROUPS_BASELINE_SHA256);
    if (!state.emit(
            QueryMsmEventKind::PostQueryBuffer, exact_state,
            "p1-query-msm-post-query-buffer",
            AUTH_GROUPS_BASELINE_SHA256, QueryMsmAbortClass::None,
            stage))
        state.refuse(
            QueryMsmAbortClass::HookRefused,
            "p1-query-msm-post-query-buffer",
            AUTH_GROUPS_BASELINE_SHA256);
    ++state.next_post_stage;
}

void QueryMsmStateSourceBridge::scope_terminal(QueryMsmStateScope& scope) {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    state.require(
        state.scope_live && !state.terminal &&
            state.phase == QueryMsmPhase::PostQuery &&
            state.next_post_stage ==
                static_cast<std::uint8_t>(
                    QueryMsmPostStage::FinalCheckerReturned) + 1,
        "p1-query-msm-scope-terminal",
        FINANCIAL_PROVER_BASELINE_SHA256);
    state.phase = QueryMsmPhase::Terminal;
    if (!state.emit(
            QueryMsmEventKind::ScopeTerminal, {},
            "p1-query-msm-scope-terminal",
            FINANCIAL_PROVER_BASELINE_SHA256) ||
        !state.hook->query_msm_terminal_noexcept()) {
        state.poison(
            QueryMsmAbortClass::TerminalPrefixIncomplete,
            "p1-query-msm-scope-terminal",
            FINANCIAL_PROVER_BASELINE_SHA256);
        throw std::runtime_error("P1-query-MSM-terminal-refused");
    }
    state.terminal = true;
}

void QueryMsmStateSourceBridge::abort_noexcept(
        QueryMsmStateScope& scope, QueryMsmAbortClass abort_class,
        std::string_view source_site,
        std::string_view source_identity_sha256,
        std::span<const unsigned char> exact_live_state) noexcept {
    auto& state = *scope.storage_;
    std::lock_guard lock(state.mutex);
    if (abort_class == QueryMsmAbortClass::None ||
        source_site.empty() || !lower_hex_word(source_identity_sha256)) {
        abort_class = QueryMsmAbortClass::SourceShape;
        source_site = "p1-query-msm-malformed-abort";
        source_identity_sha256 = FINANCIAL_PROVER_BASELINE_SHA256;
    }
    state.poison(
        abort_class, source_site, source_identity_sha256,
        exact_live_state);
}

} // namespace kpi::mpc::p1_private_state

namespace kpb::measurement::p1_state_capsule {

std::unique_ptr<::kpi::mpc::p1_private_state::QueryMsmStateScope>
P1QueryMsmStateAdapterFactoryBridge::install_source_scope(
        ::kpi::mpc::p1_private_state::QueryMsmStateHook& hook,
        std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch,
        std::uint64_t round) {
    return ::kpi::mpc::p1_private_state::QueryMsmStateScope::install(
        hook, persistent_child_epoch, root_thread_epoch, round);
}

} // namespace kpb::measurement::p1_state_capsule
