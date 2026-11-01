#pragma once

// Private child-local state surface for the selected financial query/MSM
// implementation.  The source bridge records exact worker prefix state while
// it is live.  No pointer, pthread identifier, digest-only summary, or caller
// authored completion bit is an evidence identity.

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace kpi::mpc::p1_private_state {
class QueryMsmStateHook;
class QueryMsmStateScope;
class QueryMsmWorkerToken;
struct QueryMsmStateStorage;
}

namespace kpb::measurement::p1_state_capsule {
class P1QueryMsmStateAdapter;

class P1QueryMsmStateAdapterFactoryBridge final {
    P1QueryMsmStateAdapterFactoryBridge() = delete;
    friend class P1QueryMsmStateAdapter;

    static std::unique_ptr<::kpi::mpc::p1_private_state::QueryMsmStateScope>
    install_source_scope(
        ::kpi::mpc::p1_private_state::QueryMsmStateHook&,
        std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch,
        std::uint64_t round);
};
}

namespace kpi::mpc::p1_private_state {

inline constexpr std::string_view QUERY_MSM_STATE_DOMAIN =
    "KPI_P1_QUERY_MSM_STATE_V1\n";
// Baseline only.  This isolated slice is not selected by the registered build.
inline constexpr std::string_view QUERY_MSM_BASELINE_SOURCE_COMMIT =
    "b58de1a182347c4223ebe84f92bb0bdd6c88d003";
inline constexpr std::uint64_t QUERY_MSM_SELECTED_WORKERS = 3;
inline constexpr std::uint64_t QUERY_MSM_SELECTED_CHUNK = 1024;

enum class QueryMsmKind : std::uint8_t {
    A = 1,
    B1 = 2,
    B2 = 3,
    H = 4,
    L = 5,
};

enum class QueryMsmGroup : std::uint8_t {
    G1 = 1,
    G2 = 2,
};

enum class QueryMsmEventKind : std::uint8_t {
    ScopeConstructed = 1,
    QueryBegin = 2,
    ChunkBegin = 3,
    WorkerBegin = 4,
    WorkerTranscript = 5,
    ChunkReduced = 6,
    QueryAccumulator = 7,
    QueryTerminal = 8,
    PostQueryBuffer = 9,
    ScopeTerminal = 10,
    Abort = 11,
};

enum class QueryMsmAbortClass : std::uint8_t {
    None = 0,
    SourceShape = 1,
    WorkerLaunch = 2,
    WorkerExecution = 3,
    WorkerDropped = 4,
    HookRefused = 5,
    QueryException = 6,
    ScopeUnlinked = 7,
    TerminalPrefixIncomplete = 8,
    ReplayOrOrder = 9,
    Serialization = 10,
    CursorFailure = 11,
};

enum class QueryMsmPhase : std::uint8_t {
    Constructed = 1,
    BetweenQueries = 2,
    Query = 3,
    Chunk = 4,
    Workers = 5,
    ChunkReduced = 6,
    QueryTerminal = 7,
    PostQuery = 8,
    Terminal = 9,
    Poisoned = 10,
};

// These are the query-adjacent buffers materialized after L.  Direct_MC's
// private challenge/randomness internals remain the separate MAC-check family;
// these stages retain the concrete outer vectors and mixed-protocol values
// passed into and returned from that checker.
enum class QueryMsmPostStage : std::uint8_t {
    MixedInputs = 1,
    MixedMasksAndDifferences = 2,
    MixedProducts = 3,
    FinalCheckerInputs = 4,
    FinalCheckerOpened = 5,
    FinalCheckerReturned = 6,
};

struct QueryMsmEventView final {
    QueryMsmEventKind kind{};
    QueryMsmAbortClass abort_class{};
    QueryMsmPhase phase{};
    QueryMsmKind query{};
    QueryMsmGroup group{};
    QueryMsmPostStage post_stage{};
    std::uint64_t sequence{};
    std::uint64_t persistent_child_epoch{};
    std::uint64_t root_thread_epoch{};
    std::uint64_t worker_thread_epoch{};
    std::uint64_t round{};
    std::uint64_t query_ordinal{};
    std::uint64_t chunk_ordinal{};
    std::uint64_t worker_ordinal{};
    std::uint64_t query_points{};
    std::uint64_t query_scalars{};
    std::uint64_t chunk_first{};
    std::uint64_t chunk_count{};
    std::uint64_t worker_first{};
    std::uint64_t worker_last{};
    std::uint64_t completed_workers{};
    std::uint64_t cursor_point{};
    std::string_view source_site;
    std::string_view source_identity_sha256;
    std::span<const unsigned char> exact_state;
};

class QueryMsmStateHook {
    QueryMsmStateHook() = default;
    friend class QueryMsmStateScope;
    friend class QueryMsmStateSourceBridge;
    friend class QueryMsmWorkerToken;
    friend struct QueryMsmStateStorage;
    friend class ::kpb::measurement::p1_state_capsule::
        P1QueryMsmStateAdapter;

    virtual bool record_query_msm_event(
        const QueryMsmEventView&) noexcept = 0;
    virtual bool bind_query_msm_worker_epoch(
        std::uint64_t round, std::uint64_t query_ordinal,
        std::uint64_t chunk_ordinal, std::uint64_t worker_ordinal,
        std::uint64_t& logical_worker_epoch) noexcept = 0;
    virtual bool query_msm_terminal_noexcept() noexcept = 0;
    virtual void query_msm_unavailable_noexcept() noexcept = 0;

#ifdef KPI_P1_QUERY_MSM_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit QueryMsmStateHook(TestOnlyConstruction) {}
#endif

public:
    QueryMsmStateHook(const QueryMsmStateHook&) = delete;
    QueryMsmStateHook& operator=(const QueryMsmStateHook&) = delete;
    virtual ~QueryMsmStateHook() = default;
};

class QueryMsmStateScope final {
private:
    std::shared_ptr<QueryMsmStateStorage> storage_;
    explicit QueryMsmStateScope(std::shared_ptr<QueryMsmStateStorage>);
    static std::unique_ptr<QueryMsmStateScope> install(
        QueryMsmStateHook&, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t round);
    friend class QueryMsmStateSourceBridge;
    friend class QueryMsmWorkerToken;
    friend class ::kpb::measurement::p1_state_capsule::
        P1QueryMsmStateAdapterFactoryBridge;

public:
    QueryMsmStateScope(const QueryMsmStateScope&) = delete;
    QueryMsmStateScope& operator=(const QueryMsmStateScope&) = delete;
    QueryMsmStateScope(QueryMsmStateScope&&) = delete;
    QueryMsmStateScope& operator=(QueryMsmStateScope&&) = delete;
    ~QueryMsmStateScope();
};

class QueryMsmWorkerToken final {
    std::shared_ptr<QueryMsmStateStorage> storage_;
    std::uint64_t round_{};
    std::uint64_t query_ordinal_{};
    std::uint64_t chunk_ordinal_{};
    std::uint64_t worker_ordinal_{};
    std::uint64_t worker_thread_epoch_{};
    std::uint64_t worker_first_{};
    std::uint64_t worker_last_{};
    bool active_{};

    QueryMsmWorkerToken(
        std::shared_ptr<QueryMsmStateStorage>, std::uint64_t round,
        std::uint64_t query_ordinal, std::uint64_t chunk_ordinal,
        std::uint64_t worker_ordinal, std::uint64_t worker_thread_epoch,
        std::uint64_t worker_first, std::uint64_t worker_last);
    friend class QueryMsmStateSourceBridge;

public:
    QueryMsmWorkerToken() = default;
    QueryMsmWorkerToken(const QueryMsmWorkerToken&) = delete;
    QueryMsmWorkerToken& operator=(const QueryMsmWorkerToken&) = delete;
    QueryMsmWorkerToken(QueryMsmWorkerToken&&) noexcept;
    QueryMsmWorkerToken& operator=(QueryMsmWorkerToken&&) = delete;
    ~QueryMsmWorkerToken();
};

class QueryMsmStateSourceBridge final {
    QueryMsmStateSourceBridge() = delete;

public:
#ifdef KPI_P1_QUERY_MSM_STATE_HOOK_TEST_SETUP
    static std::unique_ptr<QueryMsmStateScope> test_only_install(
        QueryMsmStateHook&, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t round);
#endif

    static void query_begin(
        QueryMsmStateScope&, QueryMsmKind, QueryMsmGroup,
        std::uint64_t points, std::uint64_t scalars,
        std::span<const unsigned char> exact_unused_scalar = {});
    static void chunk_begin(
        QueryMsmStateScope&, std::uint64_t first, std::uint64_t count,
        std::span<const unsigned char> exact_cursor_state);
    static QueryMsmWorkerToken worker_begin(
        QueryMsmStateScope&, std::uint64_t worker,
        std::uint64_t first, std::uint64_t last);
    static void worker_transcript(
        QueryMsmWorkerToken&&, std::span<const unsigned char> exact_state);
    static void worker_abort_noexcept(
        QueryMsmWorkerToken&&, QueryMsmAbortClass,
        std::span<const unsigned char> exact_live_prefix,
        std::string_view source_site,
        std::string_view source_identity_sha256) noexcept;
    static void chunk_reduced(
        QueryMsmStateScope&,
        std::span<const unsigned char> exact_partial_set_and_chunk_sum);
    static void query_accumulator(
        QueryMsmStateScope&, std::span<const unsigned char> exact_running_sum);
    static void query_terminal(
        QueryMsmStateScope&, std::span<const unsigned char> exact_result);
    static void post_query_buffer(
        QueryMsmStateScope&, QueryMsmPostStage,
        std::span<const unsigned char> exact_state);
    static void scope_terminal(QueryMsmStateScope&);
    static void abort_noexcept(
        QueryMsmStateScope&, QueryMsmAbortClass,
        std::string_view source_site,
        std::string_view source_identity_sha256,
        std::span<const unsigned char> exact_live_state = {}) noexcept;
};

struct QueryMsmStateSourceStatus final {
    bool canonical_fieldwise_worker_transcripts{};
    bool exact_prefix_state_per_point{};
    bool observed_completion_interleaving{};
    bool query_chunk_worker_state_machine{};
    bool post_query_outer_buffer_state_machine{};
    bool abort_prefix_unavailable{};
    bool capsule_family_adapter{};
    bool selected_financial_callsite{};
    bool actual_two_round_receipt{};
    bool complete_corrupt_p1_view{};
};

inline constexpr QueryMsmStateSourceStatus kQueryMsmStateSourceStatus{
    .canonical_fieldwise_worker_transcripts = true,
    .exact_prefix_state_per_point = true,
    .observed_completion_interleaving = true,
    .query_chunk_worker_state_machine = true,
    .post_query_outer_buffer_state_machine = true,
    .abort_prefix_unavailable = true,
    .capsule_family_adapter = false,
    .selected_financial_callsite = false,
    .actual_two_round_receipt = false,
    .complete_corrupt_p1_view = false,
};

} // namespace kpi::mpc::p1_private_state
