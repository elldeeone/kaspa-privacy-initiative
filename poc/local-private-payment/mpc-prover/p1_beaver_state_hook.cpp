#include "p1_beaver_source_capture.hpp"
#include "p1_scalar_capture_manifest.hpp"

#include <algorithm>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace kpi::mpc::p1_private_state {

class BeaverStateHookAccess final {
public:
    static bool record(
            BeaverStateHook& hook, const BeaverEventView& view) noexcept {
        return hook.record_beaver_event(view);
    }
    static bool terminal(BeaverStateHook& hook) noexcept {
        return hook.beaver_terminal_noexcept();
    }
    static void unavailable(BeaverStateHook& hook) noexcept {
        hook.beaver_unavailable_noexcept();
    }
};

namespace {

constexpr std::string_view BEAVER_HPP_SHA256 =
    "05fa49b197da6dc91a15178708c9c0b4b04d6117be6c47bd27f7c515a4b355dc";
constexpr std::string_view MASCOT_PREP_HPP_SHA256 =
    "f81df667d0cf357f526bf13b58da873a0578fdabae30019324825e7308cf1b9d";
constexpr std::string_view REPLICATED_PREP_HPP_SHA256 =
    "5069278c110e652cbd49c51711edfa2b29284bf91bda5871785ef3dcf7eb874a";
// SHA-256 of BEAVER_SOURCE_CLOSURE_MANIFEST. It is not a hash of this
// implementation and therefore has no self-reference.
constexpr std::string_view SOURCE_MANIFEST_SHA256 =
    "08ced91c263dfb836f9c9f675d055baa06100690941669d45295ee9b48fa4676";
constexpr std::size_t MAX_EVENT_STATE_BYTES = 512U * 1024U * 1024U;

bool is_sha256(std::string_view value) {
    return value.size() == 64 && std::all_of(
        value.begin(), value.end(), [](unsigned char byte) {
            return (byte >= '0' && byte <= '9') ||
                (byte >= 'a' && byte <= 'f');
        });
}

void append_u64(std::vector<unsigned char>& output, std::uint64_t value) {
    if (output.size() > MAX_EVENT_STATE_BYTES - 8U)
        throw std::runtime_error("P1-Beaver-event-size");
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    if (value.size() > MAX_EVENT_STATE_BYTES ||
        output.size() > MAX_EVENT_STATE_BYTES - 8U ||
        value.size() > MAX_EVENT_STATE_BYTES - output.size() - 8U)
        throw std::runtime_error("P1-Beaver-event-size");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_text(
        std::vector<unsigned char>& output, std::string_view value) {
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

struct CacheState final {
    std::uint64_t epoch{};
    std::uint64_t size{};
};

struct ActiveCapture final {
    BeaverStateHook* hook{};
    std::thread::id owner_thread;
    std::uint64_t persistent_child_epoch{};
    std::uint64_t root_thread_epoch{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    std::uint64_t sequence{};
    std::uint64_t round{};
    std::uint64_t round_event_index{};
    std::uint64_t completed_rounds{};
    std::uint64_t next_batch_epoch{1};
    std::uint64_t batch_epoch{};
    std::uint64_t scalar_capture_site{};
    std::uint64_t expected_multiplications{};
    std::uint64_t prepared{};
    std::uint64_t masked{};
    std::uint64_t opened{};
    std::uint64_t finalized{};
    std::uint64_t next_cache_epoch{1};
    const void* beaver_object{};
    std::unordered_map<const void*, CacheState> caches;
    std::vector<unsigned char> pending_triple_identity;
    BeaverPhase phase{BeaverPhase::Constructed};
    bool healthy{true};
    bool terminal{};
};

std::mutex capture_mutex;
ActiveCapture* active_capture{};

void wipe_secret(std::vector<unsigned char>& value) noexcept {
    volatile unsigned char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
        cursor[index] = 0;
    value.clear();
}

void unavailable_locked(ActiveCapture& active) noexcept {
    wipe_secret(active.pending_triple_identity);
    if (!active.healthy) return;
    active.healthy = false;
    active.phase = BeaverPhase::Unavailable;
    BeaverStateHookAccess::unavailable(*active.hook);
}

std::pair<std::string_view, std::string_view> source_for(
        BeaverEventKind kind) {
    switch (kind) {
    case BeaverEventKind::CacheBatchGenerated:
        return {
            "MP-SPDZ/Protocols/MascotPrep.hpp:MascotTriplePrep::buffer_triples/post-cache-append",
            MASCOT_PREP_HPP_SHA256};
    case BeaverEventKind::CacheTriplePop:
        return {
            "MP-SPDZ/Protocols/ReplicatedPrep.hpp:BufferPrep::get_three_no_count/cache-pop",
            REPLICATED_PREP_HPP_SHA256};
    case BeaverEventKind::Init:
        return {
            "MP-SPDZ/Protocols/Beaver.hpp:Beaver::init_mul/post-clear",
            BEAVER_HPP_SHA256};
    case BeaverEventKind::Prepare:
        return {
            "MP-SPDZ/Protocols/Beaver.hpp:Beaver::prepare_mul_fast/post-append",
            BEAVER_HPP_SHA256};
    case BeaverEventKind::TripleMask:
        return {
            "MP-SPDZ/Protocols/Beaver.hpp:Beaver::pre_fast_exchange/triple-mask",
            BEAVER_HPP_SHA256};
    case BeaverEventKind::OpenedResult:
        return {
            "MP-SPDZ/Protocols/Beaver.hpp:Beaver::post_fast_exchange/opened-result",
            BEAVER_HPP_SHA256};
    case BeaverEventKind::FinalizeReturn:
        return {
            "MP-SPDZ/Protocols/Beaver.hpp:Beaver::finalize_mul_fast/return",
            BEAVER_HPP_SHA256};
    default:
        return {"KPI:p1_beaver_state:lifecycle", SOURCE_MANIFEST_SHA256};
    }
}

bool emit_locked(
        ActiveCapture& active, BeaverEventKind kind,
        BeaverAbortClass abort_class, std::uint64_t item_index,
        std::uint64_t cache_epoch, std::uint64_t cache_size_before,
        std::uint64_t cache_size_after, bool source_succeeded,
        std::span<const unsigned char> source_state) noexcept {
    if (!active.healthy || active.terminal ||
        active.sequence == std::numeric_limits<std::uint64_t>::max() ||
        active.round_event_index ==
            std::numeric_limits<std::uint64_t>::max() ||
        source_state.size() > MAX_EVENT_STATE_BYTES) {
        unavailable_locked(active);
        return false;
    }
    const auto [source_site, source_identity] = source_for(kind);
    const BeaverEventView view{
        .kind = kind,
        .abort_class = abort_class,
        .phase = active.phase,
        .sequence = ++active.sequence,
        .persistent_child_epoch = active.persistent_child_epoch,
        .root_thread_epoch = active.root_thread_epoch,
        .round = active.round,
        .round_event_index = ++active.round_event_index,
        .batch_epoch = active.batch_epoch,
        .scalar_capture_site = active.scalar_capture_site,
        .expected_multiplications = active.expected_multiplications,
        .item_index = item_index,
        .cache_epoch = cache_epoch,
        .cache_size_before = cache_size_before,
        .cache_size_after = cache_size_after,
        .local_role = active.local_role,
        .player_count = active.player_count,
        .source_succeeded = source_succeeded,
        .source_site = source_site,
        .source_identity_sha256 = source_identity,
        .source_state = source_state,
    };
    if (!BeaverStateHookAccess::record(*active.hook, view)) {
        unavailable_locked(active);
        return false;
    }
    return true;
}

bool owner_locked(ActiveCapture& active) noexcept {
    if (active.owner_thread != std::this_thread::get_id()) {
        unavailable_locked(active);
        return false;
    }
    return true;
}

bool begin_round_locked(ActiveCapture& active, std::uint64_t round) noexcept {
    if (!owner_locked(active) || !active.healthy || active.terminal ||
        active.phase != BeaverPhase::BetweenRounds ||
        round != active.completed_rounds + 1 || round == 0 || round > 2) {
        unavailable_locked(active);
        return false;
    }
    active.round = round;
    active.round_event_index = 0;
    active.phase = BeaverPhase::Round;
    return emit_locked(
        active, BeaverEventKind::RoundBegin, BeaverAbortClass::None,
        0, 0, 0, 0, true, {});
}

bool begin_batch_locked(
        ActiveCapture& active, std::uint64_t site,
        std::uint64_t count) noexcept {
    const auto capture_site =
        static_cast<p1_capture::ScalarCaptureSite>(site);
    if (!owner_locked(active) || !active.healthy || active.terminal ||
        (active.phase != BeaverPhase::Round &&
         active.phase != BeaverPhase::BatchComplete) ||
        !active.pending_triple_identity.empty() || count == 0 ||
        !p1_capture::selected_financial_scalar_site(capture_site) ||
        p1_capture::scalar_capture_kind(capture_site) !=
            p1_capture::ScalarCaptureKind::Authenticated ||
        active.next_batch_epoch ==
            std::numeric_limits<std::uint64_t>::max()) {
        unavailable_locked(active);
        return false;
    }
    active.batch_epoch = active.next_batch_epoch++;
    active.scalar_capture_site = site;
    active.expected_multiplications = count;
    active.prepared = 0;
    active.masked = 0;
    active.opened = 0;
    active.finalized = 0;
    active.beaver_object = nullptr;
    wipe_secret(active.pending_triple_identity);
    active.phase = BeaverPhase::BatchDeclared;
    return emit_locked(
        active, BeaverEventKind::BatchBegin, BeaverAbortClass::None,
        0, 0, 0, 0, true, {});
}

bool end_round_locked(ActiveCapture& active, std::uint64_t round) noexcept {
    if (!owner_locked(active) || !active.healthy || active.terminal ||
        round != active.round ||
        (active.phase != BeaverPhase::Round &&
         active.phase != BeaverPhase::BatchComplete) ||
        active.beaver_object != nullptr ||
        !active.pending_triple_identity.empty()) {
        unavailable_locked(active);
        return false;
    }
    if (!emit_locked(
            active, BeaverEventKind::RoundEnd, BeaverAbortClass::None,
            0, 0, 0, 0, true, {}))
        return false;
    active.completed_rounds = round;
    active.round = 0;
    active.batch_epoch = 0;
    active.scalar_capture_site = 0;
    active.expected_multiplications = 0;
    active.phase = BeaverPhase::BetweenRounds;
    return true;
}

bool abort_locked(
        ActiveCapture& active, BeaverAbortClass abort_class) noexcept {
    if (!owner_locked(active) || !active.healthy || active.terminal ||
        abort_class == BeaverAbortClass::None) {
        unavailable_locked(active);
        return false;
    }
    std::vector<unsigned char> live_state;
    try {
        static constexpr std::string_view domain =
            "KPI_P1_BEAVER_ABORT_LIVE_STATE_V1\n";
        live_state.insert(live_state.end(), domain.begin(), domain.end());
        append_u64(live_state, static_cast<std::uint64_t>(active.phase));
        append_u64(live_state, active.prepared);
        append_u64(live_state, active.masked);
        append_u64(live_state, active.opened);
        append_u64(live_state, active.finalized);
        append_u64(
            live_state, active.pending_triple_identity.empty() ? 0U : 1U);
        std::vector<CacheState> caches;
        caches.reserve(active.caches.size());
        for (const auto& [object, state] : active.caches) {
            (void)object;
            caches.push_back(state);
        }
        std::sort(
            caches.begin(), caches.end(), [](const auto& left,
                                             const auto& right) {
                return left.epoch < right.epoch;
            });
        append_u64(live_state, caches.size());
        for (const auto& cache : caches) {
            append_u64(live_state, cache.epoch);
            append_u64(live_state, cache.size);
        }
    }
    catch (...) {
        unavailable_locked(active);
        return false;
    }
    const bool retained = emit_locked(
        active, BeaverEventKind::Abort, abort_class, active.finalized,
        0, 0, 0, false, live_state);
    wipe_secret(live_state);
    unavailable_locked(active);
    return retained;
}

bool finish_locked(ActiveCapture& active) noexcept {
    if (!owner_locked(active) || !active.healthy || active.terminal)
        return false;
    if (
        active.phase != BeaverPhase::BetweenRounds ||
        active.completed_rounds != 2 || active.beaver_object != nullptr ||
        !active.pending_triple_identity.empty()) {
        (void)abort_locked(
            active, BeaverAbortClass::TerminalIncomplete);
        return false;
    }
    active.terminal = true;
    active.phase = BeaverPhase::Terminal;
    if (!BeaverStateHookAccess::terminal(*active.hook)) {
        active.terminal = false;
        unavailable_locked(active);
        return false;
    }
    return true;
}

} // namespace

std::vector<unsigned char> encode_beaver_event(
        const BeaverEventView& value) {
    if (value.kind < BeaverEventKind::Construct ||
        value.kind > BeaverEventKind::Abort || value.sequence == 0 ||
        value.persistent_child_epoch == 0 || value.root_thread_epoch == 0 ||
        value.local_role != 1 || value.player_count != 3 ||
        value.source_site.empty() ||
        !is_sha256(value.source_identity_sha256) ||
        value.source_state.size() > MAX_EVENT_STATE_BYTES ||
        (value.abort_class == BeaverAbortClass::None) !=
            (value.kind != BeaverEventKind::Abort) ||
        (value.source_succeeded ==
            (value.kind == BeaverEventKind::Abort)))
        throw std::runtime_error("P1-Beaver-event-shape");
    std::vector<unsigned char> output;
    output.insert(
        output.end(), BEAVER_STATE_DOMAIN.begin(), BEAVER_STATE_DOMAIN.end());
    append_u64(output, static_cast<std::uint64_t>(value.kind));
    append_u64(output, static_cast<std::uint64_t>(value.abort_class));
    append_u64(output, static_cast<std::uint64_t>(value.phase));
    append_u64(output, value.sequence);
    append_u64(output, value.persistent_child_epoch);
    append_u64(output, value.root_thread_epoch);
    append_u64(output, value.round);
    append_u64(output, value.round_event_index);
    append_u64(output, value.batch_epoch);
    append_u64(output, value.scalar_capture_site);
    append_u64(output, value.expected_multiplications);
    append_u64(output, value.item_index);
    append_u64(output, value.cache_epoch);
    append_u64(output, value.cache_size_before);
    append_u64(output, value.cache_size_after);
    append_u64(output, value.local_role);
    append_u64(output, value.player_count);
    append_u64(output, value.source_succeeded ? 1U : 0U);
    append_text(output, value.source_site);
    append_text(output, value.source_identity_sha256);
    append_bytes(output, value.source_state);
    return output;
}

struct BeaverSourceScope::Storage final {
    ActiveCapture active;
    bool installed{};
};

BeaverSourceScope::BeaverSourceScope(
        BeaverStateHook& hook, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count)
    : storage_(std::make_unique<Storage>()) {
    if (persistent_child_epoch == 0 || root_thread_epoch == 0 ||
        local_role != 1 || player_count != 3)
        throw std::runtime_error("P1-Beaver-scope-shape");
    std::lock_guard lock(capture_mutex);
    if (active_capture != nullptr)
        throw std::runtime_error("P1-Beaver-scope-overlap");
    auto& active = storage_->active;
    active.hook = &hook;
    active.owner_thread = std::this_thread::get_id();
    active.persistent_child_epoch = persistent_child_epoch;
    active.root_thread_epoch = root_thread_epoch;
    active.local_role = local_role;
    active.player_count = player_count;
    active_capture = &active;
    storage_->installed = true;
    if (!emit_locked(
            active, BeaverEventKind::Construct, BeaverAbortClass::None,
            0, 0, 0, 0, true, {})) {
        active_capture = nullptr;
        storage_->installed = false;
        throw std::runtime_error("P1-Beaver-construct-rejected");
    }
    active.phase = BeaverPhase::BetweenRounds;
}

BeaverSourceScope::~BeaverSourceScope() {
    if (!storage_ || !storage_->installed) return;
    std::lock_guard lock(capture_mutex);
    if (active_capture == &storage_->active) {
        auto& active = storage_->active;
        if (!active.terminal) {
            if (active.healthy &&
                active.owner_thread == std::this_thread::get_id()) {
                const auto classification =
                    active.beaver_object != nullptr ||
                    active.phase == BeaverPhase::BatchDeclared ||
                    active.phase == BeaverPhase::Initialized ||
                    active.phase == BeaverPhase::Prepared ||
                    active.phase == BeaverPhase::Exchanged ||
                    active.phase == BeaverPhase::Finalizing ?
                    BeaverAbortClass::PartialBatch :
                    BeaverAbortClass::TerminalIncomplete;
                (void)abort_locked(active, classification);
            }
            else
                unavailable_locked(active);
        }
        active_capture = nullptr;
    }
    storage_->installed = false;
}

bool BeaverStateSourceBridge::capture_required_noexcept() noexcept {
    std::lock_guard lock(capture_mutex);
    return active_capture != nullptr;
}

BeaverRetainResult
BeaverStateSourceBridge::serialization_failure_noexcept() noexcept {
    std::lock_guard lock(capture_mutex);
    if (!active_capture) return BeaverRetainResult::NotRequired;
    unavailable_locked(*active_capture);
    return BeaverRetainResult::Failed;
}

BeaverRetainResult BeaverStateSourceBridge::cache_batch_raw_noexcept(
        const void* cache_object, std::uint64_t size_before,
        std::uint64_t size_after,
        std::span<const unsigned char> source_state) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return BeaverRetainResult::NotRequired;
    if (!owner_locked(*active) || !active->healthy || cache_object == nullptr ||
        active->phase != BeaverPhase::Prepared ||
        active->prepared != active->expected_multiplications ||
        active->masked >= active->expected_multiplications ||
        !active->pending_triple_identity.empty() ||
        source_state.empty() || size_after <= size_before) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    auto iterator = active->caches.find(cache_object);
    bool inserted = false;
    if (iterator == active->caches.end()) {
        if (active->next_cache_epoch ==
            std::numeric_limits<std::uint64_t>::max()) {
            unavailable_locked(*active);
            return BeaverRetainResult::Failed;
        }
        try {
            std::tie(iterator, inserted) = active->caches.try_emplace(
                cache_object,
                CacheState{
                    .epoch = active->next_cache_epoch,
                    .size = size_before});
        }
        catch (...) {
            unavailable_locked(*active);
            return BeaverRetainResult::Failed;
        }
        ++active->next_cache_epoch;
    }
    auto& cache = iterator->second;
    if ((!inserted && cache.size != size_before) ||
        !emit_locked(
            *active, BeaverEventKind::CacheBatchGenerated,
            BeaverAbortClass::None, 0, cache.epoch, size_before,
            size_after, true, source_state)) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    cache.size = size_after;
    return BeaverRetainResult::Retained;
}

BeaverRetainResult BeaverStateSourceBridge::cache_pop_raw_noexcept(
        const void* cache_object, std::uint64_t size_before,
        std::uint64_t size_after,
        std::span<const unsigned char> source_state,
        std::span<const unsigned char> triple_identity) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return BeaverRetainResult::NotRequired;
    const auto found = active->caches.find(cache_object);
    if (!owner_locked(*active) || !active->healthy || cache_object == nullptr ||
        active->phase != BeaverPhase::Prepared ||
        active->prepared != active->expected_multiplications ||
        active->masked >= active->expected_multiplications ||
        !active->pending_triple_identity.empty() ||
        source_state.empty() || triple_identity.empty() ||
        triple_identity.size() > MAX_EVENT_STATE_BYTES ||
        found == active->caches.end() ||
        found->second.size != size_before || size_before == 0 ||
        size_after + 1 != size_before) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    try {
        active->pending_triple_identity.assign(
            triple_identity.begin(), triple_identity.end());
    }
    catch (...) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    if (!emit_locked(
            *active, BeaverEventKind::CacheTriplePop,
            BeaverAbortClass::None, active->masked, found->second.epoch,
            size_before, size_after, true, source_state)) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    found->second.size = size_after;
    return BeaverRetainResult::Retained;
}

BeaverRetainResult BeaverStateSourceBridge::init_raw_noexcept(
        const void* beaver_object) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return BeaverRetainResult::NotRequired;
    if (!owner_locked(*active) || !active->healthy ||
        active->phase != BeaverPhase::BatchDeclared ||
        beaver_object == nullptr || active->beaver_object != nullptr) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    active->beaver_object = beaver_object;
    active->phase = BeaverPhase::Initialized;
    return emit_locked(
        *active, BeaverEventKind::Init, BeaverAbortClass::None,
        0, 0, 0, 0, true, {}) ? BeaverRetainResult::Retained :
        BeaverRetainResult::Failed;
}

BeaverRetainResult BeaverStateSourceBridge::prepare_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return BeaverRetainResult::NotRequired;
    if (!owner_locked(*active) || !active->healthy ||
        (active->phase != BeaverPhase::Initialized &&
         active->phase != BeaverPhase::Prepared) ||
        beaver_object != active->beaver_object ||
        active->prepared >= active->expected_multiplications ||
        !active->pending_triple_identity.empty() || source_state.empty()) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    const auto index = active->prepared++;
    active->phase = BeaverPhase::Prepared;
    return emit_locked(
        *active, BeaverEventKind::Prepare, BeaverAbortClass::None,
        index, 0, 0, 0, true, source_state) ?
        BeaverRetainResult::Retained : BeaverRetainResult::Failed;
}

BeaverRetainResult BeaverStateSourceBridge::triple_mask_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state,
        std::span<const unsigned char> triple_identity) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return BeaverRetainResult::NotRequired;
    if (!owner_locked(*active) || !active->healthy ||
        active->phase != BeaverPhase::Prepared ||
        beaver_object != active->beaver_object ||
        active->prepared != active->expected_multiplications ||
        active->masked >= active->expected_multiplications ||
        source_state.empty() || triple_identity.empty() ||
        triple_identity.size() !=
            active->pending_triple_identity.size() ||
        !std::equal(
            triple_identity.begin(), triple_identity.end(),
            active->pending_triple_identity.begin())) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    const auto index = active->masked++;
    const bool retained = emit_locked(
        *active, BeaverEventKind::TripleMask, BeaverAbortClass::None,
        index, 0, 0, 0, true, source_state);
    wipe_secret(active->pending_triple_identity);
    return retained ? BeaverRetainResult::Retained :
        BeaverRetainResult::Failed;
}

BeaverRetainResult BeaverStateSourceBridge::opened_result_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return BeaverRetainResult::NotRequired;
    if (!owner_locked(*active) || !active->healthy ||
        (active->phase != BeaverPhase::Prepared &&
         active->phase != BeaverPhase::Exchanged) ||
        beaver_object != active->beaver_object ||
        active->masked != active->expected_multiplications ||
        active->opened >= active->expected_multiplications ||
        !active->pending_triple_identity.empty() || source_state.empty()) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    const auto index = active->opened++;
    active->phase = BeaverPhase::Exchanged;
    return emit_locked(
        *active, BeaverEventKind::OpenedResult, BeaverAbortClass::None,
        index, 0, 0, 0, true, source_state) ?
        BeaverRetainResult::Retained : BeaverRetainResult::Failed;
}

BeaverRetainResult BeaverStateSourceBridge::finalize_return_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return BeaverRetainResult::NotRequired;
    if (!owner_locked(*active) || !active->healthy ||
        (active->phase != BeaverPhase::Exchanged &&
         active->phase != BeaverPhase::Finalizing) ||
        beaver_object != active->beaver_object ||
        active->opened != active->expected_multiplications ||
        active->finalized >= active->expected_multiplications ||
        !active->pending_triple_identity.empty() || source_state.empty()) {
        unavailable_locked(*active);
        return BeaverRetainResult::Failed;
    }
    const auto index = active->finalized++;
    active->phase = BeaverPhase::Finalizing;
    if (!emit_locked(
            *active, BeaverEventKind::FinalizeReturn,
            BeaverAbortClass::None, index, 0, 0, 0, true,
            source_state))
        return BeaverRetainResult::Failed;
    if (active->finalized == active->expected_multiplications) {
        active->phase = BeaverPhase::BatchComplete;
        if (!emit_locked(
                *active, BeaverEventKind::BatchTerminal,
                BeaverAbortClass::None, active->finalized,
                0, 0, 0, true, {}))
            return BeaverRetainResult::Failed;
        active->beaver_object = nullptr;
    }
    return BeaverRetainResult::Retained;
}

} // namespace kpi::mpc::p1_private_state

namespace kpb::measurement::p1_state_capsule {

using ::kpi::mpc::p1_private_state::BeaverAbortClass;
using ::kpi::mpc::p1_private_state::BeaverSourceScope;
using ::kpi::mpc::p1_private_state::BeaverStateHook;

std::unique_ptr<BeaverSourceScope>
P1BeaverStateAdapterFactoryBridge::install_source_scope(
        BeaverStateHook& hook, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count) {
    return std::unique_ptr<BeaverSourceScope>(new BeaverSourceScope(
        hook, persistent_child_epoch, root_thread_epoch, local_role,
        player_count));
}

bool P1BeaverStateAdapterFactoryBridge::round_begin(
        BeaverSourceScope& scope, std::uint64_t round) noexcept {
    std::lock_guard lock(::kpi::mpc::p1_private_state::capture_mutex);
    if (!scope.storage_ || !scope.storage_->installed ||
        ::kpi::mpc::p1_private_state::active_capture !=
            &scope.storage_->active)
        return false;
    return ::kpi::mpc::p1_private_state::begin_round_locked(
        scope.storage_->active, round);
}

bool P1BeaverStateAdapterFactoryBridge::batch_begin(
        BeaverSourceScope& scope, std::uint64_t site,
        std::uint64_t count) noexcept {
    std::lock_guard lock(::kpi::mpc::p1_private_state::capture_mutex);
    if (!scope.storage_ || !scope.storage_->installed ||
        ::kpi::mpc::p1_private_state::active_capture !=
            &scope.storage_->active)
        return false;
    return ::kpi::mpc::p1_private_state::begin_batch_locked(
        scope.storage_->active, site, count);
}

bool P1BeaverStateAdapterFactoryBridge::round_end(
        BeaverSourceScope& scope, std::uint64_t round) noexcept {
    std::lock_guard lock(::kpi::mpc::p1_private_state::capture_mutex);
    if (!scope.storage_ || !scope.storage_->installed ||
        ::kpi::mpc::p1_private_state::active_capture !=
            &scope.storage_->active)
        return false;
    return ::kpi::mpc::p1_private_state::end_round_locked(
        scope.storage_->active, round);
}

bool P1BeaverStateAdapterFactoryBridge::abort(
        BeaverSourceScope& scope, BeaverAbortClass abort_class) noexcept {
    std::lock_guard lock(::kpi::mpc::p1_private_state::capture_mutex);
    if (!scope.storage_ || !scope.storage_->installed ||
        ::kpi::mpc::p1_private_state::active_capture !=
            &scope.storage_->active)
        return false;
    return ::kpi::mpc::p1_private_state::abort_locked(
        scope.storage_->active, abort_class);
}

bool P1BeaverStateAdapterFactoryBridge::finish(
        std::unique_ptr<BeaverSourceScope>&& scope) noexcept {
    if (!scope) return false;
    std::lock_guard lock(::kpi::mpc::p1_private_state::capture_mutex);
    if (!scope->storage_ || !scope->storage_->installed ||
        ::kpi::mpc::p1_private_state::active_capture !=
            &scope->storage_->active)
        return false;
    const bool result = ::kpi::mpc::p1_private_state::finish_locked(
        scope->storage_->active);
    ::kpi::mpc::p1_private_state::active_capture = nullptr;
    scope->storage_->installed = false;
    return result;
}

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
std::unique_ptr<BeaverSourceScope>
P1BeaverStateAdapterFactoryBridge::test_only_install_source_scope(
        BeaverStateHook& hook, std::uint64_t child,
        std::uint64_t thread, std::uint64_t role,
        std::uint64_t players) {
    return install_source_scope(hook, child, thread, role, players);
}

bool P1BeaverStateAdapterFactoryBridge::test_only_round_begin(
        BeaverSourceScope& scope, std::uint64_t round) noexcept {
    return round_begin(scope, round);
}

bool P1BeaverStateAdapterFactoryBridge::test_only_batch_begin(
        BeaverSourceScope& scope, std::uint64_t site,
        std::uint64_t count) noexcept {
    return batch_begin(scope, site, count);
}

bool P1BeaverStateAdapterFactoryBridge::test_only_round_end(
        BeaverSourceScope& scope, std::uint64_t round) noexcept {
    return round_end(scope, round);
}

bool P1BeaverStateAdapterFactoryBridge::test_only_abort(
        BeaverSourceScope& scope, BeaverAbortClass abort_class) noexcept {
    return abort(scope, abort_class);
}

bool P1BeaverStateAdapterFactoryBridge::test_only_finish(
        std::unique_ptr<BeaverSourceScope>&& scope) noexcept {
    return finish(std::move(scope));
}
#endif

} // namespace kpb::measurement::p1_state_capsule

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
namespace kpi::mpc::p1_private_state {

std::unique_ptr<BeaverSourceScope> BeaverStateTestBridge::install(
        BeaverStateHook& hook, std::uint64_t child,
        std::uint64_t thread, std::uint64_t role,
        std::uint64_t players) {
    return ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapterFactoryBridge::test_only_install_source_scope(
            hook, child, thread, role, players);
}

bool BeaverStateTestBridge::round_begin(
        BeaverSourceScope& scope, std::uint64_t round) noexcept {
    return ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapterFactoryBridge::test_only_round_begin(
            scope, round);
}

bool BeaverStateTestBridge::batch_begin(
        BeaverSourceScope& scope, std::uint64_t site,
        std::uint64_t count) noexcept {
    return ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapterFactoryBridge::test_only_batch_begin(
            scope, site, count);
}

bool BeaverStateTestBridge::round_end(
        BeaverSourceScope& scope, std::uint64_t round) noexcept {
    return ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapterFactoryBridge::test_only_round_end(
            scope, round);
}

bool BeaverStateTestBridge::abort(
        BeaverSourceScope& scope, BeaverAbortClass abort_class) noexcept {
    return ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapterFactoryBridge::test_only_abort(
            scope, abort_class);
}

bool BeaverStateTestBridge::finish(
        std::unique_ptr<BeaverSourceScope>&& scope) noexcept {
    return ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapterFactoryBridge::test_only_finish(
            std::move(scope));
}

} // namespace kpi::mpc::p1_private_state
#endif
