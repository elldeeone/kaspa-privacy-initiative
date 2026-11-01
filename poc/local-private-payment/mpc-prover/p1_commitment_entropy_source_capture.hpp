#pragma once

// Source bridge compiled into patched MP-SPDZ Tools/Commit.cpp. Production
// recording is inert unless the source-owned capsule adapter installs the sole
// scope and explicitly binds every participating logical thread.

#include "p1_commitment_entropy_state_hook.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <utility>
#include <vector>

class octetStream;
class Commitment;
void Commit(
    octetStream&, octetStream&, const octetStream&, int send_player);

namespace kpi::mpc::p1_private_state {

enum class CommitmentEntropyRetainResult : std::uint8_t {
    NotRequired = 1,
    Retained = 2,
    Failed = 3,
};

class CommitmentEntropySourceScope;
class CommitmentEntropyThreadScope;

// Complete before the friendship grant. A standalone include cannot redefine
// this class to reach either private constructor.
class CommitmentEntropyScopeFactoryBridge final {
    CommitmentEntropyScopeFactoryBridge() = delete;
    static CommitmentEntropySourceScope install(
        CommitmentEntropyStateHook&, std::uint64_t logical_process_epoch,
        std::uint64_t root_thread_epoch);
    static CommitmentEntropyThreadScope bind_thread(
        std::uint64_t logical_thread_epoch);
    friend class ::kpb::measurement::p1_state_capsule::
        P1EntropyStateAdapter;

#ifdef KPI_P1_COMMITMENT_ENTROPY_STATE_HOOK_TEST_SETUP
public:
    static CommitmentEntropySourceScope test_only_install(
        CommitmentEntropyStateHook& hook,
        std::uint64_t logical_process_epoch,
        std::uint64_t root_thread_epoch);
    static CommitmentEntropyThreadScope test_only_bind_thread(
        std::uint64_t logical_thread_epoch);
#endif
};

class CommitmentEntropySourceScope final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit CommitmentEntropySourceScope(std::unique_ptr<Storage>);
    friend class CommitmentEntropyScopeFactoryBridge;

public:
    CommitmentEntropySourceScope(const CommitmentEntropySourceScope&) = delete;
    CommitmentEntropySourceScope& operator=(
        const CommitmentEntropySourceScope&) = delete;
    CommitmentEntropySourceScope(CommitmentEntropySourceScope&&) noexcept;
    CommitmentEntropySourceScope& operator=(
        CommitmentEntropySourceScope&&) = delete;
    ~CommitmentEntropySourceScope();
    bool finish_noexcept() && noexcept;
};

class CommitmentEntropyThreadScope final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit CommitmentEntropyThreadScope(std::unique_ptr<Storage>);
    friend class CommitmentEntropyScopeFactoryBridge;

public:
    CommitmentEntropyThreadScope(const CommitmentEntropyThreadScope&) = delete;
    CommitmentEntropyThreadScope& operator=(
        const CommitmentEntropyThreadScope&) = delete;
    CommitmentEntropyThreadScope(CommitmentEntropyThreadScope&&) noexcept;
    CommitmentEntropyThreadScope& operator=(
        CommitmentEntropyThreadScope&&) = delete;
    ~CommitmentEntropyThreadScope();
};

class CommitmentEntropySourceBridge final {
    CommitmentEntropySourceBridge() = delete;
    static CommitmentEntropyRetainResult record_legacy_commit_noexcept(
        int commitment_owner,
        std::span<const unsigned char> exact_entropy) noexcept;
    static CommitmentEntropyRetainResult record_object_commit_noexcept(
        int commitment_owner,
        std::span<const unsigned char> exact_entropy) noexcept;
    static void require_recorded(CommitmentEntropyRetainResult result) noexcept {
        if (result == CommitmentEntropyRetainResult::Failed)
            std::abort();
    }
    friend void ::Commit(
        octetStream&, octetStream&, const octetStream&, int);
    friend class ::Commitment;

#ifdef KPI_P1_COMMITMENT_ENTROPY_STATE_HOOK_TEST_SETUP
public:
    static CommitmentEntropyRetainResult test_only_record_legacy_commit(
            int commitment_owner,
            std::span<const unsigned char> exact_entropy) noexcept {
        return record_legacy_commit_noexcept(
            commitment_owner, exact_entropy);
    }
    static CommitmentEntropyRetainResult test_only_record_object_commit(
            int commitment_owner,
            std::span<const unsigned char> exact_entropy) noexcept {
        return record_object_commit_noexcept(
            commitment_owner, exact_entropy);
    }
#endif
};

#ifdef KPI_P1_COMMITMENT_ENTROPY_STATE_HOOK_TEST_SETUP
inline CommitmentEntropySourceScope
CommitmentEntropyScopeFactoryBridge::test_only_install(
        CommitmentEntropyStateHook& hook,
        std::uint64_t logical_process_epoch,
        std::uint64_t root_thread_epoch) {
    return install(hook, logical_process_epoch, root_thread_epoch);
}
#endif

} // namespace kpi::mpc::p1_private_state

#ifdef KPI_P1_COMMITMENT_ENTROPY_SOURCE_IMPLEMENTATION

namespace kpi::mpc::p1_private_state {
namespace commitment_entropy_source_detail {

struct ActiveCapture final {
    CommitmentEntropyStateHook* hook{};
    std::uint64_t generation{};
    std::uint64_t logical_process_epoch{};
    std::uint64_t next_object_epoch{1};
    std::array<std::uint64_t, 2> counters{};
    std::uint64_t explicit_thread_bindings{};
    std::vector<std::uint64_t> bound_thread_epochs;
    bool healthy{true};
};

struct ThreadBinding final {
    std::uint64_t generation{};
    std::uint64_t logical_thread_epoch{};
    bool explicit_binding{};
};

std::mutex capture_mutex;
ActiveCapture* active_capture{};
std::atomic<std::uint64_t> next_generation{1};
thread_local ThreadBinding thread_binding;

void mark_unavailable_locked(ActiveCapture& active) noexcept {
    if (!active.healthy) return;
    active.healthy = false;
    active.hook->commitment_entropy_unavailable_noexcept();
}

CommitmentEntropyRetainResult retain(
        CommitmentEntropySourceSite site, int commitment_owner,
        std::span<const unsigned char> exact_entropy) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return CommitmentEntropyRetainResult::NotRequired;
    if (!active->healthy) return CommitmentEntropyRetainResult::Failed;
    const auto site_value = static_cast<unsigned>(site);
    const auto index = site_value == 0 ? 2 : site_value - 1;
    if (commitment_owner < 0 || index >= active->counters.size() ||
        exact_entropy.size() != COMMITMENT_ENTROPY_BYTES ||
        thread_binding.generation != active->generation ||
        thread_binding.logical_thread_epoch == 0 ||
        active->logical_process_epoch == 0 ||
        active->next_object_epoch ==
            std::numeric_limits<std::uint64_t>::max() ||
        active->counters[index] ==
            std::numeric_limits<std::uint64_t>::max()) {
        mark_unavailable_locked(*active);
        return CommitmentEntropyRetainResult::Failed;
    }
    const auto before = active->counters[index]++;
    const CommitmentEntropyView view{
        .source_site = site,
        .commitment_owner = static_cast<std::uint64_t>(commitment_owner),
        .logical_process_epoch = active->logical_process_epoch,
        .logical_thread_epoch = thread_binding.logical_thread_epoch,
        .object_epoch = active->next_object_epoch++,
        .counter_before = before,
        .counter_after = before + 1,
        .exact_entropy = exact_entropy,
    };
    if (!active->hook->record_commitment_entropy(view)) {
        mark_unavailable_locked(*active);
        return CommitmentEntropyRetainResult::Failed;
    }
    return CommitmentEntropyRetainResult::Retained;
}

} // namespace commitment_entropy_source_detail

struct CommitmentEntropySourceScope::Storage final {
    commitment_entropy_source_detail::ActiveCapture active;
    bool installed{};
};

struct CommitmentEntropyThreadScope::Storage final {
    std::uint64_t generation{};
    std::uint64_t logical_thread_epoch{};
    bool installed{};
};

CommitmentEntropySourceScope::CommitmentEntropySourceScope(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}

CommitmentEntropySourceScope::CommitmentEntropySourceScope(
        CommitmentEntropySourceScope&&) noexcept = default;

CommitmentEntropySourceScope::~CommitmentEntropySourceScope() {
    using namespace commitment_entropy_source_detail;
    if (!storage_ || !storage_->installed) return;
    std::lock_guard lock(capture_mutex);
    if (active_capture == &storage_->active) {
        mark_unavailable_locked(storage_->active);
        active_capture = nullptr;
    }
    if (thread_binding.generation == storage_->active.generation &&
        !thread_binding.explicit_binding)
        thread_binding = {};
    storage_->installed = false;
}

bool CommitmentEntropySourceScope::finish_noexcept() && noexcept {
    using namespace commitment_entropy_source_detail;
    if (!storage_ || !storage_->installed) return false;
    std::lock_guard lock(capture_mutex);
    if (active_capture != &storage_->active) return false;
    const bool owner_thread =
        thread_binding.generation == storage_->active.generation &&
        !thread_binding.explicit_binding &&
        storage_->active.bound_thread_epochs.size() == 1 &&
        thread_binding.logical_thread_epoch ==
            storage_->active.bound_thread_epochs.front();
    const bool healthy = storage_->active.healthy && owner_thread &&
        storage_->active.explicit_thread_bindings == 0 &&
        storage_->active.hook->commitment_entropy_terminal_noexcept();
    if (!healthy) mark_unavailable_locked(storage_->active);
    active_capture = nullptr;
    if (thread_binding.generation == storage_->active.generation &&
        !thread_binding.explicit_binding)
        thread_binding = {};
    storage_->installed = false;
    return healthy;
}

CommitmentEntropyThreadScope::CommitmentEntropyThreadScope(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}

CommitmentEntropyThreadScope::CommitmentEntropyThreadScope(
        CommitmentEntropyThreadScope&&) noexcept = default;

CommitmentEntropyThreadScope::~CommitmentEntropyThreadScope() {
    using namespace commitment_entropy_source_detail;
    if (!storage_ || !storage_->installed) return;
    std::lock_guard lock(capture_mutex);
    if (active_capture &&
        active_capture->generation == storage_->generation) {
        const bool owner_thread =
            thread_binding.generation == storage_->generation &&
            thread_binding.explicit_binding &&
            thread_binding.logical_thread_epoch ==
                storage_->logical_thread_epoch;
        if (!owner_thread ||
            active_capture->explicit_thread_bindings == 0) {
            mark_unavailable_locked(*active_capture);
        } else {
            --active_capture->explicit_thread_bindings;
            const auto found = std::find(
                active_capture->bound_thread_epochs.begin(),
                active_capture->bound_thread_epochs.end(),
                storage_->logical_thread_epoch);
            if (found == active_capture->bound_thread_epochs.end())
                mark_unavailable_locked(*active_capture);
            else
                active_capture->bound_thread_epochs.erase(found);
        }
    }
    if (thread_binding.generation == storage_->generation &&
        thread_binding.explicit_binding &&
        thread_binding.logical_thread_epoch ==
            storage_->logical_thread_epoch)
        thread_binding = {};
    storage_->installed = false;
}

CommitmentEntropySourceScope
CommitmentEntropyScopeFactoryBridge::install(
        CommitmentEntropyStateHook& hook,
        std::uint64_t logical_process_epoch,
        std::uint64_t root_thread_epoch) {
    using namespace commitment_entropy_source_detail;
    if (logical_process_epoch == 0 || root_thread_epoch == 0)
        throw std::runtime_error("P1-commitment-entropy-zero-epoch");
    auto storage = std::make_unique<CommitmentEntropySourceScope::Storage>();
    storage->active.hook = &hook;
    storage->active.logical_process_epoch = logical_process_epoch;
    storage->active.bound_thread_epochs.push_back(root_thread_epoch);
    const auto generation = next_generation.fetch_add(1);
    if (generation == 0 ||
        generation == std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error(
            "P1-commitment-entropy-generation-exhausted");
    storage->active.generation = generation;
    {
        std::lock_guard lock(capture_mutex);
        if (active_capture || thread_binding.generation != 0)
            throw std::runtime_error(
                "P1-commitment-entropy-capture-already-installed");
        active_capture = &storage->active;
        thread_binding = ThreadBinding{
            .generation = generation,
            .logical_thread_epoch = root_thread_epoch,
            .explicit_binding = false,
        };
        storage->installed = true;
    }
    return CommitmentEntropySourceScope(std::move(storage));
}

CommitmentEntropyThreadScope
CommitmentEntropyScopeFactoryBridge::bind_thread(
        std::uint64_t logical_thread_epoch) {
    using namespace commitment_entropy_source_detail;
    if (logical_thread_epoch == 0)
        throw std::runtime_error("P1-commitment-entropy-zero-thread-epoch");
    auto storage = std::make_unique<CommitmentEntropyThreadScope::Storage>();
    std::lock_guard lock(capture_mutex);
    if (!active_capture || !active_capture->healthy ||
        thread_binding.generation != 0 ||
        std::find(
            active_capture->bound_thread_epochs.begin(),
            active_capture->bound_thread_epochs.end(),
            logical_thread_epoch) !=
            active_capture->bound_thread_epochs.end() ||
        active_capture->explicit_thread_bindings ==
            std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("P1-commitment-entropy-thread-bind-refused");
    // Allocate before mutating TLS/count. If push_back throws, the attempted
    // binding has made no observable state change and can be retried safely.
    active_capture->bound_thread_epochs.push_back(logical_thread_epoch);
    thread_binding = ThreadBinding{
        .generation = active_capture->generation,
        .logical_thread_epoch = logical_thread_epoch,
        .explicit_binding = true,
    };
    ++active_capture->explicit_thread_bindings;
    storage->generation = active_capture->generation;
    storage->logical_thread_epoch = logical_thread_epoch;
    storage->installed = true;
    return CommitmentEntropyThreadScope(std::move(storage));
}

#ifdef KPI_P1_COMMITMENT_ENTROPY_STATE_HOOK_TEST_SETUP
CommitmentEntropyThreadScope
CommitmentEntropyScopeFactoryBridge::test_only_bind_thread(
        std::uint64_t logical_thread_epoch) {
    return bind_thread(logical_thread_epoch);
}
#endif

CommitmentEntropyRetainResult
CommitmentEntropySourceBridge::record_legacy_commit_noexcept(
        int commitment_owner,
        std::span<const unsigned char> exact_entropy) noexcept {
    return commitment_entropy_source_detail::retain(
        CommitmentEntropySourceSite::LegacyCommitFunction,
        commitment_owner, exact_entropy);
}

CommitmentEntropyRetainResult
CommitmentEntropySourceBridge::record_object_commit_noexcept(
        int commitment_owner,
        std::span<const unsigned char> exact_entropy) noexcept {
    return commitment_entropy_source_detail::retain(
        CommitmentEntropySourceSite::CommitmentObject,
        commitment_owner, exact_entropy);
}

} // namespace kpi::mpc::p1_private_state

#endif // KPI_P1_COMMITMENT_ENTROPY_SOURCE_IMPLEMENTATION
