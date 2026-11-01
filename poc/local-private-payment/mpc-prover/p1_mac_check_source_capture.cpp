#include "p1_mac_check_source_capture.hpp"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace kpi::mpc::p1_private_state {
namespace mac_check_source_detail {

struct AttemptState final {
    std::uint64_t check_epoch{};
    std::uint64_t logical_thread_epoch{};
    std::uint64_t pending_open_count{};
    std::uint64_t next_site{2};
};

struct ActiveCapture final {
    MacCheckStateHook* hook{};
    std::uint64_t generation{};
    std::uint64_t logical_process_epoch{};
    std::uint64_t source_round{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    std::uint64_t root_thread_epoch{};
    std::uint64_t next_check_epoch{1};
    std::uint64_t completed_check_count{};
    std::uint64_t explicit_thread_bindings{};
    std::vector<std::uint64_t> bound_thread_epochs;
    std::optional<AttemptState> attempt;
    bool healthy{true};
};

struct ThreadBinding final {
    std::uint64_t generation{};
    std::uint64_t logical_thread_epoch{};
    bool explicit_binding{};
};

struct BeginResult final {
    bool required{};
    bool retained{};
    std::uint64_t generation{};
    std::uint64_t check_epoch{};
};

struct UnavailableContext final {
    MacCheckUnavailableSite site{};
    MacCheckUnavailableReason reason{};
    bool derive_active_attempt{true};
    std::uint64_t active_check_epoch{};
    std::uint64_t completed_edge_count{};
    std::uint64_t expected_thread_epoch{};
    std::uint64_t pending_open_count{};
    std::uint64_t pending_after_reset{};
    std::span<const unsigned char> exact_tau_sum{};
};

std::mutex capture_mutex;
ActiveCapture* active_capture{};
std::atomic<std::uint64_t> next_generation{1};
thread_local ThreadBinding thread_binding;

bool mark_unavailable_locked(
        ActiveCapture& active, const UnavailableContext& context) noexcept {
    if (!active.healthy) return false;
    MacCheckUnavailableView view{
        .site = context.site,
        .reason = context.reason,
        .logical_process_epoch = active.logical_process_epoch,
        .source_round = active.source_round,
        .completed_check_count = active.completed_check_count,
        .active_check_epoch = context.active_check_epoch,
        .completed_edge_count = context.completed_edge_count,
        .expected_thread_epoch = context.expected_thread_epoch,
        .observed_thread_epoch =
            thread_binding.generation == active.generation
                ? thread_binding.logical_thread_epoch : 0,
        .local_role = active.local_role,
        .player_count = active.player_count,
        .pending_open_count = context.pending_open_count,
        .pending_after_reset = context.pending_after_reset,
        .exact_tau_sum = context.exact_tau_sum,
    };
    if (context.derive_active_attempt && active.attempt.has_value()) {
        view.active_check_epoch = active.attempt->check_epoch;
        view.completed_edge_count = active.attempt->next_site - 1;
        view.expected_thread_epoch =
            active.attempt->logical_thread_epoch;
        view.pending_open_count = active.attempt->pending_open_count;
    }
    active.healthy = false;
    return active.hook->record_mac_check_unavailable(view);
}

bool exact_packed_fields(
        std::span<const unsigned char> value, std::uint64_t count) noexcept {
    if (count > std::numeric_limits<std::size_t>::max() /
                    MAC_CHECK_FIELD_BYTES)
        return false;
    return value.size() ==
        static_cast<std::size_t>(count * MAC_CHECK_FIELD_BYTES);
}

MacCheckEventIdentity identity(
        const ActiveCapture& active, const AttemptState& attempt,
        std::uint64_t before) noexcept {
    return {
        .logical_process_epoch = active.logical_process_epoch,
        .logical_thread_epoch = attempt.logical_thread_epoch,
        .source_round = active.source_round,
        .check_epoch = attempt.check_epoch,
        .event_counter_before = before,
        .event_counter_after = before + 1,
        .local_role = active.local_role,
        .player_count = active.player_count,
        .pending_open_count = attempt.pending_open_count,
    };
}

bool bound_to_attempt(
        const ActiveCapture& active, const AttemptState& attempt) noexcept {
    return thread_binding.generation == active.generation &&
        thread_binding.logical_thread_epoch ==
            attempt.logical_thread_epoch;
}

BeginResult begin(
        int local_role, std::size_t player_count,
        std::uint64_t pending_open_count,
        std::span<const unsigned char> exact_alpha_share,
        std::span<const unsigned char> exact_pending_values,
        std::span<const unsigned char> exact_pending_macs) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return {.required = false, .retained = true};
    BeginResult result{.required = true, .retained = false};
    if (!active->healthy) return result;
    if (active->attempt.has_value()) {
        (void)mark_unavailable_locked(*active, {
            .site = MacCheckUnavailableSite::CheckBegin,
            .reason = MacCheckUnavailableReason::BeginConcurrent,
        });
        return result;
    }
    const bool metadata_valid = local_role >= 0 &&
        static_cast<std::uint64_t>(local_role) == active->local_role &&
        player_count <= std::numeric_limits<std::uint64_t>::max() &&
        static_cast<std::uint64_t>(player_count) == active->player_count &&
        pending_open_count != 0 &&
        active->next_check_epoch !=
            std::numeric_limits<std::uint64_t>::max() &&
        exact_alpha_share.size() == MAC_CHECK_FIELD_BYTES &&
        exact_packed_fields(exact_pending_values, pending_open_count) &&
        exact_packed_fields(exact_pending_macs, pending_open_count);
    if (!metadata_valid) {
        (void)mark_unavailable_locked(*active, {
            .site = MacCheckUnavailableSite::CheckBegin,
            .reason = MacCheckUnavailableReason::BeginMetadataInvalid,
            .derive_active_attempt = false,
            .active_check_epoch = active->next_check_epoch,
            .expected_thread_epoch =
                thread_binding.generation == active->generation
                    ? thread_binding.logical_thread_epoch : 0,
            .pending_open_count = pending_open_count,
        });
        return result;
    }
    if (thread_binding.generation != active->generation ||
        thread_binding.logical_thread_epoch == 0) {
        (void)mark_unavailable_locked(*active, {
            .site = MacCheckUnavailableSite::CheckBegin,
            .reason = MacCheckUnavailableReason::BeginThreadUnbound,
            .derive_active_attempt = false,
            .active_check_epoch = active->next_check_epoch,
            .pending_open_count = pending_open_count,
        });
        return result;
    }
    const AttemptState attempt{
        .check_epoch = active->next_check_epoch,
        .logical_thread_epoch = thread_binding.logical_thread_epoch,
        .pending_open_count = pending_open_count,
        .next_site = 2,
    };
    const MacCheckBeginView view{
        .identity = identity(*active, attempt, 0),
        .exact_alpha_share = exact_alpha_share,
        .exact_pending_values = exact_pending_values,
        .exact_pending_macs = exact_pending_macs,
    };
    if (!active->hook->record_mac_check_begin(view)) {
        (void)mark_unavailable_locked(*active, {
            .site = MacCheckUnavailableSite::CheckBegin,
            .reason = MacCheckUnavailableReason::HookRejected,
            .derive_active_attempt = false,
            .active_check_epoch = attempt.check_epoch,
            .expected_thread_epoch = attempt.logical_thread_epoch,
            .pending_open_count = attempt.pending_open_count,
        });
        return result;
    }
    active->attempt = attempt;
    ++active->next_check_epoch;
    result.retained = true;
    result.generation = active->generation;
    result.check_epoch = attempt.check_epoch;
    return result;
}

template<class View, class Validator, class Callback>
bool retain(
        std::uint64_t generation, std::uint64_t check_epoch,
        MacCheckSourceSite site, View&& view, Validator&& validator,
        Callback&& callback) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active || !active->healthy) return false;
    const auto unavailable_site =
        static_cast<MacCheckUnavailableSite>(site);
    if (active->generation != generation) {
        (void)mark_unavailable_locked(*active, {
            .site = unavailable_site,
            .reason = MacCheckUnavailableReason::EdgeGenerationMismatch,
        });
        return false;
    }
    if (!active->attempt.has_value()) {
        (void)mark_unavailable_locked(*active, {
            .site = unavailable_site,
            .reason = MacCheckUnavailableReason::EdgeAttemptMissing,
            .derive_active_attempt = false,
        });
        return false;
    }
    if (active->attempt->check_epoch != check_epoch) {
        (void)mark_unavailable_locked(*active, {
            .site = unavailable_site,
            .reason = MacCheckUnavailableReason::EdgeCheckMismatch,
        });
        return false;
    }
    if (active->attempt->next_site != static_cast<std::uint64_t>(site)) {
        (void)mark_unavailable_locked(*active, {
            .site = unavailable_site,
            .reason = MacCheckUnavailableReason::EdgeOrderMismatch,
        });
        return false;
    }
    if (!bound_to_attempt(*active, *active->attempt)) {
        (void)mark_unavailable_locked(*active, {
            .site = unavailable_site,
            .reason = MacCheckUnavailableReason::EdgeThreadMismatch,
        });
        return false;
    }
    view.identity = identity(
        *active, *active->attempt, static_cast<std::uint64_t>(site) - 1);
    if (!validator(*active->attempt, view)) {
        (void)mark_unavailable_locked(*active, {
            .site = unavailable_site,
            .reason = MacCheckUnavailableReason::EdgePayloadInvalid,
        });
        return false;
    }
    if (!callback(*active->hook, view)) {
        (void)mark_unavailable_locked(*active, {
            .site = unavailable_site,
            .reason = MacCheckUnavailableReason::HookRejected,
        });
        return false;
    }
    ++active->attempt->next_site;
    if (site == MacCheckSourceSite::SuccessReset) {
        active->attempt.reset();
        ++active->completed_check_count;
    }
    return true;
}

bool seed(
        std::uint64_t generation, std::uint64_t check_epoch,
        std::span<const unsigned char> exact_collective_seed) noexcept {
    MacCheckCollectiveSeedView view{
        .identity = {},
        .exact_collective_seed = exact_collective_seed,
    };
    return retain(
        generation, check_epoch, MacCheckSourceSite::CollectiveSeed,
        view, [](const AttemptState&, const auto& selected) noexcept {
            return selected.exact_collective_seed.size() ==
                MAC_CHECK_SEED_BYTES;
        },
        [](MacCheckStateHook& hook, const auto& selected) {
            return hook.record_mac_check_collective_seed(selected);
        });
}

bool tau(
        std::uint64_t generation, std::uint64_t check_epoch,
        std::uint64_t coefficient_count,
        std::span<const unsigned char> exact_coefficients,
        std::span<const unsigned char> exact_local_tau) noexcept {
    MacCheckLocalTauView view{
        .identity = {},
        .coefficient_count = coefficient_count,
        .exact_coefficients = exact_coefficients,
        .exact_local_tau = exact_local_tau,
    };
    return retain(
        generation, check_epoch, MacCheckSourceSite::LocalTau, view,
        [](const AttemptState& attempt, const auto& selected) noexcept {
            return selected.coefficient_count ==
                    attempt.pending_open_count &&
                exact_packed_fields(
                    selected.exact_coefficients,
                    selected.coefficient_count) &&
                selected.exact_local_tau.size() == MAC_CHECK_FIELD_BYTES;
        },
        [](MacCheckStateHook& hook, const auto& selected) {
            return hook.record_mac_check_local_tau(selected);
        });
}

bool success(
        std::uint64_t generation, std::uint64_t check_epoch,
        std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_tau_sum) noexcept {
    MacCheckSuccessResetView view{
        .identity = {},
        .pending_after_reset = pending_after_reset,
        .exact_tau_sum = exact_tau_sum,
    };
    return retain(
            generation, check_epoch, MacCheckSourceSite::SuccessReset, view,
            [](const AttemptState&, const auto& selected) noexcept {
                return selected.pending_after_reset == 0 &&
                    selected.exact_tau_sum.size() ==
                        MAC_CHECK_FIELD_BYTES &&
                    std::all_of(
                        selected.exact_tau_sum.begin(),
                        selected.exact_tau_sum.end(),
                        [](unsigned char byte) { return byte == 0; });
            },
            [](MacCheckStateHook& hook, const auto& selected) {
                return hook.record_mac_check_success_reset(selected);
            });
}

bool failure(
        std::uint64_t generation, std::uint64_t check_epoch,
        std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_tau_sum) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active || !active->healthy) return false;
    const auto reject = [&](MacCheckUnavailableReason reason) noexcept {
        (void)mark_unavailable_locked(*active, {
            .site = MacCheckUnavailableSite::FailureReset,
            .reason = reason,
        });
        return false;
    };
    if (active->generation != generation)
        return reject(MacCheckUnavailableReason::EdgeGenerationMismatch);
    if (!active->attempt.has_value())
        return reject(MacCheckUnavailableReason::EdgeAttemptMissing);
    if (active->attempt->check_epoch != check_epoch)
        return reject(MacCheckUnavailableReason::EdgeCheckMismatch);
    if (active->attempt->next_site !=
            static_cast<std::uint64_t>(MacCheckSourceSite::SuccessReset))
        return reject(MacCheckUnavailableReason::EdgeOrderMismatch);
    if (!bound_to_attempt(*active, *active->attempt))
        return reject(MacCheckUnavailableReason::EdgeThreadMismatch);
    if (pending_after_reset != 0 ||
        exact_tau_sum.size() != MAC_CHECK_FIELD_BYTES ||
        std::all_of(
            exact_tau_sum.begin(), exact_tau_sum.end(),
            [](unsigned char byte) { return byte == 0; }))
        return reject(MacCheckUnavailableReason::EdgePayloadInvalid);
    const bool retained = mark_unavailable_locked(*active, {
        .site = MacCheckUnavailableSite::FailureReset,
        .reason = MacCheckUnavailableReason::ProtocolMacFailure,
        .pending_after_reset = pending_after_reset,
        .exact_tau_sum = exact_tau_sum,
    });
    active->attempt.reset();
    return retained;
}

bool source_unavailable(
        MacCheckUnavailableSite site,
        MacCheckUnavailableReason reason) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return true;
    if (!active->healthy) return false;
    return mark_unavailable_locked(*active, {
        .site = site,
        .reason = reason,
    });
}

void drop_attempt(
        std::uint64_t generation, std::uint64_t check_epoch) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active || active->generation != generation) return;
    if (active->attempt.has_value() &&
        active->attempt->check_epoch == check_epoch) {
        (void)mark_unavailable_locked(*active, {
            .site = MacCheckUnavailableSite::AttemptScope,
            .reason = MacCheckUnavailableReason::AttemptDropped,
        });
        active->attempt.reset();
    } else if (active->healthy) {
        (void)mark_unavailable_locked(*active, {
            .site = MacCheckUnavailableSite::AttemptScope,
            .reason = MacCheckUnavailableReason::AttemptDropped,
        });
    }
}

} // namespace mac_check_source_detail

struct MacCheckSourceScope::Storage final {
    mac_check_source_detail::ActiveCapture active;
    bool installed{};
};

struct MacCheckThreadScope::Storage final {
    std::uint64_t generation{};
    std::uint64_t logical_thread_epoch{};
    bool installed{};
};

MacCheckSourceScope::MacCheckSourceScope(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}

MacCheckSourceScope::MacCheckSourceScope(MacCheckSourceScope&&) noexcept =
    default;

MacCheckSourceScope::~MacCheckSourceScope() {
    using namespace mac_check_source_detail;
    if (!storage_ || !storage_->installed) return;
    std::lock_guard lock(capture_mutex);
    if (active_capture == &storage_->active) {
        (void)mark_unavailable_locked(storage_->active, {
            .site = MacCheckUnavailableSite::CaptureScope,
            .reason = MacCheckUnavailableReason::CaptureScopeDropped,
            .expected_thread_epoch = storage_->active.root_thread_epoch,
        });
        active_capture = nullptr;
    }
    if (thread_binding.generation == storage_->active.generation &&
        !thread_binding.explicit_binding)
        thread_binding = {};
    storage_->installed = false;
}

bool MacCheckSourceScope::finish_noexcept() && noexcept {
    using namespace mac_check_source_detail;
    if (!storage_ || !storage_->installed) return false;
    std::lock_guard lock(capture_mutex);
    if (active_capture != &storage_->active) return false;
    bool healthy = storage_->active.healthy;
    const bool owner_thread =
        thread_binding.generation == storage_->active.generation &&
        !thread_binding.explicit_binding &&
        thread_binding.logical_thread_epoch ==
            storage_->active.root_thread_epoch;
    if (healthy && !owner_thread) {
        (void)mark_unavailable_locked(storage_->active, {
            .site = MacCheckUnavailableSite::CaptureTerminal,
            .reason = MacCheckUnavailableReason::TerminalOwnerMismatch,
            .expected_thread_epoch = storage_->active.root_thread_epoch,
        });
        healthy = false;
    }
    const bool structurally_complete =
        !storage_->active.attempt.has_value() &&
        storage_->active.completed_check_count != 0 &&
        storage_->active.explicit_thread_bindings == 0 &&
        storage_->active.bound_thread_epochs.size() == 1 &&
        storage_->active.bound_thread_epochs.front() ==
            storage_->active.root_thread_epoch;
    if (healthy && !structurally_complete) {
        (void)mark_unavailable_locked(storage_->active, {
            .site = MacCheckUnavailableSite::CaptureTerminal,
            .reason = MacCheckUnavailableReason::TerminalIncomplete,
            .expected_thread_epoch = storage_->active.root_thread_epoch,
        });
        healthy = false;
    }
    if (healthy &&
        !storage_->active.hook->mac_check_capture_terminal_noexcept()) {
        (void)mark_unavailable_locked(storage_->active, {
            .site = MacCheckUnavailableSite::CaptureTerminal,
            .reason = MacCheckUnavailableReason::TerminalRejected,
            .expected_thread_epoch = storage_->active.root_thread_epoch,
        });
        healthy = false;
    }
    active_capture = nullptr;
    if (thread_binding.generation == storage_->active.generation &&
        !thread_binding.explicit_binding)
        thread_binding = {};
    storage_->installed = false;
    return healthy;
}

MacCheckThreadScope::MacCheckThreadScope(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}

MacCheckThreadScope::MacCheckThreadScope(MacCheckThreadScope&&) noexcept =
    default;

MacCheckThreadScope::~MacCheckThreadScope() {
    using namespace mac_check_source_detail;
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
            active_capture->explicit_thread_bindings == 0 ||
            (active_capture->attempt.has_value() &&
             active_capture->attempt->logical_thread_epoch ==
                 storage_->logical_thread_epoch)) {
            (void)mark_unavailable_locked(*active_capture, {
                .site = MacCheckUnavailableSite::ThreadScope,
                .reason = MacCheckUnavailableReason::ThreadScopeViolation,
                .expected_thread_epoch = storage_->logical_thread_epoch,
            });
        } else {
            --active_capture->explicit_thread_bindings;
            const auto found = std::find(
                active_capture->bound_thread_epochs.begin(),
                active_capture->bound_thread_epochs.end(),
                storage_->logical_thread_epoch);
            if (found == active_capture->bound_thread_epochs.end())
                (void)mark_unavailable_locked(*active_capture, {
                    .site = MacCheckUnavailableSite::ThreadScope,
                    .reason =
                        MacCheckUnavailableReason::ThreadScopeViolation,
                    .expected_thread_epoch =
                        storage_->logical_thread_epoch,
                });
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

MacCheckAttemptScope::MacCheckAttemptScope(
        std::uint64_t generation, std::uint64_t check_epoch,
        bool required, bool installed) noexcept
    : generation_(generation), check_epoch_(check_epoch),
      required_(required), installed_(installed) {}

MacCheckAttemptScope::MacCheckAttemptScope(
        MacCheckAttemptScope&& other) noexcept
    : generation_(other.generation_), check_epoch_(other.check_epoch_),
      required_(other.required_), installed_(other.installed_) {
    other.installed_ = false;
    other.required_ = false;
}

MacCheckAttemptScope::~MacCheckAttemptScope() {
    if (required_ && installed_)
        mac_check_source_detail::drop_attempt(generation_, check_epoch_);
}

MacCheckSourceScope MacCheckScopeFactoryBridge::install(
        MacCheckStateHook& hook, std::uint64_t logical_process_epoch,
        std::uint64_t source_round, std::uint64_t root_thread_epoch,
        std::uint64_t local_role, std::uint64_t player_count) {
    using namespace mac_check_source_detail;
    if (logical_process_epoch == 0 ||
        (source_round != 1 && source_round != 2) ||
        root_thread_epoch == 0 || player_count == 0 ||
        local_role >= player_count)
        throw std::runtime_error("P1-MAC-check-invalid-installation");
    auto storage = std::make_unique<MacCheckSourceScope::Storage>();
    storage->active.hook = &hook;
    storage->active.logical_process_epoch = logical_process_epoch;
    storage->active.source_round = source_round;
    storage->active.local_role = local_role;
    storage->active.player_count = player_count;
    storage->active.root_thread_epoch = root_thread_epoch;
    storage->active.bound_thread_epochs.push_back(root_thread_epoch);
    const auto generation = next_generation.fetch_add(1);
    if (generation == 0 ||
        generation == std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("P1-MAC-check-generation-exhausted");
    storage->active.generation = generation;
    {
        std::lock_guard lock(capture_mutex);
        if (active_capture || thread_binding.generation != 0)
            throw std::runtime_error("P1-MAC-check-capture-already-installed");
        active_capture = &storage->active;
        thread_binding = {
            .generation = generation,
            .logical_thread_epoch = root_thread_epoch,
            .explicit_binding = false,
        };
        storage->installed = true;
    }
    return MacCheckSourceScope(std::move(storage));
}

MacCheckThreadScope MacCheckScopeFactoryBridge::bind_thread(
        std::uint64_t logical_thread_epoch) {
    using namespace mac_check_source_detail;
    if (logical_thread_epoch == 0) {
        std::lock_guard lock(capture_mutex);
        if (active_capture && active_capture->healthy)
            (void)mark_unavailable_locked(*active_capture, {
                .site = MacCheckUnavailableSite::ThreadScope,
                .reason = MacCheckUnavailableReason::ThreadScopeViolation,
            });
        throw std::runtime_error("P1-MAC-check-zero-thread-epoch");
    }
    std::unique_ptr<MacCheckThreadScope::Storage> storage;
    try {
        storage = std::make_unique<MacCheckThreadScope::Storage>();
    } catch (...) {
        std::lock_guard lock(capture_mutex);
        if (active_capture && active_capture->healthy)
            (void)mark_unavailable_locked(*active_capture, {
                .site = MacCheckUnavailableSite::ThreadScope,
                .reason = MacCheckUnavailableReason::ThreadScopeViolation,
                .expected_thread_epoch = logical_thread_epoch,
            });
        throw;
    }
    std::lock_guard lock(capture_mutex);
    if (!active_capture || !active_capture->healthy ||
        thread_binding.generation != 0 ||
        std::find(
            active_capture->bound_thread_epochs.begin(),
            active_capture->bound_thread_epochs.end(),
            logical_thread_epoch) !=
            active_capture->bound_thread_epochs.end() ||
        active_capture->explicit_thread_bindings ==
            std::numeric_limits<std::uint64_t>::max()) {
        if (active_capture && active_capture->healthy)
            (void)mark_unavailable_locked(*active_capture, {
                .site = MacCheckUnavailableSite::ThreadScope,
                .reason = MacCheckUnavailableReason::ThreadScopeViolation,
                .expected_thread_epoch = logical_thread_epoch,
            });
        throw std::runtime_error("P1-MAC-check-thread-bind-refused");
    }
    try {
        active_capture->bound_thread_epochs.push_back(logical_thread_epoch);
    } catch (...) {
        (void)mark_unavailable_locked(*active_capture, {
            .site = MacCheckUnavailableSite::ThreadScope,
            .reason = MacCheckUnavailableReason::ThreadScopeViolation,
            .expected_thread_epoch = logical_thread_epoch,
        });
        throw;
    }
    thread_binding = {
        .generation = active_capture->generation,
        .logical_thread_epoch = logical_thread_epoch,
        .explicit_binding = true,
    };
    ++active_capture->explicit_thread_bindings;
    storage->generation = active_capture->generation;
    storage->logical_thread_epoch = logical_thread_epoch;
    storage->installed = true;
    return MacCheckThreadScope(std::move(storage));
}

MacCheckAttemptScope MacCheckSourceBridge::check_begin_noexcept(
        int local_role, std::size_t player_count,
        std::uint64_t pending_open_count,
        std::span<const unsigned char> exact_alpha_share,
        std::span<const unsigned char> exact_pending_values,
        std::span<const unsigned char> exact_pending_macs) noexcept {
    const auto result = mac_check_source_detail::begin(
        local_role, player_count, pending_open_count, exact_alpha_share,
        exact_pending_values, exact_pending_macs);
    if (!result.retained) std::abort();
    return MacCheckAttemptScope(
        result.generation, result.check_epoch, result.required,
        result.required);
}

void MacCheckSourceBridge::collective_seed_noexcept(
        MacCheckAttemptScope& scope,
        std::span<const unsigned char> exact_collective_seed) noexcept {
    if (!scope.required_) return;
    if (!scope.installed_ || !mac_check_source_detail::seed(
            scope.generation_, scope.check_epoch_, exact_collective_seed))
        std::abort();
}

void MacCheckSourceBridge::local_tau_noexcept(
        MacCheckAttemptScope& scope, std::uint64_t coefficient_count,
        std::span<const unsigned char> exact_coefficients,
        std::span<const unsigned char> exact_local_tau) noexcept {
    if (!scope.required_) return;
    if (!scope.installed_ || !mac_check_source_detail::tau(
            scope.generation_, scope.check_epoch_, coefficient_count,
            exact_coefficients, exact_local_tau))
        std::abort();
}

void MacCheckSourceBridge::success_reset_noexcept(
        MacCheckAttemptScope& scope, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_tau_sum) noexcept {
    if (!scope.required_) return;
    if (!scope.installed_ || !mac_check_source_detail::success(
            scope.generation_, scope.check_epoch_, pending_after_reset,
            exact_tau_sum))
        std::abort();
    scope.installed_ = false;
}

void MacCheckSourceBridge::failure_reset_noexcept(
        MacCheckAttemptScope& scope, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_nonzero_tau_sum) noexcept {
    if (!scope.required_) return;
    if (!scope.installed_ || !mac_check_source_detail::failure(
            scope.generation_, scope.check_epoch_, pending_after_reset,
            exact_nonzero_tau_sum))
        std::abort();
    scope.installed_ = false;
}

void MacCheckSourceBridge::debug_branch_noexcept() noexcept {
    if (!mac_check_source_detail::source_unavailable(
            MacCheckUnavailableSite::DebugBranch,
            MacCheckUnavailableReason::UnsupportedDebugBranch))
        std::abort();
}

void MacCheckSourceBridge::source_serialization_failure_noexcept() noexcept {
    if (!mac_check_source_detail::source_unavailable(
            MacCheckUnavailableSite::SourceSerialization,
            MacCheckUnavailableReason::SourceSerializationFailure))
        std::abort();
}

#ifdef KPI_P1_MAC_CHECK_STATE_HOOK_TEST_SETUP
MacCheckSourceScope MacCheckScopeFactoryBridge::test_only_install(
        MacCheckStateHook& hook, std::uint64_t logical_process_epoch,
        std::uint64_t source_round, std::uint64_t root_thread_epoch,
        std::uint64_t local_role, std::uint64_t player_count) {
    return install(
        hook, logical_process_epoch, source_round, root_thread_epoch,
        local_role, player_count);
}

MacCheckThreadScope MacCheckScopeFactoryBridge::test_only_bind_thread(
        std::uint64_t logical_thread_epoch) {
    return bind_thread(logical_thread_epoch);
}

MacCheckAttemptScope MacCheckSourceBridge::test_only_check_begin(
        int local_role, std::size_t player_count,
        std::uint64_t pending_open_count,
        std::span<const unsigned char> exact_alpha_share,
        std::span<const unsigned char> exact_pending_values,
        std::span<const unsigned char> exact_pending_macs) noexcept {
    return check_begin_noexcept(
        local_role, player_count, pending_open_count, exact_alpha_share,
        exact_pending_values, exact_pending_macs);
}

void MacCheckSourceBridge::test_only_collective_seed(
        MacCheckAttemptScope& scope,
        std::span<const unsigned char> exact_collective_seed) noexcept {
    collective_seed_noexcept(scope, exact_collective_seed);
}

void MacCheckSourceBridge::test_only_local_tau(
        MacCheckAttemptScope& scope, std::uint64_t coefficient_count,
        std::span<const unsigned char> exact_coefficients,
        std::span<const unsigned char> exact_local_tau) noexcept {
    local_tau_noexcept(
        scope, coefficient_count, exact_coefficients, exact_local_tau);
}

void MacCheckSourceBridge::test_only_success_reset(
        MacCheckAttemptScope& scope, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_tau_sum) noexcept {
    success_reset_noexcept(scope, pending_after_reset, exact_tau_sum);
}

void MacCheckSourceBridge::test_only_failure_reset(
        MacCheckAttemptScope& scope, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_nonzero_tau_sum) noexcept {
    failure_reset_noexcept(
        scope, pending_after_reset, exact_nonzero_tau_sum);
}

void MacCheckSourceBridge::test_only_debug_branch() noexcept {
    debug_branch_noexcept();
}

void MacCheckSourceBridge::test_only_source_serialization_failure() noexcept {
    source_serialization_failure_noexcept();
}
#endif

} // namespace kpi::mpc::p1_private_state
