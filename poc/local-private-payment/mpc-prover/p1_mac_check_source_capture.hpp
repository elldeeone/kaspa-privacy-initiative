#pragma once

#include "p1_mac_check_state_hook.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

template<class U> class MAC_Check_;

namespace kpi::mpc::p1_private_state {

class MacCheckSourceScope;
class MacCheckThreadScope;
class MacCheckAttemptScope;

class MacCheckScopeFactoryBridge final {
    MacCheckScopeFactoryBridge() = delete;
    static MacCheckSourceScope install(
        MacCheckStateHook&, std::uint64_t logical_process_epoch,
        std::uint64_t source_round, std::uint64_t root_thread_epoch,
        std::uint64_t local_role, std::uint64_t player_count);
    static MacCheckThreadScope bind_thread(
        std::uint64_t logical_thread_epoch);
    friend class ::kpb::measurement::p1_state_capsule::
        P1MacCheckStateAdapter;

#ifdef KPI_P1_MAC_CHECK_STATE_HOOK_TEST_SETUP
public:
    static MacCheckSourceScope test_only_install(
        MacCheckStateHook&, std::uint64_t logical_process_epoch,
        std::uint64_t source_round, std::uint64_t root_thread_epoch,
        std::uint64_t local_role, std::uint64_t player_count);
    static MacCheckThreadScope test_only_bind_thread(
        std::uint64_t logical_thread_epoch);
#endif
};

class MacCheckSourceScope final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit MacCheckSourceScope(std::unique_ptr<Storage>);
    friend class MacCheckScopeFactoryBridge;

public:
    MacCheckSourceScope(const MacCheckSourceScope&) = delete;
    MacCheckSourceScope& operator=(const MacCheckSourceScope&) = delete;
    MacCheckSourceScope(MacCheckSourceScope&&) noexcept;
    MacCheckSourceScope& operator=(MacCheckSourceScope&&) = delete;
    ~MacCheckSourceScope();
    bool finish_noexcept() && noexcept;
};

class MacCheckThreadScope final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit MacCheckThreadScope(std::unique_ptr<Storage>);
    friend class MacCheckScopeFactoryBridge;

public:
    MacCheckThreadScope(const MacCheckThreadScope&) = delete;
    MacCheckThreadScope& operator=(const MacCheckThreadScope&) = delete;
    MacCheckThreadScope(MacCheckThreadScope&&) noexcept;
    MacCheckThreadScope& operator=(MacCheckThreadScope&&) = delete;
    ~MacCheckThreadScope();
};

class MacCheckAttemptScope final {
    std::uint64_t generation_{};
    std::uint64_t check_epoch_{};
    bool required_{};
    bool installed_{};
    MacCheckAttemptScope(
        std::uint64_t generation, std::uint64_t check_epoch,
        bool required, bool installed) noexcept;
    friend class MacCheckSourceBridge;

public:
    MacCheckAttemptScope(const MacCheckAttemptScope&) = delete;
    MacCheckAttemptScope& operator=(const MacCheckAttemptScope&) = delete;
    MacCheckAttemptScope(MacCheckAttemptScope&&) noexcept;
    MacCheckAttemptScope& operator=(MacCheckAttemptScope&&) = delete;
    ~MacCheckAttemptScope();
};

// These are exact source edges, private to MAC_Check_<U>::Check. There is no
// generic record method, raw hook pointer, fd, digest, or caller-selected site.
class MacCheckSourceBridge final {
    MacCheckSourceBridge() = delete;
    static MacCheckAttemptScope check_begin_noexcept(
        int local_role, std::size_t player_count,
        std::uint64_t pending_open_count,
        std::span<const unsigned char> exact_alpha_share,
        std::span<const unsigned char> exact_pending_values,
        std::span<const unsigned char> exact_pending_macs) noexcept;
    static void collective_seed_noexcept(
        MacCheckAttemptScope&,
        std::span<const unsigned char> exact_collective_seed) noexcept;
    static void local_tau_noexcept(
        MacCheckAttemptScope&, std::uint64_t coefficient_count,
        std::span<const unsigned char> exact_coefficients,
        std::span<const unsigned char> exact_local_tau) noexcept;
    static void success_reset_noexcept(
        MacCheckAttemptScope&, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_tau_sum) noexcept;
    // The selected MP-SPDZ non-zero tau branch retains the three-event
    // successful prefix and closes this installed family as Unavailable.
    static void failure_reset_noexcept(
        MacCheckAttemptScope&, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_nonzero_tau_sum) noexcept;
    static void debug_branch_noexcept() noexcept;
    static void source_serialization_failure_noexcept() noexcept;
    template<class U> friend class ::MAC_Check_;

#ifdef KPI_P1_MAC_CHECK_STATE_HOOK_TEST_SETUP
public:
    static MacCheckAttemptScope test_only_check_begin(
        int local_role, std::size_t player_count,
        std::uint64_t pending_open_count,
        std::span<const unsigned char> exact_alpha_share,
        std::span<const unsigned char> exact_pending_values,
        std::span<const unsigned char> exact_pending_macs) noexcept;
    static void test_only_collective_seed(
        MacCheckAttemptScope&,
        std::span<const unsigned char> exact_collective_seed) noexcept;
    static void test_only_local_tau(
        MacCheckAttemptScope&, std::uint64_t coefficient_count,
        std::span<const unsigned char> exact_coefficients,
        std::span<const unsigned char> exact_local_tau) noexcept;
    static void test_only_success_reset(
        MacCheckAttemptScope&, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_tau_sum) noexcept;
    static void test_only_failure_reset(
        MacCheckAttemptScope&, std::uint64_t pending_after_reset,
        std::span<const unsigned char> exact_nonzero_tau_sum) noexcept;
    static void test_only_debug_branch() noexcept;
    static void test_only_source_serialization_failure() noexcept;
#endif
};

} // namespace kpi::mpc::p1_private_state
