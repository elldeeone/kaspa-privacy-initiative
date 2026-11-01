#pragma once

// Private, child-local adapter surface for the observer-v5 corrupt-P1 state
// capsule. It does not mint a recorder and it does not expose state to the
// parent. MascotContext owns the hook through a unique_ptr for its full
// lifetime; the concrete capsule adapter independently retains shared ledger
// ownership rather than borrowing recorder or thread pointers.

#include <cstdint>
#include <limits>
#include <memory>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kpi::mpc {
class MascotContext;
}

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority;
class P1StateThreadEpochAuthority;
class P1ContextAndRetryStateAdapter;

// Complete before either private friendship grant. A standalone include
// therefore cannot define an exact-name recorder and acquire adapter Storage.
class P1ContextAndRetryStateAdapterFactoryBridge final {
    P1ContextAndRetryStateAdapterFactoryBridge() = delete;
public:
    static std::unique_ptr<P1ContextAndRetryStateAdapter> take(
        P1CorruptStateRecorderAuthority&,
        const P1StateThreadEpochAuthority&);
};
}

namespace kpi::mpc::p1_private_state {

#ifdef KPI_P1_CONTEXT_STATE_HOOK_TEST_SETUP
class TestOnlyContextAndRetryStateHook;
#endif

enum class ContextTransition : std::uint8_t {
    Validate = 1,
    Retry = 2,
    Poison = 3,
};

struct ContextAndRetrySnapshotView final {
    std::uint64_t party_id{};
    std::uint64_t player_count{};
    std::uint64_t generation{};
    std::uint64_t failure_epoch{};
    std::uint64_t check_counter{};
    std::uint64_t transition_counter{};
    std::uint64_t public_phase_counter{};
    bool poisoned{};
    bool encrypted_player{};
    bool transcript_capture_attached{};
    bool private_state_hook_attached{};
    bool public_stage_callback_attached{};
    std::string_view last_public_phase;
    const std::set<std::string>& validation_attempts;
};

namespace detail {

inline void append_u64(
        std::vector<unsigned char>& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

inline void append_string(
        std::vector<unsigned char>& output, std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("P1-context-state-string-too-large");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

} // namespace detail

// Canonical format.  Integers are little-endian u64, booleans are one byte,
// strings are u64-length-prefixed byte strings, and validation attempts use
// std::set's canonical bytewise ordering.  No pointer value is serialized.
inline std::vector<unsigned char> encode_context_and_retry_snapshot(
        const ContextAndRetrySnapshotView& value) {
    const auto attempts = static_cast<std::uint64_t>(
        value.validation_attempts.size());
    std::uint64_t expected_transitions = value.public_phase_counter;
    const auto add_expected = [&](std::uint64_t count) {
        if (count > std::numeric_limits<std::uint64_t>::max() -
                expected_transitions)
            throw std::runtime_error(
                "P1-context-state-transition-count-overflow");
        expected_transitions += count;
    };
    add_expected(value.check_counter);
    add_expected(attempts);
    add_expected(value.poisoned ? 1 : 0);
    if (value.player_count != 3 || value.party_id >= value.player_count ||
        !value.encrypted_player || !value.transcript_capture_attached ||
        !value.private_state_hook_attached ||
        value.generation == 0 ||
        value.last_public_phase.size() > 1024 ||
        value.validation_attempts.size() >
            std::numeric_limits<std::uint64_t>::max() ||
        (value.public_phase_counter == 0) !=
            value.last_public_phase.empty() ||
        value.failure_epoch != (value.poisoned ? 1 : 0) ||
        value.transition_counter != expected_transitions)
        throw std::runtime_error("invalid-P1-context-state-snapshot");

    static constexpr std::string_view domain =
        "KPI_P1_CONTEXT_AND_RETRY_STATE_V1\n";
    std::size_t reserve = domain.size() + 9 * 8 + 5;
    if (value.last_public_phase.size() >
        std::numeric_limits<std::size_t>::max() - reserve)
        throw std::runtime_error("P1-context-state-size-overflow");
    reserve += value.last_public_phase.size();
    for (const auto& attempt : value.validation_attempts) {
        if (attempt.empty() || attempt.size() > 1024 ||
            attempt.find('\0') != std::string::npos ||
            reserve > std::numeric_limits<std::size_t>::max() - 8 ||
            attempt.size() >
                std::numeric_limits<std::size_t>::max() - reserve - 8)
            throw std::runtime_error("invalid-P1-context-validation-attempt");
        reserve += 8 + attempt.size();
    }

    std::vector<unsigned char> output;
    output.reserve(reserve);
    output.insert(output.end(), domain.begin(), domain.end());
    detail::append_u64(output, value.party_id);
    detail::append_u64(output, value.player_count);
    detail::append_u64(output, value.generation);
    detail::append_u64(output, value.failure_epoch);
    detail::append_u64(output, value.check_counter);
    detail::append_u64(output, value.transition_counter);
    detail::append_u64(output, value.public_phase_counter);
    output.push_back(value.poisoned);
    output.push_back(value.encrypted_player);
    output.push_back(value.transcript_capture_attached);
    output.push_back(value.private_state_hook_attached);
    output.push_back(value.public_stage_callback_attached);
    detail::append_string(output, value.last_public_phase);
    detail::append_u64(output, value.validation_attempts.size());
    for (const auto& attempt : value.validation_attempts)
        detail::append_string(output, attempt);
    return output;
}

class ContextAndRetryStateHook {
    ContextAndRetryStateHook() = default;
    friend class ::kpi::mpc::MascotContext;
    friend class ::kpb::measurement::p1_state_capsule::
        P1ContextAndRetryStateAdapter;
#ifdef KPI_P1_CONTEXT_STATE_HOOK_TEST_SETUP
    friend class TestOnlyContextAndRetryStateHook;
#endif

    virtual void context_constructed(
        std::span<const unsigned char> exact_snapshot) = 0;
    virtual void context_transition(
        ContextTransition, std::uint64_t counter_before,
        std::uint64_t counter_after,
        std::span<const unsigned char> exact_snapshot) = 0;
    virtual void context_terminal(
        std::span<const unsigned char> exact_snapshot) = 0;

    // Called when an exact snapshot/transition cannot be retained.  It must
    // not throw; the containing capsule is permanently unavailable.
    virtual void context_unavailable_noexcept() noexcept = 0;

public:
    ContextAndRetryStateHook(const ContextAndRetryStateHook&) = delete;
    ContextAndRetryStateHook& operator=(const ContextAndRetryStateHook&) =
        delete;
    virtual ~ContextAndRetryStateHook() = default;
};

struct ContextStateHookSourceStatus final {
    bool canonical_wrapper_state_serializer{};
    bool construction_transition_terminal_surface{};
    bool no_raw_pointer_serialization{};
    bool mascot_context_hook_points{};
    bool production_adapter_construction{};
    bool capsule_family_adapter{};
    bool selected_p1_child_integration{};
    bool complete_corrupt_p1_view{};
};

inline constexpr ContextStateHookSourceStatus kContextStateHookSourceStatus{
    .canonical_wrapper_state_serializer = true,
    .construction_transition_terminal_surface = true,
    .no_raw_pointer_serialization = true,
    .mascot_context_hook_points = true,
    .production_adapter_construction = true,
    .capsule_family_adapter = true,
    .selected_p1_child_integration = false,
    .complete_corrupt_p1_view = false,
};

} // namespace kpi::mpc::p1_private_state

namespace kpb::measurement::p1_state_capsule {

// Complete in the same authoritative header before any capsule friendship can
// name it. The sole constructor is private to the live recorder. MascotContext
// owns this final adapter, while Storage retains the ledger capability needed
// for callbacks and fail-closed destruction.
class P1ContextAndRetryStateAdapter final
        : public kpi::mpc::p1_private_state::ContextAndRetryStateHook {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1ContextAndRetryStateAdapter(std::unique_ptr<Storage>);
    friend class P1ContextAndRetryStateAdapterFactoryBridge;

    void context_constructed(
        std::span<const unsigned char> exact_snapshot) override;
    void context_transition(
        kpi::mpc::p1_private_state::ContextTransition,
        std::uint64_t counter_before, std::uint64_t counter_after,
        std::span<const unsigned char> exact_snapshot) override;
    void context_terminal(
        std::span<const unsigned char> exact_snapshot) override;
    void context_unavailable_noexcept() noexcept override;

public:
    P1ContextAndRetryStateAdapter(
        const P1ContextAndRetryStateAdapter&) = delete;
    P1ContextAndRetryStateAdapter& operator=(
        const P1ContextAndRetryStateAdapter&) = delete;
    P1ContextAndRetryStateAdapter(
        P1ContextAndRetryStateAdapter&&) = delete;
    P1ContextAndRetryStateAdapter& operator=(
        P1ContextAndRetryStateAdapter&&) = delete;
    ~P1ContextAndRetryStateAdapter() override;

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
    void test_only_constructed(std::span<const unsigned char> value) {
        context_constructed(value);
    }
    void test_only_transition(
            kpi::mpc::p1_private_state::ContextTransition kind,
            std::uint64_t before, std::uint64_t after,
            std::span<const unsigned char> value) {
        context_transition(kind, before, after, value);
    }
    void test_only_terminal(std::span<const unsigned char> value) {
        context_terminal(value);
    }
    void test_only_unavailable_noexcept() noexcept {
        context_unavailable_noexcept();
    }
#endif
};

} // namespace kpb::measurement::p1_state_capsule
