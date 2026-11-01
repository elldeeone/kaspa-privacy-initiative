#include "../../p1_context_state_hook.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace state = kpi::mpc::p1_private_state;

namespace kpi::mpc::p1_private_state {

class TestOnlyContextAndRetryStateHook final
        : public ContextAndRetryStateHook {
    void context_constructed(std::span<const unsigned char>) override {}
    void context_transition(
        ContextTransition, std::uint64_t, std::uint64_t,
        std::span<const unsigned char>) override {}
    void context_terminal(std::span<const unsigned char>) override {}
    void context_unavailable_noexcept() noexcept override {}

public:
    TestOnlyContextAndRetryStateHook() = default;
};

} // namespace kpi::mpc::p1_private_state

namespace {

std::uint64_t take_u64(
        std::span<const unsigned char> bytes, std::size_t& offset) {
    assert(offset <= bytes.size() && bytes.size() - offset >= 8);
    std::uint64_t result = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
        result |= std::uint64_t{bytes[offset++]} << shift;
    return result;
}

std::string take_string(
        std::span<const unsigned char> bytes, std::size_t& offset) {
    const auto size = take_u64(bytes, offset);
    assert(size <= bytes.size() - offset);
    std::string result(
        reinterpret_cast<const char*>(bytes.data() + offset), size);
    offset += size;
    return result;
}

bool refuses(const std::function<void()>& action) {
    try {
        action();
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

state::ContextAndRetrySnapshotView view(
        const std::set<std::string>& attempts) {
    return {
        .party_id = 1,
        .player_count = 3,
        .generation = 7,
        .failure_epoch = 0,
        .check_counter = 0,
        .transition_counter = 0,
        .public_phase_counter = 0,
        .poisoned = false,
        .encrypted_player = true,
        .transcript_capture_attached = true,
        .private_state_hook_attached = true,
        .public_stage_callback_attached = false,
        .last_public_phase = {},
        .validation_attempts = attempts,
    };
}

} // namespace

int main() {
    using Sink = state::TestOnlyContextAndRetryStateHook;
    static_assert(std::is_default_constructible_v<Sink>);
    static_assert(!std::is_copy_constructible_v<Sink>);
    static_assert(std::has_virtual_destructor_v<
                  state::ContextAndRetryStateHook>);
    static_assert(state::kContextStateHookSourceStatus
                      .canonical_wrapper_state_serializer);
    static_assert(state::kContextStateHookSourceStatus
                      .mascot_context_hook_points);
    static_assert(state::kContextStateHookSourceStatus
                      .production_adapter_construction);
    static_assert(state::kContextStateHookSourceStatus
                      .capsule_family_adapter);
    static_assert(!state::kContextStateHookSourceStatus
                       .selected_p1_child_integration);
    static_assert(!state::kContextStateHookSourceStatus
                       .complete_corrupt_p1_view);
    Sink sink;
    (void)sink;

    const std::set<std::string> none;
    const auto initial = state::encode_context_and_retry_snapshot(view(none));
    const std::string_view domain =
        "KPI_P1_CONTEXT_AND_RETRY_STATE_V1\n";
    assert(initial.size() >= domain.size());
    assert(std::equal(
        domain.begin(), domain.end(), initial.begin()));
    std::size_t offset = domain.size();
    assert(take_u64(initial, offset) == 1);
    assert(take_u64(initial, offset) == 3);
    assert(take_u64(initial, offset) == 7);
    assert(take_u64(initial, offset) == 0);
    assert(take_u64(initial, offset) == 0);
    assert(take_u64(initial, offset) == 0);
    assert(take_u64(initial, offset) == 0);
    assert(initial[offset++] == 0);
    assert(initial[offset++] == 1);
    assert(initial[offset++] == 1);
    assert(initial[offset++] == 1);
    assert(initial[offset++] == 0);
    assert(take_string(initial, offset).empty());
    assert(take_u64(initial, offset) == 0);
    assert(offset == initial.size());

    std::set<std::string> attempts;
    attempts.insert("bbbb");
    attempts.insert("aaaa");
    auto complete = view(attempts);
    complete.failure_epoch = 1;
    complete.check_counter = 3;
    complete.transition_counter = 8;
    complete.public_phase_counter = 2;
    complete.poisoned = true;
    complete.public_stage_callback_attached = true;
    complete.last_public_phase = "phase-two";
    const auto encoded = state::encode_context_and_retry_snapshot(complete);
    const auto encoded_again =
        state::encode_context_and_retry_snapshot(complete);
    assert(encoded == encoded_again && encoded != initial);
    offset = domain.size() + 7 * 8 + 5;
    assert(take_string(encoded, offset) == "phase-two");
    assert(take_u64(encoded, offset) == 2);
    assert(take_string(encoded, offset) == "aaaa");
    assert(take_string(encoded, offset) == "bbbb");
    assert(offset == encoded.size());

    const auto refuses_view = [&](auto mutate) {
        auto wrong = view(none);
        mutate(wrong);
        return refuses([&] {
            state::encode_context_and_retry_snapshot(wrong);
        });
    };
    assert(refuses_view([](auto& wrong) { wrong.player_count = 2; }));
    assert(refuses_view([](auto& wrong) { wrong.party_id = 3; }));
    assert(refuses_view([](auto& wrong) {
        wrong.encrypted_player = false;
    }));
    assert(refuses_view([](auto& wrong) {
        wrong.transcript_capture_attached = false;
    }));
    assert(refuses_view([](auto& wrong) {
        wrong.private_state_hook_attached = false;
    }));
    assert(refuses_view([](auto& wrong) { wrong.generation = 0; }));

    assert(refuses_view([](auto& wrong) {
        wrong.public_phase_counter = 1;
        wrong.transition_counter = 1;
    }));
    assert(refuses_view([](auto& wrong) {
        wrong.last_public_phase = "unexpected";
    }));
    assert(refuses_view([](auto& wrong) {
        wrong.poisoned = true;
        wrong.transition_counter = 1;
    }));
    assert(refuses_view([](auto& wrong) { wrong.failure_epoch = 1; }));
    assert(refuses_view([](auto& wrong) {
        wrong.transition_counter = 1;
    }));

    assert(refuses_view([](auto& wrong) {
        wrong.public_phase_counter =
            std::numeric_limits<std::uint64_t>::max();
        wrong.check_counter = 1;
    }));

    const std::set<std::string> empty_attempt{{""}};
    assert(refuses([&] {
        state::encode_context_and_retry_snapshot(view(empty_attempt));
    }));
    const std::set<std::string> nul_attempt{{std::string("a\0b", 3)}};
    assert(refuses([&] {
        state::encode_context_and_retry_snapshot(view(nul_attempt));
    }));
    const std::set<std::string> long_attempt{{std::string(1025, 'a')}};
    assert(refuses([&] {
        state::encode_context_and_retry_snapshot(view(long_attempt));
    }));
}
