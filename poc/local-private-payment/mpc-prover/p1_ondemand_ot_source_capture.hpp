#pragma once

// Source-owned field-wise packer for the exact pinned MP-SPDZ
// OnDemandOTTripleSetup implementation. It is included only by the patched
// source callsites. Object memory, padding, pointers, pthread identifiers, and
// allocator metadata are never serialized.

#include "p1_ondemand_ot_state_hook.hpp"

#include "OT/OTTripleSetup.h"
#include "Tools/random.h"
#include "Tools/time-func.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb_mp_spdz_p1_ondemand_ot {
namespace state = kpi::mpc::p1_private_state;

namespace detail {

inline constexpr std::size_t MAX_SOURCE_STATE_BYTES =
    8U * 1024U * 1024U;

inline std::size_t checked_size_add(
        std::size_t left, std::size_t right) {
    if (left > MAX_SOURCE_STATE_BYTES ||
        right > MAX_SOURCE_STATE_BYTES - left)
        throw std::runtime_error("P1-OnDemandOT-source-size");
    return left + right;
}

inline void require_reserved_append(
        const std::vector<unsigned char>& output, std::size_t count) {
    if (count > MAX_SOURCE_STATE_BYTES ||
        output.size() > MAX_SOURCE_STATE_BYTES - count ||
        count > output.capacity() - output.size())
        throw std::runtime_error("P1-OnDemandOT-source-capacity");
}

inline std::size_t encoded_bytes_size(std::size_t size) {
    return checked_size_add(8U, size);
}

inline void cleanse(std::vector<unsigned char>& value) noexcept {
    volatile unsigned char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
        cursor[index] = 0;
    value.clear();
}

class SecretBytes final {
    std::vector<unsigned char> value_;
public:
    SecretBytes() = default;
    explicit SecretBytes(std::vector<unsigned char> value) {
        if (value.size() > MAX_SOURCE_STATE_BYTES)
            throw std::runtime_error("P1-OnDemandOT-source-size");
        value_.swap(value);
    }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept {
        value_.swap(other.value_);
    }
    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            cleanse(value_);
            value_.swap(other.value_);
        }
        return *this;
    }
    ~SecretBytes() { cleanse(value_); }
    std::span<const unsigned char> view() const noexcept { return value_; }
    std::size_t size() const noexcept { return value_.size(); }
#ifdef KPI_P1_ONDEMAND_OT_SOURCE_CAPTURE_TEST_SETUP
    const std::vector<unsigned char>& test_only_bytes() const noexcept {
        return value_;
    }
#endif
};

inline void append_u64(
        std::vector<unsigned char>& output, std::uint64_t value) {
    require_reserved_append(output, 8U);
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

inline void append_i64(
        std::vector<unsigned char>& output, std::int64_t value) {
    append_u64(output, static_cast<std::uint64_t>(value));
}

inline void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    const auto encoded = encoded_bytes_size(value.size());
    require_reserved_append(output, encoded);
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

inline void append_domain(
        std::vector<unsigned char>& output, std::string_view domain) {
    require_reserved_append(output, domain.size());
    output.insert(output.end(), domain.begin(), domain.end());
}

inline std::size_t encoded_bit_vector_size(const BitVector& value) {
    return checked_size_add(8U, encoded_bytes_size(value.size_bytes()));
}

inline void append_bit_vector(
        std::vector<unsigned char>& output, const BitVector& value) {
    append_u64(output, value.size());
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(value.get_ptr()),
        value.size_bytes()));
}

inline void reserve_exact(
        std::vector<unsigned char>& output, std::size_t required) {
    if (!output.empty() || required > MAX_SOURCE_STATE_BYTES)
        throw std::runtime_error("P1-OnDemandOT-source-reserve");
    output.reserve(required);
    if (output.capacity() < required)
        throw std::runtime_error("P1-OnDemandOT-source-reserve");
}

} // namespace detail

// Friend of only the pinned PRNG, Timer, BaseOT, OTTripleSetup, and
// OnDemandOTTripleSetup classes named by the source patch. Every result is a
// zeroizing temporary consumed synchronously by the private hook.
class SourceAccess final {
    SourceAccess() = delete;

    enum class RandomWindow : std::uint8_t {
        UndefinedAfterInitSeed = 0,
        Defined = 1,
    };

    inline static constexpr std::string_view TIMER_DOMAIN =
        "KPI_P1_MP_SPDZ_TIMER_PRIVATE_STATE_V1\n";
    inline static constexpr std::string_view PRNG_DOMAIN =
        "KPI_P1_MP_SPDZ_PRNG_PRIVATE_STATE_V2\n";
    inline static constexpr std::string_view SETUP_DOMAIN =
        "KPI_P1_MP_SPDZ_OT_TRIPLE_SETUP_STATE_V2\n";
    inline static constexpr std::string_view BASE_DOMAIN =
        "KPI_P1_MP_SPDZ_BASE_OT_TRANSIENT_STATE_V2\n";
    inline static constexpr std::string_view MAP_DOMAIN =
        "KPI_P1_MP_SPDZ_ONDEMAND_OT_MAP_STATE_V2\n";

    static std::size_t add_size(
            std::size_t total, std::size_t addition) {
        return detail::checked_size_add(total, addition);
    }

    static constexpr std::size_t timer_encoded_size() {
        return TIMER_DOMAIN.size() + 5U * 8U;
    }

    static std::size_t prng_schedule_size(const PRNG& value) {
#ifdef USE_AES
#if defined(__AES__) || !defined(__x86_64__)
        return value.useC ? sizeof(value.KeyScheduleC) :
            sizeof(value.KeySchedule);
#else
        (void)value;
        return sizeof(value.KeyScheduleC);
#endif
#else
        (void)value;
        return 0U;
#endif
    }

    static std::size_t prng_encoded_size(
            const PRNG& value, RandomWindow random_window) {
        if (value.cnt < 0 || value.cnt > PRNG::RAND_SIZE ||
            value.n_cached_bits < 0 || value.n_cached_bits > 64 ||
            !value.initialized)
            throw std::runtime_error("P1-OnDemandOT-prng-cursor");
        std::size_t result = PRNG_DOMAIN.size();
        result = add_size(result, 4U * 8U);
        result = add_size(result, detail::encoded_bytes_size(SEED_SIZE));
        result = add_size(
            result, detail::encoded_bytes_size(PRNG::RAND_SIZE));
        result = add_size(result, 8U);
        result = add_size(
            result, detail::encoded_bytes_size(
                random_window == RandomWindow::Defined ?
                    PRNG::RAND_SIZE : 0U));
        result = add_size(result, 8U);
        result = add_size(
            result, detail::encoded_bytes_size(prng_schedule_size(value)));
        result = add_size(result, 4U * 8U);
        return add_size(result, timer_encoded_size());
    }

    static std::uint64_t logical_peer(
            const OTTripleSetup& setup, std::uint64_t index) {
        if (setup.nparties != 3 || setup.my_num < 0 ||
            setup.my_num >= setup.nparties ||
            index >= static_cast<std::uint64_t>(setup.nparties - 1))
            throw std::runtime_error("P1-OnDemandOT-peer-index");
        return index >= static_cast<std::uint64_t>(setup.my_num) ?
            index + 1 : index;
    }

    static void append_timer(
            std::vector<unsigned char>& output, const Timer& value) {
        if (value.startv.tv_nsec < 0 || value.startv.tv_nsec >= 1000000000L)
            throw std::runtime_error("P1-OnDemandOT-timer-nsec");
        detail::append_domain(output, TIMER_DOMAIN);
        detail::append_i64(output, value.startv.tv_sec);
        detail::append_i64(output, value.startv.tv_nsec);
        detail::append_u64(output, value.running ? 1U : 0U);
        detail::append_i64(output, value.elapsed_time);
        detail::append_i64(output, value.clock_id);
    }

    static detail::SecretBytes serialize_prng(
            const PRNG& value, RandomWindow random_window) {
        const auto required = prng_encoded_size(value, random_window);
        std::vector<unsigned char> output;
        detail::reserve_exact(output, required);
        detail::append_domain(output, PRNG_DOMAIN);
        detail::append_u64(output, SEED_SIZE);
        detail::append_u64(output, PRNG::RAND_SIZE);
        detail::append_u64(output, PIPELINES);
        detail::append_u64(output, CALL_SIZE);
        detail::append_bytes(output, std::span(
            reinterpret_cast<const unsigned char*>(value.seed), SEED_SIZE));
        detail::append_bytes(output, std::span(
            reinterpret_cast<const unsigned char*>(value.state),
            PRNG::RAND_SIZE));
        detail::append_u64(
            output, random_window == RandomWindow::Defined ? 1U : 0U);
        if (random_window == RandomWindow::Defined)
            detail::append_bytes(output, std::span(
                reinterpret_cast<const unsigned char*>(value.random),
                PRNG::RAND_SIZE));
        else
            detail::append_bytes(output, {});
#ifdef USE_AES
#if defined(__AES__) || !defined(__x86_64__)
        detail::append_u64(output, value.useC ? 1U : 2U);
        if (value.useC) {
            std::array<unsigned char, sizeof(value.KeyScheduleC)> schedule{};
            for (std::size_t index = 0;
                 index < std::size(value.KeyScheduleC); ++index) {
                const auto word = static_cast<std::uint32_t>(
                    value.KeyScheduleC[index]);
                for (unsigned shift = 0; shift < 4; ++shift)
                    schedule[index * 4U + shift] =
                        static_cast<unsigned char>(word >> (8U * shift));
            }
            detail::append_bytes(output, schedule);
        } else {
            detail::append_bytes(output, std::span(
                reinterpret_cast<const unsigned char*>(value.KeySchedule),
                sizeof(value.KeySchedule)));
        }
#else
        detail::append_u64(output, 1U);
        std::array<unsigned char, sizeof(value.KeyScheduleC)> schedule{};
        for (std::size_t index = 0;
             index < std::size(value.KeyScheduleC); ++index) {
            const auto word = static_cast<std::uint32_t>(
                value.KeyScheduleC[index]);
            for (unsigned shift = 0; shift < 4; ++shift)
                schedule[index * 4U + shift] =
                    static_cast<unsigned char>(word >> (8U * shift));
        }
        detail::append_bytes(output, schedule);
#endif
#else
        detail::append_u64(output, 3U);
        detail::append_bytes(output, {});
#endif
        detail::append_u64(output, static_cast<std::uint64_t>(value.cnt));
        detail::append_u64(
            output, static_cast<std::uint64_t>(value.n_cached_bits));
        detail::append_u64(
            output, static_cast<std::uint64_t>(value.cached_bits));
        detail::append_u64(output, value.initialized ? 1U : 0U);
        append_timer(output, value.timer);
        if (output.size() != required)
            throw std::runtime_error("P1-OnDemandOT-prng-size");
        return detail::SecretBytes(std::move(output));
    }

    static detail::SecretBytes serialize_setup(const OTTripleSetup& setup) {
        if (setup.nparties != 3 || setup.my_num < 0 ||
            setup.my_num >= setup.nparties || setup.source_player == nullptr ||
            setup.baseOTs.size() != 2 || setup.players.size() != 2 ||
            std::any_of(setup.baseOTs.begin(), setup.baseOTs.end(),
                        [](const auto* value) { return value == nullptr; }) ||
            std::any_of(setup.players.begin(), setup.players.end(),
                        [](const auto* value) { return value == nullptr; }) ||
            setup.baseSenderInputs.size() != 2 ||
            setup.baseReceiverOutputs.size() != 2 ||
            setup.base_receiver_inputs.size() != 128)
            throw std::runtime_error("P1-OnDemandOT-setup-shape");
        auto prng = serialize_prng(setup.G, RandomWindow::Defined);
        std::size_t required = SETUP_DOMAIN.size();
        required = add_size(required, 10U * 8U);
        for (const auto& [name, timer] : setup.timers) {
            (void)timer;
            required = add_size(
                required, detail::encoded_bytes_size(name.size()));
            required = add_size(required, timer_encoded_size());
        }
        required = add_size(
            required,
            detail::encoded_bit_vector_size(setup.base_receiver_inputs));
        required = add_size(required, 8U);
        for (std::size_t peer = 0;
             peer < setup.baseSenderInputs.size(); ++peer) {
            const auto& senders = setup.baseSenderInputs.at(peer);
            const auto& receivers = setup.baseReceiverOutputs.at(peer);
            if (senders.size() != 128 || receivers.size() != 128)
                throw std::runtime_error("P1-OnDemandOT-base-shape");
            required = add_size(required, 2U * 8U);
            for (std::size_t index = 0; index < senders.size(); ++index) {
                required = add_size(
                    required,
                    detail::encoded_bit_vector_size(senders[index][0]));
                required = add_size(
                    required,
                    detail::encoded_bit_vector_size(senders[index][1]));
                required = add_size(
                    required,
                    detail::encoded_bit_vector_size(receivers[index]));
            }
        }
        required = add_size(
            required, detail::encoded_bytes_size(prng.size()));
        std::vector<unsigned char> output;
        detail::reserve_exact(output, required);
        detail::append_domain(output, SETUP_DOMAIN);
        detail::append_u64(output, setup.nparties);
        detail::append_u64(output, setup.my_num);
        detail::append_u64(output, setup.source_player == nullptr ? 0U : 1U);
        detail::append_u64(output, setup.baseOTs.size());
        for (const auto* base : setup.baseOTs)
            detail::append_u64(output, base == nullptr ? 0U : 1U);
        detail::append_u64(output, setup.players.size());
        for (const auto* player : setup.players)
            detail::append_u64(output, player == nullptr ? 0U : 1U);
        detail::append_u64(output, setup.timers.size());
        for (const auto& [name, timer] : setup.timers) {
            detail::append_bytes(output, std::span(
                reinterpret_cast<const unsigned char*>(name.data()),
                name.size()));
            append_timer(output, timer);
        }
        detail::append_bit_vector(output, setup.base_receiver_inputs);
        detail::append_u64(output, setup.baseSenderInputs.size());
        for (std::size_t peer = 0;
             peer < setup.baseSenderInputs.size(); ++peer) {
            detail::append_u64(output, logical_peer(setup, peer));
            const auto& senders = setup.baseSenderInputs.at(peer);
            const auto& receivers = setup.baseReceiverOutputs.at(peer);
            detail::append_u64(output, senders.size());
            for (std::size_t index = 0; index < senders.size(); ++index) {
                detail::append_bit_vector(output, senders[index][0]);
                detail::append_bit_vector(output, senders[index][1]);
                detail::append_bit_vector(output, receivers[index]);
            }
        }
        detail::append_bytes(output, prng.view());
        if (output.size() != required)
            throw std::runtime_error("P1-OnDemandOT-setup-size");
        return detail::SecretBytes(std::move(output));
    }

    static detail::SecretBytes serialize_base(const BaseOT& value) {
        if (value.P != nullptr || value.nOT != 128 ||
            value.ot_role != BOTH || value.receiver_inputs.size() != 128 ||
            value.sender_inputs.size() != 128 ||
            value.receiver_outputs.size() != 128 ||
            value.G_sender.size() != 128 || value.G_receiver.size() != 128)
            throw std::runtime_error("P1-OnDemandOT-returned-base-shape");
        std::size_t required = BASE_DOMAIN.size();
        required = add_size(required, 3U * 8U);
        required = add_size(
            required,
            detail::encoded_bit_vector_size(value.receiver_inputs));
        for (std::size_t index = 0; index < value.sender_inputs.size();
             ++index) {
            required = add_size(
                required,
                detail::encoded_bit_vector_size(
                    value.sender_inputs[index][0]));
            required = add_size(
                required,
                detail::encoded_bit_vector_size(
                    value.sender_inputs[index][1]));
            required = add_size(
                required,
                detail::encoded_bit_vector_size(
                    value.receiver_outputs[index]));
            for (const auto size : {
                     prng_encoded_size(
                         value.G_sender[index][0], RandomWindow::Defined),
                     prng_encoded_size(
                         value.G_sender[index][1], RandomWindow::Defined),
                     prng_encoded_size(
                         value.G_receiver[index], RandomWindow::Defined)})
                required = add_size(
                    required, detail::encoded_bytes_size(size));
        }
        std::vector<unsigned char> output;
        // All 384 nested PRNG lengths are included in the checked exact size.
        // Every append refuses before growth, so no freed allocation can retain
        // a stale secret copy.
        detail::reserve_exact(output, required);
        detail::append_domain(output, BASE_DOMAIN);
        detail::append_u64(output, value.P == nullptr ? 0U : 1U);
        detail::append_u64(output, value.nOT);
        detail::append_u64(output, static_cast<unsigned>(value.ot_role));
        detail::append_bit_vector(output, value.receiver_inputs);
        for (std::size_t index = 0; index < value.sender_inputs.size();
             ++index) {
            detail::append_bit_vector(output, value.sender_inputs[index][0]);
            detail::append_bit_vector(output, value.sender_inputs[index][1]);
            detail::append_bit_vector(output, value.receiver_outputs[index]);
            auto sender_zero = serialize_prng(
                value.G_sender[index][0], RandomWindow::Defined);
            auto sender_one = serialize_prng(
                value.G_sender[index][1], RandomWindow::Defined);
            auto receiver = serialize_prng(
                value.G_receiver[index], RandomWindow::Defined);
            detail::append_bytes(output, sender_zero.view());
            detail::append_bytes(output, sender_one.view());
            detail::append_bytes(output, receiver.view());
        }
        if (output.size() != required)
            throw std::runtime_error("P1-OnDemandOT-base-size");
        return detail::SecretBytes(std::move(output));
    }

    static detail::SecretBytes serialize_map(
            const OnDemandOTTripleSetup& map,
            std::span<const unsigned char> exact_setup) {
        if (map.setups.size() != 1)
            throw std::runtime_error("P1-OnDemandOT-map-cardinality");
        const auto& entry = *map.setups.begin();
        if (entry.first == nullptr || entry.second == nullptr ||
            entry.second->source_player != entry.first)
            throw std::runtime_error("P1-OnDemandOT-map-correspondence");
        auto required = add_size(MAP_DOMAIN.size(), 2U * 8U);
        required = add_size(
            required, detail::encoded_bytes_size(exact_setup.size()));
        std::vector<unsigned char> output;
        detail::reserve_exact(output, required);
        detail::append_domain(output, MAP_DOMAIN);
        detail::append_u64(output, map.setups.size());
        // Deliberately encode only the single logical entry ordinal. The raw
        // pointer key is process-local correspondence, never authority.
        detail::append_u64(output, 0);
        detail::append_bytes(output, exact_setup);
        if (output.size() != required)
            throw std::runtime_error("P1-OnDemandOT-map-size");
        return detail::SecretBytes(std::move(output));
    }

    static void serialization_abort(const void* source_player) noexcept {
        state::OnDemandOtStateSourceBridge::
            source_serialization_abort_noexcept(source_player);
    }

public:
    static bool capture_required(const Player& player) noexcept {
        return state::OnDemandOtStateSourceBridge::capture_required_noexcept(
            &player, static_cast<std::uint64_t>(player.my_num()),
            static_cast<std::uint64_t>(player.num_players()));
    }

    static bool capture_required_pointer(const Player* player) noexcept {
        return state::OnDemandOtStateSourceBridge::
            capture_required_pointer_noexcept(player);
    }

    static void map_lookup(
            const OnDemandOTTripleSetup& map, Player& player) noexcept {
        if (!capture_required(player)) return;
        try {
            const auto found = map.setups.find(&player);
            if (found == map.setups.end()) {
                (void)state::OnDemandOtStateSourceBridge::map_lookup(
                    &player, map.setups.size(), false, {});
            } else {
                auto snapshot = serialize_setup(*found->second);
                (void)state::OnDemandOtStateSourceBridge::map_lookup(
                    &player, map.setups.size(), true, snapshot.view());
            }
        } catch (...) {
            serialization_abort(&player);
        }
    }

    static void map_entry_create_begin(Player& player) noexcept {
        if (capture_required(player))
            (void)state::OnDemandOtStateSourceBridge::
                map_entry_create_begin(&player);
    }

    static void prng_before_choices(OTTripleSetup& setup) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            auto snapshot = serialize_prng(
                setup.G, RandomWindow::UndefinedAfterInitSeed);
            (void)state::OnDemandOtStateSourceBridge::
                prng_before_choice_consume(
                    setup.source_player, snapshot.view());
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void prng_after_choices(OTTripleSetup& setup) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            auto snapshot = serialize_prng(setup.G, RandomWindow::Defined);
            (void)state::OnDemandOtStateSourceBridge::
                prng_after_choice_consume(
                    setup.source_player, snapshot.view());
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void worker_begin(
            OTTripleSetup& setup, std::uint64_t index) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            const auto peer = logical_peer(setup, index);
            (void)state::OnDemandOtStateSourceBridge::ot_setup_worker_begin(
                setup.source_player, index, peer);
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void worker_end(
            OTTripleSetup& setup, std::uint64_t index,
            bool succeeded) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            const auto peer = logical_peer(setup, index);
            (void)state::OnDemandOtStateSourceBridge::ot_setup_worker_end(
                setup.source_player, index, peer, succeeded);
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void setup_root_abort(OTTripleSetup& setup) noexcept {
        if (setup.source_player &&
            capture_required_pointer(setup.source_player))
            state::OnDemandOtStateSourceBridge::setup_root_abort_noexcept(
                setup.source_player);
    }

    static void map_entry_created(
            const OnDemandOTTripleSetup& map, Player& player) noexcept {
        if (!capture_required(player)) return;
        try {
            const auto found = map.setups.find(&player);
            if (found == map.setups.end())
                throw std::runtime_error("P1-OnDemandOT-entry-absent");
            auto snapshot = serialize_setup(*found->second);
            (void)state::OnDemandOtStateSourceBridge::map_entry_created(
                &player, map.setups.size(), snapshot.view());
        } catch (...) {
            serialization_abort(&player);
        }
    }

    static void get_fresh_begin(const OTTripleSetup& setup) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            auto snapshot = serialize_setup(setup);
            (void)state::OnDemandOtStateSourceBridge::get_fresh_begin(
                setup.source_player, snapshot.view());
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void get_base_before(
            const OTTripleSetup& setup, std::uint64_t index) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            auto snapshot = serialize_setup(setup);
            (void)state::OnDemandOtStateSourceBridge::ot_extend_before(
                setup.source_player, index, logical_peer(setup, index),
                snapshot.view());
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void seeded_initial_advance(
            const OTTripleSetup& setup, std::uint64_t index,
            const BaseOT& base) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            auto snapshot = serialize_base(base);
            (void)state::OnDemandOtStateSourceBridge::
                ot_seeded_initial_advance(
                    setup.source_player, index,
                    logical_peer(setup, index), snapshot.view());
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void stored_advance(
            const OTTripleSetup& setup, std::uint64_t index,
            const BaseOT& base) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            auto stored = serialize_setup(setup);
            auto transient = serialize_base(base);
            (void)state::OnDemandOtStateSourceBridge::
                ot_extend_stored_advance(
                    setup.source_player, index,
                    logical_peer(setup, index), stored.view(),
                    transient.view());
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void returned_advance(
            const OTTripleSetup& setup, std::uint64_t index,
            const BaseOT& base) noexcept {
        if (!setup.source_player ||
            !capture_required_pointer(setup.source_player))
            return;
        try {
            auto snapshot = serialize_base(base);
            (void)state::OnDemandOtStateSourceBridge::
                ot_extend_returned_advance(
                    setup.source_player, index,
                    logical_peer(setup, index), snapshot.view());
        } catch (...) {
            serialization_abort(setup.source_player);
        }
    }

    static void get_fresh_end(
            const OnDemandOTTripleSetup& map, Player& player,
            const OTTripleSetup& returned) noexcept {
        if (!capture_required(player)) return;
        try {
            const auto found = map.setups.find(&player);
            if (found == map.setups.end())
                throw std::runtime_error("P1-OnDemandOT-entry-absent");
            auto stored = serialize_setup(*found->second);
            auto result = serialize_setup(returned);
            (void)state::OnDemandOtStateSourceBridge::get_fresh_end(
                &player, map.setups.size(), stored.view(), result.view());
        } catch (...) {
            serialization_abort(&player);
        }
    }

    static Player* map_destructor_begin(
            const OnDemandOTTripleSetup& map) noexcept {
        if (map.setups.empty()) {
            state::OnDemandOtStateSourceBridge::
                empty_map_destructor_noexcept();
            return nullptr;
        }
        auto* player = map.setups.begin()->first;
        if (!capture_required_pointer(player)) return player;
        try {
            auto entry = serialize_setup(*map.setups.begin()->second);
            auto snapshot = serialize_map(map, entry.view());
            (void)state::OnDemandOtStateSourceBridge::map_destructor_begin(
                player, map.setups.size(), snapshot.view(), entry.view());
        } catch (...) {
            serialization_abort(player);
        }
        return player;
    }

    static void map_destructor_terminal(
            Player* player, const OnDemandOTTripleSetup& map) noexcept {
        if (!player || !capture_required_pointer(player)) return;
        (void)state::OnDemandOtStateSourceBridge::map_destructor_terminal(
            player, map.setups.size());
    }

#ifdef KPI_P1_ONDEMAND_OT_SOURCE_CAPTURE_TEST_SETUP
    static bool test_only_underreserve_refuses_without_growth() {
        std::vector<unsigned char> output;
        output.reserve(7U);
        const auto* const before_data = output.data();
        const auto before_capacity = output.capacity();
        try {
            detail::append_u64(output, 1U);
        } catch (const std::runtime_error&) {
            return output.empty() && output.data() == before_data &&
                output.capacity() == before_capacity;
        }
        return false;
    }

    static detail::SecretBytes test_only_fixture_setup(
            OTTripleSetup& setup, const void* source_player,
            std::uint64_t local_role) {
        setup.source_player = reinterpret_cast<Player*>(
            const_cast<void*>(source_player));
        setup.nparties = 3;
        setup.my_num = static_cast<int>(local_role);
        setup.base_receiver_inputs.resize(128);
        setup.baseOTs.resize(2, reinterpret_cast<BaseOT*>(1));
        setup.players.resize(2, reinterpret_cast<TwoPartyPlayer*>(1));
        setup.baseSenderInputs.resize(2);
        setup.baseReceiverOutputs.resize(2);
        std::array<unsigned char, SEED_SIZE> seed{};
        for (std::size_t index = 0; index < seed.size(); ++index)
            seed[index] = static_cast<unsigned char>(index + 1U);
        setup.G.SetSeed(seed.data());
        for (std::size_t index = 0; index < 128; ++index)
            setup.base_receiver_inputs.set_bit(
                index, (setup.G.get_uchar() & 1U) != 0);
        for (std::size_t peer = 0; peer < 2; ++peer) {
            setup.baseSenderInputs[peer].resize(128);
            setup.baseReceiverOutputs[peer].resize(128);
            for (std::size_t index = 0; index < 128; ++index) {
                for (std::size_t side = 0; side < 2; ++side) {
                    setup.baseSenderInputs[peer][index][side].resize(128);
                    for (std::size_t byte = 0; byte < 16; ++byte)
                        setup.baseSenderInputs[peer][index][side].set_byte(
                            byte, static_cast<unsigned char>(
                                peer * 17U + index + side + byte + 1U));
                }
                setup.baseReceiverOutputs[peer][index].resize(128);
                for (std::size_t byte = 0; byte < 16; ++byte)
                    setup.baseReceiverOutputs[peer][index].set_byte(
                        byte, static_cast<unsigned char>(
                            peer * 29U + index + byte + 1U));
            }
        }
        return serialize_setup(setup);
    }

    static detail::SecretBytes test_only_prng_before() {
        PRNG value;
        std::array<unsigned char, SEED_SIZE> seed{};
        for (std::size_t index = 0; index < seed.size(); ++index)
            seed[index] = static_cast<unsigned char>(0xa0U + index);
        value.SetSeed(seed.data());
        return serialize_prng(
            value, RandomWindow::UndefinedAfterInitSeed);
    }

    static detail::SecretBytes test_only_prng_after(
            const OTTripleSetup& setup) {
        return serialize_prng(setup.G, RandomWindow::Defined);
    }

    static BaseOT test_only_seeded_base(
            const OTTripleSetup& setup, std::uint64_t peer_index) {
        BaseOT result(128, nullptr);
        result.receiver_inputs = setup.base_receiver_inputs;
        result.sender_inputs = setup.baseSenderInputs.at(peer_index);
        result.receiver_outputs = setup.baseReceiverOutputs.at(peer_index);
        result.set_seeds();
        return result;
    }

    static detail::SecretBytes test_only_base(const BaseOT& value) {
        return serialize_base(value);
    }

    static detail::SecretBytes test_only_setup(const OTTripleSetup& setup) {
        return serialize_setup(setup);
    }
#endif
};

} // namespace kpb_mp_spdz_p1_ondemand_ot
