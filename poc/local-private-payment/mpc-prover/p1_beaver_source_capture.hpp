#pragma once

// Field-wise source bridge for the pinned Beaver/BufferPrep/MascotPrep
// callsites.  The bridge is inert unless the private capsule adapter has
// installed a source scope.  A selected source callsite must abort if a
// required record is rejected; silently continuing would create an incomplete
// corrupt-P1 view.

#include "p1_beaver_state_hook.hpp"

#include "Math/gfp.h"
#include "Protocols/Share.h"
#include "Tools/octetStream.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kpi::mpc::p1_private_state {

enum class BeaverRetainResult : std::uint8_t {
    NotRequired = 1,
    Retained = 2,
    Failed = 3,
};

namespace beaver_source_detail {

inline constexpr std::size_t MAX_SOURCE_STATE_BYTES =
    512U * 1024U * 1024U;

class SecretBytes final {
    std::vector<unsigned char> value_;

public:
    explicit SecretBytes(std::vector<unsigned char> value)
        : value_(std::move(value)) {}
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept
        : value_(std::move(other.value_)) {}
    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            wipe();
            value_ = std::move(other.value_);
        }
        return *this;
    }
    ~SecretBytes() { wipe(); }
    std::span<const unsigned char> view() const noexcept { return value_; }

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
    void test_only_wipe() noexcept { wipe(); }
#endif

private:
    void wipe() noexcept {
        volatile unsigned char* cursor = value_.data();
        for (std::size_t index = 0; index < value_.size(); ++index)
            cursor[index] = 0;
        value_.clear();
    }
};

inline void append_u64(
        std::vector<unsigned char>& output, std::uint64_t value) {
    if (output.size() > MAX_SOURCE_STATE_BYTES - 8U)
        throw std::runtime_error("P1-Beaver-source-size");
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

inline void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    if (value.size() > MAX_SOURCE_STATE_BYTES ||
        output.size() > MAX_SOURCE_STATE_BYTES - 8U ||
        value.size() > MAX_SOURCE_STATE_BYTES - output.size() - 8U)
        throw std::runtime_error("P1-Beaver-source-size");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

inline void append_domain(
        std::vector<unsigned char>& output, std::string_view domain) {
    if (domain.size() > MAX_SOURCE_STATE_BYTES - output.size())
        throw std::runtime_error("P1-Beaver-source-domain-size");
    output.insert(output.end(), domain.begin(), domain.end());
}

template<class Value>
void append_native_pack(
        std::vector<unsigned char>& output, const Value& value) {
    octetStream packed;
    value.pack(packed);
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(packed.get_data()),
        packed.get_length()));
    if (packed.get_length())
        std::fill_n(
            reinterpret_cast<volatile unsigned char*>(packed.get_data()),
            packed.get_length(), static_cast<unsigned char>(0));
}

template<class T>
void append_share(
        std::vector<unsigned char>& output, const T& value) {
    append_native_pack(output, value.get_share());
    append_native_pack(output, value.get_mac());
}

template<class T>
SecretBytes encode_share_pair(
        std::string_view domain, const T& first, const T& second) {
    std::vector<unsigned char> output;
    append_domain(output, domain);
    append_share(output, first);
    append_share(output, second);
    return SecretBytes(std::move(output));
}

template<class T>
SecretBytes encode_triple(
        std::string_view domain, const std::array<T, 3>& triple) {
    std::vector<unsigned char> output;
    append_domain(output, domain);
    for (const auto& value : triple) append_share(output, value);
    return SecretBytes(std::move(output));
}

template<class T>
SecretBytes encode_cache_batch(
        std::span<const std::array<T, 3>> triples) {
    static constexpr std::string_view domain =
        "KPI_P1_BEAVER_CACHE_BATCH_NATIVE_V1\n";
    std::vector<unsigned char> output;
    append_domain(output, domain);
    append_u64(output, triples.size());
    for (const auto& triple : triples)
        for (const auto& value : triple) append_share(output, value);
    return SecretBytes(std::move(output));
}

template<class T>
SecretBytes encode_triple_and_masks(
        const std::array<T, 3>& triple,
        const T& masked_left, const T& masked_right) {
    static constexpr std::string_view domain =
        "KPI_P1_BEAVER_TRIPLE_AND_MASKS_NATIVE_V1\n";
    std::vector<unsigned char> output;
    append_domain(output, domain);
    for (const auto& value : triple) append_share(output, value);
    append_share(output, masked_left);
    append_share(output, masked_right);
    return SecretBytes(std::move(output));
}

template<class T>
SecretBytes encode_opened_result(
        const typename T::open_type& epsilon,
        const typename T::open_type& delta,
        const std::array<T, 3>& mutated_triple,
        const T& result) {
    static constexpr std::string_view domain =
        "KPI_P1_BEAVER_OPENED_RESULT_NATIVE_V1\n";
    std::vector<unsigned char> output;
    append_domain(output, domain);
    append_native_pack(output, epsilon);
    append_native_pack(output, delta);
    for (const auto& value : mutated_triple) append_share(output, value);
    append_share(output, result);
    return SecretBytes(std::move(output));
}

} // namespace beaver_source_detail

class BeaverStateSourceBridge final {
    BeaverStateSourceBridge() = delete;
    using SelectedShare = Share<gfp_<0, 4>>;

    static bool capture_required_noexcept() noexcept;
    static BeaverRetainResult serialization_failure_noexcept() noexcept;
    static BeaverRetainResult cache_batch_raw_noexcept(
        const void* cache_object, std::uint64_t size_before,
        std::uint64_t size_after,
        std::span<const unsigned char> source_state) noexcept;
    static BeaverRetainResult cache_pop_raw_noexcept(
        const void* cache_object, std::uint64_t size_before,
        std::uint64_t size_after,
        std::span<const unsigned char> source_state,
        std::span<const unsigned char> triple_identity) noexcept;
    static BeaverRetainResult init_raw_noexcept(
        const void* beaver_object) noexcept;
    static BeaverRetainResult prepare_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state) noexcept;
    static BeaverRetainResult triple_mask_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state,
        std::span<const unsigned char> triple_identity) noexcept;
    static BeaverRetainResult opened_result_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state) noexcept;
    static BeaverRetainResult finalize_return_raw_noexcept(
        const void* beaver_object,
        std::span<const unsigned char> source_state) noexcept;

    template<class Callable>
    static BeaverRetainResult capture_encoded(Callable&& callable) noexcept {
        if (!capture_required_noexcept())
            return BeaverRetainResult::NotRequired;
        try {
            return callable();
        }
        catch (...) {
            return serialization_failure_noexcept();
        }
    }

public:
    static void require_recorded(BeaverRetainResult result) noexcept {
        if (result == BeaverRetainResult::Failed) std::abort();
    }

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
    static BeaverRetainResult test_only_cache_batch(
            const void* object, std::uint64_t before,
            std::uint64_t after,
            std::span<const unsigned char> state) noexcept {
        return cache_batch_raw_noexcept(object, before, after, state);
    }
    static BeaverRetainResult test_only_cache_pop(
            const void* object, std::uint64_t before,
            std::uint64_t after,
            std::span<const unsigned char> state,
            std::span<const unsigned char> triple_identity) noexcept {
        return cache_pop_raw_noexcept(
            object, before, after, state, triple_identity);
    }
    static BeaverRetainResult test_only_init(const void* object) noexcept {
        return init_raw_noexcept(object);
    }
    static BeaverRetainResult test_only_prepare(
            const void* object,
            std::span<const unsigned char> state) noexcept {
        return prepare_raw_noexcept(object, state);
    }
    static BeaverRetainResult test_only_triple_mask(
            const void* object,
            std::span<const unsigned char> state,
            std::span<const unsigned char> triple_identity) noexcept {
        return triple_mask_raw_noexcept(
            object, state, triple_identity);
    }
    static BeaverRetainResult test_only_opened_result(
            const void* object,
            std::span<const unsigned char> state) noexcept {
        return opened_result_raw_noexcept(object, state);
    }
    static BeaverRetainResult test_only_finalize_return(
            const void* object,
            std::span<const unsigned char> state) noexcept {
        return finalize_return_raw_noexcept(object, state);
    }
    static BeaverRetainResult test_only_serialization_failure() noexcept {
        return serialization_failure_noexcept();
    }
#endif

    template<class T>
    static BeaverRetainResult cache_batch_generated(
            const void* cache_object,
            std::span<const std::array<T, 3>> generated,
            std::uint64_t size_before,
            std::uint64_t size_after) noexcept {
        if constexpr (!std::is_same_v<T, SelectedShare>) {
            return BeaverRetainResult::NotRequired;
        } else {
            return capture_encoded([&] {
                auto bytes = beaver_source_detail::encode_cache_batch(
                    generated);
                return cache_batch_raw_noexcept(
                    cache_object, size_before, size_after, bytes.view());
            });
        }
    }

    template<class T>
    static BeaverRetainResult cache_triple_pop(
            const void* cache_object,
            const std::array<T, 3>& triple,
            std::uint64_t size_before,
            std::uint64_t size_after) noexcept {
        if constexpr (!std::is_same_v<T, SelectedShare>) {
            return BeaverRetainResult::NotRequired;
        } else {
            return capture_encoded([&] {
                auto bytes = beaver_source_detail::encode_triple(
                    "KPI_P1_BEAVER_TRIPLE_IDENTITY_NATIVE_V1\n", triple);
                return cache_pop_raw_noexcept(
                    cache_object, size_before, size_after, bytes.view(),
                    bytes.view());
            });
        }
    }

    template<class T>
    static BeaverRetainResult init_mul(
            const void* beaver_object) noexcept {
        if constexpr (!std::is_same_v<T, SelectedShare>)
            return BeaverRetainResult::NotRequired;
        else
            return capture_required_noexcept() ?
                init_raw_noexcept(beaver_object) :
                BeaverRetainResult::NotRequired;
    }

    template<class T>
    static BeaverRetainResult prepare_mul(
            const void* beaver_object, const T& left,
            const T& right) noexcept {
        if constexpr (!std::is_same_v<T, SelectedShare>) {
            return BeaverRetainResult::NotRequired;
        } else {
            return capture_encoded([&] {
                auto bytes = beaver_source_detail::encode_share_pair(
                    "KPI_P1_BEAVER_MULTIPLICANDS_NATIVE_V1\n", left,
                    right);
                return prepare_raw_noexcept(beaver_object, bytes.view());
            });
        }
    }

    template<class T>
    static BeaverRetainResult triple_and_masks(
            const void* beaver_object,
            const std::array<T, 3>& triple,
            const T& masked_left, const T& masked_right) noexcept {
        if constexpr (!std::is_same_v<T, SelectedShare>) {
            return BeaverRetainResult::NotRequired;
        } else {
            return capture_encoded([&] {
                auto bytes = beaver_source_detail::encode_triple_and_masks(
                    triple, masked_left, masked_right);
                auto identity = beaver_source_detail::encode_triple(
                    "KPI_P1_BEAVER_TRIPLE_IDENTITY_NATIVE_V1\n", triple);
                return triple_mask_raw_noexcept(
                    beaver_object, bytes.view(), identity.view());
            });
        }
    }

    template<class T>
    static BeaverRetainResult opened_result(
            const void* beaver_object,
            const typename T::open_type& epsilon,
            const typename T::open_type& delta,
            const std::array<T, 3>& mutated_triple,
            const T& result) noexcept {
        if constexpr (!std::is_same_v<T, SelectedShare>) {
            return BeaverRetainResult::NotRequired;
        } else {
            return capture_encoded([&] {
                auto bytes = beaver_source_detail::encode_opened_result<T>(
                    epsilon, delta, mutated_triple, result);
                return opened_result_raw_noexcept(
                    beaver_object, bytes.view());
            });
        }
    }

    template<class T>
    static BeaverRetainResult finalize_return(
            const void* beaver_object, const T& result) noexcept {
        if constexpr (!std::is_same_v<T, SelectedShare>) {
            return BeaverRetainResult::NotRequired;
        } else {
            return capture_encoded([&] {
                std::vector<unsigned char> output;
                beaver_source_detail::append_domain(
                    output, "KPI_P1_BEAVER_FINAL_RETURN_NATIVE_V1\n");
                beaver_source_detail::append_share(output, result);
                beaver_source_detail::SecretBytes bytes(std::move(output));
                return finalize_return_raw_noexcept(
                    beaver_object, bytes.view());
            });
        }
    }
};

} // namespace kpi::mpc::p1_private_state
