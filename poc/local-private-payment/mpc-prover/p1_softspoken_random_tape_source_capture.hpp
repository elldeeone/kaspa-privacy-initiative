#pragma once

// Field-wise source packer for the exact pinned cryptoTools/libOTe malicious
// SoftSpokenOT path. Encoding is two-pass: the first pass computes a checked
// exact size, the second reserves once before writing any secret byte. Object
// memory, padding, allocator metadata, vtables, function pointers, sockets,
// native thread identifiers, and source Player addresses are never encoded.

#include "p1_softspoken_random_tape_state_hook.hpp"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <algorithm>
#include <array>
#include <concepts>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kpb_libote_p1_softspoken {
namespace state = kpi::mpc::p1_private_state;

namespace detail {

inline constexpr std::size_t MAX_SOURCE_STATE_BYTES =
    64U * 1024U * 1024U;

inline std::size_t checked_add(std::size_t left, std::size_t right) {
    if (left > MAX_SOURCE_STATE_BYTES ||
        right > MAX_SOURCE_STATE_BYTES - left)
        throw std::runtime_error("P1-SoftSpoken-source-size");
    return left + right;
}

inline void cleanse_bytes(
        unsigned char* data, std::size_t size) noexcept {
    volatile unsigned char* cursor = data;
    for (std::size_t index = 0; index < size; ++index)
        cursor[index] = 0;
}

inline void cleanse(std::vector<unsigned char>& value) noexcept {
    cleanse_bytes(value.data(), value.size());
    value.clear();
}

class SecretBytes final {
    std::vector<unsigned char> value_;
public:
    SecretBytes() = default;
    explicit SecretBytes(std::vector<unsigned char> value) {
        if (value.size() > MAX_SOURCE_STATE_BYTES)
            throw std::runtime_error("P1-SoftSpoken-source-size");
        value_.swap(value);
    }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept { value_.swap(other.value_); }
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
#ifdef KPI_P1_SOFTSPOKEN_RANDOM_TAPE_SOURCE_CAPTURE_TEST_SETUP
    const std::vector<unsigned char>& test_only_bytes() const noexcept {
        return value_;
    }
#endif
};

struct SizeSink final {
    std::size_t size{};
    void raw(std::size_t count) { size = checked_add(size, count); }
    void u64(std::uint64_t) { raw(8U); }
    void bytes(std::span<const unsigned char> value) {
        u64(value.size());
        raw(value.size());
    }
    void domain(std::string_view value) { raw(value.size()); }
};

struct ByteSink final {
    std::vector<unsigned char>& output;

    void require(std::size_t count) const {
        if (count > output.capacity() - output.size())
            throw std::runtime_error("P1-SoftSpoken-source-capacity");
    }
    void raw(std::span<const unsigned char> value) {
        require(value.size());
        output.insert(output.end(), value.begin(), value.end());
    }
    void u64(std::uint64_t value) {
        require(8U);
        for (int shift = 56; shift >= 0; shift -= 8)
            output.push_back(static_cast<unsigned char>(value >> shift));
    }
    void bytes(std::span<const unsigned char> value) {
        require(checked_add(8U, value.size()));
        u64(value.size());
        raw(value);
    }
    void domain(std::string_view value) {
        raw(std::span(
            reinterpret_cast<const unsigned char*>(value.data()),
            value.size()));
    }
};

template<class Encode>
SecretBytes encode_exact(Encode&& encode) {
    SizeSink sizing;
    encode(sizing);
    std::vector<unsigned char> output;
    output.reserve(sizing.size);
    if (output.capacity() < sizing.size)
        throw std::runtime_error("P1-SoftSpoken-source-reserve");
    ByteSink writing{output};
    encode(writing);
    if (output.size() != sizing.size)
        throw std::runtime_error("P1-SoftSpoken-source-size-mismatch");
    return SecretBytes(std::move(output));
}

} // namespace detail

// This is the sole friend added to AESRekeyManager by the pinned patch. All
// other source fields used here are already public in the pinned closure.
class SourceAccess final {
    SourceAccess() = delete;

    inline static constexpr std::string_view PRNG_DOMAIN =
        "KPI_P1_CRYPTOTOOLS_PRNG_STATE_V1\n";
    inline static constexpr std::string_view BASE_DOMAIN =
        "KPI_P1_SOFTSPOKEN_BASE_MATERIAL_V1\n";
    inline static constexpr std::string_view SENDER_DOMAIN =
        "KPI_P1_SOFTSPOKEN_MAL_SENDER_STATE_V1\n";
    inline static constexpr std::string_view RECEIVER_DOMAIN =
        "KPI_P1_SOFTSPOKEN_MAL_RECEIVER_STATE_V1\n";
    inline static constexpr std::string_view RTCR_DOMAIN =
        "KPI_P1_SOFTSPOKEN_RTCR_STATE_V1\n";
    inline static constexpr std::string_view CHECK_DOMAIN =
        "KPI_P1_SOFTSPOKEN_CHECK_TRANSIENT_V1\n";
    inline static constexpr std::string_view OUTPUT_DOMAIN =
        "KPI_P1_SOFTSPOKEN_OUTPUT_STATE_V1\n";
    inline static constexpr std::string_view SEED_DOMAIN =
        "KPI_P1_SOFTSPOKEN_SEED_V1\n";

    template<class Sink>
    static void pack_block(Sink& sink, const osuCrypto::block& value) {
        const auto words = value.template get<std::uint64_t>();
        sink.u64(words[0]);
        sink.u64(words[1]);
    }

    template<class Sink>
    static void pack_aes(Sink& sink, const osuCrypto::AES& value) {
        sink.u64(value.mRoundKey.size());
        for (const auto& key : value.mRoundKey) pack_block(sink, key);
    }

    template<class Sink, class Range>
    static void pack_blocks(Sink& sink, const Range& values) {
        sink.u64(values.size());
        for (const auto& value : values) pack_block(sink, value);
    }

    template<class Sink>
    static void pack_bit_vector(
            Sink& sink, const osuCrypto::BitVector& value) {
        sink.u64(value.size());
        sink.bytes(std::span(
            reinterpret_cast<const unsigned char*>(value.data()),
            static_cast<std::size_t>(value.sizeBytes())));
    }

    template<class Sink>
    static void pack_prng(Sink& sink, const osuCrypto::PRNG& value) {
        sink.domain(PRNG_DOMAIN);
        pack_blocks(sink, value.mBuffer);
        pack_aes(sink, value.mAes);
        sink.u64(value.mBytesIdx);
        sink.u64(value.mBlockIdx);
        sink.u64(value.mBufferByteCapacity);
    }

    template<class Sink, class Manager>
    static void pack_aes_manager(Sink& sink, const Manager& value) {
        sink.u64(value.mAesKeyUseCount);
        sink.u64(value.mAESs.mIndex);
        pack_aes(sink, value.mAESs.mPrng);
        sink.u64(value.mAESs.mAesRoundKeys.mAESs.size());
        for (const auto& aes : value.mAESs.mAesRoundKeys.mAESs)
            pack_aes(sink, aes);
    }

    template<class Sink, class Element>
    static void pack_element(Sink& sink, const Element& value) {
        using T = std::remove_cvref_t<Element>;
        if constexpr (std::same_as<T, osuCrypto::block>) {
            pack_block(sink, value);
        } else if constexpr (std::same_as<T, std::array<osuCrypto::block, 2>>) {
            pack_block(sink, value[0]);
            pack_block(sink, value[1]);
        } else if constexpr (std::integral<T>) {
            sink.u64(static_cast<std::uint64_t>(value));
        } else {
            static_assert(sizeof(T) == 0, "unsupported SoftSpoken element");
        }
    }

    template<class Sink, class Matrix>
    static void pack_matrix(Sink& sink, const Matrix& value) {
        sink.u64(value.rows());
        sink.u64(value.cols());
        sink.u64(value.size());
        for (const auto& element : value) pack_element(sink, element);
    }

    template<class Sink, class Pprf>
    static void pack_pprf(Sink& sink, const Pprf& value) {
        sink.u64(value.mDomain);
        sink.u64(value.mDepth);
        sink.u64(value.mPntCount);
        sink.u64(value.mEagerSend);
        sink.u64(static_cast<bool>(value.mOutputFn));
        pack_matrix(sink, value.mBaseOTs);
        pack_blocks(sink, value.mTempBuffer);
        if constexpr (requires { value.mValue; }) {
            pack_blocks(sink, value.mValue);
        } else {
            pack_matrix(sink, value.mBaseChoices);
        }
    }

    template<class Sink, class Vole>
    static void pack_small_vole(Sink& sink, const Vole& value) {
        sink.u64(value.mFieldBits);
        sink.u64(value.mNumVoles);
        sink.u64(value.mNumVolesPadded);
        sink.u64(value.mMalicious);
        sink.u64(value.mInit);
        pack_blocks(sink, value.mSeeds);
        sink.u64(static_cast<bool>(value.mPprf));
        if (value.mPprf) pack_pprf(sink, *value.mPprf);
        if constexpr (requires { value.mDelta; }) {
            pack_bit_vector(sink, value.mDelta);
            sink.bytes(std::span(
                reinterpret_cast<const unsigned char*>(
                    value.mDeltaUnpacked.data()),
                static_cast<std::size_t>(value.mDeltaUnpacked.size())));
        }
    }

    template<class Sink, class Subspace>
    static void pack_subspace(Sink& sink, const Subspace& value) {
        sink.u64(value.code().dimension());
        sink.u64(value.code().length());
        sink.u64(value.code().codimension());
        pack_small_vole(sink, value.mVole);
        pack_blocks(sink, value.mMessages);
        if constexpr (requires { value.mCorrectionU; value.mReadIndex; }) {
            pack_blocks(sink, value.mCorrectionU);
            sink.u64(value.mReadIndex);
        }
        pack_prng(sink, value.hashKeyPrng);
        pack_block(sink, value.hashKeySqAndA64);
        sink.u64(value.hashKey);
        sink.u64(value.hashKeyUseCount);
        if constexpr (requires { value.mHashW; }) {
            pack_blocks(sink, value.mHashW);
            pack_blocks(sink, value.mSubtotalW);
        } else {
            pack_blocks(sink, value.hashU);
            pack_blocks(sink, value.subtotalU);
            pack_blocks(sink, value.hashV);
            pack_blocks(sink, value.subtotalV);
        }
    }

    template<class Sink, class Base>
    static void pack_soft_base(Sink& sink, const Base& value) {
        pack_subspace(sink, value.mSubVole);
        sink.u64(value.mBlockIdx);
        sink.u64(value.mNumThreads);
        sink.u64(value.mRandomOt);
        pack_aes_manager(sink, value.mAesMgr);
    }

    template<class Sink, class Object>
    static void pack_object(Sink& sink, const Object& value) {
        if constexpr (requires { value.mExtraW; }) {
            sink.domain(SENDER_DOMAIN);
            pack_soft_base(sink, value.mBase);
            pack_blocks(sink, value.mExtraW);
        } else {
            sink.domain(RECEIVER_DOMAIN);
            pack_soft_base(sink, value.mBase);
            pack_blocks(sink, value.mExtraV);
        }
    }

    template<class Sink, class Rtcr>
    static void pack_rtcr(Sink& sink, const Rtcr& value) {
        sink.domain(RTCR_DOMAIN);
        pack_aes_manager(sink, value);
        sink.u64(value.mHashKeys.size());
        for (const auto& key : value.mHashKeys) pack_block(sink, key);
        sink.u64(value.mTweak);
        pack_block(sink, value.mTweakMul);
    }

    template<class Sink, class Range>
    static void pack_integrals(Sink& sink, const Range& values) {
        sink.u64(values.size());
        for (const auto value : values)
            sink.u64(static_cast<std::uint64_t>(value));
    }

    template<class Range>
    static void scrub_range(Range& values) noexcept {
        using Value = std::remove_reference_t<decltype(*values.data())>;
        if (values.data() && values.capacity())
            detail::cleanse_bytes(
                reinterpret_cast<unsigned char*>(values.data()),
                static_cast<std::size_t>(values.capacity()) * sizeof(Value));
        values.clear();
    }

    static void scrub_aes(osuCrypto::AES& value) noexcept {
        for (auto& key : value.mRoundKey)
            detail::cleanse_bytes(key.data(), sizeof(key));
    }

    template<class Manager>
    static void scrub_aes_manager(Manager& value) noexcept {
        value.mAesKeyUseCount = ~std::uint64_t{0};
        value.mAESs.mIndex = ~std::uint64_t{0};
        scrub_aes(value.mAESs.mPrng);
        for (auto& aes : value.mAESs.mAesRoundKeys.mAESs)
            scrub_aes(aes);
    }

    static void scrub_prng_impl(osuCrypto::PRNG& value) noexcept {
        scrub_range(value.mBuffer);
        scrub_aes(value.mAes);
        value.mBytesIdx = 0;
        value.mBlockIdx = 0;
        value.mBufferByteCapacity = 0;
    }

    template<class Pprf>
    static void scrub_pprf(Pprf& value) noexcept {
        if constexpr (requires { value.mValue; })
            scrub_range(value.mValue);
        if (value.mBaseOTs.data() && value.mBaseOTs.size())
            detail::cleanse_bytes(
                reinterpret_cast<unsigned char*>(value.mBaseOTs.data()),
                static_cast<std::size_t>(value.mBaseOTs.size()) *
                    sizeof(*value.mBaseOTs.data()));
        if constexpr (requires { value.mBaseChoices; }) {
            if (value.mBaseChoices.data() && value.mBaseChoices.size())
                detail::cleanse_bytes(
                    reinterpret_cast<unsigned char*>(
                        value.mBaseChoices.data()),
                    static_cast<std::size_t>(value.mBaseChoices.size()) *
                        sizeof(*value.mBaseChoices.data()));
        }
        scrub_range(value.mTempBuffer);
    }

    template<class Vole>
    static void scrub_small_vole(Vole& value) noexcept {
        scrub_range(value.mSeeds);
        if (value.mPprf) scrub_pprf(*value.mPprf);
        if constexpr (requires { value.mDelta; }) {
            if (value.mDelta.data() && value.mDelta.capacity())
                detail::cleanse_bytes(
                    reinterpret_cast<unsigned char*>(value.mDelta.data()),
                    static_cast<std::size_t>(value.mDelta.capacity() / 8U));
            scrub_range(value.mDeltaUnpacked);
        }
    }

    template<class Subspace>
    static void scrub_subspace(Subspace& value) noexcept {
        scrub_small_vole(value.mVole);
        scrub_range(value.mMessages);
        if constexpr (requires { value.mCorrectionU; })
            scrub_range(value.mCorrectionU);
        scrub_prng_impl(value.hashKeyPrng);
        detail::cleanse_bytes(value.hashKeySqAndA64.data(),
                              sizeof(value.hashKeySqAndA64));
        value.hashKey = 0;
        value.hashKeyUseCount = ~std::uint64_t{0};
        if constexpr (requires { value.mHashW; }) {
            scrub_range(value.mHashW);
            scrub_range(value.mSubtotalW);
        } else {
            scrub_range(value.hashU);
            scrub_range(value.subtotalU);
            scrub_range(value.hashV);
            scrub_range(value.subtotalV);
        }
    }

public:
    static detail::SecretBytes serialize_prng(
            const osuCrypto::PRNG& value) {
        return detail::encode_exact([&](auto& sink) {
            pack_prng(sink, value);
        });
    }

    static detail::SecretBytes serialize_seed(
            const osuCrypto::block& value) {
        return detail::encode_exact([&](auto& sink) {
            sink.domain(SEED_DOMAIN);
            pack_block(sink, value);
        });
    }

    template<class Object>
    static detail::SecretBytes serialize_object(const Object& value) {
        return detail::encode_exact([&](auto& sink) {
            pack_object(sink, value);
        });
    }

    template<class Rtcr>
    static detail::SecretBytes serialize_rtcr(const Rtcr& value) {
        return detail::encode_exact([&](auto& sink) {
            pack_rtcr(sink, value);
        });
    }

    template<class Blocks>
    static detail::SecretBytes serialize_sender_base(
            const Blocks& messages,
            const osuCrypto::BitVector& choices) {
        return detail::encode_exact([&](auto& sink) {
            sink.domain(BASE_DOMAIN);
            sink.u64(static_cast<std::uint64_t>(state::SoftSpokenRole::Sender));
            pack_blocks(sink, messages);
            pack_bit_vector(sink, choices);
        });
    }

    template<class Pairs>
    static detail::SecretBytes serialize_receiver_base(
            const Pairs& messages,
            const osuCrypto::BitVector& choices) {
        return detail::encode_exact([&](auto& sink) {
            sink.domain(BASE_DOMAIN);
            sink.u64(static_cast<std::uint64_t>(
                state::SoftSpokenRole::Receiver));
            sink.u64(messages.size());
            for (const auto& pair : messages) {
                pack_block(sink, pair[0]);
                pack_block(sink, pair[1]);
            }
            pack_bit_vector(sink, choices);
        });
    }

    template<class Output>
    static detail::SecretBytes serialize_output(
            state::SoftSpokenRole role, const Output& output) {
        return detail::encode_exact([&](auto& sink) {
            sink.domain(OUTPUT_DOMAIN);
            sink.u64(static_cast<std::uint64_t>(role));
            sink.u64(output.size());
            for (const auto& value : output) pack_element(sink, value);
        });
    }

    template<class Object, class... Ranges>
    static bool stage_check(
            const Object& object, const Ranges&... ranges) noexcept {
        try {
            auto transient = detail::encode_exact([&](auto& sink) {
                sink.domain(CHECK_DOMAIN);
                pack_object(sink, object);
                (pack_integrals(sink, ranges), ...);
            });
            return state::SoftSpokenRandomTapeStateSourceBridge::
                stage_check_transient(transient.view());
        } catch (...) {
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(
                    state::SoftSpokenAbortClass::SourceSerialization,
                    state::SoftSpokenRolePhase::Rtcr);
            return false;
        }
    }

    template<class Object>
    static bool capture_vole_expanded(
            const Object& object, const osuCrypto::PRNG& prng,
            const osuCrypto::block& seed) noexcept {
        try {
            auto object_bytes = serialize_object(object);
            auto prng_bytes = serialize_prng(prng);
            auto seed_bytes = serialize_seed(seed);
            return state::SoftSpokenRandomTapeStateSourceBridge::vole_expanded(
                object_bytes.view(), prng_bytes.view(), seed_bytes.view());
        } catch (...) {
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(
                    state::SoftSpokenAbortClass::SourceSerialization,
                    state::SoftSpokenRolePhase::Base);
            return false;
        }
    }

    template<class Object>
    static bool capture_tape(
            const Object& object, const osuCrypto::PRNG& prng) noexcept {
        try {
            auto object_bytes = serialize_object(object);
            auto prng_bytes = serialize_prng(prng);
            return state::SoftSpokenRandomTapeStateSourceBridge::tape_consumed(
                object_bytes.view(), prng_bytes.view());
        } catch (...) {
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(
                    state::SoftSpokenAbortClass::SourceSerialization,
                    state::SoftSpokenRolePhase::Expanded);
            return false;
        }
    }

    template<class Object>
    static bool capture_challenge(
            const Object& object, const osuCrypto::PRNG& prng) noexcept {
        try {
            auto object_bytes = serialize_object(object);
            auto prng_bytes = serialize_prng(prng);
            return state::SoftSpokenRandomTapeStateSourceBridge::
                challenge_bound(object_bytes.view(), prng_bytes.view());
        } catch (...) {
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(
                    state::SoftSpokenAbortClass::SourceSerialization,
                    state::SoftSpokenRolePhase::Tape);
            return false;
        }
    }

    template<class Object, class Rtcr>
    static bool capture_rtcr(
            const Object& object, const osuCrypto::PRNG& prng,
            const Rtcr& rtcr) noexcept {
        try {
            auto object_bytes = serialize_object(object);
            auto prng_bytes = serialize_prng(prng);
            auto rtcr_bytes = serialize_rtcr(rtcr);
            return state::SoftSpokenRandomTapeStateSourceBridge::rtcr_bound(
                object_bytes.view(), prng_bytes.view(), rtcr_bytes.view());
        } catch (...) {
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(
                    state::SoftSpokenAbortClass::SourceSerialization,
                    state::SoftSpokenRolePhase::Challenge);
            return false;
        }
    }

    template<class Object>
    static bool capture_check_derived(
            const Object& object, const osuCrypto::PRNG& prng) noexcept {
        try {
            auto object_bytes = serialize_object(object);
            auto prng_bytes = serialize_prng(prng);
            return state::SoftSpokenRandomTapeStateSourceBridge::check_derived(
                object_bytes.view(), prng_bytes.view(), {});
        } catch (...) {
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(
                    state::SoftSpokenAbortClass::SourceSerialization,
                    state::SoftSpokenRolePhase::Rtcr);
            return false;
        }
    }

    template<class Object>
    static bool capture_check_terminal(
            const Object& object, const osuCrypto::PRNG& prng) noexcept {
        try {
            auto object_bytes = serialize_object(object);
            auto prng_bytes = serialize_prng(prng);
            return state::SoftSpokenRandomTapeStateSourceBridge::check_terminal(
                object_bytes.view(), prng_bytes.view());
        } catch (...) {
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(
                    state::SoftSpokenAbortClass::SourceSerialization,
                    state::SoftSpokenRolePhase::CheckDerived);
            return false;
        }
    }

    static void scrub_prng(osuCrypto::PRNG& value) noexcept {
        scrub_prng_impl(value);
    }

    template<class Object>
    static void scrub_object(Object& value) noexcept {
        scrub_subspace(value.mBase.mSubVole);
        scrub_aes_manager(value.mBase.mAesMgr);
        if constexpr (requires { value.mExtraW; })
            scrub_range(value.mExtraW);
        else
            scrub_range(value.mExtraV);
    }

    template<class Range>
    static void scrub_blocks(Range& value) noexcept {
        scrub_range(value);
    }

#ifdef KPI_P1_SOFTSPOKEN_RANDOM_TAPE_SOURCE_CAPTURE_TEST_SETUP
    static bool test_only_underreserve_refuses_without_growth() {
        std::vector<unsigned char> output;
        output.reserve(7U);
        const auto* before = output.data();
        const auto capacity = output.capacity();
        try {
            detail::ByteSink sink{output};
            sink.u64(1U);
        } catch (const std::runtime_error&) {
            return output.empty() && output.data() == before &&
                output.capacity() == capacity;
        }
        return false;
    }
#endif
};

// Guards are source-owned so every constructor/coroutine exception produces a
// typed abort prefix without changing the upstream exception.
class RoleGuard final {
    state::SoftSpokenRole role_{};
    state::SoftSpokenAbortClass abort_{};
    state::SoftSpokenRolePhase phase_{state::SoftSpokenRolePhase::Begun};
    bool finished_{};
public:
    RoleGuard(
            state::SoftSpokenRole role,
            state::SoftSpokenAbortClass abort) noexcept
        : role_(role), abort_(abort) {}
    RoleGuard(const RoleGuard&) = delete;
    RoleGuard& operator=(const RoleGuard&) = delete;
    ~RoleGuard() {
        if (!finished_)
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_current_noexcept(abort_, phase_);
    }
    void phase(state::SoftSpokenRolePhase phase) noexcept { phase_ = phase; }
    void finish() noexcept { finished_ = true; }
    state::SoftSpokenRole role() const noexcept { return role_; }
};

class CallGuard final {
    const void* source_player_{};
    bool finished_{};
public:
    explicit CallGuard(const void* source_player) noexcept
        : source_player_(source_player) {}
    CallGuard(const CallGuard&) = delete;
    CallGuard& operator=(const CallGuard&) = delete;
    ~CallGuard() {
        if (!finished_)
            state::SoftSpokenRandomTapeStateSourceBridge::
                abort_player_noexcept(
                    source_player_, state::SoftSpokenAbortClass::CallException);
    }
    void finish() noexcept { finished_ = true; }
};

} // namespace kpb_libote_p1_softspoken
