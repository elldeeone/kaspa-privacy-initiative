#include "p1_query_msm_source_capture.hpp"

#include "Tools/octetStream.h"

#include <algorithm>
#include <array>
#include <future>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>

namespace kpi::mpc::p1_private_state::query_msm_source {
namespace {

constexpr std::string_view SOURCE_IDENTITY_SHA256 =
    "ab59818aa9363030ef7d47adfe731e203348868155cd7c26f098a510a6dbb5f2";
constexpr std::string_view H_TAIL_DOMAIN =
    "KPI_P1_QUERY_MSM_H_UNUSED_SCALAR_V1\n";
constexpr std::string_view CURSOR_G1_DOMAIN =
    "KPI_P1_QUERY_MSM_CURSOR_G1_V1\n";
constexpr std::string_view CURSOR_G2_DOMAIN =
    "KPI_P1_QUERY_MSM_CURSOR_G2_V1\n";
constexpr std::string_view WORKER_G1_DOMAIN =
    "KPI_P1_QUERY_MSM_WORKER_G1_V1\n";
constexpr std::string_view WORKER_G2_DOMAIN =
    "KPI_P1_QUERY_MSM_WORKER_G2_V1\n";
constexpr std::string_view REDUCTION_G1_DOMAIN =
    "KPI_P1_QUERY_MSM_REDUCTION_G1_V1\n";
constexpr std::string_view REDUCTION_G2_DOMAIN =
    "KPI_P1_QUERY_MSM_REDUCTION_G2_V1\n";
constexpr std::string_view ACCUMULATOR_G1_DOMAIN =
    "KPI_P1_QUERY_MSM_ACCUMULATOR_G1_V1\n";
constexpr std::string_view ACCUMULATOR_G2_DOMAIN =
    "KPI_P1_QUERY_MSM_ACCUMULATOR_G2_V1\n";
constexpr std::string_view TERMINAL_G1_DOMAIN =
    "KPI_P1_QUERY_MSM_TERMINAL_G1_V1\n";
constexpr std::string_view TERMINAL_G2_DOMAIN =
    "KPI_P1_QUERY_MSM_TERMINAL_G2_V1\n";
constexpr std::string_view MIXED_INPUTS_DOMAIN =
    "KPI_P1_QUERY_MSM_MIXED_INPUTS_V1\n";
constexpr std::string_view MIXED_MASKS_DOMAIN =
    "KPI_P1_QUERY_MSM_MIXED_MASKS_AND_DIFFERENCES_V1\n";
constexpr std::string_view MIXED_PRODUCTS_DOMAIN =
    "KPI_P1_QUERY_MSM_MIXED_PRODUCTS_V1\n";
constexpr std::string_view CHECKER_INPUTS_DOMAIN =
    "KPI_P1_QUERY_MSM_FINAL_CHECKER_INPUTS_V1\n";
constexpr std::string_view CHECKER_OPENED_DOMAIN =
    "KPI_P1_QUERY_MSM_FINAL_CHECKER_OPENED_V1\n";
constexpr std::string_view CHECKER_RETURNED_DOMAIN =
    "KPI_P1_QUERY_MSM_FINAL_CHECKER_RETURNED_V1\n";

constexpr std::size_t AUTH_SCALAR_BYTES = 2 * FR_BYTES;
constexpr std::size_t AUTH_G1_BYTES = 2 * G1_BYTES;
constexpr std::size_t AUTH_G2_BYTES = 2 * G2_BYTES;

std::size_t checked_add(std::size_t left, std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left)
        throw std::runtime_error("P1-query-MSM-serialization-size");
    return left + right;
}

std::size_t checked_mul(std::size_t left, std::size_t right) {
    if (left && right > std::numeric_limits<std::size_t>::max() / left)
        throw std::runtime_error("P1-query-MSM-serialization-size");
    return left * right;
}

void wipe(std::span<unsigned char> value) noexcept {
    volatile unsigned char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
        cursor[index] = 0;
}

class SecretBytes final {
    std::unique_ptr<unsigned char[]> bytes_;
    std::size_t size_{};
    std::size_t used_{};

public:
    explicit SecretBytes(std::size_t size)
        : bytes_(size ? std::make_unique<unsigned char[]>(size) : nullptr),
          size_(size) {
        if (!size) throw std::runtime_error("P1-query-MSM-empty-state");
    }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept
        : bytes_(std::move(other.bytes_)), size_(other.size_),
          used_(other.used_) {
        other.size_ = 0;
        other.used_ = 0;
    }
    SecretBytes& operator=(SecretBytes&&) = delete;
    ~SecretBytes() {
        if (bytes_) wipe({bytes_.get(), size_});
    }

    void put(std::span<const unsigned char> value) {
        if (value.size() > size_ - used_)
            throw std::runtime_error("P1-query-MSM-serialization-overrun");
        std::copy(value.begin(), value.end(), bytes_.get() + used_);
        used_ += value.size();
    }

    void put(std::string_view value) {
        put({reinterpret_cast<const unsigned char*>(value.data()),
             value.size()});
    }

    void u64(std::uint64_t value) {
        std::array<unsigned char, 8> encoded{};
        for (unsigned index = 0; index < encoded.size(); ++index)
            encoded[index] = static_cast<unsigned char>(
                value >> (8 * (encoded.size() - 1 - index)));
        put(encoded);
        wipe(encoded);
    }

    std::span<const unsigned char> complete() const {
        if (used_ != size_)
            throw std::runtime_error("P1-query-MSM-serialization-underrun");
        return {bytes_.get(), size_};
    }

    std::span<const unsigned char> prefix() const noexcept {
        return {bytes_.get(), used_};
    }
};

class PackedWiper final {
    octetStream* packed_;
public:
    explicit PackedWiper(octetStream& packed) : packed_(&packed) {}
    ~PackedWiper() {
        if (packed_->get_length())
            wipe({reinterpret_cast<unsigned char*>(packed_->get_data()),
                  packed_->get_length()});
    }
};

void put_field(SecretBytes& output, const Fr& value) {
    octetStream packed;
    packed.reserve(FR_BYTES);
    PackedWiper guard(packed);
    value.pack(packed);
    if (packed.get_length() != FR_BYTES)
        throw std::runtime_error("P1-query-MSM-Fr-width");
    output.put({reinterpret_cast<const unsigned char*>(packed.get_data()),
                packed.get_length()});
}

template<class Group>
void put_group(SecretBytes& output, const Group& value) {
    auto bytes = value.network_bytes();
    try {
        output.put(bytes);
    } catch (...) {
        wipe(bytes);
        throw;
    }
    wipe(bytes);
}

void put_auth_scalar(SecretBytes& output, const AuthScalar& value) {
    put_field(output, value.get_share());
    put_field(output, value.get_mac());
}

template<class AuthGroup>
void put_auth_group(SecretBytes& output, const AuthGroup& value) {
    put_group(output, value.get_share());
    put_group(output, value.get_mac());
}

template<class AuthGroup>
struct GroupWiper final {
    AuthGroup* value;
    ~GroupWiper() { *value = AuthGroup{}; }
};

SecretBytes encoded_auth_scalar(
        std::string_view domain, const AuthScalar& value) {
    SecretBytes output(checked_add(domain.size(), AUTH_SCALAR_BYTES));
    output.put(domain);
    put_auth_scalar(output, value);
    (void) output.complete();
    return output;
}

template<class AuthGroup>
SecretBytes encoded_auth_group(
        std::string_view domain, const AuthGroup& value,
        std::size_t group_bytes) {
    SecretBytes output(checked_add(domain.size(), 2 * group_bytes));
    output.put(domain);
    put_auth_group(output, value);
    (void) output.complete();
    return output;
}

template<class Group>
SecretBytes encoded_cursor(
        std::string_view domain, std::size_t compressed_width,
        std::span<const unsigned char> compressed,
        std::span<const Group> decoded, std::size_t group_width) {
    if (decoded.empty() ||
        compressed.size() != checked_mul(decoded.size(), compressed_width))
        throw std::runtime_error("P1-query-MSM-cursor-shape");
    const auto records = checked_mul(
        decoded.size(), checked_add(compressed_width, group_width));
    SecretBytes output(checked_add(checked_add(domain.size(), 8), records));
    output.put(domain);
    output.u64(decoded.size());
    output.put(compressed);
    for (const auto& point : decoded) put_group(output, point);
    (void) output.complete();
    return output;
}

template<class Group, class AuthGroup>
AuthGroup selected_map(const Group& point, const AuthScalar& scalar) {
    if constexpr (std::is_same_v<Group, G1Value> &&
                  std::is_same_v<AuthGroup, AuthG1>)
        return public_point_map(point, scalar);
    else if constexpr (std::is_same_v<Group, G2Value> &&
                       std::is_same_v<AuthGroup, AuthG2>)
        return public_point_map(point, scalar);
    else
        static_assert(std::is_same_v<Group, void>,
                      "unselected query/MSM group type");
}

template<class Group, class AuthGroup>
AuthGroup captured_chunk(
        QueryMsmStateScope& scope, std::uint64_t query_first,
        std::span<const unsigned char> compressed_points,
        std::span<const Group> decoded_points,
        std::span<const AuthScalar> scalars,
        std::size_t compressed_width, std::size_t group_width,
        std::string_view cursor_domain, std::string_view worker_domain,
        std::string_view reduction_domain) {
    if (decoded_points.empty() || decoded_points.size() != scalars.size() ||
        decoded_points.size() > QUERY_MSM_SELECTED_CHUNK)
        throw std::runtime_error("P1-query-MSM-chunk-shape");
    try {
        auto cursor = encoded_cursor(
            cursor_domain, compressed_width, compressed_points,
            decoded_points, group_width);
        QueryMsmStateSourceBridge::chunk_begin(
            scope, query_first, decoded_points.size(), cursor.complete());

        const auto worker_count = std::min<std::size_t>(
            QUERY_MSM_SELECTED_WORKERS, decoded_points.size());
        std::array<std::future<AuthGroup>, QUERY_MSM_SELECTED_WORKERS>
            futures;
        std::size_t launched = 0;
        try {
            for (std::size_t worker = 0; worker < worker_count; ++worker) {
                const auto local_first =
                    decoded_points.size() * worker / worker_count;
                const auto local_last =
                    decoded_points.size() * (worker + 1) / worker_count;
                futures[worker] = std::async(
                    std::launch::async,
                    [&, worker, local_first, local_last] {
                        auto token = QueryMsmStateSourceBridge::worker_begin(
                            scope, worker,
                            query_first + local_first,
                            query_first + local_last);
                        const auto count = local_last - local_first;
                        const auto record_bytes = checked_add(
                            checked_add(group_width, AUTH_SCALAR_BYTES),
                            4 * group_width);
                        SecretBytes transcript(checked_add(
                            checked_add(worker_domain.size(), 8),
                            checked_mul(count, record_bytes)));
                        transcript.put(worker_domain);
                        transcript.u64(count);
                        AuthGroup partial;
                        try {
                            for (std::size_t index = local_first;
                                 index < local_last; ++index) {
                                auto mapped = selected_map<Group, AuthGroup>(
                                    decoded_points[index], scalars[index]);
                                GroupWiper<AuthGroup> mapped_wiper{&mapped};
                                partial += mapped;
                                put_group(transcript, decoded_points[index]);
                                put_auth_scalar(transcript, scalars[index]);
                                put_auth_group(transcript, mapped);
                                put_auth_group(transcript, partial);
                            }
                            QueryMsmStateSourceBridge::worker_transcript(
                                std::move(token), transcript.complete());
                            return partial;
                        } catch (...) {
                            QueryMsmStateSourceBridge::worker_abort_noexcept(
                                std::move(token),
                                QueryMsmAbortClass::WorkerExecution,
                                transcript.prefix(),
                                "p1-query-msm-worker-execution",
                                SOURCE_IDENTITY_SHA256);
                            partial = AuthGroup{};
                            throw;
                        }
                    });
                ++launched;
            }
        } catch (...) {
            for (std::size_t worker = 0; worker < launched; ++worker)
                if (futures[worker].valid()) futures[worker].wait();
            QueryMsmStateSourceBridge::abort_noexcept(
                scope, QueryMsmAbortClass::WorkerLaunch,
                "p1-query-msm-worker-launch", SOURCE_IDENTITY_SHA256);
            throw;
        }

        std::array<AuthGroup, QUERY_MSM_SELECTED_WORKERS> partials{};
        struct PartialsWiper final {
            std::array<AuthGroup, QUERY_MSM_SELECTED_WORKERS>* values;
            ~PartialsWiper() {
                for (auto& value : *values) value = AuthGroup{};
            }
        } partials_wiper{&partials};
        std::array<bool, QUERY_MSM_SELECTED_WORKERS> obtained{};
        try {
            for (std::size_t worker = 0; worker < worker_count; ++worker) {
                partials[worker] = futures[worker].get();
                obtained[worker] = true;
            }
        } catch (...) {
            for (std::size_t worker = 0; worker < worker_count; ++worker) {
                if (obtained[worker] || !futures[worker].valid()) continue;
                try { (void) futures[worker].get(); } catch (...) {}
            }
            QueryMsmStateSourceBridge::abort_noexcept(
                scope, QueryMsmAbortClass::QueryException,
                "p1-query-msm-worker-join", SOURCE_IDENTITY_SHA256);
            throw;
        }

        AuthGroup total;
        for (std::size_t worker = 0; worker < worker_count; ++worker)
            total += partials[worker];
        const auto reduction_bytes = checked_add(
            checked_add(reduction_domain.size(), 8),
            checked_mul(worker_count + 1, 2 * group_width));
        SecretBytes reduction(reduction_bytes);
        reduction.put(reduction_domain);
        reduction.u64(worker_count);
        for (std::size_t worker = 0; worker < worker_count; ++worker)
            put_auth_group(reduction, partials[worker]);
        put_auth_group(reduction, total);
        QueryMsmStateSourceBridge::chunk_reduced(
            scope, reduction.complete());
        return total;
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::Serialization,
            "p1-query-msm-chunk-capture", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

template<class Callable>
void capture_post(
        QueryMsmStateScope& scope, QueryMsmPostStage stage,
        Callable&& callable) {
    try {
        auto encoded = callable();
        QueryMsmStateSourceBridge::post_query_buffer(
            scope, stage, encoded.complete());
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::Serialization,
            "p1-query-msm-post-buffer", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

} // namespace

void begin_g1_query(
        QueryMsmStateScope& scope, QueryMsmKind kind,
        std::uint64_t points, std::span<const AuthScalar> scalars) {
    try {
        if (kind == QueryMsmKind::B2 || points == 0 ||
            (kind == QueryMsmKind::H ? scalars.size() != points + 1 :
                                      scalars.size() != points))
            throw std::runtime_error("P1-query-MSM-G1-query-shape");
        if (kind == QueryMsmKind::H) {
            auto tail = encoded_auth_scalar(H_TAIL_DOMAIN, scalars.back());
            QueryMsmStateSourceBridge::query_begin(
                scope, kind, QueryMsmGroup::G1, points, scalars.size(),
                tail.complete());
        } else {
            QueryMsmStateSourceBridge::query_begin(
                scope, kind, QueryMsmGroup::G1, points, scalars.size());
        }
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::SourceShape,
            "p1-query-msm-G1-begin", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

void begin_g2_query(
        QueryMsmStateScope& scope, std::uint64_t points,
        std::span<const AuthScalar> scalars) {
    try {
        if (points == 0 || scalars.size() != points)
            throw std::runtime_error("P1-query-MSM-G2-query-shape");
        QueryMsmStateSourceBridge::query_begin(
            scope, QueryMsmKind::B2, QueryMsmGroup::G2,
            points, scalars.size());
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::SourceShape,
            "p1-query-msm-G2-begin", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

AuthG1 captured_g1_chunk(
        QueryMsmStateScope& scope, std::uint64_t first,
        std::span<const unsigned char> compressed_points,
        std::span<const G1Value> decoded_points,
        std::span<const AuthScalar> scalars) {
    return captured_chunk<G1Value, AuthG1>(
        scope, first, compressed_points, decoded_points, scalars,
        COMPRESSED_G1_BYTES, G1_BYTES, CURSOR_G1_DOMAIN,
        WORKER_G1_DOMAIN, REDUCTION_G1_DOMAIN);
}

AuthG2 captured_g2_chunk(
        QueryMsmStateScope& scope, std::uint64_t first,
        std::span<const unsigned char> compressed_points,
        std::span<const G2Value> decoded_points,
        std::span<const AuthScalar> scalars) {
    return captured_chunk<G2Value, AuthG2>(
        scope, first, compressed_points, decoded_points, scalars,
        COMPRESSED_G2_BYTES, G2_BYTES, CURSOR_G2_DOMAIN,
        WORKER_G2_DOMAIN, REDUCTION_G2_DOMAIN);
}

void g1_accumulator(QueryMsmStateScope& scope, const AuthG1& value) {
    try {
        auto encoded = encoded_auth_group(
            ACCUMULATOR_G1_DOMAIN, value, G1_BYTES);
        QueryMsmStateSourceBridge::query_accumulator(
            scope, encoded.complete());
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::Serialization,
            "p1-query-msm-G1-accumulator", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

void g2_accumulator(QueryMsmStateScope& scope, const AuthG2& value) {
    try {
        auto encoded = encoded_auth_group(
            ACCUMULATOR_G2_DOMAIN, value, G2_BYTES);
        QueryMsmStateSourceBridge::query_accumulator(
            scope, encoded.complete());
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::Serialization,
            "p1-query-msm-G2-accumulator", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

void terminal_g1(QueryMsmStateScope& scope, const AuthG1& value) {
    try {
        auto encoded = encoded_auth_group(
            TERMINAL_G1_DOMAIN, value, G1_BYTES);
        QueryMsmStateSourceBridge::query_terminal(scope, encoded.complete());
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::Serialization,
            "p1-query-msm-G1-terminal", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

void terminal_g2(QueryMsmStateScope& scope, const AuthG2& value) {
    try {
        auto encoded = encoded_auth_group(
            TERMINAL_G2_DOMAIN, value, G2_BYTES);
        QueryMsmStateSourceBridge::query_terminal(scope, encoded.complete());
    } catch (...) {
        QueryMsmStateSourceBridge::abort_noexcept(
            scope, QueryMsmAbortClass::Serialization,
            "p1-query-msm-G2-terminal", SOURCE_IDENTITY_SHA256);
        throw;
    }
}

void mixed_inputs(
        QueryMsmStateScope& scope, std::span<const AuthG1, 2> groups,
        std::span<const AuthScalar, 2> scalars) {
    capture_post(scope, QueryMsmPostStage::MixedInputs, [&] {
        SecretBytes output(checked_add(
            MIXED_INPUTS_DOMAIN.size(), 2 * AUTH_G1_BYTES +
                2 * AUTH_SCALAR_BYTES));
        output.put(MIXED_INPUTS_DOMAIN);
        for (const auto& group : groups) put_auth_group(output, group);
        for (const auto& scalar : scalars) put_auth_scalar(output, scalar);
        (void) output.complete();
        return output;
    });
}

void mixed_masks_and_differences(
        QueryMsmStateScope& scope,
        std::span<const AuthScalar, 6> triples,
        std::span<const AuthG1, 2> group_masks,
        std::span<const AuthScalar, 2> scalar_masks,
        std::span<const AuthG1, 2> product_masks,
        std::span<const AuthG1, 2> masked_groups,
        std::span<const AuthScalar, 2> masked_scalars,
        std::span<const Fr, 2> scalar_differences,
        std::span<const G1Value, 2> group_differences) {
    capture_post(scope, QueryMsmPostStage::MixedMasksAndDifferences, [&] {
        constexpr auto payload =
            6 * AUTH_SCALAR_BYTES + 2 * AUTH_G1_BYTES +
            2 * AUTH_SCALAR_BYTES + 2 * AUTH_G1_BYTES +
            2 * AUTH_G1_BYTES + 2 * AUTH_SCALAR_BYTES +
            2 * FR_BYTES + 2 * G1_BYTES;
        SecretBytes output(checked_add(MIXED_MASKS_DOMAIN.size(), payload));
        output.put(MIXED_MASKS_DOMAIN);
        for (const auto& value : triples) put_auth_scalar(output, value);
        for (const auto& value : group_masks) put_auth_group(output, value);
        for (const auto& value : scalar_masks) put_auth_scalar(output, value);
        for (const auto& value : product_masks) put_auth_group(output, value);
        for (const auto& value : masked_groups) put_auth_group(output, value);
        for (const auto& value : masked_scalars) put_auth_scalar(output, value);
        for (const auto& value : scalar_differences) put_field(output, value);
        for (const auto& value : group_differences) put_group(output, value);
        (void) output.complete();
        return output;
    });
}

void mixed_products(
        QueryMsmStateScope& scope,
        std::span<const AuthG1, 2> products) {
    capture_post(scope, QueryMsmPostStage::MixedProducts, [&] {
        SecretBytes output(checked_add(
            MIXED_PRODUCTS_DOMAIN.size(), 2 * AUTH_G1_BYTES));
        output.put(MIXED_PRODUCTS_DOMAIN);
        for (const auto& value : products) put_auth_group(output, value);
        (void) output.complete();
        return output;
    });
}

void final_checker_inputs(
        QueryMsmStateScope& scope, const AuthG1& a,
        const AuthG2& b, const AuthG1& c) {
    capture_post(scope, QueryMsmPostStage::FinalCheckerInputs, [&] {
        SecretBytes output(checked_add(
            CHECKER_INPUTS_DOMAIN.size(),
            2 * AUTH_G1_BYTES + AUTH_G2_BYTES));
        output.put(CHECKER_INPUTS_DOMAIN);
        put_auth_group(output, a);
        put_auth_group(output, c);
        put_auth_group(output, b);
        (void) output.complete();
        return output;
    });
}

void final_checker_opened(
        QueryMsmStateScope& scope,
        std::span<const G1Value, 2> g1, const G2Value& g2) {
    capture_post(scope, QueryMsmPostStage::FinalCheckerOpened, [&] {
        SecretBytes output(checked_add(
            CHECKER_OPENED_DOMAIN.size(), 2 * G1_BYTES + G2_BYTES));
        output.put(CHECKER_OPENED_DOMAIN);
        for (const auto& value : g1) put_group(output, value);
        put_group(output, g2);
        (void) output.complete();
        return output;
    });
}

void final_checker_returned(
        QueryMsmStateScope& scope,
        std::span<const G1Value, 2> g1, const G2Value& g2) {
    capture_post(scope, QueryMsmPostStage::FinalCheckerReturned, [&] {
        SecretBytes output(checked_add(
            CHECKER_RETURNED_DOMAIN.size(), 2 * G1_BYTES + G2_BYTES));
        output.put(CHECKER_RETURNED_DOMAIN);
        for (const auto& value : g1) put_group(output, value);
        put_group(output, g2);
        (void) output.complete();
        return output;
    });
}

} // namespace kpi::mpc::p1_private_state::query_msm_source
