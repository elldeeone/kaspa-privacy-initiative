#include "../query_msm_correspondence.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace {
struct AuthPair {
    std::int64_t share{};
    std::int64_t mac{};
    AuthPair& operator+=(const AuthPair& other) {
        share += other.share; mac += other.mac; return *this;
    }
    bool operator==(const AuthPair&) const = default;
};

AuthPair map(std::int64_t point, const AuthPair& scalar) {
    return {point * scalar.share, point * scalar.mac};
}

template<class Callable>
void refuses(Callable&& callable) {
    bool refused = false;
    try { callable(); } catch (const std::runtime_error&) { refused = true; }
    assert(refused);
}
}

int main() {
    using kpi::mpc::financial::query_msm::deterministic_worker_sum;
    for (std::size_t size = 1; size <= 67; ++size) {
        std::vector<std::int64_t> points;
        std::vector<AuthPair> scalars;
        AuthPair serial;
        for (std::size_t index = 0; index < size; ++index) {
            points.push_back(static_cast<std::int64_t>(index + 3));
            scalars.push_back({static_cast<std::int64_t>(2 * index + 1),
                               static_cast<std::int64_t>(5 * index + 2)});
            serial += map(points.back(), scalars.back());
        }
        for (const std::size_t workers : {1U, 2U, 3U, 8U, 128U}) {
            const auto parallel = deterministic_worker_sum(
                std::span<const std::int64_t>(points),
                std::span<const AuthPair>(scalars), workers, 1024, map);
            assert(parallel == serial);
        }
    }
    const std::array<std::int64_t, 1> point{{2}};
    const std::array<AuthPair, 1> scalar{{{3, 4}}};
    refuses([&] { (void)deterministic_worker_sum(
        std::span<const std::int64_t>{}, std::span<const AuthPair>{},
        1, 1, map); });
    refuses([&] { (void)deterministic_worker_sum(
        std::span<const std::int64_t>(point),
        std::span<const AuthPair>{}, 1, 1, map); });
    refuses([&] { (void)deterministic_worker_sum(
        std::span<const std::int64_t>(point),
        std::span<const AuthPair>(scalar), 0, 1, map); });
    refuses([&] { (void)deterministic_worker_sum(
        std::span<const std::int64_t>(point),
        std::span<const AuthPair>(scalar), 1, 0, map); });
}
