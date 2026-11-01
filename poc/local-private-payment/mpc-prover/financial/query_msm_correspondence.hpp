#pragma once

// Source-closed deterministic worker reduction used by the selected financial
// Groth16 query path. Public query points and captured authenticated scalar
// lanes determine every returned share/MAC pair. This does not claim to
// capture scheduler state, physical RAM, disk access, or host timing.

#include <algorithm>
#include <cstddef>
#include <future>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::query_msm {

inline constexpr std::string_view CORRESPONDENCE_MANIFEST = R"MANIFEST(KPB_FINANCIAL_QUERY_MSM_CORRESPONDENCE_V1
A|public-query=A|scalar=assignment[0:variables]|result=authenticated-g1-A
B1|public-query=B1|scalar=assignment[0:variables]|result=authenticated-g1-B1-base
B2|public-query=B2|scalar=assignment[0:variables]|result=authenticated-g2-B2
H|public-query=H[0:domain-1]|scalar=streamed-H[0:domain-1]|unused-scalar=streamed-H[domain-1]|result=authenticated-g1-H
L|public-query=L|scalar=assignment[instances:variables]|result=authenticated-g1-L
A-mask|public-point=delta1|scalar-site=20|result=authenticated-g1-A
B2-mask|public-point=delta2|scalar-site=21|result=authenticated-g2-B2
A-public|public-point=alpha1|result=authenticated-g1-A
B1-public|public-point=beta1|result=authenticated-g1-B1-base
B2-public|public-point=beta2|result=authenticated-g2-B2
temporary|compressed-query-bytes|captured=no|coverage=query-store-preimage-and-source
temporary|decoded-public-point-chunk|captured=no|coverage=query-store-preimage-and-source
temporary|point-map-share-and-mac|captured=no|coverage=executable-linear-reconstruction
temporary|worker-partial|captured=no|coverage=executable-linear-reconstruction
temporary|running-query-sum|captured=no|coverage=executable-linear-reconstruction
peer-effect|financial-local-query-schedule|captured=player-transport
local-effect|public-stage-callback-label-and-time|captured=no|coverage=unmodeled
)MANIFEST";

// sha256(CORRESPONDENCE_MANIFEST), asserted by the source control. Its source
// file is part of the selected build closure; the runtime authority separately
// binds model/query-store preimages and the scalar call-site manifest.
inline constexpr std::string_view CORRESPONDENCE_MANIFEST_SHA256 =
    "7cd5956c8a30da0d9bf2e040b1d67b83ffd516a211aba8d08985c6ecdae13ace";

template<class Group, class Scalar, class Map>
auto deterministic_worker_sum(
        std::span<const Group> points,
        std::span<const Scalar> scalars,
        std::size_t workers,
        std::size_t maximum_chunk,
        Map&& map) {
    using Result = std::remove_cvref_t<decltype(
        map(std::declval<const Group&>(), std::declval<const Scalar&>()))>;
    if (points.size() != scalars.size() || points.empty() ||
        points.size() > maximum_chunk || workers == 0)
        throw std::runtime_error("financial-local-point-chunk-shape");
    const auto count = std::min(workers, points.size());
    std::vector<std::future<Result>> partials;
    partials.reserve(count);
    for (std::size_t worker = 0; worker < count; ++worker) {
        const auto first = points.size() * worker / count;
        const auto last = points.size() * (worker + 1) / count;
        partials.push_back(std::async(
            std::launch::async,
            [points, scalars, first, last, &map] {
                Result result;
                for (std::size_t index = first; index < last; ++index)
                    result += map(points[index], scalars[index]);
                return result;
            }));
    }
    Result total;
    for (auto& partial : partials) total += partial.get();
    return total;
}

} // namespace kpi::mpc::financial::query_msm
