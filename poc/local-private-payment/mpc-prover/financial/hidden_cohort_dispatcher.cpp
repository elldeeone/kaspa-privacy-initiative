#include "hidden_cohort_dispatcher.hpp"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <utility>

namespace kpi::mpc::financial::hidden_cohort {
namespace {
constexpr std::string_view MODEL =
    "f3ca3c18f17ed8175fa420364e9aa2824a12af4320ca1dc00ba2508f60ba28ff";
constexpr std::string_view SOURCE =
    "3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829";
constexpr std::string_view TRACE =
    "4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e";
constexpr std::string_view LAYOUT =
    "9a3ee5f5eb98384273e2b608f71a60f89c49e6fc9c1029586f8f201b84617e1e";
constexpr std::string_view RECIPE =
    "ef6279fa5633c77230a8a8b8ae9b70a58770a30e6c6f5e0bcf97edba0d0e0edb";

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(), [](auto byte) { return byte != 0; });
}
void validate(const Selection& value) {
    need(nonzero(value.attempt) && nonzero(value.cohort) &&
         value.attempt != value.cohort && value.masked_frame_bytes > 0 &&
         value.masked_frame_bytes <= std::numeric_limits<std::size_t>::max() / 3);
    std::set<Digest> certificates(value.owner_certificates.begin(),
                                  value.owner_certificates.end());
    need(certificates.size() == 3 &&
         std::all_of(certificates.begin(), certificates.end(), nonzero));
    const auto& p = value.permutation;
    need(p.model == MODEL && p.source == SOURCE && p.trace == TRACE &&
         p.layout == LAYOUT && p.recipe == RECIPE && p.random_bits == 768 &&
         p.input_rows == 3 && p.output_rows == 6 && p.nf_sort_private &&
         p.output_sort_private && !p.dispatcher_chosen);
}
std::string hex(const Digest& value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : value) out << std::setw(2) << unsigned(byte);
    return out.str();
}
std::string invariant(const Selection& selection, const Digest& aggregate) {
    // This contains no input body, owner order, upload handle or per-owner
    // commitment. The reviewed integration must replace this source-only
    // binding with the registered construction and verified-release identity.
    return std::string("KPB_HIDDEN_COHORT_AGGREGATE_V1\n") +
        hex(selection.attempt) + "\n" + hex(selection.cohort) + "\n" +
        selection.permutation.model + "\n" + selection.permutation.trace +
        "\n" + hex(aggregate) + "\n";
}
}

Dispatcher::Dispatcher(Selection selection) : selection_(std::move(selection)) {
    validate(selection_);
    capture_.attempt = selection_.attempt;
    capture_.cohort = selection_.cohort;
    capture_.ingress_route = std::string(COMMON_INGRESS_ROUTE);
    capture_.owner_mapping_exported = false;
    capture_.public_slot_association_exported = false;
    capture_.filenames_exported = false;
    capture_.per_owner_release_routes = 0;
}

void Dispatcher::admit(Ingress value) {
    need(!sealed_ && value.owner_role >= 0 && value.owner_role < 3 &&
         value.owner_certificate == selection_.owner_certificates.at(value.owner_role) &&
         value.attempt == selection_.attempt && value.cohort == selection_.cohort &&
         value.connection_ordinal == capture_.connection_order.size() &&
         value.attempt_ordinal == 0 && value.route == COMMON_INGRESS_ROUTE &&
         !value.retry && value.opaque_masked_frame.size() == selection_.masked_frame_bytes &&
         !by_role_.at(value.owner_role).has_value());
    need(std::find(capture_.connection_order.begin(), capture_.connection_order.end(),
                   value.owner_role) == capture_.connection_order.end());
    capture_.connection_order.push_back(value.owner_role);
    capture_.upload_order.push_back(value.owner_role);
    capture_.observed_lengths.push_back(value.opaque_masked_frame.size());
    by_role_.at(value.owner_role).emplace(std::move(value.opaque_masked_frame));
}

SealedCohort Dispatcher::seal() {
    need(!sealed_ && capture_.connection_order.size() == 3 &&
         capture_.upload_order.size() == 3 &&
         std::all_of(by_role_.begin(), by_role_.end(),
                     [](const auto& value) { return value.has_value(); }));
    sealed_ = true;
    std::array<std::vector<unsigned char>, 3> bodies;
    for (std::size_t role = 0; role < bodies.size(); ++role)
        bodies[role] = std::move(*by_role_[role]);
    return SealedCohort(std::move(selection_), std::move(bodies),
                        std::move(capture_));
}

SealedCohort::SealedCohort(Selection selection,
                           std::array<std::vector<unsigned char>, 3> bodies,
                           PublicCapture capture)
    : selection_(std::move(selection)), by_role_(std::move(bodies)),
      capture_(std::move(capture)) {}

AggregateRelease SealedCohort::release_unlabelled_aggregate(
    const Digest& aggregate_identity) {
    need(!released_ && nonzero(aggregate_identity));
    released_ = true;
    return AggregateRelease{
        .aggregate_identity = aggregate_identity,
        .route = std::string(COMMON_AGGREGATE_ROUTE),
        .invariant_identity = invariant(selection_, aggregate_identity),
        .release_count = 1,
        .owner_mapping_exported = false,
    };
}

SourceStatus source_status() {
    return SourceStatus{
        .schema = "kpb-hidden-cohort-dispatcher-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .authenticated_mpc_integration = false,
        .registered_driver_integration = false,
        .launch_authorized = false,
        .privacy_qualified = false,
    };
}

} // namespace kpi::mpc::financial::hidden_cohort
