#include "native_terminal_projection_intake_bridge.hpp"

#include "native_terminal_completion.hpp"
#include "native_terminal_mapping_source.hpp"
#include "../mpc-prover/financial/baseline_public_effects_collector.hpp"
#include "../mpc-prover/financial/registered_projection_route.hpp"

#include <algorithm>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <vector>

namespace kpb::native_terminal {
namespace {

namespace registered = kpi::mpc::financial::registered_driver;
namespace route = registered::projection_route;
namespace baseline = registered::baseline_disclosure;
using Classification = registered::CaptureClassification;
using Digest = std::array<unsigned char, 32>;
using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw capture::CaptureRefused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

std::string hex(const Digest& value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 0x0f]);
    }
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest hash(std::span<const std::byte> value) {
    return hash({reinterpret_cast<const unsigned char*>(value.data()),
                 value.size()});
}

void add(Bytes& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void little(Bytes& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

void add_plan(Bytes& out, const route::PublicProjectionRoutePlan& value) {
    little(out, static_cast<std::uint8_t>(value.classification));
    little(out, value.round); little(out, value.computing_role);
    for (const auto* field : {
             &value.trial, &value.attempt, &value.cohort,
             &value.financial_run, &value.capture_plan_identity,
             &value.producer_process_authority,
             &value.producer_exit_authority,
             &value.dispatcher_process_authority,
             &value.dispatcher_exit_authority})
        add(out, *field);
}

Digest retained_identity(
        const route::PublicProjectionRoutePlan& plan,
        const Digest& route_identity, const Digest& fork_binding,
        const Digest& projection_identity,
        std::span<const std::byte> projection) {
    Bytes bytes;
    static constexpr std::string_view domain =
        "KPB_PARENT_RETAINED_PUBLIC_PROJECTION_V1\n";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    add_plan(bytes, plan); add(bytes, route_identity);
    add(bytes, fork_binding); add(bytes, projection_identity);
    bytes.insert(bytes.end(),
                 reinterpret_cast<const unsigned char*>(projection.data()),
                 reinterpret_cast<const unsigned char*>(projection.data()) +
                     projection.size());
    return hash(bytes);
}

bool receipt_matches_plan(
        const route::PublicRetainedProjectionReceipt& receipt,
        const route::PublicProjectionRoutePlan& plan) {
    return receipt.round == plan.round && receipt.trial == plan.trial &&
        receipt.attempt == plan.attempt && receipt.cohort == plan.cohort &&
        receipt.financial_run == plan.financial_run &&
        receipt.producer_process_authority ==
            plan.producer_process_authority &&
        receipt.producer_exit_authority == plan.producer_exit_authority &&
        receipt.dispatcher_process_authority ==
            plan.dispatcher_process_authority &&
        receipt.dispatcher_exit_authority ==
            plan.dispatcher_exit_authority &&
        receipt.exact_size && receipt.read_complete && receipt.kernel_eof &&
        receipt.clean;
}

void validate_common(
        const route::PublicRetainedProjectionReceipt& receipt,
        const route::PublicProjectionRoutePlan& plan,
        std::span<const std::byte> projection,
        const Digest& projection_identity, const Digest& route_identity,
        const Digest& retained, const Digest& fork_binding,
        const PaymentTerminalSelection& selected,
        Classification expected_classification) {
    const auto round = selected.native.ordinal;
    need((round == 1 || round == 2) &&
         plan.classification == expected_classification &&
         plan.round == round && plan.computing_role == 0 &&
         receipt_matches_plan(receipt, plan) &&
         plan.trial == selected.native.trial &&
         plan.trial == selected.producer_binding.trial &&
         plan.attempt == selected.producer_binding.attempt &&
         plan.cohort == selected.producer_binding.round_cohorts[round - 1] &&
         plan.financial_run ==
             selected.producer_binding.financial_runs[round - 1] &&
         plan.capture_plan_identity ==
             selected.producer_binding.round_capture_plans[round - 1] &&
         selected.capture_binding.construction_classification ==
             static_cast<unsigned>(expected_classification) &&
         selected.capture_binding.construction_attempt_sha256 ==
             hex(plan.attempt) &&
         selected.capture_binding.capture_plan_sha256 ==
             hex(plan.capture_plan_identity) &&
         selected.capture_binding.projection_sha256 ==
             hex(projection_identity) &&
         projection_identity == selected.native.projection &&
         projection_identity == hash(projection) &&
         nonzero(route_identity) && nonzero(retained) &&
         nonzero(fork_binding) && retained == retained_identity(
             plan, route_identity, fork_binding, projection_identity,
             projection));
    for (const auto* field : {
             &plan.producer_process_authority,
             &plan.producer_exit_authority,
             &plan.dispatcher_process_authority,
             &plan.dispatcher_exit_authority})
        need(nonzero(*field));
}

} // namespace

NativeTerminalChildProjectionEvidence
NativeTerminalProjectionIntake::consume_candidate(
        route::NativeTerminalRetainedProjectionAuthority&& authority,
        const PaymentTerminalSelection& selected) {
    need(authority.live_.exchange(false));
    validate_common(
        authority.receipt_, authority.plan_, authority.projection_,
        authority.projection_identity_, authority.route_identity_,
        authority.retained_identity_, authority.fork_binding_identity_,
        selected, Classification::HiddenCandidate);
    need(selected.producer_binding.classification ==
         measurement::Classification::HiddenCandidate);
    NativeTerminalChildProjectionEvidence result;
    result.projection = authority.projection_;
    result.projection_identity = authority.projection_identity_;
    result.retained_identity = authority.retained_identity_;
    result.fork_binding_identity = authority.fork_binding_identity_;
    result.round = authority.plan_.round;
    result.classification = authority.plan_.classification;
    result.owner_mapping_present = false;
    result.intake_identity = recompute_intake_identity(
        result, selected.native.trial,
        selected.native.outer_parent_process,
        selected.native.outer_parent_executable);
    need(nonzero(result.intake_identity));
    return result;
}

NativeTerminalChildProjectionEvidence
NativeTerminalProjectionIntake::consume_baseline(
        route::NativeTerminalRetainedProjectionAuthority&& authority,
        baseline::BaselineTerminalOwnerMappingAuthority&& mapping,
        const PaymentTerminalSelection& selected) {
    const bool route_live = authority.live_.exchange(false);
    const bool mapping_live = mapping.live_.exchange(false);
    need(route_live && mapping_live);
    validate_common(
        authority.receipt_, authority.plan_, authority.projection_,
        authority.projection_identity_, authority.route_identity_,
        authority.retained_identity_, authority.fork_binding_identity_,
        selected,
        Classification::ExplicitOwnerPublicEffectsBaseline);
    need(selected.producer_binding.classification ==
         measurement::Classification::TransparentBaseline);
    const auto& value = mapping.value_;
    const auto& plan = authority.plan_;
    const auto context_identity = hash(std::span<const std::byte>{
        authority.projection_.data() + 193 + 8, 276});
    need(value.status == "EXPLICIT_OWNER_PUBLIC_EFFECTS" &&
         value.classification == plan.classification &&
         value.round == plan.round && value.run == plan.financial_run &&
         value.trial == plan.trial && value.attempt == plan.attempt &&
         value.cohort == plan.cohort &&
         value.capture_plan_identity == plan.capture_plan_identity &&
         value.projection_identity == authority.projection_identity_ &&
         value.context_identity == context_identity &&
         nonzero(value.receipt_identity));
    NativeTerminalChildProjectionEvidence result;
    result.projection = authority.projection_;
    result.projection_identity = authority.projection_identity_;
    result.retained_identity = authority.retained_identity_;
    result.fork_binding_identity = authority.fork_binding_identity_;
    result.owner_mapping_authority_identity = value.receipt_identity;
    result.round = authority.plan_.round;
    result.classification = authority.plan_.classification;
    result.owner_mapping_present = true;
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto& row = value.owner_effects[owner];
        need(row.owner == owner && nonzero(row.owner_contract_identity) &&
             nonzero(row.public_nullifier) &&
             nonzero(row.public_tuple_hashes[0]) &&
             nonzero(row.public_tuple_hashes[1]) &&
             row.public_tuple_hashes[0] != row.public_tuple_hashes[1]);
        result.owner_nullifiers[owner] = row.public_nullifier;
        result.owner_tuple_hashes[owner] = row.public_tuple_hashes;
    }
    result.intake_identity = recompute_intake_identity(
        result, selected.native.trial,
        selected.native.outer_parent_process,
        selected.native.outer_parent_executable);
    need(nonzero(result.intake_identity));
    return result;
}

} // namespace kpb::native_terminal
