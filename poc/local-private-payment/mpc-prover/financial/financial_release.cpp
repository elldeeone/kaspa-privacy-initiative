#include "financial_assignment.hpp"
#include "construction.hpp"
#include "registered_driver_bridge.hpp"
#include "registered_capture_session.hpp"
#include "baseline_public_effects_collector.hpp"
#include "registered_projection_route_capture_bridge.hpp"
#include "registered_full_cohort_release_barrier_contract.hpp"
#include <algorithm>
#include <array>

#if defined(INSECURE) || defined(NDEBUG) || defined(KPI_HISTORY_UNFUNDED_SETUP)
#error "Financial release requires the persistent history bridge and normal checks"
#endif

namespace kpi::mpc::financial {
namespace {
using Bytes = std::vector<unsigned char>;
void append(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void integer(Bytes& out, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; ++i) out.push_back(static_cast<unsigned char>(value >> (8 * i)));
}
history::State successor_state(std::span<const unsigned char> core) {
    if (core.size() != FinancialConstruction::CORE_BYTES)
        throw std::runtime_error("financial-successor-core-shape");
    history::State state{};
    std::copy_n("KPBAST01", 8, state.begin());
    std::copy_n(core.begin() + 104, 32, state.begin() + 8);
    std::copy_n(core.begin() + 284, 32, state.begin() + 40);
    std::copy_n(core.begin() + 348, 4, state.begin() + 72);
    std::copy_n(core.begin() + 316, 32, state.begin() + 76);
    std::copy_n(core.begin() + 352, 4, state.begin() + 108);
    return state;
}
}

history::EgressRelease FinancialHistoryAccess::release_verified_impl(
    MascotContext& context, VerifiedFinancialProof&& verified,
    history::PreparedEpochTicket&& prepared,
    registered_driver::RegisteredCaptureSession* capture) {
    context.require_healthy();
    try {
        if (verified.egress_claimed_ || verified.context_ != &context ||
            verified.generation_ != context.generation() || verified.epoch_ != context.failure_epoch() ||
            prepared.binding_ != verified.attempt_ || prepared.effects() != verified.effects_ ||
            prepared.validated_binding() != verified.validation_identity_ ||
            prepared.construction_binding() != verified.construction_identity_)
            throw std::runtime_error("financial-verified-proof-release-binding");
        verified.construction_->require_live(context, verified.attempt_);
        verified.egress_claimed_ = true;
        const auto bits = verified.construction_->core_bits();
        if (bits.size() != FinancialConstruction::CORE_BIT_COUNT)
            throw std::runtime_error("financial-release-core-bit-shape");
        // These are exactly the immutable, already validated core bits. Pack
        // only linear combinations before the single checked core opening.
        std::vector<AuthScalar> packed;
        packed.reserve(FinancialConstruction::CORE_BYTES);
        for (size_t byte = 0; byte < FinancialConstruction::CORE_BYTES; ++byte) {
            AuthScalar value;
            for (size_t bit = 0; bit < 8; ++bit) value += bits[8 * byte + bit] * Fr(1 << bit);
            packed.push_back(std::move(value));
        }
        const auto opened = context.open_public_checked(packed);
        if (opened.size() != FinancialConstruction::CORE_BYTES)
            throw std::runtime_error("financial-release-core-byte-shape");
        Bytes core;
        core.reserve(opened.size());
        for (const auto& field : opened) {
            const bigint value(canonical_fr(field));
            if (value < 0 || value > 255) throw std::runtime_error("financial-release-byte-range");
            core.push_back(static_cast<unsigned char>(value.get_ui()));
        }
        if (history::digest(core) != verified.effects_)
            throw std::runtime_error("financial-release-core-effects-binding");
        const auto next = successor_state(core);
        const auto next_spk = history::reserve_spk(next, verified.construction_->native_tail());
        Bytes projection;
        projection.reserve(10685);
        const std::array<unsigned char, 12> tag{'K','P','B','A','F','X','0','1',1,0,1,0};
        append(projection, tag);
        append(projection, verified.attempt_.old_point);
        integer(projection, UINT64_MAX, 8);
        append(projection, std::span(core).subspan(276, 8));
        integer(projection, 37, 2);
        append(projection, verified.attempt_.old_spk);
        integer(projection, 1, 2);
        append(projection, std::span(core).subspan(356, 8));
        integer(projection, 37, 2);
        append(projection, next_spk);
        projection.insert(projection.end(), 37, 0); // Sigops, locktime, subnetwork, gas.
        integer(projection, FinancialConstruction::CORE_BYTES + 128, 4);
        if (projection.size() != 193) throw std::runtime_error("financial-projection-prefix-shape");
        append(projection, core);
        append(projection, verified.proof_);
        context.check_field_pending();
        context.report_public_phase("financial-core-MAC-checked-before-egress");
        // The private constructor fsyncs exact EGRESS on every role and then
        // authenticates all-three durable agreement before getters exist.
        return history::EgressRelease(context, std::move(prepared), core,
                                      verified.proof_, projection, capture);
    } catch (...) { context.poison(); throw; }
}

history::EgressRelease FinancialHistoryAccess::release_verified(
    MascotContext& context, VerifiedFinancialProof&& verified,
    history::PreparedEpochTicket&& prepared) {
    return release_verified_impl(context, std::move(verified),
                                 std::move(prepared), nullptr);
}

history::EgressRelease FinancialHistoryAccess::release_verified_registered(
    MascotContext& context, VerifiedFinancialProof&& verified,
    history::PreparedEpochTicket&& prepared) {
    auto& capture = verified.construction_->registered_capture_session();
    return release_verified_impl(context, std::move(verified),
                                 std::move(prepared), &capture);
}

registered_driver::PartyDriverCompletionAuthority
FinancialHistoryAccess::complete_registered_egress(
    MascotContext& context, const FinancialConstruction& construction,
    const history::EgressRelease& release) {
    context.require_healthy();
    try {
        construction.require_live(context, construction.attempt_);
        if (release.binding_identity() !=
            construction.locked_attempt().binding_identity())
            throw std::runtime_error(
                "registered-party-egress-construction-binding");
        return construction.registered_authority().complete_egress();
    } catch (...) { context.poison(); throw; }
}

void FinancialHistoryAccess::await_registered_release_barrier(
        MascotContext& context,
        const FinancialConstruction& construction,
        const history::EgressRelease& release,
        registered_driver::ChildRoleCompletionEndpointAuthority& endpoint) {
    context.require_healthy();
    try {
        construction.require_live(context, construction.attempt_);
        if (release.binding_identity() !=
            construction.locked_attempt().binding_identity())
            throw std::runtime_error(
                "registered-release-barrier-construction-binding");
        auto verified =
            registered_driver::VerifiedEgressAuthorityBridge::from_release(
                release);
        auto ready = construction.registered_authority()
            .begin_release_ready(std::move(verified));
        auto authorization =
            registered_driver::RegisteredFullCohortReleaseBarrier::
                arrive_and_wait(std::move(ready), endpoint);
        construction.registered_authority().authorize_release(
            std::move(authorization));
    } catch (...) { context.poison(); throw; }
}

void FinancialHistoryAccess::route_registered_projection(
        MascotContext& context,
        const FinancialConstruction& construction,
        const history::EgressRelease& release,
        registered_driver::projection_route::
            Role0ProjectionRouteWriterAuthority&& writer) {
    context.require_healthy();
    try {
        construction.require_live(context, construction.attempt_);
        if (release.binding_identity() !=
            construction.locked_attempt().binding_identity())
            throw std::runtime_error(
                "registered-projection-route-construction-binding");
        construction.registered_authority().require_release_authorized();
        registered_driver::RegisteredProjectionRouteCaptureBridge::consume(
            construction.registered_capture_session(), std::move(writer));
    } catch (...) { context.poison(); throw; }
}

registered_driver::baseline_disclosure::
PartyBaselineOwnerEffectsAuthority
FinancialHistoryAccess::baseline_owner_scoring(
        MascotContext& context,
        const FinancialConstruction& construction,
        const history::EgressRelease& release,
        fresh_owner_issuance::BaselineOwnerRosterReceiverAuthority&& roster) {
    auto verified = registered_driver::baseline_disclosure::
        BaselineDisclosureAuthorityBridge::from_registered_egress(
            construction, release);
    auto plan = registered_driver::baseline_disclosure::
        BaselineDisclosureAuthorityBridge::from_verified_egress(
            std::move(verified));
    return registered_driver::baseline_disclosure::
        AuthenticatedBaselineOwnerReceiver::receive(
            context, construction, release, std::move(plan),
            std::move(roster));
}
}  // namespace kpi::mpc::financial
