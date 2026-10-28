#include "financial_assignment.hpp"
#include "construction.hpp"
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

history::EgressRelease FinancialHistoryAccess::release_verified(MascotContext& context,
    VerifiedFinancialProof&& verified, history::PreparedEpochTicket&& prepared) {
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
        return history::EgressRelease(context, std::move(prepared), core, verified.proof_, projection);
    } catch (...) { context.poison(); throw; }
}
}  // namespace kpi::mpc::financial
