#include "packed_assignment.hpp"
#include "../auth_groups.hpp"
#include <array>

namespace kpi::mpc {
// The same implementation-private friend as the qualified prover. Keeping the
// identical definition in this TU exposes no caller-facing point accessor.
struct FinalProofAccess {
    static G1Value a(const G1ServerOpened& point) { return point.point_; }
};
}

namespace kpi::mpc::financial {
namespace {
AuthG1 query_g1(const packed::PackedModel& model, packed::Query query,
                std::span<const AuthScalar> scalars) {
    const auto points = model.query_size(query);
    // LibSnark's final H coefficient multiplies the implicit identity. This
    // sole explicit padding rule is the same as the qualified old prover.
    if ((query == packed::Query::H && points + 1 != scalars.size()) ||
        (query != packed::Query::H && points != scalars.size()))
        throw std::runtime_error("packed-G1-query-assignment-arity");
    AuthG1 sum;
    for (uint64_t i = 0; i < points; ++i)
        sum += public_point_map(model.g1_query(query, i), scalars[static_cast<size_t>(i)]);
    return sum;
}

AuthG2 query_g2(const packed::PackedModel& model, std::span<const AuthScalar> scalars) {
    const auto points = model.query_size(packed::Query::B2);
    if (points != scalars.size()) throw std::runtime_error("packed-G2-query-assignment-arity");
    AuthG2 sum;
    for (uint64_t i = 0; i < points; ++i)
        sum += public_point_map(model.g2_query(i), scalars[static_cast<size_t>(i)]);
    return sum;
}
}

ProofPublic prove_packed_public_fixture(MascotContext& context,
    PackedValidatedAssignment&& validated, const BatchedValidationBinding& binding, size_t batch) {
    try {
        validated.consume_public_fixture(context, binding);
        const auto& model = validated.model_;
        const auto& metadata = model.metadata();
        const auto assignment = std::span<const AuthScalar>(validated.assignment_);
        const auto identity = model.identity();
        context.agree_public_bytes("packed-validated-immutable-model", {
            reinterpret_cast<const unsigned char*>(identity.data()), identity.size()});
        const auto h = validated.make_h_map(context, batch);
        const auto r = context.random_auth(), s = context.random_auth();
        const std::array<AuthScalar, 1> rv{r}, sv{s};
        const auto rs = context.multiply_batch(rv, sv).at(0);
        const auto delta1 = model.base_g1(packed::BaseG1::Delta);
        const auto delta2 = model.base_g2(packed::BaseG2::Delta);
        auto a = query_g1(model, packed::Query::A, assignment);
        a += public_point_map(delta1, r);
        add_public(a, model.base_g1(packed::BaseG1::Alpha), context);
        auto b1 = query_g1(model, packed::Query::B1, assignment);
        b1 += public_point_map(delta1, s);
        add_public(b1, model.base_g1(packed::BaseG1::Beta), context);
        auto b2 = query_g2(model, assignment);
        b2 += public_point_map(delta2, s);
        add_public(b2, model.base_g2(packed::BaseG2::Beta), context);
        const auto l = query_g1(model, packed::Query::L,
            assignment.subspan(static_cast<size_t>(metadata.instances)));
        const auto h_point = query_g1(model, packed::Query::H, h);
        model.check_backing_unchanged();
        GroupMacSetup group_checks(context.player());
        context.report_public_phase("packed-group-MAC-coordinators-ready");
        const auto [opened_a, opened_b1] = open_checked_g1_pair(context, a, b1);
        context.report_public_phase("packed-masked-A-and-B1-MAC-checked");
        auto c = server_opened_point_map(opened_a, s);
        c += server_opened_point_map(opened_b1, r);
        c -= public_point_map(delta1, rs);
        c += l;
        c += h_point;
        const auto [opened_c, opened_b2] = open_checked_g1_g2(context, c, b2);
        context.report_public_phase("packed-final-B2-and-C-MAC-checked");
        ProofPublic result{FinalProofAccess::a(opened_a), opened_b2, opened_c};
        const auto encoded = encode_native_proof(result);
        const auto decoded = decode_native_proof(encoded);
        if (decoded.a != result.a || decoded.b != result.b || decoded.c != result.c)
            throw std::runtime_error("packed-native-proof-roundtrip");
        context.agree_public_bytes("packed-complete-proof", encoded);
        context.check_field_pending();
        model.check_backing_unchanged();
        return result;
    } catch (...) {
        context.poison();
        throw;
    }
}
}  // namespace kpi::mpc::financial
