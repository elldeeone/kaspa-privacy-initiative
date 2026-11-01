#include "packed_assignment.hpp"
#include "../auth_groups.hpp"
#include "../p1_capture_seams.hpp"
#include <array>

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
        const auto r = context.random_auth(
            p1_capture::ScalarCaptureSite::PackedProofMaskR);
        const auto s = context.random_auth(
            p1_capture::ScalarCaptureSite::PackedProofMaskS);
        const auto delta1 = model.base_g1(packed::BaseG1::Delta);
        const auto delta2 = model.base_g2(packed::BaseG2::Delta);
        auto a = query_g1(model, packed::Query::A, assignment);
        a += public_point_map(delta1, r);
        add_public(a, model.base_g1(packed::BaseG1::Alpha), context);
        auto b1_base = query_g1(model, packed::Query::B1, assignment);
        add_public(b1_base, model.base_g1(packed::BaseG1::Beta), context);
        auto b2 = query_g2(model, assignment);
        b2 += public_point_map(delta2, s);
        add_public(b2, model.base_g2(packed::BaseG2::Beta), context);
        const auto l = query_g1(model, packed::Query::L,
            assignment.subspan(static_cast<size_t>(metadata.instances)));
        const auto h_point = query_g1(model, packed::Query::H, h);
        model.check_backing_unchanged();
        GroupMacSetup group_checks(context.player());
        context.report_public_phase("packed-group-MAC-coordinators-ready");
        // Canonical algebraic order, independent of query scheduling.
        const std::array<AuthG1, 4> base_group_state{{
            a, b1_base, l, h_point}};
        if (auto* capture = context.p1_capture_seams())
            capture->proof_base_group_state(base_group_state, b2);
        const std::array<AuthG1, 2> secret_groups{a, b1_base};
        const std::array<AuthScalar, 2> secret_scalars{s, r};
        const auto products = secret_scalar_g1_products(
            context, group_checks, secret_groups, secret_scalars);
        context.report_public_phase("packed-masked-secret-G1-products-MAC-checked");
        auto c = products[0];
        c += products[1];
        c += l;
        c += h_point;
        const auto opened = open_final_groth16(
            context, group_checks, a, b2, c);
        context.report_public_phase("packed-final-A-B2-C-MAC-checked");
        ProofPublic result{opened.a, opened.b, opened.c};
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
