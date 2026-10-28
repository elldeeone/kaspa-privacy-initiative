#include "auth_groth16.hpp"
#include "auth_fft.hpp"

namespace kpi::mpc {
namespace {
std::vector<G1Value> admit_g1_query(const std::vector<AffinePoint>& points) {
    std::vector<G1Value> result;
    result.reserve(points.size());
    for (const auto& point : points) result.push_back(G1Value::admit(point, true));
    return result;
}
std::vector<G2Value> admit_g2_query(const std::vector<AffinePoint>& points) {
    std::vector<G2Value> result;
    result.reserve(points.size());
    for (const auto& point : points) result.push_back(G2Value::admit(point, true));
    return result;
}
}

// Only the final A opening is released through this implementation-private
// accessor. Auxiliary B1 has no serializer or caller-facing public result.
struct FinalProofAccess {
    static G1Value a(const G1ServerOpened& point) { return point.point_; }
};

AdmittedProvingKey admit_proving_key(const PublicModel& model) {
    validate_public_model(model);
    initialize_bn254_groups();
    const size_t variables = model.num_instance + model.num_private;
    if (model.a_query.size() != variables || model.b_g1_query.size() != variables ||
        model.b_g2_query.size() != variables || model.l_query.size() != model.num_private ||
        model.h_query.size() + 1 != model.domain.n)
        throw std::invalid_argument("Groth16 proving-key query dimensions");
    AdmittedProvingKey result{
        G1Value::admit(model.alpha_g1, false),
        G1Value::admit(model.beta_g1, false),
        G1Value::admit(model.delta_g1, false),
        G2Value::admit(model.beta_g2, false),
        G2Value::admit(model.delta_g2, false),
        admit_g1_query(model.a_query), admit_g1_query(model.b_g1_query),
        admit_g1_query(model.l_query), admit_g1_query(model.h_query),
        admit_g2_query(model.b_g2_query)};
    // The selected LibSnark H-map has N coefficients and the original key has
    // exactly N-1 H points. Preserve the documented tail-times-identity algebra
    // explicitly; every MSM below has equal-length vectors.
    result.h_query_padded.emplace_back();
    if (result.h_query_padded.size() != model.domain.n)
        throw std::invalid_argument("LibSnark H padding policy");
    return result;
}

ProofPublic prove(MascotContext& ctx, const PublicModel& model,
                  const AdmittedProvingKey& key,
                  std::span<const AuthScalar> full_assignment) {
    if (full_assignment.size() != model.num_instance + model.num_private)
        throw std::invalid_argument("Groth16 full-assignment dimension");
    ctx.agree_public_bytes("Groth16-public-model", model.encoded_model);

    // libsnark_h FIRST evaluates every R1CS row using this same authenticated
    // assignment and reveals only the exact aggregate validity bit. It refuses
    // an invalid extended witness before any proof-related group opening.
    const auto h = libsnark_h(ctx, model, full_assignment);
    if (h.size() != model.domain.n || key.h_query_padded.size() != h.size())
        throw std::invalid_argument("LibSnark H-map dimension");
    const auto r = ctx.random_auth();
    const auto s = ctx.random_auth();
    const std::array<AuthScalar, 1> r_vector{r}, s_vector{s};
    const auto rs = ctx.multiply_batch(r_vector, s_vector).at(0);
    ctx.report_public_phase("authenticated-proof-masks-derived");
    GroupMacSetup group_checks(ctx.player());
    ctx.report_public_phase("group-MAC-coordinators-ready");

    auto a = msm_g1(key.a_query, full_assignment);
    a += public_point_map(key.delta1, r);
    add_public(a, key.alpha, ctx);
    auto b1 = msm_g1(key.b1_query, full_assignment);
    b1 += public_point_map(key.delta1, s);
    add_public(b1, key.beta1, ctx);
    auto b2 = msm_g2(key.b2_query, full_assignment);
    b2 += public_point_map(key.delta2, s);
    add_public(b2, key.beta2, ctx);
    const auto private_assignment = full_assignment.subspan(model.num_instance);
    const auto l = msm_g1(key.l_query, private_assignment);
    const auto h_group = msm_g1(key.h_query_padded, h);

    // The selected established formula opens masked A and auxiliary B1 to the
    // computing servers. Scalar and BOTH point authentication checks complete
    // before these points can be multiplied with secret masks. A colluding
    // server still sees B1; this functional gate is not a privacy qualification.
    const auto [opened_a, opened_b1] = open_checked_g1_pair(ctx, a, b1);
    ctx.report_public_phase("masked-A-and-B1-MAC-checked");
    AuthG1 c = server_opened_point_map(opened_a, s);
    c += server_opened_point_map(opened_b1, r);
    c -= public_point_map(key.delta1, rs);
    c += l;
    c += h_group;
    const auto [opened_c, opened_b2] = open_checked_g1_g2(ctx, c, b2);
    ctx.report_public_phase("final-B2-and-C-MAC-checked");
    ProofPublic result{FinalProofAccess::a(opened_a), opened_b2, opened_c};
    // Strict final-role admission and canonical codec roundtrip. Independent
    // Ark verification remains mandatory before a caller publishes a result.
    const auto encoded = encode_native_proof(result);
    const auto roundtrip = decode_native_proof(encoded);
    if (result.a != roundtrip.a || result.b != roundtrip.b || result.c != roundtrip.c)
        throw std::runtime_error("Native128 proof roundtrip");
    ctx.agree_public_bytes("Groth16-complete-proof", encoded);
    ctx.check_field_pending();
    return result;
}
}  // namespace kpi::mpc
