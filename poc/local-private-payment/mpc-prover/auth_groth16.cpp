#include "auth_groth16.hpp"
#include "auth_fft.hpp"
#include "batched_assignment.hpp"
#include "p1_capture_seams.hpp"

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

namespace {
ProofPublic complete_from_h(MascotContext& ctx, const PublicModel& model,
                            const AdmittedProvingKey& key,
                            std::span<const AuthScalar> full_assignment,
                            std::span<const AuthScalar> h) {
    if (h.size() != model.domain.n || key.h_query_padded.size() != h.size())
        throw std::invalid_argument("LibSnark H-map dimension");
    const auto r = ctx.random_auth(
        p1_capture::ScalarCaptureSite::ToyProofMaskR);
    const auto s = ctx.random_auth(
        p1_capture::ScalarCaptureSite::ToyProofMaskS);
    ctx.report_public_phase("authenticated-proof-masks-derived");
    GroupMacSetup group_checks(ctx.player());
    ctx.report_public_phase("group-MAC-coordinators-ready");

    auto a = msm_g1(key.a_query, full_assignment);
    a += public_point_map(key.delta1, r);
    add_public(a, key.alpha, ctx);
    // Appendix-E B1_base excludes s*delta. C then needs exactly the two
    // established secret scalar-group products s*A and r*B1_base.
    auto b1_base = msm_g1(key.b1_query, full_assignment);
    add_public(b1_base, key.beta1, ctx);
    auto b2 = msm_g2(key.b2_query, full_assignment);
    b2 += public_point_map(key.delta2, s);
    add_public(b2, key.beta2, ctx);
    const auto private_assignment = full_assignment.subspan(model.num_instance);
    const auto l = msm_g1(key.l_query, private_assignment);
    const auto h_group = msm_g1(key.h_query_padded, h);
    // Canonical algebraic order, independent of construction scheduling.
    const std::array<AuthG1, 4> base_group_state{{a, b1_base, l, h_group}};
    if (auto* capture = ctx.p1_capture_seams())
        capture->proof_base_group_state(base_group_state, b2);

    const std::array<AuthG1, 2> secret_groups{a, b1_base};
    const std::array<AuthScalar, 2> secret_scalars{s, r};
    const auto products = secret_scalar_g1_products(
        ctx, group_checks, secret_groups, secret_scalars);
    ctx.report_public_phase("masked-secret-G1-products-MAC-checked");
    AuthG1 c = products[0];
    c += products[1];
    c += l;
    c += h_group;
    const auto opened = open_final_groth16(ctx, group_checks, a, b2, c);
    ctx.report_public_phase("final-A-B2-C-MAC-checked");
    ProofPublic result{opened.a, opened.b, opened.c};
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
}  // namespace

ProofPublic prove(MascotContext& ctx, const PublicModel& model,
                  const AdmittedProvingKey& key,
                  std::span<const AuthScalar> full_assignment,
                  std::span<const AuthScalar> additional_private_residuals) {
    try {
    if (full_assignment.size() != model.num_instance + model.num_private)
        throw std::invalid_argument("Groth16 full-assignment dimension");
    ctx.agree_public_bytes("Groth16-public-model", model.encoded_model);
    // The independently qualified toy API always retains its exact check.
    const auto h = libsnark_h(ctx, model, full_assignment, additional_private_residuals);
    return complete_from_h(ctx, model, key, full_assignment, h);
    } catch (...) {
        ctx.poison();
        throw;
    }
}

ProofPublic prove_validated(MascotContext& ctx, ValidatedAssignment&& validated,
                           const BatchedValidationBinding& expected) {
    try {
        validated.consume_for_proof(ctx, expected);
        const auto& model = validated.model_;
        ctx.agree_public_bytes("Groth16-validated-immutable-model", model.encoded_model);
        const auto h = validated.make_h_map(ctx);
        const auto key = admit_proving_key(model);
        return complete_from_h(ctx, model, key, validated.assignment_, h);
    } catch (...) {
        ctx.poison();
        throw;
    }
}
}  // namespace kpi::mpc
