#pragma once
#include "auth_groups.hpp"
#include "proof_codec.hpp"

namespace kpi::mpc {
struct AdmittedProvingKey {
    G1Value alpha, beta1, delta1;
    G2Value beta2, delta2;
    std::vector<G1Value> a_query, b1_query, l_query, h_query_padded;
    std::vector<G2Value> b2_query;
};

AdmittedProvingKey admit_proving_key(const PublicModel& model);
// full_assignment is the SAME authenticated, extended assignment used for the
// complete R1CS validity check and QAP. This API does not accept WTNS files or
// a clear combined-witness dealer. The initial model's public prefix is toy-only.
ProofPublic prove(MascotContext& ctx, const PublicModel& model,
                  const AdmittedProvingKey& key,
                  std::span<const AuthScalar> full_assignment);
}  // namespace kpi::mpc
