#pragma once
#include "auth_field.hpp"
#include <filesystem>

namespace kpi::mpc {
struct FftPlan {
    size_t n;
    Fr omega;
    Fr omega_inverse;
    Fr inv_n;
    Fr coset_shift;
};

struct SparseTerm {
    size_t index;
    Fr coefficient;
};
using SparseRow = std::vector<SparseTerm>;

// Public affine coordinates only. G1 has one coefficient per coordinate;
// G2 uses Fq2 coefficients c0,c1. Group admission remains role-specific.
struct AffinePoint {
    bool infinity;
    std::vector<std::string> x;
    std::vector<std::string> y;
};

struct PublicModel {
    size_t num_instance;
    size_t num_private;
    size_t num_constraints;
    FftPlan domain;
    std::vector<Fr> public_inputs;  // Toy only: includes ONE. Never early NFs.
    std::vector<SparseRow> A, B, C;
    AffinePoint alpha_g1, beta_g1, beta_g2, delta_g1, delta_g2;
    std::vector<AffinePoint> a_query, b_g1_query, b_g2_query, l_query, h_query;
    std::string source_identity;
    std::string model_identity;
    std::string proving_key_identity;
    std::string verifying_key_identity;
    std::string verifying_key_hex;
    std::vector<unsigned char> encoded_model;
};

PublicModel load_public_model(const std::filesystem::path& path);
PublicModel parse_public_model(std::span<const unsigned char> encoded);
void validate_public_model(const PublicModel& model);
}  // namespace kpi::mpc
