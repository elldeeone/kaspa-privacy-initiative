#pragma once
#include "public_model.hpp"

namespace kpi::mpc {
AuthScalar evaluate_linear(const SparseRow& row,
                           std::span<const AuthScalar> assignment);
void auth_fft(std::span<AuthScalar> values, const FftPlan& plan);
void auth_ifft(std::span<AuthScalar> values, const FftPlan& plan);
void scale_public(std::span<AuthScalar> values,
                  std::span<const Fr> coefficients);
void require_valid_assignment(MascotContext& context, const PublicModel& model,
                              std::span<const AuthScalar> assignment,
                              std::span<const AuthScalar> additional_private_residuals = {});
std::vector<AuthScalar> libsnark_h(MascotContext& context,
                                  const PublicModel& model,
                                  std::span<const AuthScalar> assignment,
                                  std::span<const AuthScalar> additional_private_residuals = {});
}  // namespace kpi::mpc
