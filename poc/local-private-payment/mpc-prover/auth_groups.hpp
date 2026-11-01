#pragma once
#include "bn254_values.hpp"
#include "financial/financial_assignment.hpp"

namespace kpi::mpc {
using AuthG1 = Share<G1Value>;
using AuthG2 = Share<G2Value>;
struct FinalGroth16Opening;
class GroupMacSetup;

// Only the selected durable financial assignment may authorize P1 capture of
// the final A/B2/C opening. Toy and public-fixture paths remain valid without
// capture but cannot turn this generic group opener into a private-data sink.
class FinalGroth16CaptureAuthority final {
    MascotContext* context_;
    std::uint64_t generation_;
    std::uint64_t failure_epoch_;
    bool active_;

    explicit FinalGroth16CaptureAuthority(MascotContext&);
    friend class financial::FinancialValidatedAssignment;
    friend class GroupMacSetup;
public:
    ~FinalGroth16CaptureAuthority();
    FinalGroth16CaptureAuthority(FinalGroth16CaptureAuthority&&) noexcept;
    FinalGroth16CaptureAuthority(const FinalGroth16CaptureAuthority&) = delete;
    FinalGroth16CaptureAuthority& operator=(
        const FinalGroth16CaptureAuthority&) = delete;
    FinalGroth16CaptureAuthority& operator=(
        FinalGroth16CaptureAuthority&&) = delete;
};

// Stock MAC checkers require one coordinator per authenticated value type.
// Keep both alive through every group opening and destroy them only after the
// local Direct_MC instances have completed and been destroyed.
class GroupMacSetup {
    Player* player_;
    void require_bound(MascotContext& context) const;
    FinalGroth16Opening open_final(
        MascotContext&, const AuthG1&, const AuthG2&, const AuthG1&,
        FinalGroth16CaptureAuthority*);
    friend std::array<AuthG1, 2> secret_scalar_g1_products(
        MascotContext&, GroupMacSetup&, std::span<const AuthG1, 2>,
        std::span<const AuthScalar, 2>);
    friend FinalGroth16Opening open_final_groth16(
        MascotContext&, GroupMacSetup&, const AuthG1&, const AuthG2&,
        const AuthG1&);
    friend FinalGroth16Opening open_final_groth16(
        MascotContext&, GroupMacSetup&, const AuthG1&, const AuthG2&,
        const AuthG1&, FinalGroth16CaptureAuthority&&);
public:
    explicit GroupMacSetup(Player& player);
    ~GroupMacSetup();
    GroupMacSetup(const GroupMacSetup&) = delete;
    GroupMacSetup& operator=(const GroupMacSetup&) = delete;
};

// The only unmasked group-opening result exposed by this module. Callers can
// obtain it only after both group MAC checks and the pending scalar checks
// complete for the final Groth16 (A, B2, C) tuple.
struct FinalGroth16Opening {
    G1Value a;
    G2Value b;
    G1Value c;
};

AuthG1 public_point_map(const G1Value& point, const AuthScalar& scalar);
AuthG2 public_point_map(const G2Value& point, const AuthScalar& scalar);
AuthG1 msm_g1(std::span<const G1Value> points, std::span<const AuthScalar> scalars);
AuthG2 msm_g2(std::span<const G2Value> points, std::span<const AuthScalar> scalars);
void add_public(AuthG1& accumulator, const G1Value& point, const MascotContext& ctx);
void add_public(AuthG2& accumulator, const G2Value& point, const MascotContext& ctx);

// Smart--Alaoui/SPDZ scalar-group Beaver multiplication. Exactly two products
// are admitted because collaborative Groth16 requires s*A and r*B1_base.
// The only intermediate openings are fresh one-time-masked differences.
std::array<AuthG1, 2> secret_scalar_g1_products(
    MascotContext& context, GroupMacSetup& group_macs,
    std::span<const AuthG1, 2> groups,
    std::span<const AuthScalar, 2> scalars);

FinalGroth16Opening open_final_groth16(
    MascotContext& context, GroupMacSetup& group_macs,
    const AuthG1& a, const AuthG2& b, const AuthG1& c);
FinalGroth16Opening open_final_groth16(
    MascotContext& context, GroupMacSetup& group_macs,
    const AuthG1& a, const AuthG2& b, const AuthG1& c,
    FinalGroth16CaptureAuthority&& authority);
}  // namespace kpi::mpc
