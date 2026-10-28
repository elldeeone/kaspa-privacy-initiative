#pragma once
#include "bn254_values.hpp"

namespace kpi::mpc {
using AuthG1 = Share<G1Value>;
using AuthG2 = Share<G2Value>;

// Stock MAC checkers require one coordinator per authenticated value type.
// Keep both alive through every group opening and destroy them only after the
// local Direct_MC instances have completed and been destroyed.
class GroupMacSetup {
public:
    explicit GroupMacSetup(Player& player);
    ~GroupMacSetup();
    GroupMacSetup(const GroupMacSetup&) = delete;
    GroupMacSetup& operator=(const GroupMacSetup&) = delete;
};

// These wrappers carry checked SERVER-INTERNAL openings. There is deliberately
// no serializer/coordinate accessor or implicit conversion to a public point.
class G1ServerOpened {
    G1Value point_;
    explicit G1ServerOpened(G1Value point) : point_(std::move(point)) {}
    friend std::pair<G1ServerOpened, G1ServerOpened> open_checked_g1_pair(MascotContext&, const AuthG1&, const AuthG1&);
    friend AuthG1 server_opened_point_map(const G1ServerOpened&, const AuthScalar&);
    friend struct FinalProofAccess;
};

AuthG1 public_point_map(const G1Value& point, const AuthScalar& scalar);
AuthG2 public_point_map(const G2Value& point, const AuthScalar& scalar);
AuthG1 server_opened_point_map(const G1ServerOpened& point, const AuthScalar& scalar);
AuthG1 msm_g1(std::span<const G1Value> points, std::span<const AuthScalar> scalars);
AuthG2 msm_g2(std::span<const G2Value> points, std::span<const AuthScalar> scalars);
void add_public(AuthG1& accumulator, const G1Value& point, const MascotContext& ctx);
void add_public(AuthG2& accumulator, const G2Value& point, const MascotContext& ctx);
std::pair<G1ServerOpened, G1ServerOpened> open_checked_g1_pair(MascotContext& ctx,
                                                          const AuthG1& first,
                                                          const AuthG1& second);
std::pair<G1Value, G2Value> open_checked_g1_g2(MascotContext& ctx,
                                            const AuthG1& first,
                                            const AuthG2& second);
}  // namespace kpi::mpc
