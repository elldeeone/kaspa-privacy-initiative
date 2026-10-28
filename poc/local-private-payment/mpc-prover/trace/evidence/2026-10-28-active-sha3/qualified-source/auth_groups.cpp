#include "auth_groups.hpp"
#include "Protocols/MAC_Check.hpp"

namespace kpi::mpc {
namespace {
template<class Group, class AuthGroup>
AuthGroup point_map(const Group& point, const AuthScalar& scalar) {
    point.check();
    AuthGroup out;
    out.set_share(point * scalar.get_share());
    out.set_mac(point * scalar.get_mac());
    return out;
}

template<class Group, class AuthGroup>
AuthGroup msm(std::span<const Group> points, std::span<const AuthScalar> scalars) {
    if (points.size() != scalars.size()) throw std::invalid_argument("authenticated MSM arity");
    AuthGroup result;
    for (size_t i = 0; i < points.size(); ++i)
        result += point_map<Group, AuthGroup>(points[i], scalars[i]);
    return result;
}
}

GroupMacSetup::GroupMacSetup(Player& player) {
    AuthG1::MAC_Check::setup(player);
    try {
        AuthG2::MAC_Check::setup(player);
    } catch (...) {
        AuthG1::MAC_Check::teardown();
        throw;
    }
}

GroupMacSetup::~GroupMacSetup() {
    AuthG2::MAC_Check::teardown();
    AuthG1::MAC_Check::teardown();
}

AuthG1 public_point_map(const G1Value& point, const AuthScalar& scalar) {
    return point_map<G1Value, AuthG1>(point, scalar);
}
AuthG2 public_point_map(const G2Value& point, const AuthScalar& scalar) {
    return point_map<G2Value, AuthG2>(point, scalar);
}
AuthG1 server_opened_point_map(const G1ServerOpened& point, const AuthScalar& scalar) {
    return public_point_map(point.point_, scalar);
}
AuthG1 msm_g1(std::span<const G1Value> points, std::span<const AuthScalar> scalars) {
    return msm<G1Value, AuthG1>(points, scalars);
}
AuthG2 msm_g2(std::span<const G2Value> points, std::span<const AuthScalar> scalars) {
    return msm<G2Value, AuthG2>(points, scalars);
}
void add_public(AuthG1& accumulator, const G1Value& point, const MascotContext& ctx) {
    point.check();
    accumulator += AuthG1::constant(point, ctx.party_id(), ctx.alpha_i());
}
void add_public(AuthG2& accumulator, const G2Value& point, const MascotContext& ctx) {
    point.check();
    accumulator += AuthG2::constant(point, ctx.party_id(), ctx.alpha_i());
}

std::pair<G1ServerOpened, G1ServerOpened> open_checked_g1_pair(MascotContext& ctx,
                                                          const AuthG1& first,
                                                          const AuthG1& second) {
    ctx.check_field_pending();
    typename AuthG1::Direct_MC checker(ctx.alpha_i());
    const std::vector<AuthG1> shares{first, second};
    std::vector<G1Value> opened;
    checker.POpen_Begin(opened, shares, ctx.player());
    checker.POpen_End(opened, shares, ctx.player());
    checker.Check(ctx.player());
    ctx.check_field_pending();
    if (opened.size() != 2) throw std::runtime_error("G1 opening arity");
    for (const auto& point : opened) point.check();
    return {G1ServerOpened(opened[0]), G1ServerOpened(opened[1])};
}

std::pair<G1Value, G2Value> open_checked_g1_g2(MascotContext& ctx,
                                            const AuthG1& first,
                                            const AuthG2& second) {
    ctx.check_field_pending();
    typename AuthG1::Direct_MC g1_checker(ctx.alpha_i());
    typename AuthG2::Direct_MC g2_checker(ctx.alpha_i());
    const std::vector<AuthG1> g1_shares{first};
    const std::vector<AuthG2> g2_shares{second};
    std::vector<G1Value> g1_opened;
    std::vector<G2Value> g2_opened;
    g1_checker.POpen_Begin(g1_opened, g1_shares, ctx.player());
    g1_checker.POpen_End(g1_opened, g1_shares, ctx.player());
    g2_checker.POpen_Begin(g2_opened, g2_shares, ctx.player());
    g2_checker.POpen_End(g2_opened, g2_shares, ctx.player());
    // Neither type is returned until BOTH group MAC checks and the pending
    // scalar checks succeed. No late final-verifier shortcut is allowed.
    g1_checker.Check(ctx.player());
    g2_checker.Check(ctx.player());
    ctx.check_field_pending();
    if (g1_opened.size() != 1 || g2_opened.size() != 1)
        throw std::runtime_error("mixed-group opening arity");
    g1_opened[0].check();
    g2_opened[0].check();
    return {g1_opened[0], g2_opened[0]};
}
}  // namespace kpi::mpc
