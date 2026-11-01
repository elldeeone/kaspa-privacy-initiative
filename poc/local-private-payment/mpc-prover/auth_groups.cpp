#include "auth_groups.hpp"
#include "p1_capture_seams.hpp"
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

FinalGroth16CaptureAuthority::FinalGroth16CaptureAuthority(
        MascotContext& context)
    : context_(&context), generation_(context.generation()),
      failure_epoch_(context.failure_epoch()), active_(true) {}

FinalGroth16CaptureAuthority::FinalGroth16CaptureAuthority(
        FinalGroth16CaptureAuthority&& other) noexcept
    : context_(other.context_), generation_(other.generation_),
      failure_epoch_(other.failure_epoch_), active_(other.active_) {
    other.active_ = false;
}

FinalGroth16CaptureAuthority::~FinalGroth16CaptureAuthority() {
    if (active_ && context_ != nullptr) context_->poison();
}

GroupMacSetup::GroupMacSetup(Player& player) : player_(&player) {
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

void GroupMacSetup::require_bound(MascotContext& context) const {
    if (player_ == nullptr || player_ != &context.player()) {
        context.poison();
        throw std::runtime_error("group-MAC-setup-context-binding");
    }
}

AuthG1 public_point_map(const G1Value& point, const AuthScalar& scalar) {
    return point_map<G1Value, AuthG1>(point, scalar);
}
AuthG2 public_point_map(const G2Value& point, const AuthScalar& scalar) {
    return point_map<G2Value, AuthG2>(point, scalar);
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

namespace {
std::array<Fr, 2> open_fresh_masked_scalar_pair(
        MascotContext& context,
        const std::array<AuthScalar, 2>& masked) {
    // This helper is TU-private and has exactly one caller: the constructor
    // below that has just consumed two fresh one-time MASCOT triples. It must
    // never become a general secret-to-public opening API.
    context.check_field_pending();
    const std::vector<AuthScalar> selected(masked.begin(), masked.end());
    std::vector<Fr> opened;
    context.protocols().output.POpen(opened, selected, context.player());
    context.check_field_pending();
    if (opened.size() != masked.size())
        throw std::runtime_error("masked scalar opening arity");
    if (auto* capture = context.p1_capture_seams())
        capture->masked_field_differences(opened);
    return {opened[0], opened[1]};
}

std::array<G1Value, 2> open_masked_g1_pair(
        MascotContext& context, const std::array<AuthG1, 2>& masked) {
    context.check_field_pending();
    typename AuthG1::Direct_MC checker(context.alpha_i());
    const std::vector<AuthG1> shares(masked.begin(), masked.end());
    std::vector<G1Value> opened;
    checker.POpen_Begin(opened, shares, context.player());
    checker.POpen_End(opened, shares, context.player());
    checker.Check(context.player());
    context.check_field_pending();
    if (opened.size() != 2) throw std::runtime_error("G1 opening arity");
    for (const auto& point : opened) point.check();
    if (auto* capture = context.p1_capture_seams())
        capture->masked_group_differences(opened);
    return {opened[0], opened[1]};
}
}  // namespace

std::array<AuthG1, 2> secret_scalar_g1_products(
        MascotContext& context, GroupMacSetup& group_macs,
        std::span<const AuthG1, 2> groups,
        std::span<const AuthScalar, 2> scalars) {
    try {
        context.require_healthy();
        group_macs.require_bound(context);
        // BN254 G1 is prime-order and (1,2) is its standard generator. Mapping
        // a fresh MASCOT field triple (a,b,c=a*b) gives the authenticated
        // scalar-group triple (a*G,b,c*G) without a new preprocessing trust.
        const auto g1_generator = G1Value::admit(
            {false, {"1"}, {"2"}}, false);
        std::array<AuthG1, 2> group_masks;
        std::array<AuthScalar, 2> scalar_masks;
        std::array<AuthG1, 2> product_masks;
        std::array<AuthG1, 2> masked_groups;
        std::array<AuthScalar, 2> masked_scalars;
        std::vector<AuthScalar> captured_triples;
        captured_triples.reserve(6);
        for (std::size_t index = 0; index < groups.size(); ++index) {
            AuthScalar triple_a, triple_b, triple_c;
            context.protocols().preprocessing.get_three(DATA_TRIPLE,
                triple_a, triple_b, triple_c);
            captured_triples.insert(captured_triples.end(),
                {triple_a, triple_b, triple_c});
            group_masks[index] = public_point_map(g1_generator, triple_a);
            scalar_masks[index] = triple_b;
            product_masks[index] = public_point_map(g1_generator, triple_c);
            masked_groups[index] = groups[index] - group_masks[index];
            masked_scalars[index] = scalars[index] - scalar_masks[index];
        }
        context.capture_authenticated_values(
            p1_capture::ScalarCaptureSite::BeaverTriple, captured_triples);
        const std::array<AuthG1, 6> mixed_group_state{{
            group_masks[0], product_masks[0], masked_groups[0],
            group_masks[1], product_masks[1], masked_groups[1]}};
        if (auto* capture = context.p1_capture_seams())
            capture->beaver_mixed_group_state(mixed_group_state);

        const auto scalar_differences =
            open_fresh_masked_scalar_pair(context, masked_scalars);
        const auto group_differences =
            open_masked_g1_pair(context, masked_groups);
        if (scalar_differences.size() != groups.size())
            throw std::runtime_error("scalar-group opening arity");

        std::array<AuthG1, 2> products;
        for (std::size_t index = 0; index < products.size(); ++index) {
            const auto scalar_difference = scalar_differences[index];
            const auto& group_difference = group_differences[index];
            auto product = product_masks[index];
            product += group_masks[index] * scalar_difference;
            product += public_point_map(group_difference, scalar_masks[index]);
            add_public(product, group_difference * scalar_difference,
                       context);
            products[index] = std::move(product);
        }
        if (auto* capture = context.p1_capture_seams())
            capture->beaver_product_group_state(products);
        return products;
    } catch (...) {
        context.poison();
        throw;
    }
}

FinalGroth16Opening GroupMacSetup::open_final(
        MascotContext& context,
        const AuthG1& a, const AuthG2& b, const AuthG1& c,
        FinalGroth16CaptureAuthority* authority) {
    require_bound(context);
    auto* capture = context.p1_capture_seams();
    if (capture != nullptr && authority == nullptr)
        throw std::runtime_error("captured-final-opening-authority-required");
    if (authority != nullptr &&
        (!authority->active_ || authority->context_ != &context ||
         authority->generation_ != context.generation() ||
         authority->failure_epoch_ != context.failure_epoch()))
        throw std::runtime_error("final-opening-authority-binding");
    context.check_field_pending();
    const std::vector<AuthG1> g1_shares{a, c};
    const std::vector<AuthG2> g2_shares{b};
    const auto checked_open = [&]() {
        typename AuthG1::Direct_MC g1_checker(context.alpha_i());
        typename AuthG2::Direct_MC g2_checker(context.alpha_i());
        std::vector<G1Value> g1_opened;
        std::vector<G2Value> g2_opened;
        g1_checker.POpen_Begin(g1_opened, g1_shares, context.player());
        g1_checker.POpen_End(g1_opened, g1_shares, context.player());
        g2_checker.POpen_Begin(g2_opened, g2_shares, context.player());
        g2_checker.POpen_End(g2_opened, g2_shares, context.player());
        // Neither type is returned until BOTH group MAC checks and the pending
        // scalar checks succeed. No late final-verifier shortcut is allowed.
        g1_checker.Check(context.player());
        g2_checker.Check(context.player());
        context.check_field_pending();
        if (g1_opened.size() != 2 || g2_opened.size() != 1)
            throw std::runtime_error("mixed-group opening arity");
        for (const auto& point : g1_opened) point.check();
        g2_opened[0].check();
        return std::pair{std::move(g1_opened), std::move(g2_opened)};
    };
    if (capture != nullptr) {
        auto permit = capture->begin_final_group_opening_capture(
            context, std::span<const AuthG1, 2>(g1_shares.data(), 2), b);
        auto [g1_opened, g2_opened] = checked_open();
        capture->final_group_openings(
            std::move(permit), context,
            std::span<const AuthG1, 2>(g1_shares.data(), 2), b,
            std::span<const G1Value, 2>(g1_opened.data(), 2), g2_opened[0]);
        authority->active_ = false;
        return {g1_opened[0], g2_opened[0], g1_opened[1]};
    }
    auto [g1_opened, g2_opened] = checked_open();
    if (authority != nullptr) authority->active_ = false;
    return {g1_opened[0], g2_opened[0], g1_opened[1]};
}

FinalGroth16Opening open_final_groth16(
        MascotContext& context, GroupMacSetup& group_macs,
        const AuthG1& a, const AuthG2& b, const AuthG1& c) {
    try {
        return group_macs.open_final(context, a, b, c, nullptr);
    } catch (...) {
        context.poison();
        throw;
    }
}

FinalGroth16Opening open_final_groth16(
        MascotContext& context, GroupMacSetup& group_macs,
        const AuthG1& a, const AuthG2& b, const AuthG1& c,
        FinalGroth16CaptureAuthority&& authority) {
    try {
        return group_macs.open_final(context, a, b, c, &authority);
    } catch (...) {
        context.poison();
        throw;
    }
}
}  // namespace kpi::mpc
