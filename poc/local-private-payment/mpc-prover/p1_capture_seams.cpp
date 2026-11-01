#include "p1_capture_seams.hpp"

#include <array>
#include <limits>
#include <vector>

namespace kpi::mpc::p1_capture {
namespace {

template<class Value, class Selector>
std::vector<unsigned char> encode_fields(
        std::span<const Value> values, Selector selected) {
    if (values.size() >
        std::numeric_limits<std::size_t>::max() /
            static_cast<std::size_t>(Fr::size()))
        throw CaptureRefused();
    octetStream encoded;
    encoded.reserve(values.size() * static_cast<std::size_t>(Fr::size()));
    for (const auto& value : values)
        selected(value).pack(encoded);
    return {encoded.get_data(), encoded.get_data() + encoded.get_length()};
}

template<class Group>
std::vector<unsigned char> encode_groups(
        std::span<const Group> values, std::size_t element_size) {
    if (values.size() > std::numeric_limits<std::size_t>::max() / element_size)
        throw CaptureRefused();
    std::vector<unsigned char> encoded;
    encoded.reserve(values.size() * element_size);
    for (const auto& value : values) {
        const auto next = value.network_bytes();
        if (next.size() != element_size) throw CaptureRefused();
        encoded.insert(encoded.end(), next.begin(), next.end());
    }
    return encoded;
}

template<class AuthGroup>
std::vector<unsigned char> encode_authenticated_groups(
        std::span<const AuthGroup> values, std::size_t element_size) {
    if (values.size() > std::numeric_limits<std::size_t>::max() /
            (2 * element_size))
        throw CaptureRefused();
    std::vector<unsigned char> encoded;
    encoded.reserve(values.size() * 2 * element_size);
    for (const auto& value : values) {
        for (const auto* selected : {&value.get_share(), &value.get_mac()}) {
            const auto next = selected->network_bytes();
            if (next.size() != element_size) throw CaptureRefused();
            encoded.insert(encoded.end(), next.begin(), next.end());
        }
    }
    return encoded;
}

} // namespace

P1TypedCaptureSeams::FinalGroupOpeningPermit::FinalGroupOpeningPermit(
        P1TypedCaptureSeams& owner, MascotContext& context,
        std::vector<unsigned char> g1_state,
        std::vector<unsigned char> g2_state)
    : owner_(&owner), context_(&context), generation_(context.generation()),
      failure_epoch_(context.failure_epoch()), g1_state_(std::move(g1_state)),
      g2_state_(std::move(g2_state)), active_(true) {}

P1TypedCaptureSeams::FinalGroupOpeningPermit::FinalGroupOpeningPermit(
        FinalGroupOpeningPermit&& other) noexcept
    : owner_(other.owner_), context_(other.context_),
      generation_(other.generation_), failure_epoch_(other.failure_epoch_),
      g1_state_(std::move(other.g1_state_)),
      g2_state_(std::move(other.g2_state_)), active_(other.active_) {
    other.active_ = false;
}

P1TypedCaptureSeams::FinalGroupOpeningPermit::~FinalGroupOpeningPermit() {
    if (active_ && owner_ != nullptr) owner_->poison();
}

P1TypedCaptureSeams::P1TypedCaptureSeams(P1CapturingPlayer& player)
    : capture_(*player.capture_), player_(player) {
    for (const auto semantic : {
             Semantic::OwnerInputOffsetFrame,
             Semantic::OwnerInputPreprocessingShareFrame,
             Semantic::AuthenticatedShare,
             Semantic::MacShare,
             Semantic::RandomnessShare,
             Semantic::RandomnessMac,
             Semantic::GroupOpeningG1,
             Semantic::GroupOpeningG2,
             Semantic::PublicProjection,
             Semantic::FieldOpening,
             Semantic::MaskedGroupDifferenceG1,
             Semantic::MaskedFieldDifference,
             Semantic::MacKeyShare,
             Semantic::AuthenticatedG1State,
             Semantic::AuthenticatedG2State,
             Semantic::ScalarCaptureBinding})
        capture_.declare_instrumented(semantic);
}

void P1TypedCaptureSeams::poison() noexcept {
    capture_.poison();
}

void P1TypedCaptureSeams::bind_financial_query_model(
        const std::string& model_sha256,
        const std::string& query_store_sha256) {
    capture_.bind_query_model_preimages(
        model_sha256, query_store_sha256);
}

void P1TypedCaptureSeams::released_projection(
        std::span<const unsigned char> projection) {
    if (!released_projection_.empty() || projection.size() != 10685)
        throw CaptureRefused();
    released_projection_.assign(projection.begin(), projection.end());
}

void P1TypedCaptureSeams::close_complete() {
    if (released_projection_.size() != 10685) throw CaptureRefused();
    capture_.seal_projection(released_projection_);
    capture_.close_complete();
}

void P1TypedCaptureSeams::owner_input_offset_frame(
        unsigned owner, std::span<const unsigned char> exact_frame) {
    capture_.owner_input_offset_frame(owner, Fr32Lane::checked(exact_frame));
}

void P1TypedCaptureSeams::owner_input_preprocessing_share_frame(
        unsigned owner, std::span<const unsigned char> exact_frame) {
    capture_.owner_input_preprocessing_share_frame(
        owner, Fr32Lane::checked(exact_frame));
}

void P1TypedCaptureSeams::authenticated_values(
        ScalarCaptureSite site, std::span<const AuthScalar> values) {
    if (values.empty()) return;
    const auto shares = encode_fields<AuthScalar>(
        values, [](const AuthScalar& value) -> const auto& {
            return value.get_share();
        });
    const auto macs = encode_fields<AuthScalar>(
        values, [](const AuthScalar& value) -> const auto& {
            return value.get_mac();
        });
    capture_.authenticated_values(
        site, Fr32Lane::checked(shares), Fr32Lane::checked(macs));
}

void P1TypedCaptureSeams::randomness_values(
        ScalarCaptureSite site, std::span<const AuthScalar> values) {
    if (values.empty()) return;
    const auto shares = encode_fields<AuthScalar>(
        values, [](const AuthScalar& value) -> const auto& {
            return value.get_share();
        });
    const auto macs = encode_fields<AuthScalar>(
        values, [](const AuthScalar& value) -> const auto& {
            return value.get_mac();
        });
    capture_.randomness(
        site, Fr32Lane::checked(shares), Fr32Lane::checked(macs));
}

void P1TypedCaptureSeams::mac_key_share(const Fr& value) {
    const std::array<Fr, 1> selected{{value}};
    const auto encoded = encode_fields<Fr>(
        selected, [](const Fr& field) -> const Fr& { return field; });
    capture_.mac_key_share(Fr32Lane::checked(encoded));
}

void P1TypedCaptureSeams::field_openings(std::span<const Fr> values) {
    if (values.empty()) return;
    const auto opened = encode_fields<Fr>(
        values, [](const Fr& value) -> const Fr& { return value; });
    capture_.field_opening(Fr32Lane::checked(opened));
}

void P1TypedCaptureSeams::masked_field_differences(
        std::span<const Fr> values) {
    if (values.size() != 2) throw CaptureRefused();
    const auto opened = encode_fields<Fr>(
        values, [](const Fr& value) -> const Fr& { return value; });
    capture_.masked_field_differences(Fr32Lane::checked(opened));
}

void P1TypedCaptureSeams::masked_group_differences(
        std::span<const G1Value> values) {
    if (values.size() != 2) throw CaptureRefused();
    const auto opened = encode_groups(values, G1_CAPTURE_BYTES);
    capture_.masked_group_differences(G1Lane::checked(opened));
}

void P1TypedCaptureSeams::proof_base_group_state(
        std::span<const AuthG1, 4> values, const AuthG2& b2) {
    const auto g1 = encode_authenticated_groups<AuthG1>(
        values, G1_CAPTURE_BYTES);
    const std::array<AuthG2, 1> selected_b2{{b2}};
    const auto g2 = encode_authenticated_groups<AuthG2>(
        selected_b2, G2_CAPTURE_BYTES);
    capture_.authenticated_g1_state(
        GroupStateStage::Base, AuthenticatedG1Lane::checked(g1));
    capture_.authenticated_g2_state(
        GroupStateStage::Base, AuthenticatedG2Lane::checked(g2));
}

void P1TypedCaptureSeams::beaver_mixed_group_state(
        std::span<const AuthG1, 6> values) {
    const auto encoded = encode_authenticated_groups<AuthG1>(
        values, G1_CAPTURE_BYTES);
    capture_.authenticated_g1_state(
        GroupStateStage::Mixed, AuthenticatedG1Lane::checked(encoded));
}

void P1TypedCaptureSeams::beaver_product_group_state(
        std::span<const AuthG1, 2> values) {
    const auto encoded = encode_authenticated_groups<AuthG1>(
        values, G1_CAPTURE_BYTES);
    capture_.authenticated_g1_state(
        GroupStateStage::Products, AuthenticatedG1Lane::checked(encoded));
}

P1TypedCaptureSeams::FinalGroupOpeningPermit
P1TypedCaptureSeams::begin_final_group_opening_capture(
        MascotContext& context, std::span<const AuthG1, 2> g1,
        const AuthG2& g2) {
    if (context.p1_capture_seams() != this) throw CaptureRefused();
    auto encoded_g1 = encode_authenticated_groups<AuthG1>(
        g1, G1_CAPTURE_BYTES);
    const std::array<AuthG2, 1> selected_g2{{g2}};
    auto encoded_g2 = encode_authenticated_groups<AuthG2>(
        selected_g2, G2_CAPTURE_BYTES);
    capture_.authenticated_g1_state(
        GroupStateStage::Final, AuthenticatedG1Lane::checked(encoded_g1));
    capture_.authenticated_g2_state(
        GroupStateStage::Final, AuthenticatedG2Lane::checked(encoded_g2));
    return FinalGroupOpeningPermit(
        *this, context, std::move(encoded_g1), std::move(encoded_g2));
}

void P1TypedCaptureSeams::final_group_openings(
        FinalGroupOpeningPermit&& permit, MascotContext& context,
        std::span<const AuthG1, 2> g1_state, const AuthG2& g2_state,
        std::span<const G1Value, 2> g1_opened, const G2Value& g2_opened) {
    if (!permit.active_ || permit.owner_ != this ||
        permit.context_ != &context || permit.generation_ != context.generation() ||
        permit.failure_epoch_ != context.failure_epoch() ||
        context.p1_capture_seams() != this)
        throw CaptureRefused();
    const auto current_g1 = encode_authenticated_groups<AuthG1>(
        g1_state, G1_CAPTURE_BYTES);
    const std::array<AuthG2, 1> selected_g2{{g2_state}};
    const auto current_g2 = encode_authenticated_groups<AuthG2>(
        selected_g2, G2_CAPTURE_BYTES);
    if (current_g1 != permit.g1_state_ || current_g2 != permit.g2_state_)
        throw CaptureRefused();
    const auto opened_g1 = encode_groups<G1Value>(g1_opened, G1_CAPTURE_BYTES);
    const std::array<G2Value, 1> selected_opened_g2{{g2_opened}};
    const auto opened_g2 = encode_groups<G2Value>(
        selected_opened_g2, G2_CAPTURE_BYTES);
    capture_.final_group_opening(G1Lane::checked(opened_g1));
    capture_.final_group_opening(G2Lane::checked(opened_g2));
    permit.active_ = false;
}

#ifdef KPI_P1_CAPTURE_TEST_SETUP
void P1TypedCaptureSeams::test_only_final_group_state_and_openings(
        std::span<const AuthG1, 2> g1_state, const AuthG2& g2_state,
        std::span<const G1Value, 2> g1_opened,
        std::span<const G2Value, 1> g2_opened) {
    const auto encoded_g1 = encode_authenticated_groups<AuthG1>(
        g1_state, G1_CAPTURE_BYTES);
    const auto encoded_g2 = encode_authenticated_groups<AuthG2>(
        std::span<const AuthG2, 1>(&g2_state, 1), G2_CAPTURE_BYTES);
    capture_.authenticated_g1_state(
        GroupStateStage::Final, AuthenticatedG1Lane::checked(encoded_g1));
    capture_.authenticated_g2_state(
        GroupStateStage::Final, AuthenticatedG2Lane::checked(encoded_g2));
    const auto opened_g1 = encode_groups<G1Value>(g1_opened, G1_CAPTURE_BYTES);
    const auto opened_g2 = encode_groups<G2Value>(g2_opened, G2_CAPTURE_BYTES);
    capture_.final_group_opening(G1Lane::checked(opened_g1));
    capture_.final_group_opening(G2Lane::checked(opened_g2));
}
#endif

} // namespace kpi::mpc::p1_capture
