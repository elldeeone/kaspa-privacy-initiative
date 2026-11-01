#include "counterfactual_feasibility_authority.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <openssl/crypto.h>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::measurement::counterfactual_feasibility {
namespace {

constexpr std::size_t ROUNDS = 2;
constexpr std::size_t OWNERS = 3;
constexpr std::size_t OUTPUTS = 6;
constexpr std::size_t VIEWS = 4;
constexpr std::uint64_t NOTE_FLOOR = 60'000'000;
constexpr std::uint64_t MAX_VALUE = 2'870'000'000'000'000'000ULL;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

constexpr unsigned char nibble(char value) {
    return value >= '0' && value <= '9'
        ? static_cast<unsigned char>(value - '0')
        : value >= 'a' && value <= 'f'
            ? static_cast<unsigned char>(10 + value - 'a')
            : 0xff;
}

constexpr Digest hex_digest(std::string_view value) {
    Digest result{};
    if (value.size() != result.size() * 2) return {};
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto high = nibble(value[index * 2]);
        const auto low = nibble(value[index * 2 + 1]);
        if (high > 15 || low > 15) return {};
        result[index] = static_cast<unsigned char>((high << 4U) | low);
    }
    return result;
}

constexpr Digest WORKLOAD_IDENTITY = hex_digest(
    "7fedea9560e241b08521ec3d88c29dba4592f017b6e909092f530a97ee210170");
constexpr Digest REHEARSAL_IDENTITY = hex_digest(
    "34b4d30dfdcb5d72c852c049a788400978571d09d21eb728eeb16f86833b9ed5");
constexpr Digest RELATION_SOURCE_IDENTITY = hex_digest(
    "bae649e1c80fa82f5f1a22446197be7bfaa3b367ea21875e2a6384b98567c022");
constexpr Digest FULL_W1_VERIFIER_SOURCE_IDENTITY = hex_digest(
    "3342f27468273ffd0492f704649444dda429815f34217f585429c97128fa6b07");
constexpr Digest FULL_W1_TYPED_BRIDGE_SOURCE_IDENTITY = hex_digest(
    "4ebcc80a2c72cdcc407e5970e626cfac8cd84d27934ed4a8825004e2f7ff8b63");
constexpr Digest SOURCE_TABLE_IDENTITY = hex_digest(
    "04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7");
constexpr Digest MATRIX_IDENTITY = hex_digest(
    "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab");
constexpr Digest MATRIX_EQUIVALENCE_IDENTITY = hex_digest(
    "52ca327ac2d3dd2921c0aa913060f8a97f127d81c5d125c1892dc989853ac692");
constexpr Digest OBSERVER_SOURCE_IDENTITY = hex_digest(
    "aceadace4a5d6cbfaf20a3404e6690409bb15570f01a816914a0d7eb92cfc0eb");
constexpr Digest MODEL_SOURCE_IDENTITY = hex_digest(
    "3e22997c8932709496c843929e4a0752b3bc7f001690c2119a6692b6388a645a");
constexpr Digest ACCEPTANCE_GATE_IDENTITY = hex_digest(
    "e59e003f6022a9a1bf3c9773de4f1ef5ab8614624d3eb1f75b370c291422eae3");
constexpr Digest DELIVERY_KEY_ADR_IDENTITY = hex_digest(
    "df255f2d3238caf5298db344cae24fed79ba10e80af5c28a436d471c5acc0cff");

enum class InputKind : std::uint8_t {
    Original = 1,
    Received = 2,
    Change = 3,
};

enum class LeakageClass : std::uint8_t {
    FrozenBoundedV3PublicP1C1Direct = 1,
};

struct OwnerValues {
    std::uint64_t input{};
    std::uint64_t payment{};
    std::uint64_t change{};
    std::uint64_t fee{};
    InputKind input_kind{};
    bool operator==(const OwnerValues&) const = default;
};

struct RoundValues {
    std::array<OwnerValues, OWNERS> owners{};
    std::uint8_t c1_visible_payment_creator{};
    bool operator==(const RoundValues&) const = default;
};

struct Mapping {
    std::array<std::uint8_t, OWNERS> input{};
    std::array<std::uint8_t, OWNERS> payment{};
    std::array<std::uint8_t, OWNERS> change{};
    bool operator==(const Mapping&) const = default;
};

struct TwoRoundWorld {
    std::array<Mapping, ROUNDS> rounds{};
    bool operator==(const TwoRoundWorld&) const = default;
};

// Private instance/effects binding carried by both verified closures. In the
// future production path this is minted once by the linear live-source bridge,
// never reconstructed from a manifest or caller digest. The test-only factory
// below uses existing binding fields solely to exercise the join contract.
struct SourceInstanceBinding {
    Digest epoch{};
    Digest accepted_history{};
    std::array<Digest, ROUNDS> effects{};
    bool operator==(const SourceInstanceBinding&) const = default;
};

// Internal capability bodies. They have no public constructor or observable
// state. The current control-only source factory can create synthetic bodies;
// a production body must eventually be moved from the Rust FullW1 verifier and
// the accepted runtime-Close owner respectively.
struct FullW1RelationEvidence final {};
struct RuntimeCloseDescendantEvidence final {};

struct Plan {
    RunBinding binding;
    Digest workload_identity{};
    Digest rehearsal_identity{};
    Digest relation_source_identity{};
    Digest full_w1_verifier_source_identity{};
    Digest full_w1_typed_bridge_source_identity{};
    Digest source_table_identity{};
    Digest matrix_identity{};
    Digest matrix_equivalence_identity{};
    Digest observer_source_identity{};
    Digest model_source_identity{};
    Digest acceptance_gate_identity{};
    Digest delivery_key_adr_identity{};
    std::array<RoundValues, ROUNDS> rounds{};
    LeakageClass leakage_class{};
    bool before_observation{};
    bool exact_two_round_w1{};
    bool swap_honest_inputs{};
    bool swap_honest_changes{};
    bool swap_honest_payments{};
};

struct Observation {
    RunBinding binding;
    std::array<std::vector<TwoRoundWorld>, VIEWS> candidates{};
    bool observation_complete{};
};

struct PostBarrierTruth {
    RunBinding binding;
    TwoRoundWorld truth;
    std::array<RoundValues, ROUNDS> rounds{};
    bool barrier_complete{};
    std::uint8_t sealed_owner_scores{};
};

template<std::size_t N>
bool is_permutation(const std::array<std::uint8_t, N>& value,
                    std::uint8_t limit) {
    if (limit != N) return false;
    std::array<bool, N> seen{};
    for (const auto item : value) {
        if (item >= limit || seen[item]) return false;
        seen[item] = true;
    }
    return true;
}

bool valid_mapping(const Mapping& value) {
    if (!is_permutation(value.input, static_cast<std::uint8_t>(OWNERS)))
        return false;
    std::array<bool, OUTPUTS> outputs{};
    for (std::size_t owner = 0; owner < OWNERS; ++owner) {
        if (value.payment[owner] >= OUTPUTS ||
            value.change[owner] >= OUTPUTS ||
            value.payment[owner] == value.change[owner] ||
            outputs[value.payment[owner]] || outputs[value.change[owner]])
            return false;
        outputs[value.payment[owner]] = true;
        outputs[value.change[owner]] = true;
    }
    return std::all_of(outputs.begin(), outputs.end(),
                       [](bool item) { return item; });
}

bool valid_world(const TwoRoundWorld& value) {
    return std::all_of(value.rounds.begin(), value.rounds.end(),
                       valid_mapping);
}

bool in_note_range(std::uint64_t value) {
    return value >= NOTE_FLOOR && value <= MAX_VALUE;
}

bool valid_equation(const OwnerValues& value) {
    if (!in_note_range(value.input) || !in_note_range(value.payment) ||
        !in_note_range(value.change) || value.fee == 0 ||
        value.fee > MAX_VALUE)
        return false;
    if (value.payment > std::numeric_limits<std::uint64_t>::max() -
            value.change)
        return false;
    const auto outputs = value.payment + value.change;
    if (outputs > std::numeric_limits<std::uint64_t>::max() - value.fee)
        return false;
    return outputs + value.fee == value.input;
}

void validate_plan(const Plan& plan) {
    validate_measurement_run_binding(plan.binding);
    need(plan.binding.classification == Classification::HiddenCandidate &&
         plan.binding.workload == WORKLOAD_IDENTITY &&
         plan.workload_identity == WORKLOAD_IDENTITY &&
         plan.rehearsal_identity == REHEARSAL_IDENTITY &&
         plan.relation_source_identity == RELATION_SOURCE_IDENTITY &&
         plan.full_w1_verifier_source_identity ==
             FULL_W1_VERIFIER_SOURCE_IDENTITY &&
         plan.full_w1_typed_bridge_source_identity ==
             FULL_W1_TYPED_BRIDGE_SOURCE_IDENTITY &&
         plan.source_table_identity == SOURCE_TABLE_IDENTITY &&
         plan.matrix_identity == MATRIX_IDENTITY &&
         plan.matrix_equivalence_identity == MATRIX_EQUIVALENCE_IDENTITY &&
         plan.observer_source_identity == OBSERVER_SOURCE_IDENTITY &&
         plan.model_source_identity == MODEL_SOURCE_IDENTITY &&
         plan.acceptance_gate_identity == ACCEPTANCE_GATE_IDENTITY &&
         plan.delivery_key_adr_identity == DELIVERY_KEY_ADR_IDENTITY &&
         plan.leakage_class ==
             LeakageClass::FrozenBoundedV3PublicP1C1Direct &&
         plan.before_observation && plan.exact_two_round_w1 &&
         plan.swap_honest_inputs && plan.swap_honest_changes &&
         !plan.swap_honest_payments);

    for (const auto& round : plan.rounds) {
        need(round.owners[0].input == round.owners[2].input &&
             round.owners[0].payment == round.owners[2].payment &&
             round.owners[0].change == round.owners[2].change &&
             round.owners[0].fee == round.owners[2].fee &&
             round.owners[0].fee == round.owners[1].fee);
        for (const auto& owner : round.owners) need(valid_equation(owner));
    }

    const auto& first = plan.rounds[0];
    const auto& second = plan.rounds[1];
    for (const auto& owner : first.owners)
        need(owner.input == 2'000'000'000 &&
             owner.payment == 500'000'000 &&
             owner.input_kind == InputKind::Original);
    need(first.c1_visible_payment_creator == 0);

    need(second.owners[0].input == 500'000'000 &&
         second.owners[2].input == 500'000'000 &&
         second.owners[1].input == first.owners[1].change &&
         second.owners[0].payment == 200'000'000 &&
         second.owners[1].payment == 200'000'000 &&
         second.owners[2].payment == 200'000'000 &&
         second.owners[0].input_kind == InputKind::Received &&
         second.owners[1].input_kind == InputKind::Change &&
         second.owners[2].input_kind == InputKind::Received &&
         second.c1_visible_payment_creator == 2);
}

TwoRoundWorld rewire(const TwoRoundWorld& truth) {
    need(valid_world(truth));
    TwoRoundWorld result = truth;
    for (auto& round : result.rounds) {
        std::swap(round.input[0], round.input[2]);
        std::swap(round.change[0], round.change[2]);
    }
    return result;
}

std::pair<std::uint8_t, std::uint8_t> pair_for_input(
        const Mapping& mapping, std::uint8_t input) {
    for (std::size_t owner = 0; owner < OWNERS; ++owner) {
        if (mapping.input[owner] == input)
            return {mapping.payment[owner], mapping.change[owner]};
    }
    refuse();
}

const OwnerValues& owner_for_input_slot(
        const Mapping& truth, const RoundValues& values,
        std::uint8_t slot) {
    for (std::size_t owner = 0; owner < OWNERS; ++owner)
        if (truth.input[owner] == slot) return values.owners[owner];
    refuse();
}

std::uint64_t output_value(const Mapping& truth,
                           const RoundValues& values,
                           std::uint8_t slot) {
    for (std::size_t owner = 0; owner < OWNERS; ++owner) {
        if (truth.payment[owner] == slot) return values.owners[owner].payment;
        if (truth.change[owner] == slot) return values.owners[owner].change;
    }
    refuse();
}

InputKind input_kind(const Mapping& truth, const RoundValues& values,
                     std::uint8_t slot) {
    return owner_for_input_slot(truth, values, slot).input_kind;
}

void validate_rewired_witness(const Plan& plan,
                              const PostBarrierTruth& sealed,
                              const TwoRoundWorld& alternative) {
    need(sealed.rounds == plan.rounds && valid_world(sealed.truth) &&
         valid_world(alternative));
    for (std::size_t round_index = 0; round_index < ROUNDS;
         ++round_index) {
        const auto& truth = sealed.truth.rounds[round_index];
        const auto& alt = alternative.rounds[round_index];
        const auto& values = sealed.rounds[round_index];

        need(alt.input[0] == truth.input[2] &&
             alt.input[2] == truth.input[0] &&
             alt.change[0] == truth.change[2] &&
             alt.change[2] == truth.change[0] &&
             alt.payment == truth.payment &&
             alt.input[1] == truth.input[1] &&
             alt.change[1] == truth.change[1] &&
             alt.payment[1] == truth.payment[1]);

        for (const std::size_t honest : {std::size_t{0}, std::size_t{2}}) {
            const auto physical_nf = truth.input[honest];
            need(pair_for_input(truth, physical_nf) !=
                 pair_for_input(alt, physical_nf));
        }

        const auto c1_creator = values.c1_visible_payment_creator;
        need(c1_creator == (round_index == 0 ? 0 : 2) &&
             alt.payment[c1_creator] == truth.payment[c1_creator]);

        for (std::size_t owner = 0; owner < OWNERS; ++owner) {
            const auto& source_input = owner_for_input_slot(
                truth, values, alt.input[owner]);
            OwnerValues rewired{
                .input = source_input.input,
                .payment = output_value(truth, values, alt.payment[owner]),
                .change = output_value(truth, values, alt.change[owner]),
                .fee = values.owners[owner].fee,
                .input_kind = input_kind(truth, values, alt.input[owner]),
            };
            need(valid_equation(rewired));
            if (round_index == 0)
                need(rewired.input_kind == InputKind::Original);
            else if (owner == 1)
                need(rewired.input_kind == InputKind::Change);
            else
                need(rewired.input_kind == InputKind::Received);
        }
    }
}

void validate_candidates(const Observation& observed,
                         const TwoRoundWorld& truth,
                         const TwoRoundWorld& alternative) {
    need(observed.observation_complete);
    for (const auto& view : observed.candidates) {
        need(!view.empty());
        for (std::size_t index = 0; index < view.size(); ++index) {
            need(valid_world(view[index]) &&
                 std::find(view.begin(), view.begin() + index,
                           view[index]) == view.begin() + index);
        }
        need(std::find(view.begin(), view.end(), truth) != view.end() &&
             std::find(view.begin(), view.end(), alternative) != view.end());
    }
}

#ifdef KPB_COUNTERFACTUAL_FEASIBILITY_TEST_SETUP
Plan exact_plan(const RunBinding& binding) {
    constexpr std::uint64_t fee = 7'000'000;
    Plan result{
        .binding = binding,
        .workload_identity = WORKLOAD_IDENTITY,
        .rehearsal_identity = REHEARSAL_IDENTITY,
        .relation_source_identity = RELATION_SOURCE_IDENTITY,
        .full_w1_verifier_source_identity =
            FULL_W1_VERIFIER_SOURCE_IDENTITY,
        .full_w1_typed_bridge_source_identity =
            FULL_W1_TYPED_BRIDGE_SOURCE_IDENTITY,
        .source_table_identity = SOURCE_TABLE_IDENTITY,
        .matrix_identity = MATRIX_IDENTITY,
        .matrix_equivalence_identity = MATRIX_EQUIVALENCE_IDENTITY,
        .observer_source_identity = OBSERVER_SOURCE_IDENTITY,
        .model_source_identity = MODEL_SOURCE_IDENTITY,
        .acceptance_gate_identity = ACCEPTANCE_GATE_IDENTITY,
        .delivery_key_adr_identity = DELIVERY_KEY_ADR_IDENTITY,
        .leakage_class = LeakageClass::FrozenBoundedV3PublicP1C1Direct,
        .before_observation = true,
        .exact_two_round_w1 = true,
        .swap_honest_inputs = true,
        .swap_honest_changes = true,
        .swap_honest_payments = false,
    };
    result.rounds[0] = {
        .owners = {
            OwnerValues{2'000'000'000, 500'000'000,
                        1'493'000'000, fee, InputKind::Original},
            OwnerValues{2'000'000'000, 500'000'000,
                        1'493'000'000, fee, InputKind::Original},
            OwnerValues{2'000'000'000, 500'000'000,
                        1'493'000'000, fee, InputKind::Original},
        },
        .c1_visible_payment_creator = 0,
    };
    result.rounds[1] = {
        .owners = {
            OwnerValues{500'000'000, 200'000'000,
                        293'000'000, fee, InputKind::Received},
            OwnerValues{1'493'000'000, 200'000'000,
                        1'286'000'000, fee, InputKind::Change},
            OwnerValues{500'000'000, 200'000'000,
                        293'000'000, fee, InputKind::Received},
        },
        .c1_visible_payment_creator = 2,
    };
    return result;
}

TwoRoundWorld exact_truth() {
    TwoRoundWorld result;
    for (auto& round : result.rounds) {
        round.input = {0, 1, 2};
        round.payment = {0, 2, 4};
        round.change = {1, 3, 5};
    }
    return result;
}

SourceInstanceBinding test_only_source_instance(const RunBinding& binding) {
    return {
        .epoch = binding.attempt,
        .accepted_history = binding.source_closure,
        .effects = binding.projections,
    };
}
#endif

} // namespace

struct CounterfactualPlanSelectionAuthority::Storage {
    Plan plan;
    ~Storage() { OPENSSL_cleanse(plan.rounds.data(), sizeof(plan.rounds)); }
};
struct CounterfactualPrecommitAuthority::Storage {
    Plan plan;
    ~Storage() { OPENSSL_cleanse(plan.rounds.data(), sizeof(plan.rounds)); }
};
struct ObservationCandidateResidualAuthority::Storage {
    Observation observation;
    ~Storage() {
        for (auto& view : observation.candidates)
            if (!view.empty())
                OPENSSL_cleanse(view.data(), view.size() * sizeof(view[0]));
    }
};
struct PostBarrierTruthResidualAuthority::Storage {
    PostBarrierTruth sealed;
    ~Storage() {
        OPENSSL_cleanse(&sealed.truth, sizeof(sealed.truth));
        OPENSSL_cleanse(sealed.rounds.data(), sizeof(sealed.rounds));
    }
};
struct CounterfactualArithmeticShapeAuthority::Storage {
    RunBinding binding;
    TwoRoundWorld alternative;
    ~Storage() { OPENSSL_cleanse(&alternative, sizeof(alternative)); }
};
struct LiveCounterfactualSourceInstanceAuthority::Storage {
    RunBinding binding;
    SourceInstanceBinding relation_instance;
    SourceInstanceBinding close_instance;
    TwoRoundWorld relation_alternative;
    TwoRoundWorld close_alternative;
    std::array<Digest, ROUNDS> close_projections{};
    std::unique_ptr<FullW1RelationEvidence> relation_evidence;
    std::unique_ptr<RuntimeCloseDescendantEvidence> close_evidence;
    ~Storage() {
        OPENSSL_cleanse(&relation_instance, sizeof(relation_instance));
        OPENSSL_cleanse(&close_instance, sizeof(close_instance));
        OPENSSL_cleanse(&relation_alternative,
                        sizeof(relation_alternative));
        OPENSSL_cleanse(&close_alternative, sizeof(close_alternative));
        OPENSSL_cleanse(close_projections.data(),
                        sizeof(close_projections));
    }
};
struct FullW1WithCloseResidualAuthority::Storage {
    RunBinding binding;
    SourceInstanceBinding relation_instance;
    SourceInstanceBinding close_instance;
    TwoRoundWorld relation_alternative;
    TwoRoundWorld close_alternative;
    std::array<Digest, ROUNDS> close_projections{};
    std::unique_ptr<FullW1RelationEvidence> relation_evidence;
    std::unique_ptr<RuntimeCloseDescendantEvidence> close_evidence;
    ~Storage() {
        OPENSSL_cleanse(&relation_instance, sizeof(relation_instance));
        OPENSSL_cleanse(&close_instance, sizeof(close_instance));
        OPENSSL_cleanse(&relation_alternative,
                        sizeof(relation_alternative));
        OPENSSL_cleanse(&close_alternative, sizeof(close_alternative));
        OPENSSL_cleanse(close_projections.data(),
                        sizeof(close_projections));
    }
};
struct CounterfactualJointClosureAuthority::Storage {
    RunBinding binding;
    SourceInstanceBinding source_instance;
    TwoRoundWorld alternative;
    std::unique_ptr<FullW1RelationEvidence> relation_evidence;
    std::unique_ptr<RuntimeCloseDescendantEvidence> close_evidence;
    ~Storage() {
        OPENSSL_cleanse(&source_instance, sizeof(source_instance));
        OPENSSL_cleanse(&alternative, sizeof(alternative));
    }
};
struct CounterfactualFeasibilityAuthority::Storage {
    RunBinding binding;
    SourceInstanceBinding source_instance;
    std::unique_ptr<FullW1RelationEvidence> relation_evidence;
    std::unique_ptr<RuntimeCloseDescendantEvidence> close_evidence;
    ~Storage() { OPENSSL_cleanse(&source_instance, sizeof(source_instance)); }
};

#define KPB_MOVE_ONLY_DEFINITIONS(Type)                                      \
    Type::Type(std::unique_ptr<Storage> storage)                             \
        : storage_(std::move(storage)) {}                                    \
    Type::Type(Type&& other) noexcept                                        \
        : storage_(std::move(other.storage_)) {}                             \
    Type::~Type() = default

KPB_MOVE_ONLY_DEFINITIONS(CounterfactualPlanSelectionAuthority);
KPB_MOVE_ONLY_DEFINITIONS(CounterfactualPrecommitAuthority);
KPB_MOVE_ONLY_DEFINITIONS(ObservationCandidateResidualAuthority);
KPB_MOVE_ONLY_DEFINITIONS(PostBarrierTruthResidualAuthority);
KPB_MOVE_ONLY_DEFINITIONS(CounterfactualArithmeticShapeAuthority);
KPB_MOVE_ONLY_DEFINITIONS(LiveCounterfactualSourceInstanceAuthority);
KPB_MOVE_ONLY_DEFINITIONS(FullW1WithCloseResidualAuthority);
KPB_MOVE_ONLY_DEFINITIONS(CounterfactualJointClosureAuthority);
KPB_MOVE_ONLY_DEFINITIONS(CounterfactualFeasibilityAuthority);

#undef KPB_MOVE_ONLY_DEFINITIONS

CounterfactualFeasibilityTransfer::CounterfactualFeasibilityTransfer(
        void* storage, void (*destroy)(void*) noexcept)
    : storage_(storage), destroy_(destroy) {
    need(storage_ != nullptr && destroy_ != nullptr);
}

CounterfactualFeasibilityTransfer::CounterfactualFeasibilityTransfer(
        CounterfactualFeasibilityTransfer&& other) noexcept
    : storage_(std::exchange(other.storage_, nullptr)),
      destroy_(std::exchange(other.destroy_, nullptr)) {}

CounterfactualFeasibilityTransfer::~CounterfactualFeasibilityTransfer() {
    if (storage_ != nullptr) destroy_(storage_);
}

CounterfactualFeasibilityTransfer
CounterfactualFeasibilityAuthority::transfer_for_acceptance() && {
    auto* released = storage_.release();
    need(released != nullptr);
    return CounterfactualFeasibilityTransfer(
        released, [](void* opaque) noexcept {
            delete static_cast<Storage*>(opaque);
        });
}

CounterfactualPrecommitAuthority CounterfactualFeasibilityBridge::precommit(
        CounterfactualPlanSelectionAuthority&& supplied) {
    auto consumed = std::move(supplied.storage_);
    need(consumed != nullptr);
    validate_plan(consumed->plan);
    auto result = std::make_unique<CounterfactualPrecommitAuthority::Storage>();
    result->plan = std::move(consumed->plan);
    return CounterfactualPrecommitAuthority(std::move(result));
}

CounterfactualArithmeticShapeAuthority
CounterfactualFeasibilityBridge::verify_arithmetic_shape(
        CounterfactualPrecommitAuthority&& supplied_plan,
        ObservationCandidateResidualAuthority&& supplied_observation,
        PostBarrierTruthResidualAuthority&& supplied_truth) {
    // Burn every supplied capability before checking any one of them.  A mixed
    // replay/fresh call must not preserve the still-live peers for another try.
    auto plan = std::move(supplied_plan.storage_);
    auto observation = std::move(supplied_observation.storage_);
    auto truth = std::move(supplied_truth.storage_);
    need(plan != nullptr && observation != nullptr && truth != nullptr);

    validate_plan(plan->plan);
    validate_measurement_run_binding(observation->observation.binding);
    validate_measurement_run_binding(truth->sealed.binding);
    need(observation->observation.binding == plan->plan.binding &&
         truth->sealed.binding == plan->plan.binding &&
         truth->sealed.barrier_complete &&
         truth->sealed.sealed_owner_scores == OWNERS);

    const auto alternative = rewire(truth->sealed.truth);
    validate_rewired_witness(plan->plan, truth->sealed, alternative);
    validate_candidates(observation->observation, truth->sealed.truth,
                        alternative);

    auto result =
        std::make_unique<CounterfactualArithmeticShapeAuthority::Storage>();
    result->binding = plan->plan.binding;
    result->alternative = alternative;
    return CounterfactualArithmeticShapeAuthority(std::move(result));
}

CounterfactualFeasibilityAuthority
CounterfactualFeasibilityBridge::close_full_witness(
        CounterfactualArithmeticShapeAuthority&& supplied_shape,
        CounterfactualJointClosureAuthority&& supplied_joint) {
    // Burn both capabilities at entry. A mixed replay must not preserve the
    // still-live peer for another attempt.
    auto shape = std::move(supplied_shape.storage_);
    auto joint = std::move(supplied_joint.storage_);
    need(shape != nullptr && joint != nullptr);
    validate_measurement_run_binding(shape->binding);
    validate_measurement_run_binding(joint->binding);
    need(shape->binding == joint->binding &&
         shape->alternative == joint->alternative);
    auto result = std::make_unique<CounterfactualFeasibilityAuthority::Storage>();
    result->binding = shape->binding;
    result->source_instance = joint->source_instance;
    result->relation_evidence = std::move(joint->relation_evidence);
    result->close_evidence = std::move(joint->close_evidence);
    need(result->relation_evidence != nullptr &&
         result->close_evidence != nullptr);
    return CounterfactualFeasibilityAuthority(std::move(result));
}

FullW1WithCloseResidualAuthority
CounterfactualFullW1WitnessBridge::construct_and_verify(
        LiveCounterfactualSourceInstanceAuthority&& supplied) {
    // The live source is indivisible: consume the sole runtime-Close residual
    // together with the FullW1 source before checking either arm.
    auto source = std::move(supplied.storage_);
    need(source != nullptr);
    validate_measurement_run_binding(source->binding);
    auto relation_evidence = std::move(source->relation_evidence);
    auto close_evidence = std::move(source->close_evidence);
    need(relation_evidence != nullptr &&
         valid_world(source->relation_alternative));

    auto result =
        std::make_unique<FullW1WithCloseResidualAuthority::Storage>();
    result->binding = source->binding;
    result->relation_instance = source->relation_instance;
    result->close_instance = source->close_instance;
    result->relation_alternative = source->relation_alternative;
    result->close_alternative = source->close_alternative;
    result->close_projections = source->close_projections;
    result->relation_evidence = std::move(relation_evidence);
    result->close_evidence = std::move(close_evidence);
    return FullW1WithCloseResidualAuthority(std::move(result));
}

CounterfactualJointClosureAuthority
CounterfactualRuntimeCloseBridge::close_descendants(
        FullW1WithCloseResidualAuthority&& supplied) {
    auto residual = std::move(supplied.storage_);
    need(residual != nullptr);
    validate_measurement_run_binding(residual->binding);
    auto relation_evidence = std::move(residual->relation_evidence);
    auto close_evidence = std::move(residual->close_evidence);
    need(relation_evidence != nullptr && close_evidence != nullptr &&
         residual->relation_instance == residual->close_instance &&
         residual->relation_alternative == residual->close_alternative &&
         residual->close_projections == residual->binding.projections &&
         valid_world(residual->close_alternative));

    auto result =
        std::make_unique<CounterfactualJointClosureAuthority::Storage>();
    result->binding = residual->binding;
    result->source_instance = residual->relation_instance;
    result->alternative = residual->relation_alternative;
    result->relation_evidence = std::move(relation_evidence);
    result->close_evidence = std::move(close_evidence);
    return CounterfactualJointClosureAuthority(std::move(result));
}

#ifdef KPB_COUNTERFACTUAL_FEASIBILITY_TEST_SETUP
CounterfactualPlanSelectionAuthority
CounterfactualFeasibilityBridge::test_only_plan(
        const RunBinding& binding, TestOnlyCounterfactualFault fault) {
    auto result = std::make_unique<CounterfactualPlanSelectionAuthority::Storage>();
    result->plan = exact_plan(binding);
    auto& plan = result->plan;
    switch (fault) {
    case TestOnlyCounterfactualFault::None: break;
    case TestOnlyCounterfactualFault::PlanAfterObservation:
        plan.before_observation = false; break;
    case TestOnlyCounterfactualFault::WrongWorkloadIdentity:
        plan.workload_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongRehearsalIdentity:
        plan.rehearsal_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongRelationIdentity:
        plan.relation_source_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongFullW1VerifierIdentity:
        plan.full_w1_verifier_source_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongFullW1BridgeIdentity:
        plan.full_w1_typed_bridge_source_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongSourceTableIdentity:
        plan.source_table_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongMatrixIdentity:
        plan.matrix_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongMatrixEvidenceIdentity:
        plan.matrix_equivalence_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::WrongLeakageClosureIdentity:
        plan.model_source_identity[0] ^= 1; break;
    case TestOnlyCounterfactualFault::InputSwapDisabled:
        plan.swap_honest_inputs = false; break;
    case TestOnlyCounterfactualFault::ChangeSwapDisabled:
        plan.swap_honest_changes = false; break;
    case TestOnlyCounterfactualFault::PaymentSwapEnabled:
        plan.swap_honest_payments = true; break;
    case TestOnlyCounterfactualFault::WrongLeakageClass:
        plan.leakage_class = static_cast<LeakageClass>(2); break;
    case TestOnlyCounterfactualFault::UnequalHonestInput:
        ++plan.rounds[0].owners[2].input;
        ++plan.rounds[0].owners[2].change;
        break;
    case TestOnlyCounterfactualFault::UnequalPayment:
        ++plan.rounds[0].owners[2].payment;
        --plan.rounds[0].owners[2].change;
        break;
    case TestOnlyCounterfactualFault::UnequalFee:
        ++plan.rounds[0].owners[2].fee;
        --plan.rounds[0].owners[2].change;
        break;
    case TestOnlyCounterfactualFault::BadEquation:
        ++plan.rounds[0].owners[0].change; break;
    case TestOnlyCounterfactualFault::BadValueRange:
        plan.rounds[0].owners[0].change = NOTE_FLOOR - 1; break;
    case TestOnlyCounterfactualFault::WrongRound2Selection:
        plan.rounds[1].owners[0].input_kind = InputKind::Change; break;
    default: break;
    }
    return CounterfactualPlanSelectionAuthority(std::move(result));
}

ObservationCandidateResidualAuthority
CounterfactualFeasibilityBridge::test_only_observation(
        const RunBinding& binding, TestOnlyCounterfactualFault fault) {
    auto result =
        std::make_unique<ObservationCandidateResidualAuthority::Storage>();
    auto& observed = result->observation;
    observed.binding = binding;
    observed.observation_complete = true;
    const auto truth = exact_truth();
    const auto alternative = rewire(truth);
    for (auto& view : observed.candidates) view = {truth, alternative};
    std::size_t missing = VIEWS;
    if (fault == TestOnlyCounterfactualFault::MissingW1Public) missing = 0;
    if (fault == TestOnlyCounterfactualFault::MissingW1Dispatcher) missing = 1;
    if (fault ==
        TestOnlyCounterfactualFault::MissingW1CorruptServerWallet) missing = 2;
    if (fault == TestOnlyCounterfactualFault::MissingW1Union) missing = 3;
    if (missing < VIEWS) observed.candidates[missing].pop_back();
    if (fault == TestOnlyCounterfactualFault::MalformedCandidate) {
        auto malformed = alternative;
        malformed.rounds[0].input[0] = malformed.rounds[0].input[1];
        observed.candidates[0].push_back(malformed);
    }
    if (fault == TestOnlyCounterfactualFault::ObservationNotComplete)
        observed.observation_complete = false;
    return ObservationCandidateResidualAuthority(std::move(result));
}

PostBarrierTruthResidualAuthority
CounterfactualFeasibilityBridge::test_only_post_barrier(
        const RunBinding& binding, TestOnlyCounterfactualFault fault) {
    auto result =
        std::make_unique<PostBarrierTruthResidualAuthority::Storage>();
    auto& sealed = result->sealed;
    sealed.binding = binding;
    sealed.truth = exact_truth();
    sealed.rounds = exact_plan(binding).rounds;
    sealed.barrier_complete = true;
    sealed.sealed_owner_scores = OWNERS;
    if (fault == TestOnlyCounterfactualFault::BarrierNotComplete)
        sealed.barrier_complete = false;
    if (fault == TestOnlyCounterfactualFault::ScoresIncomplete)
        sealed.sealed_owner_scores = OWNERS - 1;
    if (fault == TestOnlyCounterfactualFault::MalformedTruthMapping)
        sealed.truth.rounds[0].input[0] = sealed.truth.rounds[0].input[1];
    if (fault == TestOnlyCounterfactualFault::WrongC1VisibleCreator)
        sealed.rounds[0].c1_visible_payment_creator = 2;
    if (fault == TestOnlyCounterfactualFault::TruthValueMismatch) {
        ++sealed.rounds[0].owners[0].input;
        ++sealed.rounds[0].owners[0].change;
    }
    return PostBarrierTruthResidualAuthority(std::move(result));
}

LiveCounterfactualSourceInstanceAuthority
CounterfactualFeasibilityBridge::test_only_live_source(
        const RunBinding& binding, TestOnlyCounterfactualFault fault) {
    auto result =
        std::make_unique<LiveCounterfactualSourceInstanceAuthority::Storage>();
    result->binding = binding;
    result->relation_instance = test_only_source_instance(binding);
    result->close_instance = result->relation_instance;
    result->relation_alternative = rewire(exact_truth());
    result->close_alternative = result->relation_alternative;
    result->close_projections = binding.projections;
    result->relation_evidence = std::make_unique<FullW1RelationEvidence>();
    result->close_evidence =
        std::make_unique<RuntimeCloseDescendantEvidence>();
    if (fault == TestOnlyCounterfactualFault::FullWitnessIncomplete)
        result->relation_evidence.reset();
    if (fault == TestOnlyCounterfactualFault::FullWitnessWrongW1)
        std::swap(result->relation_alternative.rounds[0].payment[0],
                  result->relation_alternative.rounds[0].payment[2]);
    if (fault == TestOnlyCounterfactualFault::CloseWrongW1)
        std::swap(result->close_alternative.rounds[0].payment[0],
                  result->close_alternative.rounds[0].payment[2]);
    if (fault == TestOnlyCounterfactualFault::JointWrongW1) {
        std::swap(result->relation_alternative.rounds[0].payment[0],
                  result->relation_alternative.rounds[0].payment[2]);
        result->close_alternative = result->relation_alternative;
    }
    if (fault == TestOnlyCounterfactualFault::CloseWrongInstance)
        result->close_instance.epoch[0] ^= 1;
    if (fault == TestOnlyCounterfactualFault::CloseIncomplete)
        result->close_evidence.reset();
    return LiveCounterfactualSourceInstanceAuthority(std::move(result));
}

void CounterfactualFeasibilityBridge::test_only_consume(
        CounterfactualFeasibilityAuthority&& supplied) {
    auto consumed = std::move(supplied.storage_);
    need(consumed != nullptr);
    validate_measurement_run_binding(consumed->binding);
}
#endif

} // namespace kpb::measurement::counterfactual_feasibility

namespace kpb::measurement::acceptance_v4 {

counterfactual_feasibility::CounterfactualFeasibilityTransfer
CounterfactualFeasibilityAcceptanceBridge::take(
        counterfactual_feasibility::CounterfactualFeasibilityAuthority&&
            supplied) {
    return std::move(supplied).transfer_for_acceptance();
}

} // namespace kpb::measurement::acceptance_v4
