#pragma once

// Baseline-only post-EGRESS owner mapping. The selected public recipe names
// exact authenticated columns for each owner's NF and the already-constrained
// output-permutation selectors. Runtime opens only those bits; raw pre-shuffle
// tuples, notes, values, keys, shares and witnesses are never opened.

#include "registered_driver_bridge.hpp"
#include "authenticated_baseline_owner_receiver_contract.hpp"

#include <array>
#include <atomic>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <utility>

namespace kpi::mpc {
class MascotContext;
namespace history { class EgressRelease; }
namespace financial {
class FinancialConstruction;

namespace registered_driver::baseline_disclosure {
class BaselineEffectsPlanAuthority;
class PreparedBaselineOwnerEffects;
class BaselineOwnerPreDisclosureConsentAuthority;
class OwnerPrivateEffectsAuthority;
class ConsumedOwnerPrivateEffects;

// Complete friend boundary. Callers may burn a source into the opaque result,
// but only the authenticated receiver can inspect that result.
class OwnerPrivateEffectsReceiverBridge final {
public:
    static ConsumedOwnerPrivateEffects consume(
        OwnerPrivateEffectsAuthority&&);
};

struct OwnerEffectsColumns {
    // LE bits within each canonical NF byte.
    std::array<std::size_t, 32 * 8> input_nf_bits{};
    // [owner-local source output][public EGRESS destination].
    std::array<std::array<std::size_t, 6>, 2> output_permutation{};
};

class BaselineOwnerEffectsRecipe final {
    std::string identity_, source_identity_, layout_identity_;
    std::size_t model_variables_{}, instances_{};
    std::array<OwnerEffectsColumns, 3> owners_{};
    BaselineOwnerEffectsRecipe(
        std::string, std::string, std::string, std::size_t, std::size_t,
        std::array<OwnerEffectsColumns, 3>);
public:
    BaselineOwnerEffectsRecipe(const BaselineOwnerEffectsRecipe&) = delete;
    BaselineOwnerEffectsRecipe& operator=(
        const BaselineOwnerEffectsRecipe&) = delete;

    // expected_* comes only from the admitted registered compiler selection.
    // owner_layout is the already authenticated canonical layout, not counts.
    static std::shared_ptr<const BaselineOwnerEffectsRecipe> load(
        const std::filesystem::path&, const std::string& expected_identity,
        const std::string& expected_source_identity,
        const std::string& expected_layout_identity,
        std::size_t model_variables, std::size_t instances,
        const std::array<std::span<const std::size_t>, 3>& owner_layout);

    const std::string& identity() const { return identity_; }
    const std::string& source_identity() const { return source_identity_; }
    const std::string& layout_identity() const { return layout_identity_; }
    std::size_t model_variables() const { return model_variables_; }
    std::size_t instances() const { return instances_; }
    const std::array<OwnerEffectsColumns, 3>& owners() const {
        return owners_;
    }
};

struct PublicOwnerPrivateEffects {
    CaptureClassification classification{};
    unsigned round{};
    unsigned owner{};
    Digest run{}, attempt{}, cohort{};
    Digest capture_plan_identity{};
    Digest projection_identity{};
    Digest context_identity{};
    Digest owner_contract_identity{};
    Digest public_nullifier{};
    std::array<Digest, 2> public_tuple_hashes{};
    std::array<Digest, 2> public_tuple_commitments{};
    Digest relation_source_identity{};
    Digest owner_effects_recipe_identity{};
    Digest baseline_plan_identity{};
    Digest verified_egress_identity{};
    Digest policy_identity{};
    Digest authority_identity{};
};

class OwnerPrivateEffectsAuthority final {
    PublicOwnerPrivateEffects value_;
    std::atomic_bool live_{true};
    explicit OwnerPrivateEffectsAuthority(PublicOwnerPrivateEffects);
    friend class BaselineOwnerEffectsRecipeBridge;
    friend class OwnerPrivateEffectsReceiverBridge;
    friend class PreparedBaselineOwnerEffects;
public:
    OwnerPrivateEffectsAuthority(const OwnerPrivateEffectsAuthority&) = delete;
    OwnerPrivateEffectsAuthority& operator=(
        const OwnerPrivateEffectsAuthority&) = delete;
    OwnerPrivateEffectsAuthority(OwnerPrivateEffectsAuthority&&) noexcept;
    OwnerPrivateEffectsAuthority& operator=(
        OwnerPrivateEffectsAuthority&&) = delete;
};

class ConsumedOwnerPrivateEffects final {
    PublicOwnerPrivateEffects value_;
    explicit ConsumedOwnerPrivateEffects(PublicOwnerPrivateEffects value)
        : value_(std::move(value)) {}
    friend class OwnerPrivateEffectsReceiverBridge;
    friend class AuthenticatedBaselineOwnerReceiver;
public:
    ConsumedOwnerPrivateEffects(const ConsumedOwnerPrivateEffects&) = delete;
    ConsumedOwnerPrivateEffects& operator=(
        const ConsumedOwnerPrivateEffects&) = delete;
    ConsumedOwnerPrivateEffects(ConsumedOwnerPrivateEffects&&) noexcept =
        default;
    ConsumedOwnerPrivateEffects& operator=(ConsumedOwnerPrivateEffects&&) =
        delete;
};

// Retains the original one-shot plan; derivation never mints a substitute.
// The parent takes the plan once and each owner source exactly once.
class PreparedBaselineOwnerEffects final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit PreparedBaselineOwnerEffects(std::unique_ptr<Storage>);
    friend class BaselineOwnerEffectsRecipeBridge;
public:
    PreparedBaselineOwnerEffects(const PreparedBaselineOwnerEffects&) = delete;
    PreparedBaselineOwnerEffects& operator=(
        const PreparedBaselineOwnerEffects&) = delete;
    PreparedBaselineOwnerEffects(PreparedBaselineOwnerEffects&&) noexcept;
    PreparedBaselineOwnerEffects& operator=(
        PreparedBaselineOwnerEffects&&) = delete;
    ~PreparedBaselineOwnerEffects();

    BaselineEffectsPlanAuthority take_plan();
    OwnerPrivateEffectsAuthority take_owner(unsigned owner);
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    const PublicOwnerPrivateEffects& test_only_owner(unsigned owner) const;
#endif
};

// Fully defined friend boundary. Production accepts only the genuine immutable
// construction, durable EGRESS and the one-shot baseline plan. No overload
// accepts paths, offsets, spans, digests, JSON, receipts or success Booleans.
class BaselineOwnerEffectsRecipeBridge final {
    struct OpenedOwnerEffects {
        std::array<Digest, 3> nullifiers{};
        std::array<std::array<unsigned, 6>, 6> output_permutation{};
        std::array<Digest, 6> egress_tuple_hashes{};
        std::array<Digest, 6> egress_tuple_commitments{};
        Digest context_identity{};
        Digest relation_source_identity{};
        Digest owner_effects_recipe_identity{};
    };
    static BaselineEffectsPlanAuthority claim_plan(
        BaselineEffectsPlanAuthority&&);
    static PreparedBaselineOwnerEffects derive_claimed(
        BaselineEffectsPlanAuthority&&, OpenedOwnerEffects);
    static PreparedBaselineOwnerEffects derive_opened(
        BaselineEffectsPlanAuthority&&, OpenedOwnerEffects);
public:
    static PreparedBaselineOwnerEffects derive(
        MascotContext&, const FinancialConstruction&,
        const history::EgressRelease&, BaselineEffectsPlanAuthority&&,
        BaselineOwnerPreDisclosureConsentAuthority&&);
#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
    struct TestOpenedOwnerEffects {
        std::array<Digest, 3> nullifiers{};
        // [pre-shuffle source output][public EGRESS destination].
        std::array<std::array<unsigned, 6>, 6> output_permutation{};
        std::array<Digest, 6> egress_tuple_hashes{};
        std::array<Digest, 6> egress_tuple_commitments{};
        Digest context_identity{};
        Digest relation_source_identity{};
        Digest owner_effects_recipe_identity{};
    };
    static PreparedBaselineOwnerEffects test_only_derive_opened(
        BaselineEffectsPlanAuthority&&, TestOpenedOwnerEffects);
#endif
};

struct BaselineOwnerEffectsSourceStatus {
    std::string schema;
    std::string status;
    bool exact_selected_owner_nf_columns;
    bool authenticated_output_permutation_columns;
    bool raw_pre_shuffle_tuples_opened;
    bool post_egress_mac_checked_opening;
    bool exact_egress_set_join;
    bool hidden_candidate_factory_absent;
    bool registered_recipe_selected;
    bool registered_driver_configured;
    bool launch_authorized;
};

BaselineOwnerEffectsSourceStatus baseline_owner_effects_source_status();

} // namespace registered_driver::baseline_disclosure
} // namespace financial
} // namespace kpi::mpc
