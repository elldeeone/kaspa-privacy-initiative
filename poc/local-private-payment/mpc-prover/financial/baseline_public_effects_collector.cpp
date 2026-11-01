#include "baseline_public_effects_collector.hpp"
#include "authenticated_baseline_owner_receiver.hpp"

#include <algorithm>
#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

template<std::size_t N>
void all_nonzero_distinct(const std::array<Digest, N>& values) {
    for (std::size_t i = 0; i < N; ++i) {
        need(nonzero(values[i]));
        for (std::size_t j = 0; j < i; ++j) need(values[i] != values[j]);
    }
}

template<std::size_t N>
void canonical_set(const std::array<Digest, N>& values) {
    all_nonzero_distinct(values);
    need(std::is_sorted(values.begin(), values.end()));
}

void validate(const PublicBaselineEffectsPlan& value) {
    need(value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         (value.round == 1 || value.round == 2));
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.verified_egress_identity,
             &value.policy_identity})
        need(nonzero(*field));
    all_nonzero_distinct(value.owner_contracts);
    canonical_set(value.public_nullifiers);
    canonical_set(value.public_tuple_hashes);
}

void validate(const OwnerEffectsDisclosureInput& value) {
    need(value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         (value.round == 1 || value.round == 2) && value.owner < 3 &&
         value.public_tuple_hashes[0] != value.public_tuple_hashes[1]);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity,
             &value.owner_contract_identity, &value.public_nullifier,
             &value.public_tuple_hashes[0], &value.public_tuple_hashes[1],
             &value.authenticated_session_identity})
        need(nonzero(*field));
}

Digest plan_identity(const PublicBaselineEffectsPlan& value) {
    Bytes bytes;
    text(bytes, "KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_PLAN_V1\n");
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    integer(bytes, value.round);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.verified_egress_identity})
        add(bytes, *field);
    for (const auto& field : value.owner_contracts) add(bytes, field);
    for (const auto& field : value.public_nullifiers) add(bytes, field);
    for (const auto& field : value.public_tuple_hashes) add(bytes, field);
    add(bytes, value.policy_identity);
    return identity_registry::digest(bytes);
}

Digest disclosure_identity(const OwnerEffectsDisclosureInput& value) {
    Bytes bytes;
    text(bytes, "KPB_AUTHENTICATED_OWNER_PUBLIC_EFFECTS_V1\n");
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    integer(bytes, value.round); integer(bytes, value.owner);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity,
             &value.owner_contract_identity, &value.public_nullifier,
             &value.public_tuple_hashes[0], &value.public_tuple_hashes[1],
             &value.authenticated_session_identity}) add(bytes, *field);
    return identity_registry::digest(bytes);
}

Digest explicit_receipt_identity(const PublicExplicitOwnerEffects& value) {
    Bytes bytes;
    text(bytes, "KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_RECEIPT_V1\n");
    integer(bytes, value.status.size());
    add(bytes, std::span(
        reinterpret_cast<const unsigned char*>(value.status.data()),
        value.status.size()));
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    integer(bytes, value.round);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity}) add(bytes, *field);
    for (const auto& effect : value.owner_effects) {
        integer(bytes, effect.owner);
        add(bytes, effect.owner_contract_identity);
        add(bytes, effect.public_nullifier);
        add(bytes, effect.public_tuple_hashes[0]);
        add(bytes, effect.public_tuple_hashes[1]);
    }
    return identity_registry::digest(bytes);
}

} // namespace

VerifiedBaselinePublicEffectsAuthority::
VerifiedBaselinePublicEffectsAuthority(PublicBaselineEffectsPlan value)
    : value_(std::move(value)) {
    validate(value_);
}

VerifiedBaselinePublicEffectsAuthority::
VerifiedBaselinePublicEffectsAuthority(
    VerifiedBaselinePublicEffectsAuthority&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
VerifiedBaselinePublicEffectsAuthority
VerifiedBaselinePublicEffectsAuthority::test_only_mint(
    PublicBaselineEffectsPlan value) {
    return VerifiedBaselinePublicEffectsAuthority(std::move(value));
}
#endif

BaselineEffectsPlanAuthority::BaselineEffectsPlanAuthority(
    PublicBaselineEffectsPlan value) : value_(std::move(value)) {
    validate(value_);
    identity_ = plan_identity(value_);
}

BaselineEffectsPlanAuthority::BaselineEffectsPlanAuthority(
        PublicBaselineEffectsPlan value, Digest identity, ClaimedTransfer)
    : value_(std::move(value)), identity_(identity) {
    validate(value_);
    need(identity_ == plan_identity(value_));
}

BaselineEffectsPlanAuthority::BaselineEffectsPlanAuthority(
    BaselineEffectsPlanAuthority&& other) noexcept
    : value_(other.value_), identity_(other.identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
BaselineEffectsPlanAuthority BaselineEffectsPlanAuthority::test_only_mint(
    PublicBaselineEffectsPlan value) {
    return BaselineEffectsPlanAuthority(std::move(value));
}
#endif

AuthenticatedOwnerEffectsDisclosureAuthority::
AuthenticatedOwnerEffectsDisclosureAuthority(
    OwnerEffectsDisclosureInput value) : value_(std::move(value)) {
    std::sort(value_.public_tuple_hashes.begin(),
              value_.public_tuple_hashes.end());
    validate(value_);
    identity_ = disclosure_identity(value_);
}

AuthenticatedOwnerEffectsDisclosureAuthority::
AuthenticatedOwnerEffectsDisclosureAuthority(
    AuthenticatedOwnerEffectsDisclosureAuthority&& other) noexcept
    : value_(other.value_), identity_(other.identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
AuthenticatedOwnerEffectsDisclosureAuthority
AuthenticatedOwnerEffectsDisclosureAuthority::test_only_mint(
    OwnerEffectsDisclosureInput value) {
    return AuthenticatedOwnerEffectsDisclosureAuthority(std::move(value));
}
#endif

ExplicitOwnerPublicEffectsAuthority::ExplicitOwnerPublicEffectsAuthority(
    PublicExplicitOwnerEffects receipt) : receipt_(std::move(receipt)) {}

BaselineTerminalOwnerMappingAuthority::
BaselineTerminalOwnerMappingAuthority(PublicExplicitOwnerEffects value)
    : value_(std::move(value)) {
    need(value_.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         value_.status == "EXPLICIT_OWNER_PUBLIC_EFFECTS" &&
         value_.receipt_identity == explicit_receipt_identity(value_));
}

BaselineTerminalOwnerMappingAuthority::
BaselineTerminalOwnerMappingAuthority(
        BaselineTerminalOwnerMappingAuthority&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {}

Digest ExplicitOwnerPublicEffectsAuthority::receipt_identity(
        const PublicExplicitOwnerEffects& value) {
    return explicit_receipt_identity(value);
}

ExplicitOwnerPublicEffectsAuthority::ExplicitOwnerPublicEffectsAuthority(
    ExplicitOwnerPublicEffectsAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

ExplicitOwnerPublicEffectsAuthority
ExplicitOwnerPublicEffectsAuthority::from_bound_party(
        PartyBaselineOwnerEffectsAuthority& supplied,
        const PublicAuthorizedAttempt& attempt,
        const Digest& egress_binding, const Digest& projection_identity,
        const Digest& context_identity) {
    try {
        need(!supplied.observer_exported_.exchange(true));
        const auto& value = supplied.value_;
        need(value.classification ==
                 CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
             (value.round == 1 || value.round == 2) && value.role == 0 &&
             attempt.role == 0 &&
             attempt.classification == value.classification &&
             attempt.round == value.round && attempt.run == value.run &&
             attempt.trial == value.trial &&
             attempt.attempt == value.attempt &&
             attempt.cohort == value.cohort &&
             attempt.capture_plan_identity == value.capture_plan_identity &&
             attempt.owner_contracts == value.owner_contracts &&
             attempt.durable_lock == egress_binding &&
             projection_identity == value.projection_identity &&
             context_identity == value.context_identity);
        PublicExplicitOwnerEffects receipt{
            .status = "EXPLICIT_OWNER_PUBLIC_EFFECTS",
            .classification = value.classification,
            .round = value.round,
            .run = value.run,
            .trial = value.trial,
            .attempt = value.attempt,
            .cohort = value.cohort,
            .capture_plan_identity = value.capture_plan_identity,
            .projection_identity = value.projection_identity,
            .context_identity = value.context_identity,
        };
        for (unsigned owner = 0; owner < receipt.owner_effects.size(); ++owner) {
            const auto& truth = value.owner_truth[owner];
            need(truth.owner == owner && truth.round == value.round &&
                 truth.run == value.run && truth.trial == value.trial &&
                 truth.attempt == value.attempt &&
                 truth.cohort == value.cohort &&
                 truth.capture_plan_identity == value.capture_plan_identity &&
                 truth.projection_identity == value.projection_identity &&
                 truth.context_identity == value.context_identity &&
                 truth.owner_contract_identity == value.owner_contracts[owner]);
            receipt.owner_effects[owner] = PublicOwnerEffect{
                .owner = owner,
                .owner_contract_identity = truth.owner_contract_identity,
                .public_nullifier = truth.public_nullifier,
                .public_tuple_hashes = truth.public_tuple_hashes,
            };
        }
        receipt.receipt_identity = receipt_identity(receipt);
        return ExplicitOwnerPublicEffectsAuthority(std::move(receipt));
    } catch (...) { refuse(); }
}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
ExplicitOwnerPublicEffectsAuthority
ExplicitOwnerPublicEffectsAuthority::test_only_mint(
        PublicExplicitOwnerEffects value) {
    value.receipt_identity = receipt_identity(value);
    return ExplicitOwnerPublicEffectsAuthority(std::move(value));
}
#endif

ExplicitOwnerPublicEffectsAuthority BaselinePublicEffectsCollector::collect(
    BaselineEffectsPlanAuthority&& selected,
    std::array<AuthenticatedOwnerEffectsDisclosureAuthority, 3>&& supplied) {
    try {
        const bool plan_live = selected.live_.exchange(false);
        bool disclosures_live = true;
        for (auto& disclosure : supplied)
            disclosures_live = disclosure.live_.exchange(false) &&
                               disclosures_live;
        need(plan_live && disclosures_live);
        validate(selected.value_);

        std::array<bool, 3> seen{};
        std::array<PublicOwnerEffect, 3> effects{};
        std::array<Digest, 3> actual_nullifiers{};
        std::array<Digest, 6> actual_tuples{};
        std::array<Digest, 3> sessions{};
        std::size_t tuple_at = 0;
        for (const auto& disclosure : supplied) {
            const auto& value = disclosure.value_;
            validate(value);
            need(value.classification == selected.value_.classification &&
                 value.round == selected.value_.round &&
                 value.run == selected.value_.run &&
                 value.trial == selected.value_.trial &&
                 value.attempt == selected.value_.attempt &&
                 value.cohort == selected.value_.cohort &&
                 value.capture_plan_identity ==
                     selected.value_.capture_plan_identity &&
                 value.projection_identity ==
                     selected.value_.projection_identity &&
                 value.context_identity == selected.value_.context_identity &&
                 !seen[value.owner] &&
                 value.owner_contract_identity ==
                     selected.value_.owner_contracts[value.owner]);
            seen[value.owner] = true;
            actual_nullifiers[value.owner] = value.public_nullifier;
            actual_tuples[tuple_at++] = value.public_tuple_hashes[0];
            actual_tuples[tuple_at++] = value.public_tuple_hashes[1];
            sessions[value.owner] = value.authenticated_session_identity;
            effects[value.owner] = PublicOwnerEffect{
                .owner = value.owner,
                .owner_contract_identity = value.owner_contract_identity,
                .public_nullifier = value.public_nullifier,
                .public_tuple_hashes = value.public_tuple_hashes,
            };
        }
        need(seen == std::array<bool, 3>{true, true, true});
        all_nonzero_distinct(sessions);
        std::sort(actual_nullifiers.begin(), actual_nullifiers.end());
        std::sort(actual_tuples.begin(), actual_tuples.end());
        need(actual_nullifiers == selected.value_.public_nullifiers &&
             actual_tuples == selected.value_.public_tuple_hashes);

        PublicExplicitOwnerEffects receipt{
            .status = "EXPLICIT_OWNER_PUBLIC_EFFECTS",
            .classification = selected.value_.classification,
            .round = selected.value_.round,
            .run = selected.value_.run,
            .trial = selected.value_.trial,
            .attempt = selected.value_.attempt,
            .cohort = selected.value_.cohort,
            .capture_plan_identity = selected.value_.capture_plan_identity,
            .projection_identity = selected.value_.projection_identity,
            .context_identity = selected.value_.context_identity,
            .owner_effects = effects,
        };
        receipt.receipt_identity =
            ExplicitOwnerPublicEffectsAuthority::receipt_identity(receipt);
        return ExplicitOwnerPublicEffectsAuthority(std::move(receipt));
    } catch (...) { refuse(); }
}

Digest BaselineDisclosureAuthorityBridge::policy_identity() {
    constexpr char label[] =
        "KPB_EXPLICIT_OWNER_PUBLIC_EFFECTS_POLICY_V1\n";
    return identity_registry::digest(std::span(
        reinterpret_cast<const unsigned char*>(label), sizeof(label) - 1));
}

BaselineEffectsPlanAuthority
BaselineDisclosureAuthorityBridge::from_verified_egress(
    VerifiedBaselinePublicEffectsAuthority&& verified) {
    try {
        need(verified.live_.exchange(false));
        validate(verified.value_);
        need(verified.value_.policy_identity == policy_identity());
        return BaselineEffectsPlanAuthority(std::move(verified.value_));
    } catch (...) { refuse(); }
}

SourceStatus source_status() {
    return SourceStatus{
        .schema = "kpb-baseline-public-effects-collector-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .classification_bound_to_capture_plan = true,
        .exact_three_owner_partition = true,
        .grouped_owner_mapping_preserved = true,
        .hidden_candidate_disclosure_factory_absent = true,
        .verified_egress_authority_integration = true,
        .authenticated_owner_ipc_integration = true,
        .parent_dispatcher_integration = true,
        .actual_capture_completion = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
