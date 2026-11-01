#include "fresh_owner_trial_issuance.hpp"
#include "fresh_owner_process_adapter.hpp"
#include "../../private_batch_trial/privacy_fresh_owner_transactional_replay_authority.hpp"

#include <algorithm>
#include <exception>
#include <set>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::fresh_owner_issuance {

enum class FreshOwnerTransactionalIssuanceOutcomeState : unsigned char {
    Pending,
    Committed,
    CommittedTransferredToRound1Process,
    UnavailableStop,
};

struct FreshOwnerTransactionalIssuanceOutcomeStorage final {
    FreshOwnerTransactionalIssuanceOutcomeState state{
        FreshOwnerTransactionalIssuanceOutcomeState::Pending};
    std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>
        prepared_receipt;
    std::optional<registered_driver::
        RegisteredPreidentityReadyIssuanceResidual> ready;
    std::optional<std::array<OwnerLocalIssuanceAuthority, 3>> owners;
    std::optional<kpb::measurement::fresh_owner_transactional_replay::
        FreshOwnerReplayOutcomeTransfer> replay_outcome;
    std::optional<FreshOwnerTrialIssuanceAuthority> issuance;
};
namespace {

using Bytes = std::vector<unsigned char>;

#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
void (*split_postprepare_hook)() = nullptr;
#endif

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

bool zero(const Digest& value) { return value == Digest{}; }

bool fresh_public_identity(const Digest& value) {
    return !zero(value) &&
        value != identity_registry::mandatory_aborted_run() &&
        value != mandatory_consumed_owner_root_identity();
}

void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(Bytes& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(Bytes& out, unsigned value) {
    for (unsigned index = 0; index < 4; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

void add(Bytes& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

Digest hash(const Bytes& bytes) { return identity_registry::digest(bytes); }

Digest hash(std::string_view value) {
    return identity_registry::digest(std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

Digest checked_hex(const std::string& value) {
    const auto result = identity_registry::unhex(value);
    need(identity_registry::hex(result) == value);
    return result;
}

std::string contract_metadata(const OwnerInputContract& value) {
    // This is a metadata identity, not an owner-body hash.  The selected
    // driver later revalidates canonical_owner_contract at its own boundary.
    for (const auto* identity : {
             &value.run_nonce, &value.model_identity,
             &value.source_identity, &value.proving_key_identity,
             &value.verifying_key_identity, &value.cohort_identity,
             &value.owner_certificate_sha256, &value.trace_identity,
             &value.layout_identity})
        (void)checked_hex(*identity);
    for (const auto& identity : value.server_certificate_sha256)
        (void)checked_hex(identity);
    need(value.owner_id >= 0 && value.owner_id < 3 &&
         value.input_count == OWNER_PRIVATE_INPUT_V2_BYTES / 32 - 1);
    std::set<std::string> certificates(
        value.server_certificate_sha256.begin(),
        value.server_certificate_sha256.end());
    need(certificates.size() == 3 &&
         !certificates.contains(value.owner_certificate_sha256));
    return "KPB_FRESH_OWNER_CONTRACT_METADATA_V1\n" + value.run_nonce +
        "\n" + value.model_identity + "\n" + value.source_identity + "\n" +
        value.proving_key_identity + "\n" + value.verifying_key_identity +
        "\n" + value.trace_identity + "\n" + value.layout_identity + "\n" +
        value.cohort_identity + "\n" + std::to_string(value.owner_id) +
        "\n" + std::to_string(value.input_count) + "\n" +
        value.server_certificate_sha256[0] + "\n" +
        value.server_certificate_sha256[1] + "\n" +
        value.server_certificate_sha256[2] + "\n" +
        value.owner_certificate_sha256 + "\n";
}

Digest contract_identity(const OwnerInputContract& value) {
    return hash(contract_metadata(value));
}

bool same_contract_family(
        const OwnerInputContract& left, const OwnerInputContract& right) {
    return left.model_identity == right.model_identity &&
        left.source_identity == right.source_identity &&
        left.proving_key_identity == right.proving_key_identity &&
        left.verifying_key_identity == right.verifying_key_identity &&
        left.trace_identity == right.trace_identity &&
        left.layout_identity == right.layout_identity &&
        left.input_count == right.input_count;
}

Digest logical_owner_binding(
        const PublicOwnerIssuanceReceipt& value,
        const LogicalOwnerIdentity& logical_owner,
        const Digest& nonce) {
    Bytes bytes;
    add(bytes, "KPB_FRESH_OWNER_OPAQUE_LOGICAL_BINDING_V1\n");
    add(bytes, value.run);
    add(bytes, value.trial);
    add(bytes, value.root_identity);
    add(bytes, value.owner_component);
    add(bytes, logical_owner);
    add(bytes, nonce);
    return hash(bytes);
}

Digest owner_issuance_identity(const PublicOwnerIssuanceReceipt& value) {
    Bytes bytes;
    add(bytes, "KPB_FRESH_OWNER_LOCAL_ISSUANCE_V1\n");
    add(bytes, static_cast<unsigned>(value.classification));
    for (const auto* identity : {
             &value.authority_identity, &value.registration_identity,
             &value.service_identity, &value.controller_source_identity,
             &value.controller_build_identity,
             &value.owner_issuer_source_identity,
             &value.owner_issuer_build_identity, &value.run, &value.trial,
             &value.root_identity, &value.baseline_policy_identity,
             &value.owner_process_identity, &value.logical_owner_binding})
        add(bytes, *identity);
    add(bytes, value.owner_component);
    for (const auto& round : value.rounds) {
        add(bytes, round.round);
        for (const auto* identity : {
                 &round.attempt, &round.cohort,
                 &round.accepted_input_head_identity,
                 &round.history_gate_identity, &round.contract_identity,
                 &round.file_identity, &round.file_metadata_identity,
                 &round.owner_tls_spki_identity})
            add(bytes, *identity);
        add(bytes, round.file_bytes);
        for (const auto& identity : round.server_tls_spki_identities)
            add(bytes, identity);
    }
    return hash(bytes);
}

void require_classification(const PublicOwnerIssuanceReceipt& value) {
    using registered_driver::CaptureClassification;
    need(value.classification == CaptureClassification::HiddenCandidate ||
         value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    if (value.classification ==
        CaptureClassification::ExplicitOwnerPublicEffectsBaseline)
        need(!zero(value.baseline_policy_identity));
    else
        need(zero(value.baseline_policy_identity));
}

void require_owner_receipt(PublicOwnerIssuanceReceipt& value) {
    require_classification(value);
    need(value.owner_component < 3 &&
         value.run != identity_registry::mandatory_aborted_run() &&
         value.root_identity != mandatory_consumed_owner_root_identity());
    for (const auto* identity : {
             &value.authority_identity, &value.registration_identity,
             &value.service_identity, &value.controller_source_identity,
             &value.controller_build_identity,
             &value.owner_issuer_source_identity,
             &value.owner_issuer_build_identity, &value.run, &value.trial,
             &value.root_identity, &value.owner_process_identity})
        need(!zero(*identity) &&
             *identity != identity_registry::mandatory_aborted_run() &&
             *identity != mandatory_consumed_owner_root_identity());

    std::set<Digest> lifecycle;
    std::set<Digest> files;
    std::set<Digest> owner_certificates;
    std::set<Digest> owner_spkis;
    std::set<Digest> server_certificates;
    std::set<Digest> server_spkis;
    for (unsigned index = 0; index < value.rounds.size(); ++index) {
        auto& round = value.rounds[index];
        need(round.round == index + 1 &&
             round.file_bytes == OWNER_PRIVATE_INPUT_V2_BYTES &&
             round.contract.owner_id ==
                 static_cast<int>(value.owner_component) &&
             round.contract.run_nonce == identity_registry::hex(round.attempt) &&
             round.contract.cohort_identity ==
                 identity_registry::hex(round.cohort));
        for (const auto* identity : {
                 &round.attempt, &round.cohort,
                 &round.accepted_input_head_identity,
                 &round.history_gate_identity, &round.file_identity,
                 &round.file_metadata_identity,
                 &round.owner_tls_spki_identity})
            need(!zero(*identity) &&
                 *identity != identity_registry::mandatory_aborted_run() &&
                 *identity != mandatory_consumed_owner_root_identity());
        need(lifecycle.insert(round.attempt).second &&
             lifecycle.insert(round.cohort).second &&
             lifecycle.insert(round.accepted_input_head_identity).second &&
             lifecycle.insert(round.history_gate_identity).second &&
             files.insert(round.file_identity).second &&
             files.insert(round.file_metadata_identity).second &&
             owner_spkis.insert(round.owner_tls_spki_identity).second);
        for (const auto& spki : round.server_tls_spki_identities)
            need(!zero(spki) && server_spkis.insert(spki).second);
        for (const auto& certificate :
             round.contract.server_certificate_sha256)
            need(server_certificates.insert(checked_hex(certificate)).second);
        need(owner_certificates.insert(checked_hex(
                 round.contract.owner_certificate_sha256)).second);
        round.contract_identity = contract_identity(round.contract);
    }
    need(same_contract_family(
        value.rounds[0].contract, value.rounds[1].contract));
}

bool same_common_receipt(
        const PublicOwnerIssuanceReceipt& left,
        const PublicOwnerIssuanceReceipt& right) {
    return left.classification == right.classification &&
        left.authority_identity == right.authority_identity &&
        left.registration_identity == right.registration_identity &&
        left.service_identity == right.service_identity &&
        left.controller_source_identity == right.controller_source_identity &&
        left.controller_build_identity == right.controller_build_identity &&
        left.owner_issuer_source_identity ==
            right.owner_issuer_source_identity &&
        left.owner_issuer_build_identity ==
            right.owner_issuer_build_identity &&
        left.run == right.run && left.trial == right.trial &&
        left.root_identity == right.root_identity &&
        left.baseline_policy_identity == right.baseline_policy_identity;
}

Digest aggregate_issuance_identity(
        const PublicFreshOwnerTrialIssuanceReceipt& value) {
    Bytes bytes;
    add(bytes, "KPB_FRESH_OWNER_TRIAL_ISSUANCE_V1\n");
    add(bytes, static_cast<unsigned>(value.classification));
    for (const auto* identity : {
             &value.authority_identity, &value.registration_identity,
             &value.service_identity, &value.controller_source_identity,
             &value.controller_build_identity,
             &value.owner_issuer_source_identity,
             &value.owner_issuer_build_identity, &value.run, &value.trial,
             &value.root_identity, &value.baseline_policy_identity,
             &value.roster_authority_identity,
             &value.replay_policy_identity})
        add(bytes, *identity);
    for (const auto& owner : value.owners)
        add(bytes, owner.issuance_identity);
    return hash(bytes);
}

Digest round_issuance_identity(
        const PublicFreshOwnerTrialIssuanceReceipt& value, unsigned round) {
    Bytes bytes;
    add(bytes, "KPB_FRESH_OWNER_ROUND_AUTHORITY_V1\n");
    add(bytes, value.issuance_identity);
    add(bytes, round);
    return hash(bytes);
}

Digest roster_issuance_identity(
        const PublicFreshOwnerTrialIssuanceReceipt& value) {
    Bytes bytes;
    add(bytes, "KPB_BASELINE_OWNER_ROSTER_AUTHORITY_V1\n");
    add(bytes, value.issuance_identity);
    add(bytes, value.roster_authority_identity);
    add(bytes, value.baseline_policy_identity);
    return hash(bytes);
}

Digest receiver_identity(
        const PublicBaselineOwnerRosterReceipt& value,
        unsigned round, unsigned role) {
    Bytes bytes;
    add(bytes, "KPB_BASELINE_OWNER_ROSTER_RECEIVER_V1\n");
    add(bytes, value.issuance_identity);
    add(bytes, round);
    add(bytes, role);
    return hash(bytes);
}

std::vector<Digest> replay_identities(
        const std::array<PublicOwnerIssuanceReceipt, 3>& owners) {
    std::vector<Digest> result{
        owners[0].run, owners[0].trial, owners[0].root_identity,
        owners[0].rounds[0].attempt, owners[0].rounds[0].cohort,
        owners[0].rounds[0].accepted_input_head_identity,
        owners[0].rounds[0].history_gate_identity,
        owners[0].rounds[1].attempt, owners[0].rounds[1].cohort,
        owners[0].rounds[1].accepted_input_head_identity,
        owners[0].rounds[1].history_gate_identity,
    };
    for (const auto& owner : owners) {
        result.push_back(owner.owner_process_identity);
        result.push_back(owner.logical_owner_binding);
        result.push_back(owner.issuance_identity);
        for (const auto& round : owner.rounds) {
            result.push_back(round.file_identity);
            result.push_back(round.file_metadata_identity);
            result.push_back(round.owner_tls_spki_identity);
            result.push_back(checked_hex(
                round.contract.owner_certificate_sha256));
        }
    }
    for (const auto& round : owners[0].rounds) {
        for (const auto& value : round.server_tls_spki_identities)
            result.push_back(value);
        for (const auto& value : round.contract.server_certificate_sha256)
            result.push_back(checked_hex(value));
    }
    need(std::set<Digest>(result.begin(), result.end()).size() ==
         result.size());
    return result;
}

} // namespace

OwnerLocalIssuanceAuthority::OwnerLocalIssuanceAuthority(
        PublicOwnerIssuanceReceipt receipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier> verifier,
        Digest binding_nonce,
        registered_driver::RegisteredOwnerIssuancePermit&& permit)
    : receipt_(std::move(receipt)), verifier_(std::move(verifier)),
      binding_nonce_(binding_nonce) {
    preidentity_permit_.emplace(std::move(permit));
    need(verifier_ != nullptr && !zero(binding_nonce_));
    logical_owner_identity_ = verifier_->logical_identity();
    need(!zero(logical_owner_identity_));
    require_owner_receipt(receipt_);
    receipt_.logical_owner_binding = logical_owner_binding(
        receipt_, logical_owner_identity_, binding_nonce_);
    receipt_.issuance_identity = owner_issuance_identity(receipt_);
}

OwnerLocalIssuanceAuthority::OwnerLocalIssuanceAuthority(
        PublicOwnerIssuanceReceipt&& receipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier>&& verifier,
        LogicalOwnerIdentity logical_owner_identity, Digest binding_nonce,
        registered_driver::RegisteredOwnerIssuancePermit&& permit) noexcept
    : receipt_(std::move(receipt)), verifier_(std::move(verifier)),
      logical_owner_identity_(logical_owner_identity),
      binding_nonce_(binding_nonce) {
    preidentity_permit_.emplace(std::move(permit));
}

#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
OwnerLocalIssuanceAuthority::OwnerLocalIssuanceAuthority(
        PublicOwnerIssuanceReceipt receipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier> verifier,
        Digest binding_nonce)
    : receipt_(std::move(receipt)), verifier_(std::move(verifier)),
      binding_nonce_(binding_nonce) {
    need(verifier_ != nullptr && !zero(binding_nonce_));
    logical_owner_identity_ = verifier_->logical_identity();
    need(!zero(logical_owner_identity_));
    require_owner_receipt(receipt_);
    receipt_.logical_owner_binding = logical_owner_binding(
        receipt_, logical_owner_identity_, binding_nonce_);
    receipt_.issuance_identity = owner_issuance_identity(receipt_);
}
#endif

OwnerLocalIssuanceAuthority::OwnerLocalIssuanceAuthority(
        OwnerLocalIssuanceAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      verifier_(std::move(other.verifier_)),
      logical_owner_identity_(other.logical_owner_identity_),
      binding_nonce_(other.binding_nonce_),
      preidentity_permit_(std::move(other.preidentity_permit_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
OwnerLocalIssuanceAuthority OwnerLocalIssuanceAuthority::test_only_mint(
        PublicOwnerIssuanceReceipt receipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier> verifier,
        Digest binding_nonce) {
    return OwnerLocalIssuanceAuthority(
        std::move(receipt), std::move(verifier), binding_nonce);
}

OwnerLocalIssuanceAuthority OwnerLocalIssuanceAuthority::test_only_mint(
        PublicOwnerIssuanceReceipt receipt,
        std::shared_ptr<const LongLivedOwnerProofVerifier> verifier,
        Digest binding_nonce,
        registered_driver::RegisteredOwnerIssuancePermit&& permit) {
    return OwnerLocalIssuanceAuthority(
        std::move(receipt), std::move(verifier), binding_nonce,
        std::move(permit));
}
#endif

OwnerIssuanceReplayGuardAuthority::OwnerIssuanceReplayGuardAuthority(
        PublicOwnerIssuanceReplayPolicy policy,
        std::shared_ptr<ExternalOwnerIssuanceReplayRegistry> registry)
    : policy_(policy), registry_(std::move(registry)) {
    need(registry_ != nullptr &&
         fresh_public_identity(policy_.authority_identity) &&
         fresh_public_identity(policy_.policy_identity) &&
         policy_.permission_separated &&
         policy_.monotonic && !policy_.child_path_exposed &&
         !policy_.child_fd_exposed);
}

OwnerIssuanceReplayGuardAuthority::OwnerIssuanceReplayGuardAuthority(
        OwnerIssuanceReplayGuardAuthority&& other) noexcept
    : policy_(other.policy_), registry_(std::move(other.registry_)),
      live_(other.live_.exchange(false)) {}

FreshOwnerTransactionalIssuanceOutcomeAuthority::
FreshOwnerTransactionalIssuanceOutcomeAuthority(
        std::unique_ptr<FreshOwnerTransactionalIssuanceOutcomeStorage>&&
            storage) noexcept
    : storage_(std::move(storage)) {}

FreshOwnerTransactionalIssuanceOutcomeAuthority::
FreshOwnerTransactionalIssuanceOutcomeAuthority(
        FreshOwnerTransactionalIssuanceOutcomeAuthority&&) noexcept =
    default;

FreshOwnerTransactionalIssuanceOutcomeAuthority::
~FreshOwnerTransactionalIssuanceOutcomeAuthority() = default;

bool FreshOwnerTransactionalIssuanceOutcomeAuthority::
committed_for_round1_process() const noexcept {
    return storage_ != nullptr &&
        storage_->state ==
            FreshOwnerTransactionalIssuanceOutcomeState::Committed &&
        storage_->issuance.has_value() &&
        storage_->replay_outcome.has_value();
}

FreshOwnerTrialIssuanceAuthority
FreshOwnerTransactionalIssuanceOutcomeAuthority::
take_committed_for_round1_process() noexcept {
    if (!committed_for_round1_process()) std::terminate();
    FreshOwnerTrialIssuanceAuthority result(
        std::move(*storage_->issuance));
    storage_->issuance.reset();
    storage_->state = FreshOwnerTransactionalIssuanceOutcomeState::
        CommittedTransferredToRound1Process;
    return result;
}

bool FreshOwnerTransactionalIssuanceOutcomeAuthority::
retains_round1_process_lineage() const noexcept {
    if (storage_ == nullptr || storage_->prepared_receipt == nullptr ||
        !storage_->replay_outcome.has_value())
        return false;
    if (storage_->state ==
        FreshOwnerTransactionalIssuanceOutcomeState::UnavailableStop)
        return !storage_->issuance.has_value() &&
            storage_->ready.has_value() && storage_->owners.has_value();
    if (storage_->state == FreshOwnerTransactionalIssuanceOutcomeState::
            CommittedTransferredToRound1Process)
        return !storage_->issuance.has_value() &&
            !storage_->ready.has_value() && !storage_->owners.has_value();
    return storage_->state ==
               FreshOwnerTransactionalIssuanceOutcomeState::Committed &&
        storage_->issuance.has_value() && !storage_->ready.has_value() &&
        !storage_->owners.has_value();
}

#ifdef KPI_FRESH_OWNER_TRANSACTIONAL_ISSUANCE_TEST_SETUP
TestFreshOwnerTransactionalIssuanceOutcome
FreshOwnerTransactionalIssuanceTestBridge::inspect(
        const FreshOwnerTransactionalIssuanceOutcomeAuthority& outcome)
        noexcept {
    if (outcome.storage_ == nullptr)
        return TestFreshOwnerTransactionalIssuanceOutcome::Invalid;
    const auto& storage = *outcome.storage_;
    if (storage.state ==
            FreshOwnerTransactionalIssuanceOutcomeState::Committed &&
        storage.prepared_receipt != nullptr &&
        storage.replay_outcome.has_value() &&
        storage.issuance.has_value() && !storage.ready.has_value() &&
        !storage.owners.has_value())
        return TestFreshOwnerTransactionalIssuanceOutcome::Committed;
    if (storage.state ==
            FreshOwnerTransactionalIssuanceOutcomeState::UnavailableStop &&
        storage.prepared_receipt != nullptr &&
        storage.replay_outcome.has_value() &&
        !storage.issuance.has_value() && storage.ready.has_value() &&
        storage.owners.has_value())
        return TestFreshOwnerTransactionalIssuanceOutcome::UnavailableStop;
    return TestFreshOwnerTransactionalIssuanceOutcome::Invalid;
}
#endif

#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
OwnerIssuanceReplayGuardAuthority
OwnerIssuanceReplayGuardAuthority::test_only_mint(
        PublicOwnerIssuanceReplayPolicy policy,
        std::shared_ptr<ExternalOwnerIssuanceReplayRegistry> registry) {
    return OwnerIssuanceReplayGuardAuthority(policy, std::move(registry));
}
#endif

FreshOwnerPersistentActivationAuthority::
FreshOwnerPersistentActivationAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt> receipt,
        registered_driver::RegisteredPreidentityReadyIssuanceResidual&& ready)
        noexcept
    : receipt_(std::move(receipt)), ready_(std::move(ready)) {}

FreshOwnerPersistentActivationAuthority::
FreshOwnerPersistentActivationAuthority(
        FreshOwnerPersistentActivationAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)), ready_(std::move(other.ready_)),
      live_(other.live_.exchange(false)) {}

FreshOwnerProducerClosureAuthority::FreshOwnerProducerClosureAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt> receipt)
        noexcept
    : receipt_(std::move(receipt)) {}

FreshOwnerProducerClosureAuthority::FreshOwnerProducerClosureAuthority(
        FreshOwnerProducerClosureAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      live_(other.live_.exchange(false)) {}

FreshOwnerTrialIssuanceAuthority::FreshOwnerTrialIssuanceAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt> receipt,
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
            verifiers,
        FreshOwnerPersistentActivationAuthority&& persistent_activation)
        noexcept
    : receipt_(std::move(receipt)), logical_owner_ids_(logical_owner_ids),
      verifiers_(std::move(verifiers)) {
    persistent_activation_.emplace(std::move(persistent_activation));
    producer_closure_.emplace(FreshOwnerProducerClosureAuthority(receipt_));
}

#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
FreshOwnerTrialIssuanceAuthority::FreshOwnerTrialIssuanceAuthority(
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt> receipt,
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
            verifiers)
    : receipt_(std::move(receipt)),
      logical_owner_ids_(logical_owner_ids),
      verifiers_(std::move(verifiers)) {}
#endif

FreshOwnerTrialIssuanceAuthority::FreshOwnerTrialIssuanceAuthority(
        FreshOwnerTrialIssuanceAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      logical_owner_ids_(other.logical_owner_ids_),
      verifiers_(std::move(other.verifiers_)),
      persistent_activation_(std::move(other.persistent_activation_)),
      producer_closure_(std::move(other.producer_closure_)),
      live_(other.live_.exchange(false)) {}

void FreshOwnerTrialIssuanceAuthority::
validate_for_persistent_activation() const {
    try {
        need(live_.load() && persistent_activation_.has_value() &&
             persistent_activation_->live_.load() && receipt_ != nullptr);
        const auto& receipt = *receipt_;
        using registered_driver::CaptureClassification;
        need(receipt.classification == CaptureClassification::HiddenCandidate ||
             receipt.classification == CaptureClassification::
                 ExplicitOwnerPublicEffectsBaseline);
        for (const auto* identity : {
                 &receipt.authority_identity,
                 &receipt.registration_identity,
                 &receipt.service_identity,
                 &receipt.controller_source_identity,
                 &receipt.controller_build_identity,
                 &receipt.owner_issuer_source_identity,
                 &receipt.owner_issuer_build_identity,
                 &receipt.run, &receipt.trial, &receipt.root_identity,
                 &receipt.replay_policy_identity,
                 &receipt.issuance_identity})
            need(fresh_public_identity(*identity));
        if (receipt.classification ==
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline)
            need(fresh_public_identity(receipt.baseline_policy_identity) &&
                 fresh_public_identity(receipt.roster_authority_identity));
        else
            need(zero(receipt.baseline_policy_identity) &&
                 zero(receipt.roster_authority_identity));

        std::set<LogicalOwnerIdentity> logical_ids;
        for (unsigned owner = 0; owner < receipt.owners.size(); ++owner) {
            const auto& retained = receipt.owners[owner];
            need(retained.owner_component == owner &&
                 verifiers_[owner] != nullptr &&
                 !zero(logical_owner_ids_[owner]) &&
                 verifiers_[owner]->logical_identity() ==
                     logical_owner_ids_[owner] &&
                 logical_ids.insert(logical_owner_ids_[owner]).second &&
                 fresh_public_identity(retained.logical_owner_binding) &&
                 fresh_public_identity(retained.issuance_identity));
            auto checked = retained;
            require_owner_receipt(checked);
            for (unsigned round = 0; round < 2; ++round)
                need(checked.rounds[round].contract_identity ==
                     retained.rounds[round].contract_identity);
            need(owner_issuance_identity(retained) ==
                     retained.issuance_identity &&
                 (owner == 0 ||
                  same_common_receipt(receipt.owners[0], retained)));
        }
        need(logical_ids.size() == 3 &&
             aggregate_issuance_identity(receipt) ==
                 receipt.issuance_identity);
        (void)replay_identities(receipt.owners);
    } catch (...) { refuse(); }
}

FreshOwnerRoundAuthority::FreshOwnerRoundAuthority(
        PublicFreshOwnerRoundReceipt receipt,
        std::array<OwnerInputContract, 3> contracts)
    : receipt_(std::move(receipt)), contracts_(std::move(contracts)) {}

FreshOwnerRoundAuthority::FreshOwnerRoundAuthority(
        FreshOwnerRoundAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      contracts_(std::move(other.contracts_)),
      live_(other.live_.exchange(false)) {}

BaselineOwnerRosterAuthority::BaselineOwnerRosterAuthority(
        PublicBaselineOwnerRosterReceipt receipt,
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
            verifiers)
    : receipt_(std::move(receipt)), logical_owner_ids_(logical_owner_ids),
      verifiers_(std::move(verifiers)) {}

BaselineOwnerRosterAuthority::BaselineOwnerRosterAuthority(
        BaselineOwnerRosterAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      logical_owner_ids_(other.logical_owner_ids_),
      verifiers_(std::move(other.verifiers_)),
      live_(other.live_.exchange(false)) {}

FreshOwnerTrialSplit::FreshOwnerTrialSplit(
        FreshOwnerRoundAuthority&& round1,
        FreshOwnerRoundAuthority&& round2,
        std::optional<BaselineOwnerRosterAuthority>&& roster,
        std::optional<FreshOwnerPersistentActivationAuthority>&&
            persistent_activation,
        std::optional<FreshOwnerProducerClosureAuthority>&& producer_closure)
        noexcept
    : roster_(std::move(roster)),
      persistent_activation_(std::move(persistent_activation)),
      producer_closure_(std::move(producer_closure)) {
    rounds_[0].emplace(std::move(round1));
    rounds_[1].emplace(std::move(round2));
}

FreshOwnerRoundAuthority FreshOwnerTrialSplit::take_round(unsigned round) {
    need(round == 1 || round == 2);
    auto& selected = rounds_[round - 1];
    need(selected.has_value());
    FreshOwnerRoundAuthority result(std::move(*selected));
    selected.reset();
    return result;
}

BaselineOwnerRosterAuthority
FreshOwnerTrialSplit::take_baseline_roster() {
    need(roster_.has_value());
    BaselineOwnerRosterAuthority result(std::move(*roster_));
    roster_.reset();
    return result;
}

FreshOwnerPersistentActivationAuthority
FreshOwnerTrialSplit::take_persistent_activation() {
    need(persistent_activation_.has_value());
    FreshOwnerPersistentActivationAuthority result(
        std::move(*persistent_activation_));
    persistent_activation_.reset();
    return result;
}

FreshOwnerProducerClosureAuthority
FreshOwnerTrialSplit::take_producer_closure() {
    need(producer_closure_.has_value());
    FreshOwnerProducerClosureAuthority result(
        std::move(*producer_closure_));
    producer_closure_.reset();
    return result;
}

BaselineOwnerRosterReceiverAuthority::
BaselineOwnerRosterReceiverAuthority(
        PublicBaselineOwnerRosterReceiverReceipt receipt,
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
            verifiers)
    : receipt_(std::move(receipt)), logical_owner_ids_(logical_owner_ids),
      verifiers_(std::move(verifiers)) {}

BaselineOwnerRosterReceiverAuthority::
BaselineOwnerRosterReceiverAuthority(
        BaselineOwnerRosterReceiverAuthority&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      logical_owner_ids_(other.logical_owner_ids_),
      verifiers_(std::move(other.verifiers_)),
      live_(other.live_.exchange(false)) {}

BaselineOwnerRosterReceiverSplit::BaselineOwnerRosterReceiverSplit(
        const PublicBaselineOwnerRosterReceipt& roster,
        const std::array<LogicalOwnerIdentity, 3>& logical_owner_ids,
        const std::array<
            std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>& verifiers) {
    for (unsigned round = 1; round <= 2; ++round) {
        for (unsigned role = 0; role < 3; ++role) {
            PublicBaselineOwnerRosterReceiverReceipt receipt{
                .classification = roster.classification,
                .round = round,
                .role = role,
                .run = roster.run,
                .trial = roster.trial,
                .root_identity = roster.root_identity,
                .policy_identity = roster.policy_identity,
                .roster_authority_identity =
                    roster.roster_authority_identity,
                .receiver_identity = receiver_identity(roster, round, role),
            };
            auto authority = BaselineOwnerRosterReceiverAuthority(
                std::move(receipt), logical_owner_ids, verifiers);
            receivers_[(round - 1) * 3 + role].emplace(
                std::move(authority));
        }
    }
}

BaselineOwnerRosterReceiverAuthority
BaselineOwnerRosterReceiverSplit::take(unsigned round, unsigned role) {
    need((round == 1 || round == 2) && role < 3);
    auto& selected = receivers_[(round - 1) * 3 + role];
    need(selected.has_value());
    BaselineOwnerRosterReceiverAuthority result(std::move(*selected));
    selected.reset();
    return result;
}

VerifiedLogicalOwnerConsent::VerifiedLogicalOwnerConsent(
        unsigned owner, LogicalOwnerIdentity logical_owner_identity)
    : owner_(owner), logical_owner_identity_(logical_owner_identity) {}

VerifiedLogicalOwnerConsent::VerifiedLogicalOwnerConsent(
        VerifiedLogicalOwnerConsent&& other) noexcept
    : owner_(other.owner_),
      logical_owner_identity_(other.logical_owner_identity_),
      live_(other.live_.exchange(false)) {}

VerifiedBaselineOwnerRoster::VerifiedBaselineOwnerRoster(
        PublicBaselineOwnerRosterReceiverReceipt receipt,
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids)
    : receipt_(std::move(receipt)), logical_owner_ids_(logical_owner_ids) {}

VerifiedBaselineOwnerRoster::VerifiedBaselineOwnerRoster(
        VerifiedBaselineOwnerRoster&& other) noexcept
    : receipt_(std::move(other.receipt_)),
      logical_owner_ids_(other.logical_owner_ids_),
      live_(other.live_.exchange(false)) {}

ConsumedVerifiedLogicalOwnerConsent::ConsumedVerifiedLogicalOwnerConsent(
        unsigned owner, LogicalOwnerIdentity logical_owner_identity)
    : owner_(owner), logical_owner_identity_(logical_owner_identity) {}

ConsumedVerifiedBaselineOwnerRoster::ConsumedVerifiedBaselineOwnerRoster(
        PublicBaselineOwnerRosterReceiverReceipt receipt,
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids)
    : receipt_(std::move(receipt)), logical_owner_ids_(logical_owner_ids) {}

ConsumedVerifiedLogicalOwnerConsent
BaselineOwnerRosterVerifiedBridge::consume(
        VerifiedLogicalOwnerConsent&& consent) {
    need(consent.live_.exchange(false) && consent.owner_ < 3 &&
         !zero(consent.logical_owner_identity_));
    return ConsumedVerifiedLogicalOwnerConsent(
        consent.owner_, consent.logical_owner_identity_);
}

ConsumedVerifiedBaselineOwnerRoster
BaselineOwnerRosterVerifiedBridge::consume(
        VerifiedBaselineOwnerRoster&& roster) {
    need(roster.live_.exchange(false) &&
         roster.receipt_.classification ==
             registered_driver::CaptureClassification::
                 ExplicitOwnerPublicEffectsBaseline &&
         roster.receipt_.round >= 1 && roster.receipt_.round <= 2 &&
         roster.receipt_.role < 3 &&
         std::ranges::none_of(
             roster.logical_owner_ids_,
             [](const auto& value) { return zero(value); }));
    return ConsumedVerifiedBaselineOwnerRoster(
        roster.receipt_, roster.logical_owner_ids_);
}

BaselineOwnerRosterReceiverSession::BaselineOwnerRosterReceiverSession(
        PublicBaselineOwnerRosterReceiverReceipt receipt,
        std::array<LogicalOwnerIdentity, 3> logical_owner_ids,
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
            verifiers)
    : receipt_(std::move(receipt)), logical_owner_ids_(logical_owner_ids),
      verifiers_(std::move(verifiers)) {}

VerifiedLogicalOwnerConsent
BaselineOwnerRosterReceiverSession::verify_owner_proof(
        unsigned owner, std::span<const unsigned char> challenge,
        std::span<const unsigned char> proof) {
    try {
        need(!poisoned_ && !finished_ && owner < 3 &&
             !verified_[owner] && verifiers_[owner] != nullptr &&
             verifiers_[owner]->logical_identity() ==
                 logical_owner_ids_[owner] &&
             verifiers_[owner]->verify(challenge, proof));
        verified_[owner] = true;
        return VerifiedLogicalOwnerConsent(
            owner, logical_owner_ids_[owner]);
    } catch (...) {
        poisoned_ = true;
        throw;
    }
}

VerifiedBaselineOwnerRoster
BaselineOwnerRosterReceiverSession::finish() {
    try {
        need(!poisoned_ && !finished_ &&
             std::ranges::all_of(verified_, [](bool value) { return value; }));
        finished_ = true;
        return VerifiedBaselineOwnerRoster(receipt_, logical_owner_ids_);
    } catch (...) {
        poisoned_ = true;
        throw;
    }
}

FreshOwnerTrialIssuanceAuthority
FreshOwnerTrialIssuanceBridge::join_exact_three_impl(
        registered_driver::RegisteredPreidentityReadyIssuanceResidual* ready,
        std::array<OwnerLocalIssuanceAuthority, 3>&& authorities,
        OwnerIssuanceReplayGuardAuthority&& replay,
        const Digest& roster_authority_identity) {
    try {
        if (ready != nullptr)
            registered_driver::RegisteredPreidentityReadyIssuanceBridge::
                validate_owner_lineage(
                    *ready, authorities[0], authorities[1], authorities[2]);
#ifndef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
        else
            refuse();
#endif
        need(replay.live_.load() && replay.registry_ != nullptr);
        // Preallocate the immutable aggregate receipt before any replay or
        // owner capability is claimed. All receipt/string copies and set
        // allocations below therefore fail while the caller still owns every
        // linear input.
        auto result =
            std::make_shared<PublicFreshOwnerTrialIssuanceReceipt>();
        std::array<PublicOwnerIssuanceReceipt, 3> receipts{};
        std::array<LogicalOwnerIdentity, 3> logical_ids{};
        std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
            verifiers{};
        for (unsigned owner = 0; owner < authorities.size(); ++owner) {
            auto& authority = authorities[owner];
            need(authority.live_.load() &&
                 authority.receipt_.owner_component == owner &&
                 authority.verifier_ != nullptr);
            receipts[owner] = authority.receipt_;
            logical_ids[owner] = authority.logical_owner_identity_;
            verifiers[owner] = authority.verifier_;
            if (owner != 0) need(same_common_receipt(receipts[0], receipts[owner]));
        }
        if (receipts[0].classification ==
            registered_driver::CaptureClassification::
                ExplicitOwnerPublicEffectsBaseline)
            need(fresh_public_identity(roster_authority_identity));
        else
            need(zero(roster_authority_identity));
        need(std::set<LogicalOwnerIdentity>(
                 logical_ids.begin(), logical_ids.end()).size() == 3);

        std::set<Digest> process_ids, bindings, file_ids, metadata_ids;
        std::set<Digest> all_tls_certificates, all_tls_spkis;
        for (unsigned owner = 0; owner < receipts.size(); ++owner) {
            const auto& receipt = receipts[owner];
            need(process_ids.insert(receipt.owner_process_identity).second &&
                 bindings.insert(receipt.logical_owner_binding).second);
            for (unsigned round = 0; round < 2; ++round) {
                const auto& item = receipt.rounds[round];
                need(item.round == round + 1 &&
                     item.attempt == receipts[0].rounds[round].attempt &&
                     item.cohort == receipts[0].rounds[round].cohort &&
                     item.accepted_input_head_identity ==
                         receipts[0].rounds[round]
                             .accepted_input_head_identity &&
                     item.history_gate_identity ==
                         receipts[0].rounds[round].history_gate_identity &&
                     item.contract.server_certificate_sha256 ==
                         receipts[0].rounds[round]
                             .contract.server_certificate_sha256 &&
                     item.server_tls_spki_identities ==
                         receipts[0].rounds[round]
                             .server_tls_spki_identities &&
                     same_contract_family(
                         receipts[0].rounds[0].contract, item.contract) &&
                     file_ids.insert(item.file_identity).second &&
                     metadata_ids.insert(item.file_metadata_identity).second &&
                     all_tls_certificates.insert(checked_hex(
                         item.contract.owner_certificate_sha256)).second &&
                     all_tls_spkis.insert(
                         item.owner_tls_spki_identity).second);
            }
        }
        for (unsigned round = 0; round < 2; ++round) {
            for (const auto& certificate :
                 receipts[0].rounds[round]
                     .contract.server_certificate_sha256)
                need(all_tls_certificates.insert(
                    checked_hex(certificate)).second);
            for (const auto& spki :
                 receipts[0].rounds[round].server_tls_spki_identities)
                need(all_tls_spkis.insert(spki).second);
        }
        need(all_tls_certificates.size() == 12 &&
             all_tls_spkis.size() == 12);

        const auto& first = receipts[0];
        *result = PublicFreshOwnerTrialIssuanceReceipt{
            .classification = first.classification,
            .authority_identity = first.authority_identity,
            .registration_identity = first.registration_identity,
            .service_identity = first.service_identity,
            .controller_source_identity = first.controller_source_identity,
            .controller_build_identity = first.controller_build_identity,
            .owner_issuer_source_identity =
                first.owner_issuer_source_identity,
            .owner_issuer_build_identity =
                first.owner_issuer_build_identity,
            .run = first.run,
            .trial = first.trial,
            .root_identity = first.root_identity,
            .baseline_policy_identity = first.baseline_policy_identity,
            .roster_authority_identity = roster_authority_identity,
            .replay_policy_identity = replay.policy_.policy_identity,
            .owners = receipts,
        };
        result->issuance_identity = aggregate_issuance_identity(*result);
        const auto consumed = replay_identities(receipts);
        std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>
            immutable_result = result;

        // The legacy registry interface is not transactional; the dedicated
        // two-phase replacement remains a source-status blocker. Within this
        // interface, all potentially allocating local work is complete before
        // the replay guard is claimed and the external consume is invoked.
        need(replay.live_.exchange(false));
        replay.registry_->consume(consumed);
        for (auto& authority : authorities)
            if (!authority.live_.exchange(false)) std::terminate();
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
        if (ready == nullptr)
            return FreshOwnerTrialIssuanceAuthority(
                immutable_result, logical_ids, std::move(verifiers));
#endif
        auto persistent_activation = FreshOwnerPersistentActivationAuthority(
            immutable_result, std::move(*ready));
        return FreshOwnerTrialIssuanceAuthority(
            std::move(immutable_result), logical_ids, std::move(verifiers),
            std::move(persistent_activation));
    } catch (...) { refuse(); }
}

FreshOwnerTrialIssuanceAuthority
FreshOwnerTrialIssuanceBridge::join_exact_three(
        registered_driver::RegisteredPreidentityReadyIssuanceResidual&& ready,
        std::array<OwnerLocalIssuanceAuthority, 3>&& authorities,
        OwnerIssuanceReplayGuardAuthority&& replay,
        const Digest& roster_authority_identity) {
    return join_exact_three_impl(
        &ready, std::move(authorities), std::move(replay),
        roster_authority_identity);
}

FreshOwnerTransactionalIssuanceOutcomeAuthority
FreshOwnerTransactionalIssuanceBridge::join_authenticated_exact_three(
        registered_driver::RegisteredPreidentityReadyAuthority&& ready,
        AuthenticatedOwnerProcessBundle&& owner0,
        AuthenticatedOwnerProcessBundle&& owner1,
        AuthenticatedOwnerProcessBundle&& owner2,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&& selected_registry,
        const std::array<unsigned char, 32>& roster_authority_identity) {
    namespace replay =
        kpb::measurement::fresh_owner_transactional_replay;

    // Everything below this validation through replay prepare is staging:
    // Ready and all three authenticated process bundles remain live.  The
    // selected registry prepare is deliberately the final throwing action.
    const void* const epoch_token = registered_driver::
        RegisteredPreidentityReadyIssuanceBridge::
            validate_for_transactional_staging(ready);
    need(epoch_token != nullptr);
    const std::array<AuthenticatedOwnerProcessBundle*, 3> bundles{
        &owner0, &owner1, &owner2};
    std::array<PublicOwnerIssuanceReceipt, 3> receipts{};
    std::array<LogicalOwnerIdentity, 3> logical_ids{};
    std::array<Digest, 3> binding_nonces{};
    std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
        owner_verifiers{};
    for (unsigned owner = 0; owner < bundles.size(); ++owner) {
        const auto& bundle = *bundles[owner];
        need(bundle.live_.load() && bundle.verifier_ != nullptr &&
             bundle.receipt_.owner_component == owner &&
             !zero(bundle.binding_nonce_));
        receipts[owner] = bundle.receipt_;
        logical_ids[owner] = bundle.logical_owner_identity_;
        binding_nonces[owner] = bundle.binding_nonce_;
        owner_verifiers[owner] = bundle.verifier_;
        need(!zero(logical_ids[owner]) &&
             owner_verifiers[owner]->logical_identity() ==
                 logical_ids[owner]);
        require_owner_receipt(receipts[owner]);
        receipts[owner].logical_owner_binding = logical_owner_binding(
            receipts[owner], logical_ids[owner], binding_nonces[owner]);
        receipts[owner].issuance_identity =
            owner_issuance_identity(receipts[owner]);
        if (owner != 0)
            need(same_common_receipt(receipts[0], receipts[owner]));
    }
    if (receipts[0].classification ==
        registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline)
        need(fresh_public_identity(roster_authority_identity));
    else
        need(zero(roster_authority_identity));
    need(std::set<LogicalOwnerIdentity>(
             logical_ids.begin(), logical_ids.end()).size() == 3);

    std::set<Digest> process_ids, bindings, file_ids, metadata_ids;
    std::set<Digest> all_tls_certificates, all_tls_spkis;
    for (unsigned owner = 0; owner < receipts.size(); ++owner) {
        const auto& owner_receipt = receipts[owner];
        need(process_ids.insert(
                 owner_receipt.owner_process_identity).second &&
             bindings.insert(owner_receipt.logical_owner_binding).second);
        for (unsigned round = 0; round < 2; ++round) {
            const auto& item = owner_receipt.rounds[round];
            need(item.round == round + 1 &&
                 item.attempt == receipts[0].rounds[round].attempt &&
                 item.cohort == receipts[0].rounds[round].cohort &&
                 item.accepted_input_head_identity ==
                     receipts[0].rounds[round]
                         .accepted_input_head_identity &&
                 item.history_gate_identity ==
                     receipts[0].rounds[round].history_gate_identity &&
                 item.contract.server_certificate_sha256 ==
                     receipts[0].rounds[round]
                         .contract.server_certificate_sha256 &&
                 item.server_tls_spki_identities ==
                     receipts[0].rounds[round]
                         .server_tls_spki_identities &&
                 same_contract_family(
                     receipts[0].rounds[0].contract, item.contract) &&
                 file_ids.insert(item.file_identity).second &&
                 metadata_ids.insert(item.file_metadata_identity).second &&
                 all_tls_certificates.insert(checked_hex(
                     item.contract.owner_certificate_sha256)).second &&
                 all_tls_spkis.insert(
                     item.owner_tls_spki_identity).second);
        }
    }
    for (unsigned round = 0; round < 2; ++round) {
        for (const auto& certificate :
             receipts[0].rounds[round].contract.server_certificate_sha256)
            need(all_tls_certificates.insert(
                checked_hex(certificate)).second);
        for (const auto& spki :
             receipts[0].rounds[round].server_tls_spki_identities)
            need(all_tls_spkis.insert(spki).second);
    }
    need(all_tls_certificates.size() == 12 &&
         all_tls_spkis.size() == 12);

    const auto registry_identity =
        selected_registry.registry_identity_for_transactional_prepare();
    const auto replay_policy_identity =
        selected_registry.replay_policy_identity_for_transactional_prepare();
    need(fresh_public_identity(registry_identity) &&
         fresh_public_identity(replay_policy_identity) &&
         registry_identity != replay_policy_identity);
    auto receipt = std::make_shared<PublicFreshOwnerTrialIssuanceReceipt>();
    auto outcome_storage =
        std::make_unique<FreshOwnerTransactionalIssuanceOutcomeStorage>();
    const auto& first = receipts[0];
    *receipt = PublicFreshOwnerTrialIssuanceReceipt{
        .classification = first.classification,
        .authority_identity = first.authority_identity,
        .registration_identity = first.registration_identity,
        .service_identity = first.service_identity,
        .controller_source_identity = first.controller_source_identity,
        .controller_build_identity = first.controller_build_identity,
        .owner_issuer_source_identity = first.owner_issuer_source_identity,
        .owner_issuer_build_identity = first.owner_issuer_build_identity,
        .run = first.run,
        .trial = first.trial,
        .root_identity = first.root_identity,
        .baseline_policy_identity = first.baseline_policy_identity,
        .roster_authority_identity = roster_authority_identity,
        .replay_policy_identity = replay_policy_identity,
        .owners = receipts,
    };
    receipt->issuance_identity = aggregate_issuance_identity(*receipt);
    const auto replay_values = replay_identities(receipts);
    need(replay_values.size() == replay::EXACT_OWNER_REPLAY_IDENTITY_COUNT);
    replay::ExactOwnerReplaySet exact_replay_set{};
    std::ranges::copy(replay_values, exact_replay_set.begin());
    std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>
        immutable_receipt = receipt;
    outcome_storage->prepared_receipt = immutable_receipt;

    // Prebuild the exact owner capabilities and final verifier array without
    // claiming their source bundles.  They remain bridge-local until prepare
    // succeeds, and simply destruct if staging or prepare refuses.
    auto issuance_verifiers = owner_verifiers;
    std::array<OwnerLocalIssuanceAuthority, 3> staged_owners{
        OwnerLocalIssuanceAuthority(
            std::move(receipts[0]), std::move(owner_verifiers[0]),
            logical_ids[0], binding_nonces[0],
            registered_driver::RegisteredOwnerIssuancePermit(
                epoch_token, 0)),
        OwnerLocalIssuanceAuthority(
            std::move(receipts[1]), std::move(owner_verifiers[1]),
            logical_ids[1], binding_nonces[1],
            registered_driver::RegisteredOwnerIssuancePermit(
                epoch_token, 1)),
        OwnerLocalIssuanceAuthority(
            std::move(receipts[2]), std::move(owner_verifiers[2]),
            logical_ids[2], binding_nonces[2],
            registered_driver::RegisteredOwnerIssuancePermit(
                epoch_token, 2)),
    };

    replay::FreshOwnerReplayPrepareAuthority prepared = [&] {
        try {
            return replay::FreshOwnerTransactionalReplayBridge::prepare(
                std::move(selected_registry), exact_replay_set);
        } catch (...) { refuse(); }
    }();

    static_assert(std::is_nothrow_move_constructible_v<
        registered_driver::RegisteredPreidentityReadyIssuanceResidual>);
    static_assert(std::is_nothrow_move_constructible_v<
        AuthenticatedOwnerProcessBundle>);
    static_assert(std::is_nothrow_move_constructible_v<
        OwnerLocalIssuanceAuthority>);
    for (auto* bundle : bundles)
        if (!bundle->live_.exchange(false)) std::terminate();
    outcome_storage->ready.emplace(
        registered_driver::RegisteredPreidentityReadyIssuanceBridge::
            consume_for_transactional_issuance(std::move(ready)));
    outcome_storage->owners.emplace(std::move(staged_owners));

    auto replay_outcome =
        replay::FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(prepared));
    auto replay_transfer =
        std::move(replay_outcome).transfer_for_transactional_issuance();
    const bool committed =
        replay_transfer.committed_for_transactional_issuance() &&
        replay_transfer.registry_identity_for_transactional_issuance() ==
            registry_identity &&
        replay_transfer.replay_policy_identity_for_transactional_issuance() ==
            replay_policy_identity;
    outcome_storage->replay_outcome.emplace(std::move(replay_transfer));
    if (!committed) {
        outcome_storage->state =
            FreshOwnerTransactionalIssuanceOutcomeState::UnavailableStop;
        return FreshOwnerTransactionalIssuanceOutcomeAuthority(
            std::move(outcome_storage));
    }

    for (auto& authority : *outcome_storage->owners)
        if (!authority.live_.exchange(false)) std::terminate();
    FreshOwnerPersistentActivationAuthority persistent_activation(
        immutable_receipt, std::move(*outcome_storage->ready));
    outcome_storage->ready.reset();
    outcome_storage->owners.reset();
    outcome_storage->issuance.emplace(
        FreshOwnerTrialIssuanceAuthority(
            std::move(immutable_receipt), logical_ids,
            std::move(issuance_verifiers),
            std::move(persistent_activation)));
    outcome_storage->state =
        FreshOwnerTransactionalIssuanceOutcomeState::Committed;
    return FreshOwnerTransactionalIssuanceOutcomeAuthority(
        std::move(outcome_storage));
}

FreshOwnerTransactionalIssuanceOutcomeAuthority
FreshOwnerTransactionalIssuanceBridge::join_exact_three(
        registered_driver::RegisteredPreidentityReadyIssuanceResidual&& ready,
        OwnerLocalIssuanceAuthority&& owner0,
        OwnerLocalIssuanceAuthority&& owner1,
        OwnerLocalIssuanceAuthority&& owner2,
        kpb::measurement::fresh_owner_transactional_replay::
            SelectedOwnerReplayRegistryAuthority&& selected_registry,
        const std::array<unsigned char, 32>& roster_authority_identity) {
    namespace replay =
        kpb::measurement::fresh_owner_transactional_replay;

    registered_driver::RegisteredPreidentityReadyIssuanceBridge::
        validate_owner_lineage(ready, owner0, owner1, owner2);
    const std::array<OwnerLocalIssuanceAuthority*, 3> authorities{
        &owner0, &owner1, &owner2};
    auto receipt = std::make_shared<PublicFreshOwnerTrialIssuanceReceipt>();
    auto outcome_storage =
        std::make_unique<FreshOwnerTransactionalIssuanceOutcomeStorage>();
    std::array<PublicOwnerIssuanceReceipt, 3> receipts{};
    std::array<LogicalOwnerIdentity, 3> logical_ids{};
    std::array<std::shared_ptr<const LongLivedOwnerProofVerifier>, 3>
        verifiers{};
    for (unsigned owner = 0; owner < authorities.size(); ++owner) {
        const auto& authority = *authorities[owner];
        need(authority.live_.load() &&
             authority.receipt_.owner_component == owner &&
             authority.verifier_ != nullptr);
        receipts[owner] = authority.receipt_;
        logical_ids[owner] = authority.logical_owner_identity_;
        verifiers[owner] = authority.verifier_;
        if (owner != 0)
            need(same_common_receipt(receipts[0], receipts[owner]));
    }
    if (receipts[0].classification ==
        registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline)
        need(fresh_public_identity(roster_authority_identity));
    else
        need(zero(roster_authority_identity));
    need(std::set<LogicalOwnerIdentity>(
             logical_ids.begin(), logical_ids.end()).size() == 3);

    std::set<Digest> process_ids, bindings, file_ids, metadata_ids;
    std::set<Digest> all_tls_certificates, all_tls_spkis;
    for (unsigned owner = 0; owner < receipts.size(); ++owner) {
        const auto& owner_receipt = receipts[owner];
        need(process_ids.insert(
                 owner_receipt.owner_process_identity).second &&
             bindings.insert(owner_receipt.logical_owner_binding).second);
        for (unsigned round = 0; round < 2; ++round) {
            const auto& item = owner_receipt.rounds[round];
            need(item.round == round + 1 &&
                 item.attempt == receipts[0].rounds[round].attempt &&
                 item.cohort == receipts[0].rounds[round].cohort &&
                 item.accepted_input_head_identity ==
                     receipts[0].rounds[round]
                         .accepted_input_head_identity &&
                 item.history_gate_identity ==
                     receipts[0].rounds[round].history_gate_identity &&
                 item.contract.server_certificate_sha256 ==
                     receipts[0].rounds[round]
                         .contract.server_certificate_sha256 &&
                 item.server_tls_spki_identities ==
                     receipts[0].rounds[round]
                         .server_tls_spki_identities &&
                 same_contract_family(
                     receipts[0].rounds[0].contract, item.contract) &&
                 file_ids.insert(item.file_identity).second &&
                 metadata_ids.insert(item.file_metadata_identity).second &&
                 all_tls_certificates.insert(checked_hex(
                     item.contract.owner_certificate_sha256)).second &&
                 all_tls_spkis.insert(
                     item.owner_tls_spki_identity).second);
        }
    }
    for (unsigned round = 0; round < 2; ++round) {
        for (const auto& certificate :
             receipts[0].rounds[round].contract.server_certificate_sha256)
            need(all_tls_certificates.insert(
                checked_hex(certificate)).second);
        for (const auto& spki :
             receipts[0].rounds[round].server_tls_spki_identities)
            need(all_tls_spkis.insert(spki).second);
    }
    need(all_tls_certificates.size() == 12 &&
         all_tls_spkis.size() == 12);

    const auto registry_identity =
        selected_registry.registry_identity_for_transactional_prepare();
    const auto replay_policy_identity =
        selected_registry.replay_policy_identity_for_transactional_prepare();
    need(fresh_public_identity(registry_identity) &&
         fresh_public_identity(replay_policy_identity) &&
         registry_identity != replay_policy_identity);
    const auto& first = receipts[0];
    *receipt = PublicFreshOwnerTrialIssuanceReceipt{
        .classification = first.classification,
        .authority_identity = first.authority_identity,
        .registration_identity = first.registration_identity,
        .service_identity = first.service_identity,
        .controller_source_identity = first.controller_source_identity,
        .controller_build_identity = first.controller_build_identity,
        .owner_issuer_source_identity = first.owner_issuer_source_identity,
        .owner_issuer_build_identity = first.owner_issuer_build_identity,
        .run = first.run,
        .trial = first.trial,
        .root_identity = first.root_identity,
        .baseline_policy_identity = first.baseline_policy_identity,
        .roster_authority_identity = roster_authority_identity,
        .replay_policy_identity = replay_policy_identity,
        .owners = receipts,
    };
    receipt->issuance_identity = aggregate_issuance_identity(*receipt);

    const auto replay_values = replay_identities(receipts);
    need(replay_values.size() == replay::EXACT_OWNER_REPLAY_IDENTITY_COUNT);
    replay::ExactOwnerReplaySet exact_replay_set{};
    std::ranges::copy(replay_values, exact_replay_set.begin());
    std::shared_ptr<const PublicFreshOwnerTrialIssuanceReceipt>
        immutable_receipt = receipt;
    outcome_storage->prepared_receipt = immutable_receipt;

    replay::FreshOwnerReplayPrepareAuthority prepared = [&] {
        try {
            return replay::FreshOwnerTransactionalReplayBridge::prepare(
                std::move(selected_registry), exact_replay_set);
        } catch (...) { refuse(); }
    }();

    static_assert(std::is_nothrow_move_constructible_v<
        registered_driver::RegisteredPreidentityReadyIssuanceResidual>);
    static_assert(std::is_nothrow_move_constructible_v<
        OwnerLocalIssuanceAuthority>);
    outcome_storage->ready.emplace(std::move(ready));
    outcome_storage->owners.emplace(
        std::array<OwnerLocalIssuanceAuthority, 3>{
            std::move(owner0), std::move(owner1), std::move(owner2)});
    auto replay_outcome =
        replay::FreshOwnerTransactionalReplayBridge::commit_after_claim(
            std::move(prepared));
    auto replay_transfer =
        std::move(replay_outcome).transfer_for_transactional_issuance();
    const bool committed =
        replay_transfer.committed_for_transactional_issuance() &&
        replay_transfer.registry_identity_for_transactional_issuance() ==
            registry_identity &&
        replay_transfer.replay_policy_identity_for_transactional_issuance() ==
            replay_policy_identity;
    outcome_storage->replay_outcome.emplace(std::move(replay_transfer));
    if (!committed) {
        outcome_storage->state =
            FreshOwnerTransactionalIssuanceOutcomeState::UnavailableStop;
        return FreshOwnerTransactionalIssuanceOutcomeAuthority(
            std::move(outcome_storage));
    }

    for (auto& authority : *outcome_storage->owners)
        if (!authority.live_.exchange(false)) std::terminate();
    FreshOwnerPersistentActivationAuthority persistent_activation(
        immutable_receipt, std::move(*outcome_storage->ready));
    outcome_storage->ready.reset();
    outcome_storage->owners.reset();
    FreshOwnerTrialIssuanceAuthority committed_issuance(
        std::move(immutable_receipt), logical_ids, std::move(verifiers),
        std::move(persistent_activation));
    outcome_storage->issuance.emplace(std::move(committed_issuance));
    outcome_storage->state =
        FreshOwnerTransactionalIssuanceOutcomeState::Committed;
    return FreshOwnerTransactionalIssuanceOutcomeAuthority(
        std::move(outcome_storage));
}

#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
FreshOwnerTrialIssuanceAuthority
FreshOwnerTrialIssuanceBridge::join_exact_three(
        std::array<OwnerLocalIssuanceAuthority, 3>&& authorities,
        OwnerIssuanceReplayGuardAuthority&& replay,
        const Digest& roster_authority_identity) {
    return join_exact_three_impl(
        nullptr, std::move(authorities), std::move(replay),
        roster_authority_identity);
}
#endif

FreshOwnerTrialSplit FreshOwnerTrialIssuanceBridge::split(
        FreshOwnerTrialIssuanceAuthority&& authority) {
    try {
        need(authority.live_.load());
#ifndef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
        need(authority.persistent_activation_.has_value() &&
             authority.producer_closure_.has_value());
#endif
        need(authority.receipt_ != nullptr);
        const auto& value = *authority.receipt_;
        std::array<PublicFreshOwnerRoundReceipt, 2> public_rounds{};
        std::array<std::array<OwnerInputContract, 3>, 2> contracts{};
        for (unsigned round = 0; round < 2; ++round) {
            public_rounds[round] = PublicFreshOwnerRoundReceipt{
                .classification = value.classification,
                .round = round + 1,
                .authority_identity = value.authority_identity,
                .registration_identity = value.registration_identity,
                .service_identity = value.service_identity,
                .controller_source_identity =
                    value.controller_source_identity,
                .controller_build_identity =
                    value.controller_build_identity,
                .run = value.run,
                .trial = value.trial,
                .attempt = value.owners[0].rounds[round].attempt,
                .cohort = value.owners[0].rounds[round].cohort,
                .accepted_input_head_identity =
                    value.owners[0].rounds[round]
                        .accepted_input_head_identity,
                .history_gate_identity =
                    value.owners[0].rounds[round].history_gate_identity,
                .root_identity = value.root_identity,
                .issuance_identity = round_issuance_identity(
                    value, round + 1),
            };
            for (unsigned owner = 0; owner < 3; ++owner)
                contracts[round][owner] =
                    value.owners[owner].rounds[round].contract;
        }
        std::optional<BaselineOwnerRosterAuthority> roster;
        if (value.classification == registered_driver::CaptureClassification::
                ExplicitOwnerPublicEffectsBaseline) {
            auto roster_authority = BaselineOwnerRosterAuthority(
                PublicBaselineOwnerRosterReceipt{
                    .classification = value.classification,
                    .run = value.run,
                    .trial = value.trial,
                    .root_identity = value.root_identity,
                    .policy_identity = value.baseline_policy_identity,
                    .roster_authority_identity =
                        value.roster_authority_identity,
                    .issuance_identity = roster_issuance_identity(value),
                },
                authority.logical_owner_ids_, authority.verifiers_);
            roster.emplace(std::move(roster_authority));
        }
        FreshOwnerRoundAuthority round1(
            std::move(public_rounds[0]), std::move(contracts[0]));
        FreshOwnerRoundAuthority round2(
            std::move(public_rounds[1]), std::move(contracts[1]));
        // Every hash/copy/allocation above completed while the caller still
        // owned the issuance. The remaining exchange and capability moves are
        // non-allocating; no exception boundary exists after the claim.
#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
        if (split_postprepare_hook != nullptr) split_postprepare_hook();
#endif
        if (!authority.live_.exchange(false)) std::terminate();
        return FreshOwnerTrialSplit(
            std::move(round1), std::move(round2),
            std::move(roster),
            std::move(authority.persistent_activation_),
            std::move(authority.producer_closure_));
    } catch (...) { refuse(); }
}

#ifdef KPI_FRESH_OWNER_ISSUANCE_TEST_SETUP
void FreshOwnerTrialIssuanceBridge::test_only_set_split_postprepare_hook(
        void (*hook)()) noexcept {
    split_postprepare_hook = hook;
}
#endif

BaselineOwnerRosterReceiverSplit BaselineOwnerRosterBridge::split(
        BaselineOwnerRosterAuthority&& authority) {
    try {
        need(authority.live_.exchange(false) &&
             authority.receipt_.classification ==
                 registered_driver::CaptureClassification::
                     ExplicitOwnerPublicEffectsBaseline &&
             !zero(authority.receipt_.policy_identity));
        return BaselineOwnerRosterReceiverSplit(
            authority.receipt_, authority.logical_owner_ids_,
            authority.verifiers_);
    } catch (...) { refuse(); }
}

BaselineOwnerRosterReceiverSession
BaselineOwnerRosterReceiverBridge::consume(
        BaselineOwnerRosterReceiverAuthority&& authority,
        registered_driver::CaptureClassification classification,
        unsigned round, unsigned role,
        const Digest& run, const Digest& trial,
        const Digest& policy_identity) {
    try {
        need(authority.live_.exchange(false));
        const auto& value = authority.receipt_;
        need(classification == registered_driver::CaptureClassification::
                 ExplicitOwnerPublicEffectsBaseline &&
             value.classification == classification &&
             value.round == round && value.role == role &&
             value.run == run && value.trial == trial &&
             value.policy_identity == policy_identity &&
             !zero(value.roster_authority_identity) &&
             !zero(value.receiver_identity));
        return BaselineOwnerRosterReceiverSession(
            value, authority.logical_owner_ids_, authority.verifiers_);
    } catch (...) { refuse(); }
}

Digest mandatory_consumed_owner_root_identity() {
    return hash(
        "KPB_CONSUMED_OWNER_ROOT_V1\n"
        "/run/user/1000/kpb-unfunded-batch-components-20261028-05/owners\n");
}

FreshOwnerIssuanceSourceStatus fresh_owner_issuance_source_status() {
    return {
        .schema = "kpi-fresh-owner-issuance-source-status/v1",
        .status = "SOURCE_ONLY_CONFIGURED0",
        .exact_three_owner_process_authorities = true,
        .two_fresh_round_contracts = true,
        .round2_history_metadata_bound = true,
        .controller_reads_or_hashes_private_body = false,
        .stable_logical_owner_ids_public = false,
        .baseline_roster_possession_verification = true,
        .permission_separated_replay_registry_interface = true,
        .preidentity_owner_permit_gate = true,
        .causal_selected_owner_plan_factory = false,
        .transactional_replay_prepare_commit = false,
        .persistent_activation_child = true,
        .producer_closure_child = true,
        .postissuance_failure_composite = false,
        .authenticated_owner_process_adapter = false,
        .private_lifecycle_owner_process_adapter = false,
        .round2_accepted_history_capability_gate = false,
        .permission_separated_replay_registry_minter = false,
        .selected_driver_round_adapter = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::fresh_owner_issuance
