#include "authenticated_baseline_owner_receiver.hpp"
#include "registered_capture_session.hpp"

#include "baseline_owner_effects_recipe.hpp"
#include "baseline_public_effects_collector.hpp"
#include "construction_storage.hpp"
#include "fresh_owner_trial_issuance.hpp"
#include "../owner_connections.hpp"
#include "ExternalIO/Client.hpp"

#include <algorithm>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <set>
#include <stdexcept>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;
constexpr std::size_t ROW_BYTES = 520;
constexpr std::size_t MAX_OWNER_PROOF_BYTES = 4096;
constexpr std::array<unsigned char, 8> CHALLENGE_MAGIC{
    'K','P','B','B','O','E','R','1'};

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}
std::string hex(std::span<const unsigned char> value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (const auto byte : value) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}
Digest public_key_identity(X509* certificate) {
    need(certificate != nullptr);
    const int length = i2d_X509_PUBKEY(
        X509_get_X509_PUBKEY(certificate), nullptr);
    need(length > 0);
    Bytes encoded(static_cast<std::size_t>(length));
    unsigned char* cursor = encoded.data();
    need(i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &cursor) ==
         length);
    return hash(encoded);
}
Digest require_authenticated_peer(client_socket* socket,
                                  const std::string& expected_name,
                                  const std::string& expected_fingerprint) {
    X509* certificate = SSL_get1_peer_certificate(socket->native_handle());
    need(certificate != nullptr);
    const auto release = [](X509* value) { X509_free(value); };
    std::unique_ptr<X509, decltype(release)> owned(certificate, release);
    need(SSL_get_verify_result(socket->native_handle()) == X509_V_OK &&
         X509_check_host(certificate, expected_name.data(),
                         expected_name.size(),
                         X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, nullptr) == 1);
    unsigned char fingerprint[EVP_MAX_MD_SIZE]{};
    unsigned length{};
    need(X509_digest(certificate, EVP_sha256(), fingerprint, &length) == 1 &&
         length == 32 && expected_fingerprint.size() == 64);
    const auto actual = hex(std::span(fingerprint, length));
    need(CRYPTO_memcmp(actual.data(), expected_fingerprint.data(),
                       actual.size()) == 0);
    return public_key_identity(certificate);
}

Digest contract_identity(const OwnerInputContract& contract) {
    const auto canonical = canonical_owner_contract(contract);
    return hash(std::span(
        reinterpret_cast<const unsigned char*>(canonical.data()),
        canonical.size()));
}

PrivateOwnerScoringTruth truth(
    const PublicOwnerPrivateEffects& source,
    const Digest& trial, const Digest& logical_owner_identity,
    const Digest& roster_authority_identity,
    const Digest& roster_root_identity,
    const Digest& pre_disclosure_challenge_identity);

Digest consent_nonce(const PublicOwnerPrivateEffects& value,
                     const Digest& trial,
                     const Digest& logical_owner_identity,
                     const Digest& roster_authority_identity,
                     const Digest& roster_root_identity,
                     const Digest& pre_disclosure_challenge_identity) {
    return BaselineOwnerConsentProtocol::consent_nonce(
        value.classification,
        truth(value, trial, logical_owner_identity,
              roster_authority_identity, roster_root_identity,
              pre_disclosure_challenge_identity),
        value.relation_source_identity,
        value.owner_effects_recipe_identity, value.policy_identity);
}

Bytes challenge(const PublicOwnerPrivateEffects& value,
                const Digest& trial,
                const Digest& logical_owner_identity,
                const Digest& roster_authority_identity,
                const Digest& roster_root_identity,
                const Digest& pre_disclosure_challenge_identity,
                const Digest& nonce) {
    const auto selected = truth(
        value, trial, logical_owner_identity, roster_authority_identity,
        roster_root_identity, pre_disclosure_challenge_identity);
    const auto frame = BaselineOwnerConsentProtocol::challenge(
        value.classification, selected, value.relation_source_identity,
        value.owner_effects_recipe_identity, value.policy_identity,
        pre_disclosure_challenge_identity, nonce);
    return Bytes(frame.begin(), frame.end());
}

Bytes acknowledgment(std::span<const unsigned char> challenge_bytes) {
    need(challenge_bytes.size() ==
         BaselineOwnerConsentProtocol::CHALLENGE_BYTES);
    BaselineOwnerConsentProtocol::Challenge frame{};
    std::copy(challenge_bytes.begin(), challenge_bytes.end(), frame.begin());
    const auto result = BaselineOwnerConsentProtocol::acknowledge(frame);
    return Bytes(result.begin(), result.end());
}

bool exact_frame(const octetStream& frame,
                 std::span<const unsigned char> expected) {
    return frame.get_length() == expected.size() &&
        CRYPTO_memcmp(frame.get_data(), expected.data(), expected.size()) == 0;
}

Digest session_identity(unsigned role, const Digest& peer_key,
                        std::span<const unsigned char> challenge_bytes,
                        std::span<const unsigned char> ack,
                        const PublicOwnerPrivateEffects& source) {
    Bytes bytes;
    text(bytes, "KPB_AUTHENTICATED_BASELINE_OWNER_SESSION_V1\n");
    bytes.push_back(static_cast<unsigned char>(role));
    add(bytes, peer_key); add(bytes, hash(challenge_bytes));
    add(bytes, hash(ack)); add(bytes, source.baseline_plan_identity);
    add(bytes, source.verified_egress_identity);
    return hash(bytes);
}

Digest pre_disclosure_session_identity(
        unsigned role, const Digest& peer_key,
        std::span<const unsigned char> challenge_bytes,
        std::span<const unsigned char> proof,
        const Digest& receiver_identity, const Digest& baseline_plan_identity,
        const Digest& verified_egress_identity) {
    Bytes bytes;
    text(bytes, "KPB_AUTHENTICATED_BASELINE_OWNER_PRE_SESSION_V1\n");
    bytes.push_back(static_cast<unsigned char>(role));
    add(bytes, peer_key); add(bytes, hash(challenge_bytes));
    add(bytes, hash(proof)); add(bytes, receiver_identity);
    add(bytes, baseline_plan_identity); add(bytes, verified_egress_identity);
    return hash(bytes);
}

void shared(const PublicOwnerPrivateEffects& first,
            const PublicOwnerPrivateEffects& value, unsigned owner) {
    need(value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         value.owner == owner && value.round == first.round &&
         value.run == first.run && value.attempt == first.attempt &&
         value.cohort == first.cohort &&
         value.capture_plan_identity == first.capture_plan_identity &&
         value.projection_identity == first.projection_identity &&
         value.context_identity == first.context_identity &&
         value.relation_source_identity == first.relation_source_identity &&
         value.owner_effects_recipe_identity ==
             first.owner_effects_recipe_identity &&
         value.baseline_plan_identity == first.baseline_plan_identity &&
         value.verified_egress_identity == first.verified_egress_identity &&
         value.policy_identity == first.policy_identity);
}

PrivateOwnerScoringTruth truth(
        const PublicOwnerPrivateEffects& source,
        const Digest& trial, const Digest& logical_owner_identity,
        const Digest& roster_authority_identity,
        const Digest& roster_root_identity,
        const Digest& pre_disclosure_challenge_identity) {
    return PrivateOwnerScoringTruth{
        .owner = source.owner,
        .round = source.round,
        .run = source.run,
        .trial = trial,
        .attempt = source.attempt,
        .cohort = source.cohort,
        .capture_plan_identity = source.capture_plan_identity,
        .projection_identity = source.projection_identity,
        .context_identity = source.context_identity,
        .owner_contract_identity = source.owner_contract_identity,
        .logical_owner_identity = logical_owner_identity,
        .roster_authority_identity = roster_authority_identity,
        .roster_root_identity = roster_root_identity,
        .pre_disclosure_challenge_identity =
            pre_disclosure_challenge_identity,
        .public_nullifier = source.public_nullifier,
        .public_tuple_hashes = source.public_tuple_hashes,
        .public_tuple_commitments = source.public_tuple_commitments,
    };
}

PublicOwnerPrivateEffects parse_challenge(
        std::span<const unsigned char> bytes, Digest& nonce, Digest& trial,
        Digest& logical_owner_identity, Digest& roster_authority_identity,
        Digest& roster_root_identity,
        Digest& pre_disclosure_challenge_identity) {
    need(bytes.size() == BaselineOwnerConsentProtocol::CHALLENGE_BYTES &&
         std::equal(
        CHALLENGE_MAGIC.begin(), CHALLENGE_MAGIC.end(), bytes.begin()));
    std::size_t at = CHALLENGE_MAGIC.size();
    PublicOwnerPrivateEffects value{};
    value.classification = static_cast<CaptureClassification>(bytes[at++]);
    value.round = bytes[at++]; value.owner = bytes[at++];
    auto take = [&](Digest& field) {
        need(at + field.size() <= bytes.size());
        std::copy_n(bytes.begin() + at, field.size(), field.begin());
        at += field.size();
    };
    take(nonce); take(value.run); take(trial); take(value.attempt);
    take(value.cohort);
    take(value.capture_plan_identity); take(value.projection_identity);
    take(value.context_identity); take(value.owner_contract_identity);
    take(logical_owner_identity);
    take(roster_authority_identity); take(roster_root_identity);
    take(pre_disclosure_challenge_identity);
    take(value.public_nullifier); take(value.public_tuple_hashes[0]);
    take(value.public_tuple_hashes[1]);
    take(value.public_tuple_commitments[0]);
    take(value.public_tuple_commitments[1]);
    take(value.relation_source_identity);
    take(value.owner_effects_recipe_identity); take(value.policy_identity);
    need(at == bytes.size());
    return value;
}
} // namespace

PartyBaselineOwnerEffectsAuthority AuthenticatedBaselineOwnerReceiver::receive(
        MascotContext& context, const FinancialConstruction& construction,
        const history::EgressRelease& release,
        BaselineEffectsPlanAuthority&& selected_plan,
        fresh_owner_issuance::BaselineOwnerRosterReceiverAuthority&& roster) {
    try {
        context.require_healthy();
        const auto& storage = *construction.storage_;
        const auto& attempt = construction.registered_authority().public_receipt();
        const auto plan = selected_plan.public_plan();
        const auto baseline_plan_identity = selected_plan.identity();
        const auto roster_receipt = roster.public_receipt();
        const auto recipe = storage.owner_effects_recipe;
        const auto core = release.core();
        need(core.size() >= 284 && recipe != nullptr);
        const auto context_identity = identity_registry::digest(
            core.subspan(8, 276));
        const auto recipe_identity = history::unhex(recipe->identity());
        need(attempt.classification ==
                 CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
             attempt.role < 3 && plan.classification == attempt.classification &&
             plan.round == attempt.round && plan.run == attempt.run &&
             plan.attempt == attempt.attempt && plan.cohort == attempt.cohort &&
             plan.capture_plan_identity == attempt.capture_plan_identity &&
             plan.projection_identity == release.packet().projection &&
             plan.owner_contracts == attempt.owner_contracts &&
             roster_receipt.classification == attempt.classification &&
             roster_receipt.round == attempt.round &&
             roster_receipt.role == attempt.role &&
             roster_receipt.run == attempt.run &&
             roster_receipt.trial == attempt.trial &&
             roster_receipt.policy_identity == plan.policy_identity &&
             storage.baseline_owner_port >= 1024 &&
             storage.baseline_owner_port <= 65533);

        auto roster_session =
            fresh_owner_issuance::BaselineOwnerRosterReceiverBridge::consume(
                std::move(roster), attempt.classification, attempt.round,
                attempt.role, attempt.run, attempt.trial,
                plan.policy_identity);

        PatientOwnerConnections clients(static_cast<int>(attempt.role));
        clients.start_listening(storage.baseline_owner_port);
        std::array<Digest, 3> peer_keys{};
        std::array<Bytes, 3> pre_challenges{};
        std::array<Digest, 3> pre_challenge_identities{};
        std::array<Digest, 3> pre_sessions{};
        std::array<Digest, 3> logical_owner_identities{};
        std::array<bool, 3> seen{};
        for (unsigned accepted = 0; accepted < 3; ++accepted) {
            const int connected = clients.get_client_connection(
                storage.baseline_owner_port);
            need(connected >= 0 && connected < 3 && !seen[connected]);
            const auto owner = static_cast<unsigned>(connected);
            seen[owner] = true;
            auto* socket = clients.get_socket(connected);
            const auto& contract = storage.baseline_owner_contracts[owner];
            peer_keys[owner] = require_authenticated_peer(
                socket, "C" + std::to_string(owner),
                contract.owner_certificate_sha256);
            need(peer_keys[owner] != public_key_identity(
                    SSL_get_certificate(socket->native_handle())) &&
                 contract_identity(contract) == attempt.owner_contracts[owner]);
            const auto pre_frame =
                BaselineOwnerPreDisclosureProtocol::challenge(
                BaselineOwnerPreDisclosureBinding{
                    .classification = attempt.classification,
                    .round = attempt.round,
                    .owner = owner,
                    .run = attempt.run,
                    .trial = attempt.trial,
                    .attempt = attempt.attempt,
                    .cohort = attempt.cohort,
                    .capture_plan_identity = attempt.capture_plan_identity,
                    .projection_identity = plan.projection_identity,
                    .context_identity = context_identity,
                    .owner_contract_identity = attempt.owner_contracts[owner],
                    .relation_source_identity = construction.attempt_.source,
                    .owner_effects_recipe_identity = recipe_identity,
                    .policy_identity = plan.policy_identity,
                    .roster_authority_identity =
                        roster_receipt.roster_authority_identity,
                    .roster_root_identity = roster_receipt.root_identity,
                });
            pre_challenges[owner].assign(
                pre_frame.begin(), pre_frame.end());
            pre_challenge_identities[owner] = hash(pre_challenges[owner]);
            octetStream(pre_challenges[owner].size(),
                        pre_challenges[owner].data()).Send(socket);
        }
        need(seen == std::array<bool, 3>{true, true, true});

        // All owners prove long-lived wallet authorization before the recipe
        // can select or open any mapping wire. Sockets remain authenticated
        // and open across the opening and exact-value acknowledgment.
        for (unsigned owner = 0; owner < 3; ++owner) {
            auto* socket = clients.get_socket(static_cast<int>(owner));
            octetStream proof;
            proof.Receive(socket);
            need(proof.get_length() > 0 &&
                 proof.get_length() <= MAX_OWNER_PROOF_BYTES);
            auto verified = roster_session.verify_owner_proof(
                owner, pre_challenges[owner],
                std::span(proof.get_data(), proof.get_length()));
            auto consumed = fresh_owner_issuance::
                BaselineOwnerRosterVerifiedBridge::consume(
                    std::move(verified));
            need(consumed.owner() == owner);
            logical_owner_identities[owner] =
                consumed.logical_owner_identity();
            pre_sessions[owner] = pre_disclosure_session_identity(
                attempt.role, peer_keys[owner], pre_challenges[owner],
                std::span(proof.get_data(), proof.get_length()),
                roster_receipt.receiver_identity, baseline_plan_identity,
                plan.verified_egress_identity);
        }

        auto verified_roster = fresh_owner_issuance::
            BaselineOwnerRosterVerifiedBridge::consume(
                roster_session.finish());
        need(verified_roster.public_receipt().receiver_identity ==
                 roster_receipt.receiver_identity &&
             verified_roster.logical_owner_ids() == logical_owner_identities);

        BaselineOwnerPreDisclosureConsentReceipt consent_receipt{
            .classification = attempt.classification,
            .round = attempt.round,
            .role = attempt.role,
            .run = attempt.run,
            .trial = attempt.trial,
            .attempt = attempt.attempt,
            .cohort = attempt.cohort,
            .capture_plan_identity = attempt.capture_plan_identity,
            .projection_identity = plan.projection_identity,
            .context_identity = context_identity,
            .relation_source_identity = construction.attempt_.source,
            .owner_effects_recipe_identity = recipe_identity,
            .baseline_plan_identity = baseline_plan_identity,
            .verified_egress_identity = plan.verified_egress_identity,
            .policy_identity = plan.policy_identity,
            .roster_authority_identity =
                roster_receipt.roster_authority_identity,
            .roster_root_identity = roster_receipt.root_identity,
            .pre_challenge_identities = pre_challenge_identities,
            .owner_contracts = attempt.owner_contracts,
            .logical_owner_identities = logical_owner_identities,
            .owner_proof_sessions = pre_sessions,
        };
        auto pre_disclosure_consent =
            BaselineOwnerPreDisclosureConsentAuthority(
                std::move(consent_receipt));
        auto prepared = BaselineOwnerEffectsRecipeBridge::derive(
            context, construction, release, std::move(selected_plan),
            std::move(pre_disclosure_consent));

        // Burn every derived source before revealing the exact mapping.
        auto retained_plan = prepared.take_plan();
        (void)retained_plan;
        std::array<ConsumedOwnerPrivateEffects, 3> sources{
            OwnerPrivateEffectsReceiverBridge::consume(prepared.take_owner(0)),
            OwnerPrivateEffectsReceiverBridge::consume(prepared.take_owner(1)),
            OwnerPrivateEffectsReceiverBridge::consume(prepared.take_owner(2)),
        };
        const auto& first = sources[0].value_;
        for (unsigned owner = 0; owner < sources.size(); ++owner) {
            shared(first, sources[owner].value_, owner);
            need(sources[owner].value_.owner_contract_identity ==
                 attempt.owner_contracts[owner]);
        }
        const auto nonce = consent_nonce(
            first, attempt.trial, logical_owner_identities[0],
            roster_receipt.roster_authority_identity,
            roster_receipt.root_identity, pre_challenge_identities[0]);
        need(nonzero(nonce));

        std::array<Bytes, 3> challenges{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            challenges[owner] = challenge(
                sources[owner].value_, attempt.trial,
                logical_owner_identities[owner],
                roster_receipt.roster_authority_identity,
                roster_receipt.root_identity,
                pre_challenge_identities[owner], nonce);
            octetStream(challenges[owner].size(), challenges[owner].data())
                .Send(clients.get_socket(static_cast<int>(owner)));
        }

        std::array<Digest, 3> sessions{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            auto* socket = clients.get_socket(static_cast<int>(owner));
            octetStream received;
            received.Receive(socket);
            const auto expected = acknowledgment(challenges[owner]);
            need(exact_frame(received, expected));
            sessions[owner] = session_identity(
                attempt.role, peer_keys[owner], challenges[owner], expected,
                sources[owner].value_);
            clients.close_connection(static_cast<int>(owner));
        }

        PrivatePartyBaselineOwnerEffects value{
            .classification = first.classification,
            .round = first.round,
            .role = attempt.role,
            .run = first.run,
            .trial = attempt.trial,
            .attempt = first.attempt,
            .cohort = first.cohort,
            .capture_plan_identity = first.capture_plan_identity,
            .projection_identity = first.projection_identity,
            .context_identity = first.context_identity,
            .relation_source_identity = first.relation_source_identity,
            .owner_effects_recipe_identity =
                first.owner_effects_recipe_identity,
            .baseline_plan_identity = first.baseline_plan_identity,
            .verified_egress_identity = first.verified_egress_identity,
            .policy_identity = first.policy_identity,
            .roster_authority_identity =
                roster_receipt.roster_authority_identity,
            .roster_root_identity = roster_receipt.root_identity,
            .consent_nonce = nonce,
            .owner_contracts = attempt.owner_contracts,
            .logical_owner_identities = logical_owner_identities,
            .pre_disclosure_challenge_identities =
                pre_challenge_identities,
            .owner_sessions = sessions,
            .owner_truth = {
                truth(sources[0].value_, attempt.trial,
                      logical_owner_identities[0],
                      roster_receipt.roster_authority_identity,
                      roster_receipt.root_identity,
                      pre_challenge_identities[0]),
                truth(sources[1].value_, attempt.trial,
                      logical_owner_identities[1],
                      roster_receipt.roster_authority_identity,
                      roster_receipt.root_identity,
                      pre_challenge_identities[1]),
                truth(sources[2].value_, attempt.trial,
                      logical_owner_identities[2],
                      roster_receipt.roster_authority_identity,
                      roster_receipt.root_identity,
                      pre_challenge_identities[2])},
        };
        PartyBaselineOwnerEffectsAuthority result(std::move(value));
        if (attempt.role == CAPTURE_STREAM_OWNER_ROLE) {
            auto public_effects =
                ExplicitOwnerPublicEffectsAuthority::
                    from_acknowledged_registered_egress(
                        result, construction, release);
            RegisteredBaselineObserverCaptureBridge::
                explicit_owner_public_effects(
                    construction.registered_capture_session(),
                    std::move(public_effects));
        }
        return result;
    } catch (...) {
        context.poison();
        refuse();
    }
}

void confirm_baseline_owner_effects(
        const std::array<std::string, 3>& hostnames, int port_base,
        const OwnerInputContract& contract,
        const BaselineOwnerConsentSelection& selected,
        const Digest& public_nullifier,
        const std::array<std::span<const unsigned char>, 2>& rows,
        BaselineOwnerProofSigner& signer) {
    need(selected.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         (selected.round == 1 || selected.round == 2) &&
         contract.owner_id >= 0 && contract.owner_id < 3 &&
         port_base >= 1024 && port_base <= 65533 &&
         nonzero(public_nullifier));
    std::array<std::pair<Digest, Digest>, 2> expected_rows{};
    for (unsigned index = 0; index < rows.size(); ++index) {
        need(rows[index].size() == ROW_BYTES);
        expected_rows[index].first = hash(rows[index]);
        std::copy_n(rows[index].begin(), 32,
                    expected_rows[index].second.begin());
    }
    std::sort(expected_rows.begin(), expected_rows.end(),
              [](const auto& left, const auto& right) {
                  return left.first < right.first;
              });
    need(expected_rows[0].first != expected_rows[1].first &&
         expected_rows[0].second != expected_rows[1].second &&
         contract.run_nonce == hex(selected.attempt) &&
         contract.cohort_identity == hex(selected.cohort));

    Client client(std::vector<std::string>(hostnames.begin(), hostnames.end()),
                  port_base, contract.owner_id);
    need(client.sockets.size() == 3);
    std::set<Digest> server_keys;
    for (unsigned role = 0; role < client.sockets.size(); ++role) {
        const auto server_key = require_authenticated_peer(
            client.sockets[role], "P" + std::to_string(role),
            contract.server_certificate_sha256[role]);
        need(server_keys.insert(server_key).second &&
             server_key != public_key_identity(
                 SSL_get_certificate(client.sockets[role]->native_handle())));
    }
    const auto pre_raw = std::span(client.specification.get_data(),
                                   client.specification.get_length());
    const auto pre = BaselineOwnerPreDisclosureProtocol::parse(pre_raw);
    need(pre.classification == selected.classification &&
         pre.round == selected.round &&
         pre.owner == static_cast<unsigned>(contract.owner_id) &&
         pre.run == selected.run && pre.trial == selected.trial &&
         pre.attempt == selected.attempt && pre.cohort == selected.cohort &&
         pre.capture_plan_identity == selected.capture_plan_identity &&
         pre.projection_identity == selected.projection_identity &&
         pre.context_identity == selected.context_identity &&
         pre.owner_contract_identity == contract_identity(contract) &&
         pre.relation_source_identity == selected.relation_source_identity &&
         pre.owner_effects_recipe_identity ==
             selected.owner_effects_recipe_identity &&
         pre.policy_identity == selected.policy_identity &&
         pre.roster_authority_identity ==
             selected.roster_authority_identity &&
         pre.roster_root_identity == selected.roster_root_identity);
    const auto proof = signer.prove(pre_raw);
    need(!proof.empty() && proof.size() <= MAX_OWNER_PROOF_BYTES);
    for (auto* socket : client.sockets)
        octetStream(proof.size(), proof.data()).Send(socket);

    std::array<Bytes, 3> final_challenges{};
    for (unsigned role = 0; role < client.sockets.size(); ++role) {
        octetStream frame;
        frame.Receive(client.sockets[role]);
        final_challenges[role].assign(
            frame.get_data(), frame.get_data() + frame.get_length());
        need(final_challenges[role].size() ==
             BaselineOwnerConsentProtocol::CHALLENGE_BYTES);
        if (role != 0) need(final_challenges[role] == final_challenges[0]);
    }
    const auto raw = std::span(final_challenges[0]);
    Digest nonce{}, trial{}, logical_owner_identity{}, roster_authority{},
        roster_root{}, pre_challenge_identity{};
    const auto received = parse_challenge(
        raw, nonce, trial, logical_owner_identity, roster_authority,
        roster_root, pre_challenge_identity);
    need(received.classification == selected.classification &&
         received.round == selected.round &&
         received.owner == static_cast<unsigned>(contract.owner_id) &&
         received.run == selected.run &&
         trial == selected.trial &&
         received.attempt == selected.attempt &&
         received.cohort == selected.cohort &&
         received.capture_plan_identity == selected.capture_plan_identity &&
         received.projection_identity == selected.projection_identity &&
         received.context_identity == selected.context_identity &&
         logical_owner_identity == selected.logical_owner_identity &&
         roster_authority == selected.roster_authority_identity &&
         roster_root == selected.roster_root_identity &&
         pre_challenge_identity == hash(pre_raw) &&
         received.owner_contract_identity == contract_identity(contract) &&
         received.public_nullifier == public_nullifier &&
         received.public_tuple_hashes ==
             std::array<Digest, 2>{expected_rows[0].first,
                                   expected_rows[1].first} &&
         received.public_tuple_commitments ==
             std::array<Digest, 2>{expected_rows[0].second,
                                   expected_rows[1].second} &&
         received.relation_source_identity ==
             selected.relation_source_identity &&
         received.owner_effects_recipe_identity ==
             selected.owner_effects_recipe_identity &&
         received.policy_identity == selected.policy_identity &&
         nonce == consent_nonce(
             received, trial, logical_owner_identity, roster_authority,
             roster_root, pre_challenge_identity));
    const auto ack = acknowledgment(raw);
    for (auto* socket : client.sockets)
        octetStream(ack.size(), ack.data()).Send(socket);
}

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
