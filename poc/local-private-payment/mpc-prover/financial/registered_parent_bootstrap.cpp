#include "registered_parent_bootstrap.hpp"

#include "fresh_owner_trial_issuance.hpp"
#include "registered_capture_plan_roster_bridge.hpp"
#include "registered_parent_role_fork.hpp"
#include "../p1_scalar_capture_manifest.hpp"
#include "../trace/sealed_trace.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

using Bytes = std::vector<unsigned char>;
using fresh_owner_issuance::PublicFreshOwnerRoundReceipt;

constexpr std::uint8_t PHASE_READY = 0;
constexpr std::uint8_t PHASE_BOOTSTRAP_OFFER = 1;
constexpr std::uint8_t PHASE_MODEL_ADMITTED = 2;
constexpr std::size_t OFFER_BYTES = 3072;
constexpr std::size_t ACK_BYTES = 320;
constexpr std::array<unsigned char, 8> OFFER_MAGIC{
    'K', 'P', 'B', 'B', 'O', 'O', 'T', '1'};
constexpr std::array<unsigned char, 8> ACK_MAGIC{
    'K', 'P', 'B', 'B', 'A', 'C', 'K', '1'};
constexpr std::string_view FR_MODULUS =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, std::string_view value) {
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}
void byte(Bytes& out, unsigned value) {
    need(value <= std::numeric_limits<unsigned char>::max());
    out.push_back(static_cast<unsigned char>(value));
}
void u32(Bytes& out, std::uint64_t value) {
    need(value <= std::numeric_limits<std::uint32_t>::max());
    for (unsigned shift = 0; shift < 32; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void u64(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void digest(Bytes& out, const Digest& value) {
    need(nonzero(value));
    add(out, value);
}
void fixed_text(Bytes& out, std::string_view value, std::size_t width) {
    need(value.size() == width);
    add(out, value);
}

Digest checked_hex(std::string_view value) {
    need(value.size() == 64 &&
         value.find_first_not_of("0123456789abcdef") ==
             std::string_view::npos);
    const auto result = identity_registry::unhex(std::string(value));
    need(identity_registry::hex(result) == value);
    return result;
}

bool lowercase_uuid_v4(std::string_view value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) ==
            std::string_view::npos)
        return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            continue;
        const char character = value[index];
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f')))
            return false;
    }
    return true;
}

Digest driver_identity(const PublicDriverSelection& value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_DRIVER_SELECTION_V2\n");
    u64(bytes, value.role);
    for (const auto* field : {
             &value.authority_identity, &value.selection_identity,
             &value.service_identity, &value.source_identity,
             &value.build_identity, &value.roster_identity,
             &value.capture_source_identity, &value.capture_build_identity,
             &value.capture_launcher_identity,
             &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity})
        digest(bytes, *field);
    need(value.owner_port >= 0);
    u64(bytes, static_cast<std::uint64_t>(value.owner_port));
    u64(bytes, value.multiplication_batch);
    return identity_registry::digest(bytes);
}

Digest capture_identity(const PublicCapturePlan& value) {
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_CAPTURE_PLAN_V4\n");
    u64(bytes, static_cast<std::uint8_t>(value.classification));
    u64(bytes, value.round);
    u64(bytes, value.capture_trial_id.size());
    add(bytes, value.capture_trial_id);
    u64(bytes, value.capture_attempt_id.size());
    add(bytes, value.capture_attempt_id);
    u64(bytes, value.capture_identity.size());
    add(bytes, value.capture_identity);
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.source_identity, &value.build_identity,
             &value.launcher_identity, &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity})
        digest(bytes, *field);
    for (const int fd : value.fixed_fds) {
        need(fd >= 0);
        u64(bytes, static_cast<std::uint64_t>(fd));
    }
    return identity_registry::digest(bytes);
}

void require_driver(const PublicDriverSelection& value, const Digest& id) {
    need(value.role < 3 && value.owner_port >= 1024 &&
         value.owner_port <= 65533 && value.multiplication_batch > 0);
    for (const auto* field : {
             &value.authority_identity, &value.selection_identity,
             &value.service_identity, &value.source_identity,
             &value.build_identity, &value.roster_identity,
             &value.capture_source_identity, &value.capture_build_identity,
             &value.capture_launcher_identity,
             &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity})
        need(nonzero(*field));
    need(identity_registry::hex(value.scalar_capture_manifest_identity) ==
             p1_capture::SCALAR_CAPTURE_MANIFEST_SHA256 &&
         driver_identity(value) == id);
}

void require_capture(const PublicCapturePlan& value, const Digest& id) {
    need((value.classification == CaptureClassification::HiddenCandidate ||
          value.classification == CaptureClassification::
              ExplicitOwnerPublicEffectsBaseline) &&
         (value.round == 1 || value.round == 2) &&
         lowercase_uuid_v4(value.capture_trial_id) &&
         lowercase_uuid_v4(value.capture_attempt_id) &&
         lowercase_uuid_v4(value.capture_identity) &&
         value.capture_trial_id != value.capture_attempt_id &&
         value.capture_trial_id != value.capture_identity &&
         value.capture_attempt_id != value.capture_identity &&
         value.trial == RegisteredCapturePlanRosterBridge::trial_identity(
             value.capture_trial_id));
    for (const auto* field : {
             &value.run, &value.trial, &value.attempt, &value.cohort,
             &value.source_identity, &value.build_identity,
             &value.launcher_identity, &value.model_preimage_identity,
             &value.query_store_preimage_identity,
             &value.scalar_capture_manifest_identity})
        need(nonzero(*field));
    constexpr std::array<int, 10> expected{
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29};
    need(value.fixed_fds == expected &&
         identity_registry::hex(value.scalar_capture_manifest_identity) ==
             p1_capture::SCALAR_CAPTURE_MANIFEST_SHA256 &&
         capture_identity(value) == id);
}

std::string canonical_contract(const OwnerInputContract& value) {
    for (const auto* field : {
             &value.run_nonce, &value.model_identity,
             &value.source_identity, &value.proving_key_identity,
             &value.verifying_key_identity, &value.cohort_identity,
             &value.owner_certificate_sha256, &value.trace_identity,
             &value.layout_identity})
        (void)checked_hex(*field);
    for (const auto& field : value.server_certificate_sha256)
        (void)checked_hex(field);
    const std::set<std::string> servers(
        value.server_certificate_sha256.begin(),
        value.server_certificate_sha256.end());
    need(servers.size() == 3 &&
         !servers.contains(value.owner_certificate_sha256) &&
         value.owner_id >= 0 && value.owner_id < 3 &&
         value.input_count ==
             fresh_owner_issuance::OWNER_PRIVATE_INPUT_V2_BYTES / 32 - 1);
    return std::string("KPI_MASCOT_OWNER_DDNNT_INPUT_V2\nBN254\nFr\n") +
        std::string(FR_MODULUS) + "\nDDNNT_ACTIVE_5N\n" + value.run_nonce +
        "\n" + value.model_identity + "\n" + value.source_identity +
        "\n" + value.proving_key_identity + "\n" +
        value.verifying_key_identity + "\n" + value.trace_identity + "\n" +
        value.layout_identity + "\n" + value.cohort_identity + "\n" +
        std::to_string(value.owner_id) + "\n" +
        std::to_string(value.input_count) + "\nP0\n" +
        value.server_certificate_sha256[0] + "\nP1\n" +
        value.server_certificate_sha256[1] + "\nP2\n" +
        value.server_certificate_sha256[2] + "\nC" +
        std::to_string(value.owner_id) + "\n" +
        value.owner_certificate_sha256 + "\n";
}

Digest contract_identity(const OwnerInputContract& value) {
    const auto canonical = canonical_contract(value);
    return identity_registry::digest(std::span(
        reinterpret_cast<const unsigned char*>(canonical.data()),
        canonical.size()));
}

std::array<Digest, 3> require_contracts(
        const std::array<OwnerInputContract, 3>& values,
        const PublicFreshOwnerRoundReceipt& round) {
    std::array<Digest, 3> result{};
    std::set<std::string> owner_certificates;
    for (unsigned owner = 0; owner < values.size(); ++owner) {
        const auto& value = values[owner];
        need(value.owner_id == static_cast<int>(owner) &&
             value.run_nonce == identity_registry::hex(round.attempt) &&
             value.cohort_identity == identity_registry::hex(round.cohort) &&
             owner_certificates.insert(
                 value.owner_certificate_sha256).second);
        if (owner) {
            const auto& first = values[0];
            need(value.model_identity == first.model_identity &&
                 value.source_identity == first.source_identity &&
                 value.proving_key_identity ==
                     first.proving_key_identity &&
                 value.verifying_key_identity ==
                     first.verifying_key_identity &&
                 value.trace_identity == first.trace_identity &&
                 value.layout_identity == first.layout_identity &&
                 value.input_count == first.input_count &&
                 value.server_certificate_sha256 ==
                     first.server_certificate_sha256);
        }
        result[owner] = contract_identity(value);
    }
    return result;
}

void require_round(const PublicFreshOwnerRoundReceipt& value) {
    need((value.classification == CaptureClassification::HiddenCandidate ||
          value.classification == CaptureClassification::
              ExplicitOwnerPublicEffectsBaseline) &&
         (value.round == 1 || value.round == 2));
    for (const auto* field : {
             &value.authority_identity, &value.registration_identity,
             &value.service_identity, &value.controller_source_identity,
             &value.controller_build_identity, &value.run, &value.trial,
             &value.attempt, &value.cohort,
             &value.accepted_input_head_identity,
             &value.history_gate_identity, &value.root_identity,
             &value.issuance_identity})
        need(nonzero(*field));
}

bool same_artifact(const PublicInheritedSealedQueryArtifact& left,
                   const PublicInheritedSealedQueryArtifact& right) {
    return left.artifact_identity == right.artifact_identity &&
        left.container_sha256 == right.container_sha256 &&
        left.canonical_pk_sha256 == right.canonical_pk_sha256 &&
        left.decoder_identity == right.decoder_identity &&
        left.container_bytes == right.container_bytes &&
        left.canonical_pk_bytes == right.canonical_pk_bytes &&
        left.snapshot_device == right.snapshot_device &&
        left.snapshot_inode == right.snapshot_inode;
}

Digest artifact_identity(const PublicInheritedSealedQueryArtifact& value) {
    Bytes bytes;
    add(bytes, "KPB_INHERITED_SEALED_QUERY_ARTIFACT_V1\n");
    for (const auto* field : {
             &value.container_sha256, &value.canonical_pk_sha256,
             &value.decoder_identity})
        digest(bytes, *field);
    u64(bytes, value.container_bytes);
    u64(bytes, value.canonical_pk_bytes);
    u64(bytes, value.snapshot_device);
    u64(bytes, value.snapshot_inode);
    return identity_registry::digest(bytes);
}

struct RoleData {
    PublicFreshOwnerRoundReceipt round;
    std::array<OwnerInputContract, 3> contracts;
    std::array<Digest, 3> contract_identities{};
    PublicDriverSelection driver;
    Digest driver_identity{};
    PublicCapturePlan capture;
    Digest capture_identity{};
    PublicInheritedSealedQueryArtifact artifact;
};

struct ParentBinding {
    Digest fork_plan_identity{};
    std::array<detail::RoleCompletionBinding, 3> roles{};
};

std::unique_ptr<ParentBootstrapPlanAuthority::Storage> make_plan_storage(
        PublicFreshOwnerRoundReceipt round,
        std::array<OwnerInputContract, 3> contracts,
        PublicCapturePlan capture, Digest capture_id,
        std::array<PublicDriverSelection, 3> drivers,
        std::array<Digest, 3> driver_ids,
        PublicInheritedSealedQueryArtifact artifact,
        ParentBinding parent);

void header(Bytes& out, const std::array<unsigned char, 8>& magic,
            const detail::RoleCompletionBinding& binding,
            unsigned stage) {
    need(binding.role < 3 &&
         (binding.round == 1 || binding.round == 2) &&
         binding.parent_pid > 1 && binding.child_pid > 1 &&
         binding.parent_pid != binding.child_pid);
    add(out, magic);
    byte(out, 1);
    byte(out, binding.role);
    byte(out, binding.round);
    byte(out, stage);
    u32(out, static_cast<std::uint64_t>(binding.parent_pid));
    u32(out, static_cast<std::uint64_t>(binding.child_pid));
    for (const auto* field : {
             &binding.fork_plan_identity, &binding.offer_identity,
             &binding.ack_identity, &binding.channel_nonce})
        digest(out, *field);
}

void finish(Bytes& out, std::size_t exact_size) {
    need(out.size() + Digest{}.size() <= exact_size);
    out.resize(exact_size - Digest{}.size(), 0);
    digest(out, identity_registry::digest(out));
    need(out.size() == exact_size);
}

Digest packet_identity(std::span<const unsigned char> packet) {
    need(packet.size() >= Digest{}.size());
    Digest result{};
    std::copy_n(packet.end() - result.size(), result.size(), result.begin());
    need(nonzero(result) &&
         result == identity_registry::digest(
             packet.first(packet.size() - result.size())));
    return result;
}

void encode_round(Bytes& out, const PublicFreshOwnerRoundReceipt& value) {
    byte(out, static_cast<unsigned>(value.classification));
    byte(out, value.round);
    for (const auto* field : {
             &value.authority_identity, &value.registration_identity,
             &value.service_identity, &value.controller_source_identity,
             &value.controller_build_identity, &value.run, &value.trial,
             &value.attempt, &value.cohort,
             &value.accepted_input_head_identity,
             &value.history_gate_identity, &value.root_identity,
             &value.issuance_identity})
        digest(out, *field);
}

void encode_driver(Bytes& out, const RoleData& value) {
    const auto& driver = value.driver;
    byte(out, driver.role);
    for (const auto* field : {
             &driver.authority_identity, &driver.selection_identity,
             &driver.service_identity, &driver.source_identity,
             &driver.build_identity, &driver.roster_identity,
             &driver.capture_source_identity,
             &driver.capture_build_identity,
             &driver.capture_launcher_identity,
             &driver.model_preimage_identity,
             &driver.query_store_preimage_identity,
             &driver.scalar_capture_manifest_identity})
        digest(out, *field);
    need(driver.owner_port >= 0);
    u32(out, static_cast<std::uint64_t>(driver.owner_port));
    u64(out, driver.multiplication_batch);
    digest(out, value.driver_identity);
}

void encode_capture(Bytes& out, const RoleData& value) {
    const auto& capture = value.capture;
    byte(out, static_cast<unsigned>(capture.classification));
    byte(out, capture.round);
    fixed_text(out, capture.capture_trial_id, 36);
    fixed_text(out, capture.capture_attempt_id, 36);
    fixed_text(out, capture.capture_identity, 36);
    for (const auto* field : {
             &capture.run, &capture.trial, &capture.attempt, &capture.cohort,
             &capture.source_identity, &capture.build_identity,
             &capture.launcher_identity,
             &capture.model_preimage_identity,
             &capture.query_store_preimage_identity,
             &capture.scalar_capture_manifest_identity})
        digest(out, *field);
    for (const int fd : capture.fixed_fds) {
        need(fd >= 0);
        u32(out, static_cast<std::uint64_t>(fd));
    }
    digest(out, value.capture_identity);
}

void encode_contract(Bytes& out, const OwnerInputContract& value,
                     const Digest& identity) {
    for (const auto* field : {
             &value.run_nonce, &value.model_identity,
             &value.source_identity, &value.proving_key_identity,
             &value.verifying_key_identity, &value.cohort_identity})
        digest(out, checked_hex(*field));
    need(value.owner_id >= 0);
    byte(out, static_cast<unsigned>(value.owner_id));
    u64(out, value.input_count);
    for (const auto& field : value.server_certificate_sha256)
        digest(out, checked_hex(field));
    digest(out, checked_hex(value.owner_certificate_sha256));
    digest(out, checked_hex(value.trace_identity));
    digest(out, checked_hex(value.layout_identity));
    digest(out, identity);
}

void encode_artifact(Bytes& out,
                     const PublicInheritedSealedQueryArtifact& value) {
    for (const auto* field : {
             &value.artifact_identity, &value.container_sha256,
             &value.canonical_pk_sha256, &value.decoder_identity})
        digest(out, *field);
    u64(out, value.container_bytes);
    u64(out, value.canonical_pk_bytes);
    u64(out, value.snapshot_device);
    u64(out, value.snapshot_inode);
}

Bytes offer_packet(const RoleData& value,
                   const detail::RoleCompletionBinding& binding) {
    need(value.driver.role == binding.role &&
         value.round.round == binding.round);
    Bytes out;
    out.reserve(OFFER_BYTES);
    header(out, OFFER_MAGIC, binding, PHASE_BOOTSTRAP_OFFER);
    encode_round(out, value.round);
    encode_driver(out, value);
    encode_capture(out, value);
    for (unsigned owner = 0; owner < value.contracts.size(); ++owner)
        encode_contract(out, value.contracts[owner],
                        value.contract_identities[owner]);
    encode_artifact(out, value.artifact);
    finish(out, OFFER_BYTES);
    return out;
}

unsigned take_byte(std::span<const unsigned char> in, std::size_t& at) {
    need(at < in.size());
    return in[at++];
}
std::uint32_t take_u32(
        std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 4 <= in.size() - at);
    std::uint32_t result = 0;
    for (unsigned shift = 0; shift < 32; shift += 8)
        result |= std::uint32_t(in[at++]) << shift;
    return result;
}
std::uint64_t take_u64(
        std::span<const unsigned char> in, std::size_t& at) {
    need(at <= in.size() && 8 <= in.size() - at);
    std::uint64_t result = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
        result |= std::uint64_t(in[at++]) << shift;
    return result;
}
Digest take_digest(
        std::span<const unsigned char> in, std::size_t& at) {
    Digest result{};
    need(at <= in.size() && result.size() <= in.size() - at);
    std::copy_n(in.begin() + at, result.size(), result.begin());
    at += result.size();
    need(nonzero(result));
    return result;
}
std::string take_fixed_text(
        std::span<const unsigned char> in, std::size_t& at,
        std::size_t width) {
    need(at <= in.size() && width <= in.size() - at);
    std::string result(
        reinterpret_cast<const char*>(in.data() + at), width);
    at += width;
    return result;
}

void require_header(std::span<const unsigned char> packet,
                    const std::array<unsigned char, 8>& magic,
                    const detail::RoleCompletionBinding& binding,
                    unsigned stage, std::size_t& at) {
    need(packet.size() >= 8 + 4 + 8 + 4 * Digest{}.size() &&
         std::equal(magic.begin(), magic.end(), packet.begin()));
    at = magic.size();
    need(take_byte(packet, at) == 1 &&
         take_byte(packet, at) == binding.role &&
         take_byte(packet, at) == binding.round &&
         take_byte(packet, at) == stage &&
         take_u32(packet, at) ==
             static_cast<std::uint32_t>(binding.parent_pid) &&
         take_u32(packet, at) ==
             static_cast<std::uint32_t>(binding.child_pid) &&
         take_digest(packet, at) == binding.fork_plan_identity &&
         take_digest(packet, at) == binding.offer_identity &&
         take_digest(packet, at) == binding.ack_identity &&
         take_digest(packet, at) == binding.channel_nonce);
}

PublicFreshOwnerRoundReceipt decode_round(
        std::span<const unsigned char> packet, std::size_t& at) {
    PublicFreshOwnerRoundReceipt result{
        .classification = static_cast<CaptureClassification>(
            take_byte(packet, at)),
        .round = take_byte(packet, at),
        .authority_identity = take_digest(packet, at),
        .registration_identity = take_digest(packet, at),
        .service_identity = take_digest(packet, at),
        .controller_source_identity = take_digest(packet, at),
        .controller_build_identity = take_digest(packet, at),
        .run = take_digest(packet, at),
        .trial = take_digest(packet, at),
        .attempt = take_digest(packet, at),
        .cohort = take_digest(packet, at),
        .accepted_input_head_identity = take_digest(packet, at),
        .history_gate_identity = take_digest(packet, at),
        .root_identity = take_digest(packet, at),
        .issuance_identity = take_digest(packet, at),
    };
    require_round(result);
    return result;
}

std::pair<PublicDriverSelection, Digest> decode_driver(
        std::span<const unsigned char> packet, std::size_t& at) {
    PublicDriverSelection result{
        .role = take_byte(packet, at),
        .authority_identity = take_digest(packet, at),
        .selection_identity = take_digest(packet, at),
        .service_identity = take_digest(packet, at),
        .source_identity = take_digest(packet, at),
        .build_identity = take_digest(packet, at),
        .roster_identity = take_digest(packet, at),
        .capture_source_identity = take_digest(packet, at),
        .capture_build_identity = take_digest(packet, at),
        .capture_launcher_identity = take_digest(packet, at),
        .model_preimage_identity = take_digest(packet, at),
        .query_store_preimage_identity = take_digest(packet, at),
        .scalar_capture_manifest_identity = take_digest(packet, at),
        .owner_port = static_cast<int>(take_u32(packet, at)),
        .multiplication_batch = take_u64(packet, at),
    };
    const auto identity = take_digest(packet, at);
    require_driver(result, identity);
    return {std::move(result), identity};
}

std::pair<PublicCapturePlan, Digest> decode_capture(
        std::span<const unsigned char> packet, std::size_t& at) {
    PublicCapturePlan result{
        .classification = static_cast<CaptureClassification>(
            take_byte(packet, at)),
        .round = take_byte(packet, at),
        .capture_trial_id = take_fixed_text(packet, at, 36),
        .capture_attempt_id = take_fixed_text(packet, at, 36),
        .capture_identity = take_fixed_text(packet, at, 36),
        .run = take_digest(packet, at),
        .trial = take_digest(packet, at),
        .attempt = take_digest(packet, at),
        .cohort = take_digest(packet, at),
        .source_identity = take_digest(packet, at),
        .build_identity = take_digest(packet, at),
        .launcher_identity = take_digest(packet, at),
        .model_preimage_identity = take_digest(packet, at),
        .query_store_preimage_identity = take_digest(packet, at),
        .scalar_capture_manifest_identity = take_digest(packet, at),
    };
    for (auto& fd : result.fixed_fds)
        fd = static_cast<int>(take_u32(packet, at));
    const auto identity = take_digest(packet, at);
    require_capture(result, identity);
    return {std::move(result), identity};
}

std::pair<OwnerInputContract, Digest> decode_contract(
        std::span<const unsigned char> packet, std::size_t& at) {
    OwnerInputContract result{};
    result.run_nonce = identity_registry::hex(take_digest(packet, at));
    result.model_identity = identity_registry::hex(take_digest(packet, at));
    result.source_identity = identity_registry::hex(take_digest(packet, at));
    result.proving_key_identity =
        identity_registry::hex(take_digest(packet, at));
    result.verifying_key_identity =
        identity_registry::hex(take_digest(packet, at));
    result.cohort_identity = identity_registry::hex(take_digest(packet, at));
    result.owner_id = static_cast<int>(take_byte(packet, at));
    result.input_count = static_cast<std::size_t>(take_u64(packet, at));
    for (auto& field : result.server_certificate_sha256)
        field = identity_registry::hex(take_digest(packet, at));
    result.owner_certificate_sha256 =
        identity_registry::hex(take_digest(packet, at));
    result.trace_identity =
        identity_registry::hex(take_digest(packet, at));
    result.layout_identity =
        identity_registry::hex(take_digest(packet, at));
    const auto identity = take_digest(packet, at);
    need(contract_identity(result) == identity);
    return {std::move(result), identity};
}

PublicInheritedSealedQueryArtifact decode_artifact(
        std::span<const unsigned char> packet, std::size_t& at) {
    PublicInheritedSealedQueryArtifact result{
        .artifact_identity = take_digest(packet, at),
        .container_sha256 = take_digest(packet, at),
        .canonical_pk_sha256 = take_digest(packet, at),
        .decoder_identity = take_digest(packet, at),
        .container_bytes = take_u64(packet, at),
        .canonical_pk_bytes = take_u64(packet, at),
        .snapshot_device = take_u64(packet, at),
        .snapshot_inode = take_u64(packet, at),
    };
    need(result.container_bytes > 0 && result.canonical_pk_bytes > 0 &&
         result.snapshot_device > 0 && result.snapshot_inode > 0 &&
         artifact_identity(result) == result.artifact_identity);
    return result;
}

RoleData parse_offer(
        std::span<const unsigned char> packet,
        const detail::RoleCompletionBinding& binding,
        const PublicInheritedSealedQueryArtifact& inherited,
        Digest& bootstrap_identity) {
    need(packet.size() == OFFER_BYTES);
    std::size_t at = 0;
    require_header(
        packet, OFFER_MAGIC, binding, PHASE_BOOTSTRAP_OFFER, at);
    RoleData result;
    result.round = decode_round(packet, at);
    auto driver = decode_driver(packet, at);
    result.driver = std::move(driver.first);
    result.driver_identity = driver.second;
    auto capture = decode_capture(packet, at);
    result.capture = std::move(capture.first);
    result.capture_identity = capture.second;
    for (unsigned owner = 0; owner < result.contracts.size(); ++owner) {
        auto decoded = decode_contract(packet, at);
        result.contracts[owner] = std::move(decoded.first);
        result.contract_identities[owner] = decoded.second;
    }
    result.artifact = decode_artifact(packet, at);
    need(at <= packet.size() - Digest{}.size() &&
         std::all_of(packet.begin() + at,
                     packet.end() - Digest{}.size(),
                     [](unsigned char value) { return value == 0; }));
    bootstrap_identity = packet_identity(packet);
    need(same_artifact(result.artifact, inherited));
    return result;
}

void require_role_data(
        const RoleData& value,
        const detail::RoleCompletionBinding& binding) {
    require_round(value.round);
    require_driver(value.driver, value.driver_identity);
    require_capture(value.capture, value.capture_identity);
    const auto owners = require_contracts(value.contracts, value.round);
    need(owners == value.contract_identities &&
         value.round.round == binding.round &&
         value.capture.capture_trial_id == binding.capture_trial_id &&
         value.round.issuance_identity ==
             binding.fresh_owner_issuance_identity &&
         value.driver.role == binding.role &&
         value.round.authority_identity == binding.authority_identity &&
         value.round.service_identity == binding.service_identity &&
         value.driver.authority_identity == binding.authority_identity &&
         value.driver.service_identity == binding.service_identity &&
         value.driver_identity == binding.driver_selection_identity &&
         value.capture_identity == binding.capture_plan_identity &&
         value.capture.source_identity == binding.capture_source_identity &&
         value.capture.build_identity == binding.capture_build_identity &&
         value.capture.launcher_identity ==
             binding.capture_launcher_identity &&
         value.round.classification == value.capture.classification &&
         value.round.run == value.capture.run &&
         value.round.trial == value.capture.trial &&
         value.round.attempt == value.capture.attempt &&
         value.round.cohort == value.capture.cohort &&
         value.round.controller_source_identity ==
             value.driver.source_identity &&
         value.round.controller_build_identity ==
             value.driver.build_identity &&
         value.driver.capture_source_identity ==
             value.capture.source_identity &&
         value.driver.capture_build_identity == value.capture.build_identity &&
         value.driver.capture_launcher_identity ==
             value.capture.launcher_identity &&
         value.driver.model_preimage_identity ==
             value.capture.model_preimage_identity &&
         value.driver.query_store_preimage_identity ==
             value.capture.query_store_preimage_identity &&
         value.driver.scalar_capture_manifest_identity ==
             value.capture.scalar_capture_manifest_identity);
    identity_registry::Selection selection{
        .run = value.round.run,
        .trial = value.round.trial,
        .attempt = value.round.attempt,
        .cohort = value.round.cohort,
        .accepted_head = value.round.accepted_input_head_identity,
        .owner_contracts = owners,
    };
    need(identity_registry::selection_identity(selection) ==
         value.driver.selection_identity);
}

PublicRegisteredRoleBootstrap public_receipt(
        const RoleData& value,
        const detail::RoleCompletionBinding& binding,
        const Digest& bootstrap) {
    return {
        .role = binding.role,
        .round = binding.round,
        .classification = value.round.classification,
        .capture_trial_id = value.capture.capture_trial_id,
        .bootstrap_identity = bootstrap,
        .fork_plan_identity = binding.fork_plan_identity,
        .offer_identity = binding.offer_identity,
        .delivery_ack_identity = binding.ack_identity,
        .channel_nonce = binding.channel_nonce,
        .authority_identity = value.round.authority_identity,
        .supervisor_session = binding.supervisor_session,
        .party_session = binding.party_session,
        .registration_identity = value.round.registration_identity,
        .service_identity = value.round.service_identity,
        .driver_selection_identity = value.driver_identity,
        .selection_identity = value.driver.selection_identity,
        .run = value.round.run,
        .trial = value.round.trial,
        .attempt = value.round.attempt,
        .cohort = value.round.cohort,
        .accepted_input_head_identity =
            value.round.accepted_input_head_identity,
        .history_gate_identity = value.round.history_gate_identity,
        .fresh_owner_issuance_identity = value.round.issuance_identity,
        .owner_contract_identities = value.contract_identities,
        .capture_plan_identity = value.capture_identity,
        .capture_source_identity = value.capture.source_identity,
        .capture_build_identity = value.capture.build_identity,
        .capture_launcher_identity = value.capture.launcher_identity,
        .model_preimage_identity = value.driver.model_preimage_identity,
        .query_store_preimage_identity =
            value.driver.query_store_preimage_identity,
        .scalar_capture_manifest_identity =
            value.driver.scalar_capture_manifest_identity,
        .inherited_query_artifact_identity = value.artifact.artifact_identity,
    };
}

Bytes admission_ack(
        const detail::RoleCompletionBinding& binding,
        const PublicRegisteredRoleBootstrap& receipt,
        const Digest& model, const Digest& query, bool wrong_ack) {
    Bytes out;
    out.reserve(ACK_BYTES);
    header(out, ACK_MAGIC, binding, PHASE_MODEL_ADMITTED);
    digest(out, receipt.bootstrap_identity);
    digest(out, model);
    Digest supplied_query = query;
    if (wrong_ack) supplied_query[0] ^= 0xffU;
    digest(out, supplied_query);
    digest(out, receipt.inherited_query_artifact_identity);
    finish(out, ACK_BYTES);
    return out;
}

void require_admission_ack(
        std::span<const unsigned char> packet,
        const detail::RoleCompletionBinding& binding,
        const PublicRegisteredRoleBootstrap& expected) {
    need(packet.size() == ACK_BYTES);
    std::size_t at = 0;
    require_header(packet, ACK_MAGIC, binding, PHASE_MODEL_ADMITTED, at);
    need(take_digest(packet, at) == expected.bootstrap_identity &&
         take_digest(packet, at) == expected.model_preimage_identity &&
         take_digest(packet, at) ==
             expected.query_store_preimage_identity &&
         take_digest(packet, at) ==
             expected.inherited_query_artifact_identity &&
         at <= packet.size() - Digest{}.size() &&
         std::all_of(packet.begin() + at,
                     packet.end() - Digest{}.size(),
                     [](unsigned char value) { return value == 0; }));
    (void)packet_identity(packet);
}

} // namespace

struct ParentBootstrapPlanAuthority::Storage {
    std::array<RoleData, 3> roles;
    ParentBinding parent;
    std::atomic_bool live{true};
};

struct RegisteredChildBootstrapPending::Storage {
    RoleData role;
    PublicRegisteredRoleBootstrap receipt;
    InheritedSealedQueryArtifact artifact;
    ChildRoleCompletionEndpointAuthority* endpoint{};
    std::atomic_bool live{true};
    Storage(RoleData value, PublicRegisteredRoleBootstrap public_value,
            InheritedSealedQueryArtifact inherited,
            ChildRoleCompletionEndpointAuthority& channel)
        : role(std::move(value)), receipt(std::move(public_value)),
          artifact(std::move(inherited)), endpoint(&channel) {}
};

struct RegisteredOwnerContractsBootstrap::Storage {
    std::array<OwnerInputContract, 3> contracts;
    explicit Storage(std::array<OwnerInputContract, 3> value)
        : contracts(std::move(value)) {}
};

struct RegisteredAdmittedRoleBootstrap::Storage {
    PublicRegisteredRoleBootstrap receipt;
    std::optional<CompiledFreshAttemptAuthority> fresh;
    std::optional<CompiledDriverSelection> driver;
    std::optional<CapturePlanAuthority> capture;
    std::optional<std::array<OwnerInputContract, 3>> contracts;
    Storage(PublicRegisteredRoleBootstrap public_value,
            CompiledFreshAttemptAuthority&& fresh_value,
            CompiledDriverSelection driver_value,
            CapturePlanAuthority&& capture_value,
            std::array<OwnerInputContract, 3> contract_values)
        : receipt(std::move(public_value)),
          driver(std::move(driver_value)),
          contracts(std::move(contract_values)) {
        fresh.emplace(std::move(fresh_value));
        capture.emplace(std::move(capture_value));
    }
};

namespace {

std::unique_ptr<ParentBootstrapPlanAuthority::Storage> make_plan_storage(
        PublicFreshOwnerRoundReceipt round,
        std::array<OwnerInputContract, 3> contracts,
        PublicCapturePlan capture, Digest capture_id,
        std::array<PublicDriverSelection, 3> drivers,
        std::array<Digest, 3> driver_ids,
        PublicInheritedSealedQueryArtifact artifact,
        ParentBinding parent) {
    require_round(round);
    require_capture(capture, capture_id);
    need(artifact_identity(artifact) == artifact.artifact_identity);
    const auto owner_identities = require_contracts(contracts, round);
    auto storage = std::make_unique<ParentBootstrapPlanAuthority::Storage>();
    storage->parent = parent;
    for (unsigned role = 0; role < storage->roles.size(); ++role) {
        require_driver(drivers[role], driver_ids[role]);
        RoleData value{
            .round = round,
            .contracts = contracts,
            .contract_identities = owner_identities,
            .driver = drivers[role],
            .driver_identity = driver_ids[role],
            .capture = capture,
            .capture_identity = capture_id,
            .artifact = artifact,
        };
        require_role_data(value, parent.roles[role]);
        storage->roles[role] = std::move(value);
    }
    return storage;
}

} // namespace

InheritedSealedQueryArtifact::InheritedSealedQueryArtifact(
        PublicInheritedSealedQueryArtifact receipt,
        std::shared_ptr<const SealedTraceArtifact> artifact)
    : receipt_(std::move(receipt)), artifact_(std::move(artifact)) {}

ParentBootstrapPlanAuthority::ParentBootstrapPlanAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
ParentBootstrapPlanAuthority::ParentBootstrapPlanAuthority(
        ParentBootstrapPlanAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}
ParentBootstrapPlanAuthority::~ParentBootstrapPlanAuthority() = default;

RegisteredChildBootstrapPending::RegisteredChildBootstrapPending(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredChildBootstrapPending::RegisteredChildBootstrapPending(
        RegisteredChildBootstrapPending&& other) noexcept
    : storage_(std::move(other.storage_)) {}
RegisteredChildBootstrapPending::~RegisteredChildBootstrapPending() {
    if (storage_ && storage_->live.exchange(false) && storage_->endpoint)
        storage_->endpoint->poison_role_channel();
}
const PublicRegisteredRoleBootstrap&
RegisteredChildBootstrapPending::public_receipt() const {
    need(storage_ && storage_->live.load());
    return storage_->receipt;
}

RegisteredOwnerContractsBootstrap::RegisteredOwnerContractsBootstrap(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredOwnerContractsBootstrap::RegisteredOwnerContractsBootstrap(
        RegisteredOwnerContractsBootstrap&& other) noexcept
    : storage_(std::move(other.storage_)) {}
RegisteredOwnerContractsBootstrap::~RegisteredOwnerContractsBootstrap() =
    default;
std::span<const OwnerInputContract>
RegisteredOwnerContractsBootstrap::contracts() const {
    need(storage_ != nullptr);
    return storage_->contracts;
}

RegisteredAdmittedRoleBootstrap::RegisteredAdmittedRoleBootstrap(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }
RegisteredAdmittedRoleBootstrap::RegisteredAdmittedRoleBootstrap(
        RegisteredAdmittedRoleBootstrap&& other) noexcept
    : storage_(std::move(other.storage_)) {}
RegisteredAdmittedRoleBootstrap::~RegisteredAdmittedRoleBootstrap() = default;
const PublicRegisteredRoleBootstrap&
RegisteredAdmittedRoleBootstrap::public_receipt() const {
    need(storage_ != nullptr);
    return storage_->receipt;
}
CompiledFreshAttemptAuthority
RegisteredAdmittedRoleBootstrap::take_fresh_attempt() {
    need(storage_ && storage_->fresh.has_value());
    CompiledFreshAttemptAuthority result(std::move(*storage_->fresh));
    storage_->fresh.reset();
    return result;
}
CompiledDriverSelection
RegisteredAdmittedRoleBootstrap::take_driver_selection() {
    need(storage_ && storage_->driver.has_value());
    CompiledDriverSelection result(std::move(*storage_->driver));
    storage_->driver.reset();
    return result;
}
CapturePlanAuthority RegisteredAdmittedRoleBootstrap::take_capture_plan() {
    need(storage_ && storage_->capture.has_value());
    CapturePlanAuthority result(std::move(*storage_->capture));
    storage_->capture.reset();
    return result;
}
RegisteredOwnerContractsBootstrap
RegisteredAdmittedRoleBootstrap::take_owner_contracts() {
    need(storage_ && storage_->contracts.has_value());
    auto result = RegisteredOwnerContractsBootstrap(
        std::make_unique<RegisteredOwnerContractsBootstrap::Storage>(
            std::move(*storage_->contracts)));
    storage_->contracts.reset();
    return result;
}

InheritedSealedQueryArtifact
RegisteredParentBootstrapTransport::admit_public_query_artifact(
        std::shared_ptr<const SealedTraceArtifact> artifact) {
    try {
        need(artifact && artifact->gzip() && artifact->container_bytes() > 0 &&
             artifact->canonical_bytes() > 0 &&
             artifact->snapshot_device() > 0 &&
             artifact->snapshot_inode() > 0);
        PublicInheritedSealedQueryArtifact receipt{
            .container_sha256 = checked_hex(artifact->container_sha256()),
            .canonical_pk_sha256 =
                checked_hex(artifact->canonical_sha256()),
            .decoder_identity = checked_hex(artifact->decoder_identity()),
            .container_bytes = artifact->container_bytes(),
            .canonical_pk_bytes = artifact->canonical_bytes(),
            .snapshot_device = artifact->snapshot_device(),
            .snapshot_inode = artifact->snapshot_inode(),
        };
        receipt.artifact_identity = artifact_identity(receipt);
        return InheritedSealedQueryArtifact(
            std::move(receipt), std::move(artifact));
    } catch (...) { refuse(); }
}

ParentBootstrapPlanAuthority RegisteredParentBootstrapTransport::prepare(
        fresh_owner_issuance::ConsumedFreshOwnerRoundBootstrap&& fresh,
        RosterBoundCapturePlan&& bound_capture,
        std::span<const CompiledDriverSelection> drivers,
        const InheritedSealedQueryArtifact& artifact,
        ParentRoleChildren& children) {
    try {
        auto capture_holder = std::exchange(
            bound_capture.capture_, std::nullopt);
        const bool roster_present = bound_capture.roster_.has_value();
        bound_capture.roster_.reset();
        const bool fresh_was_live = fresh.live_.exchange(false);
        need(capture_holder.has_value() && roster_present);
        auto capture = std::move(*capture_holder);
        const bool capture_was_live = capture.live_.exchange(false);
        need(fresh_was_live && capture_was_live &&
             capture.scope_ == CapturePlanAuthority::Scope::Parent &&
             capture.computing_role_ == 3);
        need(drivers.size() == 3 && artifact.artifact_ != nullptr &&
             artifact.artifact_->gzip() &&
             artifact_identity(artifact.receipt_) ==
                 artifact.receipt_.artifact_identity);
        std::array<PublicDriverSelection, 3> public_drivers{};
        std::array<Digest, 3> driver_ids{};
        for (unsigned role = 0; role < public_drivers.size(); ++role) {
            public_drivers[role] = drivers[role].value_;
            driver_ids[role] = drivers[role].identity_;
        }
        ParentBinding parent;
        {
            std::lock_guard guard(children.mutex_);
            need(children.live_ && nonzero(children.fork_plan_identity_));
            parent = {children.fork_plan_identity_,
                      children.completion_bindings_};
            for (unsigned role = 0; role < parent.roles.size(); ++role)
                need(!children.completion_endpoints_taken_[role] &&
                     children.completion_fds_[role] >= 64 &&
                     children.supervisor_phases_[role] == PHASE_READY &&
                     parent.roles[role].role == role &&
                     parent.roles[role].child_pid ==
                         children.child_pid(role));
        }
        auto storage = make_plan_storage(
            std::move(fresh.receipt_), std::move(fresh.contracts_),
            std::move(capture.value_), capture.identity_,
            std::move(public_drivers), driver_ids, artifact.receipt_, parent);
        return ParentBootstrapPlanAuthority(std::move(storage));
    } catch (...) { refuse(); }
}

#ifdef KPI_REGISTERED_PARENT_BOOTSTRAP_TEST_SETUP
ParentBootstrapPlanAuthority
RegisteredParentBootstrapTransport::test_only_prepare(
        fresh_owner_issuance::PublicFreshOwnerRoundReceipt round,
        std::span<const OwnerInputContract> supplied_contracts,
        CapturePlanAuthority&& capture,
        std::span<const CompiledDriverSelection> drivers,
        const InheritedSealedQueryArtifact& artifact,
        ParentRoleChildren& children) {
    try {
        need(supplied_contracts.size() == 3 &&
             capture.live_.exchange(false) &&
             capture.scope_ == CapturePlanAuthority::Scope::Parent &&
             capture.computing_role_ == 3);
        need(drivers.size() == 3 && artifact.artifact_ != nullptr &&
             artifact.artifact_->gzip() &&
             artifact_identity(artifact.receipt_) ==
                 artifact.receipt_.artifact_identity);
        std::array<OwnerInputContract, 3> contracts{
            supplied_contracts[0], supplied_contracts[1],
            supplied_contracts[2]};
        std::array<PublicDriverSelection, 3> public_drivers{};
        std::array<Digest, 3> driver_ids{};
        for (unsigned role = 0; role < public_drivers.size(); ++role) {
            public_drivers[role] = drivers[role].value_;
            driver_ids[role] = drivers[role].identity_;
        }
        ParentBinding parent;
        {
            std::lock_guard guard(children.mutex_);
            need(children.live_ && nonzero(children.fork_plan_identity_));
            parent = {children.fork_plan_identity_,
                      children.completion_bindings_};
            for (unsigned role = 0; role < parent.roles.size(); ++role)
                need(!children.completion_endpoints_taken_[role] &&
                     children.completion_fds_[role] >= 64 &&
                     children.supervisor_phases_[role] == PHASE_READY &&
                     parent.roles[role].role == role &&
                     parent.roles[role].child_pid ==
                         children.child_pid(role));
        }
        auto storage = make_plan_storage(
            std::move(round), std::move(contracts),
            std::move(capture.value_), capture.identity_,
            std::move(public_drivers), driver_ids, artifact.receipt_, parent);
        return ParentBootstrapPlanAuthority(std::move(storage));
    } catch (...) { refuse(); }
}
#endif

RegisteredChildBootstrapPending
RegisteredParentBootstrapTransport::receive(
        ChildRoleCompletionEndpointAuthority& endpoint,
        const ParentAuthenticatedPartyDeliveryAuthority& delivery,
        const InheritedSealedQueryArtifact& artifact) {
    try {
        need(delivery.live_.load() && artifact.artifact_ != nullptr &&
             endpoint.binding_.role == delivery.value_.role &&
             endpoint.binding_.round == delivery.value_.round &&
             endpoint.binding_.parent_pid == delivery.value_.parent_pid &&
             endpoint.binding_.child_pid == delivery.value_.child_pid &&
             endpoint.binding_.authority_identity ==
                 delivery.value_.authority_identity &&
             endpoint.binding_.supervisor_session ==
                 delivery.value_.supervisor_session &&
             endpoint.binding_.party_session ==
                 delivery.value_.party_session &&
             endpoint.binding_.service_identity ==
                 delivery.value_.service_identity &&
             endpoint.binding_.driver_selection_identity ==
                 delivery.value_.driver_selection_identity &&
             endpoint.binding_.capture_plan_identity ==
                 delivery.value_.capture_plan_identity &&
             endpoint.binding_.capture_source_identity ==
                 delivery.value_.capture_source_identity &&
             endpoint.binding_.capture_build_identity ==
                 delivery.value_.capture_build_identity &&
             endpoint.binding_.capture_launcher_identity ==
                 delivery.value_.capture_launcher_identity &&
             endpoint.binding_.fork_plan_identity ==
                 delivery.value_.fork_plan_identity &&
             endpoint.binding_.offer_identity ==
                 delivery.value_.offer_identity &&
             endpoint.binding_.ack_identity == delivery.value_.ack_identity);
        const auto packet = endpoint.receive_role_packet(
            PHASE_READY, PHASE_BOOTSTRAP_OFFER, OFFER_BYTES);
        Digest bootstrap{};
        auto role = parse_offer(
            packet, endpoint.binding_, artifact.receipt_, bootstrap);
        require_role_data(role, endpoint.binding_);
        auto receipt = public_receipt(role, endpoint.binding_, bootstrap);
        return RegisteredChildBootstrapPending(
            std::make_unique<RegisteredChildBootstrapPending::Storage>(
                std::move(role), std::move(receipt), artifact, endpoint));
    } catch (...) {
        endpoint.poison_role_channel();
        refuse();
    }
}

std::shared_ptr<const SealedTraceArtifact>
RegisteredParentBootstrapTransport::query_artifact(
        const RegisteredChildBootstrapPending& pending) {
    try {
        need(pending.storage_ && pending.storage_->live.load() &&
             pending.storage_->artifact.artifact_ != nullptr &&
             same_artifact(pending.storage_->role.artifact,
                           pending.storage_->artifact.receipt_));
        return pending.storage_->artifact.artifact_;
    } catch (...) { refuse(); }
}

RegisteredAdmittedRoleBootstrap
RegisteredParentBootstrapTransport::authorize_impl(
        RegisteredChildBootstrapPending&& pending,
        std::string_view model_identity_text,
        std::string_view query_store_identity_text,
        bool test_wrong_ack) {
    ChildRoleCompletionEndpointAuthority* endpoint = nullptr;
    try {
        need(pending.storage_ && pending.storage_->live.exchange(false));
        auto storage = std::move(pending.storage_);
        endpoint = storage->endpoint;
        need(endpoint != nullptr &&
             same_artifact(storage->role.artifact,
                           storage->artifact.receipt_));
        const auto model = checked_hex(model_identity_text);
        const auto query = checked_hex(query_store_identity_text);
        need(model == storage->receipt.model_preimage_identity &&
             query == storage->receipt.query_store_preimage_identity);
        const auto ack = admission_ack(
            endpoint->binding_, storage->receipt, model, query,
            test_wrong_ack);
        endpoint->send_role_packet(
            PHASE_BOOTSTRAP_OFFER, PHASE_MODEL_ADMITTED, ack);

        CompiledFreshAttemptAuthority fresh(
            PublicCompiledFreshAttempt{
                .role = storage->receipt.role,
                .authority_identity = storage->receipt.authority_identity,
                .run = storage->receipt.run,
                .trial = storage->receipt.trial,
                .attempt = storage->receipt.attempt,
                .cohort = storage->receipt.cohort,
                .service_identity = storage->receipt.service_identity,
                .source_identity = storage->role.driver.source_identity,
                .build_identity = storage->role.driver.build_identity,
                .driver_selection_identity =
                    storage->receipt.driver_selection_identity,
            });
        CompiledDriverSelection driver(storage->role.driver);
        CapturePlanAuthority capture(storage->role.capture);
        return RegisteredAdmittedRoleBootstrap(
            std::make_unique<RegisteredAdmittedRoleBootstrap::Storage>(
                storage->receipt, std::move(fresh), std::move(driver),
                std::move(capture), std::move(storage->role.contracts)));
    } catch (...) {
        if (endpoint) endpoint->poison_role_channel();
        refuse();
    }
}

#ifdef KPI_REGISTERED_PARENT_BOOTSTRAP_TEST_SETUP
RegisteredAdmittedRoleBootstrap
RegisteredParentBootstrapTransport::test_only_authorize_admitted_model(
        RegisteredChildBootstrapPending&& pending,
        const TestModelBinding& binding) {
    need(binding.model_identity != nullptr &&
         binding.query_store_identity != nullptr);
    return authorize_impl(
        std::move(pending), binding.model_identity,
        binding.query_store_identity, binding.wrong_ack);
}
#endif

void RegisteredParentBootstrapTransport::deliver_impl(
        ParentBootstrapPlanAuthority&& authority,
        ParentRoleChildren& children, std::uint8_t raw_fault) {
    try {
        need(authority.storage_ &&
             authority.storage_->live.exchange(false));
        auto storage = std::move(authority.storage_);
        ParentBinding current;
        {
            std::lock_guard guard(children.mutex_);
            need(children.live_ && nonzero(children.fork_plan_identity_));
            current = {children.fork_plan_identity_,
                       children.completion_bindings_};
            for (unsigned role = 0; role < current.roles.size(); ++role)
                need(!children.completion_endpoints_taken_[role] &&
                     children.completion_fds_[role] >= 64 &&
                     children.supervisor_phases_[role] == PHASE_READY &&
                     current.roles[role].role == role &&
                     current.roles[role].child_pid ==
                         children.child_pid(role));
        }
        need(current.fork_plan_identity ==
                 storage->parent.fork_plan_identity);
        for (unsigned role = 0; role < current.roles.size(); ++role) {
            const auto& left = current.roles[role];
            const auto& right = storage->parent.roles[role];
            need(left.role == right.role && left.round == right.round &&
                 left.capture_trial_id == right.capture_trial_id &&
                 left.parent_pid == right.parent_pid &&
                 left.child_pid == right.child_pid &&
                 left.fork_plan_identity == right.fork_plan_identity &&
                 left.offer_identity == right.offer_identity &&
                 left.ack_identity == right.ack_identity &&
                 left.channel_nonce == right.channel_nonce &&
                 left.authority_identity == right.authority_identity &&
                 left.supervisor_session == right.supervisor_session &&
                 left.party_session == right.party_session &&
                 left.service_identity == right.service_identity &&
                 left.driver_selection_identity ==
                     right.driver_selection_identity &&
                 left.capture_plan_identity == right.capture_plan_identity &&
                 left.capture_source_identity ==
                     right.capture_source_identity &&
                 left.capture_build_identity ==
                     right.capture_build_identity &&
                 left.capture_launcher_identity ==
                     right.capture_launcher_identity);
        }
        std::array<Bytes, 3> packets;
        std::array<PublicRegisteredRoleBootstrap, 3> receipts;
        for (unsigned role = 0; role < packets.size(); ++role) {
            require_role_data(storage->roles[role], current.roles[role]);
            packets[role] = offer_packet(
                storage->roles[role], current.roles[role]);
            receipts[role] = public_receipt(
                storage->roles[role], current.roles[role],
                packet_identity(packets[role]));
        }

#ifdef KPI_REGISTERED_PARENT_BOOTSTRAP_TEST_SETUP
        const auto fault = static_cast<ParentBootstrapTestFault>(raw_fault);
        need(fault == ParentBootstrapTestFault::None ||
             fault == ParentBootstrapTestFault::SwapRoleZeroAndOneOffers ||
             fault == ParentBootstrapTestFault::
                 WrongAdmissionAcknowledgement);
        if (fault == ParentBootstrapTestFault::SwapRoleZeroAndOneOffers) {
            children.send_role_packet(
                0, PHASE_READY, PHASE_BOOTSTRAP_OFFER, packets[1]);
            children.send_role_packet(
                1, PHASE_READY, PHASE_BOOTSTRAP_OFFER, packets[0]);
            children.send_role_packet(
                2, PHASE_READY, PHASE_BOOTSTRAP_OFFER, packets[2]);
        } else
#else
        need(raw_fault == 0);
#endif
        {
            for (unsigned role = 0; role < packets.size(); ++role)
                children.send_role_packet(
                    role, PHASE_READY, PHASE_BOOTSTRAP_OFFER,
                    packets[role]);
        }

        for (unsigned role = 0; role < packets.size(); ++role) {
            const auto ack = children.receive_role_packet(
                role, PHASE_BOOTSTRAP_OFFER,
                PHASE_MODEL_ADMITTED, ACK_BYTES);
            require_admission_ack(
                ack, current.roles[role], receipts[role]);
        }
    } catch (...) {
        children.poison_role_channels();
        refuse();
    }
}

void RegisteredParentBootstrapTransport::deliver(
        ParentBootstrapPlanAuthority&& authority,
        ParentRoleChildren& children) {
    deliver_impl(std::move(authority), children, 0);
}

#ifdef KPI_REGISTERED_PARENT_BOOTSTRAP_TEST_SETUP
void RegisteredParentBootstrapTransport::test_only_deliver(
        ParentBootstrapPlanAuthority&& authority,
        ParentRoleChildren& children, ParentBootstrapTestFault fault) {
    deliver_impl(
        std::move(authority), children,
        static_cast<std::uint8_t>(fault));
}
#endif

ParentBootstrapSourceStatus parent_bootstrap_source_status() {
    return {
        .schema = "kpb-registered-parent-bootstrap-source-status/v1",
        .status = "SOURCE_ONLY_CONFIGURED0",
        .typed_fresh_owner_history_consumption = true,
        .exact_three_role_authenticated_transport = true,
        .one_parent_sealed_query_artifact = true,
        .independent_child_pread_streams = true,
        .child_full_model_and_query_admission_gate = true,
        .caller_digest_or_json_authority_route = false,
        .production_selected_driver_factory = false,
        .production_round1_history_minter = false,
        .production_round2_successor_history_minter = false,
        .selected_gate_callsite_integration = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver

