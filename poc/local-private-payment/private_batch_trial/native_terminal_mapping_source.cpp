#include "native_terminal_mapping_source.hpp"

#include "native_terminal_completion.hpp"
#include "native_terminal_projection_intake_bridge.hpp"
#include "../mpc-prover/financial/registered_driver_bridge.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <openssl/sha.h>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace kpb::native_terminal {
namespace {

using Digest = std::array<unsigned char, 32>;
using Projection = std::array<std::byte, 10685>;
using Classification =
    kpi::mpc::financial::registered_driver::CaptureClassification;

[[noreturn]] void refuse() { throw capture::CaptureRefused(); }
void need(bool value) { if (!value) refuse(); }

Digest hash(std::span<const std::byte> value) {
    Digest result{};
    need(SHA256(reinterpret_cast<const unsigned char*>(value.data()),
                value.size(), result.data()) != nullptr);
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void text(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void little(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

bool lower_hex(char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f');
}

void word(const std::string& value) {
    need(value.size() == 64 &&
         std::all_of(value.begin(), value.end(), lower_hex));
}

void uuid(const std::string& value) {
    need(value.size() == 36);
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            need(value[index] == '-');
        else
            need(lower_hex(value[index]));
    }
    need(value[14] == '4' &&
         std::string_view("89ab").find(value[19]) != std::string_view::npos);
}

std::string hex(const Digest& value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 0x0f]);
    }
    return result;
}

std::uint32_t u32(const unsigned char* value) {
    std::uint32_t result{};
    for (unsigned index = 0; index < 4; ++index)
        result |= static_cast<std::uint32_t>(value[index]) << (8 * index);
    return result;
}

std::uint64_t u64(const unsigned char* value) {
    std::uint64_t result{};
    for (unsigned index = 0; index < 8; ++index)
        result |= static_cast<std::uint64_t>(value[index]) << (8 * index);
    return result;
}

bool nonzero(std::span<const unsigned char> value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

bool less_little_endian(const Digest& left, const Digest& right) {
    return std::lexicographical_compare(
        left.rbegin(), left.rend(), right.rbegin(), right.rend());
}

struct ParsedProjection {
    Digest identity{};
    std::array<Digest, 3> nullifiers{};
    std::array<Digest, 6> tuple_hashes{};
};

ParsedProjection parse_projection(std::span<const std::byte> supplied) {
    need(supplied.size() == 10685);
    const auto* raw = reinterpret_cast<const unsigned char*>(supplied.data());
    const auto* prefix = raw;
    const auto* body = raw + 193;
    need(std::memcmp(prefix, "KPBAFX01\x01\0\x01\0", 12) == 0 &&
         std::all_of(prefix + 48, prefix + 56,
                     [](unsigned char value) { return value == 0xff; }) &&
         prefix[64] == 37 && prefix[65] == 0 &&
         prefix[103] == 1 && prefix[104] == 0 &&
         prefix[113] == 37 && prefix[114] == 0 &&
         prefix[152] == 0 &&
         std::all_of(prefix + 153, prefix + 189,
                     [](unsigned char value) { return value == 0; }) &&
         u32(prefix + 189) == 10492);
    for (const std::size_t offset : {std::size_t{66}, std::size_t{115}})
        need(prefix[offset] == 0 && prefix[offset + 1] == 0 &&
             prefix[offset + 2] == 0xaa && prefix[offset + 3] == 0x20 &&
             prefix[offset + 36] == 0x87);
    need(std::memcmp(body, "KPBAEF01", 8) == 0 &&
         std::memcmp(prefix + 12, body + 168, 36) == 0 &&
         u64(prefix + 56) == u64(body + 276) &&
         u64(prefix + 105) == u64(body + 356));

    const auto old_n = u32(body + 268);
    const auto old_m = u32(body + 272);
    const auto new_n = u32(body + 348);
    const auto new_m = u32(body + 352);
    const auto reserve = u64(body + 276);
    const auto remaining = u64(body + 356);
    const auto fee = u64(body + 364);
    need(nonzero({body + 168, 32}) && old_n >= 3 && old_n <= 65536 &&
         old_m >= 1 && old_m <= 131072 && new_n == old_n + 6 &&
         new_m == old_m + 3 && new_n <= 65536 && new_m <= 131072 &&
         reserve >= 60'000'000 && remaining >= 60'000'000 && fee >= 1 &&
         remaining <= 2'870'000'000'000'000'000ULL &&
         reserve <= 2'870'000'000'000'000'000ULL &&
         fee <= 2'870'000'000'000'000'000ULL && remaining + fee == reserve);

    ParsedProjection parsed{.identity = hash(supplied)};
    for (unsigned index = 0; index < parsed.nullifiers.size(); ++index)
        std::copy_n(body + 404 + 96 * index, 32,
                    parsed.nullifiers[index].begin());
    need(std::all_of(parsed.nullifiers.begin(), parsed.nullifiers.end(),
                     [](const Digest& value) { return nonzero(value); }) &&
         less_little_endian(parsed.nullifiers[0], parsed.nullifiers[1]) &&
         less_little_endian(parsed.nullifiers[1], parsed.nullifiers[2]));

    std::array<Digest, 6> commitments{};
    static constexpr std::array<unsigned char, 8> empty_commitment_domain{
        'K', 'P', 'X', '1', 'C', 'M', 'E', 0};
    const auto empty_commitment = hash(empty_commitment_domain);
    for (unsigned index = 0; index < parsed.tuple_hashes.size(); ++index) {
        const auto* row = body + 692 + 520 * index;
        std::copy_n(row, 32, commitments[index].begin());
        const auto ciphertext_hash = hash({row + 96, 264});
        need(nonzero(commitments[index]) &&
             commitments[index] != empty_commitment &&
             std::equal(ciphertext_hash.begin(), ciphertext_hash.end(),
                        row + 360));
        parsed.tuple_hashes[index] = hash({row, 520});
    }
    need(std::all_of(commitments.begin(), commitments.end(),
        [&](const Digest& value) {
            return std::count(commitments.begin(), commitments.end(), value)
                == 1;
        }) &&
        std::all_of(parsed.tuple_hashes.begin(), parsed.tuple_hashes.end(),
        [&](const Digest& value) {
            return std::count(parsed.tuple_hashes.begin(),
                              parsed.tuple_hashes.end(), value) == 1;
        }));
    return parsed;
}

Digest source_identity(
        const ParsedProjection& parsed, unsigned round,
        const capture::Binding& binding, Classification classification,
        bool owner_mapping_present,
        const Digest& retained_identity, const Digest& fork_binding_identity,
        const Digest& intake_identity,
        const Digest& owner_mapping_authority_identity,
        const Digest& trial,
        const Digest& outer_parent_process,
        const Digest& outer_parent_executable,
        const std::array<Digest, 3>& owner_nullifiers,
        const std::array<std::array<Digest, 2>, 3>& owner_tuple_hashes) {
    std::vector<unsigned char> bytes;
    text(bytes, "KPB_NATIVE_TERMINAL_MAPPING_SOURCE_V1\n");
    add(bytes, parsed.identity); little(bytes, round);
    little(bytes, static_cast<unsigned>(classification));
    text(bytes, binding.attempt_id); text(bytes, binding.cohort_sha256);
    text(bytes, binding.financial_run_id); text(bytes, binding.capture_identity);
    text(bytes, binding.projection_sha256);
    little(bytes, binding.construction_classification);
    text(bytes, binding.construction_attempt_sha256);
    text(bytes, binding.capture_plan_sha256);
    add(bytes, retained_identity);
    add(bytes, fork_binding_identity);
    add(bytes, intake_identity);
    add(bytes, owner_mapping_authority_identity);
    add(bytes, trial);
    add(bytes, outer_parent_process);
    add(bytes, outer_parent_executable);
    for (const auto& value : parsed.nullifiers) add(bytes, value);
    for (const auto& value : parsed.tuple_hashes) add(bytes, value);
    bytes.push_back(owner_mapping_present ? 1 : 0);
    if (owner_mapping_present) {
        for (unsigned owner = 0; owner < 3; ++owner) {
            add(bytes, owner_nullifiers[owner]);
            for (const auto& value : owner_tuple_hashes[owner])
                add(bytes, value);
        }
    }
    // The final two bytes bind the narrow completeness statements: the fixed
    // projection grammar was fully parsed, and this terminal stream has no
    // explicit owner -> NF/tuple mapping export. Public state continuity is a
    // distinct modeled relation and is not classified as absent here.
    bytes.push_back(1); bytes.push_back(1);
    return hash(bytes);
}

Digest compute_intake_identity(
        const Digest& retained_identity, const Digest& fork_binding_identity,
        const Digest& projection_identity,
        const Digest& owner_mapping_authority_identity,
        const Digest& trial,
        const Digest& outer_parent_process,
        const Digest& outer_parent_executable, unsigned round,
        Classification classification) {
    std::vector<unsigned char> bytes;
    text(bytes, "KPB_NATIVE_TERMINAL_PROJECTION_INTAKE_V1\n");
    add(bytes, retained_identity); add(bytes, fork_binding_identity);
    add(bytes, projection_identity);
    add(bytes, owner_mapping_authority_identity);
    add(bytes, trial);
    add(bytes, outer_parent_process); add(bytes, outer_parent_executable);
    little(bytes, round); little(bytes, static_cast<unsigned>(classification));
    return hash(bytes);
}

} // namespace

NativeTerminalMappingSourceAuthority
NativeTerminalMappingSourceAuthority::from_projection(
        std::span<const std::byte> projection, unsigned round,
        const capture::Binding& binding, Classification classification,
        bool owner_mapping_present, OriginEvidence origin,
        const std::array<Digest, 3>& owner_nullifiers,
        const std::array<std::array<Digest, 2>, 3>& owner_tuple_hashes) {
    need(round == 1 || round == 2);
    uuid(binding.attempt_id); word(binding.cohort_sha256);
    word(binding.financial_run_id); uuid(binding.capture_identity);
    word(binding.projection_sha256);
    word(binding.construction_attempt_sha256);
    word(binding.capture_plan_sha256);
    const auto parsed = parse_projection(projection);
    need(hex(parsed.identity) == binding.projection_sha256 &&
         binding.construction_classification ==
             static_cast<unsigned>(classification) &&
         ((classification == Classification::HiddenCandidate &&
           !owner_mapping_present) ||
          (classification ==
               Classification::ExplicitOwnerPublicEffectsBaseline &&
           owner_mapping_present)) &&
         nonzero(origin.retained_identity) &&
         nonzero(origin.fork_binding_identity) &&
         nonzero(origin.intake_identity) && nonzero(origin.trial) &&
         nonzero(origin.outer_parent_process) &&
         nonzero(origin.outer_parent_executable) &&
         (owner_mapping_present ==
          nonzero(origin.owner_mapping_authority_identity)));

    if (!owner_mapping_present) {
        need(std::all_of(owner_nullifiers.begin(), owner_nullifiers.end(),
                         [](const Digest& value) { return !nonzero(value); }) &&
             std::all_of(owner_tuple_hashes.begin(),
                         owner_tuple_hashes.end(), [](const auto& rows) {
                 return std::all_of(rows.begin(), rows.end(),
                     [](const Digest& value) { return !nonzero(value); });
             }));
    } else {
        need(std::all_of(owner_nullifiers.begin(), owner_nullifiers.end(),
                         [](const Digest& value) { return nonzero(value); }) &&
             std::all_of(owner_tuple_hashes.begin(),
                         owner_tuple_hashes.end(), [](const auto& rows) {
                 return std::all_of(rows.begin(), rows.end(),
                     [](const Digest& value) { return nonzero(value); });
             }) &&
             std::set<Digest>(owner_nullifiers.begin(),
                              owner_nullifiers.end()).size() == 3);
        auto selected_nfs = owner_nullifiers;
        auto expected_nfs = parsed.nullifiers;
        std::sort(selected_nfs.begin(), selected_nfs.end());
        std::sort(expected_nfs.begin(), expected_nfs.end());
        need(selected_nfs == expected_nfs);
        std::array<Digest, 6> selected_tuples{};
        unsigned at = 0;
        for (const auto& rows : owner_tuple_hashes)
            for (const auto& row : rows) selected_tuples[at++] = row;
        need(std::set<Digest>(selected_tuples.begin(),
                              selected_tuples.end()).size() == 6);
        auto expected_tuples = parsed.tuple_hashes;
        std::sort(selected_tuples.begin(), selected_tuples.end());
        std::sort(expected_tuples.begin(), expected_tuples.end());
        need(selected_tuples == expected_tuples);
    }

    return NativeTerminalMappingSourceAuthority(PrivateEvidence{
            .round = round,
            .classification = classification,
            .binding = binding,
            .nullifiers = parsed.nullifiers,
            .tuple_hashes = parsed.tuple_hashes,
            .owner_nullifiers = owner_nullifiers,
            .owner_tuple_hashes = owner_tuple_hashes,
            .origin = origin,
            .source_identity = source_identity(
                parsed, round, binding, classification,
                owner_mapping_present, origin.retained_identity,
                origin.fork_binding_identity, origin.intake_identity,
                origin.owner_mapping_authority_identity,
                origin.trial, origin.outer_parent_process,
                origin.outer_parent_executable, owner_nullifiers,
                owner_tuple_hashes),
            .owner_mapping_present = owner_mapping_present,
            .owner_mapping_absent = !owner_mapping_present,
            .grouping_source_complete = true,
            .explicit_owner_mapping_export_source_complete = true,
            .public_continuity_modeled_separately = true,
        });
}

NativeTerminalMappingSourceAuthority::NativeTerminalMappingSourceAuthority(
        PrivateEvidence evidence) : evidence_(std::move(evidence)) {}

NativeTerminalMappingSourceAuthority::NativeTerminalMappingSourceAuthority(
        NativeTerminalMappingSourceAuthority&& other) noexcept
    : evidence_(std::move(other.evidence_)),
      live_(other.live_.exchange(false)) {}

NativeTerminalMappingSourceAuthority
NativeTerminalProjectionIntake::admit_authenticated_child(
        NativeTerminalChildProjectionEvidence&& retained,
        const PublicPaymentTerminalOffer& offer) {
    need(retained.round == offer.native.ordinal &&
         retained.projection_identity == offer.native.projection &&
         retained.projection_identity == hash(retained.projection) &&
         (retained.classification == Classification::HiddenCandidate ||
          retained.classification ==
              Classification::ExplicitOwnerPublicEffectsBaseline) &&
         retained.owner_mapping_present ==
             (retained.classification ==
              Classification::ExplicitOwnerPublicEffectsBaseline) &&
         retained.intake_identity == recompute_intake_identity(
             retained, offer.native.trial,
             offer.native.outer_parent_process,
             offer.native.outer_parent_executable));
    const NativeTerminalMappingSourceAuthority::OriginEvidence origin{
        .retained_identity = retained.retained_identity,
        .fork_binding_identity = retained.fork_binding_identity,
        .intake_identity = retained.intake_identity,
        .owner_mapping_authority_identity =
            retained.owner_mapping_authority_identity,
        .trial = offer.native.trial,
        .outer_parent_process = offer.native.outer_parent_process,
        .outer_parent_executable = offer.native.outer_parent_executable,
    };
    return NativeTerminalMappingSourceAuthority::from_projection(
        retained.projection, retained.round, offer.capture_binding,
        retained.classification, retained.owner_mapping_present, origin,
        retained.owner_nullifiers, retained.owner_tuple_hashes);
}

Digest NativeTerminalProjectionIntake::recompute_intake_identity(
        const NativeTerminalChildProjectionEvidence& retained,
        const Digest& trial,
        const Digest& outer_parent_process,
        const Digest& outer_parent_executable) {
    return compute_intake_identity(
        retained.retained_identity, retained.fork_binding_identity,
        retained.projection_identity,
        retained.owner_mapping_authority_identity, trial,
        outer_parent_process, outer_parent_executable, retained.round,
        retained.classification);
}

#ifdef KPB_TERMINAL_MAPPING_SOURCE_TEST_SETUP
NativeTerminalMappingSourceAuthority
NativeTerminalMappingSourceAuthority::test_only_candidate_from_projection(
        std::span<const std::byte> projection, unsigned round,
        const capture::Binding& binding) {
    const auto projection_identity = hash(projection);
    OriginEvidence origin{
        .retained_identity = projection_identity,
        .fork_binding_identity = projection_identity,
        .intake_identity = compute_intake_identity(
            projection_identity, projection_identity, projection_identity,
            Digest{},
            projection_identity, projection_identity, projection_identity,
            round, Classification::HiddenCandidate),
        .trial = projection_identity,
        .outer_parent_process = projection_identity,
        .outer_parent_executable = projection_identity,
    };
    return from_projection(
        projection, round, binding, Classification::HiddenCandidate,
        false, origin);
}

NativeTerminalMappingSourceAuthority
NativeTerminalMappingSourceAuthority::
test_only_candidate_from_projection_with_origin_salt(
        std::span<const std::byte> projection, unsigned round,
        const capture::Binding& binding, unsigned char salt) {
    need(salt != 0);
    const auto projection_identity = hash(projection);
    const auto salted = [&](unsigned char label) {
        std::vector<unsigned char> bytes;
        text(bytes, "KPB_NATIVE_TERMINAL_TEST_ORIGIN_V1\n");
        add(bytes, projection_identity);
        bytes.push_back(salt); bytes.push_back(label);
        return hash(bytes);
    };
    OriginEvidence origin{
        .retained_identity = salted(1),
        .fork_binding_identity = salted(2),
        .trial = salted(3),
        .outer_parent_process = salted(4),
        .outer_parent_executable = salted(5),
    };
    origin.intake_identity = compute_intake_identity(
        origin.retained_identity, origin.fork_binding_identity,
        projection_identity, Digest{}, origin.trial,
        origin.outer_parent_process, origin.outer_parent_executable,
        round, Classification::HiddenCandidate);
    return from_projection(
        projection, round, binding, Classification::HiddenCandidate,
        false, origin);
}

NativeTerminalMappingSourceAuthority
NativeTerminalMappingSourceAuthority::test_only_candidate_with_owner_rows(
        std::span<const std::byte> projection, unsigned round,
        const capture::Binding& binding,
        const std::array<Digest, 3>& owner_nullifiers,
        const std::array<std::array<Digest, 2>, 3>& owner_tuple_hashes) {
    const auto projection_identity = hash(projection);
    OriginEvidence origin{
        .retained_identity = projection_identity,
        .fork_binding_identity = projection_identity,
        .intake_identity = compute_intake_identity(
            projection_identity, projection_identity, projection_identity,
            Digest{}, projection_identity, projection_identity,
            projection_identity, round, Classification::HiddenCandidate),
        .trial = projection_identity,
        .outer_parent_process = projection_identity,
        .outer_parent_executable = projection_identity,
    };
    return from_projection(
        projection, round, binding, Classification::HiddenCandidate,
        false, origin, owner_nullifiers, owner_tuple_hashes);
}

NativeTerminalMappingSourceAuthority
NativeTerminalMappingSourceAuthority::test_only_baseline_from_projection(
        std::span<const std::byte> projection, unsigned round,
        const capture::Binding& binding,
        const std::array<Digest, 3>& owner_nullifiers,
        const std::array<std::array<Digest, 2>, 3>& owner_tuple_hashes) {
    const auto projection_identity = hash(projection);
    OriginEvidence origin{
        .retained_identity = projection_identity,
        .fork_binding_identity = projection_identity,
        .owner_mapping_authority_identity = projection_identity,
        .trial = projection_identity,
        .outer_parent_process = projection_identity,
        .outer_parent_executable = projection_identity,
    };
    origin.intake_identity = compute_intake_identity(
        projection_identity, projection_identity, projection_identity,
        projection_identity, origin.trial,
        origin.outer_parent_process, origin.outer_parent_executable, round,
        Classification::ExplicitOwnerPublicEffectsBaseline);
    return from_projection(
        projection, round, binding,
        Classification::ExplicitOwnerPublicEffectsBaseline,
        true, origin, owner_nullifiers, owner_tuple_hashes);
}
#endif

} // namespace kpb::native_terminal
