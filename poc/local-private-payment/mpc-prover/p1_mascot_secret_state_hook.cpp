#include "p1_mascot_secret_state_hook.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <utility>

namespace kpi::mpc::p1_private_state {
namespace {

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void append_bool(std::vector<unsigned char>& out, bool value) {
    out.push_back(value ? 1 : 0);
}

void append_bytes(
        std::vector<unsigned char>& out,
        std::span<const unsigned char> value) {
    if (value.size() > std::numeric_limits<std::uint64_t>::max() ||
        out.size() > std::numeric_limits<std::size_t>::max() - 8 ||
        value.size() >
            std::numeric_limits<std::size_t>::max() - out.size() - 8)
        throw std::runtime_error("P1-MASCOT-secret-state-size-overflow");
    append_u64(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

void append_string(std::vector<unsigned char>& out, std::string_view value) {
    append_bytes(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

bool valid_text(std::string_view value, bool empty_allowed = false) {
    return (empty_allowed || !value.empty()) &&
        value.find('\0') == std::string_view::npos;
}

bool all_decimal(std::string_view value) {
    return !value.empty() &&
        std::all_of(value.begin(), value.end(), [](unsigned char byte) {
            return byte >= '0' && byte <= '9';
        });
}

bool valid_metadata(const MascotFileMetadataView& value) {
    if (!value.present)
        return value.device == 0 && value.inode == 0 && value.mode == 0 &&
            value.uid == 0 && value.gid == 0 && value.link_count == 0 &&
            value.size == 0 && value.mtime_seconds == 0 &&
            value.mtime_nanoseconds == 0 && value.ctime_seconds == 0 &&
            value.ctime_nanoseconds == 0;
    return value.inode != 0 && value.link_count != 0 &&
        value.mtime_nanoseconds < 1'000'000'000ULL &&
        value.ctime_nanoseconds < 1'000'000'000ULL;
}

bool same_opened_file(
        const MascotFileMetadataView& left,
        const MascotFileMetadataView& right) {
    return left.present && right.present && left.device == right.device &&
        left.inode == right.inode && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid &&
        left.link_count == right.link_count && left.size == right.size &&
        left.mtime_seconds == right.mtime_seconds &&
        left.mtime_nanoseconds == right.mtime_nanoseconds &&
        left.ctime_seconds == right.ctime_seconds &&
        left.ctime_nanoseconds == right.ctime_nanoseconds;
}

bool same_opened_identity(
        const MascotFileMetadataView& left,
        const MascotFileMetadataView& right) {
    return left.present && right.present && left.device == right.device &&
        left.inode == right.inode && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid &&
        left.link_count == right.link_count;
}

bool absent(const MascotFileMetadataView& value) {
    return valid_metadata(value) && !value.present;
}

bool regular_or_absent(const MascotFileMetadataView& value) {
    return !value.present || (value.mode & S_IFMT) == S_IFREG;
}

bool coherent_if_present(
        const MascotFileMetadataView& left,
        const MascotFileMetadataView& right) {
    return !left.present || !right.present ||
        same_opened_identity(left, right);
}

bool valid_file(const MascotFileSnapshotView& value) {
    const bool valid_parent_directory =
        (value.parent_directory_result == MascotStepResult::NotAttempted &&
         value.parent_directory_errno == 0) ||
        (value.parent_directory_result == MascotStepResult::Succeeded &&
         value.parent_directory_errno == 0) ||
        (value.parent_directory_result == MascotStepResult::Failed &&
         value.parent_directory_errno != 0);
    if (!valid_metadata(value.path_lstat_before) ||
        !valid_metadata(value.descriptor_before) ||
        !valid_metadata(value.descriptor_after) ||
        !valid_metadata(value.path_lstat_after) ||
        !valid_metadata(value.reopened_descriptor) ||
        !regular_or_absent(value.descriptor_before) ||
        !regular_or_absent(value.descriptor_after) ||
        !regular_or_absent(value.reopened_descriptor) ||
        !coherent_if_present(
            value.descriptor_before, value.descriptor_after) ||
        !coherent_if_present(
            value.descriptor_after, value.reopened_descriptor) ||
        !valid_parent_directory)
        return false;
    const auto no_rename =
        value.rename_result == MascotStepResult::NotAttempted &&
        value.rename_errno == 0;
    const auto no_unlink =
        value.unlink_result == MascotStepResult::NotAttempted &&
        value.unlink_errno == 0;
    if (!no_rename || !no_unlink) return false;
    switch (value.result) {
    case MascotFileResult::NotAttempted:
        return value.parent_directory_result ==
                MascotStepResult::NotAttempted &&
            !value.no_follow && value.operation_errno == 0 &&
            value.open_flags == 0 &&
            value.bytes_transferred == 0 &&
            value.fsync_result == MascotStepResult::NotAttempted &&
            value.fsync_errno == 0 &&
            absent(value.path_lstat_before) &&
            absent(value.descriptor_before) &&
            absent(value.descriptor_after) &&
            absent(value.path_lstat_after) &&
            absent(value.reopened_descriptor) &&
            value.exact_file_bytes.empty();
    case MascotFileResult::Missing:
        return value.parent_directory_result ==
                MascotStepResult::NotAttempted &&
            value.no_follow && value.operation_errno != 0 &&
            value.open_flags != 0 &&
            value.bytes_transferred == 0 &&
            absent(value.descriptor_before) &&
            absent(value.descriptor_after) &&
            absent(value.reopened_descriptor) &&
            value.exact_file_bytes.empty();
    case MascotFileResult::Captured:
    {
        const bool read_capture =
            value.fsync_result == MascotStepResult::NotAttempted &&
            value.fsync_errno == 0 &&
            same_opened_file(
                value.path_lstat_before, value.descriptor_before) &&
            same_opened_file(
                value.descriptor_before, value.descriptor_after);
        const bool write_capture =
            value.fsync_result == MascotStepResult::Succeeded &&
            value.fsync_errno == 0 &&
            (absent(value.path_lstat_before) ||
             same_opened_identity(
                 value.path_lstat_before, value.descriptor_before));
        return value.parent_directory_result != MascotStepResult::Failed &&
            value.no_follow && value.operation_errno == 0 &&
            value.open_flags != 0 &&
            (read_capture || write_capture) &&
            same_opened_identity(
                value.descriptor_before, value.descriptor_after) &&
            same_opened_file(
                value.descriptor_after, value.reopened_descriptor) &&
            same_opened_file(
                value.path_lstat_after, value.reopened_descriptor) &&
            value.bytes_transferred == value.exact_file_bytes.size() &&
            value.reopened_descriptor.size == value.exact_file_bytes.size();
    }
    case MascotFileResult::Partial:
        return value.parent_directory_result != MascotStepResult::Failed &&
            value.no_follow && value.operation_errno != 0 &&
            value.open_flags != 0 &&
            value.descriptor_before.present &&
            value.bytes_transferred == value.exact_file_bytes.size();
    case MascotFileResult::Failed:
        return value.no_follow && value.operation_errno != 0 &&
            value.open_flags != 0;
    }
    return false;
}

void append_metadata(
        std::vector<unsigned char>& out,
        const MascotFileMetadataView& value) {
    append_bool(out, value.present);
    for (const auto field : {
             value.device, value.inode, value.mode, value.uid, value.gid,
             value.link_count, value.size,
             std::bit_cast<std::uint64_t>(value.mtime_seconds),
             value.mtime_nanoseconds,
             std::bit_cast<std::uint64_t>(value.ctime_seconds),
             value.ctime_nanoseconds})
        append_u64(out, field);
}

void cleanse(std::vector<unsigned char>& value) noexcept {
    volatile unsigned char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
        cursor[index] = 0;
    value.clear();
}

class CleanseOnError final {
    std::vector<unsigned char>& value_;
    bool armed_{true};
public:
    explicit CleanseOnError(std::vector<unsigned char>& value)
        : value_(value) {}
    CleanseOnError(const CleanseOnError&) = delete;
    CleanseOnError& operator=(const CleanseOnError&) = delete;
    ~CleanseOnError() {
        if (armed_) cleanse(value_);
    }
    void release() noexcept { armed_ = false; }
};

bool same_bytes(
        std::span<const unsigned char> left,
        const std::vector<unsigned char>& right) noexcept {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

bool same_bytes(
        std::span<const unsigned char> left,
        std::span<const unsigned char> right) noexcept {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

void replace_secret(
        std::vector<unsigned char>& target,
        std::span<const unsigned char> source) {
    cleanse(target);
    target.assign(source.begin(), source.end());
}

MascotFileSnapshotView not_attempted_file() { return {}; }

struct PinnedSource final {
    std::string_view path;
    std::string_view sha256;
};

inline constexpr std::array<PinnedSource, 13> kPinnedSourceManifest{{
    {"OT/NPartyTripleGenerator.h",
     "294a0d5f132efe7d3b5bcc1856c511ba64dbce9921cae46e4534add184fff1c3"},
    {"OT/NPartyTripleGenerator.hpp",
     "a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6"},
    {"OT/MascotMacKey.hpp",
     "155a8848fb253ce2bead8e9f03df703337ce6a94e97db18a9593c1383e5d2a0c"},
    {"Protocols/MascotPrep.h",
     "579541d2ec20cdfdf44cd75e0098eb4635c8c61bf4439d20494d6e395f800d8e"},
    {"OT/OTMultiplier.h",
     "b9784a784781b305f75626494ad2907fca49bdfbfcc1f8d27c035851a629891b"},
    {"OT/OTMultiplier.hpp",
     "12429b0c5a81c17e02c80b36b5636d763efa679086e5244dabe1838792b25eb4"},
    {"Protocols/MAC_Check.hpp",
     "6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8"},
    {"Protocols/fake-stuff.hpp",
     "4b3f41798f961a417d255f69ac973c309b40c2e0ff64f4767d42d15b832bf5e0"},
    {"Protocols/Share.hpp",
     "7ce9e81184a3b31545fd137730fd3f0c35b5881fb41b981600a644aa68fd8d09"},
    {"Protocols/Share.h",
     "e657f7d39b6d9bf8f5b4e07123157c0d34b02619f162104801da00b9ea136520"},
    {"Math/gfp.h",
     "3b9af0a4a83abeda72d8e48a5c90f88b2497368d964b829d50f6ef8e0092e912"},
    {"OT/MascotMacKey.h",
     "4485bc99b8ec3727c1dfb95baf7d2fcfe7b85e3112631cc885162eb3c4054a55"},
    {"OT/OTTripleSetup.cpp",
     "05d1988b32947701965a4e6fa891c285637c40678d2267828f7bf0ca355a61aa"},
}};

} // namespace

std::string_view mascot_secret_source_site(MascotSecretEventKind kind) {
    switch (kind) {
    case MascotSecretEventKind::ScalarStateBegin:
        return "Protocols/MascotPrep.h:MascotInputPrep::get_mac_key";
    case MascotSecretEventKind::SetupBegin:
        return "OT/NPartyTripleGenerator.hpp:OTTripleGenerator::get_mac_key";
    case MascotSecretEventKind::CacheOpened:
    case MascotSecretEventKind::CacheLocalValidation:
    case MascotSecretEventKind::CachePeerValidation:
    case MascotSecretEventKind::Regeneration:
    case MascotSecretEventKind::WriteCandidate:
    case MascotSecretEventKind::Writeback:
    case MascotSecretEventKind::PrepStaticInstalled:
    case MascotSecretEventKind::PrepMacFileWrite:
        return "OT/MascotMacKey.hpp:MascotMacKey::read_or_generate";
    case MascotSecretEventKind::BitPrepDerived:
        return "OT/NPartyTripleGenerator.hpp:OTTripleGenerator::get_mac_key";
    case MascotSecretEventKind::StaticInstalled:
        return "Protocols/MascotPrep.h:MascotInputPrep::get_mac_key";
    case MascotSecretEventKind::Teardown:
        return "Protocols/MascotPrep.h:MascotInputPrep::teardown";
    }
    return {};
}

std::string_view mascot_secret_upstream_file_sha256(
        MascotSecretEventKind kind) {
    switch (kind) {
    case MascotSecretEventKind::ScalarStateBegin:
        return "579541d2ec20cdfdf44cd75e0098eb4635c8c61bf4439d20494d6e395f800d8e";
    case MascotSecretEventKind::SetupBegin:
        return "a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6";
    case MascotSecretEventKind::CacheOpened:
    case MascotSecretEventKind::CacheLocalValidation:
    case MascotSecretEventKind::CachePeerValidation:
    case MascotSecretEventKind::Regeneration:
    case MascotSecretEventKind::WriteCandidate:
    case MascotSecretEventKind::Writeback:
    case MascotSecretEventKind::PrepStaticInstalled:
    case MascotSecretEventKind::PrepMacFileWrite:
        return "155a8848fb253ce2bead8e9f03df703337ce6a94e97db18a9593c1383e5d2a0c";
    case MascotSecretEventKind::BitPrepDerived:
        return "a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6";
    case MascotSecretEventKind::StaticInstalled:
    case MascotSecretEventKind::Teardown:
        return "579541d2ec20cdfdf44cd75e0098eb4635c8c61bf4439d20494d6e395f800d8e";
    }
    return {};
}

std::vector<unsigned char> encode_mascot_secret_event(
        const MascotSecretEventView& value) {
    const auto kind = static_cast<std::uint64_t>(value.kind);
    const auto branch = static_cast<std::uint64_t>(value.branch);
    const auto local = static_cast<std::uint64_t>(value.local_validation);
    const auto peer = static_cast<std::uint64_t>(value.peer_validation);
    const auto regenerated = static_cast<std::uint64_t>(value.regeneration);
    const auto writeback = static_cast<std::uint64_t>(value.writeback);
    const auto prep_mac_write =
        static_cast<std::uint64_t>(value.prep_mac_write);
    const auto source_site = mascot_secret_source_site(value.kind);
    const auto source_sha256 =
        mascot_secret_upstream_file_sha256(value.kind);
    if (kind == 0 || kind > 13 || value.sequence == 0 ||
        value.local_role != 1 || value.player_count != 3 ||
        !value.encrypted_player || value.batch_size == 0 ||
        value.bucket_size == 0 || value.statistical_security == 0 ||
        (value.native_size_width != 4 && value.native_size_width != 8) ||
        (value.native_byte_order != 1 && value.native_byte_order != 2) ||
        branch == 0 || branch > 6 || local == 0 || local > 3 ||
        peer == 0 || peer > 3 || regenerated == 0 || regenerated > 3 ||
        writeback == 0 || writeback > 3 || prep_mac_write == 0 ||
        prep_mac_write > 3 || source_site.empty() ||
        source_sha256.size() != 64 ||
        !valid_text(value.player_id) || !all_decimal(value.field_modulus) ||
        !valid_text(value.canonical_cache_domain) ||
        !valid_text(value.diagnostic_path) ||
        !valid_text(value.failure_reason, true) || !valid_file(value.file))
        throw std::runtime_error("invalid-P1-MASCOT-secret-state-event");

    const auto no_file = value.file.result ==
        MascotFileResult::NotAttempted;
    const auto no_complete_keys =
        !value.complete_key_before_initialized &&
        !value.complete_key_after_initialized &&
        value.complete_key_before.empty() &&
        value.complete_key_after.empty();
    const auto no_scalar_keys = value.scalar_key_before.empty() &&
        value.scalar_key_after.empty();
    const auto no_prep_scalar_keys = value.prep_scalar_key_before.empty() &&
        value.prep_scalar_key_after.empty();
    const auto no_expected_scalar = value.expected_scalar_key.empty();
    const auto no_bit_prep_derivation =
        !value.bit_prep_aliases_main &&
        value.derived_complete_key.empty();
    if (value.kind != MascotSecretEventKind::CacheOpened &&
        value.kind != MascotSecretEventKind::Writeback &&
        value.kind != MascotSecretEventKind::PrepMacFileWrite && !no_file)
        throw std::runtime_error("unexpected-P1-MASCOT-file-snapshot");
    if (value.kind != MascotSecretEventKind::WriteCandidate &&
        value.kind != MascotSecretEventKind::PrepMacFileWrite &&
        !value.exact_write_candidate.empty())
        throw std::runtime_error("unexpected-P1-MASCOT-write-candidate");
    if (value.kind != MascotSecretEventKind::BitPrepDerived &&
        !no_bit_prep_derivation)
        throw std::runtime_error("unexpected-P1-MASCOT-bit-prep-derivation");

    switch (value.kind) {
    case MascotSecretEventKind::ScalarStateBegin:
        if (!no_file || value.sequence != 1 || !no_complete_keys ||
            value.branch != MascotCacheBranch::Undecided ||
            value.local_validation != MascotStepResult::NotAttempted ||
            value.peer_validation != MascotStepResult::NotAttempted ||
            value.regeneration != MascotStepResult::NotAttempted ||
            value.writeback != MascotStepResult::NotAttempted ||
            value.prep_mac_write != MascotStepResult::NotAttempted ||
            value.scalar_key_before.empty() ||
            !value.scalar_key_after.empty() ||
            value.prep_scalar_key_before.empty() ||
            !value.prep_scalar_key_after.empty() || !no_expected_scalar ||
            !value.failure_reason.empty())
            throw std::runtime_error("invalid-P1-MASCOT-scalar-begin");
        break;
    case MascotSecretEventKind::SetupBegin:
        if (!no_file || value.sequence != 2 ||
            value.local_validation != MascotStepResult::NotAttempted ||
            value.peer_validation != MascotStepResult::NotAttempted ||
            value.regeneration != MascotStepResult::NotAttempted ||
            value.writeback != MascotStepResult::NotAttempted ||
            value.prep_mac_write != MascotStepResult::NotAttempted ||
            value.complete_key_before.empty() ||
            value.complete_key_after_initialized ||
            !value.complete_key_after.empty() ||
            !no_scalar_keys || !no_prep_scalar_keys || !no_expected_scalar ||
            (value.complete_key_before_initialized !=
             (value.branch == MascotCacheBranch::StaticReuse)) ||
            !value.failure_reason.empty())
            throw std::runtime_error("invalid-P1-MASCOT-setup-event");
        break;
    case MascotSecretEventKind::CacheOpened:
        if (value.file.result == MascotFileResult::NotAttempted ||
            value.file.fsync_result != MascotStepResult::NotAttempted ||
            !no_complete_keys || !no_scalar_keys || !no_prep_scalar_keys ||
            !no_expected_scalar)
            throw std::runtime_error("invalid-P1-MASCOT-cache-open");
        break;
    case MascotSecretEventKind::CacheLocalValidation:
        if (!no_file ||
            value.local_validation == MascotStepResult::NotAttempted ||
            (value.local_validation == MascotStepResult::Succeeded &&
             (!value.complete_key_after_initialized ||
              value.complete_key_after.empty() ||
              !value.failure_reason.empty())) ||
            (value.local_validation == MascotStepResult::Failed &&
             (value.complete_key_after_initialized ||
              value.complete_key_after.empty() ||
              value.failure_reason.empty())) ||
            value.complete_key_before_initialized || !no_scalar_keys ||
            !no_prep_scalar_keys || !no_expected_scalar ||
            !value.complete_key_before.empty())
            throw std::runtime_error("invalid-P1-MASCOT-local-validation");
        break;
    case MascotSecretEventKind::CachePeerValidation:
        if (!no_file || !no_complete_keys || !no_scalar_keys ||
            !no_prep_scalar_keys || !no_expected_scalar ||
            value.peer_validation == MascotStepResult::NotAttempted ||
            (value.peer_validation == MascotStepResult::Succeeded &&
             !value.failure_reason.empty()) ||
            (value.peer_validation == MascotStepResult::Failed &&
             value.failure_reason.empty()))
            throw std::runtime_error("invalid-P1-MASCOT-peer-validation");
        break;
    case MascotSecretEventKind::Regeneration:
        if (!no_file || value.regeneration != MascotStepResult::Succeeded ||
            value.complete_key_before_initialized || !no_scalar_keys ||
            !no_prep_scalar_keys || !no_expected_scalar ||
            !value.complete_key_before.empty() ||
            !value.complete_key_after_initialized ||
            value.complete_key_after.empty() ||
            !value.failure_reason.empty())
            throw std::runtime_error("invalid-P1-MASCOT-regeneration");
        break;
    case MascotSecretEventKind::WriteCandidate:
        if (!no_file || !no_scalar_keys || !no_prep_scalar_keys ||
            !no_expected_scalar ||
            !value.complete_key_before_initialized ||
            value.complete_key_before.empty() ||
            !value.complete_key_after_initialized ||
            value.complete_key_after.empty() ||
            value.exact_write_candidate.empty() ||
            !value.failure_reason.empty())
            throw std::runtime_error("invalid-P1-MASCOT-write-candidate");
        break;
    case MascotSecretEventKind::Writeback:
        if (!no_complete_keys || !no_scalar_keys || !no_prep_scalar_keys ||
            !no_expected_scalar ||
            (value.writeback == MascotStepResult::Succeeded &&
             (value.file.result != MascotFileResult::Captured ||
              value.file.fsync_result != MascotStepResult::Succeeded ||
              !value.failure_reason.empty())) ||
            (value.writeback == MascotStepResult::Failed &&
             (value.file.result != MascotFileResult::Partial &&
              value.file.result != MascotFileResult::Failed)) ||
            value.writeback == MascotStepResult::NotAttempted)
            throw std::runtime_error("invalid-P1-MASCOT-writeback");
        break;
    case MascotSecretEventKind::PrepStaticInstalled:
        if (!no_file || !no_complete_keys || !no_scalar_keys ||
            value.writeback != MascotStepResult::Succeeded ||
            value.prep_mac_write != MascotStepResult::NotAttempted ||
            value.prep_scalar_key_before.empty() ||
            value.prep_scalar_key_after.empty() ||
            value.expected_scalar_key.empty() ||
            !same_bytes(
                value.prep_scalar_key_after, value.expected_scalar_key) ||
            !value.failure_reason.empty())
            throw std::runtime_error("invalid-P1-MASCOT-prep-static");
        break;
    case MascotSecretEventKind::PrepMacFileWrite:
    {
        const bool candidate_prefix =
            value.file.exact_file_bytes.size() <=
                value.exact_write_candidate.size() &&
            std::equal(
                value.file.exact_file_bytes.begin(),
                value.file.exact_file_bytes.end(),
                value.exact_write_candidate.begin());
        if (!no_complete_keys || !no_scalar_keys || !no_prep_scalar_keys ||
            !no_expected_scalar || value.exact_write_candidate.empty() ||
            value.writeback != MascotStepResult::Succeeded ||
            value.prep_mac_write == MascotStepResult::NotAttempted ||
            !candidate_prefix ||
            (value.prep_mac_write == MascotStepResult::Succeeded &&
             (value.file.result != MascotFileResult::Captured ||
              value.file.fsync_result != MascotStepResult::Succeeded ||
              value.file.exact_file_bytes.size() !=
                  value.exact_write_candidate.size() ||
              !value.failure_reason.empty())) ||
            (value.prep_mac_write == MascotStepResult::Failed &&
             (value.file.result != MascotFileResult::Partial &&
              value.file.result != MascotFileResult::Failed)) ||
            (value.prep_mac_write == MascotStepResult::Failed &&
             value.failure_reason.empty()))
            throw std::runtime_error("invalid-P1-MASCOT-prep-mac-write");
        break;
    }
    case MascotSecretEventKind::BitPrepDerived:
        if (!no_file || !no_scalar_keys || !no_prep_scalar_keys ||
            !no_expected_scalar ||
            value.prep_mac_write != MascotStepResult::Succeeded ||
            !value.complete_key_before_initialized ||
            !value.complete_key_after_initialized ||
            value.complete_key_before.empty() ||
            value.complete_key_after.empty() ||
            value.derived_complete_key.empty() ||
            !value.bit_prep_aliases_main ||
            value.complete_key_after.size() !=
                value.derived_complete_key.size() ||
            !std::equal(
                value.complete_key_after.begin(),
                value.complete_key_after.end(),
                value.derived_complete_key.begin()) ||
            !value.failure_reason.empty())
            throw std::runtime_error("invalid-P1-MASCOT-bit-prep-derived");
        break;
    case MascotSecretEventKind::StaticInstalled:
        if (!no_file || value.complete_key_before_initialized ||
            !value.complete_key_before.empty() ||
            !value.complete_key_after_initialized ||
            value.complete_key_after.empty() ||
            value.scalar_key_before.empty() ||
            value.scalar_key_after.empty() ||
            !no_prep_scalar_keys || value.expected_scalar_key.empty() ||
            !same_bytes(
                value.scalar_key_after, value.expected_scalar_key) ||
            ((value.branch == MascotCacheBranch::StaticReuse) !=
             (value.prep_mac_write == MascotStepResult::NotAttempted)) ||
            (value.branch != MascotCacheBranch::StaticReuse &&
             value.prep_mac_write != MascotStepResult::Succeeded) ||
            !value.failure_reason.empty())
            throw std::runtime_error("missing-P1-MASCOT-installed-key");
        break;
    case MascotSecretEventKind::Teardown:
        if (!no_file || !value.complete_key_before_initialized ||
            value.complete_key_after_initialized ||
            value.complete_key_before.empty() ||
            value.complete_key_after.empty() ||
            value.scalar_key_before.empty() || value.scalar_key_after.empty() ||
            value.prep_scalar_key_before.empty() ||
            value.prep_scalar_key_after.empty() || !no_expected_scalar ||
            !same_bytes(
                value.prep_scalar_key_before,
                value.prep_scalar_key_after) ||
            !same_bytes(
                value.scalar_key_before,
                value.prep_scalar_key_before) ||
            ((value.branch == MascotCacheBranch::StaticReuse) !=
             (value.prep_mac_write == MascotStepResult::NotAttempted)) ||
            (value.branch != MascotCacheBranch::StaticReuse &&
             value.prep_mac_write != MascotStepResult::Succeeded) ||
            !std::equal(
                value.scalar_key_before.begin(), value.scalar_key_before.end(),
                value.scalar_key_after.begin(), value.scalar_key_after.end()) ||
            !value.failure_reason.empty())
            throw std::runtime_error("invalid-P1-MASCOT-teardown-state");
        break;
    }

    std::vector<unsigned char> out;
    CleanseOnError cleanse_on_error(out);
    out.insert(
        out.end(), MASCOT_SECRET_EVENT_ENCODING_DOMAIN.begin(),
        MASCOT_SECRET_EVENT_ENCODING_DOMAIN.end());
    append_string(out, MASCOT_SECRETS_MP_SPDZ_COMMIT);
    append_u64(out, kPinnedSourceManifest.size());
    for (const auto& source : kPinnedSourceManifest) {
        append_string(out, source.path);
        append_string(out, source.sha256);
    }
    append_string(out, source_site);
    append_string(out, source_sha256);
    for (const auto field : {
             kind, value.sequence, value.local_role, value.player_count,
             value.batch_size, value.bucket_size,
             value.statistical_security, value.native_size_width,
             value.native_byte_order, branch, local, peer, regenerated,
             writeback, prep_mac_write,
             static_cast<std::uint64_t>(value.file.result),
             value.file.operation_errno, value.file.open_flags,
             value.file.bytes_transferred,
             static_cast<std::uint64_t>(
                 value.file.parent_directory_result),
             value.file.parent_directory_errno,
             static_cast<std::uint64_t>(value.file.fsync_result),
             value.file.fsync_errno,
             static_cast<std::uint64_t>(value.file.rename_result),
             value.file.rename_errno,
             static_cast<std::uint64_t>(value.file.unlink_result),
             value.file.unlink_errno})
        append_u64(out, field);
    append_bool(out, value.encrypted_player);
    append_bool(out, value.uses_security_parameter);
    append_bool(out, value.uses_kos);
    append_bool(out, value.file.no_follow);
    append_bool(out, value.complete_key_before_initialized);
    append_bool(out, value.complete_key_after_initialized);
    append_bool(out, value.bit_prep_aliases_main);
    append_string(out, value.player_id);
    append_string(out, value.field_modulus);
    append_string(out, value.canonical_cache_domain);
    append_string(out, value.diagnostic_path);
    append_string(out, value.failure_reason);
    append_metadata(out, value.file.path_lstat_before);
    append_metadata(out, value.file.descriptor_before);
    append_metadata(out, value.file.descriptor_after);
    append_metadata(out, value.file.path_lstat_after);
    append_metadata(out, value.file.reopened_descriptor);
    for (const auto bytes : {
             value.file.exact_file_bytes, value.complete_key_before,
             value.complete_key_after, value.scalar_key_before,
             value.scalar_key_after, value.prep_scalar_key_before,
             value.prep_scalar_key_after, value.expected_scalar_key,
             value.derived_complete_key,
             value.exact_write_candidate})
        append_bytes(out, bytes);
    cleanse_on_error.release();
    return out;
}

std::string_view mascot_secret_abort_source_site(
        MascotSecretAbortEventKind kind,
        MascotSecretAbortClass abort_class) {
    switch (kind) {
    case MascotSecretAbortEventKind::CacheUnlink:
        return abort_class == MascotSecretAbortClass::OtMultiplierFailure
            ? "OT/OTMultiplier.hpp:OTMultiplier::multiply"
            : "Protocols/MAC_Check.hpp:MAC_Check::mac_fail_remove";
    case MascotSecretAbortEventKind::WorkerFailurePublished:
    case MascotSecretAbortEventKind::WorkerTerminal:
        return "OT/NPartyTripleGenerator.hpp:run_ot_thread";
    case MascotSecretAbortEventKind::RootFailureObserved:
        return "OT/NPartyTripleGenerator.hpp:OTTripleGenerator::wait_for_multipliers";
    case MascotSecretAbortEventKind::WorkerJoined:
        return "OT/NPartyTripleGenerator.hpp:OTTripleGenerator::stop_and_join_multipliers";
    case MascotSecretAbortEventKind::Teardown:
        return "Protocols/MascotPrep.h:MascotInputPrep::teardown";
    case MascotSecretAbortEventKind::AbortTerminal:
    case MascotSecretAbortEventKind::AbortUnavailable:
        return abort_class == MascotSecretAbortClass::OtMultiplierFailure
            ? "OT/NPartyTripleGenerator.hpp:source-owned-abort-terminal"
            : "Protocols/MAC_Check.hpp:source-owned-abort-terminal";
    }
    return {};
}

std::string_view mascot_secret_abort_upstream_file_sha256(
        MascotSecretAbortEventKind kind,
        MascotSecretAbortClass abort_class) {
    switch (kind) {
    case MascotSecretAbortEventKind::CacheUnlink:
        return abort_class == MascotSecretAbortClass::OtMultiplierFailure
            ? "12429b0c5a81c17e02c80b36b5636d763efa679086e5244dabe1838792b25eb4"
            : "6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8";
    case MascotSecretAbortEventKind::WorkerFailurePublished:
    case MascotSecretAbortEventKind::WorkerTerminal:
    case MascotSecretAbortEventKind::RootFailureObserved:
    case MascotSecretAbortEventKind::WorkerJoined:
        return "a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6";
    case MascotSecretAbortEventKind::Teardown:
        return "579541d2ec20cdfdf44cd75e0098eb4635c8c61bf4439d20494d6e395f800d8e";
    case MascotSecretAbortEventKind::AbortTerminal:
    case MascotSecretAbortEventKind::AbortUnavailable:
        return abort_class == MascotSecretAbortClass::OtMultiplierFailure
            ? "a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6"
            : "6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8";
    }
    return {};
}

std::vector<unsigned char> encode_mascot_secret_abort_event(
        const MascotSecretAbortEventView& value) {
    const auto kind = static_cast<std::uint64_t>(value.kind);
    const auto abort_class = static_cast<std::uint64_t>(value.abort_class);
    const auto branch = static_cast<std::uint64_t>(value.branch);
    const auto exception_kind =
        static_cast<std::uint64_t>(value.exception_kind);
    const auto source_site = mascot_secret_abort_source_site(
        value.kind, value.abort_class);
    const auto source_sha256 = mascot_secret_abort_upstream_file_sha256(
        value.kind, value.abort_class);
    const bool no_complete_keys =
        !value.complete_key_before_initialized &&
        !value.complete_key_after_initialized &&
        value.complete_key_before.empty() &&
        value.complete_key_after.empty();
    const bool no_scalar_keys = value.scalar_key_before.empty() &&
        value.scalar_key_after.empty() &&
        value.prep_scalar_key_before.empty() &&
        value.prep_scalar_key_after.empty();
    const bool no_unlink = !value.unlink_attempted &&
        !value.unlink_succeeded && value.unlink_errno == 0 &&
        absent(value.path_lstat_before) && absent(value.path_lstat_after);
    const bool worker_target = value.source_worker_epoch != 0 &&
        value.source_worker_ordinal < value.registered_worker_count;
    if (kind == 0 || kind > 8 || abort_class == 0 || abort_class > 2 ||
        branch == 0 || branch > 6 ||
        value.branch == MascotCacheBranch::Undecided ||
        value.sequence == 0 || value.success_next_sequence == 0 ||
        value.success_counter == 0 || value.local_role != 1 ||
        value.player_count != 3 || !value.encrypted_player ||
        value.registered_worker_count > value.player_count - 1 ||
        exception_kind == 0 || exception_kind > 3 ||
        !valid_text(value.canonical_cache_domain) ||
        !valid_text(value.diagnostic_path) || source_site.empty() ||
        source_sha256.size() != 64 ||
        !valid_metadata(value.path_lstat_before) ||
        !valid_metadata(value.path_lstat_after) ||
        !regular_or_absent(value.path_lstat_before) ||
        !regular_or_absent(value.path_lstat_after))
        throw std::runtime_error("invalid-P1-MASCOT-abort-event");

    switch (value.kind) {
    case MascotSecretAbortEventKind::CacheUnlink:
        if (!value.unlink_attempted || !no_complete_keys ||
            !no_scalar_keys || value.teardown_observed ||
            value.exception_kind !=
                MascotWorkerExceptionKind::NotApplicable ||
            (value.unlink_succeeded &&
             (value.unlink_errno != 0 ||
              !value.path_lstat_before.present ||
              value.path_lstat_after.present)) ||
            (!value.unlink_succeeded && value.unlink_errno == 0) ||
            (value.abort_class ==
                 MascotSecretAbortClass::OtMultiplierFailure &&
             (!value.source_worker || !worker_target)) ||
            (value.abort_class == MascotSecretAbortClass::MacCheckFailure &&
             (value.source_worker || value.source_worker_epoch != 0 ||
              value.source_worker_ordinal != 0)))
            throw std::runtime_error("invalid-P1-MASCOT-abort-unlink");
        break;
    case MascotSecretAbortEventKind::WorkerFailurePublished:
        if (value.abort_class !=
                MascotSecretAbortClass::OtMultiplierFailure ||
            !value.source_worker || !worker_target || !value.worker_failed ||
            value.exception_kind ==
                MascotWorkerExceptionKind::NotApplicable ||
            !no_unlink || !no_complete_keys || !no_scalar_keys ||
            value.teardown_observed)
            throw std::runtime_error("invalid-P1-MASCOT-worker-failure");
        break;
    case MascotSecretAbortEventKind::WorkerTerminal:
        if (!value.source_worker || !worker_target || !no_unlink ||
            !no_complete_keys || !no_scalar_keys ||
            value.exception_kind !=
                MascotWorkerExceptionKind::NotApplicable ||
            value.teardown_observed)
            throw std::runtime_error("invalid-P1-MASCOT-worker-terminal");
        break;
    case MascotSecretAbortEventKind::RootFailureObserved:
        if (value.abort_class !=
                MascotSecretAbortClass::OtMultiplierFailure ||
            value.source_worker || !worker_target || !value.worker_failed ||
            !no_unlink || !no_complete_keys || !no_scalar_keys ||
            value.exception_kind !=
                MascotWorkerExceptionKind::NotApplicable ||
            value.teardown_observed)
            throw std::runtime_error("invalid-P1-MASCOT-root-observed");
        break;
    case MascotSecretAbortEventKind::WorkerJoined:
        if (value.source_worker || !worker_target || !no_unlink ||
            !no_complete_keys || !no_scalar_keys ||
            value.exception_kind !=
                MascotWorkerExceptionKind::NotApplicable ||
            value.teardown_observed)
            throw std::runtime_error("invalid-P1-MASCOT-worker-joined");
        break;
    case MascotSecretAbortEventKind::Teardown:
        if (value.source_worker || value.source_worker_epoch != 0 ||
            value.source_worker_ordinal != 0 || !no_unlink ||
            !value.teardown_observed ||
            !value.complete_key_before_initialized ||
            value.complete_key_after_initialized ||
            value.complete_key_before.empty() ||
            value.complete_key_after.empty() ||
            value.scalar_key_before.empty() ||
            value.scalar_key_after.empty() ||
            value.prep_scalar_key_before.empty() ||
            value.prep_scalar_key_after.empty() ||
            value.exception_kind !=
                MascotWorkerExceptionKind::NotApplicable)
            throw std::runtime_error("invalid-P1-MASCOT-abort-teardown");
        break;
    case MascotSecretAbortEventKind::AbortTerminal:
        if (value.source_worker || value.source_worker_epoch != 0 ||
            value.source_worker_ordinal != 0 || !no_unlink ||
            !no_complete_keys || !no_scalar_keys ||
            !value.all_workers_terminal || !value.all_workers_joined ||
            !value.teardown_observed ||
            value.exception_kind !=
                MascotWorkerExceptionKind::NotApplicable)
            throw std::runtime_error("invalid-P1-MASCOT-abort-terminal");
        break;
    case MascotSecretAbortEventKind::AbortUnavailable:
        if (value.source_worker || value.source_worker_epoch != 0 ||
            value.source_worker_ordinal != 0 || !no_unlink ||
            !no_complete_keys || !no_scalar_keys ||
            (value.all_workers_terminal && value.all_workers_joined &&
             value.teardown_observed) ||
            value.exception_kind !=
                MascotWorkerExceptionKind::NotApplicable)
            throw std::runtime_error("invalid-P1-MASCOT-abort-unavailable");
        break;
    }

    std::vector<unsigned char> out;
    CleanseOnError cleanse_on_error(out);
    out.insert(
        out.end(), MASCOT_SECRET_ABORT_EVENT_ENCODING_DOMAIN.begin(),
        MASCOT_SECRET_ABORT_EVENT_ENCODING_DOMAIN.end());
    append_string(out, MASCOT_SECRETS_MP_SPDZ_COMMIT);
    append_u64(out, kPinnedSourceManifest.size());
    for (const auto& source : kPinnedSourceManifest) {
        append_string(out, source.path);
        append_string(out, source.sha256);
    }
    append_string(out, source_site);
    append_string(out, source_sha256);
    for (const auto field : {
             kind, value.sequence, abort_class, branch,
             value.success_next_sequence, value.success_counter,
             value.local_role, value.player_count,
             value.source_worker_epoch, value.source_worker_ordinal,
             value.registered_worker_count, exception_kind,
             value.unlink_errno})
        append_u64(out, field);
    for (const auto flag : {
             value.encrypted_player, value.source_worker,
             value.worker_failed, value.all_workers_terminal,
             value.all_workers_joined, value.teardown_observed,
             value.unlink_attempted, value.unlink_succeeded,
             value.complete_key_before_initialized,
             value.complete_key_after_initialized})
        append_bool(out, flag);
    append_string(out, value.canonical_cache_domain);
    append_string(out, value.diagnostic_path);
    append_metadata(out, value.path_lstat_before);
    append_metadata(out, value.path_lstat_after);
    for (const auto bytes : {
             value.complete_key_before, value.complete_key_after,
             value.scalar_key_before, value.scalar_key_after,
             value.prep_scalar_key_before,
             value.prep_scalar_key_after})
        append_bytes(out, bytes);
    cleanse_on_error.release();
    return out;
}

struct MascotSecretStateHookScope::Storage final {
    enum class Next : std::uint8_t {
        ScalarStateBegin,
        Setup,
        CacheOpen,
        LocalValidation,
        PeerValidation,
        Regeneration,
        WriteCandidate,
        Writeback,
        PrepStaticInstalled,
        PrepMacFileWrite,
        BitPrepDerived,
        StaticInstalled,
        Teardown,
        Abort,
        Terminal,
        Unavailable,
    };

    struct Worker final {
        const void* source_identity{};
        std::uint64_t epoch{};
        std::uint64_t ordinal{};
        std::thread::id thread;
        bool started{};
        bool failure_published{};
        bool terminal{};
        bool root_observed{};
        bool joined{};
    };

    inline static std::mutex mutex;
    inline static Storage* active{};
    inline static thread_local Storage* local{};
    inline static thread_local Storage* worker_local{};
    inline static thread_local const void* worker_source_identity{};

    MascotSecretStateHook* hook{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    bool encrypted_player{};
    std::string player_id;
    std::string field_modulus;
    std::string cache_domain;
    std::string diagnostic_path;
    std::uint64_t batch_size{};
    std::uint64_t bucket_size{};
    std::uint64_t statistical_security{};
    bool uses_security_parameter{};
    bool uses_kos{};
    std::uint64_t sequence{1};
    MascotCacheBranch branch{MascotCacheBranch::Undecided};
    MascotStepResult local_validation{MascotStepResult::NotAttempted};
    MascotStepResult peer_validation{MascotStepResult::NotAttempted};
    MascotStepResult regeneration{MascotStepResult::NotAttempted};
    MascotStepResult writeback{MascotStepResult::NotAttempted};
    MascotStepResult prep_mac_write{MascotStepResult::NotAttempted};
    MascotFileResult cache_file_result{MascotFileResult::NotAttempted};
    Next next{Next::ScalarStateBegin};
    std::vector<unsigned char> write_candidate;
    std::vector<unsigned char> current_complete_key;
    std::vector<unsigned char> installed_scalar_key;
    std::vector<unsigned char> current_prep_scalar_key;
    std::vector<unsigned char> current_online_scalar_key;
    std::vector<Worker> workers;
    std::thread::id owner_thread;
    std::uint64_t next_worker_epoch{1};
    std::uint64_t abort_sequence{1};
    std::uint64_t registered_worker_count{};
    MascotSecretAbortClass abort_class{
        MascotSecretAbortClass::OtMultiplierFailure};
    bool aborting{};
    bool abort_unlink_seen{};
    bool abort_teardown_seen{};
    bool abort_terminal_emitted{};

    Worker* find_worker(const void* identity) noexcept {
        const auto found = std::find_if(
            workers.begin(), workers.end(), [identity](const Worker& worker) {
                return worker.source_identity == identity;
            });
        return found == workers.end() ? nullptr : &*found;
    }

    bool all_workers_terminal() const noexcept {
        return workers.size() == registered_worker_count &&
            std::all_of(workers.begin(), workers.end(), [](const Worker& value) {
                return value.started && value.terminal;
            });
    }

    bool all_workers_joined() const noexcept {
        return workers.size() == registered_worker_count &&
            std::all_of(workers.begin(), workers.end(), [](const Worker& value) {
                return value.joined;
            });
    }

    bool emit_abort(
            MascotSecretAbortEventKind kind,
            bool source_worker = false,
            const Worker* worker = nullptr,
            MascotWorkerExceptionKind exception_kind =
                MascotWorkerExceptionKind::NotApplicable,
            bool worker_failed = false,
            bool unlink_attempted = false,
            bool unlink_succeeded = false,
            std::uint64_t unlink_errno = 0,
            const MascotFileMetadataView& path_lstat_before = {},
            const MascotFileMetadataView& path_lstat_after = {},
            bool teardown_observed = false,
            bool complete_key_before_initialized = false,
            std::span<const unsigned char> complete_key_before = {},
            bool complete_key_after_initialized = false,
            std::span<const unsigned char> complete_key_after = {},
            std::span<const unsigned char> scalar_key_before = {},
            std::span<const unsigned char> scalar_key_after = {},
            std::span<const unsigned char> prep_scalar_key_before = {},
            std::span<const unsigned char> prep_scalar_key_after = {})
            noexcept {
        try {
            MascotSecretAbortEventView event{
                .kind = kind,
                .sequence = abort_sequence,
                .abort_class = abort_class,
                .branch = branch,
                .success_next_sequence = sequence,
                .success_counter = sequence > 1 ? sequence - 2 : 0,
                .local_role = local_role,
                .player_count = player_count,
                .encrypted_player = encrypted_player,
                .source_worker = source_worker,
                .source_worker_epoch = worker == nullptr ? 0 : worker->epoch,
                .source_worker_ordinal =
                    worker == nullptr ? 0 : worker->ordinal,
                .registered_worker_count = registered_worker_count,
                .exception_kind = exception_kind,
                .worker_failed = worker_failed,
                .all_workers_terminal = all_workers_terminal(),
                .all_workers_joined = all_workers_joined(),
                .teardown_observed = teardown_observed,
                .unlink_attempted = unlink_attempted,
                .unlink_succeeded = unlink_succeeded,
                .unlink_errno = unlink_errno,
                .canonical_cache_domain = cache_domain,
                .diagnostic_path = diagnostic_path,
                .path_lstat_before = path_lstat_before,
                .path_lstat_after = path_lstat_after,
                .complete_key_before_initialized =
                    complete_key_before_initialized,
                .complete_key_after_initialized =
                    complete_key_after_initialized,
                .complete_key_before = complete_key_before,
                .complete_key_after = complete_key_after,
                .scalar_key_before = scalar_key_before,
                .scalar_key_after = scalar_key_after,
                .prep_scalar_key_before = prep_scalar_key_before,
                .prep_scalar_key_after = prep_scalar_key_after,
            };
            if (hook == nullptr ||
                !hook->record_mascot_secret_abort_event(event))
                return false;
            ++abort_sequence;
            return true;
        } catch (...) {
            return false;
        }
    }

    void unavailable_noexcept() noexcept {
        if (next == Next::Unavailable) return;
        next = Next::Unavailable;
        cleanse(write_candidate);
        cleanse(current_complete_key);
        cleanse(installed_scalar_key);
        cleanse(current_prep_scalar_key);
        cleanse(current_online_scalar_key);
        if (hook != nullptr) hook->mascot_secret_unavailable_noexcept();
    }

    static Storage* current_locked_noexcept() noexcept {
        if (active == nullptr) return nullptr;
        if (local != active ||
            active->owner_thread != std::this_thread::get_id()) {
            active->unavailable_noexcept();
            return nullptr;
        }
        return active;
    }

    bool emit(
            MascotSecretEventKind kind, const MascotFileSnapshotView& file,
            std::string_view failure_reason,
            bool complete_key_before_initialized,
            std::span<const unsigned char> complete_key_before,
            bool complete_key_after_initialized,
            std::span<const unsigned char> complete_key_after,
            std::span<const unsigned char> scalar_key_before,
            std::span<const unsigned char> scalar_key_after,
            std::span<const unsigned char> candidate,
            std::span<const unsigned char> derived_complete_key = {},
            bool bit_prep_aliases_main = false,
            std::span<const unsigned char> prep_scalar_key_before = {},
            std::span<const unsigned char> prep_scalar_key_after = {},
            std::span<const unsigned char> expected_scalar_key = {},
            std::string_view event_path = {}) noexcept {
        if (next == Next::Unavailable || next == Next::Terminal) {
            unavailable_noexcept();
            return false;
        }
        try {
            MascotSecretEventView event{
                .kind = kind,
                .sequence = sequence,
                .local_role = local_role,
                .player_count = player_count,
                .encrypted_player = encrypted_player,
                .batch_size = batch_size,
                .bucket_size = bucket_size,
                .statistical_security = statistical_security,
                .uses_security_parameter = uses_security_parameter,
                .uses_kos = uses_kos,
                .native_size_width = sizeof(std::size_t),
                .native_byte_order =
                    std::endian::native == std::endian::little ? 1U : 2U,
                .branch = branch,
                .local_validation = local_validation,
                .peer_validation = peer_validation,
                .regeneration = regeneration,
                .writeback = writeback,
                .prep_mac_write = prep_mac_write,
                .player_id = player_id,
                .field_modulus = field_modulus,
                .canonical_cache_domain = cache_domain,
                .diagnostic_path = event_path.empty()
                    ? std::string_view(diagnostic_path) : event_path,
                .failure_reason = failure_reason,
                .file = file,
                .complete_key_before_initialized =
                    complete_key_before_initialized,
                .complete_key_after_initialized =
                    complete_key_after_initialized,
                .complete_key_before = complete_key_before,
                .complete_key_after = complete_key_after,
                .scalar_key_before = scalar_key_before,
                .scalar_key_after = scalar_key_after,
                .prep_scalar_key_before = prep_scalar_key_before,
                .prep_scalar_key_after = prep_scalar_key_after,
                .expected_scalar_key = expected_scalar_key,
                .bit_prep_aliases_main = bit_prep_aliases_main,
                .derived_complete_key = derived_complete_key,
                .exact_write_candidate = candidate,
            };
            if (hook == nullptr || !hook->record_mascot_secret_event(event)) {
                unavailable_noexcept();
                return false;
            }
            ++sequence;
            return true;
        } catch (...) {
            unavailable_noexcept();
            return false;
        }
    }

    ~Storage() {
        cleanse(write_candidate);
        cleanse(current_complete_key);
        cleanse(installed_scalar_key);
        cleanse(current_prep_scalar_key);
        cleanse(current_online_scalar_key);
    }
};

MascotSecretStateHookScope::MascotSecretStateHookScope(
        MascotSecretStateHook& hook, std::uint64_t local_role,
        std::uint64_t player_count, bool encrypted_player,
        std::string_view player_id, std::string_view field_modulus)
    : storage_(std::make_unique<Storage>()) {
    if (local_role != 1 || player_count != 3 || !encrypted_player ||
        !valid_text(player_id) || !all_decimal(field_modulus))
        throw std::runtime_error("invalid-P1-MASCOT-hook-scope");
    storage_->hook = &hook;
    storage_->local_role = local_role;
    storage_->player_count = player_count;
    storage_->encrypted_player = encrypted_player;
    storage_->player_id.assign(player_id);
    storage_->field_modulus.assign(field_modulus);
    storage_->owner_thread = std::this_thread::get_id();
    std::lock_guard lock(Storage::mutex);
    if (Storage::active != nullptr || Storage::local != nullptr)
        throw std::runtime_error("duplicate-P1-MASCOT-hook-scope");
    Storage::active = storage_.get();
    Storage::local = storage_.get();
}

std::unique_ptr<MascotSecretStateHookScope>
MascotSecretStateScopeFactoryBridge::install(
        MascotSecretStateHook& hook, std::uint64_t local_role,
        std::uint64_t player_count, bool encrypted_player,
        std::string_view player_id, std::string_view field_modulus) {
    return std::unique_ptr<MascotSecretStateHookScope>(
        new MascotSecretStateHookScope(
            hook, local_role, player_count, encrypted_player,
            player_id, field_modulus));
}

#ifdef KPI_P1_MASCOT_SECRET_STATE_HOOK_TEST_SETUP
std::unique_ptr<MascotSecretStateHookScope>
MascotSecretStateScopeFactoryBridge::test_only_install(
        MascotSecretStateHook& hook, std::uint64_t local_role,
        std::uint64_t player_count, bool encrypted_player,
        std::string_view player_id, std::string_view field_modulus) {
    return install(
        hook, local_role, player_count, encrypted_player,
        player_id, field_modulus);
}
#endif

MascotSecretStateHookScope::~MascotSecretStateHookScope() {
    if (!storage_) return;
    std::lock_guard lock(Storage::mutex);
    if (storage_->aborting &&
        storage_->next != Storage::Next::Unavailable &&
        !storage_->abort_terminal_emitted) {
        const bool worker_failure_closed =
            storage_->abort_class !=
                MascotSecretAbortClass::OtMultiplierFailure ||
            std::any_of(
                storage_->workers.begin(), storage_->workers.end(),
                [](const Storage::Worker& worker) {
                    return worker.failure_published &&
                        worker.root_observed;
                });
        const bool complete = storage_->abort_unlink_seen &&
            storage_->abort_teardown_seen &&
            storage_->all_workers_terminal() &&
            storage_->all_workers_joined() && worker_failure_closed;
        const auto kind = complete
            ? MascotSecretAbortEventKind::AbortTerminal
            : MascotSecretAbortEventKind::AbortUnavailable;
        if (storage_->emit_abort(
                kind, false, nullptr,
                MascotWorkerExceptionKind::NotApplicable, false,
                false, false, 0, {}, {},
                storage_->abort_teardown_seen)) {
            storage_->abort_terminal_emitted = true;
            storage_->next = complete
                ? Storage::Next::Terminal : Storage::Next::Unavailable;
        } else {
            storage_->unavailable_noexcept();
        }
        cleanse(storage_->write_candidate);
        cleanse(storage_->current_complete_key);
        cleanse(storage_->installed_scalar_key);
        cleanse(storage_->current_prep_scalar_key);
        cleanse(storage_->current_online_scalar_key);
    } else if (storage_->next != Storage::Next::Terminal) {
        storage_->unavailable_noexcept();
    }
    if (Storage::active == storage_.get()) Storage::active = nullptr;
    if (Storage::local == storage_.get()) Storage::local = nullptr;
}

bool MascotSecretStateSourceBridge::capture_required_noexcept() noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    const bool installed =
        MascotSecretStateHookScope::Storage::active != nullptr;
    (void)MascotSecretStateHookScope::Storage::current_locked_noexcept();
    return installed;
}

bool MascotSecretStateSourceBridge::scalar_state_begin(
        std::string_view cache_domain, std::string_view diagnostic_path,
        std::uint64_t batch_size, std::uint64_t bucket_size,
        std::uint64_t statistical_security, bool uses_security_parameter,
        bool uses_kos,
        std::span<const unsigned char> prep_scalar_key_before,
        std::span<const unsigned char> online_scalar_key_before) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::ScalarStateBegin ||
        !valid_text(cache_domain) || !valid_text(diagnostic_path) ||
        batch_size == 0 || bucket_size == 0 || statistical_security == 0 ||
        prep_scalar_key_before.empty() || online_scalar_key_before.empty()) {
        state->unavailable_noexcept();
        return false;
    }
    state->cache_domain.assign(cache_domain);
    state->diagnostic_path.assign(diagnostic_path);
    state->batch_size = batch_size;
    state->bucket_size = bucket_size;
    state->statistical_security = statistical_security;
    state->uses_security_parameter = uses_security_parameter;
    state->uses_kos = uses_kos;
    if (!state->emit(
            MascotSecretEventKind::ScalarStateBegin, not_attempted_file(),
            {}, false, {}, false, {}, online_scalar_key_before, {}, {}, {},
            false, prep_scalar_key_before))
        return false;
    replace_secret(state->current_prep_scalar_key, prep_scalar_key_before);
    replace_secret(state->current_online_scalar_key, online_scalar_key_before);
    state->next = MascotSecretStateHookScope::Storage::Next::Setup;
    return true;
}

bool MascotSecretStateSourceBridge::setup_begin(
        std::string_view cache_domain, std::string_view diagnostic_path,
        std::uint64_t batch_size, std::uint64_t bucket_size,
        std::uint64_t statistical_security, bool uses_security_parameter,
        bool uses_kos, bool complete_key_before_initialized,
        std::span<const unsigned char> complete_key_before) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next != MascotSecretStateHookScope::Storage::Next::Setup ||
        !valid_text(cache_domain) || !valid_text(diagnostic_path) ||
        batch_size == 0 || bucket_size == 0 ||
        statistical_security == 0 || complete_key_before.empty() ||
        cache_domain != state->cache_domain ||
        diagnostic_path != state->diagnostic_path ||
        batch_size != state->batch_size || bucket_size != state->bucket_size ||
        statistical_security != state->statistical_security ||
        uses_security_parameter != state->uses_security_parameter ||
        uses_kos != state->uses_kos) {
        state->unavailable_noexcept();
        return false;
    }
    state->branch = complete_key_before_initialized
        ? MascotCacheBranch::StaticReuse
        : MascotCacheBranch::Undecided;
    if (!state->emit(
            MascotSecretEventKind::SetupBegin, not_attempted_file(), {},
            complete_key_before_initialized, complete_key_before, false, {},
            {}, {}, {}))
        return false;
    replace_secret(state->current_complete_key, complete_key_before);
    state->next = complete_key_before_initialized
        ? MascotSecretStateHookScope::Storage::Next::StaticInstalled
        : MascotSecretStateHookScope::Storage::Next::CacheOpen;
    return true;
}

bool MascotSecretStateSourceBridge::cache_opened(
        std::string_view diagnostic_path,
        const MascotFileSnapshotView& file) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::CacheOpen ||
        file.result == MascotFileResult::NotAttempted ||
        diagnostic_path != state->diagnostic_path) {
        state->unavailable_noexcept();
        return false;
    }
    state->cache_file_result = file.result;
    if (!state->emit(
            MascotSecretEventKind::CacheOpened, file, {}, false, {}, false,
            {}, {}, {}, {}))
        return false;
    state->next =
        MascotSecretStateHookScope::Storage::Next::LocalValidation;
    return true;
}

bool MascotSecretStateSourceBridge::cache_local_validation(
        MascotStepResult result, bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after,
        std::string_view failure_reason) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::LocalValidation ||
        result == MascotStepResult::NotAttempted ||
        (result == MascotStepResult::Succeeded &&
         (state->cache_file_result != MascotFileResult::Captured ||
          !complete_key_after_initialized || complete_key_after.empty() ||
          !failure_reason.empty())) ||
        (result == MascotStepResult::Failed &&
         (complete_key_after_initialized || complete_key_after.empty() ||
          failure_reason.empty()))) {
        state->unavailable_noexcept();
        return false;
    }
    state->local_validation = result;
    if (result == MascotStepResult::Succeeded)
        state->branch = MascotCacheBranch::CacheHit;
    else if (state->cache_file_result == MascotFileResult::Missing)
        state->branch = MascotCacheBranch::RegeneratedAfterMissing;
    else
        state->branch = MascotCacheBranch::RegeneratedAfterLocalReject;
    if (!state->emit(
            MascotSecretEventKind::CacheLocalValidation,
            not_attempted_file(), failure_reason, false, {},
            complete_key_after_initialized, complete_key_after, {}, {}, {}))
        return false;
    if (result == MascotStepResult::Succeeded)
        replace_secret(
            state->current_complete_key, complete_key_after);
    state->next =
        MascotSecretStateHookScope::Storage::Next::PeerValidation;
    return true;
}

bool MascotSecretStateSourceBridge::cache_peer_validation(
        MascotStepResult result, std::string_view failure_reason) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::PeerValidation ||
        result == MascotStepResult::NotAttempted ||
        (result == MascotStepResult::Succeeded && !failure_reason.empty()) ||
        (result == MascotStepResult::Failed && failure_reason.empty())) {
        state->unavailable_noexcept();
        return false;
    }
    state->peer_validation = result;
    if (result == MascotStepResult::Failed)
        state->branch = MascotCacheBranch::RegeneratedAfterPeerReject;
    if (!state->emit(
            MascotSecretEventKind::CachePeerValidation,
            not_attempted_file(), failure_reason, false, {}, false, {}, {},
            {}, {}))
        return false;
    state->next =
        (state->local_validation == MascotStepResult::Failed ||
         state->peer_validation == MascotStepResult::Failed)
        ? MascotSecretStateHookScope::Storage::Next::Regeneration
        : MascotSecretStateHookScope::Storage::Next::WriteCandidate;
    return true;
}

bool MascotSecretStateSourceBridge::regeneration(
        bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::Regeneration ||
        !complete_key_after_initialized || complete_key_after.empty()) {
        state->unavailable_noexcept();
        return false;
    }
    state->regeneration = MascotStepResult::Succeeded;
    if (!state->emit(
            MascotSecretEventKind::Regeneration, not_attempted_file(), {},
            false, {}, true, complete_key_after, {}, {}, {}))
        return false;
    replace_secret(state->current_complete_key, complete_key_after);
    state->next =
        MascotSecretStateHookScope::Storage::Next::WriteCandidate;
    return true;
}

bool MascotSecretStateSourceBridge::write_candidate(
        bool complete_key_before_initialized,
        std::span<const unsigned char> complete_key_before,
        bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after,
        std::span<const unsigned char> exact_candidate) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::WriteCandidate ||
        !complete_key_before_initialized ||
        !complete_key_after_initialized || complete_key_before.empty() ||
        complete_key_after.empty() ||
        exact_candidate.empty() ||
        !same_bytes(complete_key_before, state->current_complete_key)) {
        state->unavailable_noexcept();
        return false;
    }
    state->write_candidate.assign(
        exact_candidate.begin(), exact_candidate.end());
    if (!state->emit(
            MascotSecretEventKind::WriteCandidate, not_attempted_file(), {},
            true, complete_key_before, true, complete_key_after, {}, {},
            exact_candidate))
        return false;
    replace_secret(state->current_complete_key, complete_key_after);
    state->next = MascotSecretStateHookScope::Storage::Next::Writeback;
    return true;
}

bool MascotSecretStateSourceBridge::writeback(
        std::string_view diagnostic_path, MascotStepResult result,
        const MascotFileSnapshotView& file,
        std::string_view failure_reason) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    const bool exact_match =
        file.exact_file_bytes.size() == state->write_candidate.size() &&
        std::equal(file.exact_file_bytes.begin(), file.exact_file_bytes.end(),
                   state->write_candidate.begin());
    if (state->next != MascotSecretStateHookScope::Storage::Next::Writeback ||
        diagnostic_path != state->diagnostic_path ||
        result == MascotStepResult::NotAttempted ||
        (result == MascotStepResult::Succeeded &&
         (file.result != MascotFileResult::Captured || !exact_match ||
          !failure_reason.empty())) ||
        (result == MascotStepResult::Failed && failure_reason.empty())) {
        state->unavailable_noexcept();
        return false;
    }
    state->writeback = result;
    const bool retained = state->emit(
        MascotSecretEventKind::Writeback, file, failure_reason, false, {},
        false, {}, {}, {}, {});
    if (!retained) return false;
    if (result == MascotStepResult::Failed) {
        state->unavailable_noexcept();
        return true;
    }
    state->next =
        MascotSecretStateHookScope::Storage::Next::PrepStaticInstalled;
    return true;
}

bool MascotSecretStateSourceBridge::prep_static_installed(
        std::span<const unsigned char> prep_scalar_key_before,
        std::span<const unsigned char> prep_scalar_key_after,
        std::span<const unsigned char> expected_scalar_key) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::PrepStaticInstalled ||
        prep_scalar_key_before.empty() || prep_scalar_key_after.empty() ||
        expected_scalar_key.empty() ||
        !same_bytes(
            prep_scalar_key_before, state->current_prep_scalar_key) ||
        !same_bytes(prep_scalar_key_after, expected_scalar_key)) {
        state->unavailable_noexcept();
        return false;
    }
    if (!state->emit(
            MascotSecretEventKind::PrepStaticInstalled,
            not_attempted_file(), {}, false, {}, false, {}, {}, {}, {}, {},
            false, prep_scalar_key_before, prep_scalar_key_after,
            expected_scalar_key))
        return false;
    replace_secret(state->current_prep_scalar_key, prep_scalar_key_after);
    state->next =
        MascotSecretStateHookScope::Storage::Next::PrepMacFileWrite;
    return true;
}

bool MascotSecretStateSourceBridge::prep_mac_file_write(
        std::string_view diagnostic_path, MascotStepResult result,
        const MascotFileSnapshotView& file,
        std::span<const unsigned char> exact_candidate,
        std::string_view failure_reason) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    const bool candidate_prefix =
        file.exact_file_bytes.size() <= exact_candidate.size() &&
        std::equal(
            file.exact_file_bytes.begin(), file.exact_file_bytes.end(),
            exact_candidate.begin());
    const bool exact_match =
        file.exact_file_bytes.size() == exact_candidate.size() &&
        candidate_prefix;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::PrepMacFileWrite ||
        !valid_text(diagnostic_path) || exact_candidate.empty() ||
        result == MascotStepResult::NotAttempted || !candidate_prefix ||
        (result == MascotStepResult::Succeeded &&
         (file.result != MascotFileResult::Captured || !exact_match ||
          !failure_reason.empty())) ||
        (result == MascotStepResult::Failed && failure_reason.empty())) {
        state->unavailable_noexcept();
        return false;
    }
    state->prep_mac_write = result;
    const bool retained = state->emit(
        MascotSecretEventKind::PrepMacFileWrite, file, failure_reason,
        false, {}, false, {}, {}, {}, exact_candidate, {}, false, {}, {}, {},
        diagnostic_path);
    if (!retained) return false;
    if (result == MascotStepResult::Failed) {
        state->unavailable_noexcept();
        return true;
    }
    state->next = MascotSecretStateHookScope::Storage::Next::BitPrepDerived;
    return true;
}

bool MascotSecretStateSourceBridge::bit_prep_derived(
        std::span<const unsigned char> complete_key_before,
        std::span<const unsigned char> complete_key_after,
        std::span<const unsigned char> derived_complete_key,
        bool bit_prep_aliases_main) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::BitPrepDerived ||
        complete_key_before.empty() || complete_key_after.empty() ||
        derived_complete_key.empty() || !bit_prep_aliases_main ||
        !same_bytes(complete_key_before, state->current_complete_key) ||
        !same_bytes(complete_key_after, derived_complete_key)) {
        state->unavailable_noexcept();
        return false;
    }
    if (!state->emit(
            MascotSecretEventKind::BitPrepDerived, not_attempted_file(), {},
            true, complete_key_before, true, complete_key_after, {}, {}, {},
            derived_complete_key, true))
        return false;
    replace_secret(state->current_complete_key, complete_key_after);
    state->next =
        MascotSecretStateHookScope::Storage::Next::StaticInstalled;
    return true;
}

bool MascotSecretStateSourceBridge::static_installed(
        bool complete_key_initialized,
        std::span<const unsigned char> complete_key,
        std::span<const unsigned char> scalar_key_before,
        std::span<const unsigned char> scalar_key_after,
        std::span<const unsigned char> expected_scalar_key) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->next !=
            MascotSecretStateHookScope::Storage::Next::StaticInstalled ||
        !complete_key_initialized || complete_key.empty() ||
        scalar_key_before.empty() || scalar_key_after.empty() ||
        expected_scalar_key.empty() ||
        !same_bytes(complete_key, state->current_complete_key) ||
        !same_bytes(scalar_key_before, state->current_online_scalar_key) ||
        !same_bytes(scalar_key_after, expected_scalar_key) ||
        !same_bytes(expected_scalar_key, state->current_prep_scalar_key)) {
        state->unavailable_noexcept();
        return false;
    }
    if (!state->emit(
            MascotSecretEventKind::StaticInstalled, not_attempted_file(), {},
            false, {}, true, complete_key, scalar_key_before,
            scalar_key_after, {}, {}, false, {}, {}, expected_scalar_key))
        return false;
    replace_secret(state->installed_scalar_key, scalar_key_after);
    replace_secret(state->current_online_scalar_key, scalar_key_after);
    state->next = MascotSecretStateHookScope::Storage::Next::Teardown;
    return true;
}

bool MascotSecretStateSourceBridge::teardown(
        bool complete_key_before_initialized,
        std::span<const unsigned char> complete_key_before,
        std::span<const unsigned char> scalar_key_before,
        bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after,
        std::span<const unsigned char> scalar_key_after,
        std::span<const unsigned char> prep_scalar_key_before,
        std::span<const unsigned char> prep_scalar_key_after) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return false;
    if (state->aborting &&
        state->next == MascotSecretStateHookScope::Storage::Next::Abort) {
        const bool valid =
            !state->abort_teardown_seen &&
            complete_key_before_initialized &&
            !complete_key_after_initialized &&
            !complete_key_before.empty() && !complete_key_after.empty() &&
            !scalar_key_before.empty() && !scalar_key_after.empty() &&
            !prep_scalar_key_before.empty() &&
            !prep_scalar_key_after.empty() &&
            same_bytes(complete_key_before, state->current_complete_key) &&
            same_bytes(scalar_key_before, state->installed_scalar_key) &&
            same_bytes(scalar_key_before, state->current_online_scalar_key) &&
            same_bytes(
                prep_scalar_key_before, state->current_prep_scalar_key) &&
            same_bytes(scalar_key_before, prep_scalar_key_before) &&
            same_bytes(scalar_key_before, scalar_key_after) &&
            same_bytes(prep_scalar_key_before, prep_scalar_key_after);
        if (!valid || !state->emit_abort(
                MascotSecretAbortEventKind::Teardown, false, nullptr,
                MascotWorkerExceptionKind::NotApplicable, false,
                false, false, 0, {}, {}, true,
                true, complete_key_before, false, complete_key_after,
                scalar_key_before, scalar_key_after,
                prep_scalar_key_before, prep_scalar_key_after)) {
            state->unavailable_noexcept();
            return false;
        }
        state->abort_teardown_seen = true;
        cleanse(state->write_candidate);
        cleanse(state->current_complete_key);
        cleanse(state->installed_scalar_key);
        cleanse(state->current_prep_scalar_key);
        cleanse(state->current_online_scalar_key);
        return true;
    }
    if (state->next != MascotSecretStateHookScope::Storage::Next::Teardown ||
        !complete_key_before_initialized || complete_key_after_initialized ||
        complete_key_before.empty() || complete_key_after.empty() ||
        scalar_key_before.empty() || scalar_key_after.empty() ||
        prep_scalar_key_before.empty() || prep_scalar_key_after.empty() ||
        !same_bytes(
            complete_key_before, state->current_complete_key) ||
        !same_bytes(
            scalar_key_before, state->installed_scalar_key) ||
        !same_bytes(
            scalar_key_before, state->current_online_scalar_key) ||
        !same_bytes(
            prep_scalar_key_before, state->current_prep_scalar_key) ||
        !same_bytes(scalar_key_before, prep_scalar_key_before) ||
        scalar_key_before.size() != scalar_key_after.size() ||
        !std::equal(
            scalar_key_before.begin(), scalar_key_before.end(),
            scalar_key_after.begin()) ||
        !same_bytes(prep_scalar_key_before, prep_scalar_key_after)) {
        state->unavailable_noexcept();
        return false;
    }
    if (!state->emit(
            MascotSecretEventKind::Teardown, not_attempted_file(), {},
            true, complete_key_before, false, complete_key_after,
            scalar_key_before, scalar_key_after, {}, {}, false,
            prep_scalar_key_before, prep_scalar_key_after))
        return false;
    state->next = MascotSecretStateHookScope::Storage::Next::Terminal;
    cleanse(state->write_candidate);
    cleanse(state->current_complete_key);
    cleanse(state->installed_scalar_key);
    cleanse(state->current_prep_scalar_key);
    cleanse(state->current_online_scalar_key);
    return true;
}

std::uint64_t MascotSecretStateSourceBridge::register_ot_worker_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_ordinal,
        std::uint64_t registered_worker_count) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return 0;
    try {
        if (state->next !=
                MascotSecretStateHookScope::Storage::Next::Teardown ||
            state->aborting || source_worker_identity == nullptr ||
            registered_worker_count != state->player_count - 1 ||
            source_worker_ordinal >= registered_worker_count ||
            state->find_worker(source_worker_identity) != nullptr ||
            std::any_of(
                state->workers.begin(), state->workers.end(),
                [source_worker_ordinal](const auto& worker) {
                    return worker.ordinal == source_worker_ordinal;
                }) ||
            (state->registered_worker_count != 0 &&
             state->registered_worker_count != registered_worker_count) ||
            state->next_worker_epoch == 0) {
            state->unavailable_noexcept();
            return 0;
        }
        const auto epoch = state->next_worker_epoch++;
        state->registered_worker_count = registered_worker_count;
        state->workers.push_back({
            .source_identity = source_worker_identity,
            .epoch = epoch,
            .ordinal = source_worker_ordinal,
            .thread = {},
            .started = false,
            .failure_published = false,
            .terminal = false,
            .root_observed = false,
            .joined = false,
        });
        return epoch;
    } catch (...) {
        state->unavailable_noexcept();
        return 0;
    }
}

bool MascotSecretStateSourceBridge::ot_worker_started_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch,
        std::uint64_t source_worker_ordinal) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state = MascotSecretStateHookScope::Storage::active;
    if (state == nullptr || source_worker_identity == nullptr ||
        MascotSecretStateHookScope::Storage::worker_local != nullptr ||
        std::this_thread::get_id() == state->owner_thread)
        return false;
    auto* worker = state->find_worker(source_worker_identity);
    if (worker == nullptr || worker->epoch != source_worker_epoch ||
        worker->ordinal != source_worker_ordinal || worker->started ||
        worker->terminal) {
        state->unavailable_noexcept();
        return false;
    }
    worker->started = true;
    worker->thread = std::this_thread::get_id();
    MascotSecretStateHookScope::Storage::worker_local = state;
    MascotSecretStateHookScope::Storage::worker_source_identity =
        source_worker_identity;
    return true;
}

void MascotSecretStateSourceBridge::ot_worker_failure_published_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch,
        MascotWorkerExceptionKind exception_kind) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state = MascotSecretStateHookScope::Storage::active;
    if (state == nullptr ||
        MascotSecretStateHookScope::Storage::worker_local != state ||
        MascotSecretStateHookScope::Storage::worker_source_identity !=
            source_worker_identity) {
        if (state != nullptr) state->unavailable_noexcept();
        return;
    }
    auto* worker = state->find_worker(source_worker_identity);
    if (worker == nullptr || worker->epoch != source_worker_epoch ||
        worker->thread != std::this_thread::get_id() ||
        worker->failure_published || worker->terminal || !state->aborting ||
        state->abort_class != MascotSecretAbortClass::OtMultiplierFailure ||
        !state->abort_unlink_seen ||
        exception_kind == MascotWorkerExceptionKind::NotApplicable) {
        state->unavailable_noexcept();
        return;
    }
    worker->failure_published = true;
    if (!state->emit_abort(
            MascotSecretAbortEventKind::WorkerFailurePublished, true,
            worker, exception_kind, true))
        state->unavailable_noexcept();
}

void MascotSecretStateSourceBridge::ot_worker_terminal_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch, bool failed) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state = MascotSecretStateHookScope::Storage::active;
    if (state == nullptr ||
        MascotSecretStateHookScope::Storage::worker_local != state ||
        MascotSecretStateHookScope::Storage::worker_source_identity !=
            source_worker_identity) {
        if (state != nullptr) state->unavailable_noexcept();
        return;
    }
    auto* worker = state->find_worker(source_worker_identity);
    if (worker == nullptr || worker->epoch != source_worker_epoch ||
        worker->thread != std::this_thread::get_id() || worker->terminal ||
        (failed != worker->failure_published)) {
        state->unavailable_noexcept();
    } else {
        worker->terminal = true;
        if (state->aborting && !state->emit_abort(
                MascotSecretAbortEventKind::WorkerTerminal, true,
                worker, MascotWorkerExceptionKind::NotApplicable, failed))
            state->unavailable_noexcept();
    }
    MascotSecretStateHookScope::Storage::worker_local = nullptr;
    MascotSecretStateHookScope::Storage::worker_source_identity = nullptr;
}

void MascotSecretStateSourceBridge::root_worker_failure_observed_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return;
    auto* worker = state->find_worker(source_worker_identity);
    if (worker == nullptr || worker->epoch != source_worker_epoch ||
        !worker->failure_published || !worker->terminal ||
        worker->root_observed || !state->aborting ||
        state->abort_class != MascotSecretAbortClass::OtMultiplierFailure) {
        state->unavailable_noexcept();
        return;
    }
    worker->root_observed = true;
    if (!state->emit_abort(
            MascotSecretAbortEventKind::RootFailureObserved, false,
            worker, MascotWorkerExceptionKind::NotApplicable, true))
        state->unavailable_noexcept();
}

void MascotSecretStateSourceBridge::ot_worker_joined_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state =
        MascotSecretStateHookScope::Storage::current_locked_noexcept();
    if (state == nullptr) return;
    auto* worker = state->find_worker(source_worker_identity);
    if (worker == nullptr || worker->epoch != source_worker_epoch ||
        !worker->started || !worker->terminal || worker->joined ||
        (worker->failure_published && !worker->root_observed)) {
        state->unavailable_noexcept();
        return;
    }
    worker->joined = true;
    if (state->aborting && !state->emit_abort(
            MascotSecretAbortEventKind::WorkerJoined, false,
            worker, MascotWorkerExceptionKind::NotApplicable,
            worker->failure_published))
        state->unavailable_noexcept();
}

bool MascotSecretStateSourceBridge::abort_cache_unlink_noexcept(
        MascotSecretAbortClass abort_class,
        std::string_view diagnostic_path, bool succeeded,
        std::uint64_t operation_errno,
        const MascotFileMetadataView& path_lstat_before,
        const MascotFileMetadataView& path_lstat_after) noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    auto* state = MascotSecretStateHookScope::Storage::active;
    if (state == nullptr) return false;
    const bool from_worker =
        abort_class == MascotSecretAbortClass::OtMultiplierFailure;
    MascotSecretStateHookScope::Storage::Worker* worker = nullptr;
    if (from_worker) {
        if (MascotSecretStateHookScope::Storage::worker_local != state)
            goto invalid;
        worker = state->find_worker(
            MascotSecretStateHookScope::Storage::worker_source_identity);
        if (worker == nullptr || !worker->started || worker->terminal)
            goto invalid;
    } else if (MascotSecretStateHookScope::Storage::local != state ||
               state->owner_thread != std::this_thread::get_id()) {
        goto invalid;
    }
    if ((state->next != MascotSecretStateHookScope::Storage::Next::Teardown &&
         state->next != MascotSecretStateHookScope::Storage::Next::Abort) ||
        state->branch == MascotCacheBranch::Undecided ||
        diagnostic_path != state->diagnostic_path ||
        state->abort_unlink_seen ||
        (state->aborting && state->abort_class != abort_class))
        goto invalid;
    state->aborting = true;
    state->abort_class = abort_class;
    state->next = MascotSecretStateHookScope::Storage::Next::Abort;
    if (!state->emit_abort(
            MascotSecretAbortEventKind::CacheUnlink, from_worker, worker,
            MascotWorkerExceptionKind::NotApplicable, false,
            true, succeeded, operation_errno,
            path_lstat_before, path_lstat_after))
        goto invalid;
    state->abort_unlink_seen = true;
    return true;

invalid:
    state->unavailable_noexcept();
    return false;
}

void MascotSecretStateSourceBridge::unavailable_noexcept() noexcept {
    std::lock_guard lock(MascotSecretStateHookScope::Storage::mutex);
    if (auto* state =
            MascotSecretStateHookScope::Storage::current_locked_noexcept())
        state->unavailable_noexcept();
}

} // namespace kpi::mpc::p1_private_state
