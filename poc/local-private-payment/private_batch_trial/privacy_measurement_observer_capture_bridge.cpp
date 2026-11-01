#include "privacy_measurement_observer_capture_bridge.hpp"

#include "c1_contact_value_authority.hpp"
#include "privacy_capture_producer_archive.hpp"
#include "privacy_capture_producer_supervisor.hpp"
#include "privacy_measurement_authority.hpp"
#include "privacy_measurement_observer_admission_storage.hpp"
#include "privacy_measurement_observer_spool_capsule_schema.hpp"
#include "privacy_measurement_run_binding_wire.hpp"
#include "privacy_measurement_sha256.hpp"
#include "privacy_measurement_structural_continuity_section_schema.hpp"
#include "privacy_measurement_worker_capsule.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <optional>
#include <openssl/evp.h>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::runtime_bridge {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

struct SecretDigest final {
    Digest value{};
    SecretDigest() = default;
    SecretDigest(const SecretDigest&) = delete;
    SecretDigest& operator=(const SecretDigest&) = delete;
    SecretDigest(SecretDigest&& other) noexcept : value(other.value) {
        volatile unsigned char* bytes = other.value.data();
        for (std::size_t index = 0; index < other.value.size(); ++index)
            bytes[index] = 0;
    }
    ~SecretDigest() {
        volatile unsigned char* bytes = value.data();
        for (std::size_t index = 0; index < value.size(); ++index)
            bytes[index] = 0;
    }
};

#ifdef KPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP
std::atomic_uint entropy_fault{0};
#endif

SecretDigest random_secret() {
    SecretDigest result;
#ifdef KPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP
    if (entropy_fault.load() == 1) refuse();
    if (entropy_fault.load() == 2) {
        result.value.fill(0xa5);
        result.value.back() = 0;
        refuse();
    }
#endif
    ssize_t count;
    do {
        count = ::getrandom(
            result.value.data(), result.value.size(), 0);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(result.value.size()));
    need(nonzero(result.value));
    return result;
}

void add(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

Digest observer_endpoint_identity(
        const Digest& snapshot_hash, std::uint64_t snapshot_size,
        const PublicObserverPermit& permit, const Digest& nonce) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_OBSERVER_FD40_ENDPOINT_V2\n");
    add(bytes, nonce);
    add(bytes, snapshot_hash);
    add(bytes, snapshot_size);
    add(bytes, permit.trial_capture_identity);
    add(bytes, permit.permit_identity);
    add(bytes, permit.binding.comparison_selection);
    add(bytes, permit.binding.run_selection);
    add(bytes, permit.binding.trial);
    add(bytes, permit.binding.capture);
    add(bytes, permit.binding.finite_manifest.manifest_identity);
    add(bytes,
        permit.binding.finite_manifest.parent_recomputation_identity);
    return detail::sha256(bytes);
}

Digest observer_snapshot_session(
        const Digest& snapshot_hash, const PublicObserverPermit& permit,
        const Digest& nonce) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_OBSERVER_FD40_PARENT_SESSION_V1\n");
    add(bytes, nonce);
    add(bytes, snapshot_hash);
    add(bytes, permit.permit_identity);
    add(bytes, permit.binding.outer_parent_process);
    return detail::sha256(bytes);
}

Digest observer_snapshot_completion(
        const Digest& closure_identity,
        const Digest& producer_process_identity,
        const ProducerClosureEvidence& evidence,
        const Digest& session) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_OBSERVER_FD40_PARENT_COMPLETION_V1\n");
    add(bytes, session);
    add(bytes, closure_identity);
    add(bytes, producer_process_identity);
    add(bytes, evidence.producer_child_exit);
    add(bytes, evidence.producer_receipt);
    add(bytes, evidence.producer_identity);
    return detail::sha256(bytes);
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

void write_all(int fd, std::span<const unsigned char> bytes) {
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::write(
            fd, bytes.data() + at, bytes.size() - at);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

void write_integer(int fd, std::uint64_t value, unsigned width = 8) {
    std::array<unsigned char, 8> bytes{};
    need(width <= bytes.size());
    for (unsigned index = 0; index < width; ++index)
        bytes[index] = static_cast<unsigned char>(value >> (8 * index));
    write_all(fd, std::span(bytes).first(width));
}

void write_digest(int fd, const Digest& value) {
    write_all(fd, value);
}

void write_worker(int fd, const WorkerBinding& value) {
    for (const auto* digest : {
             &value.source_identity, &value.build_identity,
             &value.runtime_identity, &value.assets_identity,
             &value.pinned_executable_identity,
             &value.launcher_identity})
        write_digest(fd, *digest);
}

void write_binding(int fd, const RunBinding& value) {
    const auto bytes = wire::canonical_run_binding_bytes(value);
    write_all(fd, bytes);
}

constexpr int REQUIRED_SEALS =
    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

Digest hash_fd(int fd, std::uint64_t size) {
    struct Deleter {
        void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); }
    };
    std::unique_ptr<EVP_MD_CTX, Deleter> context(EVP_MD_CTX_new());
    need(context != nullptr &&
         EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1);
    std::array<unsigned char, 1U << 16> buffer{};
    std::uint64_t at = 0;
    while (at < size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - at));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), wanted,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0 && EVP_DigestUpdate(
            context.get(), buffer.data(),
            static_cast<std::size_t>(count)) == 1);
        at += static_cast<std::uint64_t>(count);
    }
    Digest result{};
    unsigned length = 0;
    need(EVP_DigestFinal_ex(context.get(), result.data(), &length) == 1 &&
         length == result.size() && nonzero(result));
    return result;
}

int read_only_sealed_memfd(int& writable) {
    need(::fchmod(writable, 0400) == 0 &&
         ::fcntl(writable, F_ADD_SEALS, REQUIRED_SEALS) == 0 &&
         (::fcntl(writable, F_GET_SEALS) & REQUIRED_SEALS) ==
             REQUIRED_SEALS);
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", writable);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    need(result >= 0 &&
         (::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(result, F_GET_SEALS) & REQUIRED_SEALS) ==
             REQUIRED_SEALS);
    close_fd(writable);
    return result;
}

} // namespace

ObserverAdmissionAuthority ObserverCaptureCapsuleBridge::admit(
        producer_archive::ProducerSealedArchiveAuthority&& supplied_archive,
        producer_supervisor::C03RoleLaunchAdmissionAuthority&& supplied_c03,
        c1_capture::C1PostcaptureAdmissionAuthority&& supplied_c1_round1,
        c1_capture::C1PostcaptureAdmissionAuthority&& supplied_c1_round2) {
    producer_supervisor::C03RoleLaunchAdmissionAuthority c03(
        std::move(supplied_c03));
    c1_capture::C1PostcaptureAdmissionAuthority c1_round1(
        std::move(supplied_c1_round1));
    c1_capture::C1PostcaptureAdmissionAuthority c1_round2(
        std::move(supplied_c1_round2));
    try {
        const bool c03_live = c03.live_.exchange(false);
        const bool c1_round1_live = c1_round1.live_.exchange(false);
        const bool c1_round2_live = c1_round2.live_.exchange(false);
        auto archive = std::move(supplied_archive).consume_for_observer();
        need(c03_live && c1_round1_live && c1_round2_live &&
             archive.binding_ == c03.binding_ &&
             archive.closure_identity_ ==
                 c03.opaque_closure_authority_identity_ &&
             c1_round1.binding_ == archive.binding_ &&
             c1_round2.binding_ == archive.binding_ &&
             c1_round1.round_ == 1 && c1_round2.round_ == 2 &&
             c1_round1.fixed_capture_fd_ == 24 &&
             c1_round2.fixed_capture_fd_ == 29 &&
             c1_round1.c1_worker_ == c1_round2.c1_worker_);

        const auto c1_index =
            static_cast<unsigned>(ManifestComponent::C1Supervisor) - 1;
        need(c1_index < archive.binding_.finite_manifest.entries.size());
        const auto& c1_manifest =
            archive.binding_.finite_manifest.entries[c1_index];
        const WorkerBinding expected_c1{
            .source_identity = c1_manifest.source_identity,
            .build_identity = c1_manifest.build_identity,
            .runtime_identity = c1_manifest.runtime_identity,
            .assets_identity = c1_manifest.assets_identity,
            .pinned_executable_identity =
                c1_manifest.pinned_executable_identity,
            .launcher_identity = c1_manifest.launcher_identity,
        };
        need(c1_manifest.component == ManifestComponent::C1Supervisor &&
             c1_round1.c1_worker_ == expected_c1 &&
             c1_round1.contact_value_authority_identity_ !=
                 c1_round2.contact_value_authority_identity_ &&
             c1_round1.role_launch_identity_ ==
                 archive.binding_.source_closure &&
             c1_round2.role_launch_identity_ ==
                 archive.binding_.source_closure &&
             c1_round1.route_manifest_identity_ !=
                 c1_round2.route_manifest_identity_ &&
             c1_round1.route_source_identity_ !=
                 c1_round2.route_source_identity_ &&
             c1_round1.stage_plan_identity_ !=
                 c1_round2.stage_plan_identity_ &&
             c1_round1.process_identity_ != c1_round2.process_identity_ &&
             c1_round1.expected_child_exit_identity_ !=
                 c1_round2.expected_child_exit_identity_);

        auto storage = std::make_unique<ObserverAdmissionAuthority::Storage>();
        storage->binding = archive.binding_;
        storage->opaque_closure_authority_identity =
            archive.closure_identity_;
        storage->producer_process_identity = c03.producer_process_identity_;
        storage->sealed_archive = true;
        storage->archive_devices = archive.devices_;
        storage->archive_inodes = archive.inodes_;
        storage->archive_sizes = archive.sizes_;
        storage->archive_stream_evidence = archive.evidence_;
        for (unsigned slot = 0; slot < storage->archive_fds.size(); ++slot)
            storage->archive_fds[slot] =
                std::exchange(archive.fds_[slot], -1);
        storage->c03_producer_child_exit =
            c03.producer_child_exit_identity_;
        storage->c03_producer_receipt = c03.producer_receipt_identity_;
        for (unsigned index = 0; index < storage->c03_rounds.size();
             ++index) {
            const auto& input = c03.rounds_[index];
            storage->c03_rounds[index] = {
                .round = input.round,
                .fixed_fd = input.fixed_fd,
                .financial_run = input.financial_run,
                .attempt = input.attempt,
                .cohort = input.cohort,
                .capture_plan = input.capture_plan,
                .projection = input.projection,
                .source_identity = input.source_identity,
                .build_identity = input.build_identity,
                .runtime_identity = input.runtime_identity,
                .launcher_identity = input.launcher_identity,
                .process_identity = input.process_identity,
                .child_exit_identity = input.child_exit_identity,
                .model_preimage_identity = input.model_preimage_identity,
                .query_store_preimage_identity =
                    input.query_store_preimage_identity,
                .scalar_capture_manifest_identity =
                    input.scalar_capture_manifest_identity,
            };
        }
        const std::array<
            const c1_capture::C1PostcaptureAdmissionAuthority*, 2>
            c1_inputs{&c1_round1, &c1_round2};
        for (unsigned index = 0; index < storage->c1_rounds.size();
             ++index) {
            const auto& input = *c1_inputs[index];
            storage->c1_rounds[index] = {
                .round = input.round_,
                .fixed_capture_fd = input.fixed_capture_fd_,
                .contact_value_authority_identity =
                    input.contact_value_authority_identity_,
                .role_launch_identity = input.role_launch_identity_,
                .route_manifest_identity = input.route_manifest_identity_,
                .route_source_identity = input.route_source_identity_,
                .stage_plan_identity = input.stage_plan_identity_,
                .process_identity = input.process_identity_,
                .expected_child_exit_identity =
                    input.expected_child_exit_identity_,
                .worker = input.c1_worker_,
                .contact_owner_components =
                    input.contact_owner_components_,
                .operation_identities = input.operation_identities_,
            };
        }
        return ObserverAdmissionAuthority(std::move(storage));
    } catch (...) {
        refuse();
    }
}

#ifdef KPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP
ObserverAdmissionAuthority ObserverCaptureCapsuleBridge::admit(
        producer_supervisor::ProducerSpoolAuthority&& supplied_spool,
        producer_supervisor::C03RoleLaunchAdmissionAuthority&&
            supplied_c03,
        c1_capture::C1PostcaptureAdmissionAuthority&& supplied_c1_round1,
        c1_capture::C1PostcaptureAdmissionAuthority&& supplied_c1_round2) {
    using producer_supervisor::ProducerSpoolAuthority;
    using producer_supervisor::C03RoleLaunchAdmissionAuthority;
    ProducerSpoolAuthority spool(std::move(supplied_spool));
    C03RoleLaunchAdmissionAuthority c03(std::move(supplied_c03));
    c1_capture::C1PostcaptureAdmissionAuthority c1_round1(
        std::move(supplied_c1_round1));
    c1_capture::C1PostcaptureAdmissionAuthority c1_round2(
        std::move(supplied_c1_round2));
    try {
        need(spool.live_.exchange(false) && c03.live_.exchange(false) &&
             c1_round1.live_.exchange(false) &&
             c1_round2.live_.exchange(false) &&
             spool.directory_fd_ >= 0 &&
             spool.binding_ == c03.binding_ &&
             spool.opaque_closure_authority_identity_ ==
                 c03.opaque_closure_authority_identity_ &&
             spool.producer_process_identity_ ==
                 c03.producer_process_identity_ &&
             spool.producer_closure_evidence_.producer_child_exit ==
                 c03.producer_child_exit_identity_ &&
             spool.producer_closure_evidence_.producer_receipt ==
                 c03.producer_receipt_identity_ &&
             c1_round1.binding_ == spool.binding_ &&
             c1_round2.binding_ == spool.binding_ &&
             c1_round1.round_ == 1 && c1_round2.round_ == 2 &&
             c1_round1.fixed_capture_fd_ == 24 &&
             c1_round2.fixed_capture_fd_ == 29 &&
             c1_round1.c1_worker_ == c1_round2.c1_worker_);
        const auto c1_index =
            static_cast<unsigned>(ManifestComponent::C1Supervisor) - 1;
        need(c1_index < spool.binding_.finite_manifest.entries.size());
        const auto& c1_manifest =
            spool.binding_.finite_manifest.entries[c1_index];
        const WorkerBinding expected_c1{
            .source_identity = c1_manifest.source_identity,
            .build_identity = c1_manifest.build_identity,
            .runtime_identity = c1_manifest.runtime_identity,
            .assets_identity = c1_manifest.assets_identity,
            .pinned_executable_identity =
                c1_manifest.pinned_executable_identity,
            .launcher_identity = c1_manifest.launcher_identity,
        };
        need(c1_manifest.component == ManifestComponent::C1Supervisor &&
             c1_round1.c1_worker_ == expected_c1 &&
             c1_round1.contact_value_authority_identity_ !=
                 c1_round2.contact_value_authority_identity_ &&
             c1_round1.role_launch_identity_ ==
                 spool.binding_.source_closure &&
             c1_round2.role_launch_identity_ ==
                 spool.binding_.source_closure &&
             c1_round1.route_manifest_identity_ !=
                 c1_round2.route_manifest_identity_ &&
             c1_round1.route_source_identity_ !=
                 c1_round2.route_source_identity_ &&
             c1_round1.stage_plan_identity_ !=
                 c1_round2.stage_plan_identity_ &&
             c1_round1.process_identity_ != c1_round2.process_identity_ &&
             c1_round1.expected_child_exit_identity_ !=
                 c1_round2.expected_child_exit_identity_);
        auto storage = std::make_unique<ObserverAdmissionAuthority::Storage>();
        storage->binding = spool.binding_;
        storage->opaque_closure_authority_identity =
            spool.opaque_closure_authority_identity_;
        storage->spool_identity = spool.spool_identity_;
        storage->producer_process_identity =
            spool.producer_process_identity_;
        storage->writer_alias_closure_identity =
            spool.writer_alias_closure_identity_;
        storage->path_alias_closure_identity =
            spool.path_alias_closure_identity_;
        storage->producer_closure_evidence =
            spool.producer_closure_evidence_;
        for (unsigned index = 0; index < storage->leaves.size(); ++index) {
            const auto& input = spool.leaves_[index];
            storage->leaves[index] = {
                .round = input.round,
                .kind = input.kind,
                .fixed_fd = input.fixed_fd,
                .device = input.device,
                .inode = input.inode,
                .size = input.size,
                .mode = input.mode,
                .uid = input.uid,
                .link_count = input.link_count,
            };
        }
        const auto& producer = spool.producer_receipt_leaf_;
        storage->producer_receipt_leaf = {
            .round = producer.round,
            .kind = producer.kind,
            .fixed_fd = producer.fixed_fd,
            .device = producer.device,
            .inode = producer.inode,
            .size = producer.size,
            .mode = producer.mode,
            .uid = producer.uid,
            .link_count = producer.link_count,
        };
        storage->root_device = spool.device_;
        storage->root_inode = spool.inode_;
        storage->directory_fd = std::exchange(spool.directory_fd_, -1);
        storage->c03_producer_child_exit =
            c03.producer_child_exit_identity_;
        storage->c03_producer_receipt = c03.producer_receipt_identity_;
        for (unsigned index = 0; index < storage->c03_rounds.size();
             ++index) {
            const auto& input = c03.rounds_[index];
            storage->c03_rounds[index] = {
                .round = input.round,
                .fixed_fd = input.fixed_fd,
                .financial_run = input.financial_run,
                .attempt = input.attempt,
                .cohort = input.cohort,
                .capture_plan = input.capture_plan,
                .projection = input.projection,
                .source_identity = input.source_identity,
                .build_identity = input.build_identity,
                .runtime_identity = input.runtime_identity,
                .launcher_identity = input.launcher_identity,
                .process_identity = input.process_identity,
                .child_exit_identity = input.child_exit_identity,
                .model_preimage_identity = input.model_preimage_identity,
                .query_store_preimage_identity =
                    input.query_store_preimage_identity,
                .scalar_capture_manifest_identity =
                    input.scalar_capture_manifest_identity,
            };
        }
        const std::array<
            const c1_capture::C1PostcaptureAdmissionAuthority*, 2>
            c1_inputs{&c1_round1, &c1_round2};
        for (unsigned index = 0; index < storage->c1_rounds.size();
             ++index) {
            const auto& input = *c1_inputs[index];
            storage->c1_rounds[index] = {
                .round = input.round_,
                .fixed_capture_fd = input.fixed_capture_fd_,
                .contact_value_authority_identity =
                    input.contact_value_authority_identity_,
                .role_launch_identity = input.role_launch_identity_,
                .route_manifest_identity = input.route_manifest_identity_,
                .route_source_identity = input.route_source_identity_,
                .stage_plan_identity = input.stage_plan_identity_,
                .process_identity = input.process_identity_,
                .expected_child_exit_identity =
                    input.expected_child_exit_identity_,
                .worker = input.c1_worker_,
                .contact_owner_components =
                    input.contact_owner_components_,
                .operation_identities = input.operation_identities_,
            };
        }
        need(nonzero(storage->spool_identity) &&
             nonzero(storage->writer_alias_closure_identity) &&
             nonzero(storage->path_alias_closure_identity));
        return ObserverAdmissionAuthority(std::move(storage));
    } catch (...) {
        refuse();
    }
}
#endif

int ObserverCaptureCapsuleBridge::snapshot_spool(
        ObserverAdmissionAuthority& authority,
        const PublicObserverPermit& permit) {
    using namespace observer_spool_schema;
    need(authority.storage_ != nullptr);
    auto& storage = *authority.storage_;
    need(!storage.test_only && storage.sealed_archive &&
         storage.directory_fd < 0 &&
         storage.structural_continuity_fd >= 0 &&
         storage.structural_continuity_size ==
             structural_continuity_section_schema::SECTION_BYTES &&
         nonzero(storage.structural_continuity_identity) &&
         storage.binding == permit.binding &&
         storage.matched_producer_closure.has_value() &&
         nonzero(permit.trial_capture_identity) &&
         nonzero(permit.permit_identity));
    const auto& closure = *storage.matched_producer_closure;
    int writable = ::memfd_create(
        "kpb-observer-raw-archive", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(writable >= 0);
    try {
        write_all(writable, MAGIC);
        write_integer(writable, VERSION, 4);
        write_digest(writable, permit.trial_capture_identity);
        write_digest(writable, permit.permit_identity);
        write_binding(writable, storage.binding);
        write_digest(writable, storage.opaque_closure_authority_identity);
        write_digest(writable, storage.producer_process_identity);
        write_worker(writable, closure.producer_worker);
        write_digest(writable, closure.role_closure_identity);
        write_digest(writable, closure.manifest_seal);
        write_integer(writable,
            static_cast<unsigned char>(closure.construction_policy), 1);
        write_digest(
            writable, closure.construction_classification_receipt);
        write_digest(
            writable, storage.producer_closure_evidence.producer_child_exit);
        write_digest(
            writable, storage.producer_closure_evidence.producer_receipt);
        write_digest(
            writable, storage.producer_closure_evidence.producer_identity);
        write_integer(writable, closure.stream_count, 4);
        write_integer(writable, closure.closed_root_count, 4);
        write_integer(writable, closure.unknown_record_count, 4);
        for (const auto& round : storage.c03_rounds) {
            write_integer(writable, round.round, 1);
            write_integer(writable, round.fixed_fd, 1);
            for (const auto* digest : {
                     &round.financial_run, &round.attempt, &round.cohort,
                     &round.capture_plan, &round.projection,
                     &round.source_identity, &round.build_identity,
                     &round.runtime_identity, &round.launcher_identity,
                     &round.process_identity, &round.child_exit_identity,
                     &round.model_preimage_identity,
                     &round.query_store_preimage_identity,
                     &round.scalar_capture_manifest_identity})
                write_digest(writable, *digest);
        }
        for (const auto& round : storage.c1_rounds) {
            write_integer(writable, round.round, 1);
            write_integer(writable, round.fixed_capture_fd, 1);
            for (const auto* digest : {
                     &round.contact_value_authority_identity,
                     &round.role_launch_identity,
                     &round.route_manifest_identity,
                     &round.route_source_identity,
                     &round.stage_plan_identity,
                     &round.process_identity,
                     &round.expected_child_exit_identity})
                write_digest(writable, *digest);
            write_worker(writable, round.worker);
            for (const auto owner : round.contact_owner_components)
                write_integer(writable, owner, 1);
            for (const auto& digest : round.operation_identities)
                write_digest(writable, digest);
        }
        namespace structural = structural_continuity_section_schema;
        std::array<unsigned char, structural::HEADER_BYTES>
            structural_header{};
        need(::pread(storage.structural_continuity_fd,
                     structural_header.data(), structural_header.size(), 0) ==
                 static_cast<ssize_t>(structural_header.size()) &&
             std::equal(structural::MAGIC.begin(), structural::MAGIC.end(),
                        structural_header.begin()));
        const auto read_u32 = [&](std::size_t offset) {
            std::uint32_t value = 0;
            for (unsigned index = 0; index < 4; ++index)
                value |= static_cast<std::uint32_t>(
                    structural_header[offset + index]) << (8 * index);
            return value;
        };
        need(read_u32(8) == structural::VERSION &&
             read_u32(12) == structural::SECTION_BYTES &&
             structural_header[structural::FLAGS_OFFSET] ==
                 static_cast<unsigned char>(storage.binding.classification) &&
             structural_header[structural::FLAGS_OFFSET + 1] == 1 &&
             structural_header[structural::FLAGS_OFFSET + 2] == 0 &&
             structural_header[structural::FLAGS_OFFSET + 3] ==
                 structural::ROUND_COUNT &&
             std::equal(
                 storage.structural_continuity_identity.begin(),
                 storage.structural_continuity_identity.end(),
                 structural_header.begin() +
                     static_cast<std::ptrdiff_t>(
                         structural::IDENTITY_OFFSET)));
        struct stat structural_before{};
        need(::fstat(storage.structural_continuity_fd,
                     &structural_before) == 0 &&
             S_ISREG(structural_before.st_mode) &&
             static_cast<std::uint64_t>(structural_before.st_size) ==
                 structural::SECTION_BYTES &&
             (::fcntl(storage.structural_continuity_fd, F_GETFL) &
                 O_ACCMODE) == O_RDONLY &&
             (::fcntl(storage.structural_continuity_fd, F_GETFD) &
                 FD_CLOEXEC) != 0 &&
             (::fcntl(storage.structural_continuity_fd, F_GET_SEALS) &
                 REQUIRED_SEALS) == REQUIRED_SEALS);
        std::array<unsigned char, 65536> buffer{};
        std::uint64_t structural_at = 0;
        while (structural_at < structural::SECTION_BYTES) {
            const auto wanted = static_cast<std::size_t>(
                std::min<std::uint64_t>(
                    buffer.size(), structural::SECTION_BYTES -
                        structural_at));
            ssize_t count;
            do {
                count = ::pread(storage.structural_continuity_fd,
                                buffer.data(), wanted,
                                static_cast<off_t>(structural_at));
            } while (count < 0 && errno == EINTR);
            need(count > 0 &&
                 static_cast<std::size_t>(count) <= wanted);
            write_all(writable, std::span(
                buffer.data(), static_cast<std::size_t>(count)));
            structural_at += static_cast<std::uint64_t>(count);
        }
        struct stat structural_after{};
        need(::fstat(storage.structural_continuity_fd,
                     &structural_after) == 0 &&
             structural_before.st_dev == structural_after.st_dev &&
             structural_before.st_ino == structural_after.st_ino &&
             structural_before.st_size == structural_after.st_size &&
             (::fcntl(storage.structural_continuity_fd, F_GET_SEALS) &
                 REQUIRED_SEALS) == REQUIRED_SEALS);
        write_integer(writable, LEAF_COUNT, 1);
        for (unsigned index = 0; index < closure.streams.size(); ++index) {
            const auto& stream = closure.streams[index];
            const auto& evidence =
                storage.producer_closure_evidence.streams[index];
            const unsigned round = index / LEAVES_PER_ROUND + 1;
            const unsigned kind = index % LEAVES_PER_ROUND + 1;
            const int fd = storage.archive_fds[index];
            struct stat before{};
            need(stream.round == round &&
                 stream.kind == static_cast<CaptureKind>(kind) &&
                 stream.fixed_fd == 20 + index &&
                 evidence == storage.archive_stream_evidence[index] &&
                 fd >= 0 &&
                 (::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
                 (::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0 &&
                 ::fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
                 before.st_nlink == 0 &&
                 (before.st_mode & 0777) == 0600 &&
                 static_cast<std::uint64_t>(before.st_dev) ==
                     storage.archive_devices[index] &&
                 static_cast<std::uint64_t>(before.st_ino) ==
                     storage.archive_inodes[index] &&
                 static_cast<std::uint64_t>(before.st_size) ==
                     storage.archive_sizes[index] &&
                 storage.archive_sizes[index] == evidence.raw_wire_bytes &&
                 hash_fd(fd, evidence.raw_wire_bytes) ==
                     evidence.record_root);
            for (unsigned other = 0; other < index; ++other)
                need(storage.archive_devices[index] !=
                         storage.archive_devices[other] ||
                     storage.archive_inodes[index] !=
                         storage.archive_inodes[other]);
            write_integer(writable, round, 1);
            write_integer(writable, kind, 1);
            write_integer(writable, stream.fixed_fd, 1);
            write_integer(writable,
                static_cast<unsigned char>(stream.manifest_component), 1);
            write_digest(writable, stream.source_identity);
            write_digest(writable, stream.build_identity);
            write_digest(writable, stream.runtime_identity);
            write_digest(writable, stream.launcher_identity);
            write_digest(writable, stream.process_identity);
            write_digest(writable, stream.child_exit_identity);
            write_integer(writable, stream.root_closed ? 1 : 0, 1);
            write_integer(writable, stream.end_observed ? 1 : 0, 1);
            write_integer(writable, stream.eof_observed ? 1 : 0, 1);
            write_digest(writable, evidence.record_root);
            write_digest(writable, evidence.end_frame_identity);
            write_digest(writable, evidence.eof_identity);
            write_integer(writable, evidence.record_count);
            write_integer(writable, evidence.payload_bytes);
            write_integer(writable, evidence.raw_wire_bytes);
            std::uint64_t at = 0;
            while (at < evidence.raw_wire_bytes) {
                const auto wanted = static_cast<std::size_t>(
                    std::min<std::uint64_t>(
                        buffer.size(), evidence.raw_wire_bytes - at));
                ssize_t count;
                do {
                    count = ::pread(fd, buffer.data(), wanted,
                                    static_cast<off_t>(at));
                } while (count < 0 && errno == EINTR);
                need(count > 0 &&
                     static_cast<std::size_t>(count) <= wanted);
                write_all(writable, std::span(
                    buffer.data(), static_cast<std::size_t>(count)));
                at += static_cast<std::uint64_t>(count);
            }
            struct stat after{};
            need(::fstat(fd, &after) == 0 &&
                 before.st_dev == after.st_dev &&
                 before.st_ino == after.st_ino &&
                 before.st_size == after.st_size &&
                 before.st_mode == after.st_mode &&
                 before.st_nlink == after.st_nlink &&
                 hash_fd(fd, evidence.raw_wire_bytes) ==
                     evidence.record_root);
        }
        const int result = read_only_sealed_memfd(writable);
        for (auto& fd : storage.archive_fds) close_fd(fd);
        close_fd(storage.structural_continuity_fd);
        return result;
    } catch (...) {
        close_fd(writable);
        throw;
    }
}

#ifdef KPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP
int ObserverCaptureCapsuleBridge::test_only_snapshot_archive(
        ObserverAdmissionAuthority&& supplied,
        const PublicObserverPermit& permit) {
    ObserverAdmissionAuthority admission(std::move(supplied));
    return snapshot_spool(admission, permit);
}

int ObserverCaptureCapsuleBridge::test_only_prepare_archive(
        ObserverPermitAuthority&& supplied) {
    ObserverPermitAuthority permit(std::move(supplied));
    need(permit.live_.exchange(false) && permit.admission_.has_value());
    auto admission = std::move(*permit.admission_);
    permit.admission_.reset();
    return snapshot_spool(admission, permit.receipt_);
}

producer_supervisor::C03RoleLaunchAdmissionAuthority
ObserverCaptureCapsuleBridge::test_only_c03_for_producer(
        const ProducerClosureAuthority& producer,
        const std::array<producer_supervisor::C03RoleLaunchRoundBinding, 2>&
            rounds) {
    producer.validate_for_native_terminal_join();
    return producer_supervisor::C03RoleLaunchAdmissionAuthority(
        producer.receipt_.binding,
        producer.receipt_.opaque_closure_authority_identity,
        producer.receipt_.producer_process_identity,
        producer.evidence_.producer_child_exit,
        producer.evidence_.producer_receipt, rounds);
}

std::array<unsigned char, 32>
ObserverCaptureCapsuleBridge::test_only_endpoint_identity(
        const std::array<unsigned char, 32>& snapshot_hash,
        std::uint64_t snapshot_size, const PublicObserverPermit& permit,
        const std::array<unsigned char, 32>& nonce) {
    return observer_endpoint_identity(
        snapshot_hash, snapshot_size, permit, nonce);
}

void ObserverCaptureCapsuleBridge::test_only_force_entropy_failure(
        bool value) {
    entropy_fault.store(value ? 1U : 0U);
}

void ObserverCaptureCapsuleBridge::test_only_force_entropy_short_read(
        bool value) {
    entropy_fault.store(value ? 2U : 0U);
}

void ObserverCaptureCapsuleBridge::test_only_require_entropy() {
    (void)random_secret();
}
#endif

struct ObserverCaptureCapsuleHandoff::Storage {
    std::optional<ObserverExecutionPermitAuthority> execution;
    std::optional<MeasurementWorkerCapsuleAuthority> capsule;
};

ObserverCaptureCapsuleHandoff::ObserverCaptureCapsuleHandoff(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ObserverCaptureCapsuleHandoff::ObserverCaptureCapsuleHandoff(
        ObserverCaptureCapsuleHandoff&& other) noexcept
    : storage_(std::move(other.storage_)) {}

ObserverCaptureCapsuleHandoff::~ObserverCaptureCapsuleHandoff() = default;

ObserverExecutionPermitAuthority
ObserverCaptureCapsuleHandoff::take_execution_permit() {
    need(storage_ != nullptr && storage_->execution.has_value());
    ObserverExecutionPermitAuthority result(
        std::move(*storage_->execution));
    storage_->execution.reset();
    return result;
}

MeasurementWorkerCapsuleAuthority
ObserverCaptureCapsuleHandoff::take_worker_capsule() {
    need(storage_ != nullptr && storage_->capsule.has_value());
    MeasurementWorkerCapsuleAuthority result(std::move(*storage_->capsule));
    storage_->capsule.reset();
    return result;
}

ObserverCaptureCapsuleHandoff ObserverCaptureCapsuleBridge::prepare(
        ObserverPermitAuthority&& supplied, int runtime_fd,
        int canonical_source_fd, int canonical_assets_fd) {
    ObserverPermitAuthority permit(std::move(supplied));
    int snapshot_fd = -1;
    try {
        need(permit.live_.exchange(false) && permit.admission_.has_value());
        auto admission = std::move(*permit.admission_);
        permit.admission_.reset();
        need(admission.storage_ != nullptr &&
             admission.storage_->sealed_archive &&
             admission.storage_->matched_producer_closure.has_value() &&
             admission.storage_->terminal_v2_model_admission != nullptr &&
             admission.storage_->destroy_terminal_v2_model_admission !=
                 nullptr);
        snapshot_fd = snapshot_spool(admission, permit.receipt_);
        struct stat snapshot_status{};
        need(snapshot_fd >= 0 &&
             ::fstat(snapshot_fd, &snapshot_status) == 0 &&
             S_ISREG(snapshot_status.st_mode) && snapshot_status.st_size > 0 &&
             (::fcntl(snapshot_fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
             (::fcntl(snapshot_fd, F_GETFD) & FD_CLOEXEC) != 0 &&
             (::fcntl(snapshot_fd, F_GET_SEALS) & REQUIRED_SEALS) ==
                 REQUIRED_SEALS);
        const auto snapshot_size = static_cast<std::uint64_t>(
            snapshot_status.st_size);
        const auto snapshot_hash = hash_fd(snapshot_fd, snapshot_size);
        auto nonce = random_secret();
        const auto endpoint_identity = observer_endpoint_identity(
            snapshot_hash, snapshot_size, permit.receipt_, nonce.value);
        const auto snapshot_session = observer_snapshot_session(
            snapshot_hash, permit.receipt_, nonce.value);
        const auto snapshot_completion = observer_snapshot_completion(
            admission.storage_->opaque_closure_authority_identity,
            admission.storage_->producer_process_identity,
            admission.storage_->producer_closure_evidence,
            snapshot_session);
        need(nonzero(endpoint_identity) && nonzero(snapshot_session) &&
             nonzero(snapshot_completion) &&
             endpoint_identity != snapshot_hash);
        PublicMeasurementInputEndpoint::PublicLineage lineage{
            .classification = permit.receipt_.binding.classification,
            .trial = permit.receipt_.binding.trial,
            .barrier = {},
            .capture_plan_identities =
                permit.receipt_.binding.round_capture_plans,
            .financial_runs = permit.receipt_.binding.financial_runs,
            .round_attempts = permit.receipt_.binding.round_attempts,
            .round_cohorts = permit.receipt_.binding.round_cohorts,
            .projections = permit.receipt_.binding.projections,
        };
        std::vector<MeasurementInputEndpointAuthority> inputs;
        MeasurementInputEndpointAuthority endpoint(
            MeasurementInputKind::ObserverCapture, NO_OWNER, snapshot_fd,
            endpoint_identity, lineage, static_cast<std::int64_t>(::getpid()),
            snapshot_session, snapshot_completion);
        inputs.push_back(std::move(endpoint));
        close_fd(snapshot_fd);
        auto capsule = MeasurementWorkerCapsuleAuthority::seal_native(
            RuntimeChildRole::Observer, NO_OWNER, runtime_fd,
            canonical_source_fd, canonical_assets_fd, std::move(inputs));
        const auto& capsule_receipt = capsule.public_receipt();
        need(capsule_receipt.worker ==
                 permit.receipt_.binding.observer_worker &&
             capsule_receipt.role == RuntimeChildRole::Observer &&
             capsule_receipt.owner == NO_OWNER &&
             capsule_receipt.input_count == 1 &&
             capsule_receipt.inputs[0].kind ==
                 MeasurementInputKind::ObserverCapture &&
             capsule_receipt.inputs[0].identity == endpoint_identity &&
             capsule_receipt.inputs[0].lineage == lineage);
        ObserverExecutionPermitAuthority execution(permit.receipt_);
        auto result = std::make_unique<ObserverCaptureCapsuleHandoff::Storage>();
        result->execution.emplace(std::move(execution));
        result->capsule.emplace(std::move(capsule));
        return ObserverCaptureCapsuleHandoff(std::move(result));
    } catch (...) {
        close_fd(snapshot_fd);
        refuse();
    }
}

} // namespace kpb::measurement::runtime_bridge
