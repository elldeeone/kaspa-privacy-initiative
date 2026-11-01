#include "privacy_observation_barrier_fanout_authority.hpp"

#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_measurement_output_abi.hpp"
#include "privacy_measurement_run_binding_wire.hpp"
#include "privacy_native_phase_scope_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::observation_fanout {
namespace {

using runtime_bridge::PrivateChildOutputCompletion;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

void read_exact(int fd, std::span<unsigned char> target, off_t offset) {
    std::size_t at = 0;
    while (at < target.size()) {
        ssize_t amount;
        do {
            amount = ::pread(fd, target.data() + at, target.size() - at,
                             offset + static_cast<off_t>(at));
        } while (amount < 0 && errno == EINTR);
        need(amount > 0);
        at += static_cast<std::size_t>(amount);
    }
}

int reopen_read_only(int fd) {
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", fd);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    need(result >= 0 &&
         (::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
    return result;
}

Digest hash_bytes(std::span<const unsigned char> bytes) {
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

void append(std::vector<unsigned char>& out,
            std::span<const unsigned char> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

Digest opaque_identity(
        std::string_view domain, std::span<const unsigned char> nonce,
        const Digest& retained_output_identity, const Digest& content_hash,
        const RunBinding& binding,
        const PrivateChildOutputCompletion& completion,
        std::span<const unsigned char> suffix = {}) {
    std::vector<unsigned char> bytes;
    bytes.reserve(domain.size() + nonce.size() + 7 * Digest{}.size() +
                  wire::RUN_BINDING_BYTES + suffix.size());
    append(bytes, {reinterpret_cast<const unsigned char*>(domain.data()),
                   domain.size()});
    append(bytes, nonce);
    append(bytes, retained_output_identity);
    append(bytes, content_hash);
    const auto encoded_binding = wire::canonical_run_binding_bytes(binding);
    append(bytes, encoded_binding);
    append(bytes, completion.offer.permit_identity);
    append(bytes, completion.offer.transport_session);
    append(bytes, completion.offer.output_authority_identity);
    append(bytes, completion.process_identity);
    append(bytes, completion.child_exit_identity);
    append(bytes, suffix);
    return hash_bytes(bytes);
}

std::array<unsigned char, 128> fresh_entropy() {
    std::array<unsigned char, 128> result{};
    std::size_t at = 0;
    while (at < result.size()) {
        ssize_t count;
        do {
            count = ::getrandom(result.data() + at, result.size() - at, 0);
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return result;
}

struct EntropyCleanser {
    std::array<unsigned char, 128>& value;
    ~EntropyCleanser() { OPENSSL_cleanse(value.data(), value.size()); }
};

unsigned u16be(std::span<const unsigned char> value) {
    need(value.size() == 2);
    return static_cast<unsigned>(value[0]) << 8U | value[1];
}

void validate_completion(
        const PrivateChildOutputCompletion& completion,
        const Digest& sealed_identity) {
    validate_measurement_run_binding(completion.offer.binding);
    need(runtime_bridge::OBSERVER_OUTPUT_ABI.version == 3 &&
         completion.offer.role == runtime_bridge::RuntimeChildRole::Observer &&
         completion.offer.owner == runtime_bridge::NO_OWNER &&
         completion.offer.worker == completion.offer.binding.observer_worker &&
         completion.offer.output_abi_identity ==
             runtime_bridge::OBSERVER_OUTPUT_ABI.identity &&
         completion.offer.exact_size ==
             runtime_bridge::OBSERVER_OUTPUT_ABI.exact_bytes &&
         nonzero(completion.offer.permit_identity) &&
         nonzero(completion.offer.transport_session) &&
         nonzero(completion.offer.output_authority_identity) &&
         nonzero(completion.content_hash) &&
         nonzero(completion.process_identity) &&
         nonzero(completion.child_exit_identity) &&
         nonzero(sealed_identity) &&
         completion.process_identity != completion.child_exit_identity &&
         completion.authenticated_pid > 1 &&
         completion.waited_pid == completion.authenticated_pid &&
         completion.exit_code == 0 && completion.term_signal == 0 &&
         completion.credentials_verified && completion.eof_observed);
}

void validate_exact_open_inventory(std::span<const unsigned char> value) {
    using namespace runtime_bridge;
    need(value.size() == OBSERVER_STEP2_V3_BYTES &&
         validate_observer_step2_v3_section(value));
    std::size_t at = 20;
    for (const auto total : OBSERVER_STEP2_VIEW_TOTALS) {
        need(total > 0 && u16be(value.subspan(at, 2)) == total);
        at += 2;
    }
    for (const auto deferred : OBSERVER_STEP2_DEFERRED_STEP3_COUNTS)
        need(deferred == 4 && value[at++] == deferred);
    need(std::equal(OBSERVER_STEP2_REGISTRY_IDENTITY.begin(),
                    OBSERVER_STEP2_REGISTRY_IDENTITY.end(),
                    value.begin() + static_cast<std::ptrdiff_t>(at)));
    at += OBSERVER_STEP2_REGISTRY_IDENTITY.size();
    need(std::equal(OBSERVER_STEP2_MODEL_IDENTITY.begin(),
                    OBSERVER_STEP2_MODEL_IDENTITY.end(),
                    value.begin() + static_cast<std::ptrdiff_t>(at)));
    at += OBSERVER_STEP2_MODEL_IDENTITY.size();
    for (const auto& row : OBSERVER_STEP2_FAMILY_ROWS) {
        need(value[at++] == row.code);
        bool row_open = false;
        for (const auto count : row.counts) {
            need(value[at++] == count);
            row_open = row_open || count != 0;
        }
        need(row_open && value[at++] ==
             static_cast<unsigned char>(row.disposition));
    }
    need(u16be(value.subspan(at, 2)) == OBSERVER_STEP2_EMPIRICAL_OPEN_MASK &&
         OBSERVER_STEP2_EMPIRICAL_OPEN_MASK != 0);
    at += 2;
    need(u16be(value.subspan(at, 2)) == 0);
    at += 2;
    need(at == value.size());
}

} // namespace

OpenObservationFanoutAuthority ObservationBarrierFanoutBridge::prepare(
        phase_scope::ObservationOutputJoinAuthority&& supplied) {
    auto retained =
        std::move(supplied).transfer_for_observation_fanout();
    need(retained.storage_ != nullptr && retained.destroy_ != nullptr &&
         retained.completion_ != nullptr &&
         retained.sealed_output_identity_ != nullptr &&
         retained.output_ != nullptr && retained.deferred_step3_ != nullptr &&
         retained.open_step2_ != nullptr &&
         retained.deferred_step3_size_ ==
             runtime_bridge::OBSERVER_PHASE_V2_BYTES &&
         retained.open_step2_size_ ==
             runtime_bridge::OBSERVER_STEP2_V3_BYTES);
    const auto& completion = *retained.completion_;
    const auto& sealed_identity = *retained.sealed_output_identity_;
    const auto& binding = completion.offer.binding;
    validate_completion(completion, sealed_identity);
    const int retained_fd = retained.output_->native_phase_scope_read_fd();
    struct stat retained_stat{};
    constexpr int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    need(::fstat(retained_fd, &retained_stat) == 0 &&
         S_ISREG(retained_stat.st_mode) && retained_stat.st_size >= 0 &&
         static_cast<std::uint64_t>(retained_stat.st_size) ==
             runtime_bridge::OBSERVER_OUTPUT_ABI.exact_bytes &&
         (::fcntl(retained_fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         ::fcntl(retained_fd, F_GET_SEALS) == required_seals);
    const auto exact_size = static_cast<std::uint64_t>(retained_stat.st_size);
    std::vector<unsigned char> body(static_cast<std::size_t>(exact_size));
    read_exact(retained_fd, body, 0);
    const std::span<const unsigned char> deferred(
        retained.deferred_step3_, retained.deferred_step3_size_);
    const std::span<const unsigned char> open(
        retained.open_step2_, retained.open_step2_size_);
    need(runtime_bridge::validate_measurement_output_abi(
             runtime_bridge::RuntimeChildRole::Observer, body) &&
         hash_bytes(body) == completion.content_hash &&
         std::equal(
             deferred.begin(), deferred.end(),
             body.begin() + static_cast<std::ptrdiff_t>(
                 runtime_bridge::OBSERVER_PHASE_V2_OFFSET)) &&
         std::equal(
             open.begin(), open.end(),
             body.begin() + static_cast<std::ptrdiff_t>(
                 runtime_bridge::OBSERVER_STEP2_V3_OFFSET)) &&
         runtime_bridge::validate_observer_phase_v2_section(deferred));
    validate_exact_open_inventory(open);

    auto entropy = fresh_entropy();
    EntropyCleanser cleanse{entropy};
    const Digest barrier = opaque_identity(
        "KPB_OPEN_OBSERVATION_BARRIER_V1\n",
        std::span<const unsigned char>(entropy).first(32), sealed_identity,
        completion.content_hash, binding, completion);
    need(nonzero(barrier) && barrier != completion.content_hash &&
         barrier != sealed_identity);

    runtime_bridge::PublicMeasurementInputEndpoint::PublicLineage lineage{
        .classification = binding.classification,
        .trial = binding.trial,
        .barrier = barrier,
        .capture_plan_identities = binding.round_capture_plans,
        .financial_runs = binding.financial_runs,
        .round_attempts = binding.round_attempts,
        .round_cohorts = binding.round_cohorts,
        .projections = binding.projections,
    };
    std::array<std::unique_ptr<runtime_bridge::
        MeasurementInputEndpointAuthority>, 3> endpoints{};
    std::array<std::uint64_t, 3> endpoint_devices{};
    std::array<std::uint64_t, 3> endpoint_inodes{};
    std::array<bool, 3> endpoint_read_only{};
    std::array<Digest, 3> endpoint_identities{};
    for (unsigned owner = 0; owner < endpoints.size(); ++owner) {
        const unsigned char suffix = static_cast<unsigned char>(owner);
        endpoint_identities[owner] = opaque_identity(
            "KPB_OPEN_OBSERVATION_FD41_ENDPOINT_V1\n",
            std::span<const unsigned char>(entropy).subspan(
                32 + owner * 32, 32),
            sealed_identity, completion.content_hash, binding, completion,
            std::span<const unsigned char>(&suffix, 1));
        need(nonzero(endpoint_identities[owner]) &&
             endpoint_identities[owner] != barrier &&
             endpoint_identities[owner] != completion.content_hash &&
             endpoint_identities[owner] != sealed_identity);
        for (unsigned prior = 0; prior < owner; ++prior)
            need(endpoint_identities[owner] != endpoint_identities[prior]);

        int source = -1;
        try {
            source = reopen_read_only(retained_fd);
            struct stat endpoint_stat{};
            need(::fstat(source, &endpoint_stat) == 0 &&
                 S_ISREG(endpoint_stat.st_mode) &&
                 endpoint_stat.st_dev == retained_stat.st_dev &&
                 endpoint_stat.st_ino == retained_stat.st_ino &&
                 endpoint_stat.st_size == retained_stat.st_size &&
                 (::fcntl(source, F_GETFL) & O_ACCMODE) == O_RDONLY &&
                 ::fcntl(source, F_GET_SEALS) == required_seals);
            endpoints[owner] = std::unique_ptr<runtime_bridge::
                MeasurementInputEndpointAuthority>(
                    new runtime_bridge::MeasurementInputEndpointAuthority(
                        runtime_bridge::MeasurementInputKind::
                            ScoreObservation,
                        runtime_bridge::NO_OWNER, source,
                        endpoint_identities[owner], lineage,
                        static_cast<std::int64_t>(
                            completion.authenticated_pid),
                        completion.offer.transport_session,
                        completion.child_exit_identity));
            endpoint_devices[owner] = static_cast<std::uint64_t>(
                endpoint_stat.st_dev);
            endpoint_inodes[owner] = static_cast<std::uint64_t>(
                endpoint_stat.st_ino);
            endpoint_read_only[owner] = true;
            close_fd(source);
        } catch (...) {
            close_fd(source);
            throw;
        }
    }

    void* retained_storage = std::exchange(retained.storage_, nullptr);
    auto destroy = std::exchange(retained.destroy_, nullptr);
    return OpenObservationFanoutAuthority(
        retained_storage, destroy, barrier,
        static_cast<std::uint64_t>(retained_stat.st_dev),
        static_cast<std::uint64_t>(retained_stat.st_ino), exact_size,
        std::move(endpoints), endpoint_devices, endpoint_inodes,
        endpoint_read_only);
}

} // namespace kpb::measurement::observation_fanout
