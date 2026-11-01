#include "privacy_owner_score_output_split_authority.hpp"

#include "privacy_measurement_run_binding_wire.hpp"
#include "privacy_measurement_runtime_bridge.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <new>
#include <span>
#include <string_view>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::score_output_split {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

template<std::size_t Size>
void distinct_nonzero(const std::array<Digest, Size>& values) {
    for (std::size_t index = 0; index < values.size(); ++index) {
        need(nonzero(values[index]));
        for (std::size_t prior = 0; prior < index; ++prior)
            need(values[index] != values[prior]);
    }
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

int reopen_with_mode(int fd, int mode) {
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", fd);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), mode | O_CLOEXEC);
    need(result >= 0 &&
         (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
    return result;
}

void read_exact(int fd, std::span<unsigned char> target) {
    std::size_t at = 0;
    while (at < target.size()) {
        ssize_t amount;
        do {
            amount = ::pread(fd, target.data() + at,
                             target.size() - at,
                             static_cast<off_t>(at));
        } while (amount < 0 && errno == EINTR);
        need(amount > 0);
        at += static_cast<std::size_t>(amount);
    }
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

void append(std::vector<unsigned char>& out, const Digest& value) {
    append(out, std::span<const unsigned char>(value));
}

Digest opaque_identity(
        std::string_view domain, std::span<const unsigned char> nonce,
        const Digest& sealed_identity, const Digest& content_hash,
        const Digest& source_lineage_identity,
        const RunBinding& binding,
        const runtime_bridge::PrivateChildOutputCompletion& completion,
        const PublicOwnerScoreCompletion& public_completion,
        unsigned char endpoint_kind) {
    std::vector<unsigned char> bytes;
    struct BytesCleanser final {
        std::vector<unsigned char>& value;
        ~BytesCleanser() {
            if (!value.empty())
                OPENSSL_cleanse(value.data(), value.size());
        }
    } cleanser{bytes};
    bytes.reserve(domain.size() + nonce.size() +
                  wire::RUN_BINDING_BYTES + 11 * Digest{}.size() + 2);
    append(bytes, {reinterpret_cast<const unsigned char*>(domain.data()),
                   domain.size()});
    append(bytes, nonce);
    append(bytes, sealed_identity);
    append(bytes, content_hash);
    append(bytes, source_lineage_identity);
    const auto binding_bytes = wire::canonical_run_binding_bytes(binding);
    append(bytes, binding_bytes);
    append(bytes, public_completion.barrier);
    append(bytes, public_completion.permit_identity);
    append(bytes, public_completion.score_receipt);
    append(bytes, public_completion.capsule_seal);
    append(bytes, completion.offer.transport_session);
    append(bytes, completion.offer.output_authority_identity);
    append(bytes, completion.process_identity);
    append(bytes, completion.child_exit_identity);
    bytes.push_back(static_cast<unsigned char>(public_completion.owner));
    bytes.push_back(endpoint_kind);
    return hash_bytes(bytes);
}

std::array<unsigned char, 192> fresh_entropy() {
    std::array<unsigned char, 192> result{};
    std::size_t at = 0;
    while (at < result.size()) {
        ssize_t count;
        do {
            count = ::getrandom(result.data() + at,
                                result.size() - at, 0);
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return result;
}

struct EntropyCleanser {
    std::array<unsigned char, 192>& value;
    ~EntropyCleanser() { OPENSSL_cleanse(value.data(), value.size()); }
};

enum class InternalFault : unsigned char {
    None,
    BodyMutation,
    WritableReopen,
    CrossOwnerReopen,
    BeforeClaimAllocation,
    PostClaimAllocation,
};

} // namespace

OwnerScoreOutputSplitOutcomeAuthority
OwnerScoreOutputSplitBridge::split_impl(
        OwnerScoreOutputLineageAuthority&& supplied_lineage,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner0,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner1,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner2,
        unsigned char selected_fault) {
    const auto fault = static_cast<InternalFault>(selected_fault);
    if (fault == InternalFault::BeforeClaimAllocation)
        throw std::bad_alloc();
    auto result = std::make_unique<OwnerScoreOutputSplitOutcomeAuthority::Storage>();
    result->lineage.emplace(std::move(supplied_lineage));
    std::array<runtime_bridge::OwnerScoreRuntimeCompletion*, 3> supplied{
        &owner0, &owner1, &owner2};

    // Move-claim every linear input before the first validation. A stale first
    // input cannot leave either of the other two executions reusable. The
    // preallocated result retains every sealed output that was actually live.
    for (unsigned owner = 0; owner < supplied.size(); ++owner) {
        result->permit_claimed[owner] =
            supplied[owner]->permit.live_.exchange(false);
        result->completion_claimed[owner] =
            supplied[owner]->completion.live_.exchange(false);
        result->permits[owner] = supplied[owner]->permit.receipt_;
        result->completions[owner] = supplied[owner]->completion.receipt_;
        result->retained_outputs[owner] =
            std::move(supplied[owner]->completion.private_output_);
    }
    auto& permits = result->permits;
    auto& completions = result->completions;
    auto& outputs = result->retained_outputs;

    try {
        if (fault == InternalFault::PostClaimAllocation)
            throw std::bad_alloc();
        result->stop_reason =
            OwnerScoreOutputSplitStopReason::StaleOrMissingInput;
        need(result->lineage.has_value() &&
             result->lineage->live_.load() &&
             std::all_of(result->permit_claimed.begin(),
                         result->permit_claimed.end(),
                         [](bool value) { return value; }) &&
             std::all_of(result->completion_claimed.begin(),
                         result->completion_claimed.end(),
                         [](bool value) { return value; }) &&
             std::all_of(outputs.begin(), outputs.end(),
                         [](const auto& value) { return value != nullptr; }));
        result->stop_reason = OwnerScoreOutputSplitStopReason::Validation;

    const RunBinding selected_binding = permits[0].binding;
    const Digest selected_barrier = permits[0].barrier;
    validate_measurement_run_binding(selected_binding);
    need(nonzero(selected_barrier));

    std::array<runtime_bridge::PrivateChildOutputCompletion, 3>
        private_completions{};
    std::array<Digest, 3> sealed_identities{};
    std::array<Digest, 3> processes{};
    std::array<Digest, 3> child_exits{};
    std::array<Digest, 3> score_receipts{};
    std::array<Digest, 3> capsule_seals{};
    std::array<Digest, 3> transport_sessions{};
    std::array<std::uint64_t, 3> output_devices{};
    std::array<std::uint64_t, 3> output_inodes{};
    std::array<std::vector<unsigned char>, 3> bodies{};
    struct BodiesCleanser final {
        std::array<std::vector<unsigned char>, 3>& values;
        ~BodiesCleanser() {
            for (auto& value : values)
                if (!value.empty())
                    OPENSSL_cleanse(value.data(), value.size());
        }
    } bodies_cleanser{bodies};
    constexpr int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    need(result->lineage->binding_ == selected_binding &&
         nonzero(result->lineage->source_authority_identity_));
    const auto& common_expected = result->lineage->expected_[0];
    need(common_expected.method_sha256 == selected_binding.method &&
         common_expected.run_selection_sha256 ==
             selected_binding.run_selection);
    for (unsigned owner = 0; owner < 3; ++owner) {
        need(result->lineage->expected_[owner].owner == owner);
        auto normalized = result->lineage->expected_[owner];
        normalized.owner = 0;
        need(normalized == common_expected);
    }

    for (unsigned owner = 0; owner < supplied.size(); ++owner) {
        const auto& permit = permits[owner];
        const auto& completion = completions[owner];
        need(permit.owner == owner && completion.owner == owner &&
             permit.binding == selected_binding &&
             completion.binding == selected_binding &&
             permit.barrier == selected_barrier &&
             completion.barrier == selected_barrier &&
             completion.permit_identity == permit.permit_identity &&
             completion.worker == selected_binding.score_worker &&
             nonzero(permit.trial_capture_identity) &&
             nonzero(permit.observation_receipt) &&
             nonzero(permit.permit_identity) &&
             nonzero(completion.child_exit) &&
             nonzero(completion.score_receipt) &&
             nonzero(completion.capsule_seal) &&
             nonzero(completion.process_identity) &&
             completion.score_receipt != completion.capsule_seal &&
             completion.process_identity != completion.child_exit);

        const auto& private_completion =
            outputs[owner]->retained_completion();
        private_completions[owner] = private_completion;
        sealed_identities[owner] = outputs[owner]->retained_identity();
        need(nonzero(sealed_identities[owner]) &&
             private_completion.offer.binding == selected_binding &&
             private_completion.offer.role ==
                 runtime_bridge::RuntimeChildRole::OwnerScore &&
             private_completion.offer.owner == owner &&
             private_completion.offer.permit_identity ==
                 permit.permit_identity &&
             private_completion.offer.worker == selected_binding.score_worker &&
             private_completion.offer.output_abi_identity ==
                 runtime_bridge::OWNER_SCORE_OUTPUT_ABI.identity &&
             private_completion.offer.exact_size ==
                 runtime_bridge::OWNER_SCORE_OUTPUT_ABI.exact_bytes &&
             private_completion.process_identity ==
                 completion.process_identity &&
             private_completion.child_exit_identity == completion.child_exit &&
             private_completion.authenticated_pid > 1 &&
             private_completion.waited_pid ==
                 private_completion.authenticated_pid &&
             private_completion.exit_code == 0 &&
             private_completion.term_signal == 0 &&
             private_completion.credentials_verified &&
             private_completion.eof_observed);

        const int retained_fd = outputs[owner]->owner_score_split_read_fd();
        struct stat retained_stat{};
        need(::fstat(retained_fd, &retained_stat) == 0 &&
             S_ISREG(retained_stat.st_mode) && retained_stat.st_size >= 0 &&
             static_cast<std::uint64_t>(retained_stat.st_size) ==
                 runtime_bridge::OWNER_SCORE_OUTPUT_ABI.exact_bytes &&
             (::fcntl(retained_fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
             (::fcntl(retained_fd, F_GETFD) & FD_CLOEXEC) != 0 &&
             ::fcntl(retained_fd, F_GET_SEALS) == required_seals);
        output_devices[owner] = static_cast<std::uint64_t>(retained_stat.st_dev);
        output_inodes[owner] = static_cast<std::uint64_t>(retained_stat.st_ino);
        for (unsigned prior = 0; prior < owner; ++prior)
            need(output_devices[owner] != output_devices[prior] ||
                 output_inodes[owner] != output_inodes[prior]);

        bodies[owner].resize(
            runtime_bridge::OWNER_SCORE_OUTPUT_ABI.exact_bytes);
        read_exact(retained_fd, bodies[owner]);
        if (fault == InternalFault::BodyMutation && owner == 0)
            bodies[owner][0] ^= 1;
        result->stop_reason = OwnerScoreOutputSplitStopReason::BodyLineage;
        need(runtime_bridge::validate_owner_score_output_abi_for_expected_lineage(
                 bodies[owner], result->lineage->expected_[owner]) &&
             hash_bytes(bodies[owner]) == private_completion.content_hash &&
             private_completion.content_hash != sealed_identities[owner]);

        processes[owner] = completion.process_identity;
        child_exits[owner] = completion.child_exit;
        score_receipts[owner] = completion.score_receipt;
        capsule_seals[owner] = completion.capsule_seal;
        transport_sessions[owner] =
            private_completion.offer.transport_session;
    }
    distinct_nonzero(sealed_identities);
    distinct_nonzero(processes);
    distinct_nonzero(child_exits);
    distinct_nonzero(score_receipts);
    distinct_nonzero(capsule_seals);
    distinct_nonzero(transport_sessions);

    result->stop_reason = OwnerScoreOutputSplitStopReason::Entropy;
    auto entropy = fresh_entropy();
    EntropyCleanser cleanser{entropy};
    runtime_bridge::PublicMeasurementInputEndpoint::PublicLineage lineage{
        .classification = selected_binding.classification,
        .trial = selected_binding.trial,
        .barrier = selected_barrier,
        .capture_plan_identities = selected_binding.round_capture_plans,
        .financial_runs = selected_binding.financial_runs,
        .round_attempts = selected_binding.round_attempts,
        .round_cohorts = selected_binding.round_cohorts,
        .projections = selected_binding.projections,
    };
    std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>
        aggregate{};
    std::array<std::unique_ptr<runtime_bridge::MeasurementInputEndpointAuthority>, 3>
        comparison{};
    std::array<std::uint64_t, 3> aggregate_devices{};
    std::array<std::uint64_t, 3> aggregate_inodes{};
    std::array<std::uint64_t, 3> comparison_devices{};
    std::array<std::uint64_t, 3> comparison_inodes{};
    std::array<bool, 3> aggregate_read_only{};
    std::array<bool, 3> comparison_read_only{};
    std::array<Digest, 6> endpoint_identities{};

    result->stop_reason = OwnerScoreOutputSplitStopReason::Reopen;
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto& private_completion = private_completions[owner];
        endpoint_identities[2 * owner] = opaque_identity(
            "KPB_OWNER_SCORE_AGGREGATE_ENDPOINT_V1\n",
            std::span<const unsigned char>(entropy).subspan(
                2 * owner * 32, 32), sealed_identities[owner],
            private_completion.content_hash,
            result->lineage->source_authority_identity_, selected_binding,
            private_completion, completions[owner], 1);
        endpoint_identities[2 * owner + 1] = opaque_identity(
            "KPB_OWNER_SCORE_COMPARISON_ENDPOINT_V1\n",
            std::span<const unsigned char>(entropy).subspan(
                (2 * owner + 1) * 32, 32), sealed_identities[owner],
            private_completion.content_hash,
            result->lineage->source_authority_identity_, selected_binding,
            private_completion, completions[owner], 2);

        int aggregate_fd = -1;
        int comparison_fd = -1;
        try {
            const int aggregate_source =
                fault == InternalFault::CrossOwnerReopen && owner == 1
                    ? outputs[0]->owner_score_split_read_fd()
                    : outputs[owner]->owner_score_split_read_fd();
            aggregate_fd = reopen_with_mode(
                aggregate_source,
                fault == InternalFault::WritableReopen && owner == 0
                    ? O_RDWR : O_RDONLY);
            comparison_fd = reopen_with_mode(
                outputs[owner]->owner_score_split_read_fd(), O_RDONLY);

            struct stat aggregate_stat{};
            struct stat comparison_stat{};
            need(::fstat(aggregate_fd, &aggregate_stat) == 0 &&
                 ::fstat(comparison_fd, &comparison_stat) == 0 &&
                 S_ISREG(aggregate_stat.st_mode) &&
                 S_ISREG(comparison_stat.st_mode) &&
                 (::fcntl(aggregate_fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
                 (::fcntl(comparison_fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
                 ::fcntl(aggregate_fd, F_GET_SEALS) == required_seals &&
                 ::fcntl(comparison_fd, F_GET_SEALS) == required_seals &&
                 static_cast<std::uint64_t>(aggregate_stat.st_dev) ==
                     output_devices[owner] &&
                 static_cast<std::uint64_t>(aggregate_stat.st_ino) ==
                     output_inodes[owner] &&
                 static_cast<std::uint64_t>(comparison_stat.st_dev) ==
                     output_devices[owner] &&
                 static_cast<std::uint64_t>(comparison_stat.st_ino) ==
                     output_inodes[owner] &&
                 aggregate_stat.st_size == comparison_stat.st_size &&
                 static_cast<std::uint64_t>(aggregate_stat.st_size) ==
                     runtime_bridge::OWNER_SCORE_OUTPUT_ABI.exact_bytes);

            // /proc/self/fd open creates independent open file descriptions.
            // Prove the offsets do not alias before handing them to capsules.
            need(::lseek(aggregate_fd, 0, SEEK_CUR) == 0 &&
                 ::lseek(comparison_fd, 0, SEEK_CUR) == 0 &&
                 ::lseek(aggregate_fd, 17, SEEK_SET) == 17 &&
                 ::lseek(comparison_fd, 0, SEEK_CUR) == 0 &&
                 ::lseek(aggregate_fd, 0, SEEK_SET) == 0);

            aggregate[owner] = std::unique_ptr<
                runtime_bridge::MeasurementInputEndpointAuthority>(
                    new runtime_bridge::MeasurementInputEndpointAuthority(
                        runtime_bridge::MeasurementInputKind::
                            AggregateOwnerScore,
                        owner, aggregate_fd,
                        endpoint_identities[2 * owner], lineage,
                        static_cast<std::int64_t>(
                            private_completion.authenticated_pid),
                        private_completion.offer.transport_session,
                        private_completion.child_exit_identity));
            const auto comparison_kind =
                selected_binding.classification ==
                    Classification::TransparentBaseline
                ? runtime_bridge::MeasurementInputKind::
                      ComparisonBaselineOwnerScore
                : runtime_bridge::MeasurementInputKind::
                      ComparisonCandidateOwnerScore;
            comparison[owner] = std::unique_ptr<
                runtime_bridge::MeasurementInputEndpointAuthority>(
                    new runtime_bridge::MeasurementInputEndpointAuthority(
                        comparison_kind, owner, comparison_fd,
                        endpoint_identities[2 * owner + 1], lineage,
                        static_cast<std::int64_t>(
                            private_completion.authenticated_pid),
                        private_completion.offer.transport_session,
                        private_completion.child_exit_identity));
            aggregate_devices[owner] =
                static_cast<std::uint64_t>(aggregate_stat.st_dev);
            aggregate_inodes[owner] =
                static_cast<std::uint64_t>(aggregate_stat.st_ino);
            comparison_devices[owner] =
                static_cast<std::uint64_t>(comparison_stat.st_dev);
            comparison_inodes[owner] =
                static_cast<std::uint64_t>(comparison_stat.st_ino);
            aggregate_read_only[owner] = true;
            comparison_read_only[owner] = true;
            close_fd(aggregate_fd);
            close_fd(comparison_fd);
        } catch (...) {
            close_fd(aggregate_fd);
            close_fd(comparison_fd);
            throw;
        }
    }
    distinct_nonzero(endpoint_identities);

    OwnerScoreOutputSplitBundleAuthority bundle(
        std::move(*result->lineage), selected_binding, selected_barrier,
        completions,
        std::move(outputs), std::move(aggregate), std::move(comparison),
        output_devices, output_inodes,
        aggregate_devices, aggregate_inodes,
        comparison_devices, comparison_inodes,
        aggregate_read_only, comparison_read_only);
    result->bundle.emplace(std::move(bundle));
    result->lineage.reset();
    result->stop_reason = OwnerScoreOutputSplitStopReason::None;
    return OwnerScoreOutputSplitOutcomeAuthority(std::move(result));
    } catch (const std::bad_alloc&) {
        result->stop_reason = OwnerScoreOutputSplitStopReason::Allocation;
    } catch (...) {
        if (result->stop_reason == OwnerScoreOutputSplitStopReason::None)
            result->stop_reason = OwnerScoreOutputSplitStopReason::Internal;
    }
    return OwnerScoreOutputSplitOutcomeAuthority(std::move(result));
}

OwnerScoreOutputSplitOutcomeAuthority OwnerScoreOutputSplitBridge::split(
        OwnerScoreOutputLineageAuthority&& lineage,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner0,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner1,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner2) {
    return split_impl(
        std::move(lineage), std::move(owner0), std::move(owner1),
        std::move(owner2),
        static_cast<unsigned char>(InternalFault::None));
}

#ifdef KPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP
OwnerScoreOutputSplitOutcomeAuthority
OwnerScoreOutputSplitBridge::test_only_split(
        OwnerScoreOutputLineageAuthority&& lineage,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner0,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner1,
        runtime_bridge::OwnerScoreRuntimeCompletion&& owner2,
        TestOnlyOwnerScoreSplitFault fault) {
    return split_impl(
        std::move(lineage), std::move(owner0), std::move(owner1),
        std::move(owner2),
        static_cast<unsigned char>(fault));
}
#endif

} // namespace kpb::measurement::score_output_split
