#include "privacy_measurement_child_output_authority.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <concepts>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <openssl/sha.h>
#include <span>
#include <type_traits>
#include <unistd.h>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;

namespace {

std::vector<unsigned char> observer_bytes;
std::vector<unsigned char> score_bytes;

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    assert(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr);
    return result;
}

WorkerBinding worker(const ManifestEntry& entry) {
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

RunBinding binding() {
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = digest(0x10);
    result.run_selection = digest(0x11);
    result.trial = digest(0x12);
    result.attempt = digest(0x13);
    result.cohort = digest(0x14);
    result.capture = digest(0x15);
    result.method = digest(0x16);
    result.workload = digest(0x17);
    result.source_closure = digest(0x18);
    result.runtime = digest(0x19);
    result.outer_parent_process = digest(0x1a);
    result.outer_parent_executable = digest(0x1b);
    result.financial_runs = {digest(0x20), digest(0x21)};
    result.round_attempts = {digest(0x22), digest(0x23)};
    result.round_cohorts = {digest(0x24), digest(0x25)};
    result.round_capture_plans = {digest(0x26), digest(0x27)};
    result.projections = {digest(0x28), digest(0x29)};
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0x40 + index * 7);
        result.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(static_cast<unsigned char>(seed + 1)),
            .runtime_identity = digest(static_cast<unsigned char>(seed + 2)),
            .assets_identity = digest(static_cast<unsigned char>(seed + 3)),
            .pinned_executable_identity =
                digest(static_cast<unsigned char>(seed + 4)),
            .launcher_identity = digest(static_cast<unsigned char>(seed + 5)),
        };
    }
    result.finite_manifest.manifest_identity =
        recompute_finite_manifest_identity(result.finite_manifest.entries);
    result.finite_manifest.parent_recomputation_identity = digest(0xfc);
    const auto& p1 = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    result.capture_source = p1.source_identity;
    result.capture_build = p1.build_identity;
    result.capture_runtime = p1.runtime_identity;
    result.capture_launcher = p1.launcher_identity;
    result.observer_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    return result;
}

PrivateChildOutputOffer offer(
        unsigned char identity = 0xa1,
        RuntimeChildRole role = RuntimeChildRole::Observer) {
    const auto selected = binding();
    const auto* abi = measurement_output_abi(role);
    assert(abi != nullptr);
    return {
        .binding = selected,
        .role = role,
        .owner = role == RuntimeChildRole::OwnerScore ? 1U : NO_OWNER,
        .permit_identity = digest(0x91),
        .worker = role == RuntimeChildRole::Observer ?
            selected.observer_worker : selected.score_worker,
        .transport_session = digest(0x92),
        .output_authority_identity = digest(identity),
        .output_abi_identity = abi->identity,
        .exact_size = abi->exact_bytes,
    };
}

PrivateChildOutputCompletion completion(
        const PrivateChildOutputOffer& selected,
        std::span<const unsigned char> bytes) {
    return {
        .offer = selected,
        .content_hash = hash(bytes),
        .process_identity = digest(0x94),
        .child_exit_identity = digest(0x95),
        .authenticated_pid = 7001,
        .waited_pid = 7001,
        .exit_code = 0,
        .term_signal = 0,
        .credentials_verified = true,
        .eof_observed = true,
    };
}

void write_all(int fd, std::span<const unsigned char> bytes) {
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::write(
            fd, bytes.data() + at, bytes.size() - at);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

std::vector<unsigned char> read_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    assert(input.good());
    return {std::istreambuf_iterator<char>(input), {}};
}

const std::vector<unsigned char>& output_bytes() {
    return observer_bytes;
}

SealedChildOutputAuthority produce(
        const PrivateChildOutputOffer& selected,
        std::span<const unsigned char> bytes,
        PrivateChildOutputCompletion observed) {
    auto pending = MeasurementChildOutputPlane::test_only_begin(selected);
    const int child = pending.test_only_take_child_fd();
    write_all(child, bytes);
    assert(::close(child) == 0);
    auto completion_authority =
        AuthenticatedChildOutputCompletionAuthority::test_only_mint(
            std::move(observed));
    return MeasurementChildOutputPlane::finish(
        std::move(pending), std::move(completion_authority));
}

void exact_output_is_read_only_sealed_and_private() {
    static_assert(!std::copy_constructible<PendingChildOutputAuthority>);
    static_assert(!std::copy_constructible<
                  AuthenticatedChildOutputCompletionAuthority>);
    static_assert(!std::copy_constructible<SealedChildOutputAuthority>);
    static_assert(std::move_constructible<PendingChildOutputAuthority>);
    static_assert(std::move_constructible<SealedChildOutputAuthority>);
    const auto bytes = output_bytes();
    const auto selected = offer();
    const auto observed = completion(selected, bytes);
    auto pending = MeasurementChildOutputPlane::test_only_begin(selected);
    const int child = pending.test_only_take_child_fd();
    write_all(child, bytes);
    assert(::close(child) == 0);
    auto completion_authority =
        AuthenticatedChildOutputCompletionAuthority::test_only_mint(observed);
    auto sealed = MeasurementChildOutputPlane::finish(
        std::move(pending), std::move(completion_authority));
    assert(sealed.test_only_matches(observed, hash(bytes)));
    const int read_fd = sealed.test_only_duplicate_read_fd();
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert((::fcntl(read_fd, F_GETFL) & O_ACCMODE) == O_RDONLY);
    assert((::fcntl(read_fd, F_GET_SEALS) & seals) == seals);
    std::vector<unsigned char> retained(bytes.size());
    assert(::pread(read_fd, retained.data(), retained.size(), 0) ==
           static_cast<ssize_t>(retained.size()));
    assert(retained == bytes);
    errno = 0;
    assert(::write(read_fd, retained.data(), retained.size()) == -1 &&
           errno == EBADF);
    assert(::close(read_fd) == 0);
    expect_refused([&] {
        (void)MeasurementChildOutputPlane::finish(
            std::move(pending), std::move(completion_authority));
    });
}

void only_two_source_owned_role_abis_are_admitted() {
    static_assert(measurement_output_abi(RuntimeChildRole::Observer) ==
                  &OBSERVER_OUTPUT_ABI);
    static_assert(measurement_output_abi(RuntimeChildRole::OwnerScore) ==
                  &OWNER_SCORE_OUTPUT_ABI);
    static_assert(!measurement_output_abi(RuntimeChildRole::Aggregate));
    static_assert(!measurement_output_abi(
        RuntimeChildRole::OwnerComparison));
    const auto selected = offer(0xa3, RuntimeChildRole::OwnerScore);
    auto sealed = produce(
        selected, score_bytes, completion(selected, score_bytes));
    assert(sealed.test_only_matches(
        completion(selected, score_bytes), hash(score_bytes)));
    for (const auto role : {RuntimeChildRole::Aggregate,
                            RuntimeChildRole::OwnerComparison}) {
        auto invalid = offer();
        invalid.role = role;
        invalid.worker = invalid.binding.aggregate_worker;
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::test_only_begin(invalid);
        });
    }
}

void wrong_size_hash_lineage_exit_and_eof_refuse() {
    const auto bytes = output_bytes();
    {
        const auto selected = offer();
        auto short_bytes = bytes;
        short_bytes.pop_back();
        expect_refused([&] {
            (void)produce(selected, short_bytes,
                          completion(selected, bytes));
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.content_hash = digest(0xee);
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.offer.permit_identity = digest(0xef);
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.exit_code = 7;
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.eof_observed = false;
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.term_signal = 9;
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.credentials_verified = false;
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.waited_pid += 1;
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        observed.child_exit_identity = observed.process_identity;
        expect_refused([&] {
            (void)produce(selected, bytes, observed);
        });
    }
    {
        const auto selected = offer();
        auto extra = bytes;
        extra.push_back(0xff);
        expect_refused([&] {
            (void)produce(selected, extra, completion(selected, bytes));
        });
    }
}

void body_and_exact_lineage_substitutions_refuse() {
    const auto bytes = output_bytes();
    {
        auto selected = offer();
        selected.worker.source_identity = digest(0xd0);
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::test_only_begin(selected);
        });
    }
    for (unsigned variant = 0; variant < 6; ++variant) {
        const auto selected = offer();
        auto observed = completion(selected, bytes);
        switch (variant) {
        case 0:
            observed.offer.binding.run_selection = digest(0xd1);
            break;
        case 1:
            observed.offer.transport_session = digest(0xd2);
            break;
        case 2:
            observed.offer.output_authority_identity = digest(0xd3);
            break;
        case 3:
            observed.process_identity = {};
            break;
        case 4:
            observed.child_exit_identity = {};
            break;
        case 5:
            observed.authenticated_pid = observed.waited_pid = 1;
            break;
        }
        expect_refused([&] { (void)produce(selected, bytes, observed); });
    }
    {
        const auto selected = offer();
        auto malformed = bytes;
        assert(!malformed.empty());
        malformed.front() ^= 0x01;
        expect_refused([&] {
            (void)produce(
                selected, malformed, completion(selected, malformed));
        });
    }
}

void invalid_binding_role_owner_size_and_live_alias_refuse() {
    {
        auto selected = offer();
        selected.binding.source_closure = {};
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::test_only_begin(selected);
        });
    }
    {
        auto selected = offer();
        selected.owner = 0;
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::test_only_begin(selected);
        });
    }
    {
        auto selected = offer();
        selected.role = RuntimeChildRole::OwnerScore;
        selected.worker = selected.binding.score_worker;
        selected.owner = NO_OWNER;
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::test_only_begin(selected);
        });
    }
    {
        auto selected = offer();
        selected.exact_size += OUTPUT_ABI_PAGE_BYTES;
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::test_only_begin(selected);
        });
    }
    {
        auto selected = offer();
        selected.output_abi_identity = digest(0x93);
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::test_only_begin(selected);
        });
    }
    {
        const auto bytes = output_bytes();
        const auto selected = offer();
        auto pending = MeasurementChildOutputPlane::test_only_begin(selected);
        auto observed =
            AuthenticatedChildOutputCompletionAuthority::test_only_mint(
                completion(selected, bytes));
        expect_refused([&] {
            (void)MeasurementChildOutputPlane::finish(
                std::move(pending), std::move(observed));
        });
    }
}

void opaque_identity_cannot_equal_body_hash_and_repeats_do_not_link() {
    const auto bytes = output_bytes();
    auto correlated = offer();
    correlated.output_authority_identity = hash(bytes);
    expect_refused([&] {
        (void)produce(correlated, bytes, completion(correlated, bytes));
    });

    const auto first_offer = offer(0xa1);
    const auto second_offer = offer(0xa2);
    auto first = produce(
        first_offer, bytes, completion(first_offer, bytes));
    auto second = produce(
        second_offer, bytes, completion(second_offer, bytes));
    assert(first.test_only_matches(completion(first_offer, bytes),
                                   hash(bytes)));
    assert(second.test_only_matches(completion(second_offer, bytes),
                                    hash(bytes)));
}

void failed_finish_burns_pending_and_completion_independently() {
    const auto bytes = output_bytes();
    const auto selected = offer(0xac);

    auto stale_pending = MeasurementChildOutputPlane::test_only_begin(
        selected);
    const int stale_child = stale_pending.test_only_take_child_fd();
    write_all(stale_child, bytes);
    assert(::close(stale_child) == 0);
    auto first_completion =
        AuthenticatedChildOutputCompletionAuthority::test_only_mint(
            completion(selected, bytes));
    auto sealed = MeasurementChildOutputPlane::finish(
        std::move(stale_pending), std::move(first_completion));
    (void)sealed;

    auto completion_that_must_burn =
        AuthenticatedChildOutputCompletionAuthority::test_only_mint(
            completion(selected, bytes));
    expect_refused([&] {
        (void)MeasurementChildOutputPlane::finish(
            std::move(stale_pending),
            std::move(completion_that_must_burn));
    });

    auto fresh_pending = MeasurementChildOutputPlane::test_only_begin(
        selected);
    const int fresh_child = fresh_pending.test_only_take_child_fd();
    write_all(fresh_child, bytes);
    assert(::close(fresh_child) == 0);
    expect_refused([&] {
        (void)MeasurementChildOutputPlane::finish(
            std::move(fresh_pending),
            std::move(completion_that_must_burn));
    });
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 3);
    observer_bytes = read_file(argv[1]);
    score_bytes = read_file(argv[2]);
    assert(observer_bytes.size() == OBSERVER_OUTPUT_ABI.exact_bytes);
    assert(score_bytes.size() == OWNER_SCORE_OUTPUT_ABI.exact_bytes);
    exact_output_is_read_only_sealed_and_private();
    only_two_source_owned_role_abis_are_admitted();
    wrong_size_hash_lineage_exit_and_eof_refuse();
    body_and_exact_lineage_substitutions_refuse();
    invalid_binding_role_owner_size_and_live_alias_refuse();
    opaque_identity_cannot_equal_body_hash_and_repeats_do_not_link();
    failed_finish_burns_pending_and_completion_independently();
}
