#include "privacy_native_phase_scope_authority.hpp"

#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_measurement_output_abi.hpp"
#include "privacy_native_empirical_result_test_fixture.hpp"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <concepts>
#include <openssl/sha.h>
#include <span>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::phase_scope;
using namespace kpb::measurement::runtime_bridge;
namespace empirical_fixture =
    kpb::measurement::empirical_result::test_fixture;

namespace {

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

RunBinding binding(unsigned char seed = 0x10) {
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    result.comparison_selection = digest(seed);
    result.run_selection = digest(static_cast<unsigned char>(seed + 1));
    result.trial = digest(static_cast<unsigned char>(seed + 2));
    result.attempt = digest(static_cast<unsigned char>(seed + 3));
    result.cohort = digest(static_cast<unsigned char>(seed + 4));
    result.capture = digest(static_cast<unsigned char>(seed + 5));
    result.method = digest(static_cast<unsigned char>(seed + 6));
    result.workload = digest(static_cast<unsigned char>(seed + 7));
    result.source_closure = digest(static_cast<unsigned char>(seed + 8));
    result.runtime = digest(static_cast<unsigned char>(seed + 9));
    result.outer_parent_process = digest(static_cast<unsigned char>(seed + 10));
    result.outer_parent_executable = digest(static_cast<unsigned char>(seed + 11));
    result.financial_runs = {digest(0x20), digest(0x21)};
    result.round_attempts = {digest(0x22), digest(0x23)};
    result.round_cohorts = {digest(0x24), digest(0x25)};
    result.round_capture_plans = {digest(0x26), digest(0x27)};
    result.projections = {digest(0x28), digest(0x29)};
    for (unsigned index = 0;
         index < result.finite_manifest.entries.size(); ++index) {
        const auto component_seed =
            static_cast<unsigned char>(0x40 + index * 7);
        result.finite_manifest.entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(component_seed),
            .build_identity = digest(
                static_cast<unsigned char>(component_seed + 1)),
            .runtime_identity = digest(
                static_cast<unsigned char>(component_seed + 2)),
            .assets_identity = digest(
                static_cast<unsigned char>(component_seed + 3)),
            .pinned_executable_identity = digest(
                static_cast<unsigned char>(component_seed + 4)),
            .launcher_identity = digest(
                static_cast<unsigned char>(component_seed + 5)),
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
        RuntimeChildRole role = RuntimeChildRole::Observer,
        unsigned char run_seed = 0x10) {
    const auto selected = binding(run_seed);
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
        .output_authority_identity = digest(0x93),
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

SealedChildOutputAuthority produce(
        const PrivateChildOutputOffer& selected,
        std::span<const unsigned char> bytes) {
    auto pending = MeasurementChildOutputPlane::test_only_begin(selected);
    const int child = pending.test_only_take_child_fd();
    write_all(child, bytes);
    assert(::close(child) == 0);
    auto completed =
        AuthenticatedChildOutputCompletionAuthority::test_only_mint(
            completion(selected, bytes));
    return MeasurementChildOutputPlane::finish(
        std::move(pending), std::move(completed));
}

void valid_observer_retains_one_nonauthorizing_linear_join() {
    const auto bytes = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    const auto selected = offer();
    auto sealed = produce(selected, bytes);
    auto empirical = empirical_fixture::exact(selected.binding);
    auto joined = NativePrivacyPhaseScopeBridge::validate_for_observation(
        std::move(sealed), std::move(empirical));
    static_assert(!std::copy_constructible<decltype(joined)>);
    static_assert(std::move_constructible<decltype(joined)>);
    (void)joined;
    expect_refused([&] {
        (void)NativePrivacyPhaseScopeBridge::validate_for_observation(
            std::move(sealed), std::move(empirical));
    });
}

void wrong_role_binding_and_malformed_inventory_never_join() {
    const auto score_bytes = test_only_measurement_output_abi_body(
        RuntimeChildRole::OwnerScore, 1);
    const auto score_offer = offer(RuntimeChildRole::OwnerScore);
    auto score = produce(score_offer, score_bytes);
    auto score_empirical = empirical_fixture::exact(score_offer.binding);
    expect_refused([&] {
        (void)NativePrivacyPhaseScopeBridge::validate_for_observation(
            std::move(score), std::move(score_empirical));
    });

    const auto selected = offer();
    auto sealed = produce(selected, test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer));
    auto wrong_empirical = empirical_fixture::exact(binding(0x11));
    expect_refused([&] {
        (void)NativePrivacyPhaseScopeBridge::validate_for_observation(
            std::move(sealed), std::move(wrong_empirical));
    });

    const auto valid = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    for (const std::size_t absolute_offset : {
             std::size_t{7}, // v2 top-level downgrade
             static_cast<std::size_t>(OBSERVER_PHASE_V2_OFFSET),
             static_cast<std::size_t>(OBSERVER_PHASE_V2_OFFSET + 18),
             static_cast<std::size_t>(OBSERVER_STEP2_V3_OFFSET),
             static_cast<std::size_t>(OBSERVER_STEP2_V3_OFFSET + 20),
             static_cast<std::size_t>(OBSERVER_STEP2_V3_OFFSET + 32),
             static_cast<std::size_t>(OBSERVER_STEP2_V3_OFFSET + 64),
             static_cast<std::size_t>(OBSERVER_STEP2_V3_OFFSET + 101),
             static_cast<std::size_t>(OBSERVER_STEP2_V3_OFFSET + 252),
         }) {
        auto malformed = valid;
        malformed[absolute_offset] ^= 1U;
        expect_refused([&] { (void)produce(selected, malformed); });
    }

    auto zero_counts = valid;
    std::fill(zero_counts.begin() + OBSERVER_STEP2_V3_OFFSET + 20,
              zero_counts.begin() + OBSERVER_STEP2_V3_OFFSET + 28, 0);
    expect_refused([&] { (void)produce(selected, zero_counts); });

    auto forged_closed = valid;
    forged_closed[OBSERVER_STEP2_V3_OFFSET + 101] = 0;
    expect_refused([&] { (void)produce(selected, forged_closed); });
}

void stale_output_failure_burns_the_fresh_empirical_residual() {
    const auto selected = offer();
    const auto bytes = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    auto stale_output = produce(selected, bytes);
    auto first_empirical = empirical_fixture::exact(selected.binding);
    auto first = NativePrivacyPhaseScopeBridge::validate_for_observation(
        std::move(stale_output), std::move(first_empirical));
    (void)first;

    auto fresh_empirical = empirical_fixture::exact(selected.binding);
    expect_refused([&] {
        (void)NativePrivacyPhaseScopeBridge::validate_for_observation(
            std::move(stale_output), std::move(fresh_empirical));
    });
    auto fresh_output = produce(selected, bytes);
    expect_refused([&] {
        (void)NativePrivacyPhaseScopeBridge::validate_for_observation(
            std::move(fresh_output), std::move(fresh_empirical));
    });
}

} // namespace

int main() {
    static_assert(kNativePhaseScopeStatus.observer_abi_v3_exact_open_inventory);
    static_assert(kNativePhaseScopeStatus.exact_deferred_step3_section);
    static_assert(kNativePhaseScopeStatus.sealed_observer_output_retained);
    static_assert(kNativePhaseScopeStatus.native_empirical_residual_retained);
    static_assert(kNativePhaseScopeStatus.observation_output_linear_join);
    static_assert(kNativePhaseScopeStatus.standalone_prediction_permit_removed);
    static_assert(!kNativePhaseScopeStatus.native_prediction_consumer);
    static_assert(!kNativePhaseScopeStatus.native_step3_consumer);
    static_assert(!kNativePhaseScopeStatus.selected_runtime_callsite);
    static_assert(!kNativePhaseScopeStatus.configured);
    valid_observer_retains_one_nonauthorizing_linear_join();
    wrong_role_binding_and_malformed_inventory_never_join();
    stale_output_failure_burns_the_fresh_empirical_residual();
}
