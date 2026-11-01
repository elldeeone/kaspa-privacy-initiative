#include "privacy_measurement_parent_manifest.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

using namespace kpb::measurement;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

void close_fd(int fd) {
    while (::close(fd) != 0 && errno == EINTR) {}
}

int sealed_artifact(unsigned component, unsigned field) {
    const int writable = ::memfd_create(
        "kpb-parent-manifest-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writable >= 0);
    std::array<unsigned char, 67> bytes{};
    for (unsigned index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<unsigned char>(
            1 + component * 17 + field * 5 + index);
    assert(::write(writable, bytes.data(), bytes.size()) ==
           static_cast<ssize_t>(bytes.size()));
    constexpr int seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert(::fcntl(writable, F_ADD_SEALS, seals) == 0);
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", writable);
    assert(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int readonly = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    assert(readonly >= 0);
    close_fd(writable);
    return readonly;
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest hash_file(int fd) {
    struct stat status{};
    assert(::fstat(fd, &status) == 0 && status.st_size > 0);
    std::vector<unsigned char> bytes(
        static_cast<std::size_t>(status.st_size));
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::pread(
            fd, bytes.data() + at, bytes.size() - at,
            static_cast<off_t>(at));
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
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

RunBinding binding(const PublicParentManifestRecomputation& parent) {
    RunBinding result{};
    result.classification = Classification::HiddenCandidate;
    unsigned char seed = 0x20;
    for (auto* value : {
             &result.comparison_selection, &result.run_selection,
             &result.trial, &result.attempt, &result.cohort,
             &result.capture, &result.method, &result.workload,
             &result.source_closure, &result.runtime})
        *value = digest(seed++);
    result.finite_manifest = parent.manifest;
    result.outer_parent_process = parent.parent_process_identity;
    result.outer_parent_executable = parent.parent_executable_identity;
    const auto& capture = result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::P1Capture) - 1];
    result.capture_source = capture.source_identity;
    result.capture_build = capture.build_identity;
    result.capture_runtime = capture.runtime_identity;
    result.capture_launcher = capture.launcher_identity;
    result.observer_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Observer) - 1]);
    result.score_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::OwnerScore) - 1]);
    result.aggregate_worker = worker(result.finite_manifest.entries[
        static_cast<unsigned>(ManifestComponent::Aggregate) - 1]);
    for (auto* values : {
             &result.financial_runs, &result.round_attempts,
             &result.round_cohorts, &result.round_capture_plans,
             &result.projections})
        for (auto& value : *values) value = digest(seed++);
    return result;
}

std::array<ParentManifestComponentArtifacts, 10> artifacts() {
    std::array<ParentManifestComponentArtifacts, 10> result{};
    for (unsigned component = 0; component < result.size(); ++component)
        for (unsigned field = 0;
             field < result[component].fds.size(); ++field)
            result[component].fds[field] =
                sealed_artifact(component, field);
    return result;
}

void close_originals(
        std::array<ParentManifestComponentArtifacts, 10>& value) {
    for (auto& component : value)
        for (auto& fd : component.fds) {
            if (fd >= 0) close_fd(fd);
            fd = -1;
        }
}

void exact_artifacts_and_actual_parent_are_authoritative() {
    static_assert(!std::is_copy_constructible_v<
                  ParentManifestArtifactSelectionAuthority>);
    static_assert(std::is_move_constructible_v<
                  ParentManifestArtifactSelectionAuthority>);
    auto files = artifacts();
    std::array<std::array<Digest, 6>, 10> expected{};
    for (unsigned component = 0; component < files.size(); ++component)
        for (unsigned field = 0; field < files[component].fds.size(); ++field)
            expected[component][field] =
                hash_file(files[component].fds[field]);
    auto selection = ParentManifestArtifactSelector::select(
        std::move(files));
    for (const auto& component : files)
        for (const int fd : component.fds) assert(fd == -1);
    close_originals(files);
    auto manifest = ParentManifestRecomputationFactory::recompute(
        std::move(selection));
    const auto& receipt = manifest.public_receipt();
    assert(receipt.manifest.manifest_identity ==
           recompute_finite_manifest_identity(receipt.manifest.entries));
    assert(receipt.recomputation_receipt ==
           receipt.manifest.parent_recomputation_identity);
    assert(receipt.parent_process_identity != Digest{} &&
           receipt.parent_executable_identity != Digest{} &&
           receipt.manifest.manifest_identity !=
               receipt.manifest.parent_recomputation_identity);
    const int self = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    assert(self >= 0 && hash_file(self) ==
           receipt.parent_executable_identity);
    close_fd(self);
    for (unsigned index = 0; index < receipt.manifest.entries.size(); ++index) {
        assert(receipt.manifest.entries[index].component ==
               static_cast<ManifestComponent>(index + 1));
        const auto& entry = receipt.manifest.entries[index];
        assert(entry.source_identity == expected[index][0] &&
               entry.build_identity == expected[index][1] &&
               entry.runtime_identity == expected[index][2] &&
               entry.assets_identity == expected[index][3] &&
               entry.pinned_executable_identity == expected[index][4] &&
               entry.launcher_identity == expected[index][5]);
    }
    expect_refused([&] {
        (void)ParentManifestRecomputationFactory::recompute(
            std::move(selection));
    });
}

void artifact_substitution_cannot_match_selected_binding() {
    auto first_files = artifacts();
    auto first_selection = ParentManifestArtifactSelector::select(
        std::move(first_files));
    auto first = ParentManifestRecomputationFactory::recompute(
        std::move(first_selection));
    const auto selected = binding(first.public_receipt());

    auto swapped_files = artifacts();
    std::swap(swapped_files[0].fds[0], swapped_files[0].fds[1]);
    auto swapped_selection = ParentManifestArtifactSelector::select(
        std::move(swapped_files));
    auto swapped = ParentManifestRecomputationFactory::recompute(
        std::move(swapped_selection));
    assert(swapped.public_receipt().manifest.manifest_identity !=
           selected.finite_manifest.manifest_identity);
    expect_refused([&] {
        TrialCaptureJoiner wrong(selected, std::move(swapped));
        (void)wrong;
    });
    TrialCaptureJoiner accepted(selected, std::move(first));
    (void)accepted;
}

void aliases_mutability_and_entropy_fail_closed() {
    {
        auto files = artifacts();
        close_fd(files[9].fds[5]);
        files[9].fds[5] = ::dup(files[0].fds[0]);
        expect_refused([&] {
            (void)ParentManifestArtifactSelector::select(
                std::move(files));
        });
        close_originals(files);
    }
    {
        auto files = artifacts();
        close_fd(files[4].fds[2]);
        files[4].fds[2] = ::memfd_create(
            "kpb-unsealed", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        assert(files[4].fds[2] >= 0);
        const unsigned char byte = 7;
        assert(::write(files[4].fds[2], &byte, 1) == 1);
        expect_refused([&] {
            (void)ParentManifestArtifactSelector::select(
                std::move(files));
        });
        close_originals(files);
    }
    {
        auto files = artifacts();
        auto selection = ParentManifestArtifactSelector::select(
            std::move(files));
        close_originals(files);
        ParentManifestRecomputationFactory::
            test_only_force_entropy_failure(true);
        expect_refused([&] {
            (void)ParentManifestRecomputationFactory::recompute(
                std::move(selection));
        });
        ParentManifestRecomputationFactory::
            test_only_force_entropy_failure(false);
        expect_refused([&] {
            (void)ParentManifestRecomputationFactory::recompute(
                std::move(selection));
        });
    }
    {
        auto files = artifacts();
        auto selection = ParentManifestArtifactSelector::select(
            std::move(files));
        ParentManifestRecomputationFactory::
            test_only_force_entropy_short_read(true);
        expect_refused([&] {
            (void)ParentManifestRecomputationFactory::recompute(
                std::move(selection));
        });
        ParentManifestRecomputationFactory::
            test_only_force_entropy_short_read(false);
        expect_refused([&] {
            (void)ParentManifestRecomputationFactory::recompute(
                std::move(selection));
        });
    }
}

} // namespace

int main() {
    exact_artifacts_and_actual_parent_are_authoritative();
    artifact_substitution_cannot_match_selected_binding();
    aliases_mutability_and_entropy_fail_closed();
}
