#pragma once

// Parent-owned finite-manifest selection from exact immutable artifacts.
// Arbitrary callers cannot select descriptors.  The production selector stays
// absent until the source-owned 10x6 artifact table is complete; the current
// descriptor entrypoint is diagnostic-only.  The factory independently hashes
// all sixty retained artifacts, the selected child executable and a fresh
// process nonce.

#include "privacy_measurement_authority.hpp"
#include "privacy_measurement_selected_parent_launcher_contract.hpp"

#include <array>
#include <atomic>
#include <memory>

namespace kpb::measurement {

inline constexpr unsigned PARENT_MANIFEST_ARTIFACT_FIELDS = 6;

struct ParentManifestComponentArtifacts {
    // source, build, runtime, assets, pinned executable, launcher
    std::array<int, PARENT_MANIFEST_ARTIFACT_FIELDS> fds{
        {-1, -1, -1, -1, -1, -1}};
};

class ParentManifestArtifactSelectionAuthority;

class ParentManifestArtifactSelector final {
    ParentManifestArtifactSelector() = delete;
    static ParentManifestArtifactSelectionAuthority source_owned_select(
        std::array<ParentManifestComponentArtifacts, 10>&&);
    friend class SelectedParentArtifactLauncher;
public:
#ifdef KPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP
    // Diagnostic core only. Production selection must come from the future
    // source-owned parent snapshot/launcher and consume the same descriptors.
    static ParentManifestArtifactSelectionAuthority select(
        std::array<ParentManifestComponentArtifacts, 10>&&);
#endif
};

class ParentManifestArtifactSelectionAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    std::atomic_bool live_{true};
    explicit ParentManifestArtifactSelectionAuthority(
        std::unique_ptr<Storage>);
    void bind_verified_selected_child(
        unsigned executable_component, Digest executable_identity,
        Digest launch_session, Digest child_exit_identity,
        std::int64_t child_pid);
    friend class ParentManifestArtifactSelector;
    friend class ParentManifestRecomputationFactory;
    friend class SelectedParentArtifactLauncher;
public:
    ParentManifestArtifactSelectionAuthority(
        const ParentManifestArtifactSelectionAuthority&) = delete;
    ParentManifestArtifactSelectionAuthority& operator=(
        const ParentManifestArtifactSelectionAuthority&) = delete;
    ParentManifestArtifactSelectionAuthority(
        ParentManifestArtifactSelectionAuthority&&) noexcept;
    ParentManifestArtifactSelectionAuthority& operator=(
        ParentManifestArtifactSelectionAuthority&&) = delete;
    ~ParentManifestArtifactSelectionAuthority();
};

struct ParentManifestSourceStatus {
    bool exact_ten_component_artifacts{};
    bool sealed_read_only_recomputation{};
    bool actual_parent_executable{};
    bool fresh_parent_process_identity{};
    bool source_owned_artifact_selection{};
    bool launch_consumes_selected_artifacts{};
    bool selected_parent_callsite{};
    bool diagnostic_launcher_mechanism{};
    bool production_artifact_table_missing{};
    bool configured{};
};

inline constexpr ParentManifestSourceStatus kParentManifestSourceStatus{
    .exact_ten_component_artifacts = true,
    .sealed_read_only_recomputation = true,
    .actual_parent_executable = true,
    .fresh_parent_process_identity = true,
    .source_owned_artifact_selection = false,
    .launch_consumes_selected_artifacts = false,
    .diagnostic_launcher_mechanism = true,
    .production_artifact_table_missing = true,
};

} // namespace kpb::measurement
