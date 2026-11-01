#include "privacy_measurement_parent_manifest.hpp"
#include "privacy_measurement_selected_parent_fixture_table_schema.hpp"

#ifndef KPB_MEASUREMENT_SELECTED_PARENT_FIXTURE_TABLE_HEADER
#error "diagnostic control requires its compiled fixture table"
#endif
#include KPB_MEASUREMENT_SELECTED_PARENT_FIXTURE_TABLE_HEADER

#include <cassert>
#include <type_traits>

using namespace kpb::measurement;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

void exact_compiled_table_is_consumed_by_exact_child() {
    static_assert(!std::is_copy_constructible_v<
                  ParentManifestRecomputationAuthority>);
    auto result =
        SelectedParentArtifactLauncher::test_only_launch_compiled_fixture();
    const auto& receipt = result.public_receipt();
    assert(receipt.parent_executable_identity ==
        selected_parent_fixture::kArtifacts[
            selected_parent_fixture::kExecutableComponent]
            [selected_parent_fixture::kExecutableField].expected_sha256);
    for (unsigned component = 0; component < 10; ++component) {
        const auto& entry = receipt.manifest.entries[component];
        assert(entry.component == static_cast<ManifestComponent>(
            component + 1));
        const std::array<Digest, 6> actual{
            entry.source_identity, entry.build_identity,
            entry.runtime_identity, entry.assets_identity,
            entry.pinned_executable_identity, entry.launcher_identity};
        for (unsigned field = 0; field < actual.size(); ++field)
            assert(actual[field] == selected_parent_fixture::
                kArtifacts[component][field].expected_sha256);
    }
    assert(receipt.manifest.manifest_identity ==
        recompute_finite_manifest_identity(receipt.manifest.entries));
}

void symlink_and_nonzero_child_refuse() {
    expect_refused([] {
        (void)SelectedParentArtifactLauncher::
            test_only_launch_compiled_fixture(
                SelectedParentLauncherTestFault::SymlinkSource);
    });
    expect_refused([] {
        (void)SelectedParentArtifactLauncher::
            test_only_launch_compiled_fixture(
                SelectedParentLauncherTestFault::ChildNonzeroExit);
    });
}

void replacement_after_open_cannot_change_consumed_inode() {
    auto pinned = SelectedParentArtifactLauncher::
        test_only_launch_compiled_fixture(
            SelectedParentLauncherTestFault::SwapPathAfterOpen);
    assert(pinned.public_receipt().manifest.entries[0].source_identity ==
        selected_parent_fixture::kArtifacts[0][0].expected_sha256);
    expect_refused([] {
        (void)SelectedParentArtifactLauncher::
            test_only_launch_compiled_fixture();
    });
}

} // namespace

int main() {
    static_assert(kParentManifestSourceStatus.diagnostic_launcher_mechanism);
    static_assert(
        kParentManifestSourceStatus.production_artifact_table_missing);
    static_assert(!kParentManifestSourceStatus.source_owned_artifact_selection);
    static_assert(!kParentManifestSourceStatus.launch_consumes_selected_artifacts);
    static_assert(!kParentManifestSourceStatus.selected_parent_callsite);
    static_assert(!kParentManifestSourceStatus.configured);
    exact_compiled_table_is_consumed_by_exact_child();
    symlink_and_nonzero_child_refuse();
    replacement_after_open_cannot_change_consumed_inode();
    return 0;
}
