#pragma once

// Complete neutral contract for the source-owned selected-parent launcher.
// Production deliberately exposes no launch method until the exact generated
// artifact table and selected callsite exist. The fixture entrypoint is built
// only by the dedicated diagnostic control.

namespace kpb::measurement {

class ParentManifestRecomputationAuthority;

#ifdef KPB_MEASUREMENT_SELECTED_PARENT_LAUNCHER_TEST_SETUP
enum class SelectedParentLauncherTestFault : unsigned char {
    None,
    SymlinkSource,
    SwapPathAfterOpen,
    ChildNonzeroExit,
};
#endif

class SelectedParentArtifactLauncher final {
    SelectedParentArtifactLauncher() = delete;
public:
#ifdef KPB_MEASUREMENT_SELECTED_PARENT_LAUNCHER_TEST_SETUP
    static ParentManifestRecomputationAuthority
        test_only_launch_compiled_fixture(
            SelectedParentLauncherTestFault =
                SelectedParentLauncherTestFault::None);
#endif
};

} // namespace kpb::measurement
