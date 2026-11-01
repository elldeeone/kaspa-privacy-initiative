#pragma once

// Complete, dependency-neutral contract for the only production factory
// allowed to mint a parent manifest recomputation authority.  The authority
// header includes this definition before granting friendship.

namespace kpb::measurement {

class ParentManifestArtifactSelectionAuthority;
class ParentManifestRecomputationAuthority;

class ParentManifestRecomputationFactory final {
    ParentManifestRecomputationFactory() = delete;
public:
    static ParentManifestRecomputationAuthority recompute(
        ParentManifestArtifactSelectionAuthority&&);
#ifdef KPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP
    static void test_only_force_entropy_failure(bool);
    static void test_only_force_entropy_short_read(bool);
#endif
};

} // namespace kpb::measurement
