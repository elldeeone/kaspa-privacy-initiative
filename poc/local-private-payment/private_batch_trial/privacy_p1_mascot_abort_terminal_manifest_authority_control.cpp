#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"

#include <cassert>
#include <concepts>
#include <type_traits>

using namespace kpb::measurement::p1_state;

template<class T> concept HasTestOnlySummary = requires(T& value) {
    value.test_only_summary();
};
template<class T> concept HasTestOnlyCompile = requires {
    T::test_only_compile();
};

static_assert(!std::is_default_constructible_v<
              P1MascotAbortTerminalManifestAuthority>);
static_assert(!std::is_copy_constructible_v<
              P1MascotAbortTerminalManifestAuthority>);
static_assert(std::is_move_constructible_v<
              P1MascotAbortTerminalManifestAuthority>);
static_assert(!HasTestOnlySummary<
              P1MascotAbortTerminalManifestAuthority>);
static_assert(!HasTestOnlyCompile<
              P1MascotAbortTerminalManifestCompilerBridge>);

int main() {
    using namespace kpi::mpc::p1_private_state;
    assert(MASCOT_SECRET_ABORT_EVENT_ENCODING_DOMAIN !=
           MASCOT_SECRET_EVENT_ENCODING_DOMAIN);
    for (const auto abort_class : {
             MascotSecretAbortClass::OtMultiplierFailure,
             MascotSecretAbortClass::MacCheckFailure}) {
        for (const auto kind : {
                 MascotSecretAbortEventKind::CacheUnlink,
                 MascotSecretAbortEventKind::WorkerFailurePublished,
                 MascotSecretAbortEventKind::WorkerTerminal,
                 MascotSecretAbortEventKind::RootFailureObserved,
                 MascotSecretAbortEventKind::WorkerJoined,
                 MascotSecretAbortEventKind::Teardown,
                 MascotSecretAbortEventKind::AbortTerminal,
                 MascotSecretAbortEventKind::AbortUnavailable}) {
            assert(!mascot_secret_abort_source_site(kind, abort_class).empty());
            assert(mascot_secret_abort_upstream_file_sha256(
                       kind, abort_class).size() == 64);
        }
    }

    const auto status = p1_mascot_abort_terminal_manifest_source_status();
    assert(status.canonical_abort_v1_encoding);
    assert(status.exact_selected_source_identities);
    assert(status.exact_round1_regeneration_prefix);
    assert(status.exact_round2_cache_hit_prefix);
    assert(status.exact_ot_failure_variants);
    assert(status.exact_mac_failure_variants);
    assert(status.no_caller_branch_count_digest_path_or_bytes);
    assert(status.returned_worker_failure_publication_and_join);
    assert(status.constructor_failure_cleanup_and_join);
    assert(!status.unbounded_stuck_worker_terminal_closure);
    assert(status.all_family_compiler_consumes_authority);
    assert(!status.selected_role_child_callsite);
    assert(!status.postrun_exact_abort_match);
    assert(!status.configured);
    assert(status.actual_abort_manifest_mint);
}
