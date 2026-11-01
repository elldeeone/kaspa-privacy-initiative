#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"

#include <algorithm>
#include <cassert>
#include <type_traits>

using namespace kpb::measurement;
using namespace kpb::measurement::p1_state;
using namespace kpb::measurement::p1_state_capsule;

int main() {
    static_assert(!std::is_default_constructible_v<
        P1MascotAbortTerminalManifestAuthority>);
    static_assert(!std::is_copy_constructible_v<
        P1MascotAbortTerminalManifestAuthority>);
    static_assert(std::is_move_constructible_v<
        P1MascotAbortTerminalManifestAuthority>);

    auto first =
        P1MascotAbortTerminalManifestCompilerBridge::test_only_compile();
    const auto one = first.test_only_summary();
    assert(one.round_prefixes[0].disposition ==
           AbortFamilyDisposition::TerminalPrefix);
    assert(one.round_prefixes[0].exact_object_count == 1);
    assert(one.round_prefixes[0].exact_event_count == 12);
    assert(one.round_prefixes[0].exact_transition_count == 11);
    assert(one.round_prefixes[1].exact_object_count == 1);
    assert(one.round_prefixes[1].exact_event_count == 11);
    assert(one.round_prefixes[1].exact_transition_count == 10);
    for (unsigned round = 0; round < 2; ++round) {
        assert(one.variant_counts[round][0] == 3);
        assert(one.variant_counts[round][1] == 3);
        assert(one.manifest_identities[round][0] != Digest{});
        assert(one.manifest_identities[round][1] != Digest{});
        assert(one.manifest_identities[round][0] !=
               one.manifest_identities[round][1]);
    }
    assert(one.manifest_identities[0][0] !=
           one.manifest_identities[1][0]);
    assert(one.combined_manifest_identity != Digest{});
    assert(one.exact_unlink_outcome);
    assert(one.exact_returned_worker_epochs);
    assert(one.constructor_failure_join);
    assert(!one.stuck_worker_terminal_closure);
    assert(!one.selected_callsite);
    assert(!one.compiler_consumed);

    auto replay =
        P1MascotAbortTerminalManifestCompilerBridge::test_only_compile();
    const auto two = replay.test_only_summary();
    assert(two.round_prefixes == one.round_prefixes);
    assert(two.variant_counts == one.variant_counts);
    assert(two.manifest_identities == one.manifest_identities);
    assert(two.combined_manifest_identity == one.combined_manifest_identity);

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
    assert(!status.all_family_compiler_consumes_authority);
    assert(!status.selected_role_child_callsite);
    assert(!status.postrun_exact_abort_match);
    assert(!status.configured);
    assert(!status.actual_abort_manifest_mint);
}
