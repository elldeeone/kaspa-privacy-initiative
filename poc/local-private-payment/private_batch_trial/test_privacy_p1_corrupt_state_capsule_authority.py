#!/usr/bin/env python3
"""Controls for the CONFIGURED0 observer-v5 P1 state capsule."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent / "mpc-prover"


class P1CorruptStateCapsuleAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False, sanitize=False,
                fixture_library=False):
        command = [
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-pthread",
        ]
        if test_setup:
            command.append("-DKPB_P1_STATE_CAPSULE_TEST_SETUP")
        if fixture_library:
            command.append("-DKPB_P1_STATE_CAPSULE_FIXTURE_LIBRARY")
        if sanitize:
            command.extend([
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            ])
        command.extend(str(source) for source in sources)
        command.extend([
            "-I", str(HERE), "-I", str(MPC), "-lcrypto", "-o", str(output),
        ])
        return subprocess.run(
            command, capture_output=True, text=True, check=False)

    def production_sources(self):
        return (
            HERE / "privacy_p1_corrupt_state_capsule_authority.cpp",
            MPC / "p1_mascot_secret_state_hook.cpp",
            HERE / "privacy_measurement_authority.cpp",
            HERE / "privacy_measurement_child_output_authority.cpp",
            HERE / "privacy_measurement_output_abi.cpp",
        )

    def test_success_abort_state_machine_and_hostile_controls(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-state-") as directory:
            binary = Path(directory) / "control"
            compiled = self.compile(
                binary,
                HERE / "privacy_p1_corrupt_state_capsule_authority_control.cpp",
                *self.production_sources(), test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=30)
            self.assertEqual(
                (run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_control_is_asan_ubsan_clean(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-state-san-") as directory:
            binary = Path(directory) / "control"
            compiled = self.compile(
                binary,
                HERE / "privacy_p1_corrupt_state_capsule_authority_control.cpp",
                *self.production_sources(), test_setup=True, sanitize=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=30)
            self.assertEqual(
                (run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_control_only_unavailable_fixture_uses_real_close(self):
        with tempfile.TemporaryDirectory(
                prefix="kpb-p1-state-fixture-") as directory:
            directory = Path(directory)
            source = directory / "fixture.cpp"
            source.write_text(r'''
#include "privacy_p1_corrupt_state_capsule_test_fixture.hpp"
#include <cassert>
using namespace kpb::measurement::p1_state_capsule;
int main() {
    try {
        auto round1 = test_fixture::closed_unavailable(1);
        assert(!round1.test_only_summary().manifest_structurally_complete);
    } catch (...) { return 11; }
    try {
        auto round2 = test_fixture::closed_unavailable(2);
        assert(!round2.test_only_summary().manifest_structurally_complete);
    } catch (...) { return 12; }
    bool refused = false;
    try {
        auto wrong = test_fixture::closed_unavailable(0);
        (void)wrong;
    } catch (const kpb::measurement::Refused&) { refused = true; }
    assert(refused);
}
''', encoding="utf-8")
            binary = directory / "fixture"
            compiled = self.compile(
                binary, source,
                HERE / "privacy_p1_corrupt_state_capsule_authority_control.cpp",
                *self.production_sources(), test_setup=True,
                fixture_library=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=30)
            self.assertEqual(
                (run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_production_surface_has_no_minter_or_private_state_accessor(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-state-surface-") as d:
            directory = Path(d)
            source = directory / "surface.cpp"
            source.write_text(r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include <concepts>
#include <utility>
using namespace kpb::measurement::p1_state_capsule;
template<class T> concept HasTestMint = requires { T::test_only_mint({}); };
template<class T> concept HasSummary = requires(const T& value) {
    value.test_only_summary();
};
template<class T> concept HasRead = requires(const T& value) {
    value.test_only_read_all();
};
template<class T> concept HasFd = requires(const T& value) { value.fd(); };
template<class T> concept HasHash = requires(const T& value) {
    value.archive_sha256();
};
template<class T> concept HasPath = requires(const T& value) { value.path(); };
template<class T> concept HasComplete = requires(const T& value) {
    value.complete();
};
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasProjections = requires(const T& value) {
    value.projections;
};
template<class T> concept HasTestConstructed = requires(T& value) {
    value.test_only_constructed(std::span<const unsigned char>{});
};
template<class T> concept HasRawAbortPrepare = requires(
        T& value, kpb::measurement::Digest identity) {
    value.prepare_abort_terminal(
        identity, AbortClass::Protocol, identity);
};
template<class T> concept HasTestTerminalSiteMint = requires(
        T& value, kpb::measurement::Digest identity) {
    value.test_only_mint_abort_terminal_site(
        identity, AbortClass::Protocol, identity);
};
template<class T> concept HasDispositionConsume = requires(T&& value) {
    std::move(value).consume_for_child_disposition();
};
template<class T> concept HasNoArgBegin = requires(T&& value) {
    std::move(value).begin_before_player_and_protocol_setup();
};
template<class T> concept HasRawPlayerBind = requires(
        T& value, const P1StateThreadEpochAuthority& thread) {
    value.bind_root_player(
        thread, std::span<const unsigned char>{});
};
static_assert(!HasTestMint<P1CorruptStateCapsulePlanAuthority>);
static_assert(!HasSummary<P1CorruptStateCapsuleAuthority>);
static_assert(!HasRead<P1CorruptStateCapsuleAuthority>);
static_assert(!HasFd<P1CorruptStateCapsuleAuthority>);
static_assert(!HasHash<P1CorruptStateCapsuleAuthority>);
static_assert(!HasPath<P1CorruptStateCapsuleAuthority>);
static_assert(!HasComplete<P1CorruptStateCapsuleAuthority>);
static_assert(!HasReceipt<P1CorruptStateCapsuleAuthority>);
static_assert(!HasTestConstructed<P1ContextAndRetryStateAdapter>);
static_assert(!HasRawAbortPrepare<P1CorruptStateRecorderAuthority>);
static_assert(!HasTestTerminalSiteMint<P1CorruptStateRecorderAuthority>);
static_assert(!HasDispositionConsume<P1CorruptStateCapsuleAuthority>);
static_assert(!HasNoArgBegin<P1CorruptStateCapsulePlanAuthority>);
static_assert(!HasRawPlayerBind<P1CorruptStateRecorderAuthority>);
static_assert(!std::copy_constructible<P1CorruptStateCapsulePlanAuthority>);
static_assert(!std::copy_constructible<P1CorruptStateRecorderAuthority>);
static_assert(!std::copy_constructible<P1CorruptStateCapsuleAuthority>);
static_assert(!HasProjections<P1StateCapsulePrelaunchBinding>);
static_assert(!std::default_initializable<
              P1StateCapsulePostrunResidualAuthority>);
static_assert(!std::default_initializable<P1ContextAndRetryStateAdapter>);
static_assert(!std::copy_constructible<P1ContextAndRetryStateAdapter>);
static_assert(!std::default_initializable<P1PlayerTlsStateAdapter>);
static_assert(!std::copy_constructible<P1PlayerTlsStateAdapter>);
static_assert(!std::default_initializable<P1EntropyStateAdapter>);
static_assert(!std::copy_constructible<P1EntropyStateAdapter>);
static_assert(!std::default_initializable<P1AbortTerminalSiteAuthority>);
static_assert(!std::copy_constructible<P1AbortTerminalSiteAuthority>);
static_assert(!std::default_initializable<
              P1CorruptStateCapsuleChildDispositionResidual>);
static_assert(!std::copy_constructible<
              P1CorruptStateCapsuleChildDispositionResidual>);
static_assert(!HasFd<P1CorruptStateCapsuleChildDispositionResidual>);
static_assert(!HasHash<P1CorruptStateCapsuleChildDispositionResidual>);
static_assert(!HasComplete<P1CorruptStateCapsuleChildDispositionResidual>);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.source_only_capsule_authority);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.chronology_correct_prelaunch_binding);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.source_owned_prelaunch_minter);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.role1_activation_attachment);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.role0_role2_compiletime_absence);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.postrun_projection_exit_residual);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.begins_before_player_construction);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.success_and_abort_close);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.phase_bound_abort);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.terminal_specific_abort_prefixes);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.opaque_terminal_site_authority);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.source_owned_terminal_site_minter);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.thread_join_required);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.hook_manifest_inventory_enforced);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.source_family_missing_disposition_grammar);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.missing_family_cannot_complete);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.source_owned_hook_manifest_minter);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.context_retry_capsule_adapter);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.entropy_ingress_capsule_adapter);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.player_tls_prefix_capsule_adapter);
static_assert(kpi::mpc::p1_private_state::kContextStateHookSourceStatus.production_adapter_construction);
static_assert(kpi::mpc::p1_private_state::kContextStateHookSourceStatus.capsule_family_adapter);
static_assert(kpb::measurement::p1_state_capsule::kSourceStatus.unavailable_partial_retained);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.parent_held_preidentity_archive);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.fatal_signal_retention);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.topology_archive_consumed);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.pinned_upstream_serializers);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.live_registered_success_hook);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.live_registered_abort_hook);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.replay_sufficiency_verified);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.complete_passive_p1_view);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.selected_observer_consumer);
static_assert(!kpb::measurement::p1_state_capsule::kSourceStatus.configured);
int main() {}
''', encoding="utf-8")
            binary = directory / "surface"
            compiled = self.compile(binary, source, *self.production_sources())
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_complete_friend_cannot_be_redefined_or_directly_mint(self):
        probes = {
            "friend": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredP1StateCapsuleChildDispositionBridge final {
public: RegisteredP1StateCapsuleChildDispositionBridge() = delete;
};
}
int main() {}
''',
            "capsule": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using namespace kpb::measurement::p1_state_capsule;
int main() { P1CorruptStateCapsuleAuthority value(nullptr); }
''',
            "plan": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using namespace kpb::measurement::p1_state_capsule;
int main() { P1CorruptStateCapsulePlanAuthority value(nullptr); }
''',
            "adapter_redefinition": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1ContextAndRetryStateAdapter final {};
}
int main() {}
''',
            "adapter_constructor": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using namespace kpb::measurement::p1_state_capsule;
int main() { P1ContextAndRetryStateAdapter value(nullptr); }
''',
            "context_standalone_recorder": r'''
#include "p1_context_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority {
public:
  static P1ContextAndRetryStateAdapter steal() {
    return P1ContextAndRetryStateAdapter(nullptr);
  }
};
}
int main() {}
''',
            "context_standalone_factory": r'''
#include "p1_context_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1ContextAndRetryStateAdapterFactoryBridge final {};
}
int main() {}
''',
            "player_tls_adapter_redefinition": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1PlayerTlsStateAdapter final {};
}
int main() {}
''',
            "player_tls_adapter_constructor": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using namespace kpb::measurement::p1_state_capsule;
int main() { P1PlayerTlsStateAdapter value(nullptr); }
''',
            "terminal_source_redefinition": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1AbortTerminalSourceBridge final {};
}
int main() {}
''',
            "terminal_site_constructor": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using namespace kpb::measurement::p1_state_capsule;
int main() { P1AbortTerminalSiteAuthority value(nullptr); }
''',
            "child_residual_constructor": r'''
#include "privacy_p1_corrupt_state_capsule_authority.hpp"
using namespace kpb::measurement::p1_state_capsule;
int main() { P1CorruptStateCapsuleChildDispositionResidual value(nullptr); }
''',
            "child_residual_internal_access": r'''
#include "privacy_p1_corrupt_state_capsule_child_disposition_internal.hpp"
using namespace kpb::measurement::p1_state_capsule;
bool leak(const P1CorruptStateCapsuleChildDispositionResidual& value) {
    return value.storage_->complete;
}
int main() {}
''',
        }
        with tempfile.TemporaryDirectory(prefix="kpb-p1-state-forge-") as d:
            directory = Path(d)
            for name, body in probes.items():
                with self.subTest(name=name):
                    source = directory / f"{name}.cpp"
                    source.write_text(body, encoding="utf-8")
                    compiled = self.compile(
                        directory / name, source, *self.production_sources())
                    self.assertNotEqual(compiled.returncode, 0)

    def test_archive_has_no_operational_cap_and_tls_is_not_omitted(self):
        header = (HERE / (
            "privacy_p1_corrupt_state_capsule_authority.hpp"
        )).read_text(encoding="utf-8")
        source = (HERE / (
            "privacy_p1_corrupt_state_capsule_authority.cpp"
        )).read_text(encoding="utf-8")
        combined = header + source
        for token in (
            "TlsChannelState", "TlsHandshake", "TlsReadWrite",
            "openssl_source_identity", "QueryMsmCheckerTemporaries",
            "PlayerAllocation", "MascotSecrets", "SimplestOtBase",
            "SoftSpokenExtended", "MacCheck", "ContextAndRetry",
        ):
            self.assertIn(token, combined)
        self.assertIn("O_TMPFILE", source)
        self.assertIn("::fsync(", source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertNotIn("memfd_create(", source)
        self.assertNotIn("fallocate(", source)
        self.assertNotIn("posix_fallocate(", source)
        for forbidden in (
            "MAX_ARCHIVE", "MAX_CAPSULE", "max_archive_bytes",
            "max_state_bytes",
        ):
            self.assertNotIn(forbidden, combined)

        begin = source.index(
            "begin_before_player_and_protocol_setup() &&")
        close = source.index("close_noexcept(bool aborted) && noexcept")
        close_end = source.index(
            "close_success_noexcept() && noexcept", close)
        self.assertLess(
            source.index("std::make_unique<P1CorruptStateCapsuleAuthority::Storage>", begin),
            source.index("open_anonymous_disk_file()", begin))
        close_body = source[close:close_end]
        self.assertNotIn("make_unique", close_body)
        self.assertNotIn("new (std::nothrow)", close_body)
        self.assertNotIn("result->plan =", close_body)
        self.assertIn("descriptor_retained = true", close_body)
        production_begin = source.index(
            "P1StateArchiveWriterAdoptionAuthority&& adoption")
        writer_claim = source.index(
            "ledger->fd = adoption_storage->writer", production_begin)
        paired_burn = source.index(
            "std::exchange(adoption_storage->live, false)", production_begin)
        self.assertLess(paired_burn, source.index(
            "validate_plan(selected_plan)", production_begin))
        self.assertLess(
            source.index("preallocate_child_disposition", production_begin),
            writer_claim)
        disposition = source.index("consume_for_child_disposition() &&")
        disposition_end = source.index(
            "#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP", disposition)
        self.assertNotIn("make_unique", source[disposition:disposition_end])


if __name__ == "__main__":
    unittest.main()
