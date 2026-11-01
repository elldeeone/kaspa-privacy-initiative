#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"

#include "privacy_p1_corrupt_state_capsule_authority.hpp"
#include "privacy_p1_mascot_abort_terminal_manifest_authority.hpp"
#include "privacy_p1_mascot_fresh_prep_directory_authority.hpp"
#include "privacy_p1_mascot_two_round_manifest_authority.hpp"
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"

#include <cassert>
#include <concepts>
#include <type_traits>

namespace p1 = kpb::measurement::p1_state;
namespace registered = kpi::mpc::financial::registered_driver;

namespace {

template<class T> concept HasPlan = requires(T& value) { value.plan(); };
template<class T> concept HasDigest = requires(T& value) { value.digest(); };
template<class T> concept HasFd = requires(T& value) { value.fd(); };

static_assert(!std::default_initializable<
              p1::P1HookSerializerManifestAuthority>);
static_assert(!std::copy_constructible<
              p1::P1HookSerializerManifestAuthority>);
static_assert(std::move_constructible<
              p1::P1HookSerializerManifestAuthority>);
static_assert(!std::default_initializable<
              p1::P1AbortTerminalManifestAuthority>);
static_assert(!std::copy_constructible<
              p1::P1AbortTerminalManifestAuthority>);
static_assert(std::move_constructible<
              p1::P1AbortTerminalManifestAuthority>);
static_assert(!std::default_initializable<
              p1::P1StateCapsulePrelaunchUnavailableAuthority>);
static_assert(!std::copy_constructible<
              p1::P1StateCapsulePrelaunchUnavailableAuthority>);
static_assert(std::move_constructible<
              p1::P1StateCapsulePrelaunchUnavailableAuthority>);
static_assert(!std::default_initializable<
              p1::P1StateCapsulePrelaunchSplit>);
static_assert(!std::copy_constructible<
              p1::P1StateCapsulePrelaunchSplit>);
static_assert(!std::move_constructible<
              p1::P1StateCapsulePrelaunchSplit>);

static_assert(!HasPlan<p1::P1HookSerializerManifestAuthority>);
static_assert(!HasDigest<p1::P1HookSerializerManifestAuthority>);
static_assert(!HasFd<p1::P1HookSerializerManifestAuthority>);
static_assert(!HasPlan<p1::P1AbortTerminalManifestAuthority>);
static_assert(!HasDigest<p1::P1AbortTerminalManifestAuthority>);
static_assert(!HasFd<p1::P1AbortTerminalManifestAuthority>);
static_assert(!HasPlan<
              p1::P1StateCapsulePrelaunchUnavailableAuthority>);
static_assert(!HasDigest<
              p1::P1StateCapsulePrelaunchUnavailableAuthority>);
static_assert(!HasFd<
              p1::P1StateCapsulePrelaunchUnavailableAuthority>);

using CompileSignature = p1::P1StateCapsulePrelaunchUnavailableAuthority (*)(
    registered::RegisteredSelectedProducerActivationResult&&);
static_assert(std::same_as<
    decltype(&p1::P1StateCapsulePrelaunchCompilerBridge::compile),
    CompileSignature>);

} // namespace

int main() {
    const auto status = p1::p1_state_capsule_prelaunch_compiler_status();
    assert(status.hostile_bridge_substitution_rejected);
    assert(status.hook_serializer_manifest_source_minter);
    assert(status.abort_terminal_manifest_source_minter);
    assert(!status.capsule_plan_compiler_implemented);
    assert(!status.atomic_activation_split_implemented);
    assert(status.fail_closed_unavailable_authority_implemented);
    assert(status.missing_epoch_authorities_recorded);
    assert(!status.stale_lineage_control);
    assert(!status.swapped_round_control);
    assert(!status.partial_manifest_control);
    assert(status.replay_burn_control);
    assert(!status.macro_free_production_caller_static_plan_or_event_factory);
    assert(!status.caller_defined_test_macro_unforgeability);
    assert(status.exact_macro_free_build_closure_required);
    assert(!status.caller_digest_path_bytes_or_fd_input);
    assert(!status.selected_parent_callsite);
    assert(!status.configured);
    assert(!status.actual_plan_mint);
}
