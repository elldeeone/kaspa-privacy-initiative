#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"

#include <cassert>
#include <concepts>
#include <type_traits>

namespace p1 = kpb::measurement::p1_state;
namespace policy = kpb::measurement::prelaunch_policy_domain;
namespace registered = kpi::mpc::financial::registered_driver;
namespace capsule = kpb::measurement::p1_state_capsule;

using Contract = p1::P1StateCapsulePrelaunchCompilerContract;
static_assert(std::same_as<Contract::SelectedPrelaunchAuthority,
                           registered::
                               RegisteredSelectedProducerPrelaunchBindingAuthority>);
static_assert(std::same_as<Contract::PolicyDomainAuthority,
                           policy::RegisteredPrelaunchPolicyDomainAuthority>);
static_assert(std::same_as<Contract::HookSerializerManifestAuthority,
                           p1::P1HookSerializerManifestAuthority>);
static_assert(std::same_as<Contract::AbortTerminalManifestAuthority,
                           p1::P1AbortTerminalManifestAuthority>);
static_assert(std::same_as<Contract::RoundPlanAuthority,
                           capsule::P1CorruptStateCapsulePlanAuthority>);
static_assert(std::same_as<Contract::OutputAuthority,
                           p1::P1StateCapsulePrelaunchSplit>);

template<class T> concept HasPlan = requires(T& value) { value.plan(); };
template<class T> concept HasDigest = requires(T& value) { value.digest(); };
template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasCompile = requires { &T::compile; };

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
              p1::P1StateCapsulePrelaunchSplit>);
static_assert(!std::copy_constructible<
              p1::P1StateCapsulePrelaunchSplit>);
static_assert(std::move_constructible<
              p1::P1StateCapsulePrelaunchSplit>);

static_assert(!HasPlan<p1::P1HookSerializerManifestAuthority>);
static_assert(!HasDigest<p1::P1HookSerializerManifestAuthority>);
static_assert(!HasFd<p1::P1HookSerializerManifestAuthority>);
static_assert(!HasPlan<p1::P1AbortTerminalManifestAuthority>);
static_assert(!HasDigest<p1::P1AbortTerminalManifestAuthority>);
static_assert(!HasFd<p1::P1AbortTerminalManifestAuthority>);
static_assert(!HasPlan<p1::P1StateCapsulePrelaunchSplit>);
static_assert(!HasDigest<p1::P1StateCapsulePrelaunchSplit>);
static_assert(!HasFd<p1::P1StateCapsulePrelaunchSplit>);
static_assert(!HasCompile<p1::P1StateCapsulePrelaunchCompilerBridge>);

int main() {
    const auto status =
        p1::p1_state_capsule_prelaunch_compiler_status();
    assert(status.complete_bridge_name_before_friendship);
    assert(status.exact_future_type_vocabulary);
    assert(status.selected_prelaunch_required);
    assert(status.source_policy_domain_required);
    assert(status.fourteen_family_hook_serializer_manifest_required);
    assert(status.abort_terminal_manifest_required);
    assert(status.retained_producer_plus_two_round_plans_required);
    assert(status.role1_round1_round2_only_required);
    assert(status.writerless_before_topology_transfer_required);
    assert(status.stale_swapped_partial_replay_burn_controls_required);
    assert(!status.caller_static_plan_or_event_factory);
    assert(!status.caller_digest_path_bytes_or_fd_input);
    assert(!status.hook_serializer_manifest_source_minter);
    assert(!status.abort_terminal_manifest_source_minter);
    assert(!status.capsule_plan_compiler_implemented);
    assert(!status.atomic_activation_split_implemented);
    assert(!status.stale_lineage_control);
    assert(!status.swapped_round_control);
    assert(!status.partial_manifest_control);
    assert(!status.replay_burn_control);
    assert(!status.selected_parent_callsite);
    assert(!status.configured);
    assert(!status.actual_plan_mint);
}
