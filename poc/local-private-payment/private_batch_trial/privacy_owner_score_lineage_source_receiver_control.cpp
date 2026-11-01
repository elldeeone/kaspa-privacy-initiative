#include "privacy_owner_score_lineage_source_authority.hpp"
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"

#include <cassert>
#include <concepts>
#include <type_traits>

namespace source =
    kpb::measurement::score_output_lineage_source;
namespace registered = kpi::mpc::financial::registered_driver;

using Binding =
    registered::RegisteredSelectedProducerPrelaunchBindingAuthority;
using ReceiverSignature =
    source::AuthenticatedPrivacyLaunchLineageSourceAuthority (*)(Binding&);

static_assert(std::same_as<
    decltype(&source::PrivacyLaunchLineageSourceReceiverBridge::receive),
    ReceiverSignature>);
static_assert(!std::is_default_constructible_v<Binding>);
static_assert(!std::is_copy_constructible_v<Binding>);
static_assert(!std::is_copy_assignable_v<Binding>);
static_assert(!std::is_default_constructible_v<
    source::AuthenticatedPrivacyLaunchLineageSourceAuthority>);

int main() {
    assert(source::kOwnerScoreLineageSourceStatus.
           credentialed_receiver_transport_core);
    assert(!source::kOwnerScoreLineageSourceStatus.
           authenticated_python_receiver);
    assert(source::kOwnerScoreLineageSourceStatus.outer_attempt_source_join);
    assert(!source::kOwnerScoreLineageSourceStatus.selected_callsite);
    assert(!source::kOwnerScoreLineageSourceStatus.configured);
}
