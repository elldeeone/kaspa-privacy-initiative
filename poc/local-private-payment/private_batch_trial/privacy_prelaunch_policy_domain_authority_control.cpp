#include "privacy_prelaunch_policy_domain_authority.hpp"

#include <algorithm>
#include <cassert>

namespace policy = kpb::measurement::prelaunch_policy_domain;

int main() {
    auto authority =
        policy::RegisteredPrelaunchPolicyDomainSourceBridge::acquire();
    const auto summary =
        policy::RegisteredPrelaunchPolicyDomainSourceBridge::test_only_consume(
            std::move(authority));
    const auto nonzero = [](const policy::PolicyDigest& value) {
        return std::any_of(value.begin(), value.end(),
            [](unsigned char byte) { return byte != 0; });
    };
    assert(nonzero(summary.accepted_head_policy_identity));
    assert(nonzero(summary.selected_main_policy_identity));
    assert(nonzero(summary.source_manifest_identity));
    assert(summary.accepted_head_policy_identity !=
           summary.selected_main_policy_identity);
    bool replay_refused{};
    try {
        (void)policy::RegisteredPrelaunchPolicyDomainSourceBridge::
            test_only_consume(std::move(authority));
    } catch (...) { replay_refused = true; }
    assert(replay_refused);
}
