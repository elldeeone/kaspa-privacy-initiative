#pragma once

#include "native_terminal_completion.hpp"

#include <array>
#include <optional>

namespace kpb::native_terminal::test_fixture {

struct GenuineCandidateAuthorities {
    measurement::RunBinding binding;
    testnet_activation::NativeCandidateCompletionAuthority genesis;
    std::array<testnet_activation::NativeCandidateCompletionAuthority, 2>
        payments;
    measurement::ProducerClosureAuthority producer_continuation;
};

// Runs the sealed GEN3/R1/R2 children and genuine sole-reader ten-stream
// producer. Test-only source fixture; no network, RPC, funding or broadcast.
GenuineCandidateAuthorities complete_genuine_candidate_authorities();

// The sealed memfd re-execs the test binary. A test main must delegate here
// before doing parent work when this returns a value.
std::optional<int> run_selected_child();

} // namespace kpb::native_terminal::test_fixture
