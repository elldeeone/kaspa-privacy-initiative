#include "../../p1_context_state_hook.hpp"

#include <cstdint>
#include <span>

namespace state = kpi::mpc::p1_private_state;

// This deliberately must not compile.  Merely taking the future adapter's
// exact qualified name must not create a friend seam before that adapter has a
// complete, source-owned definition.
namespace kpb::measurement::p1_state_capsule {

class P1ContextAndRetryStateAdapter final
        : public state::ContextAndRetryStateHook {
    void context_constructed(std::span<const unsigned char>) override {}
    void context_transition(
        state::ContextTransition, std::uint64_t, std::uint64_t,
        std::span<const unsigned char>) override {}
    void context_terminal(std::span<const unsigned char>) override {}
    void context_unavailable_noexcept() noexcept override {}
};

} // namespace kpb::measurement::p1_state_capsule

int main() {
    kpb::measurement::p1_state_capsule::P1ContextAndRetryStateAdapter
        forbidden;
    (void)forbidden;
}
