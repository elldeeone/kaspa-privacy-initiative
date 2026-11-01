#pragma once

#include "p1_entropy_state_hook.hpp"

#include <memory>

namespace kpi::mpc::p1_private_state {

// Process-local installation guard. Production accepts only the concrete
// recorder-owned adapter; there is no fd, path, digest, role, or raw callback
// constructor. P0/P2 never receive an adapter and cannot install it.
class EntropyIngressCapture final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit EntropyIngressCapture(std::unique_ptr<Storage>);
    static EntropyIngressCapture begin_impl(
        std::unique_ptr<EntropyStateHook>&&);

public:
    static EntropyIngressCapture begin(
        std::unique_ptr<
            ::kpb::measurement::p1_state_capsule::P1EntropyStateAdapter>&&);
#ifdef KPI_P1_ENTROPY_STATE_HOOK_TEST_SETUP
    static EntropyIngressCapture test_only_begin(
        std::unique_ptr<EntropyStateHook>&&);
#endif
    EntropyIngressCapture(const EntropyIngressCapture&) = delete;
    EntropyIngressCapture& operator=(const EntropyIngressCapture&) = delete;
    EntropyIngressCapture(EntropyIngressCapture&&) noexcept;
    EntropyIngressCapture& operator=(EntropyIngressCapture&&) = delete;
    ~EntropyIngressCapture();

    // Unregister only after every source thread has joined. Destruction without
    // this call marks the private capsule unavailable.
    bool finish_noexcept() && noexcept;
};

} // namespace kpi::mpc::p1_private_state
