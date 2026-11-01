#pragma once

// Complete narrow consumer named by the registered projection route and the
// explicit-owner baseline continuation.  The implementation is intentionally
// private: only the native supervisor may burn retained parent evidence, and
// only its authenticated child may turn the transferred body into a terminal
// mapping source.  No projection body, digest, owner row, or route identity is
// exposed through this type.

#include "native_terminal_authority_consumer_contract.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace kpi::mpc::financial::registered_driver::projection_route {
class NativeTerminalRetainedProjectionAuthority;
}

namespace kpi::mpc::financial::registered_driver {
enum class CaptureClassification : std::uint8_t;
}

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
class BaselineTerminalOwnerMappingAuthority;
}

namespace kpb::native_terminal {

struct PaymentTerminalSelection;
struct PublicPaymentTerminalOffer;
class NativeTerminalMappingSourceAuthority;
class PaymentTerminalChildProgram;
int run_payment_terminal_child(PaymentTerminalChildProgram&) noexcept;

class NativeTerminalProjectionIntake final {
    static constexpr std::size_t PROJECTION_BYTES = 10685;

    NativeTerminalProjectionIntake() = delete;

    static NativeTerminalChildProjectionEvidence consume_candidate(
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&&,
        const PaymentTerminalSelection&);

    static NativeTerminalChildProjectionEvidence consume_baseline(
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&&,
        kpi::mpc::financial::registered_driver::baseline_disclosure::
            BaselineTerminalOwnerMappingAuthority&&,
        const PaymentTerminalSelection&);

    static NativeTerminalMappingSourceAuthority admit_authenticated_child(
        NativeTerminalChildProjectionEvidence&&,
        const PublicPaymentTerminalOffer&);

    static std::array<unsigned char, 32> recompute_intake_identity(
        const NativeTerminalChildProjectionEvidence&,
        const std::array<unsigned char, 32>& trial,
        const std::array<unsigned char, 32>& outer_parent_process,
        const std::array<unsigned char, 32>& outer_parent_executable);

    friend class NativeTerminalSupervisor;
    friend int run_payment_terminal_child(PaymentTerminalChildProgram&)
        noexcept;
};

// Private retained-body continuation shared only by the two complete source-
// owned consumers above. It has no public constructor or accessor.
class NativeTerminalChildProjectionEvidence final {
    std::array<std::byte, 10685> projection{};
    std::array<unsigned char, 32> projection_identity{};
    std::array<unsigned char, 32> retained_identity{};
    std::array<unsigned char, 32> fork_binding_identity{};
    std::array<unsigned char, 32> intake_identity{};
    std::array<unsigned char, 32> owner_mapping_authority_identity{};
    std::array<std::array<unsigned char, 32>, 3> owner_nullifiers{};
    std::array<std::array<std::array<unsigned char, 32>, 2>, 3>
        owner_tuple_hashes{};
    unsigned round{};
    kpi::mpc::financial::registered_driver::CaptureClassification
        classification{};
    bool owner_mapping_present{};

    NativeTerminalChildProjectionEvidence() = default;
    friend class NativeTerminalProjectionIntake;
    friend class NativeTerminalSupervisor;
    friend int run_payment_terminal_child(PaymentTerminalChildProgram&)
        noexcept;
};

} // namespace kpb::native_terminal
