#pragma once

// Complete, source-owned consumers of private activation authorities. Keeping
// these class definitions in the authority include graph prevents a hostile
// translation unit from defining a forward-only friend with the same name.

#include <cstdint>

namespace kpi::mpc::financial::registered_driver::projection_route {
class NativeTerminalRetainedProjectionAuthority;
}

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
class BaselineTerminalOwnerMappingAuthority;
}

namespace kpb::testnet_activation {
class NativeCandidateCompletionAuthority;
}

namespace kpb::native_terminal {

struct NativeTerminalSelection;
struct PaymentTerminalSelection;
class NativeTerminalChildProjectionEvidence;
class PaymentLifecycleCompletionAuthority;
class MatchedNativeTerminalProducerBundle;
class NativeTerminalProducerBundle;

enum class TestNativeTerminalFault : unsigned char {
    None = 0,
    WrongAckOffer = 1,
    CredentialRelay = 2,
    WrongCompletionKind = 3,
    WrongInputHead = 4,
    WrongProjection = 5,
    WrongCore = 6,
    WrongProof = 7,
    WrongR0 = 8,
    WrongNativeFull = 9,
    WrongConservation = 10,
    WrongAmounts = 11,
    WrongTerminalRoot = 12,
    WrongTerminalEnd = 13,
    WrongTerminalCount = 14,
    DuplicateCompletion = 15,
    NoCompletion = 16,
    NonzeroExit = 17,
    ZeroLengthRecordBeforeClose = 18,
    WrongProjectionRoute = 19,
};

class NativeTerminalSupervisor final {
    NativeTerminalSupervisor() = delete;
    static testnet_activation::NativeCandidateCompletionAuthority
        run_genesis_with_fault(
            const NativeTerminalSelection&, int sealed_executable_fd,
            TestNativeTerminalFault);
    static PaymentLifecycleCompletionAuthority run_payment_with_fault(
        const PaymentTerminalSelection&, int sealed_executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&&,
        TestNativeTerminalFault);
    static PaymentLifecycleCompletionAuthority run_payment_with_projection(
        const PaymentTerminalSelection&, int sealed_executable_fd,
        int terminal_writer_fd, NativeTerminalChildProjectionEvidence&&,
        TestNativeTerminalFault);
public:
    static testnet_activation::NativeCandidateCompletionAuthority run_genesis(
        const NativeTerminalSelection&, int sealed_executable_fd);
    static PaymentLifecycleCompletionAuthority run_payment(
        const PaymentTerminalSelection&, int sealed_executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&&);
    static PaymentLifecycleCompletionAuthority run_payment(
        const PaymentTerminalSelection&, int sealed_executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&&,
        kpi::mpc::financial::registered_driver::baseline_disclosure::
            BaselineTerminalOwnerMappingAuthority&&);
#ifdef KPB_NATIVE_TERMINAL_COMPLETION_TEST_SETUP
    static testnet_activation::NativeCandidateCompletionAuthority
        test_only_run_genesis(
            const NativeTerminalSelection&, int sealed_executable_fd,
            TestNativeTerminalFault);
    static PaymentLifecycleCompletionAuthority test_only_run_payment(
        const PaymentTerminalSelection&, int sealed_executable_fd,
        int terminal_writer_fd,
        kpi::mpc::financial::registered_driver::projection_route::
            NativeTerminalRetainedProjectionAuthority&&,
        TestNativeTerminalFault);
#endif
};

class NativeTerminalProducerJoin final {
    NativeTerminalProducerJoin() = delete;
public:
    static NativeTerminalProducerBundle mint_from_matched(
        MatchedNativeTerminalProducerBundle&&);
};

} // namespace kpb::native_terminal
