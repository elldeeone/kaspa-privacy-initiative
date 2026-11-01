#include "../registered_p1_state_archive_scm.hpp"
#include "../registered_parent_role_fork.hpp"
#include "../../../private_batch_trial/privacy_p1_corrupt_state_capsule_test_fixture.hpp"
#include "../../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <concepts>
#include <cstdlib>
#include <new>
#include <utility>

using namespace kpi::mpc::financial::registered_driver;

namespace {

std::atomic_bool deny_allocations{};

void allocation_gate(bool deny) noexcept {
    deny_allocations.store(deny, std::memory_order_relaxed);
}

[[noreturn]] void runtime_failure_probe(
        RegisteredRole1P1StateRecorderFacade&) {
    throw std::bad_alloc();
}

void* allocate(std::size_t size) {
    if (deny_allocations.load(std::memory_order_relaxed))
        throw std::bad_alloc();
    if (void* value = std::malloc(size == 0 ? 1 : size)) return value;
    throw std::bad_alloc();
}

} // namespace

void* operator new(std::size_t size) { return allocate(size); }
void* operator new[](std::size_t size) { return allocate(size); }
void operator delete(void* value) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void operator delete[](void* value, std::size_t) noexcept { std::free(value); }

template<class T>
concept HasFd = requires(const T& value) { value.fd(); };

template<class T>
concept HasDigest = requires(const T& value) { value.digest(); };

template<class T>
concept HasP1StatePrelaunch = requires(T& value) {
    value.take_p1_state_prelaunch();
};

int main() {
    static_assert(!std::default_initializable<
                  RegisteredP1StateArchiveScmTransfer>);
    static_assert(!std::copy_constructible<
                  RegisteredP1StateArchiveScmTransfer>);
    static_assert(!std::default_initializable<
                  RegisteredP1StateArchiveChildRoundAuthority>);
    static_assert(!std::copy_constructible<
                  RegisteredP1StateArchiveChildRoundAuthority>);
    static_assert(!std::default_initializable<
                  RegisteredP1StateArchiveParentRoundAuthority>);
    static_assert(!std::copy_constructible<
                  RegisteredP1StateArchiveParentRoundAuthority>);
    static_assert(!HasFd<RegisteredP1StateArchiveScmTransfer>);
    static_assert(!HasFd<RegisteredP1StateArchiveChildRoundAuthority>);
    static_assert(!HasFd<RegisteredP1StateArchiveParentRoundAuthority>);
    static_assert(!HasDigest<RegisteredP1StateArchiveScmTransfer>);
    static_assert(!std::default_initializable<
                  RegisteredRole1P1StatePrelaunchAuthority>);
    static_assert(!std::copy_constructible<
                  RegisteredRole1P1StatePrelaunchAuthority>);
    static_assert(!HasFd<RegisteredRole1P1StatePrelaunchAuthority>);
    static_assert(!HasDigest<RegisteredRole1P1StatePrelaunchAuthority>);
    static_assert(!HasP1StatePrelaunch<ParentAuthenticatedRole0Delivery>);
    static_assert(HasP1StatePrelaunch<ParentAuthenticatedRole1Delivery>);
    static_assert(!HasP1StatePrelaunch<ParentAuthenticatedRole2Delivery>);
    static_assert(!std::default_initializable<
                  RegisteredRole1P1StateRuntimeAuthority>);
    static_assert(!std::copy_constructible<
                  RegisteredRole1P1StateRuntimeAuthority>);
    static_assert(!HasFd<RegisteredRole1P1StateRuntimeAuthority>);
    static_assert(!HasDigest<RegisteredRole1P1StateRuntimeAuthority>);
    static_assert(!std::default_initializable<
                  RegisteredRole1P1StateRecorderFacade>);
    static_assert(!std::copy_constructible<
                  RegisteredRole1P1StateRecorderFacade>);
    static_assert(!std::move_constructible<
                  RegisteredRole1P1StateRecorderFacade>);
    static_assert(std::same_as<
        decltype(std::declval<
            RegisteredRole1P1StateRuntimeAuthority&>().recorder()),
        RegisteredRole1P1StateRecorderFacade&>);
    static_assert(!std::default_initializable<
                  P1StateArchiveWriterAdoptionBundle>);
    static_assert(!std::copy_constructible<
                  P1StateArchiveWriterAdoptionBundle>);
    static_assert(noexcept(
        std::declval<P1StateArchiveWriterAdoptionBundle&&>().split()));
    static_assert(!std::default_initializable<
                  P1StateArchiveWriterAdoptionAuthority>);
    static_assert(!std::copy_constructible<
                  P1StateArchiveWriterAdoptionAuthority>);
    static_assert(!std::default_initializable<
                  RegisteredP1StateArchiveChildTerminalAuthority>);
    static_assert(!std::copy_constructible<
                  RegisteredP1StateArchiveChildTerminalAuthority>);
    static_assert(!HasFd<P1StateArchiveWriterAdoptionAuthority>);
    static_assert(!HasFd<RegisteredP1StateArchiveChildTerminalAuthority>);
    static_assert(!kRegisteredP1StateArchiveScmSourceStatus.configured);
    static_assert(!kRegisteredP1StateArchiveScmSourceStatus.
                      selected_activation_callsite);
    static_assert(!kRegisteredP1StateArchiveScmSourceStatus.
                      genuine_capsule_terminal_source);

    {
        auto reservation = FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
        auto topology = std::move(reservation)
            .test_only_take_activation_transfer();
        assert(RegisteredP1StateArchiveScmBridge::
            test_only_round2_extraction_failure_retains_all(topology));
    }

    constexpr std::array faults{
        RegisteredP1StateArchiveScmTestFault::None,
        RegisteredP1StateArchiveScmTestFault::WrongRole,
        RegisteredP1StateArchiveScmTestFault::SubstitutedWriter,
        RegisteredP1StateArchiveScmTestFault::TerminalReplay,
        RegisteredP1StateArchiveScmTestFault::TerminalTruncated,
        RegisteredP1StateArchiveScmTestFault::ChildDeath,
        RegisteredP1StateArchiveScmTestFault::AdoptionAppendMode,
        RegisteredP1StateArchiveScmTestFault::AdoptionNonzeroSize,
        RegisteredP1StateArchiveScmTestFault::PostCapsuleAllocationDenied,
        RegisteredP1StateArchiveScmTestFault::WrongAdoptionRound,
        RegisteredP1StateArchiveScmTestFault::WrongAdoptionReservation,
        RegisteredP1StateArchiveScmTestFault::PreAdoptionAllocationDenied,
        RegisteredP1StateArchiveScmTestFault::StalePlanFreshChild,
        RegisteredP1StateArchiveScmTestFault::StaleChildFreshPlan,
        RegisteredP1StateArchiveScmTestFault::
            RuntimeBeginAllocationDenied,
        RegisteredP1StateArchiveScmTestFault::
            SubstitutedParentTrialExpectation,
        RegisteredP1StateArchiveScmTestFault::
            SubstitutedParentPrelaunchExpectation,
        RegisteredP1StateArchiveScmTestFault::RuntimeFailureProbeThrows,
    };
    for (const auto fault : faults) {
        auto reservation = FreshTrialCaptureTopologyReservationBridge::
            test_only_reserve_unbound();
        auto topology = std::move(reservation)
            .test_only_take_activation_transfer();
        const auto summary = RegisteredP1StateArchiveScmBridge::
            test_only_run(
                topology, fault,
                &kpb::measurement::p1_state_capsule::test_fixture::
                    closed_unavailable_adopting,
                &kpb::measurement::p1_state_capsule::test_fixture::
                    wrong_round_adoption_refused,
                &kpb::measurement::p1_state_capsule::test_fixture::
                    wrong_reservation_adoption_refused,
                &kpb::measurement::p1_state_capsule::test_fixture::
                    matching_plan_for_adoption,
                &allocation_gate, &runtime_failure_probe);
        assert(summary.expected_result);
        assert(summary.exact_two_parent_reads_retained);
        assert(summary.child_exited);
        if (fault == RegisteredP1StateArchiveScmTestFault::WrongRole ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         SubstitutedWriter ||
            fault == RegisteredP1StateArchiveScmTestFault::ChildDeath ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         AdoptionAppendMode ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         WrongAdoptionRound ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         WrongAdoptionReservation ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         PreAdoptionAllocationDenied ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         StalePlanFreshChild ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         StaleChildFreshPlan ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         RuntimeBeginAllocationDenied)
            assert(summary.exact_two_parent_reads_empty);
        if (fault == RegisteredP1StateArchiveScmTestFault::None ||
            fault == RegisteredP1StateArchiveScmTestFault::
                         PostCapsuleAllocationDenied) {
            assert(summary.authenticated_activation_acks == 2);
            assert(summary.typed_authenticated_dispositions == 2);
            assert(summary.typed_same_inode_dispositions == 2);
            assert(summary.terminal_ack_before_pidfd_wait);
            if (fault == RegisteredP1StateArchiveScmTestFault::
                             PostCapsuleAllocationDenied)
                assert(summary.post_capsule_allocation_denial_control);
        } else if (fault ==
                   RegisteredP1StateArchiveScmTestFault::WrongRole ||
                   fault == RegisteredP1StateArchiveScmTestFault::
                                SubstitutedWriter) {
            assert(summary.authenticated_activation_acks == 0);
            assert(summary.typed_authenticated_dispositions == 0);
        } else if (fault ==
                   RegisteredP1StateArchiveScmTestFault::ChildDeath) {
            assert(summary.authenticated_activation_acks == 2);
            assert(summary.typed_authenticated_dispositions == 0);
        } else if (fault == RegisteredP1StateArchiveScmTestFault::
                                RuntimeBeginAllocationDenied) {
            assert(summary.authenticated_activation_acks == 2);
            assert(summary.typed_authenticated_dispositions == 2);
            assert(summary.typed_same_inode_dispositions == 0);
            assert(summary.terminal_ack_before_pidfd_wait);
        } else if (fault == RegisteredP1StateArchiveScmTestFault::
                                RuntimeFailureProbeThrows) {
            assert(summary.authenticated_activation_acks == 2);
            assert(summary.typed_authenticated_dispositions == 1);
            assert(summary.typed_same_inode_dispositions == 1);
            assert(summary.terminal_ack_before_pidfd_wait);
        } else if (fault == RegisteredP1StateArchiveScmTestFault::
                                StalePlanFreshChild) {
            assert(summary.authenticated_activation_acks == 2);
            // Attachment burns both halves before validation; a stale plan
            // cannot preserve the fresh child endpoint or mint a fallback.
            assert(summary.typed_authenticated_dispositions == 0);
            assert(summary.typed_same_inode_dispositions == 0);
        } else {
            assert(summary.authenticated_activation_acks == 2);
            assert(summary.typed_authenticated_dispositions == 0);
        }
    }
}
