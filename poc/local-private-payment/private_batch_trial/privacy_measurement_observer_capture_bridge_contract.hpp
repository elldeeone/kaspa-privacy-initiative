#pragma once

// Complete, dependency-neutral contract for the sole observer admission and
// capsule bridge. Authorities include this before granting friendship.

#include <array>
#include <cstdint>

namespace kpb::native_terminal {
class TerminalV2ModelAdmissionAuthority;
}
namespace kpb::measurement {
class ObserverPermitAuthority;
class ProducerClosureAuthority;
struct PublicObserverPermit;
class TrialCaptureJoiner;
namespace producer_supervisor {
class ProducerSpoolAuthority;
class C03RoleLaunchAdmissionAuthority;
struct C03RoleLaunchRoundBinding;
}
namespace producer_archive { class ProducerSealedArchiveAuthority; }
namespace c1_capture { class C1PostcaptureAdmissionAuthority; }
namespace runtime_bridge {
class ObserverAdmissionAuthority;
class ObserverTerminalCaptureJoin;
class ObserverCaptureCapsuleHandoff;

class ObserverCaptureCapsuleBridge final {
    ObserverCaptureCapsuleBridge() = delete;
    static int snapshot_spool(
        ObserverAdmissionAuthority&, const PublicObserverPermit&);
public:
    static ObserverAdmissionAuthority admit(
        producer_archive::ProducerSealedArchiveAuthority&&,
        producer_supervisor::C03RoleLaunchAdmissionAuthority&&,
        c1_capture::C1PostcaptureAdmissionAuthority&& round1,
        c1_capture::C1PostcaptureAdmissionAuthority&& round2);
#ifdef KPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP
    static ObserverAdmissionAuthority admit(
        producer_supervisor::ProducerSpoolAuthority&&,
        producer_supervisor::C03RoleLaunchAdmissionAuthority&&,
        c1_capture::C1PostcaptureAdmissionAuthority&& round1,
        c1_capture::C1PostcaptureAdmissionAuthority&& round2);
#endif
    static ObserverTerminalCaptureJoin attach_terminal_v2(
        ObserverAdmissionAuthority&&,
        kpb::native_terminal::TerminalV2ModelAdmissionAuthority&&);
    static void submit_terminal_capture(
        TrialCaptureJoiner&, ObserverTerminalCaptureJoin&&);
    static ObserverCaptureCapsuleHandoff prepare(
        ObserverPermitAuthority&&, int runtime_fd,
        int canonical_source_fd, int canonical_assets_fd);
#ifdef KPB_MEASUREMENT_OBSERVER_CAPTURE_BRIDGE_TEST_SETUP
    static ObserverPermitAuthority test_only_attach_admission(
        const PublicObserverPermit&, ObserverAdmissionAuthority&&);
    static int test_only_snapshot_archive(
        ObserverAdmissionAuthority&&, const PublicObserverPermit&);
    static int test_only_prepare_archive(ObserverPermitAuthority&&);
    static producer_supervisor::C03RoleLaunchAdmissionAuthority
        test_only_c03_for_producer(
            const ProducerClosureAuthority&,
            const std::array<
                producer_supervisor::C03RoleLaunchRoundBinding, 2>&);
    static std::array<unsigned char, 32> test_only_endpoint_identity(
        const std::array<unsigned char, 32>& snapshot_hash,
        std::uint64_t snapshot_size, const PublicObserverPermit&,
        const std::array<unsigned char, 32>& nonce);
    static void test_only_force_entropy_failure(bool);
    static void test_only_force_entropy_short_read(bool);
    static void test_only_require_entropy();
#endif
};
} // namespace runtime_bridge
} // namespace kpb::measurement
