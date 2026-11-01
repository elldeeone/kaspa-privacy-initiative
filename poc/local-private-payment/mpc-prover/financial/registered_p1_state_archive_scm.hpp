#pragma once

#include "registered_p1_state_archive_scm_contract.hpp"
#include "../../private_batch_trial/privacy_measurement_authority.hpp"
#include "../../private_batch_trial/privacy_p1_corrupt_state_capsule_bridge_contract.hpp"

#include <memory>
#include <optional>
#include <cstdint>
#include <type_traits>
#include <utility>

namespace kpb::measurement::p1_state_capsule {
class P1StateThreadEpochAuthority;
class P1ContextAndRetryStateAdapter;
class P1EntropyStateAdapter;
class P1MascotSecretStateAdapter;
class P1PlayerTlsStateAdapter;
enum class SourcePhase : std::uint8_t;
}

namespace kpi::mpc::financial::registered_driver {

// Exact two-round resource transfer.  It owns both parent read descriptions
// and both sole child writer descriptions until an authenticated activation
// transport consumes them.  It has no descriptor or fingerprint getter.
class RegisteredP1StateArchiveScmTransfer final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredP1StateArchiveScmTransfer(
        std::unique_ptr<Storage>) noexcept;
    friend class RegisteredP1StateArchiveScmBridge;
public:
    RegisteredP1StateArchiveScmTransfer(
        const RegisteredP1StateArchiveScmTransfer&) = delete;
    RegisteredP1StateArchiveScmTransfer& operator=(
        const RegisteredP1StateArchiveScmTransfer&) = delete;
    RegisteredP1StateArchiveScmTransfer(
        RegisteredP1StateArchiveScmTransfer&&) noexcept;
    RegisteredP1StateArchiveScmTransfer& operator=(
        RegisteredP1StateArchiveScmTransfer&&) = delete;
    ~RegisteredP1StateArchiveScmTransfer();
};

// Child-only per-round endpoint.  Its writer and authenticated seqpacket
// endpoint are installed together by SCM_RIGHTS.  The endpoint is consumed
// only by the complete capsule disposition bridge.
class RegisteredP1StateArchiveChildRoundAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredP1StateArchiveChildRoundAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredP1StateArchiveScmBridge;
    friend class RegisteredP1StateCapsuleChildDispositionBridge;
public:
    RegisteredP1StateArchiveChildRoundAuthority(
        const RegisteredP1StateArchiveChildRoundAuthority&) = delete;
    RegisteredP1StateArchiveChildRoundAuthority& operator=(
        const RegisteredP1StateArchiveChildRoundAuthority&) = delete;
    RegisteredP1StateArchiveChildRoundAuthority(
        RegisteredP1StateArchiveChildRoundAuthority&&) noexcept;
    RegisteredP1StateArchiveChildRoundAuthority& operator=(
        RegisteredP1StateArchiveChildRoundAuthority&&) = delete;
    ~RegisteredP1StateArchiveChildRoundAuthority();
};

// Exact role-1 prelaunch conjunction. Neither the authenticated child state
// endpoint nor the source-owned capsule plan can be extracted independently.
class RegisteredRole1P1StatePrelaunchAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredRole1P1StatePrelaunchAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class RegisteredP1StateArchiveScmBridge;
public:
    RegisteredRole1P1StatePrelaunchAuthority(
        const RegisteredRole1P1StatePrelaunchAuthority&) = delete;
    RegisteredRole1P1StatePrelaunchAuthority& operator=(
        const RegisteredRole1P1StatePrelaunchAuthority&) = delete;
    RegisteredRole1P1StatePrelaunchAuthority(
        RegisteredRole1P1StatePrelaunchAuthority&&) noexcept;
    RegisteredRole1P1StatePrelaunchAuthority& operator=(
        RegisteredRole1P1StatePrelaunchAuthority&&) = delete;
    ~RegisteredRole1P1StatePrelaunchAuthority();
};

// A deliberately non-movable view over the recorder retained by the runtime.
// It exposes only the source adapters needed before protocol setup; it cannot
// transfer, close, or otherwise detach the recorder from terminal cleanup.
class RegisteredRole1P1StateRecorderFacade final {
    kpb::measurement::p1_state_capsule::
        P1CorruptStateRecorderAuthority* recorder_{};
    explicit RegisteredRole1P1StateRecorderFacade(
        kpb::measurement::p1_state_capsule::
            P1CorruptStateRecorderAuthority*) noexcept;
    friend class RegisteredP1StateArchiveScmBridge;
public:
    RegisteredRole1P1StateRecorderFacade() = delete;
    RegisteredRole1P1StateRecorderFacade(
        const RegisteredRole1P1StateRecorderFacade&) = delete;
    RegisteredRole1P1StateRecorderFacade& operator=(
        const RegisteredRole1P1StateRecorderFacade&) = delete;
    RegisteredRole1P1StateRecorderFacade(
        RegisteredRole1P1StateRecorderFacade&&) = delete;
    RegisteredRole1P1StateRecorderFacade& operator=(
        RegisteredRole1P1StateRecorderFacade&&) = delete;
    ~RegisteredRole1P1StateRecorderFacade() = default;

    kpb::measurement::p1_state_capsule::P1StateThreadEpochAuthority
    take_root_thread_epoch();
    std::unique_ptr<kpb::measurement::p1_state_capsule::
        P1ContextAndRetryStateAdapter>
    take_context_and_retry_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority&);
    std::unique_ptr<kpb::measurement::p1_state_capsule::
        P1EntropyStateAdapter>
    take_entropy_state_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority&);
    std::unique_ptr<kpb::measurement::p1_state_capsule::
        P1MascotSecretStateAdapter>
    take_mascot_secret_state_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority&);
    std::unique_ptr<kpb::measurement::p1_state_capsule::
        P1PlayerTlsStateAdapter>
    take_player_tls_state_adapter(
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority&);
    void advance_phase(
        kpb::measurement::p1_state_capsule::SourcePhase);
};

static_assert(!std::is_copy_constructible_v<
              RegisteredRole1P1StateRecorderFacade>);
static_assert(!std::is_move_constructible_v<
              RegisteredRole1P1StateRecorderFacade>);

// Live role-1 state recorder and its exact authenticated terminal endpoint.
// Only its non-movable facade escapes, so this object remains responsible for
// the recorder and an unavailable terminal disposition on every unwind path.
class RegisteredRole1P1StateRuntimeAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredRole1P1StateRuntimeAuthority(
        std::unique_ptr<Storage>) noexcept;
    static void finish_unavailable_noexcept(Storage*) noexcept;
    friend class RegisteredP1StateArchiveScmBridge;
public:
    RegisteredRole1P1StateRuntimeAuthority(
        const RegisteredRole1P1StateRuntimeAuthority&) = delete;
    RegisteredRole1P1StateRuntimeAuthority& operator=(
        const RegisteredRole1P1StateRuntimeAuthority&) = delete;
    RegisteredRole1P1StateRuntimeAuthority(
        RegisteredRole1P1StateRuntimeAuthority&&) noexcept;
    RegisteredRole1P1StateRuntimeAuthority& operator=(
        RegisteredRole1P1StateRuntimeAuthority&&) = delete;
    ~RegisteredRole1P1StateRuntimeAuthority();

    RegisteredRole1P1StateRecorderFacade& recorder();
    // Until every source serializer and terminal hook is qualified, the
    // generic role program may close only as typed UNAVAILABLE. A success
    // finalizer is intentionally absent from this production surface.
    void finish_unavailable_noexcept() && noexcept;
};

// Terminal-only child endpoint left after the writer is split for recorder
// adoption.  It carries the same unforgeable role/round/session/reservation
// and inode binding but owns no writable archive description.
class RegisteredP1StateArchiveChildTerminalAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredP1StateArchiveChildTerminalAuthority(
        std::unique_ptr<Storage>) noexcept;
    friend class RegisteredP1StateArchiveScmBridge;
    friend class RegisteredP1StateCapsuleChildDispositionBridge;
public:
    RegisteredP1StateArchiveChildTerminalAuthority(
        const RegisteredP1StateArchiveChildTerminalAuthority&) = delete;
    RegisteredP1StateArchiveChildTerminalAuthority& operator=(
        const RegisteredP1StateArchiveChildTerminalAuthority&) = delete;
    RegisteredP1StateArchiveChildTerminalAuthority(
        RegisteredP1StateArchiveChildTerminalAuthority&&) noexcept;
    RegisteredP1StateArchiveChildTerminalAuthority& operator=(
        RegisteredP1StateArchiveChildTerminalAuthority&&) = delete;
    ~RegisteredP1StateArchiveChildTerminalAuthority();
};

// Preallocated exact split.  Construction consumes one authenticated child
// round only after both output storages exist; split itself is no-throw and
// can occur exactly once.
class P1StateArchiveWriterAdoptionBundle final {
    std::optional<P1StateArchiveWriterAdoptionAuthority> writer_;
    std::optional<RegisteredP1StateArchiveChildTerminalAuthority> terminal_;
    bool live_{true};
    P1StateArchiveWriterAdoptionBundle(
        P1StateArchiveWriterAdoptionAuthority&&,
        RegisteredP1StateArchiveChildTerminalAuthority&&) noexcept;
    friend class RegisteredP1StateArchiveScmBridge;
public:
    P1StateArchiveWriterAdoptionBundle(
        const P1StateArchiveWriterAdoptionBundle&) = delete;
    P1StateArchiveWriterAdoptionBundle& operator=(
        const P1StateArchiveWriterAdoptionBundle&) = delete;
    P1StateArchiveWriterAdoptionBundle(
        P1StateArchiveWriterAdoptionBundle&&) noexcept;
    P1StateArchiveWriterAdoptionBundle& operator=(
        P1StateArchiveWriterAdoptionBundle&&) = delete;
    ~P1StateArchiveWriterAdoptionBundle();

    std::optional<std::pair<P1StateArchiveWriterAdoptionAuthority,
                            RegisteredP1StateArchiveChildTerminalAuthority>>
    split() && noexcept;
};

static_assert(std::is_nothrow_move_constructible_v<
              P1StateArchiveWriterAdoptionAuthority>);
static_assert(std::is_nothrow_move_constructible_v<
              RegisteredP1StateArchiveChildTerminalAuthority>);
static_assert(std::is_nothrow_constructible_v<
              std::pair<P1StateArchiveWriterAdoptionAuthority,
                        RegisteredP1StateArchiveChildTerminalAuthority>,
              P1StateArchiveWriterAdoptionAuthority&&,
              RegisteredP1StateArchiveChildTerminalAuthority&&>);

// Parent-only per-round endpoint.  It binds the kernel-authenticated child
// PID, role=1, round, activation command, topology identity, and archive
// inode.  Only the complete disposition bridge can consume it.
class RegisteredP1StateArchiveParentRoundAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit RegisteredP1StateArchiveParentRoundAuthority(
        std::unique_ptr<Storage>);
    friend class RegisteredP1StateArchiveScmBridge;
    friend class RegisteredP1StateCapsuleChildDispositionBridge;
public:
    RegisteredP1StateArchiveParentRoundAuthority(
        const RegisteredP1StateArchiveParentRoundAuthority&) = delete;
    RegisteredP1StateArchiveParentRoundAuthority& operator=(
        const RegisteredP1StateArchiveParentRoundAuthority&) = delete;
    RegisteredP1StateArchiveParentRoundAuthority(
        RegisteredP1StateArchiveParentRoundAuthority&&) noexcept;
    RegisteredP1StateArchiveParentRoundAuthority& operator=(
        RegisteredP1StateArchiveParentRoundAuthority&&) = delete;
    ~RegisteredP1StateArchiveParentRoundAuthority();
};

#ifdef KPI_REGISTERED_P1_STATE_ARCHIVE_SCM_TEST_SETUP
enum class RegisteredP1StateArchiveScmTestFault : unsigned char {
    None = 0,
    WrongRole = 1,
    SubstitutedWriter = 2,
    TerminalReplay = 3,
    TerminalTruncated = 4,
    ChildDeath = 5,
    AdoptionAppendMode = 6,
    AdoptionNonzeroSize = 7,
    PostCapsuleAllocationDenied = 8,
    WrongAdoptionRound = 9,
    WrongAdoptionReservation = 10,
    PreAdoptionAllocationDenied = 11,
    StalePlanFreshChild = 12,
    StaleChildFreshPlan = 13,
    RuntimeBeginAllocationDenied = 14,
    SubstitutedParentTrialExpectation = 15,
    SubstitutedParentPrelaunchExpectation = 16,
    RuntimeFailureProbeThrows = 17,
};

struct RegisteredP1StateArchiveScmTestSummary {
    bool expected_result{};
    unsigned authenticated_activation_acks{};
    unsigned typed_authenticated_dispositions{};
    unsigned typed_same_inode_dispositions{};
    bool post_capsule_allocation_denial_control{};
    bool exact_two_parent_reads_retained{};
    bool exact_two_parent_reads_empty{};
    bool terminal_ack_before_pidfd_wait{};
    bool child_exited{};
    int child_exit_code{-1};
};
#endif

struct RegisteredP1StateArchiveScmSourceStatus {
    bool exact_topology_pair_extraction{};
    bool ten_capture_resources_unchanged_control{};
    bool authenticated_role1_round_delivery{};
    bool kernel_credentials_each_packet{};
    bool exact_writer_inode_validation{};
    bool truncation_and_ancillary_rejection{};
    bool terminal_replay_rejection{};
    bool child_death_refusal{};
    bool genuine_capsule_terminal_source{};
    bool typed_parent_disposition_source{};
    bool selected_activation_callsite{};
    bool configured{};
};

// All claims remain false until the hostile runtime control and sanitizer
// suite is green.  In particular, the selected activation and recorder still
// do not consume this module.
inline constexpr RegisteredP1StateArchiveScmSourceStatus
    kRegisteredP1StateArchiveScmSourceStatus{};

} // namespace kpi::mpc::financial::registered_driver
