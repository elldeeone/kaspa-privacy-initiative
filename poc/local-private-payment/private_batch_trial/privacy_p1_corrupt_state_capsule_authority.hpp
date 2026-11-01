#pragma once

// Source-only observer-v5 authority for the corrupt P1 process's private
// protocol state. This is deliberately separate from the C03 transcript.
// No production source can mint the plan yet and no selected observer consumes
// the result. A closed capsule may be structurally unavailable; only the
// future registered join bridge can inspect that private disposition.

#include "privacy_measurement_authority.hpp"
#include "privacy_p1_corrupt_state_capsule_bridge_contract.hpp"
#include "../mpc-prover/p1_context_state_hook.hpp"
#include "../mpc-prover/p1_entropy_state_hook.hpp"
#include "../mpc-prover/p1_mascot_secret_state_hook.hpp"
#include "../mpc-prover/p1_player_tls_state_hook.hpp"
#include "../mpc-prover/financial/registered_p1_state_archive_writer_adoption_contract.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace kpb::measurement::p1_state_capsule {

inline constexpr unsigned STATE_FAMILY_COUNT = 14;

enum class StateFamily : std::uint8_t {
    MpSpdzPrng = 1,
    CryptoToolsPrng = 2,
    MascotSecrets = 3,
    SimplestOtBase = 4,
    SoftSpokenExtended = 5,
    OnDemandOtMap = 6,
    TripleAndInputCache = 7,
    Beaver = 8,
    MacCheck = 9,
    ContextAndRetry = 10,
    ProtocolSetup = 11,
    PlayerAllocation = 12,
    TlsChannelState = 13,
    QueryMsmCheckerTemporaries = 14,
};

// These tags identify source transitions, not security conclusions. Every
// transition also stores the exact versioned private state snapshot supplied
// by the pinned source adapter for its family.
enum class TransitionKind : std::uint8_t {
    EntropySeed = 1,
    PrngConsume = 2,
    CacheLoad = 3,
    CacheGenerate = 4,
    CacheWrite = 5,
    CacheUnlink = 6,
    OtSetup = 7,
    OtExtend = 8,
    OtCheck = 9,
    TripleGenerate = 10,
    TripleConsume = 11,
    InputTupleConsume = 12,
    CollectiveSeed = 13,
    BeaverPrepare = 14,
    BeaverExchange = 15,
    BeaverFinalize = 16,
    MacPrepare = 17,
    MacCoefficient = 18,
    MacTau = 19,
    MacVerify = 20,
    ContextPoison = 21,
    ContextRetry = 22,
    ContextValidate = 23,
    ProtocolSetup = 24,
    PlayerFork = 25,
    PlayerTraffic = 26,
    TlsHandshake = 27,
    TlsReadWrite = 28,
    QueryMsmStage = 29,
    CheckerStage = 30,
};

enum class SourcePhase : std::uint8_t {
    RecorderStarted = 1,
    TlsAndPlayerBound = 2,
    ProtocolSetupStarted = 3,
    ProtocolSetupComplete = 4,
    Construction = 5,
    Proof = 6,
    Release = 7,
    TerminalEgress = 8,
};

enum class AbortClass : std::uint8_t {
    Transport = 1,
    Protocol = 2,
    MacCheck = 3,
    OwnerInput = 4,
    Proof = 5,
    PublicStage = 6,
    Resource = 7,
};

struct HookTransitionDescriptor {
    std::uint64_t object_ordinal{};
    TransitionKind kind{};
    std::uint64_t counter_before{};
    std::uint64_t counter_after{};
};

enum class HookEventKind : std::uint8_t {
    Construct = 1,
    Transition = 2,
    TerminalSnapshot = 3,
    Release = 4,
};

struct HookEventDescriptor {
    std::uint64_t object_ordinal{};
    HookEventKind event_kind{};
    TransitionKind transition_kind{};
    std::uint64_t counter_before{};
    std::uint64_t counter_after{};
};

struct FamilyHookInventory {
    std::uint64_t exact_object_count{};
    std::uint64_t exact_event_count{};
    std::uint64_t exact_transition_count{};
    std::uint64_t required_transition_bitmap{};
    Digest ordered_hook_manifest_identity{};
    Digest expected_event_sequence_identity{};
    Digest expected_transition_sequence_identity{};
    bool operator==(const FamilyHookInventory&) const = default;
};

// Source coverage fixed by the private plan compiler. `Missing` is not an
// empty success claim: it is a permanent UNAVAILABLE disposition for this
// capsule. Only the canonical empty inventory and serializer identity below
// are admissible for it. A caller cannot promote that data to `Captured`.
enum class SourceFamilyDisposition : std::uint8_t {
    Captured = 1,
    Missing = 2,
};

FamilyHookInventory canonical_missing_family_hook_inventory(StateFamily);
Digest canonical_missing_family_serializer_identity(StateFamily);

// Prelaunch dependencies without a selected, source-owned binding use one
// typed canonical Missing identity per field. They are distinguishable from
// a captured pin and cannot be promoted by hashing an "unbound" label.
enum class PrelaunchDependency : std::uint8_t {
    MpSpdzSource = 1,
    SimplestOtSource = 2,
    LibOteSource = 3,
    CryptoToolsSource = 4,
    OpenSslSource = 5,
    OnlineOptions = 6,
    MascotSecretsPolicy = 7,
    ArchiveFilesystem = 8,
};

Digest canonical_missing_prelaunch_dependency_identity(
    PrelaunchDependency);

enum class AbortFamilyDisposition : std::uint8_t {
    Closed = 1,
    NotConstructed = 2,
    TerminalPrefix = 3,
};

struct AbortFamilyHookInventory {
    AbortFamilyDisposition disposition{};
    std::uint64_t exact_object_count{};
    std::uint64_t exact_event_count{};
    std::uint64_t exact_transition_count{};
    std::uint64_t required_transition_bitmap{};
    Digest expected_event_sequence_identity{};
    Digest expected_transition_sequence_identity{};
    bool operator==(const AbortFamilyHookInventory&) const = default;
};

struct AbortTerminalHookInventory {
    Digest terminal_site_identity{};
    Digest exception_type_identity{};
    SourcePhase phase{};
    AbortClass abort_class{};
    std::array<AbortFamilyHookInventory, STATE_FAMILY_COUNT> families{};
    bool operator==(const AbortTerminalHookInventory&) const = default;
};

Digest recompute_family_transition_sequence_identity(
    StateFamily, std::span<const HookTransitionDescriptor>);
Digest recompute_family_event_sequence_identity(
    StateFamily, std::span<const HookEventDescriptor>);
Digest recompute_mascot_secret_branch_manifest_identity(
    kpi::mpc::p1_private_state::MascotCacheBranch);
FamilyHookInventory recompute_mascot_secret_branch_inventory(
    kpi::mpc::p1_private_state::MascotCacheBranch);
AbortFamilyHookInventory recompute_mascot_secret_abort_prefix_inventory(
    kpi::mpc::p1_private_state::MascotCacheBranch);
Digest recompute_abort_terminal_manifest_identity(
    std::span<const AbortTerminalHookInventory>);

// Facts fixed after the preidentity process/topology reservation and before
// any MPC work. Deliberately absent: emitted projections, actual child exits,
// EGRESS identities, and capsule terminal identities. Those belong to the
// separate postrun residual and cannot be predicted at recorder startup.
struct P1StateCapsulePrelaunchBinding {
    Classification classification{};
    Digest comparison_selection{};
    Digest run_selection{};
    std::string capture_trial_id;
    Digest trial{};
    Digest measurement_attempt{};
    Digest measurement_cohort{};
    Digest capture{};
    Digest method{};
    Digest workload{};
    Digest source_closure{};
    Digest runtime{};
    FiniteManifestBinding finite_manifest;
    Digest outer_parent_process{};
    Digest outer_parent_executable{};
    Digest capture_source{};
    Digest capture_build{};
    Digest capture_runtime{};
    Digest capture_launcher{};
    WorkerBinding observer_worker;
    WorkerBinding score_worker;
    WorkerBinding aggregate_worker;
    std::array<Digest, 2> financial_runs{};
    std::array<std::string, 2> capture_attempt_ids;
    std::array<Digest, 2> round_attempts{};
    std::array<Digest, 2> round_cohorts{};
    std::array<Digest, 2> round_capture_plans{};
    Digest process_reservation_identity{};
    Digest persistent_process_session_identity{};
    std::array<Digest, 2> fork_plan_identities{};
    Digest producer_process_identity{};
    Digest role_closure_identity{};
    Digest manifest_seal{};
    Digest construction_policy_identity{};
    Digest construction_classification_receipt{};
    Digest route_policy_identity{};
    Digest stream_policy_identity{};
    // Recomputed over every preceding field with a versioned domain. The
    // production bridge must also match it to the private selected-prelaunch
    // authority; a caller-computed digest is never a minting path.
    Digest binding_identity{};
    bool operator==(const P1StateCapsulePrelaunchBinding&) const = default;
};

Digest recompute_p1_state_capsule_prelaunch_binding_identity(
    const P1StateCapsulePrelaunchBinding&);

// Reserved postrun grammar. No authority can construct this in the current
// source state. A future join must source every field from typed EGRESS,
// pidfd-exit, and sealed-capsule residuals and match prelaunch_binding_identity.
struct P1StateCapsulePostrunBinding {
    Digest prelaunch_binding_identity{};
    std::array<Digest, 2> projections{};
    std::array<Digest, 2> role1_child_exits{};
    std::array<Digest, 2> role1_egress_identities{};
    std::array<Digest, 2> capsule_archive_identities{};
    Digest postrun_identity{};
    bool operator==(const P1StateCapsulePostrunBinding&) const = default;
};

class P1StateCapsulePostrunResidualAuthority final {
    P1StateCapsulePostrunResidualAuthority() = delete;
};

struct StaticStateCapsulePlan {
    P1StateCapsulePrelaunchBinding prelaunch;
    unsigned round{};
    unsigned role{};
    WorkerBinding p1_worker;
    // These are predeclared source-plan identities available before
    // CryptoPlayer construction, not the later runtime-selected head/value.
    // The live hook must bind the actual selections as typed state events.
    Digest accepted_head_plan_identity{};
    Digest selected_main_plan_identity{};
    Digest persistent_child_identity{};
    std::uint64_t persistent_child_epoch{};
    std::uint64_t context_allocation_epoch{};
    Digest source_hook_manifest_identity{};
    Digest mp_spdz_source_identity{};
    Digest simplest_ot_source_identity{};
    Digest libote_source_identity{};
    Digest crypto_tools_source_identity{};
    Digest openssl_source_identity{};
    Digest online_options_identity{};
    Digest mascot_secrets_policy_identity{};
    Digest topology_reservation_identity{};
    Digest archive_filesystem_identity{};
    Digest abort_terminal_manifest_identity{};
    std::array<SourceFamilyDisposition, STATE_FAMILY_COUNT>
        source_family_dispositions{};
    std::array<Digest, STATE_FAMILY_COUNT> serializer_identities{};
    std::array<FamilyHookInventory, STATE_FAMILY_COUNT> hook_inventory{};
    std::vector<AbortTerminalHookInventory> abort_terminals;
    bool operator==(const StaticStateCapsulePlan&) const = default;
};

class P1CorruptStateCapsulePlanAuthority;
class P1CorruptStateRecorderAuthority;
class P1StateThreadEpochAuthority;
class P1StateObjectEpochAuthority;
class P1PlayerAllocationEpochAuthority;
class P1AbortTerminalSiteAuthority;
class P1AbortTerminalAuthority;
class P1CorruptStateCapsuleAuthority;

// Complete before friendship. The genuine source bridge has intentionally no
// mint operation in this source state.
class P1CorruptStateCapsuleSourceBridge final {
public:
    P1CorruptStateCapsuleSourceBridge() = delete;
};

// Complete before friendship. A future catch-site adapter, not a caller with
// raw digests, must mint this token from the exact terminal selected in the
// authenticated source manifest. No production minter exists yet.
class P1AbortTerminalSourceBridge final {
public:
    P1AbortTerminalSourceBridge() = delete;
};

class P1CorruptStateCapsulePlanAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1CorruptStateCapsulePlanAuthority(std::unique_ptr<Storage>);
    void validate_for_role1_prelaunch_attachment(
        unsigned round, const Digest& topology_reservation_identity,
        const Digest& capture_plan_identity) const;
    Digest unavailable_trial_identity_for_role1_prelaunch() const;
    Digest unavailable_prelaunch_binding_identity_for_role1_prelaunch() const;
    Digest capture_plan_identity_for_role1_prelaunch(unsigned round) const;
    friend class P1CorruptStateCapsuleSourceBridge;
    friend class kpi::mpc::financial::registered_driver::
        RegisteredP1StateArchiveScmBridge;
    friend class kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge;

public:
    P1CorruptStateCapsulePlanAuthority(
        const P1CorruptStateCapsulePlanAuthority&) = delete;
    P1CorruptStateCapsulePlanAuthority& operator=(
        const P1CorruptStateCapsulePlanAuthority&) = delete;
    P1CorruptStateCapsulePlanAuthority(
        P1CorruptStateCapsulePlanAuthority&&) noexcept;
    P1CorruptStateCapsulePlanAuthority& operator=(
        P1CorruptStateCapsulePlanAuthority&&) = delete;
    ~P1CorruptStateCapsulePlanAuthority();

    // Production can begin only by consuming the authenticated O_WRONLY
    // topology archive before CryptoPlayer construction. The terminal channel
    // remains a separate one-shot child authority.
    P1CorruptStateRecorderAuthority
    begin_before_player_and_protocol_setup(
        kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority&&) &&;

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
    // Control-only anonymous archive. It cannot appear in a production TU.
    P1CorruptStateRecorderAuthority
    begin_before_player_and_protocol_setup() &&;
    static P1CorruptStateCapsulePlanAuthority test_only_mint(
        StaticStateCapsulePlan);
    static P1CorruptStateCapsulePlanAuthority
    test_only_mint_matching_writer_adoption(
        StaticStateCapsulePlan,
        const kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority&);
    static P1CorruptStateCapsulePlanAuthority
    test_only_mint_wrong_writer_adoption(
        StaticStateCapsulePlan,
        const kpi::mpc::financial::registered_driver::
            P1StateArchiveWriterAdoptionAuthority&,
        bool wrong_round);
#endif
};

class P1StateThreadEpochAuthority final {
public:
    struct Storage;
private:
    std::unique_ptr<Storage> storage_;
    explicit P1StateThreadEpochAuthority(std::unique_ptr<Storage>);
    friend class P1CorruptStateRecorderAuthority;
    friend class P1ContextAndRetryStateAdapterFactoryBridge;
    friend class P1EntropyStateAdapterFactoryBridge;
    friend class P1MascotSecretStateAdapterFactoryBridge;
    friend class P1PlayerTlsStateAdapterFactoryBridge;

public:
    P1StateThreadEpochAuthority(const P1StateThreadEpochAuthority&) = delete;
    P1StateThreadEpochAuthority& operator=(
        const P1StateThreadEpochAuthority&) = delete;
    P1StateThreadEpochAuthority(P1StateThreadEpochAuthority&&) noexcept;
    P1StateThreadEpochAuthority& operator=(
        P1StateThreadEpochAuthority&&) = delete;
    ~P1StateThreadEpochAuthority();
};

class P1StateObjectEpochAuthority final {
public:
    struct Storage;
private:
    std::unique_ptr<Storage> storage_;
    explicit P1StateObjectEpochAuthority(std::unique_ptr<Storage>);
    friend class P1CorruptStateRecorderAuthority;

public:
    P1StateObjectEpochAuthority(const P1StateObjectEpochAuthority&) = delete;
    P1StateObjectEpochAuthority& operator=(
        const P1StateObjectEpochAuthority&) = delete;
    P1StateObjectEpochAuthority(P1StateObjectEpochAuthority&&) noexcept;
    P1StateObjectEpochAuthority& operator=(
        P1StateObjectEpochAuthority&&) = delete;
    ~P1StateObjectEpochAuthority();
};

class P1PlayerAllocationEpochAuthority final {
public:
    struct Storage;
private:
    std::unique_ptr<Storage> storage_;
    explicit P1PlayerAllocationEpochAuthority(std::unique_ptr<Storage>);
    friend class P1CorruptStateRecorderAuthority;

public:
    P1PlayerAllocationEpochAuthority(
        const P1PlayerAllocationEpochAuthority&) = delete;
    P1PlayerAllocationEpochAuthority& operator=(
        const P1PlayerAllocationEpochAuthority&) = delete;
    P1PlayerAllocationEpochAuthority(
        P1PlayerAllocationEpochAuthority&&) noexcept;
    P1PlayerAllocationEpochAuthority& operator=(
        P1PlayerAllocationEpochAuthority&&) = delete;
    ~P1PlayerAllocationEpochAuthority();
};

class P1AbortTerminalSiteAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1AbortTerminalSiteAuthority(std::unique_ptr<Storage>);
    friend class P1CorruptStateCapsulePlanAuthority;
    friend class kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge;
    friend class P1AbortTerminalSourceBridge;
    friend class P1CorruptStateRecorderAuthority;

public:
    P1AbortTerminalSiteAuthority(
        const P1AbortTerminalSiteAuthority&) = delete;
    P1AbortTerminalSiteAuthority& operator=(
        const P1AbortTerminalSiteAuthority&) = delete;
    P1AbortTerminalSiteAuthority(
        P1AbortTerminalSiteAuthority&&) noexcept;
    P1AbortTerminalSiteAuthority& operator=(
        P1AbortTerminalSiteAuthority&&) = delete;
    ~P1AbortTerminalSiteAuthority();
};

class P1AbortTerminalAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1AbortTerminalAuthority(std::unique_ptr<Storage>);
    friend class P1CorruptStateCapsulePlanAuthority;
    friend class kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge;
    friend class P1CorruptStateRecorderAuthority;

public:
    P1AbortTerminalAuthority(const P1AbortTerminalAuthority&) = delete;
    P1AbortTerminalAuthority& operator=(
        const P1AbortTerminalAuthority&) = delete;
    P1AbortTerminalAuthority(P1AbortTerminalAuthority&&) noexcept;
    P1AbortTerminalAuthority& operator=(
        P1AbortTerminalAuthority&&) = delete;
    ~P1AbortTerminalAuthority();
};

class P1CorruptStateRecorderAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1CorruptStateRecorderAuthority(std::unique_ptr<Storage>);
    P1CorruptStateCapsuleAuthority close_noexcept(bool aborted) && noexcept;
    P1StateObjectEpochAuthority construct_object_impl(
        StateFamily, const P1StateThreadEpochAuthority&,
        std::span<const unsigned char>, bool allow_test_reserved_family);
    void close_family_impl(StateFamily, bool allow_test_reserved_family);
    friend class P1CorruptStateCapsulePlanAuthority;
    friend class P1ContextAndRetryStateAdapterFactoryBridge;
    friend class P1EntropyStateAdapterFactoryBridge;
    friend class P1MascotSecretStateAdapterFactoryBridge;
    friend class P1PlayerTlsStateAdapterFactoryBridge;
    friend class kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge;

public:
    P1CorruptStateRecorderAuthority(
        const P1CorruptStateRecorderAuthority&) = delete;
    P1CorruptStateRecorderAuthority& operator=(
        const P1CorruptStateRecorderAuthority&) = delete;
    P1CorruptStateRecorderAuthority(
        P1CorruptStateRecorderAuthority&&) noexcept;
    P1CorruptStateRecorderAuthority& operator=(
        P1CorruptStateRecorderAuthority&&) = delete;
    ~P1CorruptStateRecorderAuthority();

    P1StateThreadEpochAuthority take_root_thread_epoch();
    std::unique_ptr<P1ContextAndRetryStateAdapter>
    take_context_and_retry_adapter(
        const P1StateThreadEpochAuthority& root_thread);
    std::unique_ptr<P1EntropyStateAdapter>
    take_entropy_state_adapter(
        const P1StateThreadEpochAuthority& root_thread);
    std::unique_ptr<P1MascotSecretStateAdapter>
    take_mascot_secret_state_adapter(
        const P1StateThreadEpochAuthority& root_thread);
    std::unique_ptr<P1PlayerTlsStateAdapter>
    take_player_tls_state_adapter(
        const P1StateThreadEpochAuthority& root_thread);
    P1StateThreadEpochAuthority fork_thread(
        const P1StateThreadEpochAuthority& parent,
        const Digest& source_fork_identity);
    void join_thread(
        P1StateThreadEpochAuthority&&,
        std::span<const unsigned char> exact_private_terminal_state);

    // Advances one exact lifecycle edge. Skipping or reversing a phase is
    // refused. Phase controls which still-unconstructed families may be
    // recorded as genuinely absent on an abort.
    void advance_phase(SourcePhase);

    P1StateObjectEpochAuthority construct_object(
        StateFamily, const P1StateThreadEpochAuthority&,
        std::span<const unsigned char> exact_private_snapshot);
    void transition(
        P1StateObjectEpochAuthority&, TransitionKind,
        std::uint64_t counter_before, std::uint64_t counter_after,
        std::span<const unsigned char> exact_private_snapshot);
    void terminal_snapshot(
        P1StateObjectEpochAuthority&,
        std::span<const unsigned char> exact_private_snapshot);
    void release_object(
        P1StateObjectEpochAuthority&&,
        std::span<const unsigned char> exact_private_snapshot);

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
    P1StateObjectEpochAuthority test_only_construct_reserved_family(
        StateFamily, const P1StateThreadEpochAuthority&,
        std::span<const unsigned char> exact_private_snapshot);
    // Fixture-only raw PlayerAllocation surface. Production reserves this
    // family to P1PlayerTlsStateAdapter so arbitrary source code cannot forge
    // a live Player prefix.
    P1PlayerAllocationEpochAuthority bind_root_player(
        const P1StateThreadEpochAuthority&,
        std::span<const unsigned char> exact_private_snapshot);
    P1PlayerAllocationEpochAuthority allocate_player_fork(
        const P1PlayerAllocationEpochAuthority& parent,
        const P1StateThreadEpochAuthority&,
        const Digest& source_fork_identity,
        std::span<const unsigned char> exact_private_snapshot);
    void player_transition(
        P1PlayerAllocationEpochAuthority&, TransitionKind,
        std::uint64_t counter_before, std::uint64_t counter_after,
        std::span<const unsigned char> exact_private_snapshot);
    void player_terminal_snapshot(
        P1PlayerAllocationEpochAuthority&,
        std::span<const unsigned char> exact_private_snapshot);
    void release_player(
        P1PlayerAllocationEpochAuthority&&,
        std::span<const unsigned char> exact_private_snapshot);
#endif

    // Generic family closure requires the plan's exact object/event/transition
    // inventory. ContextAndRetry is reserved to the owned adapter and this
    // generic closure refuses it. An early-abort path must instead record
    // explicit non-construction; success can never use that disposition.
    void close_family(StateFamily);
    void mark_family_not_constructed_before_abort(StateFamily);

    // Hook failure is itself retained. It permanently makes this capsule
    // unavailable; it can never be promoted to observer completion.
    void mark_hook_unavailable(StateFamily) noexcept;

    P1AbortTerminalAuthority prepare_abort_terminal(
        P1AbortTerminalSiteAuthority&&);

    // Both methods are nonthrowing and always burn the recorder. The returned
    // opaque authority privately records complete vs unavailable.
    P1CorruptStateCapsuleAuthority close_success_noexcept() && noexcept;
    P1CorruptStateCapsuleAuthority close_abort_noexcept(
        P1AbortTerminalAuthority&&) && noexcept;
    P1CorruptStateCapsuleAuthority close_unavailable_abort_noexcept(
        AbortClass, const Digest& exception_type_identity) && noexcept;

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
    P1AbortTerminalSiteAuthority test_only_mint_abort_terminal_site(
        const Digest& terminal_site_identity, AbortClass,
        const Digest& exception_type_identity);
    void test_only_force_fd_substitution();
    void test_only_force_write_failure();
    void test_only_force_fsync_failure();
    void test_only_force_reopen_failure();
    void test_only_force_hash_failure();
    void test_only_force_abort_token_preallocation_loss();
    void test_only_close_reserved_family(StateFamily);
#endif
};

class P1CorruptStateCapsuleAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1CorruptStateCapsuleAuthority(std::unique_ptr<Storage>);
    static std::unique_ptr<
        P1CorruptStateCapsuleChildDispositionResidual::Storage>
    preallocate_child_disposition(const StaticStateCapsulePlan&);
    P1CorruptStateCapsuleChildDispositionResidual
    consume_for_child_disposition() &&;
    friend class P1CorruptStateCapsulePlanAuthority;
    friend class kpi::mpc::financial::registered_driver::
        P1StateArchiveWriterAdoptionConsumerBridge;
    friend class P1CorruptStateRecorderAuthority;
    friend class kpi::mpc::financial::registered_driver::
        RegisteredP1StateCapsuleChildDispositionBridge;

public:
    P1CorruptStateCapsuleAuthority(
        const P1CorruptStateCapsuleAuthority&) = delete;
    P1CorruptStateCapsuleAuthority& operator=(
        const P1CorruptStateCapsuleAuthority&) = delete;
    P1CorruptStateCapsuleAuthority(
        P1CorruptStateCapsuleAuthority&&) noexcept;
    P1CorruptStateCapsuleAuthority& operator=(
        P1CorruptStateCapsuleAuthority&&) = delete;
    ~P1CorruptStateCapsuleAuthority();

#ifdef KPB_P1_STATE_CAPSULE_TEST_SETUP
    struct TestOnlySummary {
        StaticStateCapsulePlan plan;
        // Exact hook-manifest structure only. This is never observer-view
        // completeness or privacy qualification.
        bool manifest_structurally_complete{};
        bool aborted{};
        bool read_only{};
        bool anonymous_disk_backed{};
        bool writer_closed{};
        bool descriptor_retained{};
        SourcePhase terminal_phase{};
        AbortClass abort_class{};
        std::uint64_t sequence{};
        std::uint64_t archive_bytes{};
        std::uint64_t missing_family_bitmap{};
        std::uint64_t closed_family_bitmap{};
        std::uint64_t not_constructed_bitmap{};
        std::uint64_t abort_prefix_bitmap{};
        Digest abort_terminal_site_identity{};
        std::array<std::uint64_t, STATE_FAMILY_COUNT> event_counts{};
        Digest archive_sha256{};
    };
    TestOnlySummary test_only_summary() const;
    std::vector<unsigned char> test_only_read_all() const;
#endif
};

struct SourceStatus {
    bool source_only_capsule_authority{};
    bool chronology_correct_prelaunch_binding{};
    bool source_owned_prelaunch_minter{};
    bool role1_activation_attachment{};
    bool role0_role2_compiletime_absence{};
    bool postrun_projection_exit_residual{};
    bool begins_before_player_construction{};
    bool typed_private_state_archive{};
    bool success_and_abort_close{};
    bool phase_bound_abort{};
    bool terminal_specific_abort_prefixes{};
    bool opaque_terminal_site_authority{};
    bool source_owned_terminal_site_minter{};
    bool thread_join_required{};
    bool hook_manifest_inventory_enforced{};
    bool source_family_missing_disposition_grammar{};
    bool missing_family_cannot_complete{};
    bool source_owned_hook_manifest_minter{};
    bool context_retry_capsule_adapter{};
    bool entropy_ingress_capsule_adapter{};
    bool player_tls_prefix_capsule_adapter{};
    bool player_allocation_epochs{};
    bool tls_private_state_family{};
    bool query_msm_checker_temporary_family{};
    bool anonymous_disk_backed_archive{};
    bool no_operational_byte_cap{};
    bool unavailable_partial_retained{};
    bool parent_held_preidentity_archive{};
    bool fatal_signal_retention{};
    bool topology_archive_consumed{};
    bool pinned_upstream_serializers{};
    bool live_registered_success_hook{};
    bool live_registered_abort_hook{};
    bool replay_sufficiency_verified{};
    bool conjunctive_c03_history_join{};
    bool persistent_two_round_join{};
    bool complete_passive_p1_view{};
    bool selected_observer_consumer{};
    bool configured{};
};

inline constexpr SourceStatus kSourceStatus{
    .source_only_capsule_authority = true,
    .chronology_correct_prelaunch_binding = true,
    .source_owned_prelaunch_minter = false,
    .role1_activation_attachment = false,
    .role0_role2_compiletime_absence = true,
    .postrun_projection_exit_residual = false,
    .begins_before_player_construction = false,
    .typed_private_state_archive = true,
    .success_and_abort_close = false,
    .phase_bound_abort = true,
    .terminal_specific_abort_prefixes = true,
    .opaque_terminal_site_authority = true,
    .source_owned_terminal_site_minter = false,
    .thread_join_required = true,
    .hook_manifest_inventory_enforced = true,
    .source_family_missing_disposition_grammar = true,
    .missing_family_cannot_complete = true,
    .source_owned_hook_manifest_minter = true,
    .context_retry_capsule_adapter = true,
    .entropy_ingress_capsule_adapter = true,
    .player_tls_prefix_capsule_adapter = true,
    .player_allocation_epochs = true,
    .tls_private_state_family = true,
    .query_msm_checker_temporary_family = true,
    .anonymous_disk_backed_archive = true,
    .no_operational_byte_cap = true,
    .unavailable_partial_retained = true,
    .parent_held_preidentity_archive = false,
    .fatal_signal_retention = false,
    .topology_archive_consumed = false,
    .pinned_upstream_serializers = false,
    .live_registered_success_hook = false,
    .live_registered_abort_hook = false,
    .replay_sufficiency_verified = false,
    .conjunctive_c03_history_join = false,
    .persistent_two_round_join = false,
    .complete_passive_p1_view = false,
    .selected_observer_consumer = false,
    .configured = false,
};

} // namespace kpb::measurement::p1_state_capsule
