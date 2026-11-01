#pragma once

// Private evidence transport for the selected corrupt-P1 MASCOT setup. The
// source bridge exposes typed lifecycle edges only; it is not a generic
// recorder and the concrete adapter exposes no secret-state getter.

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority;
class P1StateThreadEpochAuthority;
class P1MascotSecretStateAdapter;

// Complete before either friendship grant. Only the live recorder can give
// the final adapter its shared-ledger capability.
class P1MascotSecretStateAdapterFactoryBridge final {
    P1MascotSecretStateAdapterFactoryBridge() = delete;
public:
    static std::unique_ptr<P1MascotSecretStateAdapter> take(
        P1CorruptStateRecorderAuthority&,
        const P1StateThreadEpochAuthority&);
};
}

namespace kpi::mpc::p1_private_state {

inline constexpr std::string_view MASCOT_SECRETS_MP_SPDZ_COMMIT =
    "113c4e47dd94bca9ecab029d2f0abe649bea5c52";
inline constexpr std::string_view MASCOT_SECRET_EVENT_ENCODING_DOMAIN =
    "KPI_P1_MASCOT_SECRET_STATE_V2\n";
inline constexpr std::string_view MASCOT_SECRET_ABORT_EVENT_ENCODING_DOMAIN =
    "KPI_P1_MASCOT_SECRET_ABORT_STATE_V1\n";
inline constexpr std::string_view MASCOT_SELECTED_PLAYER_ID =
    "registered-role1-of-3";
inline constexpr std::string_view MASCOT_SELECTED_FIELD_MODULUS =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

enum class MascotSecretEventKind : std::uint8_t {
    SetupBegin = 1,
    CacheOpened = 2,
    CacheLocalValidation = 3,
    CachePeerValidation = 4,
    Regeneration = 5,
    WriteCandidate = 6,
    Writeback = 7,
    BitPrepDerived = 8,
    StaticInstalled = 9,
    Teardown = 10,
    ScalarStateBegin = 11,
    PrepStaticInstalled = 12,
    PrepMacFileWrite = 13,
};

enum class MascotFileResult : std::uint8_t {
    NotAttempted = 1,
    Missing = 2,
    Captured = 3,
    Partial = 4,
    Failed = 5,
};

enum class MascotStepResult : std::uint8_t {
    NotAttempted = 1,
    Succeeded = 2,
    Failed = 3,
};

enum class MascotCacheBranch : std::uint8_t {
    Undecided = 1,
    StaticReuse = 2,
    CacheHit = 3,
    RegeneratedAfterMissing = 4,
    RegeneratedAfterLocalReject = 5,
    RegeneratedAfterPeerReject = 6,
};

enum class MascotSecretAbortClass : std::uint8_t {
    OtMultiplierFailure = 1,
    MacCheckFailure = 2,
};

enum class MascotSecretAbortEventKind : std::uint8_t {
    CacheUnlink = 1,
    WorkerFailurePublished = 2,
    WorkerTerminal = 3,
    RootFailureObserved = 4,
    WorkerJoined = 5,
    Teardown = 6,
    AbortTerminal = 7,
    AbortUnavailable = 8,
};

enum class MascotWorkerExceptionKind : std::uint8_t {
    NotApplicable = 1,
    Standard = 2,
    NonStandard = 3,
};

struct MascotFileMetadataView final {
    bool present{};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t mode{};
    std::uint64_t uid{};
    std::uint64_t gid{};
    std::uint64_t link_count{};
    std::uint64_t size{};
    std::int64_t mtime_seconds{};
    std::uint64_t mtime_nanoseconds{};
    std::int64_t ctime_seconds{};
    std::uint64_t ctime_nanoseconds{};
    bool operator==(const MascotFileMetadataView&) const = default;
};

// File identity is authoritative. diagnostic_path is retained only to explain
// the source-derived canonical Mascot-Secrets location and is never used as a
// capability or substituted for the opened descriptor identity.
struct MascotFileSnapshotView final {
    MascotFileResult result{MascotFileResult::NotAttempted};
    std::uint64_t operation_errno{};
    std::uint64_t open_flags{};
    bool no_follow{};
    std::uint64_t bytes_transferred{};
    MascotStepResult parent_directory_result{
        MascotStepResult::NotAttempted};
    std::uint64_t parent_directory_errno{};
    MascotStepResult fsync_result{MascotStepResult::NotAttempted};
    std::uint64_t fsync_errno{};
    MascotStepResult rename_result{MascotStepResult::NotAttempted};
    std::uint64_t rename_errno{};
    MascotStepResult unlink_result{MascotStepResult::NotAttempted};
    std::uint64_t unlink_errno{};
    MascotFileMetadataView path_lstat_before;
    MascotFileMetadataView descriptor_before;
    MascotFileMetadataView descriptor_after;
    MascotFileMetadataView path_lstat_after;
    MascotFileMetadataView reopened_descriptor;
    // Exact complete file body including octetStream's native size_t header
    // and every trailing byte visible through the opened descriptor.
    std::span<const unsigned char> exact_file_bytes;
};

// A source lifecycle bit distinguishes initialized/static state from the
// exact packed default object. Complete-key bytes are never omitted merely
// because the inherited scalar is zero: they cover that scalar plus the
// serialized OTTripleSetup. OnDemandOtMap owns separate PRNG/map internals.
struct MascotSecretEventView final {
    MascotSecretEventKind kind{};
    // Monotonic within the branch actually taken. Event-kind numbers are not
    // sequence numbers because cache hit, regeneration, and static reuse have
    // distinct authenticated source manifests.
    std::uint64_t sequence{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    bool encrypted_player{};
    std::uint64_t batch_size{};
    std::uint64_t bucket_size{};
    std::uint64_t statistical_security{};
    bool uses_security_parameter{};
    bool uses_kos{};
    std::uint64_t native_size_width{};
    std::uint64_t native_byte_order{}; // 1=little, 2=big
    MascotCacheBranch branch{MascotCacheBranch::Undecided};
    MascotStepResult local_validation{MascotStepResult::NotAttempted};
    MascotStepResult peer_validation{MascotStepResult::NotAttempted};
    MascotStepResult regeneration{MascotStepResult::NotAttempted};
    MascotStepResult writeback{MascotStepResult::NotAttempted};
    MascotStepResult prep_mac_write{MascotStepResult::NotAttempted};
    std::string_view player_id;
    std::string_view field_modulus;
    std::string_view canonical_cache_domain;
    std::string_view diagnostic_path;
    std::string_view failure_reason;
    MascotFileSnapshotView file;
    bool complete_key_before_initialized{};
    bool complete_key_after_initialized{};
    std::span<const unsigned char> complete_key_before;
    std::span<const unsigned char> complete_key_after;
    std::span<const unsigned char> scalar_key_before;
    std::span<const unsigned char> scalar_key_after;
    std::span<const unsigned char> prep_scalar_key_before;
    std::span<const unsigned char> prep_scalar_key_after;
    std::span<const unsigned char> expected_scalar_key;
    // At the selected Share<Fr> instantiation, bit_prep_type aliases the
    // main share type and the assignment targets this same static key.
    bool bit_prep_aliases_main{};
    std::span<const unsigned char> derived_complete_key;
    std::span<const unsigned char> exact_write_candidate;
};

// Failure evidence is a separate, versioned grammar. It is deliberately a
// typed abort terminal prefix rather than a success-family close or an empty
// MISSING-family substitution.
// source_worker_epoch is minted by the installed source scope and never by a
// caller. source_worker_identity is used only for in-process correspondence
// and is never serialized.
struct MascotSecretAbortEventView final {
    MascotSecretAbortEventKind kind{};
    std::uint64_t sequence{};
    MascotSecretAbortClass abort_class{};
    MascotCacheBranch branch{MascotCacheBranch::Undecided};
    std::uint64_t success_next_sequence{};
    std::uint64_t success_counter{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    bool encrypted_player{};
    bool source_worker{};
    std::uint64_t source_worker_epoch{};
    std::uint64_t source_worker_ordinal{};
    std::uint64_t registered_worker_count{};
    MascotWorkerExceptionKind exception_kind{
        MascotWorkerExceptionKind::NotApplicable};
    bool worker_failed{};
    bool all_workers_terminal{};
    bool all_workers_joined{};
    bool teardown_observed{};
    bool unlink_attempted{};
    bool unlink_succeeded{};
    std::uint64_t unlink_errno{};
    std::string_view canonical_cache_domain;
    std::string_view diagnostic_path;
    MascotFileMetadataView path_lstat_before;
    MascotFileMetadataView path_lstat_after;
    bool complete_key_before_initialized{};
    bool complete_key_after_initialized{};
    std::span<const unsigned char> complete_key_before;
    std::span<const unsigned char> complete_key_after;
    std::span<const unsigned char> scalar_key_before;
    std::span<const unsigned char> scalar_key_after;
    std::span<const unsigned char> prep_scalar_key_before;
    std::span<const unsigned char> prep_scalar_key_after;
};

std::string_view mascot_secret_source_site(MascotSecretEventKind);
// SHA-256 of the unmodified file at the selected upstream commit. The local
// source-closure manifest must separately bind the instrumentation patch.
std::string_view mascot_secret_upstream_file_sha256(MascotSecretEventKind);
std::vector<unsigned char> encode_mascot_secret_event(
    const MascotSecretEventView&);
std::string_view mascot_secret_abort_source_site(
    MascotSecretAbortEventKind, MascotSecretAbortClass);
std::string_view mascot_secret_abort_upstream_file_sha256(
    MascotSecretAbortEventKind, MascotSecretAbortClass);
std::vector<unsigned char> encode_mascot_secret_abort_event(
    const MascotSecretAbortEventView&);

class MascotSecretStateHook {
    MascotSecretStateHook() = default;
    friend class ::kpb::measurement::p1_state_capsule::
        P1MascotSecretStateAdapter;
#ifdef KPI_P1_MASCOT_SECRET_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit MascotSecretStateHook(TestOnlyConstruction) {}
#endif

public:
    MascotSecretStateHook(const MascotSecretStateHook&) = delete;
    MascotSecretStateHook& operator=(const MascotSecretStateHook&) = delete;
    virtual ~MascotSecretStateHook() = default;
    virtual bool record_mascot_secret_event(
        const MascotSecretEventView&) noexcept = 0;
    virtual bool record_mascot_secret_abort_event(
        const MascotSecretAbortEventView&) noexcept = 0;
    virtual void mascot_secret_unavailable_noexcept() noexcept = 0;
};

class MascotSecretStateHookScope;

// Complete before friendship. A standalone include cannot define an
// exact-name context/factory lookalike to acquire the private constructor.
class MascotSecretStateScopeFactoryBridge final {
    MascotSecretStateScopeFactoryBridge() = delete;
    friend class ::kpb::measurement::p1_state_capsule::
        P1MascotSecretStateAdapterFactoryBridge;
    static std::unique_ptr<MascotSecretStateHookScope> install(
        MascotSecretStateHook&, std::uint64_t local_role,
        std::uint64_t player_count, bool encrypted_player,
        std::string_view player_id, std::string_view field_modulus);
#ifdef KPI_P1_MASCOT_SECRET_STATE_HOOK_TEST_SETUP
public:
    static std::unique_ptr<MascotSecretStateHookScope> test_only_install(
        MascotSecretStateHook&, std::uint64_t local_role,
        std::uint64_t player_count, bool encrypted_player,
        std::string_view player_id, std::string_view field_modulus);
#endif
};

// Installed before ProtocolSetup construction and destroyed after its
// destructor. A process-wide registry detects a source call made from a
// worker without the root-thread epoch instead of silently omitting it.
class MascotSecretStateHookScope final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    MascotSecretStateHookScope(
        MascotSecretStateHook&, std::uint64_t local_role,
        std::uint64_t player_count, bool encrypted_player,
        std::string_view player_id, std::string_view field_modulus);
    friend class MascotSecretStateScopeFactoryBridge;
    friend class MascotSecretStateSourceBridge;

public:
    MascotSecretStateHookScope(const MascotSecretStateHookScope&) = delete;
    MascotSecretStateHookScope& operator=(
        const MascotSecretStateHookScope&) = delete;
    MascotSecretStateHookScope(MascotSecretStateHookScope&&) = delete;
    MascotSecretStateHookScope& operator=(
        MascotSecretStateHookScope&&) = delete;
    ~MascotSecretStateHookScope();
};

// Typed source-only entry points. There is deliberately no generic record()
// method and no way to install or retrieve a hook through this bridge.
class MascotSecretStateSourceBridge final {
    MascotSecretStateSourceBridge() = delete;
public:
    // False means no selected P1 scope exists. A wrong-thread call poisons the
    // installed scope and returns true so the source attempts (and fails) the
    // typed edge instead of silently continuing.
    static bool capture_required_noexcept() noexcept;
    static bool scalar_state_begin(
        std::string_view canonical_cache_domain,
        std::string_view diagnostic_path, std::uint64_t batch_size,
        std::uint64_t bucket_size, std::uint64_t statistical_security,
        bool uses_security_parameter, bool uses_kos,
        std::span<const unsigned char> prep_scalar_key_before,
        std::span<const unsigned char> online_scalar_key_before) noexcept;
    static bool setup_begin(
        std::string_view canonical_cache_domain,
        std::string_view diagnostic_path, std::uint64_t batch_size,
        std::uint64_t bucket_size, std::uint64_t statistical_security,
        bool uses_security_parameter, bool uses_kos,
        bool complete_key_before_initialized,
        std::span<const unsigned char> complete_key_before) noexcept;
    static bool cache_opened(
        std::string_view diagnostic_path,
        const MascotFileSnapshotView&) noexcept;
    static bool cache_local_validation(
        MascotStepResult,
        bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after,
        std::string_view failure_reason) noexcept;
    static bool cache_peer_validation(
        MascotStepResult, std::string_view failure_reason) noexcept;
    static bool regeneration(
        bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after) noexcept;
    static bool write_candidate(
        bool complete_key_before_initialized,
        std::span<const unsigned char> complete_key_before,
        bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after,
        std::span<const unsigned char> exact_candidate) noexcept;
    static bool writeback(
        std::string_view diagnostic_path, MascotStepResult,
        const MascotFileSnapshotView&,
        std::string_view failure_reason) noexcept;
    static bool prep_static_installed(
        std::span<const unsigned char> prep_scalar_key_before,
        std::span<const unsigned char> prep_scalar_key_after,
        std::span<const unsigned char> expected_scalar_key) noexcept;
    static bool prep_mac_file_write(
        std::string_view diagnostic_path, MascotStepResult,
        const MascotFileSnapshotView&,
        std::span<const unsigned char> exact_candidate,
        std::string_view failure_reason) noexcept;
    static bool bit_prep_derived(
        std::span<const unsigned char> complete_key_before,
        std::span<const unsigned char> complete_key_after,
        std::span<const unsigned char> derived_complete_key,
        bool bit_prep_aliases_main) noexcept;
    static bool static_installed(
        bool complete_key_initialized,
        std::span<const unsigned char> complete_key,
        std::span<const unsigned char> scalar_key_before,
        std::span<const unsigned char> scalar_key_after,
        std::span<const unsigned char> expected_scalar_key) noexcept;
    static bool teardown(
        bool complete_key_before_initialized,
        std::span<const unsigned char> complete_key_before,
        std::span<const unsigned char> scalar_key_before,
        bool complete_key_after_initialized,
        std::span<const unsigned char> complete_key_after,
        std::span<const unsigned char> scalar_key_after,
        std::span<const unsigned char> prep_scalar_key_before,
        std::span<const unsigned char> prep_scalar_key_after) noexcept;
    static std::uint64_t register_ot_worker_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_ordinal,
        std::uint64_t registered_worker_count) noexcept;
    static bool ot_worker_started_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch,
        std::uint64_t source_worker_ordinal) noexcept;
    static void ot_worker_failure_published_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch,
        MascotWorkerExceptionKind) noexcept;
    static void ot_worker_terminal_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch,
        bool failed) noexcept;
    static void root_worker_failure_observed_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch) noexcept;
    static void ot_worker_joined_noexcept(
        const void* source_worker_identity,
        std::uint64_t source_worker_epoch) noexcept;
    static bool abort_cache_unlink_noexcept(
        MascotSecretAbortClass,
        std::string_view diagnostic_path,
        bool succeeded,
        std::uint64_t operation_errno,
        const MascotFileMetadataView& path_lstat_before,
        const MascotFileMetadataView& path_lstat_after) noexcept;
    static void unavailable_noexcept() noexcept;
};

struct MascotSecretStateHookSourceStatus final {
    bool canonical_raw_event_encoding{};
    bool pinned_mp_spdz_source_sites{};
    bool exact_cache_file_and_complete_key_bytes{};
    bool typed_branch_specific_lifecycle{};
    bool root_thread_scope{};
    bool capsule_family_adapter{};
    bool selected_role1_installation{};
    bool complete_corrupt_p1_view{};
    bool configured{};
};

inline constexpr MascotSecretStateHookSourceStatus
kMascotSecretStateHookSourceStatus{
    .canonical_raw_event_encoding = true,
    .pinned_mp_spdz_source_sites = false,
    .exact_cache_file_and_complete_key_bytes = false,
    .typed_branch_specific_lifecycle = false,
    .root_thread_scope = true,
    .capsule_family_adapter = true,
    .selected_role1_installation = false,
    .complete_corrupt_p1_view = false,
    .configured = false,
};

} // namespace kpi::mpc::p1_private_state

namespace kpb::measurement::p1_state_capsule {

class P1MascotSecretStateAdapter final
    : public kpi::mpc::p1_private_state::MascotSecretStateHook {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1MascotSecretStateAdapter(std::unique_ptr<Storage>);
    friend class P1MascotSecretStateAdapterFactoryBridge;

public:
    P1MascotSecretStateAdapter(const P1MascotSecretStateAdapter&) = delete;
    P1MascotSecretStateAdapter& operator=(
        const P1MascotSecretStateAdapter&) = delete;
    P1MascotSecretStateAdapter(P1MascotSecretStateAdapter&&) = delete;
    P1MascotSecretStateAdapter& operator=(
        P1MascotSecretStateAdapter&&) = delete;
    ~P1MascotSecretStateAdapter() override;
    bool record_mascot_secret_event(
        const kpi::mpc::p1_private_state::MascotSecretEventView&) noexcept
        override;
    bool record_mascot_secret_abort_event(
        const kpi::mpc::p1_private_state::
            MascotSecretAbortEventView&) noexcept override;
    void mascot_secret_unavailable_noexcept() noexcept override;
};

} // namespace kpb::measurement::p1_state_capsule
