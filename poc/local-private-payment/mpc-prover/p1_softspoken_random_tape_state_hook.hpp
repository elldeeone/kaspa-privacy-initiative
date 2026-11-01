#pragma once

// Private, process-local evidence transport for the exact pinned malicious
// SoftSpokenOT random tape. Native object and pthread addresses are correlation
// keys only. They are never serialized or accepted as evidence identities.

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace kpi::mpc::p1_private_state {
class SoftSpokenRandomTapeStateHook;
class SoftSpokenRandomTapeStateScope;
struct SoftSpokenRandomTapeStateHookAccess;
}

namespace kpb::measurement::p1_state_capsule {
class P1SoftSpokenRandomTapeStateAdapter;

// Complete before friendship. Only the future concrete private capsule
// adapter can install a source scope; no recorder, fd, digest, or public take
// surface is exposed here.
class P1SoftSpokenRandomTapeStateAdapterFactoryBridge final {
    P1SoftSpokenRandomTapeStateAdapterFactoryBridge() = delete;
    friend class P1SoftSpokenRandomTapeStateAdapter;

    static std::unique_ptr<
        ::kpi::mpc::p1_private_state::SoftSpokenRandomTapeStateScope>
    install_source_scope(
        ::kpi::mpc::p1_private_state::SoftSpokenRandomTapeStateHook&,
        const void* source_player, std::uint64_t persistent_child_epoch,
        std::uint64_t player_epoch, std::uint64_t root_worker_epoch,
        std::uint64_t local_role, std::uint64_t peer_role);
};
}

namespace kpi::mpc::p1_private_state {

inline constexpr std::string_view SOFTSPOKEN_RANDOM_TAPE_DOMAIN =
    "KPI_P1_SOFTSPOKEN_OT_RANDOM_TAPE_V1\n";
inline constexpr std::string_view SOFTSPOKEN_MP_SPDZ_COMMIT =
    "113c4e47dd94bca9ecab029d2f0abe649bea5c52";
inline constexpr std::string_view SOFTSPOKEN_LIBOTE_COMMIT =
    "fe6b2ff82a976a5332b3a2efe325831588b1324a";
inline constexpr std::string_view SOFTSPOKEN_CRYPTOTOOLS_COMMIT =
    "f70175e0cbd36b808475c0c1bbf585304e43d3d0";

// Filled only from exact pre/postimages after the isolated patch is frozen.
// Until then this slice is neither selected nor an available capsule family.
inline constexpr std::string_view SOFTSPOKEN_SOURCE_CLOSURE_MANIFEST =
    "KPI_P1_SOFTSPOKEN_SOURCE_MANIFEST_PENDING_V1\n";
inline constexpr std::string_view SOFTSPOKEN_SOURCE_CLOSURE_SHA256 =
    "0000000000000000000000000000000000000000000000000000000000000000";

enum class SoftSpokenRole : std::uint8_t {
    None = 0,
    Sender = 1,
    Receiver = 2,
};

enum class SoftSpokenEventKind : std::uint8_t {
    Construct = 1,
    PathSelected = 2,
    StateLookup = 3,
    StateConstructBegin = 4,
    StateConstructEnd = 5,
    CallBegin = 6,
    RoleBegin = 7,
    SeededPrng = 8,
    BaseInstalled = 9,
    VoleExpanded = 10,
    TapeConsumed = 11,
    ChallengeBound = 12,
    RtcrBound = 13,
    CheckDerived = 14,
    CheckTerminal = 15,
    OutputReady = 16,
    RoleEnd = 17,
    Join = 18,
    CallEnd = 19,
    StateDestructorBegin = 20,
    StateDestructorTerminal = 21,
    PathRejected = 22,
    Abort = 23,
};

enum class SoftSpokenPathClass : std::uint8_t {
    None = 0,
    SelectedMaliciousK2 = 1,
    Kos = 2,
    Silent = 3,
    SemiHonest = 4,
    HighOrOtherK = 5,
    LibOte1 = 6,
    UnsupportedRole = 7,
};

enum class SoftSpokenAbortClass : std::uint8_t {
    None = 0,
    StateConstructor = 1,
    SenderException = 2,
    ReceiverException = 3,
    CallException = 4,
    SourceSerialization = 5,
    ScopeUnlinked = 6,
    PartialRoleGraph = 7,
    WrongWorker = 8,
    RejectedPath = 9,
};

enum class SoftSpokenRolePhase : std::uint8_t {
    None = 0,
    Begun = 1,
    Seeded = 2,
    Base = 3,
    Expanded = 4,
    Tape = 5,
    Challenge = 6,
    Rtcr = 7,
    CheckDerived = 8,
    CheckTerminal = 9,
    Output = 10,
    Ended = 11,
    Poisoned = 12,
};

enum class SoftSpokenSnapshotMask : std::uint8_t {
    None = 0,
    Seed = 1,
    Prng = 2,
    Base = 4,
    Object = 8,
    Transient = 16,
    Output = 32,
};

constexpr SoftSpokenSnapshotMask operator|(
        SoftSpokenSnapshotMask left,
        SoftSpokenSnapshotMask right) noexcept {
    return static_cast<SoftSpokenSnapshotMask>(
        static_cast<unsigned>(left) | static_cast<unsigned>(right));
}

struct SoftSpokenEventDescriptor final {
    SoftSpokenEventKind kind{};
    SoftSpokenSnapshotMask snapshots{};
    std::string_view source_site;
    std::string_view source_identity_sha256;
};

std::span<const SoftSpokenEventDescriptor>
softspoken_event_descriptors() noexcept;
const SoftSpokenEventDescriptor& softspoken_event_descriptor(
    SoftSpokenEventKind);

struct SoftSpokenEventView final {
    SoftSpokenEventKind kind{};
    SoftSpokenPathClass path_class{SoftSpokenPathClass::None};
    SoftSpokenAbortClass abort_class{SoftSpokenAbortClass::None};
    SoftSpokenRolePhase role_phase{SoftSpokenRolePhase::None};
    SoftSpokenRole role{SoftSpokenRole::None};
    std::uint64_t sequence{};
    std::uint64_t persistent_child_epoch{};
    std::uint64_t player_epoch{};
    std::uint64_t root_worker_epoch{};
    std::uint64_t worker_epoch{};
    std::uint64_t state_epoch{};
    std::uint64_t call_epoch{};
    std::uint64_t local_role{};
    std::uint64_t peer_role{};
    std::uint64_t ot_role_mask{};
    std::uint64_t n_ots{};
    std::uint64_t softspoken_k{};
    bool just_bits{};
    bool source_succeeded{};
    std::string_view source_site;
    std::string_view source_identity_sha256;
    std::span<const unsigned char> seed_material;
    std::span<const unsigned char> prng_state;
    std::span<const unsigned char> base_material;
    std::span<const unsigned char> object_state;
    std::span<const unsigned char> transient_state;
    std::span<const unsigned char> output_state;
};

class SoftSpokenCanonicalBytes final {
    std::vector<unsigned char> value_;
    explicit SoftSpokenCanonicalBytes(std::vector<unsigned char>);
    friend SoftSpokenCanonicalBytes encode_softspoken_event(
        const SoftSpokenEventView&);
public:
    SoftSpokenCanonicalBytes(const SoftSpokenCanonicalBytes&) = delete;
    SoftSpokenCanonicalBytes& operator=(const SoftSpokenCanonicalBytes&) =
        delete;
    SoftSpokenCanonicalBytes(SoftSpokenCanonicalBytes&&) noexcept;
    SoftSpokenCanonicalBytes& operator=(SoftSpokenCanonicalBytes&&) noexcept;
    ~SoftSpokenCanonicalBytes();
    std::span<const unsigned char> view() const noexcept { return value_; }
};

SoftSpokenCanonicalBytes encode_softspoken_event(
    const SoftSpokenEventView&);

class SoftSpokenRandomTapeStateHook {
    SoftSpokenRandomTapeStateHook() = default;
    friend class ::kpb::measurement::p1_state_capsule::
        P1SoftSpokenRandomTapeStateAdapter;
    friend class SoftSpokenRandomTapeStateScope;
    friend struct SoftSpokenRandomTapeStateHookAccess;

    virtual bool record_softspoken_event(
        const SoftSpokenEventView&) noexcept = 0;
    virtual bool bind_softspoken_worker_epoch(
        SoftSpokenRole, std::uint64_t& logical_worker_epoch) noexcept = 0;
    virtual bool softspoken_terminal_noexcept() noexcept = 0;
    virtual void softspoken_unavailable_noexcept() noexcept = 0;

#ifdef KPI_P1_SOFTSPOKEN_RANDOM_TAPE_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit SoftSpokenRandomTapeStateHook(TestOnlyConstruction) {}
#endif
public:
    SoftSpokenRandomTapeStateHook(const SoftSpokenRandomTapeStateHook&) =
        delete;
    SoftSpokenRandomTapeStateHook& operator=(
        const SoftSpokenRandomTapeStateHook&) = delete;
    virtual ~SoftSpokenRandomTapeStateHook() = default;
};

class SoftSpokenRandomTapeStateScope final {
public:
    struct Storage;
private:
    std::unique_ptr<Storage> storage_;
    SoftSpokenRandomTapeStateScope(
        SoftSpokenRandomTapeStateHook&, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_worker_epoch, std::uint64_t local_role,
        std::uint64_t peer_role);
    friend class ::kpb::measurement::p1_state_capsule::
        P1SoftSpokenRandomTapeStateAdapterFactoryBridge;
#ifdef KPI_P1_SOFTSPOKEN_RANDOM_TAPE_STATE_HOOK_TEST_SETUP
    friend class SoftSpokenRandomTapeStateTestBridge;
#endif
public:
    SoftSpokenRandomTapeStateScope(
        const SoftSpokenRandomTapeStateScope&) = delete;
    SoftSpokenRandomTapeStateScope& operator=(
        const SoftSpokenRandomTapeStateScope&) = delete;
    SoftSpokenRandomTapeStateScope(SoftSpokenRandomTapeStateScope&&) = delete;
    SoftSpokenRandomTapeStateScope& operator=(
        SoftSpokenRandomTapeStateScope&&) = delete;
    ~SoftSpokenRandomTapeStateScope();
};

// Source-only bridge. False means no private scope exists. Once a scope is
// present, malformed or rejected input poisons it and returns true so upstream
// execution cannot silently reinterpret capture failure as an unselected run.
class SoftSpokenRandomTapeStateSourceBridge final {
    SoftSpokenRandomTapeStateSourceBridge() = delete;
public:
    static bool capture_required_pointer_noexcept(
        const void* source_player) noexcept;
    static bool capture_required_current_noexcept() noexcept;
    static bool path_selected(
        const void* source_player, std::uint64_t local_role,
        std::uint64_t peer_role, std::uint64_t ot_role_mask,
        std::uint64_t softspoken_k, bool passive_only,
        bool use_kos, bool silent_ot, bool libote1) noexcept;
    static bool path_rejected(
        const void* source_player, SoftSpokenPathClass) noexcept;
    static bool state_lookup(
        const void* source_player, bool existing) noexcept;
    static bool state_construct_begin(const void* source_player) noexcept;
    static bool state_construct_end(
        const void* source_player, bool succeeded) noexcept;
    static bool call_begin(
        const void* source_player, std::uint64_t n_ots,
        bool just_bits) noexcept;
    static bool role_begin(
        const void* source_player, SoftSpokenRole) noexcept;
    static bool seeded_prng(
        std::span<const unsigned char> seed,
        std::span<const unsigned char> prng) noexcept;
    static bool base_installed(
        std::span<const unsigned char> base,
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept;
    static bool vole_expanded(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> seed) noexcept;
    static bool tape_consumed(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept;
    static bool challenge_bound(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept;
    static bool rtcr_bound(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> transient) noexcept;
    static bool stage_check_transient(
        std::span<const unsigned char> transient) noexcept;
    static bool check_derived(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> transient) noexcept;
    static bool check_terminal(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng) noexcept;
    static bool output_ready(
        std::span<const unsigned char> object,
        std::span<const unsigned char> prng,
        std::span<const unsigned char> output) noexcept;
    static bool role_end(SoftSpokenRole) noexcept;
    static bool join(const void* source_player) noexcept;
    static bool call_end(const void* source_player) noexcept;
    static bool state_destructor_begin(const void* source_player) noexcept;
    static bool state_destructor_terminal(
        const void* source_player) noexcept;
    static void abort_current_noexcept(
        SoftSpokenAbortClass, SoftSpokenRolePhase) noexcept;
    static void abort_player_noexcept(
        const void* source_player, SoftSpokenAbortClass) noexcept;
};

#ifdef KPI_P1_SOFTSPOKEN_RANDOM_TAPE_STATE_HOOK_TEST_SETUP
class SoftSpokenRandomTapeStateTestBridge final {
    SoftSpokenRandomTapeStateTestBridge() = delete;
public:
    static std::unique_ptr<SoftSpokenRandomTapeStateScope> install(
        SoftSpokenRandomTapeStateHook& hook, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_worker_epoch, std::uint64_t local_role,
        std::uint64_t peer_role);
};
#endif

} // namespace kpi::mpc::p1_private_state
